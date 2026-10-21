"""Splitting a host whose event logs record several computers.

A folder of loose event logs from many machines, or a log collector's forwarded events, loads as one host: one lane,
one role guess, every machine's names, and logon-session and time-window pivots that join events across machines.
After a tool run the Hosts panel says so, and offers to split the host by the computer each event records, or to keep
it as one host.

A split is a journal entry of routes, from a recorded computer name in lower case to the lane its events go to. It
changes only the events table's host column. Every row keeps the host it was loaded under as origin_host, which its
ID hashes, so no ID changes and every journal reference (marks, notes, tags, decisions, undos) still holds. Loads route
new rows the same way (events.load), so a rerun or a rebuild keeps the split, and apply_layout brings the table into
line with the journal whenever the case opens or its events change, which also covers a crash between the journal
entry and the update. Undoing a split takes every route of the host away, and any Keep as one host before it, so the
notice returns while the host's logs record several computers. Only event log rows and Hayabusa's hits on
them move (events.SPLIT_TOOLS); an MFT, a hive, or an import stays on its host. "Same source IP" and "Same IP at either
end" search the whole case by design, so a split changes neither.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field

import duckdb

from .accounts import name_sids
from .events import SPLIT_TOOLS, id_table, insert_columns, sql_literal
from .journal import State

TOOLS_SQL = ", ".join(sql_literal(t) for t in SPLIT_TOOLS)
LOG_TOOLS_SQL = "'evtxecmd', 'event_xml'"   # the event log readers; Hayabusa's rows are hits on their records
# Forwarded events keep the channel they were written to on their own computer, so the collector's log is known by its
# file, ForwardedEvents.evtx by default, as well as by the channel. Its events don't make their computers one machine.
# A subscription can write to a custom log, such as WEC-Security.evtx, so a log whose computers interleave is read as
# forwarded too (see _interleaved).
FORWARDED_SQL = "(log_channel = 'ForwardedEvents' OR lower(source_file) LIKE '%forwardedevents%')"


class SplitError(ValueError):
    """A split the Hosts panel can't make, with a message for the analyst."""


def computer_key(name: str | None) -> str:
    """A recorded computer name as routes and kept names hold it: trimmed, in lower case."""
    return (name or "").strip().lower()


def _label(key: str) -> str:
    return key.partition(".")[0]


def _domain(key: str) -> str:
    return key.partition(".")[2]


class Routes:
    """Where a host's split sends each recorded computer name. A name goes by its own key. A name with no route of its
    own follows its first label's, as pc01.corp.local follows a split's PC01, unless a routed name with that label is
    in a domain: a name in another domain is another machine, so it stays on the host to be split again. Lookups are
    cached, since a load asks once per event."""

    def __init__(self, routes: dict[str, str]):
        self.routes = dict(routes)
        self.qualified = {_label(k) for k in self.routes if _domain(k)}
        self.cache: dict[str | None, str | None] = {}

    def lane(self, recorded: str | None) -> str | None:
        if recorded in self.cache:
            return self.cache[recorded]
        key = computer_key(recorded)
        lane = self.routes.get(key) if key else None
        if lane is None and key and _label(key) not in self.qualified:
            lane = self.routes.get(_label(key))
        self.cache[recorded] = lane
        return lane


@dataclass
class Machine:
    """One computer among a host's event logs, as the names it was recorded under. Two names are one machine when one
    log file holds both, as after a rename, or when they're a name and its domain-qualified form, PC01 and
    PC01.corp.local. A forwarded events log joins nothing, since it holds other computers' events; nor does a log whose
    computers interleave."""
    names: list[str] = field(default_factory=list)   # as recorded, most events first
    events: int = 0
    files: set[str] = field(default_factory=set)
    forwarded: int = 0                                # of its events, those in a forwarded events log
    last_us: int | None = None
    newest: str = ""                                  # the name it was recorded under latest

    @property
    def keys(self) -> set[str]:
        return {computer_key(n) for n in self.names}


def machines(con: duckdb.DuckDBPyConnection, cache: dict | None = None) -> dict[str, list[Machine]]:
    """The computers whose event logs are still on the host they were loaded under, by host, most events first. Rows a
    split moved are left out, so a split host's own lane shows only what stayed. `cache` keeps the result until the
    events change (the server clears it then)."""
    if cache is not None and "machines" in cache:
        return cache["machines"]
    rows = con.execute(f"""
        SELECT origin_host, source_file, {FORWARDED_SQL} AS fwd, host_name_recorded, count(*), max(ts_us),
               min(record_id), max(record_id)
        FROM events WHERE tool IN ({LOG_TOOLS_SQL}) AND host_name_recorded <> '' AND host = origin_host
        GROUP BY ALL""").fetchall()
    by_host: dict[str, list[tuple]] = {}
    for row in rows:
        by_host.setdefault(row[0], []).append(row[1:])
    found = {host: _machines(host_rows) for host, host_rows in sorted(by_host.items())}
    if cache is not None:
        cache["machines"] = found
    return found


def _interleaved(rows: list[tuple]) -> set[str]:
    """The log files whose computers interleave: two first labels whose record numbers overlap. A machine's own log
    changes the name it records only at a rename, so in record order each label's events come in one run; a
    collector's log holds its computers' events as they arrived, whatever the file is called (a
    subscription can write to WEC-Security.evtx). On the Szechuan and perf-10-hosts cases, every file holding two
    labels holds each in one run, so their renamed hosts stay one computer each."""
    spans: dict[str, dict[str, list[int]]] = {}   # file -> first label -> [first record, last record]
    for source, _fwd, name, _n, _last, low, high in rows:
        key = computer_key(name)
        if key and low is not None and high is not None:
            span = spans.setdefault(source, {}).setdefault(_label(key), [low, high])
            span[0], span[1] = min(span[0], low), max(span[1], high)
    found = set()
    for source, labels in spans.items():
        reach = None
        for low, high in sorted(labels.values()):
            if reach is not None and low <= reach:
                found.add(source)
                break
            reach = high if reach is None else max(reach, high)
    return found


def _machines(rows: list[tuple]) -> list[Machine]:
    parent: dict[str, str] = {}

    def find(k: str) -> str:
        while parent[k] != k:
            parent[k] = parent[parent[k]]
            k = parent[k]
        return k

    def union(a: str, b: str) -> None:
        parent[find(a)] = find(b)

    spelled: dict[str, dict[str, list]] = {}   # key -> raw name -> [events, last_us]
    files: dict[str, set[str]] = {}
    in_file: dict[str, set[str]] = {}
    forwarded: dict[str, int] = {}
    collected = _interleaved(rows)
    for source, fwd, name, n, last, _low, _high in rows:
        key = computer_key(name)
        if not key:
            continue
        fwd = fwd or source in collected
        parent.setdefault(key, key)
        stats = spelled.setdefault(key, {}).setdefault(name, [0, None])
        stats[0] += n
        if last is not None and (stats[1] is None or last > stats[1]):
            stats[1] = last
        files.setdefault(key, set()).add(source)
        if fwd:
            forwarded[key] = forwarded.get(key, 0) + n
        else:
            in_file.setdefault(source, set()).add(key)
    for keys in in_file.values():
        first, *rest = sorted(keys)
        for k in rest:
            union(first, k)
    # A bare name is the same machine as its qualified form when the label has one domain here; with two, it could be
    # either, so it stays a machine of its own.
    by_label: dict[str, list[str]] = {}
    for key in parent:
        by_label.setdefault(_label(key), []).append(key)
    for keys in by_label.values():
        if len({_domain(k) for k in keys if _domain(k)}) <= 1:
            for k in keys[1:]:
                union(keys[0], k)
    groups: dict[str, list[str]] = {}
    for key in sorted(parent):
        groups.setdefault(find(key), []).append(key)
    out = []
    for keys in groups.values():
        named = sorted(((raw, s[0], s[1]) for k in keys for raw, s in spelled[k].items()), key=lambda x: (-x[1], x[0]))
        last = max((x[2] for x in named if x[2] is not None), default=None)
        newest = next((raw for raw, _, t in named if t == last), named[0][0]) if last is not None else named[0][0]
        out.append(Machine(names=[raw for raw, _, _ in named], events=sum(x[1] for x in named),
                           files=set().union(*(files[k] for k in keys)),
                           forwarded=sum(forwarded.get(k, 0) for k in keys), last_us=last, newest=newest))
    return sorted(out, key=lambda m: (-m.events, m.names[0].lower()))


def mark_mixed(identity, state: State, found: dict[str, list[Machine]]) -> None:
    """Flag each host whose own lane still holds two or more computers' event logs, unless the analyst kept it as one
    host with these computers. The flag is a review reason, so it counts on the Hosts button, and identity.mixed, which
    the Hosts panel's notice reads."""
    for host, ms in found.items():
        h = identity.hosts.get(host)
        if h is None or len(ms) < 2:
            continue
        kept = state.kept.get(host, set())
        if all(m.keys <= kept for m in ms):
            continue   # kept as one host, and no computer has appeared since
        identity.mixed[host] = {"host": host, "computers": len(ms), "names": len(h.names), "role": h.role,
                                "role_source": h.role_source, "forwarded": sum(m.forwarded for m in ms)}
        h.review.append(f"Its event logs were recorded by {len(ms)} computers")


def _clean(text: str) -> str:
    """A name in a lane's characters: upper case, other characters as hyphens, at most 63 long. Recorded names come
    from evidence, so they can hold anything."""
    return re.sub(r"[^A-Z0-9_-]+", "-", text.upper()).strip("-_")[:63].rstrip("-_")


def proposal(con: duckdb.DuckDBPyConnection, state: State, identity, host: str, found: dict[str, list[Machine]],
             folders: set[str]) -> dict:
    """What splitting `host` would do: a new host per computer, what stays, and the routes to journal. `folders` are
    the host folders intake found, which a new host's name mustn't take.

    The computer that has the host folder's name, or that the host's SYSTEM hive names, stays on the host; failing
    both, a log collector's own computer, the one whose events weren't all forwarded, stays. A new host
    is named from the computer's latest recorded name, its first label in upper case. Two computers with one label in
    different domains take the domain's first label too, as PC01-CORP; a bare PC01 beside them could be either, so it
    stays. A name another host, folder, or split already has takes the host's name as a suffix, DC1-LAB, then DC1-LAB-2:
    a split never merges into an existing host."""
    h = identity.hosts.get(host)
    ms = found.get(host, [])
    if h is None or len(ms) < 2:
        raise SplitError(f"{host}'s event logs record one computer, so there's nothing to split.")
    users: dict[str, int] = {}   # label -> how many of the host's computers have a name with it
    for m in ms:
        for lab in {_label(k) for k in m.keys}:
            users[lab] = users.get(lab, 0) + 1
    own = {host.lower(), *(n.lower() for n in h.registry_names)}
    # A log collector whose folder isn't named for it, as by an evidence ID, with no SYSTEM hive loaded: the one
    # computer with logs of its own, when every other computer's events were forwarded, is the collector, and stays
    # with the rest of the folder's evidence.
    named = any({_label(k) for k in m.keys} & own for m in ms)
    own_logs = [m for m in ms if m.forwarded < m.events]   # with two or more computers, one alone means the rest forwarded
    collector = own_logs[0] if not named and len(own_logs) == 1 else None
    stays, moves = [], []
    for m in ms:
        labels = {_label(k) for k in m.keys}
        if labels & own:
            stays.append((m, "the host folder's name" if host.lower() in labels else "the name the host's SYSTEM hive records"))
        elif m is collector:
            stays.append((m, "the only event logs here that weren't forwarded from other computers"))
        elif not any(_domain(k) for k in m.keys) and any(users[lab] > 1 for lab in labels):
            stays.append((m, "a name without a domain that two other computers share"))
        else:
            moves.append(m)
    if not moves:
        raise SplitError(f"Every computer in {host}'s event logs belongs to {host}, so there's nothing to split.")
    taken = {x.upper() for x in [*identity.hosts, *folders]}
    # These readers run without the lock, and a split under it changes the journal's dicts in place: loops go over copies,
    # one C call each
    taken |= {lane.upper() for routes in list(state.splits.values()) for lane in list(routes.values())}
    suffix = _clean(host)[:30].rstrip("-_") or "SPLIT"   # short enough that a suffixed name keeps some of its own
    groups, routes, unnamed = [], {}, 0
    existing = dict(state.splits.get(host, {}))
    claimed = {_label(k) for k in existing}   # labels an earlier split routed keep their lane
    for m in moves:
        key = computer_key(m.newest)
        base = _clean(_label(key))
        if users[_label(key)] > 1 and _domain(key):
            base = _clean(f"{_label(key)}-{_label(_domain(key))}")
        if not base:
            unnamed += 1
            base = _clean(f"{suffix}-COMPUTER-{unnamed}")
        lane, note = base, ""
        if lane in taken:
            note = (f"{base} is already a host here" if base in {x.upper() for x in identity.hosts} else
                    f"a host folder is named {base}" if base in {x.upper() for x in folders} else
                    f"another computer here takes {base}")
            n = 1
            while lane in taken:
                tail = f"-{suffix}" + (f"-{n}" if n > 1 else "")
                lane = base[:63 - len(tail)].rstrip("-_") + tail
                n += 1
        taken.add(lane)
        for k in m.keys:
            routes[k] = lane
        for lab in sorted({_label(k) for k in m.keys}):
            if users[lab] == 1 and lab not in claimed and lab not in routes:
                routes[lab] = lane   # so the computer's bare name follows, when only it has the label
        groups.append({"lane": lane, "names": m.names, "files": len(m.files), "forwarded": m.forwarded,
                       "events": 0, "hayabusa": 0, "note": note})
    router = Routes({**existing, **routes})
    by_lane = {g["lane"]: g for g in groups}
    stays_rows: dict[tuple[str, str], int] = {}
    for tool, artifact, recorded, n in con.execute(
            "SELECT tool, artifact, host_name_recorded, count(*) FROM events WHERE origin_host = ? AND host = origin_host "
            "GROUP BY ALL", [host]).fetchall():
        lane = router.lane(recorded) if tool in SPLIT_TOOLS else None
        if lane in by_lane:
            by_lane[lane]["hayabusa" if tool == "hayabusa" else "events"] += n
        elif lane is None:
            stays_rows[(tool, artifact)] = stays_rows.get((tool, artifact), 0) + n
    moving = _moving_references(con, state, host, router, set(by_lane))
    staying = sum(stays_rows.values())
    return {
        "host": host, "computers": len(ms), "groups": groups, "routes": routes,
        "hosts_after": len(groups) + (1 if staying else 0),
        "stays": {"total": staying,
                  "computers": [{"names": m.names, "events": m.events, "reason": why} for m, why in stays],
                  "rows": [{"tool": t, "artifact": a, "count": n}
                           for (t, a), n in sorted(stays_rows.items(), key=lambda x: -x[1])]},
        "edits": _edits_left(state, host),
        "moving": moving,
        "basis": hashlib.sha256(json.dumps(routes, sort_keys=True).encode()).hexdigest()[:16],
    }


def _moving_references(con, state: State, host: str, router: Routes, lanes: set[str]) -> dict[str, int]:
    """How many marked, noted, and tagged events the split moves to a new lane. Their IDs don't change, so each keeps
    its mark, notes, and tags; the dialog says how many."""
    wanted = set(state.marks) | set(state.notes) | set(state.tags)
    moved: set[str] = set()
    if wanted:
        table = id_table(con, "split_references", sorted(wanted))
        for uid, recorded in con.execute(
                f"SELECT event_uid, host_name_recorded FROM events WHERE origin_host = ? AND host = origin_host "
                f"AND tool IN ({TOOLS_SQL}) AND event_uid IN (SELECT v FROM {table})", [host]).fetchall():
            if router.lane(recorded) in lanes:
                moved.add(uid)
    return {"marks": len(moved & set(state.marks)), "notes": len(moved & set(state.notes)),
            "tags": len(moved & set(state.tags))}


def _edits_left(state: State, host: str) -> list[str]:
    """What the analyst set for the host that stays with it and doesn't reach the new hosts."""
    out = []
    edits = state.hosts.get(host)
    if edits and edits.role:
        out.append(f"its role, {edits.role}")
    if edits and edits.offset_seconds:
        out.append(f"its clock offset of {edits.offset_seconds:+g} s")
    if edits and (edits.add_names or edits.add_ips):
        out.append("the names and IPs added to it: " + ", ".join(sorted(edits.add_names | edits.add_ips)))
    if any(isinstance(a, dict) and a.get("host") == host for a in state.settings.get("time_zones") or []):
        out.append("its time zone axis")
    pattern = re.compile(rf"(?<![\w-]){re.escape(host)}(?![\w-])", re.IGNORECASE)
    rules = sorted(rid for rid, r in list(state.rules.items()) if pattern.search(r.get("text", "")))   # a copy
    if rules:
        out.append(f"the rules that name it: {', '.join(rules)}")
    return out


def apply_layout(con: duckdb.DuckDBPyConnection, state: State) -> set[str]:
    """Move rows to the lanes the journal's splits give them, and rows of an undone split back to the host they were
    loaded under. Returns the lanes whose rows changed. One transaction, with the SID lookup of those lanes (accounts.py),
    since a lane's lookup reads only its own logons. With nothing to change it writes nothing."""
    hosts = set(state.splits) | {h for (h,) in con.execute(
        "SELECT DISTINCT origin_host FROM events WHERE host <> origin_host").fetchall()}
    if not hosts:
        return set()
    host_list = ", ".join(sql_literal(h) for h in sorted(hosts))
    routers = {host: Routes(routes) for host, routes in state.splits.items()}
    pairs = []
    for origin, recorded in con.execute(
            f"SELECT DISTINCT origin_host, host_name_recorded FROM events WHERE origin_host IN ({host_list}) "
            f"AND tool IN ({TOOLS_SQL}) AND host_name_recorded IS NOT NULL").fetchall():
        lane = routers[origin].lane(recorded) if origin in routers else None
        if lane is not None:
            pairs.append((origin, recorded, lane))
    con.execute("BEGIN TRANSACTION")
    try:
        con.execute("CREATE OR REPLACE TEMP TABLE split_map (origin VARCHAR, recorded VARCHAR, lane VARCHAR)")
        insert_columns(con, "split_map", *zip(*pairs))   # a NUL in a recorded name goes in as it is
        con.execute(f"""
            CREATE OR REPLACE TEMP TABLE lane_fix AS
            SELECT e.rowid AS rid, e.host AS old, COALESCE(m.lane, e.origin_host) AS lane
            FROM events e LEFT JOIN split_map m ON m.origin = e.origin_host AND m.recorded = e.host_name_recorded
                 AND e.tool IN ({TOOLS_SQL})
            WHERE e.origin_host IN ({host_list}) AND e.host IS DISTINCT FROM COALESCE(m.lane, e.origin_host)""")
        old, new = con.execute("SELECT list(DISTINCT old), list(DISTINCT lane) FROM lane_fix").fetchone()
        lanes = set(old or ()) | set(new or ())
        if lanes:
            con.execute("UPDATE events SET host = f.lane FROM lane_fix f WHERE events.rowid = f.rid")
            name_sids(con, lanes)
        con.execute("COMMIT")
    except Exception:
        con.execute("ROLLBACK")
        raise
    finally:
        for table in ("split_map", "lane_fix"):
            con.execute(f"DROP TABLE IF EXISTS {table}")
    return lanes


def split_list(state: State) -> list[dict]:
    """The splits in force, for the Hosts panel's Undo split: each host, its lanes, its split entries, and what the
    analyst set on each new host, which stops applying when the split is undone."""
    out = []
    for host, info in sorted(state.split_info.items()):
        lanes = sorted(set(state.splits.get(host, {}).values()))
        out.append({"host": host, "lanes": lanes, "entries": info,
                    "edits": {lane: edits for lane in lanes if (edits := _edits_left(state, lane))}})
    return out


def kept_list(state: State, identity, found: dict[str, list[Machine]]) -> list[dict]:
    """The hosts kept as one host whose logs still record several computers, so the Hosts panel can still offer the
    split: each host, its computers, and the Keep entry."""
    return [{"host": host, "computers": len(found.get(host, [])), "entry": info}
            for host, info in sorted(state.kept_info.items())
            if host in identity.hosts and host not in identity.mixed and len(found.get(host, [])) >= 2]


def kept_keys(found: dict[str, list[Machine]], host: str) -> list[str]:
    """The computer names a Keep as one host records: every name on the host's lane now."""
    return sorted({k for m in found.get(host, []) for k in m.keys})


def intake_folders(case, paths) -> set[str]:
    """The host folders intake found, from the evidence paths it listed."""
    return {h for h in (case.host_of(p) for p in paths) if h}
