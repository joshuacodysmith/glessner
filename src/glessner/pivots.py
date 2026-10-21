"""The Event page's next pivots: for one event, the pivots worth taking in the order its kind of event
calls for, each with its reason, its value, whether it is broad, and its caveat, and then each row's count and its top
sources, which the page asks for once it has drawn.

The guidance comes from pivot_table.json, a table of 54 kinds of event. The page guides and never decides: every reason
is in that fixed table, which cites its sources, and the analyst picks the pivot. A pivot this build doesn't have drops out
of the ranking, and the rows below it move up.

A row's count is one query with the click's own conditions (queries.match_for and count_matches), over the whole case and
not within the View, so it equals the total the click lists. It reads one column, or one narrow
condition per source, so each count stays near 300 ms at 10 million events.
"""

from __future__ import annotations

import functools
import ipaddress
import json
import re
from pathlib import Path, PureWindowsPath

import duckdb

from .analysis import LEVEL_RANK
from .hashes import strongest
from .parsers import ARTIFACT_NAMES
from .pivot_names import extra_of, file_name_of, flow_id, rule_of, service_names, task_names
from .queries import (
    BASE_WHERE,
    RELATED_LIMIT,
    SYSTEM_SESSIONS,
    TIME_FROM,
    UNREVIEWED_COND,
    QueryError,
    count_matches,
    match_and_event,
    source_parts,
)
from .search import SearchError, search_sql
from .search import parse as parse_search

TABLE_FILE = Path(__file__).with_name("pivot_table.json")
# The pivots this build has. A pivot it lacks drops out, with the sentences that send the analyst to it.
BUILT = frozenset({"session", "account", "source_ip", "connection", "file", "file_name", "addr", "window", "search",
                   "service_name", "workstation", "flow", "task_name", "rule", "hash"})
# The pivots the page offers on every event: a kind's ranked rows take the ones it ranks, and the rest follow its rows as
# plain links. Same hash follows as one too, but only on an event that has a hash, so no other event's not-offered line
# grows.
OFFERED = ("session", "account", "source_ip", "connection", "file", "addr", "window", "hash")
BREAKDOWN_SHOWN = 6   # sources a row names; the rest are counted as "more"
WINDOW_SECONDS = (1, 3600)
# The kinds whose window a published source gives a size for. The others' sizes are inferred from ATT&CK's
# examples (Prefetch is written about 10 s after launch, and SRUM rows are hourly totals); the page says so.
SOURCED_WINDOWS = frozenset({"prefetch", "srum"})
SERVICE_ACCOUNTS = {"SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "ANONYMOUS LOGON"}
SERVICE_ACCOUNT_NAME = re.compile(r"^(?:DWM|UMFD)-\d+$", re.IGNORECASE)
SYSTEM_BINARIES = {"svchost.exe", "cmd.exe", "powershell.exe", "rundll32.exe", "conhost.exe", "services.exe", "winlogon.exe",
                   "lsass.exe", "explorer.exe", "wmiprvse.exe", "dllhost.exe", "taskhostw.exe"}
# A row's broad_rules that apply to the row without a test of the value: the table names them on the rows they hold for
ALWAYS_BROAD = {"logon_process", "weak_time"}
WEAK_ONLY_WHEN = {"run_key": {"artifact": "registry"}}   # the weak time of a Run key is RECmd's, not Sysmon's
USUAL = {"session": "no logon ID", "account": "no account", "source_ip": "no source IP", "connection": "no source port",
         "addr": "no source or destination IP", "window": "no time recorded", "service_name": "no service name",
         "workstation": "no source workstation", "flow": "no flow ID", "task_name": "no task name",
         "rule": "no rule or signature", "file_name": "no file name", "hash": "no file hash"}
FILE_NAME_WARNING = "Joins every file of this name, in any folder and on any host, whatever the file is."
NAME_ONLY = "(name only, any domain)"
# The providers whose events a Security or System source is expected to hold; another provider's code is named with it
USUAL_PROVIDERS = {"microsoft-windows-security-auditing", "service control manager", "microsoft-windows-eventlog",
                   "microsoft-windows-kernel-general", "microsoft-windows-kernel-power", "microsoft-windows-winlogon",
                   "microsoft-windows-security-mitigations", "microsoft-windows-groupolicy", "user32", "eventlog"}
SHORT_CHANNEL = re.compile(r"^(?:Microsoft-Windows-)?(.*?)(?:/Operational|/Admin)?$")


@functools.cache
def table() -> dict:
    return json.loads(TABLE_FILE.read_text(encoding="utf-8"))


@functools.cache
def window_kinds() -> frozenset[str]:
    """The kinds of event whose window row has a size of its own, which the analyst can edit for the case."""
    return frozenset(k["kind"] for k in table()["kinds"] for p in k["pivots"]
                     if p["pivot"] == "window" and isinstance(p.get("args", {}).get("seconds"), int))


def shown(text: str) -> str:
    """A table's text as the page shows it: without the sentences that send the analyst to a pivot this build doesn't
    have."""
    unbuilt = [p["label"] for name, p in table()["pivots"].items() if name not in BUILT]
    kept = [s for s in re.split(r"(?<=\.)\s+", text) if not any(label in s for label in unbuilt)]
    return " ".join(kept)


# ---------- the language of "match" and "when" ----------

def _text(ev: dict, column: str) -> str:
    value = ev.get(column)
    return "" if value is None else str(value).lower()


def fits(spec: dict, ev: dict) -> bool:
    """Whether an event meets a match or when: each key an events column compared without letter case, a string equal to
    it, a list any of its values, {contains} and {starts_with} part of it, any_of one of its alternatives, and
    has_hayabusa_hit an event with Hayabusa hits."""
    for key, want in spec.items():
        if key == "any_of":
            ok = any(fits(alt, ev) for alt in want)
        elif key == "has_hayabusa_hit":
            ok = bool(ev.get("hits")) == want
        elif isinstance(want, dict):
            have = _text(ev, key)
            ok = (str(want["contains"]).lower() in have if "contains" in want
                  else have.startswith(str(want["starts_with"]).lower()))
        elif isinstance(want, list):
            ok = _text(ev, key) in {str(w).lower() for w in want}
        else:
            ok = _text(ev, key) == str(want).lower()
        if not ok:
            return False
    return True


def kind_of(ev: dict) -> tuple[dict, dict | None]:
    """The kind of event this is, the first kind whose match fits (the last, "default", fits every event), and the
    overlay kind whose rows follow, if the event has Hayabusa hits."""
    kinds = table()["kinds"]
    kind = next(k for k in kinds if not k.get("overlay") and fits(k["match"], ev))
    overlay = next((k for k in kinds if k.get("overlay") and fits(k["match"], ev)), None)
    return kind, overlay


# ---------- what an event can take ----------

def _file_missing(ev: dict) -> str:
    """Why Same file can't be taken, as the page's hover text says: no path, a name with no folder,
    which Same file doesn't match, or a path with no key, such as an imported event's."""
    path = ev.get("file_path") or ""
    if not path:
        return "This event has no file path"
    if re.search(r"[\\/]", path):
        return f"Its file, {path}, can't be matched on its path"
    return f"Its file, {path}, has no full path to match on"


def _addresses(ev: dict, end: str, identity) -> list[str]:
    """The addresses a row on the pivot at either end takes, for its `end`: the source's; the end that isn't one of the
    seed host's addresses (remote); the end that is a collected host's (internal); an end that is not a collected host's
    (external, the first in source, destination order); or each distinct one."""
    source, dest = ev.get("source_ip") or "", ev.get("dest_ip") or ""
    ends = [a for a in dict.fromkeys((source, dest)) if a]
    own = set(getattr(identity.hosts.get(ev.get("host", "")), "ips", []) or [])
    if end == "source_ip":
        return [source] if source else []
    if end == "remote":
        away = [a for a in ends if a not in own and not identity.resolve_ip(a)] or [a for a in ends if a not in own]
        return away[:1]
    if end == "internal":
        return [a for a in ends if identity.resolve_ip(a)][:1]
    if end == "external":
        return [a for a in ends if not identity.resolve_ip(a)][:1]
    return ends


def _value_of(pivot: str, ev: dict) -> tuple[str, str]:
    """What the event holds for a pivot: its value as the row shows it, and the field that decides whether the event can
    take it ('' when it can)."""
    if pivot == "session":
        logon = ev.get("logon_id") or ""
        return logon, "" if logon and logon.lower() != "0x0" else USUAL[pivot]
    if pivot == "account":
        name, domain = ev.get("user_name") or "", ev.get("user_domain") or ""
        return (f"{domain}\\{name}" if domain else name), "" if name else USUAL[pivot]
    if pivot == "source_ip":
        return ev.get("source_ip") or "", "" if ev.get("source_ip") else USUAL[pivot]
    if pivot == "connection":
        ip, port = ev.get("source_ip") or "", ev.get("source_port") or ""
        return (f"{ip}:{port}" if ip and port else ""), "" if ip and port else USUAL[pivot]
    if pivot == "file":
        # The file's key is its path's, or the process's when the event names no file (an event log's)
        return ev.get("file_path") or ev.get("process_executable") or "", "" if ev.get("file_key") else _file_missing(ev)
    if pivot == "window":
        return "", "" if ev.get("adjusted_ts_us") is not None else USUAL[pivot]
    if pivot == "workstation":
        return ev.get("source_workstation") or "", "" if ev.get("source_workstation") else USUAL[pivot]
    if pivot == "service_name":
        name = (service_names(ev) or [""])[0]
        return name, "" if name else USUAL[pivot]
    if pivot == "task_name":
        name = (task_names(ev) or [""])[0]
        return name, "" if name else USUAL[pivot]
    if pivot == "flow":
        ident = flow_id(ev)[1]
        return ident, "" if ident else USUAL[pivot]
    if pivot == "file_name":
        name = file_name_of(ev)
        return name, "" if name else USUAL[pivot]
    if pivot == "rule":
        words = rule_of(ev, [h["title"] for h in sorted(ev.get("hits") or [], key=_severity)])[2]
        return words, "" if words else USUAL[pivot]
    if pivot == "hash":   # the strongest, by its length, such as "SHA-256 9f86d081...e7a3"; the others in the row's note
        shown_hash = strongest(ev.get("hashes") or "")[0]
        return shown_hash, "" if shown_hash else USUAL[pivot]
    return "", ""


def _other_hashes(ev: dict) -> str:
    """Same hash's note: the event's other hashes, in full, which the pivot matches too."""
    others = strongest(ev.get("hashes") or "")[1]
    return f"Also matches its {_listed_words(others)}." if others else ""


def _listed_words(items: list[str]) -> str:
    return items[0] if len(items) == 1 else f"{', '.join(items[:-1])} and {items[-1]}"


def _severity(hit: dict) -> tuple[int, str]:
    """Hits most severe first, as queries._branches orders an event's hits for its rule."""
    return -LEVEL_RANK.get(hit["level"], 0), hit["title"]


def _term(template: str, ev: dict, extra: dict) -> tuple[str, str]:
    """A search row's term: the template with {column} and {data.Field} filled from the event, quoted where the value needs
    it. (term, why not): a field the event lacks, or a value that holds a quote, which search can't take, gives no term."""
    problem = ""

    def fill(m) -> str:
        nonlocal problem
        name = m.group(1)
        value = str(extra.get(name[5:], "")) if name.startswith("data.") else str(ev.get(name) or "")
        if not value or value == "-":
            problem = problem or f"This event has no {name.removeprefix('data.')}"
        elif '"' in value:
            problem = problem or f"{name.removeprefix('data.')} holds a quote, which a search can't take"
        return f'"{value}"' if re.search(r"\s", value) or value.startswith("-") else value
    term = re.sub(r"\{([\w.]+)\}", fill, template)
    return ("" if problem else term), problem


# ---------- the broad flags ----------

def address_kind(ip: str) -> str:
    """'loopback' or 'link_local' for an address that joins every host's own traffic, else ''."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ""
    if addr.is_loopback or addr.is_unspecified:
        return "loopback"
    return "link_local" if addr.is_link_local else ""


def broad_texts(names: list[str], row: dict, ev: dict, identity, kind: str, override: str | None) -> list[str]:
    """The reasons a row is broad before its count is known: one of the table's broad rules fits its value, such as a
    service account or a system binary. A count above the list's limit adds its own (over_limit), which the page writes
    when the count arrives."""
    rules = table()["broad_rules"]
    out = []
    for name in names:
        rule = rules[name]
        pivot, value = row["pivot"], row["value"]
        if name in ALWAYS_BROAD:
            hit = fits(WEAK_ONLY_WHEN.get(kind, {}), ev) if name == "weak_time" else True
        elif name == "system_session":
            hit = (ev.get("logon_id") or "").lower() in SYSTEM_SESSIONS if pivot == "session" else False
        elif name in ("service_account", "machine_account"):
            who = ev.get("user_name") or ""
            service = who.upper() in SERVICE_ACCOUNTS or bool(SERVICE_ACCOUNT_NAME.match(who))
            hit = bool(who) and (who.endswith("$") if name == "machine_account" else service)
        elif name in ("loopback", "link_local"):
            hit = pivot == "addr" and address_kind(value) == name
        elif name == "own_address":
            hit = pivot == "addr" and not address_kind(value) and bool(identity.resolve_ip(value))
        elif name == "system_binary":
            # Same hash is tested on the event's own file name, as Same file name tests it
            name_of = file_name_of(ev) if pivot == "hash" else PureWindowsPath(value.replace("/", "\\")).name
            hit = name_of.lower() in SYSTEM_BINARIES if pivot in ("file", "file_name", "hash") else False
        else:
            hit = False
        if hit:
            host = identity.resolve_ip(value) if name == "own_address" else ""
            out.append(shown(override or rule["text"].replace("{host}", host or "")))
    return out


# ---------- the rows ----------

def _window(kind: dict, spec: dict, windows: dict, case_seconds: int) -> dict:
    """A window row's size: the analyst's edit for this kind of event, else the table's, else the case's. The case's own
    setting is the size for a kind that has none, and the default for Find related."""
    wanted = spec.get("args", {}).get("seconds", "case")
    default = case_seconds if wanted == "case" else int(wanted)
    edit = windows.get(kind["kind"]) if wanted != "case" else None
    seconds = edit if isinstance(edit, int) and WINDOW_SECONDS[0] <= edit <= WINDOW_SECONDS[1] else default
    basis = "case" if wanted == "case" else "source" if kind["kind"] in SOURCED_WINDOWS else "inference"
    return {"seconds": seconds, "default": default, "edited": seconds != default, "basis": basis, "kind": kind["kind"]}


def _plain_window(windows: dict, kind: dict, case_seconds: int) -> int:
    spec = next((p for p in kind["pivots"] if p["pivot"] == "window"), None)
    return _window(kind, spec, windows, case_seconds)["seconds"] if spec else case_seconds


def _sources(ids: list[str]) -> str:
    sources = table()["sources"]
    return "; ".join(sources[i]["title"] for i in ids if i in sources and "title" in sources[i])


def guidance(ev: dict, identity, windows: dict | None = None, case_seconds: int = 60) -> dict:
    """The Event page's next pivots for one event (queries.event_details' dict, with its extra data): its kind, the ranked
    rows, the pivots it can't take with their reasons, and the pivots the page offers that the kind doesn't rank, as plain
    links. `windows` is the analyst's edited time window per kind of event."""
    windows = windows or {}
    t = table()
    kind, overlay = kind_of(ev)
    extra = extra_of(ev)
    declined: dict[str, str] = {}
    for entry in [*t["not_offered_always"], *kind["not_offered"]]:
        if fits(entry.get("when", {}), ev):
            declined.setdefault(entry["pivot"], shown(entry["reason"]))
    specs = sorted(kind["pivots"], key=lambda p: p["rank"])
    if overlay:
        ranked = {p["pivot"] for p in specs}
        specs += [p for p in sorted(overlay["pivots"], key=lambda p: p["rank"]) if p["pivot"] not in ranked]
    rows, taken, unavailable = [], set(), {}
    for spec in specs:
        pivot = spec["pivot"]
        if pivot not in BUILT or not fits(spec.get("when", {}), ev):
            continue
        if pivot in declined:   # a ranked pivot the kind declines for this event says why on the not-offered line
            unavailable.setdefault(pivot, declined[pivot])
            continue
        for row in _rows_of(spec, pivot, kind, ev, extra, identity, windows, case_seconds, unavailable):
            rows.append(row)
            taken.add(pivot)
    for n, row in enumerate(rows, 1):
        row["n"] = n
    refused, plain = {}, []
    for pivot in OFFERED:
        if pivot in taken and pivot != "addr":
            continue
        if pivot in declined:
            refused[pivot] = declined[pivot]
            continue
        if pivot == "window":
            if ev.get("adjusted_ts_us") is None:
                refused[pivot] = f"This event has {USUAL['window']}"
            else:
                plain.append({"pivot": pivot, "label": t["pivots"][pivot]["label"],
                              "seconds": _plain_window(windows, kind, case_seconds)})
            continue
        if pivot == "addr":
            # An address a ranked row took is not offered again; the event's other end follows as a plain link
            ranked = {r["ip"] for r in rows if r["pivot"] == "addr"}
            ends = [a for a in _addresses(ev, "each", identity) if a not in ranked]
            plain += [{"pivot": pivot, "label": t["pivots"][pivot]["label"], "value": a} for a in ends]
            if not ends and not ranked:
                refused[pivot] = f"This event has {USUAL[pivot]}"
            continue
        value, why = _value_of(pivot, ev)
        if why and pivot == "hash":   # most events hold no hash, and their line doesn't say so
            continue
        if why:
            refused[pivot] = why if pivot == "file" else f"This event has {why}"
        else:
            name_only = pivot == "account" and not ev.get("user_domain")
            if name_only:
                value = f"{value} {NAME_ONLY}"
            plain.append({"pivot": pivot, "label": t["pivots"][pivot]["label"], "value": value,
                          **({"seconds": case_seconds} if pivot == "connection" else {}),
                          **({"name_only": True} if name_only else {})})
    for pivot, why in unavailable.items():   # ranked pivots the event holds nothing for, after the offered ones
        if pivot not in refused and pivot not in taken and not any(p["pivot"] == pivot for p in plain):
            refused[pivot] = why
    not_offered = [{"pivot": p, "label": t["pivots"][p]["label"], "reason": r} for p, r in refused.items()]
    return {"kind": kind["kind"], "title": kind["title"], "group": kind["group"], "rows": rows, "not_offered": not_offered,
            "plain": plain, "limit": RELATED_LIMIT, "over_limit_text": shown(t["broad_rules"]["over_limit"]["text"]),
            "over_limit_window_text": shown(t["broad_rules"]["over_limit"]["window_text"])}


WORKLIST_ROWS = 3   # the pivots To investigate counts beside each marked event
WORKLIST_KEYS = ("n", "pivot", "label", "value", "reason", "ip", "end", "seconds", "name", "key", "broad")


def worklist_rows(ev: dict, identity, windows: dict | None = None, case_seconds: int = 60) -> list[dict]:
    """The pivots To investigate counts beside one marked event: the first WORKLIST_ROWS countable rows of the
    event's ranking, as the Event page ranks them, each with what the page needs to count it as unreviewed events and to
    open its list. A search row is left out: a search can't be kept to unreviewed events, since `mark:` is the View's and
    not search's. Same logon session on one of Windows' own sessions is left out too: To investigate leaves those
    sessions out of its counts, and the Event page's row flags them broad instead."""
    rows = []
    for row in guidance(ev, identity, windows, case_seconds)["rows"]:
        if not row["count"] or row["pivot"] == "search":
            continue
        if row["pivot"] == "session" and (ev.get("logon_id") or "").lower() in SYSTEM_SESSIONS:
            continue
        rows.append({k: row[k] for k in WORKLIST_KEYS if k in row})
        if len(rows) == WORKLIST_ROWS:
            break
    return rows


def _rows_of(spec: dict, pivot: str, kind: dict, ev: dict, extra: dict, identity, windows: dict, case_seconds: int,
             unavailable: dict) -> list[dict]:
    """The rows one table entry gives the event: one, or one per address for a pivot at either end, or none when the event
    holds nothing for it (the reason goes to `unavailable`)."""
    t = table()
    args = spec.get("args", {})
    base = {"pivot": pivot, "label": spec.get("label") or t["pivots"][pivot]["label"], "reason": shown(spec["reason"]),
            "sources": _sources(spec.get("sources", [])), "count": spec.get("count", True),
            "breakdown": spec.get("breakdown", "over_limit"), "caveat_check": None}
    if pivot == "window":
        if ev.get("adjusted_ts_us") is None:
            unavailable[pivot] = f"This event has {USUAL[pivot]}"
            return []
        win = _window(kind, spec, windows, case_seconds)
        return [{**base, "value": "", "window": win, "seconds": win["seconds"], "key": "window",
                 "broad": broad_texts(spec.get("broad", []), {"pivot": pivot, "value": ""}, ev, identity, kind["kind"],
                                      spec.get("broad_text")),
                 "caveat": _caveat(spec, ev), "empty": _empty(pivot, ev)}]
    if pivot == "search":
        if "term" not in args:   # a hint for the analyst to type from, with no term to run
            return [{**base, "value": "", "hint": args["term_hint"], "count": False, "key": "search:hint", "broad": [],
                     "caveat": None, "empty": [], "term": ""}]
        term, why = _term(args["term"], ev, extra)
        if why:
            unavailable[pivot] = f"{base['label']}: {why[0].lower()}{why[1:]}"
            return []
        counted = base["count"] and _field_terms(term)   # a free-text word isn't counted
        return [{**base, "value": term, "term": term, "count": counted, "key": f"search:{term}", "broad": [],
                 "caveat": None, "empty": _empty(pivot, ev)}]
    if pivot == "addr":
        values = _addresses(ev, args.get("end", "each"), identity)
        if not values:
            ends = _addresses(ev, "each", identity)
            # setdefault: an outside row with no value never replaces the reason the internal row gave
            unavailable.setdefault(pivot, "Neither end of this event is a collected host's address"
                                   if ends and args.get("end") == "internal"
                                   else "Both ends of this event are collected hosts' addresses"
                                   if ends and args.get("end") == "external" else f"This event has {USUAL['addr']}")
            return []
    else:
        # A file name the table fixes for the kind (wevtutil.exe on a log clear) needs nothing from the event
        value, why = (args["value"], "") if pivot == "file_name" and "value" in args else _value_of(pivot, ev)
        if why:
            unavailable[pivot] = why if pivot == "file" else f"This event has {why}"
            return []
        values = [value]
    out = []
    for value in values:
        row = {**base, "value": value, "key": f"{pivot}:{value}" if pivot == "addr" else pivot,
               "broad": broad_texts(spec.get("broad", []), {"pivot": pivot, "value": value}, ev, identity, kind["kind"],
                                    spec.get("broad_text")),
               "caveat": _caveat(spec, ev), "caveat_check": _caveat_check(spec, ev), "empty": _empty(pivot, ev)}
        if pivot == "addr":
            row["ip"] = value
            row["end"] = args.get("end", "each")
            if row["end"] == "internal":
                row["end_host"] = identity.resolve_ip(value) or ""
        if pivot == "account" and not ev.get("user_domain"):
            row.update(value=f"{value} {NAME_ONLY}", name_only=True)
        if pivot == "connection":
            row["seconds"] = case_seconds   # the case's window bounds it; the case-wide list is one click away
        if pivot == "hash" and _other_hashes(ev):
            row["warn"] = _other_hashes(ev)
        if pivot == "file_name":
            row["warn"] = FILE_NAME_WARNING
            if "value" in args:   # the label already names the file, and the click and its count carry the name
                row.update(name=value, value="")
        out.append(row)
    return out


def _field_terms(term: str) -> bool:
    """Whether every term of a search is a field's: the rows search counts."""
    try:
        return all(t.field for t in parse_search(term))
    except SearchError:
        return False


def _caveat(spec: dict, ev: dict) -> str | None:
    """The row's caveat when its `when` fits the event."""
    caveat = spec.get("caveat")
    return shown(caveat["text"]) if caveat and fits(caveat.get("when", {}), ev) else None


def _caveat_check(spec: dict, ev: dict) -> dict | None:
    """{"check": "short_path"} when the row's caveat has that check and its `when` fits the event, else None. The count
    then says what the 8.3 path stands for, and the caveat stays where the MFT cannot say."""
    caveat = spec.get("caveat")
    if caveat and caveat.get("check") == "short_path" and fits(caveat.get("when", {}), ev):
        return {"check": "short_path"}
    return None


def _empty(pivot: str, ev: dict) -> list[str]:
    """What the page says when a pivot finds only the event itself: the table's sentences for the pivot whose `when` fits
    this event, each as shown() gives it."""
    out = []
    for entry in table()["empty_reasons"].get(pivot, []):
        if not fits(entry.get("when", {}), ev):
            continue
        text = shown(entry["text"])
        if text:
            out.append(text)
    return out


# ---------- counts and sources ----------

def source_label(parts: list[str], provider: str = "") -> str:
    """A source of a window's breakdown in words: an event log's code, with its type for a logon and its log's short name
    outside Security and System ("4624 type 3", "Sysmon 3"); a capture's record type; another evidence type's name. A
    Security or System code from an unusual provider leads with the provider ("Schannel 36874")."""
    artifact = parts[0]
    if artifact == "evtx":
        channel, code = parts[1], parts[2]
        words = f"{code} type {parts[3]}" if len(parts) > 3 and parts[3] else code
        short = SHORT_CHANNEL.match(channel).group(1) if channel not in ("Security", "System") else ""
        if not short and provider and provider.lower() not in USUAL_PROVIDERS:
            short = provider.removeprefix("Microsoft-Windows-")
        return f"{short} {words}".strip()
    name = ARTIFACT_NAMES.get(artifact, artifact)
    return f"{name} {parts[1]}" if len(parts) > 1 and parts[1] else name


def sources_of(con: duckdb.DuckDBPyConnection, branches: list[tuple[str, list]], shown_n: int = BREAKDOWN_SHOWN) -> dict:
    """How the events a pivot matches divide among sources, in one query across its branches, which never match an event
    twice: the largest `shown_n`, each with the pivot's list narrowed to it, and the rest counted together."""
    selects = [f"SELECT e.artifact AS artifact, e.log_channel AS channel, e.event_code AS code, e.logon_type AS ltype, "
               f"e.event_provider AS provider "
               f"FROM {TIME_FROM} WHERE {BASE_WHERE} AND ({where})" for where, _ in branches]
    counts: dict[tuple, int] = {}
    providers: dict[tuple, tuple[int, str]] = {}   # a source's largest provider
    for artifact, channel, code, ltype, provider, n in con.execute(
            "SELECT artifact, channel, code, ltype, provider, count(*) FROM (" + " UNION ALL ".join(selects)
            + ") GROUP BY ALL", [p for _, params in branches for p in params]).fetchall():
        key = tuple(source_parts(artifact, channel, code, ltype))
        counts[key] = counts.get(key, 0) + n
        if artifact == "evtx" and n > providers.get(key, (0, ""))[0]:
            providers[key] = (n, provider or "")
    ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    return {"sources": [{"source": list(k), "label": source_label(list(k), providers.get(k, (0, ""))[1]), "count": n}
                        for k, n in ranked[:shown_n]],
            "more": {"sources": max(len(ranked) - shown_n, 0), "count": sum(n for _, n in ranked[shown_n:])}}


@functools.cache
def fixed_file_names() -> frozenset[str]:
    """The file names the table fixes for a kind of event, in lower case: what a Same file name click may carry as `name`."""
    return frozenset(p["args"]["value"].lower() for k in table()["kinds"] for p in k["pivots"]
                     if p["pivot"] == "file_name" and "value" in p.get("args", {}))


def checked_name(name: str) -> str:
    """`name` as a click carries it: empty for the event's own file name, else one the table fixes, so a request can't
    pivot on an arbitrary name (as the address of Same IP at either end must be one of the event's)."""
    if name and name.lower() not in fixed_file_names():
        raise QueryError(f"name must be empty or one of {sorted(fixed_file_names())}")
    return name


def count_pivot(con: duckdb.DuckDBPyConnection, identity, uid: str, ts: int | None, pivot: str, *, ip: str = "",
                seconds: int = 60, term: str = "", breakdown: bool = False, scope: str = "", check: str = "",
                anchor: tuple[dict, int | None] | None = None, name: str = "", unreviewed: bool = False) -> dict:
    """One row's count: how many events the click would list, and with `breakdown`, its sources. `check` short_path adds
    `resolved`, what the host's MFT says the row's 8.3 path stands for. `anchor` is the event as queries.anchor_of reads
    it, which the server keeps from the Event page's own read. `name` is the fixed file name of a Same file name row.
    `unreviewed` counts only events with no mark, as To investigate's counts do, and the list the count opens asks the
    same. A row that can't be counted raises QueryError."""
    out: dict = {}
    if pivot == "search":
        try:
            terms = parse_search(term)
        except SearchError as exc:
            raise QueryError(str(exc)) from exc
        if not all(t.field for t in terms):
            raise QueryError("a search with a free-text word isn't counted")
        where = search_sql(terms)
        if unreviewed:
            where = f"({where}) AND {UNREVIEWED_COND}"
        out["count"] = con.execute(f"SELECT count(*) FROM events e WHERE {BASE_WHERE} AND ({where})").fetchone()[0]
        if breakdown:
            out.update(sources_of(con, [(where, [])]))
        return out
    match, _, _ = match_and_event(con, uid, pivot, seconds, ip, identity, ts, None, scope, anchor, checked_name(name),
                                  unreviewed=unreviewed)
    if match.note:
        out.update(count=0, note=match.note)
    else:
        out["count"] = count_matches(con, match)
        if breakdown and out["count"]:
            out.update(sources_of(con, match.branches))
    if check == "short_path":   # the 8.3 path's long form by the host's MFT, which the page shows in place of the caveat
        out["resolved"] = match.more.get("short_note", "")
    return out
