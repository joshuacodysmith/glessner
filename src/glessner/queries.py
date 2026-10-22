"""Read queries behind the timeline: lanes, density, events, links, details, and related events.

Lanes come from the analyst's group-by keys. Hayabusa rows never get their own lane: they mark
the EvtxECmd event they matched (the hits table), so each event appears once.

Times are clock-adjusted: an analyst-set host offset (hosts.offset_us) is added to the stored
time at query time. Stored times never change. Window filters first bound the raw ts_us, widened
by the largest offset, so DuckDB can still skip row groups by time.
"""

from __future__ import annotations

import duckdb

from . import attack
from .analysis import LEVEL_RANK, hit_join, level_rank
from .clock import KIND_WORDS
from .events import BIGINT_COLUMNS, id_table, sql_literal
from .identity import Identity
from .parsers.autoruns import BUILT as AUTORUNS_BUILT
from .pivot_names import (
    file_name_branches,
    file_name_of,
    flow_branches,
    flow_id,
    rule_branches,
    rule_counts,
    rule_of,
    service_aliases,
    service_branches,
    service_names,
    task_branches,
    task_names,
)
from .relations import LOGON_WHERE, is_local

MARK_EXPR = "COALESCE(m.label, 'Suggested: ' || sg.value, 'Unreviewed')"   # analyst mark, else a pending suggestion
TS = "(e.ts_us + COALESCE(h.offset_us, 0))"                                 # clock-adjusted time
ACCOUNT = ("CASE WHEN e.user_name = '' THEN '(no account)' WHEN e.user_domain = '' THEN e.user_name "
           "ELSE e.user_domain || '\\' || e.user_name END")                  # DOMAIN\name, as the event wrote it
GROUP_KEYS = {
    "mark": MARK_EXPR,
    "role": "COALESCE(h.role, 'Unassigned')",
    "host": "e.host",
    # Windows ignores the letter case of account names, as Same account does, so EXAMPLE\Administrator in any spelling
    # is one lane, labeled by account_names.
    "user": f"lower({ACCOUNT})",
    "tool": "e.tool",
    "artifact": "e.artifact",
    "tactic": "COALESCE(tl.tactic, 'Untagged')",   # an event with two tactics sits in both lanes
}
# The View filter's and search's fields (filters.py, search.py), each a column or a GROUP_KEYS expression.
FIELDS = {"host": "e.host", "tool": "e.tool", "artifact": "e.artifact", "channel": "e.log_channel",
          "file": "e.source_file", "run": "e.run_id", "role": GROUP_KEYS["role"], "mark": GROUP_KEYS["mark"],
          "user": ACCOUNT, "ip": "e.source_ip", "port": "e.source_port",
          "dest_ip": "e.dest_ip", "dest_port": "e.dest_port",
          # the Event page's fields, each one a View value
          "code": "e.event_code", "provider": "e.event_provider", "computer": "e.host_name_recorded",
          "logon_type": "e.logon_type", "logon_id": "e.logon_id", "workstation": "e.source_workstation",
          "process": "e.process_executable", "command_line": "e.process_command_line", "path": "e.file_path",
          "registry_key": "e.registry_path", "registry_value": "e.registry_value",
          "parent": "e.process_parent_executable", "parent_command_line": "e.process_parent_command_line",
          "registry_data": "e.registry_data"}
# An address at either end of a connection: older Sysmon records the local side as the source, so an inbound
# connection's remote address is its destination. The View and search compare it without letter case, as every field;
# the parsers store each address in normalize_ip's form.
EITHER_END = {"addr": ("e.source_ip", "e.dest_ip")}
PRESETS = [["mark", "role", "host"], ["host", "mark"], ["role", "host", "user"], ["user", "host"],
           ["host", "artifact"], ["mark", "host", "user"], ["tactic", "host"]]
# Joined only when the lanes group by tactic, because it repeats an event once per tactic.
TACTIC_JOIN = (" LEFT JOIN (SELECT event_uid, label AS tactic FROM tags WHERE kind = 'tactic') tl "
               "ON tl.event_uid = e.event_uid")
BASE_FROM = ("events e LEFT JOIN marks m ON m.event_uid = e.event_uid LEFT JOIN hosts h ON h.host = e.host "
             "LEFT JOIN hits x ON x.event_uid = e.event_uid LEFT JOIN suggested sg ON sg.event_uid = e.event_uid")
TIME_FROM = "events e LEFT JOIN hosts h ON h.host = e.host"   # enough for counts and time ranges
BASE_WHERE = "e.tool <> 'hayabusa' AND e.ts_us IS NOT NULL"
LINK_LIMIT = 300
LISTED_MESSAGE = 160   # the start of the message each listed event shows
RELATED_LIMIT = 500
# Windows' own logon sessions: LocalSystem's (0x3e7), the service accounts' (0x3e4, 0x3e5), and the anonymous logon's
# (0x3e6). Every service on a host shares one, so "the events in its session" is everything the account does there. The
# Same logon session row says so (pivots.broad_texts), and To investigate and the overview leave them out of their counts.
SYSTEM_SESSIONS = ("0x3e7", "0x3e4", "0x3e5", "0x3e6")
LOOKUPS = 2   # recorded times find_event looks an event up at, at most; past that its ID alone is as fast
WINDOW_DEFAULT_SECONDS = 60
WINDOW_RANGE_SECONDS = (1, 3600)


class QueryError(ValueError):
    """Raised for a request the queries cannot answer, such as an unknown group-by key."""


def system_list() -> str:
    """SYSTEM_SESSIONS as the elements of an SQL list."""
    return ", ".join(f"'{session}'" for session in SYSTEM_SESSIONS)


def session_key(column: str) -> str:
    """SQL for a logon ID as To investigate counts sessions by it: the ID in lower case, or '' for none, which is an empty
    ID, 0x0 (a case built by an earlier version may hold it on a 4688 or 4625), or one of Windows' own sessions."""
    return f"CASE WHEN COALESCE(lower({column}), '') IN ('', '0x0', {system_list()}) THEN '' ELSE lower({column}) END"


def local_address(column: str) -> str:
    """SQL for an address, as the events store it (normalize_ip's form), that joins every host's own traffic: loopback,
    unspecified, or link-local. relations.is_remote decides the same for one address in Python, and a test holds the two
    together."""
    return (f"(starts_with({column}, '127.') OR split_part({column}, '%', 1) IN ('::1', '0.0.0.0', '::') "
            f"OR starts_with({column}, '169.254.') OR regexp_matches({column}, '^fe[89ab][0-9a-f]:'))")


def local_scope(alias: str) -> str:
    """SQL for the host an event's source IP belongs to: its own host for a local address, else '' for an address the
    whole case shares, so counting by it keeps every host's ::1 apart."""
    return f"CASE WHEN {local_address(alias + '.source_ip')} THEN {alias}.host ELSE '' END"


def parse_groupby(text: str) -> list[str]:
    keys = [k.strip() for k in text.split(",") if k.strip()]
    if not 1 <= len(keys) <= 4 or len(set(keys)) != len(keys) or any(k not in GROUP_KEYS for k in keys):
        raise QueryError(f"group-by needs 1 to 4 distinct keys from {sorted(GROUP_KEYS)}")
    return keys


def base_from(keys: list[str]) -> str:
    return BASE_FROM + (TACTIC_JOIN if "tactic" in keys else "")


def _keys_sql(keys: list[str]) -> str:
    return ", ".join(f"{GROUP_KEYS[k]} AS k{i}" for i, k in enumerate(keys))


def raw_bounds(identity: Identity, start: int, end: int) -> list[int]:
    """The recorded times [low, high) an event adjusted into [start, end) can have, widened by the largest offsets."""
    low, high = identity.offset_bounds_us()
    return [start - high, end - low]


def window_where(identity: Identity, start: int, end: int) -> tuple[str, list[int]]:
    """SQL and parameters for 'adjusted time in [start, end)', with a raw-time bound for pruning."""
    return f"e.ts_us >= ? AND e.ts_us < ? AND {TS} >= ? AND {TS} < ?", [*raw_bounds(identity, start, end), start, end]


def case_range(con: duckdb.DuckDBPyConnection) -> tuple[int | None, int | None, int]:
    return con.execute(f"SELECT min({TS}), max({TS}), count(*) FROM {TIME_FROM} WHERE {BASE_WHERE}").fetchone()


def timeline_count(con: duckdb.DuckDBPyConnection) -> int:
    """The events on the timeline, as case_range counts them: not Hayabusa's hit rows, nor events without a time."""
    return con.execute(f"SELECT count(*) FROM events e WHERE {BASE_WHERE}").fetchone()[0]


FIT_TRIM = 0.0005   # Fit case leaves out the earliest and latest 0.05% of events,
FIT_KEEP = 0.1      # then takes back those within a tenth of the trimmed span, so only far-off strays stay out
# Autoruns' PE link times say when an image was built, not anything done on the host, and Windows 10 links its own
# binaries with a hash for a time, from 1902 to 2037. On the Szechuan dataset they would stretch Fit case from 2013 to
# 2020 into 1967 to 2025, so they don't set the window, and stay counted as strays.
FIT_SETS_WINDOW = f"NOT (e.artifact = 'autoruns' AND e.ts_desc = {sql_literal(AUTORUNS_BUILT)})"


def fit_range(con: duckdb.DuckDBPyConnection) -> dict:
    """The window Fit case shows: every event except far-off strays, such as 1980 file times among 2024 activity.
    Strays can matter (a timestomped file, a skewed clock), so they are counted, not hidden: the page names how many
    lie outside and when, and zooming out reaches them. A case of nothing but link times takes its window from them."""
    quantiles = f"SELECT quantile_disc({TS}, {FIT_TRIM}), quantile_disc({TS}, {1 - FIT_TRIM}) FROM {TIME_FROM} WHERE "
    sets = FIT_SETS_WINDOW
    lo, hi = con.execute(f"{quantiles}{BASE_WHERE} AND {sets}").fetchone()
    if lo is None:   # nothing but link times, or no events: then every event sets the window
        sets = "true"
        lo, hi = con.execute(f"{quantiles}{BASE_WHERE}").fetchone()
    if lo is None:
        return {"start": None, "end": None, "before": 0, "after": 0, "first": None, "last": None}
    low, high = lo - int((hi - lo) * FIT_KEEP), hi + int((hi - lo) * FIT_KEEP)
    start, end = con.execute(f"SELECT min({TS}) FILTER (WHERE {TS} >= ? AND {sets}), "
                             f"max({TS}) FILTER (WHERE {TS} <= ? AND {sets}) FROM {TIME_FROM} WHERE {BASE_WHERE}",
                             [low, high]).fetchone()
    # Strays are whatever lies outside the window, link times inside the kept tenth among them.
    row = con.execute(f"SELECT count(*) FILTER (WHERE {TS} < ?), count(*) FILTER (WHERE {TS} > ?), "
                      f"min({TS}), max({TS}) FROM {TIME_FROM} WHERE {BASE_WHERE}", [start, end]).fetchone()
    return dict(zip(("start", "end", "before", "after", "first", "last"), (start, end, *row)))


def lanes(con: duckdb.DuckDBPyConnection, keys: list[str], extra: str = "") -> list[dict]:
    """Lanes and their event counts. `extra` is a view filter's ' AND ...' clause (see filters.py)."""
    cols = ", ".join(f"k{i}" for i in range(len(keys)))
    rows = con.execute(f"SELECT {_keys_sql(keys)}, count(*) FROM {base_from(keys)} WHERE {BASE_WHERE}{extra} "
                       f"GROUP BY ALL ORDER BY {cols}").fetchall()
    return [{"keys": list(r[:-1]), "count": r[-1]} for r in rows]


def account_names(con: duckdb.DuckDBPyConnection) -> dict[str, str]:
    """The label of each user lane whose key, the account's name in lower case, isn't how the events write it: the case's
    most common spelling, the first in order among equals."""
    rows = con.execute(f"""
        SELECT k, first(u ORDER BY n DESC, u) FROM (
            SELECT {GROUP_KEYS['user']} AS k, {ACCOUNT} AS u, count(*) AS n FROM events e WHERE {BASE_WHERE} GROUP BY ALL)
        GROUP BY k""").fetchall()
    return {k: u for k, u in rows if k != u}


def view(con: duckdb.DuckDBPyConnection, identity: Identity, keys: list[str], start: int, end: int,
         buckets: int, limit: int, hide_machine: bool, extra: str = "", faded: str = "false", links: bool = True,
         outside: bool = False) -> dict:
    """Events in the window when there are at most `limit`, otherwise density cells. Plus logon links, unless the page
    hides them. `extra` is a view filter's ' AND ...' clause; a filter may name marks, so it needs BASE_FROM's joins.
    With `outside`, which the page asks for while Fit case's range is in view, how many events the filter shows lie
    before and after the window, and the first and last of them.

    A filter's predicate is most of the cost of each scan, so with one the count comes from the density pass: a pan
    scans the window once zoomed out and twice zoomed in, not four times. Lanes
    by tactic hold an event once per tactic, so their cells can't give the count."""
    in_window, params = window_where(identity, start, end)
    width = max((end - start) // max(buckets, 1), 1)
    nk = len(keys)
    cells = _density(con, keys, start, width, in_window, params, extra) if extra and "tactic" not in keys else None
    n = (sum(c[nk + 1] for c in cells) if cells is not None else con.execute(
        f"SELECT count(*) FROM {BASE_FROM if extra else TIME_FROM} WHERE {BASE_WHERE} AND {in_window}{extra}",
        params).fetchone()[0])
    result: dict = {"count": n, "start": start, "end": end}
    if outside:
        # Counted against the window drawn and the filter, so they add up with the count. Fit case's strays can't stand
        # in: they ignore the filter and the window's margins.
        row = con.execute(
            f"SELECT count(*) FILTER (WHERE {TS} < ?), count(*) FILTER (WHERE {TS} >= ?), min({TS}), max({TS}) "
            f"FROM {BASE_FROM if extra else TIME_FROM} WHERE {BASE_WHERE} AND ({TS} < ? OR {TS} >= ?){extra}",
            [start, end, start, end]).fetchone()
        result["outside"] = dict(zip(("before", "after", "first", "last"), row))
    if n <= limit:
        rows = con.execute(
            f"SELECT e.event_uid, {TS}, {_keys_sql(keys)}, e.event_code, left(e.message, 200), e.tool, "
            f"{MARK_EXPR}, COALESCE(x.max_level, 0), {faded} FROM {base_from(keys)} "
            f"WHERE {BASE_WHERE} AND {in_window}{extra} ORDER BY 2", params).fetchall()
        result["mode"] = "events"
        result["events"] = [{"uid": r[0], "ts": r[1], "keys": list(r[2:2 + nk]), "code": r[2 + nk], "msg": r[3 + nk],
                             "tool": r[4 + nk], "mark": r[5 + nk], "hit": r[6 + nk],
                             **({"faded": True} if r[7 + nk] else {})} for r in rows]
    else:
        result["mode"] = "density"
        result["width"] = width
        result["cells"] = _density(con, keys, start, width, in_window, params, extra) if cells is None else cells
    empty = {"mode": "individual", "items": []}
    result["links"] = view_links(con, identity, keys, start, end, width, hide_machine, extra) if links else empty
    return result


def _density(con: duckdb.DuckDBPyConnection, keys: list[str], start: int, width: int, in_window: str,
             params: list[int], extra: str) -> list[list]:
    """Each lane's event count and highest Hayabusa level per time bucket: its keys, then bucket, count, and level."""
    return [list(r) for r in con.execute(
        f"SELECT {_keys_sql(keys)}, ({TS} - ?) // ? AS b, count(*), max(COALESCE(x.max_level, 0)) "
        f"FROM {base_from(keys)} WHERE {BASE_WHERE} AND {in_window}{extra} GROUP BY ALL",
        [start, width, *params]).fetchall()]


def view_links(con: duckdb.DuckDBPyConnection, identity: Identity, keys: list[str], start: int, end: int, width: int,
               hide_machine: bool, extra: str = "") -> dict:
    """The window's logon links from the table logon_links (relations.py), each with the lane keys of the logon event,
    its target_keys, from the same query. A logon the filter hides loses its arrow. When there are more than LINK_LIMIT,
    links between the same lanes in the same density bucket are one group, which sits at its middle logon's time, so
    its arrow stays on its logons as the analyst zooms in."""
    # A window without a link recorded within its raw bounds is answered from logon_links' own copy of each logon's
    # recorded time, before any event is read: reading the events would make a window without logons take 30 ms at 5.2
    # million events, three times as long.
    if not con.execute(f"SELECT count(*) FROM logon_links WHERE ts_us >= ? AND ts_us < ?"
                       f"{' AND NOT machine' if hide_machine else ''}", raw_bounds(identity, start, end)).fetchone()[0]:
        return {"mode": "individual", "items": []}
    in_window, params = window_where(identity, start, end)
    machine = " AND NOT e.machine" if hide_machine else ""
    one_lane = " QUALIFY row_number() OVER (PARTITION BY e.event_uid ORDER BY tl.tactic) = 1" if "tactic" in keys else ""
    # The logon events are picked first and the lookup tables joined to just those, as event_keys does: joined to every
    # event in the window, a window without logons would take 85 ms at 10.5 million events, against 51 ms
    logons = ("(SELECT e.*, l.source_host, l.target_host, l.outside, l.account, l.machine, l.kind, l.via FROM events e "
              f"JOIN logon_links l ON l.event_uid = e.event_uid WHERE {LOGON_WHERE}) e")
    links = (f"SELECT e.event_uid AS uid, {TS} AS ts, e.source_host AS source, e.target_host AS target, e.outside, "
             f"e.account, e.kind, e.via, [{', '.join(GROUP_KEYS[k] for k in keys)}] AS target_keys "
             f"FROM {base_from(keys).replace('events e', logons, 1)} "
             f"WHERE {BASE_WHERE} AND {in_window}{machine}{extra}{one_lane}")
    # Read once into a table of the connection's own, which the count and then the links or their groups read
    con.execute(f"CREATE OR REPLACE TEMP TABLE window_links AS {links}", params)
    grouped = con.execute("SELECT count(*) FROM window_links").fetchone()[0] > LINK_LIMIT
    cur = con.execute(
        "SELECT source, target, outside, count(*) AS count, list(ts ORDER BY ts)[count(*) // 2 + 1] AS ts, "
        "list_sort(list(DISTINCT kind)) AS kinds, list_sort(list(DISTINCT account))[1:5] AS accounts, "
        "arg_min(target_keys, (ts, uid)) AS target_keys "
        "FROM window_links GROUP BY source, target, outside, (ts - ?) // ? ORDER BY ts, source, target",
        [start, width]) if grouped else con.execute("SELECT * FROM window_links ORDER BY ts, uid")
    names = [d[0] for d in cur.description]
    items = [dict(zip(names, r)) for r in cur.fetchall()]
    con.execute("DROP TABLE window_links")
    return {"mode": "grouped" if grouped else "individual", "items": items}


def find_event(con: duckdb.DuckDBPyConnection, uid: str, identity: Identity | None = None, ts: int | None = None,
               columns: str | None = None) -> tuple[tuple | None, list[str]]:
    """One event by its ID: its own columns, or `columns`, which may read TS, over it and its host's row (TIME_FROM);
    and the columns' names. (None, []) when there's no such event.

    Given `ts`, the clock-adjusted time the page shows the event at, it was recorded at `ts` less one of the case's
    offsets, zero among them. A lookup by a recorded time and the ID reads the time column first and compares IDs only
    for events recorded then, where a lookup by the ID alone reads every event's ID. So when the case
    has at most LOOKUPS offset values, each recorded time is looked up; with more, or when the event has moved since,
    as an offset edit moves it, it's found by its ID. The event is picked from the events table alone and only then
    joined: through the join, DuckDB took twice as long to find it. At 5.2 million events, one recorded time took 13 ms,
    two 21 ms, three 28 ms, and the ID alone 34 to 38 ms, against 80 ms through the join; at 1.2 million, 7, 10, 14,
    and 12 ms."""
    lookups = []
    if identity is not None and ts is not None:
        recorded = sorted({int(ts) - offset for offset in {0, *identity.offsets_us().values()}})
        if len(recorded) <= LOOKUPS:
            lookups.append((" UNION ALL ".join("SELECT * FROM events WHERE ts_us = ? AND event_uid = ?" for _ in recorded),
                            [p for t in recorded for p in (t, uid)]))
    lookups.append(("SELECT * FROM events WHERE event_uid = ?", [uid]))
    for pick, params in lookups:
        sql = pick if columns is None else (f"WITH picked AS MATERIALIZED ({pick}) "
                                            f"SELECT {columns} FROM {TIME_FROM.replace('events e', 'picked e', 1)}")
        cur = con.execute(sql, params)
        if (row := cur.fetchone()) is not None:
            return row, [d[0] for d in cur.description]
    return None, []


def event_details(con: duckdb.DuckDBPyConnection, uid: str, identity: Identity | None = None,
                  ts: int | None = None) -> dict | None:
    """One event's columns, clock offset, Hayabusa hits, mark, and suggestions; `ts` as find_event takes it."""
    row, names = find_event(con, uid, identity, ts)
    if row is None:
        return None
    details = dict(zip(names, row, strict=True))
    offset = con.execute("SELECT COALESCE(offset_us, 0) FROM hosts WHERE host = ?", [details["host"]]).fetchone()
    details["offset_us"] = offset[0] if offset else 0
    details["adjusted_ts_us"] = None if details["ts_us"] is None else details["ts_us"] + details["offset_us"]
    # By the keys analysis.hit_join matches on, from this event's own values rather than a join that reads every event
    details["hits"] = event_hits(con, details)
    mark = con.execute("SELECT label, note, seq FROM marks WHERE event_uid = ?", [uid]).fetchone()
    details["mark"] = {"label": mark[0], "note": mark[1], "seq": mark[2]} if mark else {"label": "Unreviewed"}
    details["suggestions"] = [
        {"value": v, "source": s, "rejected": r} for v, s, r in con.execute(
            "SELECT s.value, s.source, r.event_uid IS NOT NULL FROM suggestions s "
            "LEFT JOIN rejected r ON r.event_uid = s.event_uid AND r.source = s.source "
            "WHERE s.event_uid = ? ORDER BY s.source", [uid]).fetchall()]
    return details


def event_pairs(con: duckdb.DuckDBPyConnection, uids: list[str]) -> dict[str, dict]:
    """Each event's other half in the clock check's agreeing pairs (clock.py): a host event's record in the
    capture, or a capture record's host event. `in_capture` says which the other half is. `gap_seconds` is the host's
    time minus the capture's, both as recorded, and `kind` is in words: an RDP connection, a logon, or a download."""
    if not uids:
        return {}
    wanted = id_table(con, "pair_events", uids)
    rows = con.execute(f"""
        WITH x AS (
            SELECT host_event_uid AS uid, sensor_event_uid AS other, true AS in_capture, kind, gap_us FROM clock_pairs
            WHERE host_event_uid IN (SELECT v FROM {wanted})
            UNION ALL
            SELECT sensor_event_uid, host_event_uid, false, kind, gap_us FROM clock_pairs
            WHERE sensor_event_uid IN (SELECT v FROM {wanted}))
        SELECT x.uid, e.event_uid, e.host, e.ts_us, {TS}, e.message, x.in_capture, x.kind, x.gap_us
        FROM x JOIN events e ON e.event_uid = x.other LEFT JOIN hosts h ON h.host = e.host
        ORDER BY x.uid, e.event_uid""").fetchall()
    pairs: dict[str, dict] = {}
    for uid, other, host, ts, adjusted, message, in_capture, kind, gap in rows:
        pairs.setdefault(uid, {"uid": other, "host": host, "ts_us": ts, "adjusted_ts_us": adjusted, "message": message,
                               "in_capture": in_capture, "kind": KIND_WORDS[kind][0], "gap_seconds": gap / 1_000_000})
    return pairs


def pending_for_source(con: duckdb.DuckDBPyConnection, source: str) -> dict[str, list[str]]:
    """Unmarked, unrejected events a source suggests, grouped by suggested value."""
    out: dict[str, list[str]] = {}
    for uid, value in con.execute(
            "SELECT s.event_uid, s.value FROM suggestions s LEFT JOIN marks m ON m.event_uid = s.event_uid "
            "LEFT JOIN rejected r ON r.event_uid = s.event_uid AND r.source = s.source "
            "WHERE s.source = ? AND m.event_uid IS NULL AND r.event_uid IS NULL", [source]).fetchall():
        out.setdefault(value, []).append(uid)
    return out


# Pending suggestions of one source, grouped for review on the Suggestions page.
# "rule" is the event's most severe Hayabusa hit, or a Suricata or imported fast alert's signature, so the built-in
# sources' suggestions split by the rule behind them.
PENDING_GROUPS = {"rule": "COALESCE(t.title, '(no rule or signature)')", "host": GROUP_KEYS["host"],
                  "account": ACCOUNT, "code": "COALESCE(NULLIF(e.event_code, ''), e.artifact)"}
PENDING_LIMIT = 200   # events listed per group; the counts and group decisions cover them all
LEVEL_NAMES = {rank: name for name, rank in LEVEL_RANK.items()}
_LEVEL = level_rank("hb.rule_level")
# Suricata severity 1 ranks with Hayabusa's high and 2 with medium, the lowest each source suggests, so groups of both
# sort together; a fast alert's priority, the same number, ranks the same. An event comes from EvtxECmd, Suricata, or an
# import, never two of them, so the union in `t` never repeats an event.
_SEVERITY = "CASE a.severity WHEN 1 THEN 4 WHEN 2 THEN 3 WHEN 3 THEN 2 ELSE 1 END"
_PRIORITY = _SEVERITY.replace("a.severity", "f.priority")
_PENDING = f"""
    WITH p AS (
        SELECT s.event_uid, s.value FROM suggestions s
        LEFT JOIN marks m ON m.event_uid = s.event_uid
        LEFT JOIN rejected r ON r.event_uid = s.event_uid AND r.source = s.source
        WHERE s.source = ? AND m.event_uid IS NULL AND r.event_uid IS NULL),
    t AS (
        SELECT e2.event_uid, arg_max(hb.rule_title, {_LEVEL}) AS title, max({_LEVEL}) AS level,
               CAST(NULL AS VARCHAR) AS label
        FROM events hb {hit_join("hb", "e2")}
        WHERE hb.tool = 'hayabusa' AND e2.event_uid IN (SELECT event_uid FROM p)
        GROUP BY e2.event_uid
        UNION ALL
        SELECT a.event_uid, a.signature, {_SEVERITY}, 'severity ' || COALESCE(CAST(a.severity AS VARCHAR), 'unknown')
        FROM suricata_alerts a WHERE a.event_uid IN (SELECT event_uid FROM p)
        UNION ALL
        SELECT f.event_uid, f.signature, {_PRIORITY}, 'priority ' || COALESCE(CAST(f.priority AS VARCHAR), 'unknown')
        FROM fast_alerts f WHERE f.event_uid IN (SELECT event_uid FROM p))
    SELECT e.event_uid, {TS} AS ts, e.host, e.event_code, left(e.message, 200) AS msg, p.value, {{group}} AS g, t.level,
           t.label
    FROM p JOIN events e ON e.event_uid = p.event_uid LEFT JOIN hosts h ON h.host = e.host
    LEFT JOIN t ON t.event_uid = e.event_uid"""


def pending_events(con: duckdb.DuckDBPyConnection, source: str, group_by: str, limit: int = PENDING_LIMIT) -> dict:
    """One source's pending suggestions in groups, each with its count, its first events in time order, and the IDs of
    every event in it (`uids`, in time order): the set the page counted, which a group action then names exactly, so an
    event that becomes pending after the page loaded is never swept in.

    Grouped by rule, a group carries its level, which ranks it, and `level_label`, the words to show: the Hayabusa
    level, a Suricata alert's own "severity 1", or a fast alert's "priority 1"."""
    if group_by not in PENDING_GROUPS:
        raise ValueError(f"group_by must be one of {sorted(PENDING_GROUPS)}")
    rows = con.execute(f"""
        WITH x AS ({_PENDING.format(group=PENDING_GROUPS[group_by])})
        SELECT g, count(*) OVER (PARTITION BY g) AS n, max(level) OVER (PARTITION BY g) AS lvl,
               arg_max(label, level) OVER (PARTITION BY g) AS lbl, event_uid, ts, host, event_code, msg, value
        FROM x QUALIFY row_number() OVER (PARTITION BY g ORDER BY ts, event_uid) <= ?""", [source, limit]).fetchall()
    groups: dict[str, dict] = {}
    rule = group_by == "rule"
    for g, n, lvl, lbl, uid, ts, host, code, msg, value in rows:
        group = groups.setdefault(g, {"key": g, "count": n, "level": LEVEL_NAMES.get(lvl) if rule else None,
                                      "level_label": (lbl or LEVEL_NAMES.get(lvl)) if rule else None, "events": []})
        group["events"].append({"uid": uid, "ts": ts, "host": host, "code": code, "msg": msg, "value": value})
    for g, uids in con.execute(f"""
            WITH x AS ({_PENDING.format(group=PENDING_GROUPS[group_by])})
            SELECT g, list(event_uid ORDER BY ts, event_uid) FROM x GROUP BY g""", [source]).fetchall():
        if g in groups:
            groups[g]["uids"] = uids
    ordered = sorted(groups.values(), key=lambda g: (-LEVEL_RANK.get(g["level"] or "", 0), -g["count"], str(g["key"])))
    return {"source": source, "group_by": group_by, "total": sum(g["count"] for g in ordered), "groups": ordered}


def pending_source_events(con: duckdb.DuckDBPyConnection, source: str, first: int = 3, cap: int | None = None) -> dict:
    """One source's pending suggestions as To investigate's confirm needs them: the events' IDs in time order, and the
    first few events with their time, host, code, and message. With `cap` at most that many are read, and `more` is
    true when the source has more pending than that."""
    limit = f"LIMIT {cap + 1}" if cap is not None else ""
    rows = con.execute(f"""
        WITH x AS ({_PENDING.format(group="''")})
        SELECT event_uid, ts, host, event_code, msg FROM x ORDER BY ts NULLS LAST, event_uid {limit}""", [source]).fetchall()
    kept = rows[:cap]
    return {"uids": [r[0] for r in kept], "more": len(kept) < len(rows),
            "first": [{"uid": r[0], "ts": r[1], "host": r[2], "code": r[3], "msg": r[4]} for r in kept[:first]]}


def pending_group_uids(con: duckdb.DuckDBPyConnection, source: str, group_by: str, key: str) -> list[str]:
    """Every pending event of one group, for a decision on the whole group."""
    if group_by not in PENDING_GROUPS:
        raise ValueError(f"group_by must be one of {sorted(PENDING_GROUPS)}")
    return [u for (u,) in con.execute(
        f"SELECT event_uid FROM ({_PENDING.format(group=PENDING_GROUPS[group_by])}) WHERE g = ?", [source, key]).fetchall()]


# The flagged events: a mark whose event is no longer loaded (analysis.orphan_marks) lists no row, so it isn't counted
FLAGGED_FROM = "marks m JOIN events e ON e.event_uid = m.event_uid WHERE m.label IN ('Malicious', 'Suspicious')"


def flagged_uids(con: duckdb.DuckDBPyConnection) -> list[str]:
    """The IDs of the Malicious and Suspicious events that are loaded."""
    return [uid for (uid,) in con.execute(f"SELECT m.event_uid FROM {FLAGGED_FROM}").fetchall()]


def investigate(con: duckdb.DuckDBPyConnection, offset: int = 0, limit: int | None = None) -> list[dict]:
    """Malicious and suspicious events in time order, for the To investigate worklist: the `limit` events from `offset`
    on (all of them with no limit), each as the page lists it, with its mark and the mark's note, and under `event` its
    own columns as anchor_of reads them, with its Hayabusa hits, so pivots.worklist_rows can rank its pivots as the Event
    page does. The page counts each pivot's unreviewed events itself, after it draws, through the pivot count with
    unreviewed=1.

    One query reads the events asked for, and one more their hits: a read per event took 50 ms each at 11 million
    events. An event without a time comes last: accepting a rule's suggestions can flag one, since rules match them too.
    Ties go by ID, so the list keeps one order.
    """
    window = f"LIMIT {limit} OFFSET {offset}" if limit is not None else f"OFFSET {offset}"
    cur = con.execute(f"""
        SELECT {TS} AS adjusted_ts, COALESCE(h.offset_us, 0) AS offset, m.label, m.note, e.*
        FROM events e JOIN marks m ON m.event_uid = e.event_uid LEFT JOIN hosts h ON h.host = e.host
        WHERE m.label IN ('Malicious', 'Suspicious') ORDER BY adjusted_ts NULLS LAST, e.event_uid {window}""")
    names = [d[0] for d in cur.description]
    rows = cur.fetchall()
    hits: dict[str, list[dict]] = {}
    if rows:
        listed = id_table(con, "investigate_uids", [row[names.index("event_uid")] for row in rows])
        for uid, title, level in con.execute(f"""
                SELECT e.event_uid, hb.rule_title, hb.rule_level FROM events hb {hit_join("hb", "e")}
                WHERE hb.tool = 'hayabusa' AND e.event_uid IN (SELECT v FROM {listed})
                ORDER BY hb.rule_level, hb.rule_title""").fetchall():
            hits.setdefault(uid, []).append({"title": title, "level": level})
    items = []
    for row in rows:
        adjusted, offset, label, note = row[:4]
        ev = {n: ("" if v is None and n not in BIGINT_COLUMNS else v) for n, v in zip(names[4:], row[4:], strict=True)}
        ev.update(offset_us=offset, adjusted_ts_us=adjusted, hits=hits.get(ev["event_uid"], []))
        items.append({"uid": ev["event_uid"], "ts": adjusted, "host": ev["host"], "code": ev["event_code"],
                      "msg": (ev["message"] or "")[:LISTED_MESSAGE], "mark": label, "note": note, "event": ev})
    return items


# Logon IDs compare without case: EvtxECmd writes 0x5C1D2, the event XML 0x5c1d2. 0x0 is no logon session, which a case
# built by an earlier version may still hold on a 4688 or 4625.
RELATED = {
    "session": ("same host and logon ID",
                "e.host = ? AND lower(e.logon_id) = lower(?) AND e.logon_id <> '' AND lower(e.logon_id) <> '0x0'",
                ("host", "logon_id")),
    # The pivot's own account match is wider (_account): see there. This is the strict one, the View's `user:` value.
    "account": ("same account", "lower(e.user_domain) = lower(?) AND lower(e.user_name) = lower(?) AND e.user_name <> ''",
                ("user_domain", "user_name")),
    "source_ip": ("same source IP", "e.source_ip = ? AND e.source_ip <> ''", ("source_ip",)),
    # One network connection: the capture's SMB, DCE/RPC, LDAP, and flow records of a network logon's connection fall
    # within seconds of it on the clock-adjusted time, and so do the logon's own events. A source port is reused, so
    # the match is bounded to N seconds around the event (_connection), the case's window by default; the case-wide
    # list is scope "case". A Kerberos ticket request and the network logon made over it do NOT share the address and
    # port: on Szechuan none of 89 Kerberos events with a port shared it with a 4624 within 5 s. RDP
    # logons (4624 type 10) record no port, so those stay apart.
    "connection": ("same source IP and port", "e.source_ip = ? AND e.source_port = ? AND e.source_port <> ''",
                   ("source_ip", "source_port")),
    "file": ("same file path", "e.file_key = ? AND e.file_key <> ''", ("file_key",)),
    "window": ("same host within the time window", "e.host = ?", ("host",)),
    # One of the event's addresses as source or destination. Older Sysmon
    # records the local side as the source, so on an inbound connection the remote address is the destination: same
    # source IP from that event finds the host's own address, and from the remote side's 4624 never reaches it. The
    # address is one the event has, taken from its own stored form, so a pivot needs no lowering (the View's addr term lowers
    # both sides for a typed one).
    "addr": ("IP at either end", "(e.source_ip = ? OR e.dest_ip = ?)", ("source_ip", "dest_ip")),
    # The client computer an event names, without letter case: search's `workstation:`
    "workstation": ("same source workstation", "lower(e.source_workstation) = lower(?) AND e.source_workstation <> ''",
                    ("source_workstation",)),
    # Matched by name or flow ID or rule in the events' own data, one narrow condition per source (pivot_names.py)
    "service_name": ("same service name", "", ()),
    "task_name": ("same task name", "", ()),
    "flow": ("same flow", "", ()),
    "rule": ("same rule or signature", "", ()),
    # The file's name alone, in any folder and without letter case, bare names such as SRUM's included
    "file_name": ("same file name", "", ()),
    # Any of the event's file hashes, in the hash list case format 3 adds (_hash_match)
    "hash": ("same hash", "", ()),
}
CONNECTION_WHAT = {"source_ip": "address", "source_port": "port"}
# The sources a window's breakdown names and a window can be narrowed to: the evidence type, and for the artifacts that
# hold many kinds of record, their channel, event code, and for logons their type
SOURCE_PARTS = ("artifact", "log_channel", "event_code", "logon_type")
CHANNEL_ARTIFACTS = ("evtx", "suricata", "zeek")


class Match:
    """What one pivot matches for one event: its label, the SQL conditions that match (one branch each, which never
    match an event twice, so a count adds them and a list ORs them), and the anchor's values."""

    def __init__(self, label: str, branches: list[tuple[str, list]], anchor: dict | None = None, note: str = "",
                 counts: list[tuple[str, list]] | None = None, **more):
        self.label, self.branches, self.anchor, self.note, self.more = label, branches, anchor or {}, note, more
        self.counts = counts   # a faster count that equals the branches' (rule), which a list still reads the branches for

    def where(self) -> tuple[str, list]:
        if len(self.branches) == 1:
            return self.branches[0]
        return " OR ".join(f"({sql})" for sql, _ in self.branches), [p for _, ps in self.branches for p in ps]


def source_condition(source: list[str]) -> tuple[str, list[str]]:
    """The condition for one source of a pivot's breakdown, as [artifact, channel, event code, logon type] with the
    parts a source has (event logs have all four for a logon and three otherwise, a capture two, a tool's artifact one)."""
    if not 1 <= len(source) <= len(SOURCE_PARTS) or not all(isinstance(s, str) for s in source):
        raise QueryError("source must be a list of the evidence type and up to three more parts")
    return " AND ".join(f"e.{c} = ?" for c in SOURCE_PARTS[:len(source)]), list(source)


def source_parts(artifact: str, channel: str, code: str, logon_type: str) -> list[str]:
    """The breakdown's source for an event: source_condition's list."""
    if artifact == "evtx":
        return [artifact, channel, code] + ([logon_type] if code in ("4624", "4625") else [])
    return [artifact, channel] if artifact in CHANNEL_ARTIFACTS else [artifact]


def _check_window(seconds: int) -> None:
    """Raise QueryError for a time window outside WINDOW_RANGE_SECONDS."""
    lo, hi = WINDOW_RANGE_SECONDS
    if not lo <= seconds <= hi:
        raise QueryError(f"the time window must be {lo} to {hi} seconds")


def _near(identity: Identity | None, when: int, seconds: int) -> tuple[str, list]:
    """Within `seconds` of `when` on the adjusted time, with a bound on the recorded time that lets DuckDB skip row
    groups when the identity's offsets are known."""
    sql, params = f"abs({TS} - ?) <= ?", [when, seconds * 1_000_000]
    if identity is not None:
        low, high = raw_bounds(identity, when - seconds * 1_000_000, when + seconds * 1_000_000 + 1)
        sql, params = f"e.ts_us >= ? AND e.ts_us <= ? AND {sql}", [low, high, *params]
    return sql, params


def _account(ev: dict, con: duckdb.DuckDBPyConnection) -> Match:
    """Same account, on the account key (case format 3): the name in each spelling of the
    domain the event wrote, as the table account_domains folds them, and the same name with no domain, which SRUM, jump
    lists, ShellBags, Suricata, and every import without a domain role record. The key splits name@realm and
    user/REALM, so a 4769's Administrator@C137.LOCAL is c137.local\\administrator and joins C137\\Administrator through
    the fold. An event with no domain matches the name in any domain, and says so. The row still
    shows the account as the event wrote it."""
    name, domain, key = ev["user_name"], ev["user_domain"], ev.get("account_key") or ""
    anchor = {"user_domain": domain, "user_name": name}
    if not key:
        return Match("same account", [], anchor, "this event has no user_domain or user_name")
    if "\\" not in key:   # the key holds a backslash only after its domain (accounts.key_sql)
        return Match("same account (name only, any domain)",
                     [("e.account_key = ? OR suffix(e.account_key, ?)", [key, "\\" + key])], anchor)
    spelling, _, bare = key.partition("\\")
    spellings = _spellings(con, spelling)
    keys = [*(f"{s}\\{bare}" for s in spellings), bare]
    notes = ["Also events with this name and no domain."]
    # Two spellings are one domain by their SIDs when both have basis "sid"; otherwise a label fold joined them
    by_sid = lambda b: b == "sid" and spellings[spelling] == "sid"
    for sid, words in ((True, "the same domain by the SIDs its logons record"),
                       (False, "taken as the same domain since its first DNS label is the domain's name (an "
                               "inference: no SID was recorded under it)")):
        others = [s.upper() for s, b in spellings.items() if s != spelling and by_sid(b) == sid]
        if others:
            notes.append(f"Also written as {_joined(others)}, {words}.")
    return Match("same account", [(f"e.account_key IN ({', '.join('?' * len(keys))})", keys)], anchor,
                 match_note=" ".join(notes))


def _spellings(con: duckdb.DuckDBPyConnection, spelling: str) -> dict[str, str]:
    """The spellings of a domain that fold together with this one (accounts.build_account_domains), each with what
    folds it, or the spelling alone when none does or the table doesn't exist yet."""
    try:
        rows = con.execute("SELECT a.spelling, a.basis FROM account_domains a JOIN account_domains s "
                           "ON s.domain = a.domain WHERE s.spelling = ? ORDER BY a.spelling", [spelling]).fetchall()
    except duckdb.CatalogException:   # a database opened before the table existed
        rows = []
    return dict(rows) or {spelling: "sid"}


def _joined(items: list[str]) -> str:
    return items[0] if len(items) == 1 else f"{', '.join(items[:-1])} and {items[-1]}"


def _hash_match(ev: dict) -> Match:
    """Same hash (case format 3): the events whose hash list holds any of this event's
    hashes, in one branch. The list is lower case, so no lowering is needed here."""
    found = (ev.get("hashes") or "").split()
    if not found:
        return Match(RELATED["hash"][0], [], {}, "this event has no file hash")
    return Match(RELATED["hash"][0], [("e.hashes <> '' AND list_has_any(string_split(e.hashes, ' '), ?)", [found])],
                 {"hashes": " ".join(found)})


def _file_match(con: duckdb.DuckDBPyConnection, ev: dict, label: str, where: str, key: str, anchor: dict) -> Match:
    """Same file: the events with this file key, and the events whose 8.3 path resolves to it, which the table short_paths holds
    (short_names.py). From an event whose own key is an 8.3 path, it is the long path that host's MFT
    says it stands for. The two branches never match an event twice: a short key is never the long key it resolves to."""
    try:
        found = con.execute("SELECT long_key FROM short_paths WHERE host = ? AND short_key = ? LIMIT 1",
                            [ev["host"], key]).fetchone()
        long = found[0] if found else key
        hosts = [h for (h,) in con.execute("SELECT DISTINCT host FROM short_paths WHERE long_key = ? ORDER BY host",
                                           [long]).fetchall()]
    except duckdb.CatalogException:   # a database opened before the table existed
        return Match(label, [(where, [key])], anchor)
    if not hosts:
        return Match(label, [(where, [key])], anchor)
    whose = f"{hosts[0]}'s MFT" if len(hosts) == 1 else "the MFTs of " + " and ".join(hosts)
    if long == key:
        note, short_note = f"Also this path's 8.3 form, read from {whose}.", ""
    else:
        # The path as the host's MFT wrote it, not the lower-case key
        written = con.execute("SELECT file_path FROM events WHERE host = ? AND artifact = 'mft' AND file_key = ? "
                              "AND file_path <> '' LIMIT 1", [ev["host"], long]).fetchone()
        note = short_note = f"This 8.3 path stands for {written[0] if written else long}, by {whose}."
        note += " Also the events with that path."
    return Match(label, [(where, [long]), ("e.event_uid IN (SELECT event_uid FROM short_paths WHERE long_key = ?)", [long])],
                 anchor, match_note=note, short_note=short_note)


def event_hits(con: duckdb.DuckDBPyConnection, ev: dict) -> list[dict]:
    """An event's Hayabusa hits, by the keys analysis.hit_join matches on, from the event's own values rather than a join
    that reads every event."""
    return [{"title": t, "level": lvl} for t, lvl in con.execute(
        "SELECT rule_title, rule_level FROM events WHERE tool = 'hayabusa' AND origin_host = ? AND log_channel = ? "
        "AND record_id = ? AND source_file = ? ORDER BY rule_level, rule_title",
        [ev[k] for k in ("origin_host", "log_channel", "record_id", "source_file")]).fetchall()]


def _branches(kind: str, ev: dict, con: duckdb.DuckDBPyConnection, name: str = "") -> Match:
    """The matches of the kinds that read the event's own data, not a column. `name` is a file name the table fixes for a
    kind of event, such as wevtutil.exe on a log clear (pivots.checked_name); without it the event's own is the name."""
    label = RELATED[kind][0]
    if kind == "hash":
        return _hash_match(ev)
    if kind == "file_name":
        name = name or file_name_of(ev)
        return Match(f"file name {name}" if name else label, file_name_branches(name) if name else [], {},
                     "" if name else "this event has no file name")
    if kind == "service_name":
        names = service_aliases(con, service_names(ev))
        return Match(label, service_branches(names), {}, "" if names else "this event names no service")
    if kind == "task_name":
        names = task_names(ev)
        return Match(label, task_branches(names[0]) if names else [], {}, "" if names else "this event names no task")
    if kind == "flow":
        artifact, ident = flow_id(ev)
        return Match(label, flow_branches(artifact, ident) if ident else [], {}, "" if ident else "this event has no flow ID")
    if kind == "rule":
        hits = sorted(event_hits(con, ev), key=lambda h: (-LEVEL_RANK.get(h["level"], 0), h["title"]))
        source, key, words = rule_of(ev, [h["title"] for h in hits])
        return Match(label, rule_branches(source, key) if key else [], {}, "" if key else "this event has no rule or signature",
                     counts=rule_counts(source, key) if key else None, words=words)
    raise QueryError(f"{kind} has no match of its own")


def match_for(con: duckdb.DuckDBPyConnection, uid: str, kind: str, seconds: int, ip: str, identity: Identity | None,
              ts: int | None, source: list[str] | None = None, scope: str = "", name: str = "",
              unreviewed: bool = False) -> tuple[Match, int | None]:
    """The events a pivot matches for one event, and the event's adjusted time. `ip` is an address of the event, for the
    pivot at either end; `source` narrows any kind to one source of its breakdown; scope "case" lifts the connection's
    bound in time; `name` is the fixed file name of Same file name (_branches); `unreviewed` keeps only events with no
    mark (_unreviewed)."""
    match, when, _ = match_and_event(con, uid, kind, seconds, ip, identity, ts, source, scope, name=name, unreviewed=unreviewed)
    return match, when


def anchor_of(con: duckdb.DuckDBPyConnection, uid: str, identity: Identity | None, ts: int | None) -> tuple[dict, int | None]:
    """The event a pivot starts from, as its own columns with '' for an empty text column (a load writes it so; an older
    database may hold NULL), and its adjusted time."""
    row, names = find_event(con, uid, identity, ts, f"{TS} AS adjusted_ts, e.*")
    if row is None:
        raise QueryError("unknown event")
    return {n: ("" if v is None and n not in BIGINT_COLUMNS else v) for n, v in zip(names, row, strict=True)}, row[0]


def _narrowed(match: Match, source: list[str]) -> Match:
    """The match narrowed to one source of its breakdown, for every kind with branches: each branch gets the
    source's condition, so the list and its count read the same events the breakdown's entry counted. A fast count the
    kind had (the rule's) counts the whole rule, so it is dropped and the branches are counted. The source is echoed in
    `more`, for the list to say what it was narrowed to."""
    cond, params = source_condition(source)
    match.branches = [(f"({sql}) AND {cond}", [*ps, *params]) for sql, ps in match.branches]
    match.counts = None
    match.more["source"] = source
    return match


UNREVIEWED_COND = "NOT EXISTS (SELECT 1 FROM marks mk WHERE mk.event_uid = e.event_uid)"


def _unreviewed(match: Match) -> Match:
    """The match kept to events with no mark, for To investigate's counts and the lists they open: each branch gets the
    condition, so the list and its count read the same events, and a fast count the kind had is dropped, as _narrowed
    drops it. A pending suggestion is not a mark, so such an event still counts."""
    match.branches = [(f"({sql}) AND {UNREVIEWED_COND}", ps) for sql, ps in match.branches]
    match.counts = None
    match.more["unreviewed"] = True
    return match


def match_and_event(con: duckdb.DuckDBPyConnection, uid: str, kind: str, seconds: int, ip: str, identity: Identity | None,
                    ts: int | None, source: list[str] | None = None, scope: str = "",
                    anchor: tuple[dict, int | None] | None = None, name: str = "",
                    unreviewed: bool = False) -> tuple[Match, int | None, dict]:
    """match_for, and the event's own columns too. `anchor`, the event as anchor_of gives it, saves reading it again: a
    page counting each of an event's pivots would read it for every row, 50 ms each at 11 million events. `source` narrows
    any kind to one source of its breakdown (_narrowed), and `unreviewed` to events with no mark (_unreviewed)."""
    match, when, ev = _match_and_event(con, uid, kind, seconds, ip, identity, ts, scope, anchor, name)
    if source:
        match = _narrowed(match, source)
    if unreviewed:
        match = _unreviewed(match)
    return match, when, ev


def _match_and_event(con: duckdb.DuckDBPyConnection, uid: str, kind: str, seconds: int, ip: str, identity: Identity | None,
                     ts: int | None, scope: str, anchor: tuple[dict, int | None] | None,
                     name: str) -> tuple[Match, int | None, dict]:
    if kind not in RELATED:
        raise QueryError(f"kind must be one of {sorted(RELATED)}")
    label, where, fields = RELATED[kind]
    ev, when = anchor or anchor_of(con, uid, identity, ts)
    values = [ev[f] for f in fields]
    anchor = dict(zip(fields, values, strict=True))
    if kind == "addr":
        own = sorted({a for a in values if a})
        if not own:
            return Match(label, [], anchor, "this event has no source_ip or dest_ip"), when, ev
        if ip not in own:   # only an address the event has, so the request can't pivot on an arbitrary value
            raise QueryError(f"ip must be one of this event's addresses: {', '.join(own)}")
        # Two equality conditions, which DuckDB pushes into the scan where it doesn't for the OR:
        # the source equal, and the destination equal where the source differs
        ends = [("e.source_ip = ?", [ip]), ("e.dest_ip = ? AND e.source_ip IS DISTINCT FROM ?", [ip, ip])]
        if is_local(ip):   # every host has its own ::1 and 127.0.0.1
            ends = [(f"{sql} AND e.host = ?", [*params, ev["host"]]) for sql, params in ends]
            return Match(f"IP {ip} at either end, on {ev['host']} only", ends, anchor, address=ip, host=ev["host"]), when, ev
        return Match(f"IP {ip} at either end", ends, anchor, address=ip), when, ev
    if kind == "account":
        return _account(ev, con), when, ev
    if not where:
        return _branches(kind, ev, con, name), when, ev
    if kind == "window":
        if when is None:
            return Match(label, [], anchor, "this event has no time recorded"), when, ev
        _check_window(seconds)
        near, near_params = _near(identity, when, seconds)
        sql, params = f"{where} AND {near} AND e.event_uid <> ?", [*values, *near_params, uid]
        return Match(f"same host within {seconds} seconds", [(sql, params)], anchor), when, ev
    if any(v in (None, "") for v in values) or (kind == "session" and values[1].lower() == "0x0"):
        what = "logon_id" if kind == "session" else " or ".join(fields)
        return Match(label, [], anchor, f"this event has no {what}"), when, ev
    # A loopback or link-local address is every host's own, so a pivot on it stays within the seed's host
    own = {"host": ev["host"]} if kind in ("source_ip", "connection") and is_local(values[0]) else {}
    if own:
        where, values = f"{where} AND e.host = ?", [*values, ev["host"]]
    only = f", on {ev['host']} only" if own else ""
    if kind == "connection" and scope != "case" and when is not None:
        _check_window(seconds)
        near, near_params = _near(identity, when, seconds)
        return Match(f"same source IP and port within {seconds} seconds{only}",
                     [(f"{where} AND {near}", [*values, *near_params])], anchor, seconds=seconds, **own), when, ev
    if kind == "connection":
        label = "same source IP and port, case-wide"
    if kind == "file":
        return _file_match(con, ev, label, where, values[0], anchor), when, ev
    return Match(label + only, [(where, list(values))], anchor, **own), when, ev


def related(con: duckdb.DuckDBPyConnection, uid: str, kind: str, seconds: int = WINDOW_DEFAULT_SECONDS,
            shown: str = "true", ip: str = "", identity: Identity | None = None, ts: int | None = None,
            source: list[str] | None = None, scope: str = "", name: str = "", unreviewed: bool = False) -> dict:
    """Events related to one event, nearest in time first, returned in time order with their gap. The "addr" kind takes
    `ip`, one of the event's own addresses, and says for each result which end it was on. `ts` is the time the page
    shows the event at, as find_event takes it. Any kind takes `source`, one source of its breakdown (source_parts), which
    narrows the list and its total to that source and is echoed in the answer, and `unreviewed`, which keeps the list to
    events with no mark and is echoed too. The connection takes `seconds`, its bound in time, or scope "case" for
    none. Same file name takes `name` where the table fixes one for the kind of event (a log clear's wevtutil.exe).

    An event without a time has no nearest: its pivots list from the first in time order, with no gap, and say so in
    `nearest` and a note, and its time window answers a note. Ties go by ID, so a list of 500 keeps one order."""
    match, when = match_for(con, uid, kind, seconds, ip, identity, ts, source, scope, name, unreviewed)
    if match.note:
        return {"label": match.label, "events": [], "note": match.note}
    where, params = match.where()
    # `shown` is the page's View: each result says whether the View shows it. From an event without
    # a time every distance is NULL, so the time and the ID pick the list. The outer sort repeats the ID: DuckDB 1.5.6
    # keeps the inner order among ties, but doesn't promise to.
    rows = con.execute(
        f"SELECT * FROM (SELECT e.event_uid, {TS} AS ts, e.host, e.event_code, left(e.message, 160), {MARK_EXPR}, "
        f"({shown}), e.source_ip, e.dest_ip FROM {BASE_FROM} WHERE {BASE_WHERE} AND ({where}) "
        f"ORDER BY abs({TS} - ?), {TS}, e.event_uid LIMIT {RELATED_LIMIT}) ORDER BY ts, event_uid",
        [*params, when]).fetchall()
    total = len(rows) if len(rows) < RELATED_LIMIT else count_matches(con, match)
    cut = total > len(rows)   # a list of exactly RELATED_LIMIT events holds them all
    events = [{"uid": r[0], "ts": r[1], "host": r[2], "code": r[3], "msg": r[4], "mark": r[5], "shown": bool(r[6]),
               "gap_s": None if when is None else round((r[1] - when) / 1_000_000, 3)} for r in rows]
    out = {"label": match.label, "limited": cut, "total": total, "nearest": when is not None,
           "anchor": match.anchor, "events": events}
    if "seconds" in match.more:
        out["seconds"] = match.more["seconds"]
    if match.more.get("match_note"):
        out["match_note"] = match.more["match_note"]
    if match.more.get("host"):   # a loopback or link-local address, matched on the seed's host only
        out["host"] = match.more["host"]
    if source:   # a list narrowed to a source says which, whatever the kind
        out["source"] = source
    if unreviewed:   # and one kept to unreviewed events says so
        out["unreviewed"] = True
    if out["limited"] and when is not None:   # how far in time the nearest 500 reach
        out["reach_s"] = max(abs(e["gap_s"]) for e in events)
    if when is None:
        out["note"] = "this event has no time recorded, so the list has no gaps and starts at the earliest"
    if kind == "addr":   # which end the address was on, so a recorded destination that's the remote side shows
        for ev, r in zip(events, rows, strict=True):
            ev["end"] = "both" if r[7] == ip == r[8] else "source" if r[7] == ip else "destination"
        out["address"] = ip
    return out


def count_matches(con: duckdb.DuckDBPyConnection, match: Match) -> int:
    """How many events a pivot lists in all, as the click's own conditions find them, in one query: the sum of the
    branches' counts, each branch one scan with its filter pushed into it, which the union keeps (an OR of the branches
    does not: pivot_names.py)."""
    parts = match.counts or [(f"SELECT count(*) FROM {TIME_FROM} WHERE {BASE_WHERE} AND ({sql})", params)
                             for sql, params in match.branches]
    if not parts:
        return 0
    sql = "SELECT sum(c) FROM (" + " UNION ALL ".join(part for part, _ in parts) + ") t(c)"
    return int(con.execute(sql, [p for _, params in parts for p in params]).fetchone()[0] or 0)


def tag_counts(con: duckdb.DuckDBPyConnection) -> dict:
    """Events per tag, applied and suggested, for the View filter's Tactics section. An older technique tag off
    the ATT&CK list carries its flag, as a finding's does; suggestions are only of listed ones."""
    applied = con.execute("SELECT tag, kind, label, min(ord), count(*) FROM tags GROUP BY ALL ORDER BY 4, 3").fetchall()
    suggested = con.execute("SELECT tag, kind, label, min(ord), count(*) FROM tag_suggestions GROUP BY ALL "
                            "ORDER BY 4, 3").fetchall()
    tags: dict[str, dict] = {}
    for key, kind, label, ord_, n in applied:
        tags[key] = {"key": key, "kind": kind, "label": label, "ord": ord_, "count": n, "suggested": 0,
                     **({"flag": f} if kind == "technique" and (f := attack.flag(label)) else {})}
    for key, kind, label, ord_, n in suggested:
        tags.setdefault(key, {"key": key, "kind": kind, "label": label, "ord": ord_, "count": 0})["suggested"] = n
    return {"tags": sorted(tags.values(), key=lambda t: (t["ord"], t["kind"] != "technique", t["label"])),
            "any": con.execute("SELECT count(DISTINCT event_uid) FROM tags").fetchone()[0],
            # what Any tag adds when the View includes suggested tags: events with only a suggestion
            "any_suggested": con.execute("SELECT count(DISTINCT event_uid) FROM tag_suggestions "
                                         "WHERE event_uid NOT IN (SELECT event_uid FROM tags)").fetchone()[0]}


def mark_counts(con: duckdb.DuckDBPyConnection) -> dict[str, int]:
    """Events per mark across the case, for the View flyout; every pending suggestion counts as Suggested."""
    counts: dict[str, int] = {}
    for label, n in con.execute(f"SELECT {MARK_EXPR}, count(*) FROM {BASE_FROM} WHERE {BASE_WHERE} GROUP BY 1").fetchall():
        key = "Suggested" if label.startswith("Suggested: ") else label
        counts[key] = counts.get(key, 0) + n
    return counts


def event_keys(con, keys: list[str], uids: list[str], extra: str = "") -> dict[str, list]:
    """Each event's lane keys. With a view filter's `extra`, an event the filter hides has none."""
    if not uids:
        return {}
    # Pick the events first, then join the lookup tables to just those rows. The IDs go in through a temp table; see
    # events.insert_columns for why not parameters.
    wanted = id_table(con, "wanted_events", uids)
    picked = base_from(keys).replace("events e", f"(SELECT * FROM events WHERE event_uid IN (SELECT v FROM {wanted})) e", 1)
    rows = con.execute(f"SELECT e.event_uid, {_keys_sql(keys)} FROM {picked} WHERE true{extra}").fetchall()
    return {r[0]: list(r[1:]) for r in rows}


def sources(con: duckdb.DuckDBPyConnection) -> dict:
    """What the Filter panel lists: evidence types with tool, version, and runs, and source files by host and type. A
    file whose events have more than one channel lists them, such as a Suricata EVE file's record types or an Autoruns
    CSV's categories, so a capture's flow records can be hidden apart from its
    alerts. An event log file is one channel, unless it holds forwarded events."""
    types: dict[tuple, dict] = {}
    # A run is listed under the host it ran on, which a split by recorded computer leaves as origin_host, so
    # one run isn't listed once per lane.
    for tool, version, artifact, run, host, n in con.execute(
            f"SELECT e.tool, e.tool_version, e.artifact, e.run_id, e.origin_host, count(*) FROM events e WHERE {BASE_WHERE} "
            "GROUP BY ALL ORDER BY e.run_id").fetchall():
        t = types.setdefault((tool, artifact), {"tool": tool, "artifact": artifact, "versions": [], "count": 0, "runs": []})
        if version not in t["versions"]:
            t["versions"].append(version)
        t["count"] += n
        t["runs"].append({"run": run, "host": host, "count": n})
    hosts: dict[str, dict] = {}
    for host, tool, artifact, path, n, channels in con.execute(
            "SELECT host, tool, artifact, source_file, sum(n)::BIGINT, "
            "list({'channel': log_channel, 'count': n} ORDER BY n DESC, log_channel) FILTER (WHERE log_channel <> '') "
            f"FROM (SELECT e.host, e.tool, e.artifact, e.source_file, e.log_channel, count(*) AS n FROM events e "
            f"WHERE {BASE_WHERE} GROUP BY ALL) GROUP BY ALL ORDER BY 1, 3, 5 DESC, 4").fetchall():
        h = hosts.setdefault(host, {"host": host, "count": 0, "artifacts": {}})
        a = h["artifacts"].setdefault((tool, artifact), {"tool": tool, "artifact": artifact, "count": 0, "files": []})
        a["files"].append({"file": path, "count": n, **({"channels": channels} if channels and len(channels) > 1 else {})})
        a["count"] += n
        h["count"] += n
    hayabusa = con.execute("SELECT string_agg(DISTINCT tool_version, ', '), count(*) FROM events "
                           "WHERE tool = 'hayabusa'").fetchone()
    return {"types": sorted(types.values(), key=lambda t: -t["count"]),
            "hosts": [{**h, "artifacts": sorted(h["artifacts"].values(), key=lambda a: -a["count"])} for h in hosts.values()],
            "hayabusa": {"version": hayabusa[0] or "", "count": hayabusa[1]}}


def shown_counts(con: duckdb.DuckDBPyConnection, cond: str) -> list[list]:
    """Per host, tool, evidence type, source file, and channel, how many events a filter shows; what it hides fully is
    left out. The channel is '' for events without one."""
    return [list(r) for r in con.execute(
        f"SELECT e.host, e.tool, e.artifact, e.source_file, e.log_channel, count(*) FROM {BASE_FROM} "
        f"WHERE {BASE_WHERE} AND {cond} GROUP BY ALL").fetchall()]


def categories(con: duckdb.DuckDBPyConnection, pred_where: str, cond: str = "true", top: int = 6) -> dict:
    """The evidence types and event log channels inside one lane or Filter panel item, with their counts and
    how many of them the current filter (`cond`) shows."""
    types = con.execute(f"SELECT e.tool, e.artifact, count(*), count(*) FILTER (WHERE {cond}) FROM {BASE_FROM} "
                        f"WHERE {BASE_WHERE} AND {pred_where} GROUP BY ALL ORDER BY 3 DESC").fetchall()
    channels = con.execute(f"SELECT e.log_channel, count(*), count(*) FILTER (WHERE {cond}), count(*) OVER () "
                           f"FROM {BASE_FROM} WHERE {BASE_WHERE} AND {pred_where} AND e.artifact = 'evtx' "
                           "AND e.log_channel <> '' GROUP BY ALL ORDER BY 2 DESC LIMIT ?", [top]).fetchall()
    return {"types": [{"tool": t, "artifact": a, "count": n, "shown": k} for t, a, n, k in types],
            "channels": [{"channel": c, "count": n, "shown": k} for c, n, k, _ in channels],
            "channel_total": channels[0][3] if channels else 0}


def listed_events(con: duckdb.DuckDBPyConnection, cond: str, limit: int = RELATED_LIMIT) -> dict:
    """The first `limit` events that meet a condition on BASE_FROM, in time order, to list in the Details panel with
    ticks and mark buttons, as a search's matches are: what an overview count's click puts on the timeline.
    Hayabusa's hit rows are not events. An event without a time comes last."""
    where = f"e.tool <> 'hayabusa' AND ({cond})"
    total = con.execute(f"SELECT count(*) FROM {BASE_FROM} WHERE {where}").fetchone()[0]
    rows = con.execute(f"SELECT e.event_uid, {TS}, e.host, e.event_code, left(e.message, {LISTED_MESSAGE}), {MARK_EXPR} "
                       f"FROM {BASE_FROM} WHERE {where} ORDER BY {TS} NULLS LAST, e.event_uid LIMIT {limit}").fetchall()
    return {"total": total, "limited": total > len(rows),
            "events": [{"uid": r[0], "ts": r[1], "host": r[2], "code": r[3], "msg": r[4], "mark": r[5], "shown": True}
                       for r in rows]}
