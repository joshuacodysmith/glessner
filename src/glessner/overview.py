"""The Case overview: where to start, progress, what the case holds, its gaps, and its integrity.

Every figure comes from the case database's derived tables, the journal, the run records, the manifest, and the
evidence checks; nothing is guessed and no model is involved. The server caches the result until any of them changes
(server.api_overview).
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path

import duckdb

from .analysis import HAYABUSA_SOURCE, IDS_ALERT_SOURCE, NETWORK_DEVICE_ARTIFACTS, SURICATA_SOURCE, level_rank
from .audit import describe, recovered_words, short
from .events import from_us
from .identity import Identity
from .intake import UNLISTED
from .journal import (
    APP_NAMES,
    Check,
    Journal,
    State,
    _applies,
    _chained,
    _format2,
    _rekey_ok,
    _replayable,
    is_rekey,
    lacks,
    parse_line,
    strict,
    translate,
    unplaced_count,
)
from .queries import TS

MINUTE = 60_000_000
CLUSTER_GAP_US = 30 * MINUTE   # alerts more than this far apart start a new lead
TOP_TITLES = 3                 # rule titles or signatures a lead's why line names
# The alerts behind the red box and the alert suggestion sources, ranked as queries._SEVERITY ranks them: Hayabusa hits
# at medium level or above (3 to 5), Suricata alerts at severity 1 (high, 4) or 2 (medium, 3), and imported fast alerts
# at priority 1 or 2, ranked the same. They're the events those built-in sources suggest Suspicious.
ALERTS = """
    SELECT event_uid, 'hayabusa' AS tool, max_level AS level FROM hits WHERE max_level >= 3
    UNION ALL
    SELECT event_uid, 'suricata', CASE severity WHEN 1 THEN 4 ELSE 3 END FROM suricata_alerts WHERE severity BETWEEN 1 AND 2
    UNION ALL
    SELECT event_uid, 'import', CASE priority WHEN 1 THEN 4 ELSE 3 END FROM fast_alerts WHERE priority BETWEEN 1 AND 2"""
ALERT_SOURCE = {"hayabusa": HAYABUSA_SOURCE, "suricata": SURICATA_SOURCE, "import": IDS_ALERT_SOURCE}
# A lead's title names the tool, the levels, and what it counts: events for Hayabusa, whose hits mark the event they
# matched, and alerts for the others, one to an event.
ALERT_NAME = {"hayabusa": "Hayabusa", "suricata": "Suricata", "import": "Imported fast alerts"}
ALERT_NOUN = {"hayabusa": ("event", "events"), "suricata": ("alert", "alerts"), "import": ("alert", "alerts")}
# A Suricata alert's own words for its rank, and a fast alert's (queries._SEVERITY): severity 1 ranks with high. Read as
# "critical and high", "severity 1 and 2".
LEVEL_WORDS = {"hayabusa": ("", {5: "critical", 4: "high", 3: "medium"}), "suricata": ("severity ", {4: "1", 3: "2"}),
               "import": ("priority ", {4: "1", 3: "2"})}
TIERS = {5: "critical", 4: "high", 3: "medium"}
TIER_ORDER = {"critical": 0, "high": 1, "medium": 2, "suggestion": 3, "clock": 4}
RANKING = ("Ranked by severity: critical alerts, then high, then medium, then suggestions from rules, then host "
           "clocks; then by the earliest time. A lead counts as worked when every event in it has a mark or a "
           "decision, and a clock lead when its host is aligned to the capture. Leads come only from tool output, "
           "rules, and clock checks.")
# Log clears: the Security log's 1102 and the System log's 104, which names the log cleared, from the Event Log
# service's provider; other providers can write those IDs.
CLEAR_WHERE = ("e.event_code IN ('1102', '104') AND e.artifact = 'evtx' AND "
               "lower(e.event_provider) = 'microsoft-windows-eventlog' AND "
               "((e.event_code = '1102' AND e.log_channel = 'Security') OR (e.event_code = '104' AND e.log_channel = 'System'))")
# The marked Malicious and Suspicious events with an unreviewed related event by three fixed relations (To investigate
# counts each event's own top pivots instead, so its list can differ): same host and logon ID, any letter case, leaving
# out Windows' own sessions and 0x0; same file; same source IP, a loopback or link-local one on its own host only; related
# events on the timeline and not marked. A key's unreviewed events are all its timeline events less its marked ones, so the
# events are counted per key, and no anti-join of the case's events with the marks is needed: 0.07 s against 0.6 s for a
# per-event query, at 10.4 million events.
TIMELINE = "e.tool <> 'hayabusa' AND e.ts_us IS NOT NULL"
# queries.session_key and queries.local_scope, written out so this module's import lines stay as they are; a test holds them
# together
SESSION_KEY = "CASE WHEN COALESCE(lower({c}), '') IN ('', '0x0', '0x3e7', '0x3e4', '0x3e5', '0x3e6') THEN '' ELSE lower({c}) END"
LOCAL_SCOPE = ("CASE WHEN (starts_with({c}, '127.') OR split_part({c}, '%', 1) IN ('::1', '0.0.0.0', '::') "
               "OR starts_with({c}, '169.254.') OR regexp_matches({c}, '^fe[89ab][0-9a-f]:')) THEN {h} ELSE '' END")
NEARBY = f"""
    WITH f AS (
        SELECT v.host, {SESSION_KEY.format(c="v.logon_id")} AS lid, v.file_key, v.source_ip,
               {LOCAL_SCOPE.format(c="v.source_ip", h="v.host")} AS ip_scope
        FROM ov_ev v JOIN marks m ON m.event_uid = v.event_uid
        WHERE m.label IN ('Malicious', 'Suspicious')),
    marked AS (SELECT v.host, {SESSION_KEY.format(c="v.logon_id")} AS lid, v.file_key, v.source_ip,
                      {LOCAL_SCOPE.format(c="v.source_ip", h="v.host")} AS ip_scope
               FROM ov_ev v JOIN marks m ON m.event_uid = v.event_uid WHERE v.ts IS NOT NULL),
    s AS (SELECT e.host, lower(e.logon_id) AS lid, count(*) AS n FROM events e
          WHERE {TIMELINE} AND e.logon_id <> '' AND (e.host, lower(e.logon_id)) IN (SELECT host, lid FROM f WHERE lid <> '')
          GROUP BY ALL),
    k AS (SELECT e.file_key, count(*) AS n FROM events e
          WHERE {TIMELINE} AND e.file_key IN (SELECT file_key FROM f WHERE file_key <> '') GROUP BY ALL),
    a AS (SELECT {LOCAL_SCOPE.format(c="e.source_ip", h="e.host")} AS ip_scope, e.source_ip, count(*) AS n FROM events e
          WHERE {TIMELINE} AND e.source_ip IN (SELECT source_ip FROM f WHERE source_ip <> '') GROUP BY ALL),
    ms AS (SELECT host, lid, count(*) AS n FROM marked WHERE lid <> '' GROUP BY ALL),
    mk AS (SELECT file_key, count(*) AS n FROM marked WHERE file_key <> '' GROUP BY ALL),
    ma AS (SELECT ip_scope, source_ip, count(*) AS n FROM marked WHERE source_ip <> '' GROUP BY ALL)
    SELECT count(*) FROM f
    LEFT JOIN s ON f.lid <> '' AND s.host = f.host AND s.lid = f.lid LEFT JOIN ms ON ms.host = s.host AND ms.lid = s.lid
    LEFT JOIN k ON f.file_key <> '' AND k.file_key = f.file_key LEFT JOIN mk ON mk.file_key = k.file_key
    LEFT JOIN a ON f.source_ip <> '' AND a.ip_scope = f.ip_scope AND a.source_ip = f.source_ip
    LEFT JOIN ma ON ma.ip_scope = a.ip_scope AND ma.source_ip = a.source_ip
    WHERE COALESCE(s.n, 0) > COALESCE(ms.n, 0) OR COALESCE(k.n, 0) > COALESCE(mk.n, 0)
       OR COALESCE(a.n, 0) > COALESCE(ma.n, 0)"""


def case_overview(con: duckdb.DuckDBPyConnection, *, identity: Identity, state: State, report: dict[str, dict],
                  journal_path: Path, runs: list, run_gaps: list[dict], manifest: list, unidentified: int, orphans: int,
                  checks: dict, tool_names: dict[str, str], artifact_names: dict[str, str], build: str,
                  alignment: str, journal: dict | None = None) -> dict:
    """The overview's sections. `con` is a cursor of its own: the temp tables it makes are its connection's. `checks`
    is intake.evidence_checks's reading of verification.jsonl; `journal` is Integrity's Journal row (journal_row)."""
    last = _last_action(journal_path)
    events = _events_of_interest(con, last)
    leads = _alert_leads(con, runs, tool_names) + _rule_leads(con, state, report) + _clock_leads(identity)
    leads.sort(key=lambda lead: (TIER_ORDER[lead["level"]], lead["first"] is None, lead["first"] or 0, lead["id"]))
    hosts = _hosts(con, identity, artifact_names)
    if last and last.get("action"):
        last = {"seq": last.get("seq"), "at": last.get("at", ""), "who": last.get("who", ""),
                "text": describe(last, events)}
    files = manifest_facts(manifest)
    return {"leads": leads, "ranking": RANKING, "progress": _progress(con, state, leads, last, orphans),
            "by_host": _by_host(con, identity, leads), "hosts": hosts["rows"],
            "gaps": {"runs": run_gaps, "unidentified": unidentified, "unreadable": files["unreadable"],
                     "unlisted": files["unlisted"], "clears": hosts["clears"], "no_event_logs": hosts["no_event_logs"]},
            "integrity": {**_integrity(files, checks, journal_path, build, alignment, identity), "journal": journal}}


def _last_action(path: Path) -> dict | None:
    """The journal's newest entry by someone, as the shared reader (journal.entries) gives it, read from the file's end
    rather than by parsing every line. The app's own entries, such as the build each new build journals when it opens
    the case, are left to the audit trail and Integrity: they answer no "where was I". The case format upgrades' rekeys
    it passes on the way are exactly those that follow the entry, so it is read through them, in file order, as every
    other reader reads it: through each rekey the shared reader gives that _apply can take (journal._applies)."""
    start = None   # where the chain starts (_chain_start), found the first time a line that names no prev needs it
    with path.open("rb") as f:
        size = f.seek(0, 2)
        back = min(size, 65_536)
        while True:
            f.seek(size - back)
            # As the shared reader reads: up to the last LF, and before a last line holding 0x00. Either is a write in
            # progress, or a crash's
            *lines, torn = f.read(back).split(b"\n")
            end = size - len(torn) - 1   # where the newest whole line ends, at its LF
            if lines and not torn and b"\0" in lines[-1]:
                end -= len(lines.pop()) + 1
            if back < size:
                lines = lines[1:]   # the first may start mid-line
            rekeys = []   # the rekeys passed that the shared reader applies, newest first
            for line in reversed(lines):
                at = end - len(line)   # where the line starts
                end = at - 1           # where the line before it ends, at its LF
                if not line.strip():
                    continue
                # A line is chained when it names prev, or when a chained line comes before it, as journal._read
                # decides; an unchained line is parsed as format 2 read it
                entry = strict(line)
                chained = entry is not None and "prev" in entry
                if not chained:
                    start = _chain_start(path) if start is None else start
                    chained = at > start
                    entry = entry if chained else _format2(line)
                if not _given(entry, chained):
                    continue
                if entry.get("who") not in APP_NAMES:
                    return translate(entry, rekeys[::-1]) if rekeys else entry
                if is_rekey(entry) and _applies(entry):
                    rekeys.append(entry)
            if back == size:
                return None
            back = min(size, back * 4)   # long lines, such as a mark of many events, or several build entries


def _given(entry: dict | None, chained: bool) -> bool:
    """Whether the shared reader (journal._read) gives a line's entry, parsed as it parses the line, or None when that
    parse failed. A chained line's entry must have an envelope replay can read, complete when it names prev
    (journal.lacks), and no entry may be a rekey that no build of this format writes (journal._rekey_ok). `chained` is
    whether the line is chained: it names prev, or a chained line comes before it. _rekey_ok reads that only for an
    entry that names no prev, which is chained only when a chained line comes before it."""
    if entry is None:
        return False
    if chained and (not _replayable(entry) or ("prev" in entry and lacks(entry))):
        return False
    return not is_rekey(entry) or _rekey_ok(entry, chained)


def _chain_start(path: Path) -> int:
    """Where the journal's first chained line starts (journal._chained), or its size when no line is chained: a line
    that starts after it is chained, as the shared reader reads it."""
    at = 0
    with path.open("rb") as f:
        for line in f:
            if _chained(line.removesuffix(b"\n")):
                break
            at += len(line)
    return at


# Where each journal was read to, its entries, and its newest close (journal_facts)
_journal_read: dict[str, tuple[int, int, dict | None]] = {}


def journal_facts(path: Path) -> tuple[int, dict | None]:
    """The journal's entries and its newest close, which re-hashes the evidence (cli.cmd_close), read on from where the
    last call stopped: the journal only grows, so after a mark this reads one line. A close that the command line
    journals beside a running server shows here, though the server's own state reads it only at its next entry."""
    key = str(path)
    start, entries, close = _journal_read.get(key, (0, 0, None))
    with path.open("rb") as f:
        if f.seek(0, 2) < start:   # another file at this path: read it all
            start, entries, close = 0, 0, None
        f.seek(start)
        for line in f:
            if not line.endswith(b"\n") or b"\0" in line:
                # A line still being written, or one holding 0x00, which is torn when it is last, and which recovery then
                # cuts from the file: the read stops before it, without moving on
                break
            start += len(line)
            if not line.strip():
                continue
            entries += 1
            if b'"closed"' in line and b'"case_setting"' in line:
                # By the rule every reader shares: a whole line that isn't an entry, such as a changed one on a broken
                # chain, is skipped, and the page still loads on the read-only case it leaves
                entry = parse_line(line[:-1])
                if entry is not None and entry.get("action") == "case_setting" and entry.get("name") == "closed" and not (
                        "prev" in entry and lacks(entry)):
                    close = entry
    _journal_read[key] = (start, entries, close)
    return entries, close


def manifest_facts(manifest: list) -> dict:
    """The intake manifest's files: hashed at intake, added later by Add new evidence, and those intake could not
    read, which have an error and no hash (intake._entry). Under `unlisted`, apart from the files, the folders walk
    couldn't list (intake.ManifestEntry.is_folder), each with the error that kept it from being listed."""
    files = [e for e in manifest if not e.is_folder]
    return {"hashed": sum(1 for e in files if not e.error and not e.added_utc),
            "added": sum(1 for e in files if not e.error and e.added_utc),
            "unreadable": [{"path": e.path, "error": e.error, "added": e.added_utc} for e in files if e.error],
            "unlisted": [{"path": e.path, "error": e.error.removeprefix(f"{UNLISTED}: "), "added": e.added_utc}
                         for e in manifest if e.is_folder]}


def problem_files(problems: list[str]) -> tuple[dict[str, str], dict[str, str]]:
    """The files that intake.evidence_checks's problems name, each with what the first check to name it found, as
    (changed, not re-read). A changed file is one a check found missing or with another hash. A check that couldn't read
    a file, such as one another program held open, compared no hash, so that file counts as not re-read rather than
    changed, unless another check found it changed."""
    changed, not_reread = {}, {}
    for problem in problems:
        path, found = problem.rsplit(": ", 1) if ": " in problem else (problem, "")
        (not_reread if found.startswith("unreadable (") else changed).setdefault(path, found)
    return changed, {path: found for path, found in not_reread.items() if path not in changed}


def _events_of_interest(con: duckdb.DuckDBPyConnection, last: dict | None) -> dict[str, str]:
    """Reads, in one pass over the events, the events with a Hayabusa hit (alerts among them), the marked events, and
    the suggested events the overview counts, into the temp table ov_ev. Returns the short name of the last journal
    entry's one event, if it names one, as the audit trail names it. The pass reads narrow columns only: the scan reads
    its columns for every event before the IDs pick a few, so with the message it took 0.7 s at 10.4 million events,
    and 0.15 s without; the one message needed is looked up by its ID."""
    con.execute(f"CREATE OR REPLACE TEMP TABLE ov_alerts AS {ALERTS}")
    con.execute("CREATE OR REPLACE TEMP TABLE ov_ids AS SELECT event_uid FROM hits UNION SELECT event_uid FROM ov_alerts "
                "UNION SELECT event_uid FROM marks UNION SELECT event_uid FROM suggestions")
    con.execute(f"""
        CREATE OR REPLACE TEMP TABLE ov_ev AS
        SELECT e.event_uid, e.host, {TS} AS ts, e.origin_host, e.log_channel, e.record_id, e.source_file, e.tool_version,
               e.run_id, e.logon_id, e.file_key, e.source_ip
        FROM events e LEFT JOIN hosts h ON h.host = e.host
        WHERE e.event_uid IN (SELECT event_uid FROM ov_ids) AND e.tool <> 'hayabusa'""")
    targets = (last or {}).get("targets") or []
    single = (last or {}).get("target") or (targets[0] if len(targets) == 1 else None)
    if not single:
        return {}
    row = con.execute("SELECT host, event_code, artifact, left(message, 60) FROM events WHERE event_uid = ?",
                      [single]).fetchone()
    return {single: f"{row[0]} {row[1] or row[2]}: {row[3]}"} if row else {}


def _alert_leads(con: duckdb.DuckDBPyConnection, runs: list, tool_names: dict[str, str]) -> list[dict]:
    """Clusters of alerts per host and tool, split where two alerts are more than 30 minutes apart. An event counts as
    worked when it has a mark, or when the analyst rejected its source's suggestion. Alerts without a time are on no
    timeline, so they're in no cluster."""
    sources = " ".join(f"WHEN '{tool}' THEN '{source}'" for tool, source in ALERT_SOURCE.items())
    con.execute(f"""
        CREATE OR REPLACE TEMP TABLE ov_clustered AS
        WITH x AS (
            SELECT a.event_uid, a.tool, a.level, v.host, v.ts,
                   m.event_uid IS NOT NULL OR r.event_uid IS NOT NULL AS worked,
                   v.ts - lag(v.ts) OVER (PARTITION BY v.host, a.tool ORDER BY v.ts, a.event_uid) AS gap
            FROM ov_alerts a JOIN ov_ev v ON v.event_uid = a.event_uid
            LEFT JOIN marks m ON m.event_uid = a.event_uid
            LEFT JOIN rejected r ON r.event_uid = a.event_uid AND r.source = CASE a.tool {sources} END
            WHERE v.ts IS NOT NULL)
        SELECT *, sum(CASE WHEN gap IS NULL OR gap > {CLUSTER_GAP_US} THEN 1 ELSE 0 END)
                  OVER (PARTITION BY host, tool ORDER BY ts, event_uid ROWS UNBOUNDED PRECEDING) AS cluster
        FROM x""")
    clusters = con.execute(
        "SELECT host, tool, cluster, count(*), min(ts), max(ts), max(level), list(DISTINCT level ORDER BY level DESC), "
        "count(*) FILTER (WHERE NOT worked) FROM ov_clustered GROUP BY ALL ORDER BY host, tool, cluster").fetchall()
    if not clusters:
        return []
    # What each cluster's alerts are: Hayabusa's rule titles at medium level and above, by the keys analysis.hit_join
    # matches on, and the alerts' signatures. Each title counts the cluster's events it matched.
    titles: dict[tuple, list[tuple[str, int]]] = defaultdict(list)
    versions: dict[tuple, set[str]] = defaultdict(set)
    for host, tool, cluster, title, n, found in con.execute(f"""
            SELECT c.host, c.tool, c.cluster, h.rule_title, count(DISTINCT c.event_uid), list(DISTINCT h.tool_version)
            FROM ov_clustered c JOIN ov_ev v ON v.event_uid = c.event_uid
            JOIN events h ON h.tool = 'hayabusa' AND h.origin_host = v.origin_host AND h.log_channel = v.log_channel
                AND h.record_id = v.record_id AND h.source_file = v.source_file
            WHERE c.tool = 'hayabusa' AND {level_rank("h.rule_level")} >= 3 GROUP BY ALL
            UNION ALL
            SELECT c.host, c.tool, c.cluster, COALESCE(s.signature, f.signature, '(no signature)'),
                   count(DISTINCT c.event_uid), list(DISTINCT v.tool_version)
            FROM ov_clustered c JOIN ov_ev v ON v.event_uid = c.event_uid
            LEFT JOIN suricata_alerts s ON s.event_uid = c.event_uid LEFT JOIN fast_alerts f ON f.event_uid = c.event_uid
            WHERE c.tool <> 'hayabusa' GROUP BY ALL""").fetchall():
        titles[(host, tool, cluster)].append((title, n))
        versions[(host, tool, cluster)].update(found)
    rule_sets: dict[tuple, set[str]] = defaultdict(set)   # a Suricata run's rule set, such as ET Open 11310
    rules_of_run = {r.run_id: r.rules for r in runs if getattr(r, "rules", "")}
    for host, cluster, run in con.execute(
            "SELECT DISTINCT c.host, c.cluster, v.run_id FROM ov_clustered c JOIN ov_ev v ON v.event_uid = c.event_uid "
            "WHERE c.tool = 'suricata'").fetchall():
        if run in rules_of_run:
            rule_sets[(host, "suricata", cluster)].add(rules_of_run[run])
    leads = []
    for host, tool, cluster, n, first, last, top, levels, open_ in clusters:
        key = (host, tool, cluster)
        named = sorted(titles[key], key=lambda t: (-t[1], t[0]))
        shown = ", ".join(f"{title} ({n_:,} {ALERT_NOUN[tool][n_ != 1]})" for title, n_ in named[:TOP_TITLES])
        more = len(named) - TOP_TITLES
        why = (f"{'Rules' if tool == 'hayabusa' else 'Signatures'}: {shown}"
               + (f", and {more} more" if more > 0 else "") + ".")
        made = ", ".join(sorted(versions[key]))
        # An import's events carry the build that imported them as their tool version
        chips = [f"imported by glessner {made}" if tool == "import" else f"{tool_names.get(tool, tool)} {made}",
                 *sorted(rule_sets[key])]
        prefix, word = LEVEL_WORDS[tool]
        words = prefix + _join([word[lv] for lv in levels])
        noun = ALERT_NOUN[tool][n != 1]
        leads.append({"id": f"alerts:{tool}:{host}:{first}", "kind": "alerts", "level": TIERS[top], "tool": tool,
                      "title": f"{ALERT_NAME[tool]}, {words}: {n:,} {noun} on {host}, {_span(first, last)}",
                      "why": why, "chips": chips,
                      # The rules `why` names, for the page to link: each opens the rule's events on this host
                      **({"rules": [{"title": title, "count": n_} for title, n_ in named[:TOP_TITLES]],
                          "rules_more": max(more, 0)} if tool == "hayabusa" else {}),
                      "hosts": [host], "host": host, "start": first, "end": last, "first": first, "count": n,
                      "open": open_, "worked": open_ == 0, "action": "timeline"})
    return leads


def lead_events(con: duckdb.DuckDBPyConnection, tool: str, host: str, start: int, end: int) -> list[str]:
    """The events of an alert lead, which its action selects: the tool's alerts on the host from its first to its last
    time, as shown. A lead holds every such alert, since leads split only at gaps of more than 30 minutes."""
    if tool not in ALERT_SOURCE:
        raise ValueError(f"tool must be one of {sorted(ALERT_SOURCE)}")
    return [uid for (uid,) in con.execute(f"""
        WITH a AS ({ALERTS})
        SELECT a.event_uid FROM a JOIN events e ON e.event_uid = a.event_uid LEFT JOIN hosts h ON h.host = e.host
        WHERE a.tool = ? AND e.host = ? AND {TS} BETWEEN ? AND ? ORDER BY {TS}, a.event_uid""",
        [tool, host, start, end]).fetchall()]


def _rule_leads(con: duckdb.DuckDBPyConnection, state: State, report: dict[str, dict]) -> list[dict]:
    """One lead per suggestion rule that suggests any event, saying what the rule matches by its description. The
    built-in alert sources' events are the alert leads. Worked when nothing it suggests is pending."""
    rows = con.execute(f"""
        SELECT s.source, v.host, count(*), count(*) FILTER (WHERE m.event_uid IS NULL AND r.event_uid IS NULL), min(v.ts)
        FROM suggestions s JOIN ov_ev v ON v.event_uid = s.event_uid
        LEFT JOIN marks m ON m.event_uid = s.event_uid
        LEFT JOIN rejected r ON r.event_uid = s.event_uid AND r.source = s.source
        WHERE s.source NOT IN ('{HAYABUSA_SOURCE}', '{SURICATA_SOURCE}', '{IDS_ALERT_SOURCE}')
        GROUP BY ALL ORDER BY 1, 2""").fetchall()
    by_rule: dict[str, dict] = {}
    for source, host, n, pending, first in rows:
        lead = by_rule.setdefault(source, {"count": 0, "open": 0, "hosts": [], "first": None})
        lead["count"] += n
        lead["open"] += pending
        lead["hosts"].append(host)
        if first is not None and (lead["first"] is None or first < lead["first"]):
            lead["first"] = first
    leads = []
    for rule_id, found in sorted(by_rule.items()):
        info, stored = report.get(rule_id, {}), state.rules.get(rule_id, {})
        suggest = info.get("suggest", "")
        description = " ".join(str(info.get("description") or "").split())
        n, pending = found["count"], found["open"]
        title = (f"{rule_id} suggests {suggest.capitalize()} for {n:,} event{'s' if n != 1 else ''}: "
                 + (f"{pending:,} pending" if pending else "all decided"))
        leads.append({"id": f"rule:{rule_id}", "kind": "suggestions", "level": "suggestion", "rule": rule_id,
                      "title": title,
                      "why": description or f"The rule {rule_id} has no description; the Rules page shows what it matches.",
                      "chips": [f"rule: {rule_id}", "built in" if stored.get("builtin") else f"added by {stored.get('who', '')}"],
                      "hosts": found["hosts"], "first": found["first"], "count": n, "open": pending,
                      "worked": pending == 0, "action": "suggestions"})
    return leads


def _clock_leads(identity: Identity) -> list[dict]:
    """A host whose clock the check measured against the capture: open while the page shows its recorded times, and
    worked once its offset aligns it."""
    leads = []
    for h in identity.hosts.values():
        c = h.clock or {}
        aligned = c.get("state") == "agrees" and bool(h.offset_seconds)
        if c.get("state") != "suggest" and not aligned:
            continue
        direction = "behind" if c["skew_seconds"] < 0 else "ahead of"
        why = (f"Aligned: {h.host}'s times include its offset of {h.offset_seconds:+,g} s." if aligned
               else f"The page shows {h.host}'s times as its clock recorded them until it is aligned. Measured against "
                    f"{c['reference']}, {c['basis_text']}.")
        span = c.get("span") or {}
        leads.append({"id": f"clock:{h.host}", "kind": "clock", "level": "clock", "host": h.host, "hosts": [h.host],
                      "title": f"{h.host}'s clock ran {c['skew_text']} {direction} the capture",
                      "why": why, "chips": [f"clock check: {c['inliers']:,} of {c['pairs']:,} pairs, against {c['reference']}"],
                      "first": span.get("start"), "count": 0, "open": 0 if aligned else 1, "worked": aligned,
                      "action": "hosts"})
    return leads


def _progress(con: duckdb.DuckDBPyConnection, state: State, leads: list[dict], last: dict | None, orphans: int) -> dict:
    marks = dict(con.execute("SELECT label, count(*) FROM marks GROUP BY label").fetchall())
    # The bar: marks on events in the case, so a mark whose event a rerun dropped (an orphan) is in the counts only
    in_case = dict(con.execute("SELECT m.label, count(*) FROM marks m JOIN ov_ev v ON v.event_uid = m.event_uid "
                               "GROUP BY 1").fetchall())
    # Pending: events with a suggestion not rejected and no mark, as To investigate's count. Decided: the other events
    # with a suggestion, each marked or with every suggestion rejected.
    suggested, pending = con.execute(
        "SELECT (SELECT count(DISTINCT event_uid) FROM suggestions), (SELECT count(*) FROM suggested s "
        "LEFT JOIN marks m ON m.event_uid = s.event_uid WHERE m.event_uid IS NULL)").fetchone()
    flagged = marks.get("Malicious", 0) + marks.get("Suspicious", 0)
    nearby = con.execute(NEARBY).fetchone()[0] if flagged else 0
    # Copied first, as the overview reads without the lock: a note journaled meanwhile would change the dict as the loop
    # reads it, which raises
    notes = sum(1 for listed in list(state.notes.values()) for n in listed if not n.get("retracted"))
    return {"marks": {k: marks.get(k, 0) for k in ("Malicious", "Suspicious", "Authorized")},
            "in_case": {k: in_case.get(k, 0) for k in ("Malicious", "Suspicious", "Authorized")},
            "marked": sum(marks.values()), "orphans": orphans,
            # IDs the journal named that a case format upgrade couldn't place on one event (journal.unplaced_count)
            "unplaced": unplaced_count(state),
            "leads": len(leads), "leads_worked": sum(1 for lead in leads if lead["worked"]),
            "decided": suggested - pending, "pending": pending, "flagged": flagged, "unreviewed_nearby": nearby,
            "notes": notes, "last": last}


def _by_host(con: duckdb.DuckDBPyConnection, identity: Identity, leads: list[dict]) -> list[dict]:
    """Per host: its marked events, its events with a pending suggestion, and the leads with an event on it."""
    marks = dict(con.execute("SELECT v.host, count(*) FROM marks m JOIN ov_ev v ON v.event_uid = m.event_uid "
                             "GROUP BY 1").fetchall())
    pending = dict(con.execute("SELECT v.host, count(*) FROM suggested s JOIN ov_ev v ON v.event_uid = s.event_uid "
                               "LEFT JOIN marks m ON m.event_uid = s.event_uid WHERE m.event_uid IS NULL GROUP BY 1").fetchall())
    rows = []
    for host in sorted(identity.hosts):
        mine = [lead for lead in leads if host in lead["hosts"]]
        rows.append({"host": host, "marks": marks.get(host, 0), "pending": pending.get(host, 0), "leads": len(mine),
                     "leads_worked": sum(1 for lead in mine if lead["worked"])})
    return rows


def _hosts(con: duckdb.DuckDBPyConnection, identity: Identity, artifact_names: dict[str, str]) -> dict:
    """What each host holds, from one pass over its events: timeline events, the first and last time, the kinds of
    evidence loaded, and Hayabusa's rows; then its events with a hit, and its log clears. The first and last times are
    recorded ones plus the host's offset, which is the same for all of a host's events, so the pass reads no join: with
    the hosts joined for each event's shown time, it took 0.8 to 1.4 s at 10.4 million events, and 0.1 s without.

    A Hayabusa row stays under the host it was loaded under, and after a host split, one whose record names no
    computer stays on the split host while the event it matched moves. So the hits are counted by the lane of
    the event they matched, as the timeline draws them and the alert leads count them; the rows loaded under a host
    count apart, for a host that holds them and no events."""
    offsets = dict(con.execute("SELECT host, COALESCE(offset_us, 0) FROM hosts").fetchall())
    found: dict[str, dict] = {}
    for host, tool, artifact, timed, rows, first, last in con.execute(
            "SELECT host, tool, artifact, count(*) FILTER (WHERE ts_us IS NOT NULL), count(*), min(ts_us), max(ts_us) "
            "FROM events GROUP BY ALL ORDER BY 1, 3").fetchall():
        h = found.setdefault(host, {"events": 0, "untimed": 0, "first": None, "last": None, "hits": 0, "hit_rows": 0,
                                    "kinds": {}, "clears": []})
        if tool == "hayabusa":
            h["hit_rows"] += rows
            continue
        h["events"] += timed
        h["untimed"] += rows - timed
        h["kinds"][artifact] = h["kinds"].get(artifact, 0) + rows
        if first is not None:
            first, last = first + offsets.get(host, 0), last + offsets.get(host, 0)
            h["first"] = first if h["first"] is None else min(h["first"], first)
            h["last"] = last if h["last"] is None else max(h["last"], last)
    for host, n in con.execute("SELECT v.host, count(*) FROM hits x JOIN ov_ev v ON v.event_uid = x.event_uid "
                               "GROUP BY 1").fetchall():
        if host in found:
            found[host]["hits"] = n
    for uid, host, ts, code, channel, msg in con.execute(f"""
            SELECT e.event_uid, e.host, {TS}, e.event_code, e.log_channel, left(e.message, 120)
            FROM events e LEFT JOIN hosts h ON h.host = e.host WHERE {CLEAR_WHERE}
            ORDER BY e.host, {TS} NULLS LAST, e.event_uid""").fetchall():
        found[host]["clears"].append({"uid": uid, "host": host, "ts": ts, "code": code, "channel": channel, "msg": msg})
    rows_out, clears_out, no_logs = [], [], []
    for name in sorted(set(identity.hosts) | set(found)):
        h, ident = found.get(name), identity.hosts.get(name)
        if h is None:
            continue
        clock = (ident.clock if ident else None) or {}
        rows_out.append({
            "host": name, "role": ident.role if ident else "", "guessed": bool(ident and ident.role_source == "guess"),
            "os": (ident.os or {}).get("display", "") if ident else "", "events": h["events"], "untimed": h["untimed"],
            "first": h["first"], "last": h["last"], "hits": h["hits"], "hit_rows": h["hit_rows"],
            "kinds": [{"artifact": a, "label": artifact_names.get(a, a), "events": n}
                      for a, n in sorted(h["kinds"].items(), key=lambda kv: -kv[1])],
            "clock": _clock_text(ident, clock), "review": list(ident.review) if ident else []})
        clears_out += h["clears"]
        # A lane of a network sensor's or a firewall's records holds no event logs by its nature, so it isn't a gap
        if "evtx" not in h["kinds"] and not set(h["kinds"]) <= set(NETWORK_DEVICE_ARTIFACTS):
            no_logs.append(name)
    return {"rows": rows_out, "clears": clears_out, "no_event_logs": no_logs}


def _clock_text(ident, clock: dict) -> dict:
    """A host's clock in a few words, as the Hosts panel's clock check finds it."""
    offset = ident.offset_seconds if ident else 0
    state = clock.get("state") or "none"
    if state == "suggest":
        direction = "behind" if clock["skew_seconds"] < 0 else "ahead of"
        text = f"{clock['skew_text']} {direction} the capture, not aligned"
    elif state == "agrees":
        text = f"aligned to the capture ({offset:+,g} s)" if offset else "matches the capture"
    elif state == "disagree":
        text = "pairs with the capture disagree"
    elif ident and clock.get("reference") == ident.host:   # a sensor lane is measured against itself (clock.py)
        text = "the reference clock"
    else:
        text = f"not measured; offset {offset:+,g} s" if offset else "not measured"
    return {"state": state, "text": text, "flag": state in ("suggest", "disagree"), "reason": clock.get("reason", "")}


def _integrity(files: dict, checks: dict, journal_path: Path, build: str, alignment: str, identity: Identity) -> dict:
    """The evidence hashed at intake, with the files intake couldn't read and the folders it couldn't list counted
    apart (manifest_facts), the newest full re-hash and any problem found since the newest one that matched
    (intake.evidence_checks), with the files changed and those not re-read counted apart (problem_files), the lines of
    verification.jsonl that can't be read as a check, the journal's length, which times the page shows, and the
    build."""
    entries, _ = journal_facts(journal_path)
    changed, not_reread = problem_files(checks["problems"])
    offsets = {h.host: h.offset_seconds for h in identity.hosts.values() if h.offset_seconds}
    times = {"aligned": "UTC, aligned to the capture", "partly": "UTC, partly aligned to the capture",
             "recorded": "UTC, as each host's clock recorded them", "neither": "UTC, with clock offsets that aren't the "
             "capture's"}.get(alignment, "UTC, with clock offsets" if offsets else "UTC, as recorded")
    return {"evidence_files": files["hashed"], "added_files": files["added"], "unreadable": len(files["unreadable"]),
            "unlisted": len(files["unlisted"]), "algorithm": "SHA-256", "last_full": checks["last_full"],
            "problems": checks["problems"], "changed_files": len(changed), "not_reread": len(not_reread),
            "found_at": checks["found_at"], "unreadable_lines": checks["unreadable_lines"], "journal_entries": entries,
            "times": times, "offsets": offsets, "build": build}


# The entries after a recorded head, by action, in Integrity's words
ACTION_NOUNS = {"mark": ("mark", "marks"), "note": ("note", "notes"), "file_written": ("file record", "file records"),
                "tag": ("tag entry", "tag entries"), "case_setting": ("setting", "settings"),
                "followup": ("follow-up", "follow-ups"), "finding": ("finding entry", "finding entries"),
                "undo": ("correction", "corrections"), "case_open": ("open by a build", "opens by a build")}


# What an entry of these actions after the recorded head means. This app records the head right after it writes either,
# so one after it was written by something else, or by a build whose record failed: a rekey re-points every earlier
# entry's event IDs, and a chain_break puts earlier breaks on record
AFTER_HEAD_WORDS = {
    "case_upgrade": "A case_upgrade among them can change what earlier entries mean. This app records its head right "
                    "after it writes one, so check who added it.",
    "chain_break": "A chain_break among them puts earlier breaks on record. This app records its head right after it "
                   "writes one, so check who added it."}


def utc_minute(at: str) -> str:
    """An entry's or record's UTC time to the minute, as Integrity gives it."""
    return f"{at[:10]} {at[11:16]} UTC" if len(at or "") >= 16 else str(at or "")


def counted_actions(after: dict[str, int]) -> str:
    parts = []
    for action, n in sorted(after.items(), key=lambda kv: (-kv[1], kv[0])):
        one, many = ACTION_NOUNS.get(action, (f"{action} entry", f"{action} entries"))
        parts.append(f"{n:,} {one if n == 1 else many}")
    return ", ".join(parts)


def journal_row(journal: Journal, checked: str, found: Check | None = None, record: dict | None = None) -> dict:
    """Integrity's Journal row: how many entries, whether the chain
    is consistent, never "intact", which head kept outside the case it was compared with, when it was checked, and the
    head, which the page shows short with Copy. Without `found`, what the open found, from the journal's own read and
    Journal.recorded; with it, a full check's (Journal.full_check) and the `record` it compared. `summary` holds the two
    sentences a report prints."""
    if found is None:
        entries, on_record, head, seq = journal.chain.nonblank, journal.chain.on_record, journal.chain.head, \
            journal.chain.seq
        recorded, start, tail = journal.recorded, journal.chain.start, ""
    else:
        entries, on_record, head, seq = (found.chain.nonblank + (found.tail == "missing_lf"), found.chain.on_record,
                                         found.head, found.seq)
        recorded = ({"seq": record["seq"], "at": record.get("at", ""), "after": found.after}
                    if record and found.expected else None)
        start, tail = found.chain.start, found.tail
    breaks, read_only = journal.breaks, journal.read_only
    count = f"{entries:,} {'entry' if entries == 1 else 'entries'}"
    if breaks:
        first = breaks[0]
        where = f"line {first['line']}: " if first.get("line") else ""
        more = len(breaks) - 1
        state, text = "broken", [f"{count}. The journal was changed after it was written: {where}{first['text']}."
                                 + (f" {more:,} more break{'' if more == 1 else 's'} follow." if more else "")]
    elif on_record:
        last = on_record[-1]["seq"]
        state, text = "on_record", [f"{count}, consistent since #{last}: each names the one before it, and the break "
                                    f"before #{last} is on record."]
    else:
        state, text = "consistent", [f"{count}, consistent: each names the one before it."]
    if not any(b["kind"] in ("record_missing", "expected_missing") for b in breaks):
        if recorded is None:
            text.append("No head recorded outside the case to compare with.")
        elif recorded.get("after"):
            n = sum(recorded["after"].values())
            text.append(f"Matches the head this app recorded at {utc_minute(recorded.get('at', ''))}, entry "
                        f"#{recorded['seq']}. The {n:,} {'entry' if n == 1 else 'entries'} after it "
                        f"{'was' if n == 1 else 'were'} written without updating that record: "
                        f"{counted_actions(recorded['after'])}. Another computer, a failed write of the record, or a hand edit "
                        "can leave them.")
            for action, why in AFTER_HEAD_WORDS.items():
                if recorded["after"].get(action):
                    text.append(why)
        else:
            text.append(f"Matches the head this app recorded at {utc_minute(recorded.get('at', ''))}.")
    summary = list(text)
    text.append(f"Checked {'at open ' if found is None else ''}{utc_minute(checked)}.")
    if start and start.get("action") == "case_upgrade" and isinstance(start.get("seq"), int) and start["seq"] > 1:
        text.append(f"Entries #1 to #{start['seq'] - 1} are from before the chain, sealed by #{start['seq']}.")
    text += [f"{recovered_words(e)} (entry #{e['seq']})." for e in journal.recovered]
    text += [f"{p['text'][0].upper()}{p['text'][1:]}." for p in (found.problems if found else []) if p["kind"] == "side_file"]
    if tail == "missing_lf":
        text.append("The last entry lacks its line end; the next write adds it.")
    elif tail == "torn":
        text.append("The last line was cut short, most likely by a crash; the next write moves it aside.")
    elif tail == "writing":
        text.append("Bytes follow the last line while another process holds the journal's lock: a write in progress, "
                    "which this check can't vouch for. Check again in a moment.")
    return {"state": state, "text": text, "summary": summary, "head": head, "short": short(head), "seq": seq,
            "entries": entries, "read_only": read_only, "can_continue": bool(read_only) and journal._started(),
            "checked": checked}


def _span(first: int, last: int) -> str:
    """Two times in UTC to the second, the date once when they share it."""
    a, b = (from_us(t).strftime("%Y-%m-%d %H:%M:%S") for t in (first, last))
    if a == b:
        return f"{a} UTC"
    return f"{a} to {b[11:] if a[:10] == b[:10] else b} UTC"


def _join(words: list[str]) -> str:
    return words[0] if len(words) == 1 else ", ".join(words[:-1]) + f" and {words[-1]}"
