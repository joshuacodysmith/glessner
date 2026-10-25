"""Exports: a timeline file for other tools, the indicators file, and the Markdown report.

Timeline columns start with Timesketch's required datetime, timestamp_desc, and message, then use
ECS names, checked against Elastic's generated field list, and Winlogbeat names
where ECS has none. Exports go to the case's exports folder, which is inside the case and should
share its antivirus exclusion, because exported text quotes attacker payloads.
"""

from __future__ import annotations

import csv
import hashlib
import ipaddress
import json
import re
from contextlib import AbstractContextManager, nullcontext
from datetime import UTC, datetime
from pathlib import Path

import duckdb

from . import attack
from .accounts import SID_SQL
from .case import Case
from .caveats import CAVEAT_COLUMNS, caveat_for, caveats_for
from .caveats import table as caveat_table
from .clock import in_segment
from .events import from_us, id_table, well_formed
from .hashes import ALGORITHMS
from .identity import Identity
from .intake import Check, check_files, manifest_missing, manifest_text, unverified_text
from .journal import Journal, State, analyst, head_of
from .parsers.common import file_key, normalize_ip
from .pivot_names import extra_of, service_names, task_names
from .queries import BASE_FROM, BASE_WHERE, MARK_EXPR, TS, event_pairs
from .runner import FOUND_OUTPUT, RunRecord, read_runs, rules_text
from .tools import load_registry
from .version import build_id

SECURITY_SID = "json_extract_string(NULLIF(e.extra, ''), '$.SecurityUserID')"   # set by the EvtxECmd parser
# The account's SID: the one a looked-up name came from (accounts.py), which may be in the event's data rather than its
# System element, or else the System element's.
ACCOUNT_SID = f"COALESCE({SID_SQL}, {SECURITY_SID})"

TIME_SQL = f"strftime(make_timestamp({TS}), '%Y-%m-%dT%H:%M:%S.%fZ')"          # clock-adjusted
RECORDED_SQL = "strftime(make_timestamp(e.ts_us), '%Y-%m-%dT%H:%M:%S.%fZ')"    # as the artifact recorded it
# A network source's record: Suricata's EVE, Zeek's logs, and an imported IDS alert log. Their fields are
# in the event's own data, so each ECS column below reads the names each source writes, and is empty for a Windows event.
NETWORK = "e.artifact IN ('suricata', 'zeek', 'ids_alert')"


def _data(name: str) -> str:
    """The event's data field `name` as text; the name is quoted into the path, since EVE's hold dots."""
    return f"""json_extract_string(NULLIF(e.extra, ''), '$."{name}"')"""


def _zeek(name: str) -> str:
    return f"CASE WHEN e.artifact = 'zeek' THEN {_data(name)} END"


TIMELINE_COLUMNS = [
    (TIME_SQL, "datetime"), ("e.ts_desc", "timestamp_desc"), ("e.message", "message"),
    (TIME_SQL, "@timestamp"), (RECORDED_SQL, "recorded_datetime"),
    ("COALESCE(h.offset_us, 0) / 1000000.0", "host_clock_offset_seconds"),
    ("e.host", "host.name"), ("e.host_name_recorded", "winlog.computer_name"),
    # The host folder the event was loaded from, which differs from host.name after a split by recorded computer
    ("e.origin_host", "labels.collection_host"),
    ("e.event_code", "event.code"), ("e.event_provider", "event.provider"),
    # A network record's type is event.dataset, such as suricata.http, and not a Windows log channel
    (f"CASE WHEN {NETWORK} THEN '' ELSE e.log_channel END", "winlog.channel"),
    # An imported fast alert's log channel holds the alert's classification, which is no record type: its dataset is the
    # alert
    (f"CASE WHEN e.artifact = 'ids_alert' THEN 'ids_alert.alert' WHEN {NETWORK} THEN e.artifact || '.' || e.log_channel "
     "ELSE '' END", "event.dataset"),
    ("e.record_id", "winlog.record_id"),
    # An account known only by the SID in the event's System element is ECS's user.id,
    # not a name. A name looked up for the SID (accounts.py) is user.name, with the SID still user.id.
    (f"CASE WHEN e.user_name = {ACCOUNT_SID} THEN '' ELSE e.user_name END", "user.name"),
    ("e.user_domain", "user.domain"), (f"COALESCE({ACCOUNT_SID}, '')", "user.id"),
    ("e.source_ip", "source.ip"), ("e.source_port", "source.port"),
    ("e.dest_ip", "destination.ip"), ("e.dest_port", "destination.port"),
    ("e.source_workstation", "winlog.event_data.WorkstationName"),
    # winlog.logon.type holds the logon type's name (RemoteInteractive); the number is event_data.LogonType.
    ("e.logon_type", "winlog.event_data.LogonType"), ("e.logon_id", "winlog.logon.id"),
    ("e.process_executable", "process.executable"), ("e.process_command_line", "process.command_line"),
    ("e.process_parent_executable", "process.parent.executable"),
    ("e.process_parent_command_line", "process.parent.command_line"),
    ("e.file_path", "file.path"), ("e.registry_path", "registry.path"), ("e.registry_value", "registry.value"),
    ("e.registry_data", "registry.data.strings"),   # ECS's list of strings; one value here
    # Hayabusa's rule titles, or a network alert's signature with its ID and severity: Suricata's alert fields, or
    # an imported fast alert's signature, sid, and priority
    (f"COALESCE(array_to_string(x.titles, '; '), {_data('alert.signature')}, {_data('signature')}, '')", "rule.name"),
    (f"COALESCE({_data('alert.signature_id')}, {_data('sid')}, '')", "rule.id"),
    (f"COALESCE({_data('alert.severity')}, {_data('priority')}, '')", "event.severity"),
    # The connection, each identifier in its own column: a community ID, when the sensor's config writes one, and only
    # that; Suricata's flow ID; Zeek's uid
    (f"COALESCE({_data('community_id')}, '')", "network.community_id"),
    (f"COALESCE({_data('flow_id')}, '')", "network.flow_id"), (f"COALESCE({_zeek('uid')}, '')", "zeek.uid"),
    # ECS's url.full carries the scheme; a record with an HTTP host or URL is plain HTTP, so it reads http://
    (f"COALESCE('http://' || NULLIF(COALESCE({_data('http.hostname')}, '') || COALESCE({_data('http.url')}, ''), ''), "
     f"'http://' || NULLIF(COALESCE({_zeek('host')}, '') || COALESCE({_zeek('uri')}, ''), ''), '')", "url.full"),
    # EVE's dns.rrname (its v1 layout), the first query of its v2 layout, or Zeek's query
    (f"COALESCE({_data('dns.rrname')}, json_extract_string({_data('dns.queries')}, '$[0].rrname'), {_zeek('query')}, '')",
     "dns.question.name"),
    (f"COALESCE({_data('tls.sni')}, {_zeek('server_name')}, '')", "tls.server.name"),
    (f"COALESCE({_data('dhcp.client_mac')}, {_zeek('mac')}, '')", "client.mac"),
    (MARK_EXPR, "mark"), ("m.note", "mark_note"), ("e.tool", "tool"), ("e.tool_version", "tool_version"),
    ("e.artifact", "artifact"), ("e.source_file", "source_file"), ("e.run_id", "run_id"), ("e.event_uid", "event_uid"),
    # tags: ATT&CK tactics and techniques in ECS's threat fields, the analyst's own as tags (TAGS_JOIN)
    ("t.tactic_names", "threat.tactic.name"), ("t.tactic_ids", "threat.tactic.id"),
    ("t.techniques", "threat.technique.id"), ("t.own", "tags"),
]
# Each event's tags in one row, joined once. A subquery per column and row more than doubles an export's time, even
# with no tags at all.
TAGS_JOIN = """ LEFT JOIN (
    SELECT event_uid, string_agg(label, '; ' ORDER BY ord) FILTER (WHERE kind = 'tactic') AS tactic_names,
           string_agg(split_part(tag, ':', 2), '; ' ORDER BY ord) FILTER (WHERE kind = 'tactic') AS tactic_ids,
           string_agg(label, '; ' ORDER BY label) FILTER (WHERE kind = 'technique') AS techniques,
           string_agg(label, '; ' ORDER BY label) FILTER (WHERE kind = 'tag') AS own
    FROM tags GROUP BY event_uid) t ON t.event_uid = e.event_uid"""
FORMATS = {"csv", "jsonl"}
MARK_FILTERS = {"all", "marked", "flagged"}   # flagged: malicious or suspicious
# A spreadsheet may run a cell that begins with one of these as a formula (OWASP, CSV Injection): the operators =, +, -,
# and @ and their full-width forms, then tab, CR, and LF.
OPERATORS = ("=", "+", "-", "@", "\uff1d", "\uff0b", "\uff0d", "\uff20")
FORMULA_STARTS = (*OPERATORS, "\t", "\r", "\n")
_ESCAPED = {"-": "\\-", "\t": "\\t", "\r": "\\r", "\n": "\\n"}


def _char_class(chars) -> str:
    """A regular-expression class of `chars`, written in escapes that Python's re and DuckDB's RE2 read alike."""
    return "[" + "".join(_ESCAPED.get(c, c) for c in chars) + "]"


AT_START = f"^({_char_class(FORMULA_STARTS)})"
# Excel set to split on semicolons ignores the quotes inside a comma-separated line, so a cell also ends at a semicolon
# or a line break in its text, and an operator after one starts a formula. So does an operator after one double quote
# there: the file writes it doubled, and Excel reads the pair as an empty quoted value and runs what follows.
AFTER_SEPARATOR = f'([;\\r\\n]"?)({_char_class(OPERATORS)})'
_AFTER_SEPARATOR = re.compile(AFTER_SEPARATOR)


def spreadsheet_text(value):
    """A CSV cell's value as a spreadsheet must read it: a tab goes in front of an operator after a semicolon, CR, or
    LF, with or without one double quote between (AFTER_SEPARATOR), and in front of a first character in
    FORMULA_STARTS. A tab keeps the text a string in
    Excel, also after the file is saved and opened again. A value that isn't text is returned unchanged."""
    if not isinstance(value, str):
        return value
    value = _AFTER_SEPARATOR.sub("\\1\t\\2", value)
    return "\t" + value if value[:1] in FORMULA_STARTS else value


def spreadsheet_sql(column: str) -> str:
    """spreadsheet_text's rule as a DuckDB expression on a text column, in the same order. It stays two regexp_replace
    calls: a CASE on each cell's first character makes a large export several times slower."""
    after = f"regexp_replace({column}, '{AFTER_SEPARATOR}', '\\1' || chr(9) || '\\2', 'g')"
    return f"regexp_replace({after}, '{AT_START}', chr(9) || '\\1')"


def _timeline_csv(con: duckdb.DuckDBPyConnection, select: str, rows: str) -> tuple[str, str, str]:
    """The COPY query, its options, and the header line for a timeline CSV of `select` over `rows` (FROM and WHERE), in
    the timeline's order. Each text cell goes through spreadsheet_sql and is quoted, as OWASP's mitigation has it. The
    header is the PREFIX, which keeps it the column names alone, unquoted, as `HEADER true` writes them. With PREFIX and
    SUFFIX, DuckDB writes a newline between rows and none after the last, so the SUFFIX is that row's newline."""
    columns = [(f'"{name}"', kind) for name, kind, *_ in con.execute(f"DESCRIBE SELECT {select} {rows}").fetchall()]
    cells = [f"{spreadsheet_sql(c)} AS {c}" if kind == "VARCHAR" else c for c, kind in columns]
    text = [c for c, kind in columns if kind == "VARCHAR"]
    header = ",".join(name for _, name in TIMELINE_COLUMNS)
    query = (f"SELECT {', '.join(cells)} FROM (SELECT {select}, {TS} AS _sort_ts, e.event_uid AS _sort_uid {rows}) "
             "ORDER BY _sort_ts NULLS LAST, _sort_uid")
    return query, f"(FORMAT csv, HEADER false, FORCE_QUOTE ({', '.join(text)}), PREFIX '{header}\n', SUFFIX '\n')", header


WHOLE_CASE = {"marked", "flagged"}   # the scopes that cover the whole case whatever the window
STEMS = {"all": "timeline_all", "marked": "marked_events", "flagged": "flagged_events"}


def export_timeline(con: duckdb.DuckDBPyConnection, case: Case, identity: Identity, start: int | None, end: int | None,
                    fmt: str = "csv", marks: str = "all", extra: str = "") -> tuple[Path, int]:
    """Write events to exports/ and return the file and its row count. With `marks` all, the events whose clock-adjusted
    time is in [start, end); with marked or flagged, every such event in the case whatever the window, those with no
    time last, as the report lists them, and `start` and `end` are ignored. `extra` is a view filter's
    clause, applied only when the analyst asks; the file name then says "filtered". It only reads the database, so the
    server runs it on a reader, where marks and notes don't wait behind it."""
    if fmt not in FORMATS:
        raise ValueError(f"format must be one of {sorted(FORMATS)}")
    if marks not in MARK_FILTERS:
        raise ValueError(f"marks must be one of {sorted(MARK_FILTERS)}")
    mark_where = {"all": "", "marked": " AND m.label IS NOT NULL",
                  "flagged": " AND m.label IN ('Malicious', 'Suspicious')"}[marks]
    select = ", ".join(f'{expr} AS "{name}"' for expr, name in TIMELINE_COLUMNS)
    if marks in WHOLE_CASE:
        where = f"e.tool <> 'hayabusa'{mark_where}{extra}"
    else:
        low, high = identity.offset_bounds_us()
        start, end = int(start), int(end)   # integers only: COPY cannot take parameters, so these are inlined
        where = (f"{BASE_WHERE} AND e.ts_us >= {start - high} AND e.ts_us < {end - low} "
                 f"AND {TS} >= {start} AND {TS} < {end}{mark_where}{extra}")
    path = export_path(case, f"{STEMS[marks]}{'_filtered' if extra else ''}", fmt)
    # COPY cannot take a parameter for the file name. The name is built here from a timestamp; the case
    # folder path is quoted, with any single quote doubled, as SQL requires.
    target = path.as_posix().replace("'", "''")
    rows = f"FROM {BASE_FROM}{TAGS_JOIN} WHERE {where}"
    if fmt == "csv":
        query, options, header = _timeline_csv(con, select, rows)
    else:   # JSONL keeps every value as recorded
        query, options, header = f"SELECT {select} {rows} ORDER BY {TS} NULLS LAST, e.event_uid", "(FORMAT json)", ""
    # The count is COPY's own: on a reader without the lock, a mark between a separate count and the COPY would make the
    # count disagree with the file
    (count,) = con.execute(f"COPY ({query}) TO '{target}' {options}").fetchone()
    if header and not count:   # with no rows, the PREFIX and SUFFIX leave a blank line after the header
        path.write_text(header + "\n", encoding="utf-8", newline="")
    return path, count


def file_payload(case: Case, path: Path, *, kind: str, fmt: str, rows: int, scope: dict | None = None,
                 filters: dict | None = None, head: tuple[str, int] | None = None) -> dict:
    """A file_written entry's payload for a file the case wrote: its path inside the case folder with /
    separators, what it is, its scope and filters, its rows, and its length and SHA-256, read in pieces so a large
    timeline isn't held in memory. `head`, for a file that prints one, is that head and its entry's number. Read before
    the journal's held context is taken: nothing slow runs under it."""
    digest, size = hashlib.sha256(), 0
    with path.open("rb") as f:
        while chunk := f.read(1 << 20):
            digest.update(chunk)
            size += len(chunk)
    payload = {"path": path.relative_to(case.folder).as_posix(), "kind": kind, "format": fmt,
               "scope": scope or {"marks": "all"}, "filters": filters, "rows": rows, "bytes": size,
               "sha256": digest.hexdigest()}
    if head:
        payload.update(journal_head=head[0], head_seq=head[1])
    return payload


def record_file(journal: Journal, payload: dict, path: Path, lock: AbstractContextManager | None = None) -> tuple[dict, str]:
    """Journal a file the case wrote, under `lock` when given (the server's app.lock), and return the entry and the head
    after it, which the page and the command line show with the file. A refused entry removes the file, so
    no file sits in exports without its record. The file stays when the journal grew
    meanwhile: the entry may be written even though the append failed after its write, and a file without a record is
    the milder fault than a record of a file that was deleted."""
    size = journal.path.stat().st_size
    try:
        with lock or nullcontext():
            entry = journal.append("file_written", **payload)
    except BaseException:
        if journal.path.stat().st_size == size:
            path.unlink(missing_ok=True)
        raise
    return entry, head_of(entry)


def head_lines(journal: dict) -> list[str]:
    """The report's journal part: the chain's state and the recorded head's sentence, as Integrity gives
    them, the head when written, and why that head can't vouch for this file. `journal` is overview.journal_row's,
    with the head and entry number taken from the state the report reads."""
    return [f"Journal: {_md(' '.join(journal['summary']))}", "",
            f"Journal head when written: `{journal['head']}` (entry #{journal['seq']})", "",
            "This file's SHA-256 is in a later journal entry, so the head above names the state this file shows but "
            "can't vouch for the file itself. Check the file against the head shown when it was written, or a later "
            "close's.", ""]


# The report, in seven sections. The summary and the findings are the analyst's words; the
# app adds the rest from the case. The caveats of the marked evidence follow the timeline, since they are about it.
SECTIONS = ("Summary", "Findings", "Timeline of marked events", "Indicators", "Hosts and clocks",
            "Evidence and integrity", "Method")
REPORT_CHECK = "full check when writing the report"   # the re-hash's reason in verification.jsonl
NO_SUMMARY = ("No summary has been written. The analyst writes it on the Findings page, in their own words; the app "
              "writes none of it.")
FINDING_EVENTS = 25   # supporting events a finding's section lists before "and N more"


def write_report(con: duckdb.DuckDBPyConnection, case: Case, identity: Identity, manifest: dict[str, str],
                 state: State, extra: str = "", filter_note: str = "", journal: dict | None = None,
                 checked: Check | None = None) -> tuple[Path, int]:
    """Write the Markdown report to exports/ and return the file and the number of marked events it lists. `checked` is
    the evidence re-hash the caller already ran (see report_text)."""
    text, count = report_text(con, case, identity, manifest, state, extra, filter_note, journal, checked=checked)
    path = export_path(case, "report", "md")
    path.write_text(text, encoding="utf-8")
    return path, count


def report_text(con: duckdb.DuckDBPyConnection, case: Case, identity: Identity, manifest: dict[str, str], state: State,
                extra: str = "", filter_note: str = "", journal: dict | None = None, *, rehash: bool = True,
                checked: Check | None = None, listed: int | None = None) -> tuple[str, int]:
    """The report's text and the number of marked events it lists. `state` is the journal's: the summary (the
    `report_summary` setting), the findings, and the notes. With a view filter (`extra`, described by `filter_note`),
    the timeline lists only the filtered events and the report says so at the top. `journal` is the journal's row and
    head for the integrity part (head_lines). A preview (`rehash` false) skips the evidence re-hash and says so. The
    re-hash is `checked` when the caller already ran it, so it can run outside the locks the caller holds. `listed`
    limits the timeline to its first events, and says so; the counts, the tactics, the caveats, and the indicators still
    cover every marked event."""
    # Events without a time come last: accepting a rule's suggestions can flag one, since rules match them too. Ties
    # go by ID, so two reports of a case number its events alike.
    rows = con.execute(f"""
        SELECT e.event_uid, {TS}, e.host, m.label, m.note, e.message, e.tool, e.tool_version, e.run_id,
               e.artifact, e.source_file, e.source_record, array_to_string(x.titles, '; '), COALESCE(h.offset_us, 0)
        FROM {BASE_FROM} WHERE m.label IN ('Malicious', 'Suspicious'){extra}
        ORDER BY 2 NULLS LAST, e.event_uid""").fetchall()
    # A run is listed under the host it ran on, not once per lane of a split by recorded computer. An import
    # can load several hosts in one run, which then go by host.
    runs = con.execute("SELECT run_id, tool, tool_version, origin_host, count(*) FROM events GROUP BY ALL "
                       "ORDER BY run_id, origin_host").fetchall()
    records = {r.run_id: r for r in read_runs(case)}   # a record this build can't read fails the report, by its file's name
    splits = con.execute("SELECT origin_host, list(DISTINCT host ORDER BY host) FROM events WHERE host <> origin_host "
                         "GROUP BY 1 ORDER BY 1").fetchall()
    uids = [r[0] for r in rows]
    tagged: dict[str, list[tuple]] = {}   # event_uid -> (kind, label, ord), for the ATT&CK lines
    if rows:
        wanted = id_table(con, "report_events", uids)
        for uid, kind, label, ord_ in con.execute(f"SELECT event_uid, kind, label, ord FROM tags WHERE event_uid IN "
                                                  f"(SELECT v FROM {wanted}) ORDER BY ord, label").fetchall():
            tagged.setdefault(uid, []).append((kind, label, ord_))
    pairs = event_pairs(con, uids)   # each event's other half in the capture or on its host
    kinds = _kinds(con, uids)        # what each marked event is, for the caveats
    findings = sorted(state.findings.items())
    in_finding: dict[str, list[str]] = {}   # event_uid -> "1. Title" for each open finding it supports
    for number, (_, f) in enumerate(findings, 1):
        if not f["retired"]:
            for uid in f["targets"]:
                in_finding.setdefault(uid, []).append(f"{number}. {f['title']}")
    if not rehash:
        check = "The evidence is re-hashed when the report is written, not for a preview."
    elif not case.manifest_path.exists():
        # Once the journal records manifest.jsonl, a missing one is a change, not a case still waiting for intake
        check = (manifest_missing(state.manifests) if state.manifests
                 else "No intake manifest exists, so evidence hashes were not checked.")
    else:
        check = _evidence_check(checked if checked is not None else check_files(case, reason=REPORT_CHECK))
    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    malicious = sum(1 for r in rows if r[3] == "Malicious")
    untimed = sum(1 for r in rows if r[1] is None)
    summary = str(state.settings.get("report_summary") or "").replace("\r\n", "\n").strip()
    heading = [f"## {n}. {name}" for n, name in enumerate(SECTIONS, 1)]
    lines = [
        f"# Report: {_md(case.settings.name)}",
        "",
        f"Generated {now} by glessner {build_id()} for {_md(case.settings.analyst)}. "
        f"The summary and the findings are the analyst's words. The app adds the {len(rows)} events the analyst marked "
        f"malicious ({malicious}) or suspicious ({len(rows) - malicious}), in time order"
        f"{f', with those that have no time recorded ({untimed}) last' if untimed else ''}. It also adds the indicators "
        "from the Malicious marks, the hosts and their clocks, the evidence check, and the method.",
        "",
        *([f"**Filtered.** This report applies the analyst's view filter, so marked events outside it are left out of "
           f"the timeline and the indicators. {_md(filter_note)}", ""] if extra else []),
        heading[0], "", summary or NO_SUMMARY, "",
        heading[1], "", *_findings_section(con, findings, uids, kinds), "",
        heading[2], "",
    ]
    if not rows:
        lines.append("No events are marked malicious or suspicious yet.")
    for number, row in enumerate(rows[:listed], 1):
        lines += _event_lines(number, row, identity, state.notes, tagged.get(row[0], []), pairs.get(row[0]), manifest,
                              records, in_finding.get(row[0], []))
    if listed is not None and len(rows) > listed:
        lines += ["", f"The preview lists the first {listed:,} of {len(rows):,} events. Write report lists them all."]
    lines += _tactics_section(rows, tagged)
    lines += _caveats_section(rows, kinds)
    lines += ["", heading[3], "", *_indicators_section(indicators(con, [r[0] for r in rows if r[3] == "Malicious"], identity),
                                                      malicious)]
    lines += ["", heading[4], "", *_hosts_section(identity, splits)]
    lines += ["", heading[5], "", f"Evidence folder: `{case.settings.evidence_path}`. {check}", "",
              *(head_lines(journal) if journal else [])]
    lines += [heading[6], "", f"Written by glessner {build_id()}. The tool runs loaded in this case, by the host each ran "
              "on; the marks and the findings are the analyst's, and a rule's or a tool's suggestion counts only once the "
              "analyst accepts it.", "",
              "| Run | Tool | Version | Host | Events | Rules |", "|---|---|---|---|---|---|"]
    specs = load_registry()
    lines += [f"| `{run_id}` | {tool} | {version} | {_md(host)} | {count:,} | "
              f"{_md(rules_text(records[run_id], specs)) if run_id in records else ''} |"
              for run_id, tool, version, host, count in runs]
    lines += _tool_files_lines(list(dict.fromkeys(run[0] for run in runs)), records)
    return "\n".join(lines) + "\n", len(rows)


def _tool_files_lines(run_ids: list[str], records: dict[str, RunRecord]) -> list[str]:
    """The files the runs in the Method table ran with, each distinct set once with the runs that recorded it, in the
    order of the first of them. A run with no record, or with none of the files (RunRecord.tool_files), is left out; none
    of the runs recording any leaves no lines."""
    by_files: dict[tuple, list[str]] = {}
    for run_id in run_ids:
        if run_id in records and records[run_id].tool_files:
            by_files.setdefault(tuple(sorted(records[run_id].tool_files.items())), []).append(run_id)
    if not by_files:
        return []
    lines = ["", "Files each tool ran with, as its runs recorded them, by SHA-256. A path that ends in / is a folder, hashed "
                 "as the lines `sha256sum` prints for its files, by their paths in the folder with forward slashes, sorted in "
                 "code point order, leaving out a .git folder and links.", ""]
    for files, ids in by_files.items():
        lines.append(f"- {'Run' if len(ids) == 1 else 'Runs'} {', '.join(f'`{run_id}`' for run_id in ids)}:")
        lines += [f"  - `{_tick(path)}`: `{sha}`" for path, sha in files]
    return lines


def cited_files(path: str, record: RunRecord | None, tool_version: str) -> list[str]:
    """The evidence files whose intake hashes an event cites, which the Event page and the report share. `path` is the
    event's source file, `record` its run's record or None, and `tool_version` its own. A tool's run or an import read the
    file its event names. Output found in the evidence names the files its tool read, which its load never read, so its
    event cites the output files its run read and hashed (RunRecord.inputs), or the one the event names when it is one of
    them, as found Amcache, SRUM, and Autoruns output name their CSV and found Suricata output its EVE file. With no record
    of its run, which the tool version tells as found output still, it cites none."""
    from_output = record.from_output if record else tool_version == FOUND_OUTPUT
    if not from_output:
        return [path]
    inputs = [well_formed(p) for p in record.inputs] if record else []
    return [path] if path in inputs else inputs


def _kinds(con: duckdb.DuckDBPyConnection, uids: list[str]) -> dict[str, dict]:
    """What each event is, as the caveat table reads it (CAVEAT_COLUMNS), by event ID."""
    if not uids:
        return {}
    wanted = id_table(con, "report_kinds", uids)
    found = con.execute(f"SELECT event_uid, {', '.join(CAVEAT_COLUMNS)} FROM events WHERE event_uid IN "
                        f"(SELECT v FROM {wanted})").fetchall()
    return {r[0]: dict(zip(CAVEAT_COLUMNS, r[1:], strict=True)) for r in found}


def _sources(sources: list[dict]) -> str:
    """A caveat's sources, each a link when public, or the project file by name."""
    return ", ".join(f"[{_md(s['title'])}]({s['url']})" if s.get("url") else f"{_md(s['title'])} ({_tick(s.get('path'))})"
                     for s in sources)


def _findings_section(con: duckdb.DuckDBPyConnection, findings: list[tuple[int, dict]], marked: list[str],
                      kinds: dict[str, dict]) -> list[str]:
    """The findings the analyst wrote, in the order of their adds, each with its severity, ATT&CK techniques, who wrote
    it, its narrative, its supporting events (as entries of the timeline when marked), and the caveats of its events'
    types. Retired findings are named at the end and left out."""
    if not findings:
        return ["No findings have been written. A finding is the analyst's conclusion, with the events that support "
                "it, written on the Findings page."]
    entry = {uid: n for n, uid in enumerate(marked, 1)}
    targets = list(dict.fromkeys(u for _, f in findings if not f["retired"] for u in f["targets"]))
    events: dict[str, tuple] = {}
    if targets:
        wanted = id_table(con, "finding_targets", targets)
        events = {r[0]: r[1:] for r in con.execute(
            f"SELECT e.event_uid, {TS}, e.host, e.event_code, left(e.message, 160), {MARK_EXPR} FROM {BASE_FROM} "
            f"WHERE e.event_uid IN (SELECT v FROM {wanted})").fetchall()}
        kinds = {**kinds, **_kinds(con, [u for u in targets if u not in kinds])}
    lines, retired = [], []
    for number, (_, f) in enumerate(findings, 1):
        if f["retired"]:
            reason = f'; reason: "{_md(f["retired"].get("reason") or "")}"' if f["retired"].get("reason") else ""
            retired.append(f"{number}. {_md(f['title'])} (retired {_md(f['retired']['at'][:16].replace('T', ' '))} UTC "
                           f"by {_md(analyst(f['retired']))}{reason})")
            continue
        when = (f"edited {_md(f['edited']['at'][:16].replace('T', ' '))} UTC by {_md(analyst(f['edited']))}" if f["edited"]
                else f"added {_md(f['added']['at'][:16].replace('T', ' '))} UTC by {_md(analyst(f['added']))}")
        n = len(f["targets"])
        lines += [f"### {number}. {_md(f['title'])}", "",
                  f"{_md(f['severity'])}. ATT&CK: {_md(attack.worded(f['techniques'])) if f['techniques'] else 'none given'}. "
                  f"{n:,} supporting event{'' if n == 1 else 's'}; {when}.", ""]
        if f["narrative"].strip():
            lines += [*_md(f["narrative"]).split("\n"), ""]   # the analyst's words, one paragraph
        for uid in f["targets"][:FINDING_EVENTS]:
            ev = events.get(uid)
            if ev is None:
                lines.append(f"- An event no longer loaded: ID `{_tick(uid)}`")
                continue
            ts, host, code, message, mark = ev
            where = f"Entry {entry[uid]}" if uid in entry else f"Not in the timeline ({mark})"
            when = "No time recorded" if ts is None else _time(ts)
            lines.append(f"- {where}: {when}, {_md(host)}, {_md(code + ' ' if code and not message.startswith(code) else '')}"
                         f"{_md(message)}")
        if n > FINDING_EVENTS:
            lines.append(f"- and {n - FINDING_EVENTS:,} more")
        if not n:
            lines.append("- No events linked yet.")
        caveats = caveats_for([kinds[u] for u in f["targets"] if u in kinds])
        if caveats:
            lines += ["", "Does not prove:", "",
                      *(f"- **{_md(c['name'])}.** {_md(c['text'])} Source{'' if len(c['sources']) == 1 else 's'}: "
                        f"{_sources(c['sources'])}." for c in caveats)]
        lines.append("")
    if retired:
        lines += [f"Retired finding{'' if len(retired) == 1 else 's'}, left out: " + "; ".join(retired) + ".", ""]
    return lines[:-1] if lines and lines[-1] == "" else lines


def _caveats_section(rows: list[tuple], kinds: dict[str, dict]) -> list[str]:
    """The "What the marked evidence does not prove" part: each caveat whose kind is among the marked events, with how
    many of them it covers, in the table's order, with its text and sources; none for a kind the table
    doesn't name."""
    counts: dict[str, int] = {}
    for row in rows:
        found = caveat_for(kinds.get(row[0], {}))
        if found:
            counts[found["id"]] = counts.get(found["id"], 0) + 1
    lines = ["", "### What the marked evidence does not prove", "",
             "A fixed, sourced caveat for each kind of record among the marked events. The app writes none of them; a "
             "kind the table doesn't name has none yet.", ""]
    if not counts:
        return lines + ["No caveat is on file for the kinds of record marked."]
    for row in caveat_table():
        if row["id"] in counts:
            n = counts[row["id"]]
            lines.append(f"- **{_md(row['name'])}** ({n:,} marked): {_md(row['text'])} "
                         f"Source{'' if len(row['sources']) == 1 else 's'}: {_sources(row['sources'])}.")
    return lines


# ---------- Indicators: values from the Malicious marks, read from parsed fields only ----------

INDICATOR_TYPES = ("IP address", "Domain", "SHA-256", "SHA-1", "MD5", "Account", "File", "Service", "Task")


# Security events whose process path is the logon process the account went through: the 4624 and 4625 logons. It is an
# ordinary Windows binary, not what the marked event is about. A 4648's process is the one that used the explicit
# credentials, such as PsExec run with -u, so it stays an indicator; a 4672 names no process.
LOGON_PROCESS_CODES = {"4624", "4625"}


# The note on a File value in the Windows folder's own files or below its System32, SysWOW64, or Sysnative folders: it
# may be a system tool the attacker used, which a blocklist built from the file would block.
SYSTEM_TOOL_NOTE = "In the Windows folder: may be a system tool the attacker used. Check before you block it."
SYSTEM_FOLDERS = frozenset({"system32", "syswow64", "sysnative"})
# The registry parser's name for a domain controller's system volume, which file_key reads as a drive letter
SYSTEM_VOLUME = re.compile(r"^SYSVOL(?=[\\/])", re.IGNORECASE)


def _in_windows_folder(path: str) -> bool:
    """Whether a file path is one of the Windows folder's own files, or is below its System32, SysWOW64, or Sysnative
    folder, on any drive, in any case, and with either slash. The path is read as the file key reads it (file_key), so a
    prefetch volume, a device path, NT's \\??\\ and \\SystemRoot, a variable such as %SystemRoot%, and a doubled backslash
    count; SYSVOL is a domain controller's system volume, as the registry parser reads it. A path that starts with one
    forward slash is a URL or Unix path, and a path with no root names no volume, so neither counts. The Windows folder's
    other subfolders, such as Temp and Tasks, where a dropped file can sit, and look-alike names do not count. Everything
    below System32, SysWOW64, and Sysnative does, such as System32\\Tasks and System32\\spool."""
    below = file_key(SYSTEM_VOLUME.sub("C:", path)).split("\\")[1:]
    return len(below) > 1 and below[0] == "windows" and (len(below) == 2 or below[1] in SYSTEM_FOLDERS)


def _address(name: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """The address a value is, with an IPv6 zone ("%12") dropped, or None for a name."""
    try:
        return ipaddress.ip_address(name.split("%", 1)[0])
    except ValueError:
        return None


def _is_address(name: str) -> bool:
    return _address(name) is not None


def _local(name: str) -> bool:
    """An address that names no host and so is no indicator: the unspecified and loopback ones, the broadcast address (a
    DHCP discover goes to it), multicast, and link-local (the capture's own chatter)."""
    ip = _address(name)
    return ip is not None and (ip.is_unspecified or ip.is_loopback or ip.is_multicast or ip.is_link_local
                               or ip == ipaddress.IPv4Address("255.255.255.255"))


def indicators(con: duckdb.DuckDBPyConnection, uids: list[str], identity: Identity) -> list[dict]:
    """The indicator values among these events, which the caller takes from the Malicious marks: each as type, value,
    the number of events carrying it, the first and last clock-adjusted time seen (None for events with no time), and a
    note, "" unless the value is a File in the Windows folder (SYSTEM_TOOL_NOTE).
    Read from parsed fields only, never guessed from free text: the address columns, less the case's own hosts'
    addresses and the local ones (_local); a DNS name, an HTTP host, or a TLS server name from a network record's data; the
    hashes column; the account; the process and file path columns, less a logon's process (LOGON_PROCESS_CODES); and the
    service and task names the pivots read.
    Values are grouped without case, under the first spelling seen, in time order."""
    if not uids:
        return []
    own = {normalize_ip(ip) for h in identity.hosts.values() for ip in h.ips}
    wanted = id_table(con, "indicator_events", uids)
    found = con.execute(f"""
        SELECT e.event_uid, {TS}, e.artifact, e.event_code, e.log_channel, e.event_provider, e.source_ip, e.dest_ip,
               e.user_name, e.user_domain, e.process_executable, e.file_path, e.registry_path, e.message,
               COALESCE(e.hashes, ''), e.extra
        FROM events e LEFT JOIN hosts h ON h.host = e.host WHERE e.event_uid IN (SELECT v FROM {wanted})
        ORDER BY 2 NULLS LAST, e.event_uid""").fetchall()
    groups: dict[tuple[str, str], dict] = {}
    for (uid, ts, artifact, code, channel, provider, src, dst, user, domain, process, file, registry, message, hashes,
         extra) in found:
        ev = {"artifact": artifact, "event_code": code, "log_channel": channel, "event_provider": provider,
              "registry_path": registry, "message": message, "extra": extra}
        values = [("IP address", ip) for ip in (src, dst) if ip and ip not in own and not _local(ip)]
        # An HTTP host can be an address rather than a name, as a download from a dotted quad is
        values += [("IP address" if _is_address(name) else "Domain", name) for name in _names(ev)
                   if not (_is_address(name) and (normalize_ip(name) in own or _local(name)))]
        values += [(ALGORITHMS[len(h)], h) for h in hashes.split() if len(h) in ALGORITHMS]
        if user and user != "-":
            values.append(("Account", f"{domain}\\{user}" if domain else user))
        if artifact == "evtx" and channel == "Security" and code in LOGON_PROCESS_CODES:
            process = ""   # the logon process (winlogon.exe, svchost.exe), no sign of what the marked logon did
        values += [("File", p) for p in (process, file) if p]
        values += [("Service", s) for s in service_names(ev)] + [("Task", t) for t in task_names(ev)]
        for kind, value in values:
            key = (kind, value.lower())
            note = SYSTEM_TOOL_NOTE if kind == "File" and _in_windows_folder(value) else ""
            g = groups.setdefault(key, {"type": kind, "value": value, "events": set(), "first": None, "last": None,
                                        "note": note})
            g["events"].add(uid)
            if ts is not None:
                g["first"] = ts if g["first"] is None else min(g["first"], ts)
                g["last"] = ts if g["last"] is None else max(g["last"], ts)
    order = {kind: n for n, kind in enumerate(INDICATOR_TYPES)}
    out = [{**g, "events": len(g["events"])} for g in groups.values()]
    out.sort(key=lambda g: (order[g["type"]], g["first"] is None, g["first"] or 0, g["value"].lower()))
    return out


def _names(ev: dict) -> list[str]:
    """The names a network record's data gives: EVE's dns.rrname or its v2 queries' rrname, http.hostname, and tls.sni,
    or Zeek's query, host, and server_name."""
    if ev["artifact"] not in ("suricata", "zeek"):
        return []
    x = extra_of(ev)
    names = []
    if ev["artifact"] == "suricata":
        names += [x.get("dns.rrname"), x.get("http.hostname"), x.get("tls.sni")]
        try:
            queries = json.loads(x.get("dns.queries") or "[]")
        except ValueError:
            queries = []
        names += [q.get("rrname") for q in queries if isinstance(q, dict)]
    else:
        names += [x.get("query"), x.get("host"), x.get("server_name")]
    return list(dict.fromkeys(n.strip() for n in names if isinstance(n, str) and n.strip()))


def _indicators_section(found: list[dict], malicious: int) -> list[str]:
    """The report's Indicators table, with what it is taken from."""
    lines = [f"Taken only from the {malicious:,} event{'' if malicious == 1 else 's'} marked Malicious, from fields the "
             "tools parsed: addresses, domains, hashes, accounts, file paths, services, and tasks. Nothing is inferred "
             "from free text, and the addresses of the case's own hosts are left out. The Indicators export writes the "
             "same table as indicators.csv.", ""]
    if not malicious:
        return lines + ["No event is marked Malicious, so there are no indicators."]
    if not found:
        return lines + ["The events marked Malicious carry no parsed value of these kinds."]
    lines += ["| Type | Value | Marked events | First seen | Last seen | Note |", "|---|---|---|---|---|---|"]
    seen = lambda us: "No time recorded" if us is None else _time(us)
    lines += [f"| {g['type']} | `{_tick(g['value'])}` | {g['events']:,} | {seen(g['first'])} | {seen(g['last'])} | {g['note']} |"
              for g in found]
    return lines


def write_indicators(case: Case, found: list[dict]) -> Path:
    """The indicators as indicators.csv in exports/: type, value, marked events, first and last seen, and the note. Text
    cells follow the timeline CSV's rule (spreadsheet_text, each quoted); the header is the column names alone, unquoted."""
    path = export_path(case, "indicators", "csv")
    with path.open("w", encoding="utf-8", newline="") as f:
        csv.writer(f).writerow(["type", "value", "marked_events", "first_seen", "last_seen", "note"])
        out = csv.writer(f, quoting=csv.QUOTE_NONNUMERIC)
        for g in found:
            out.writerow([spreadsheet_text(v) for v in (g["type"], g["value"], g["events"],
                                                         *(_iso(us) for us in (g["first"], g["last"])), g["note"])])
    return path


def _iso(us: int | None) -> str:
    """A time as the timeline files write theirs, or "" for none."""
    return "" if us is None else f"{from_us(us):%Y-%m-%dT%H:%M:%S.%f}Z"


def _evidence_check(found: Check) -> str:
    """What the report's re-hash found (_files_check), then manifest.jsonl against its record in the journal, when the
    check compared one."""
    return " ".join(filter(None, (_files_check(found), found.manifest and manifest_text(found.manifest))))


def _files_check(found: Check) -> str:
    """What the report's re-hash found of the evidence files. "Every evidence file" only when it checked every one: a
    file intake couldn't read has no hash, so it can't count as matching. A manifest that lists no file says so, since
    nothing was there to match. A folder walk couldn't list counts as no file, since how many files it holds is unknown,
    and has a sentence of its own (unverified_text)."""
    n, problems, unread = found.checked, found.problems, found.unverified
    total = n + len(unread) - found.folders
    if not n and not unread:
        return "No evidence file was re-hashed when this report was written: the intake manifest lists none."
    if not unread:
        text = f"Every evidence file ({n:,}) was re-hashed when this report was written"
    elif not n:
        text = "No evidence file was re-hashed when this report was written"
    elif total == n:
        text = f"{n:,} evidence {'file was' if n == 1 else 'files were'} re-hashed when this report was written"
    else:
        text = (f"{n:,} of the {total:,} evidence files {'was' if n == 1 else 'were'} re-hashed when this "
                f"report was written")
    if problems:
        text += f". {len(problems)} do not match the intake manifest: {_md('; '.join(problems[:10]))}."
    elif not unread:
        text += ", and all match the intake manifest."
    else:
        text += ", and none differs from the intake manifest." if n else "."
    return " ".join(filter(None, (text, unverified_text(unread, _md))))


def _hosts_section(identity: Identity, splits: list[tuple]) -> list[str]:
    """The Hosts table, each split host's lanes, and why a host's times may not line up with other sources'. A role the
    analyst hasn't confirmed says it was guessed."""
    lines = ["| Host | Role | OS | Names | IPs | Clock offset |", "|---|---|---|---|---|---|"]
    clock_notes = []
    guessed = any(h.role_source == "guess" for h in identity.hosts.values())
    for h in identity.hosts.values():
        offset = f"{h.offset_seconds:+g} s" if h.offset_seconds else "none"
        system = h.os.get("display") or "Not recorded"   # a network lane has no SOFTWARE hive
        clock, said = h.clock or {}, []
        if clock.get("state") == "suggest":
            offset += f"; {clock['seconds']:+,.1f} s suggested, not applied"
            applied = f"The offset applied is {h.offset_seconds:+g} s" if h.offset_seconds else "It isn't applied"
            said += [f"Its events pair with the capture's ({clock['reference']}) and suggest a clock offset of "
                     f"{clock['display']}, {clock['basis_text']}.", clock["zone_note"],
                     f"{applied}, so its times may not line up with the capture's."]
        if clock.get("steps"):
            said += [clock["steps_text"], clock["span_note"] or "Its events on either side of a change are on different clocks."]
        if said:
            clock_notes.append(f"- **{_md(h.host)}.** " + " ".join(_md(s) for s in said if s))
        role = f"{h.role} (guessed)" if h.role_source == "guess" else h.role
        lines.append(f"| {_md(h.host)} | {_md(role)} | {_md(system)} | {_md(', '.join(h.names))} | "
                     f"{_md(', '.join(h.ips))} | {offset} |")
    if guessed:
        lines += ["", "A role marked (guessed) is the app's guess from the host's names and evidence, which the analyst "
                      "hasn't confirmed."]
    for origin, lanes in splits:
        lines += ["", f"{_md(origin)}'s event logs were split by the computer each event records, into "
                      f"{_md(', '.join(lanes))}. Evidence that isn't an event log stays on {_md(origin)}."]
    if clock_notes:
        lines += ["", "Times from these hosts may not line up with other sources:", "", *clock_notes]
    return lines


def _event_lines(number: int, row: tuple, identity: Identity, notes: dict[str, list[dict]], tags: list[tuple],
                 pair: dict | None, manifest: dict[str, str], records: dict[str, RunRecord],
                 findings: list[str] = ()) -> list[str]:
    """One numbered event of the timeline: its time, host, mark, and message, then the findings it supports, its clock,
    notes, Hayabusa rules, tags, source, and ID. `row` is report_text's query's, `tags` the event's (kind, label, ord),
    `pair` its other half in the clock check, if any, `records` the case's run records by run ID, and `findings` the open
    findings it is linked to, as "1. Title"."""
    uid, ts, host, label, note, message, tool, version, run_id, artifact, source, record, rules, offset = row
    lines = [f"{number}. **{'No time recorded' if ts is None else _time(ts)}, {_md(host)}, {label}.** {_md(message)}"]
    if findings:
        lines.append(f"   - Finding{'' if len(findings) == 1 else 's'}: {'; '.join(_md(f) for f in findings)}")
    if ts is not None:   # an event without a time has no clock to give
        if offset:
            lines.append(f"   - Clock: {_md(host)}'s offset of {offset / 1_000_000:+g} s is applied; "
                         f"the artifact recorded {_time(ts - offset)}.")
        lines += _clock_lines(identity, host, ts, ts - offset, pair)
    if note:
        lines.append(f"   - Mark note: {_md(note)}")
    lines += [f"   - Note ({_md(n['at'])}, {_md(analyst(n))}): {_md(n['text'])}" for n in notes.get(uid, [])]
    if rules:
        lines.append(f"   - Hayabusa: {_md(rules)}")
    if tags:
        # an older technique tag off the ATT&CK list carries its flag, as a finding's techniques do
        phases = [attack.worded([label]) if kind == "technique" else label for kind, label, _ in tags if kind != "tag"]
        own = [label for kind, label, _ in tags if kind == "tag"]
        lines.append("   - " + "; ".join(([f"ATT&CK: {_md(', '.join(phases))}"] if phases else []) +
                                         ([f"Tags: {_md(', '.join(own))}"] if own else [])))
    lines.append(f"   - Source: {tool} {version}, run `{run_id}`, {artifact} `{_tick(source)}` record `{_tick(record)}`, "
                 f"{_evidence_hash(cited_files(source or '', records.get(run_id), version), source or '', manifest)}.")
    lines.append(f"   - Event ID: `{uid}`")
    return lines


def _evidence_hash(files: list[str], path: str, manifest: dict[str, str]) -> str:
    """The Source line's words on the evidence hash, given the files the event cites (cited_files): the intake hash of
    the file the event names, or of the one output file a load of found output read, named as such; none when the load
    read several files, which don't say which one the event came from, or when its run's record is gone."""
    if not files:
        return "no evidence SHA-256: the run's record is gone, so the output the event was read from is unknown"
    if len(files) > 1:
        return f"no evidence SHA-256: the load read {len(files)} output files and doesn't record which one the event came from"
    sha = f"evidence SHA-256 `{manifest.get(files[0], '') or 'not in manifest'}`"
    return sha if files == [path] else f"{sha} (of the output file `{_tick(files[0])}`)"


def _tactics_section(rows: list[tuple], tagged: dict[str, list[tuple]]) -> list[str]:
    """The numbered events by the ATT&CK tactics the analyst tagged, in kill-chain order; none without."""
    by_tactic: dict[tuple, list[int]] = {}
    for number, row in enumerate(rows, 1):
        for kind, label, ord_ in tagged.get(row[0], []):
            if kind == "tactic":
                by_tactic.setdefault((ord_, label), []).append(number)
    if not by_tactic:
        return []
    return ["", "### By ATT&CK tactic", "", "The events above by the tactics the analyst tagged, in kill-chain order.", "",
            *(f"- **{_md(label)}**: events {', '.join(str(n) for n in numbers)}"
              for (_, label), numbers in sorted(by_tactic.items()))]


def _clock_lines(identity: Identity, host: str, shown: int, recorded: int, pair: dict | None) -> list[str]:
    """Both clocks for an event on a host whose suggested offset isn't applied, and the event's pair, if the clock
    check found one. `shown` is the time the summary gives, `recorded` the artifact's."""
    lines = []
    clock = identity.hosts[host].clock if host in identity.hosts else {}
    if clock.get("state") == "suggest" and (pair or in_segment(clock, recorded)):
        direction = "ahead" if clock["skew_seconds"] > 0 else "behind"
        lines.append(f"   - Capture's clock: about {_about(recorded + round(clock['seconds'] * 1_000_000), shown)}; "
                     f"{_md(host)} runs {clock['skew_text']} {direction}, not aligned.")
    if pair and pair["in_capture"]:
        lines.append(f"   - Its pair in the capture: {_md(pair['message'])}, seen at {_time(pair['adjusted_ts_us'])} "
                     f"(the same {pair['kind']}; event ID `{pair['uid']}`).")
    elif pair:
        lines.append(f"   - Its pair on {_md(pair['host'])}: {_md(pair['message'])}, recorded at "
                     f"{_time(pair['ts_us'], '')} on {_md(pair['host'])}'s clock (the same {pair['kind']}; event ID "
                     f"`{pair['uid']}`).")
    return lines


def _about(us: int, shown: int) -> str:
    """A time to a tenth of a second, with its date when that isn't the date of `shown`."""
    tenths = round(us / 100_000)
    dt, day = from_us(tenths * 100_000), from_us(shown)
    text = f"{dt:%H:%M:%S}.{tenths % 10} UTC"
    return text if dt.date() == day.date() else f"{dt:%Y-%m-%d} {text}"


def export_path(case: Case, stem: str, ext: str) -> Path:
    folder = case.folder / "exports"
    folder.mkdir(exist_ok=True)
    return folder / f"{stem}_{datetime.now(UTC).strftime('%Y%m%dT%H%M%S%fZ')}.{ext}"


def _time(us: int, zone: str = " UTC") -> str:
    return f"{from_us(us):%Y-%m-%d %H:%M:%S.%f}{zone}"


_MD_SPECIAL = re.compile(r"([\\`*_\[\]<>|#~])")


def _md(text) -> str:
    """Escape event text for Markdown. It comes from evidence, so it can hold anything."""
    return _MD_SPECIAL.sub(r"\\\1", str(text or "")).replace("\r", " ").replace("\n", " ")


def _tick(text) -> str:
    """Evidence text for a Markdown code span: a backtick would end the span, and a line break could end its
    paragraph, letting the rest render as Markdown."""
    return str(text or "").replace("`", "'").replace("\r", " ").replace("\n", " ")
