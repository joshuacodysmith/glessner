"""Command-line entry point: cases, intake, verification, tools, and runs."""

from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import re
import sys
import threading
import time
from datetime import UTC, datetime
from pathlib import Path, PureWindowsPath

import duckdb

from . import heads
from .case import CASE_FORMAT, FIRST_CHAINED, JOURNAL_FILE, Case, CaseError, copy_case, create_case, open_case
from .events import connect, from_us
from .intake import add_new, check_files, current_entries, intake, matched_text, read_manifest, unverified_text
from .journal import REPLAY_ERRORS, Journal, JournalError, check, head_of, replay
from .line_logs import LAYOUTS
from .overview import counted_actions, utc_minute
from .parsers.common import evidence_relative
from .rekey import upgraded, upgraded_copy
from .runner import LEFT_OUT, NOT_READ, RunError, RunPlan, check_options, plan_runs, read_runs, rebuild
from .tools import detect, load_registry, recommend
from .version import build_id

UNIDENTIFIED_SHOWN = 25
CHANGED = "The journal was changed after it was written"   # how Journal.read_only's reason begins
# What verify prints for a case below format 3, which has no chain to check
UNCHAINED = ("The journal has no hash chain yet: this case is format {}, and its next open for work, or a command that "
             "writes, upgrades it to format 3, which starts the chain.")


class _Version(argparse.Action):
    """--version: the build, worked out only when asked for, since it runs git."""

    def __init__(self, option_strings, dest, **kwargs):
        super().__init__(option_strings, dest, nargs=0, help="show the build, such as 0.2.0+abc1234, and exit")

    def __call__(self, parser, namespace, values, option_string=None):
        print(f"glessner {build_id()}")
        parser.exit()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="glessner")
    parser.add_argument("--version", action=_Version)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("new-case", help="create a case folder for an evidence folder")
    p.add_argument("case_folder", type=Path)
    p.add_argument("--evidence", type=Path, required=True, help="folder holding the collection")
    p.add_argument("--name", required=True)
    p.add_argument("--analyst", default=getpass.getuser())
    p.add_argument("--tools", type=Path, help="folder where forensic tools are installed")
    p.add_argument("--host", default="", help="single-host collection: the host every file belongs to")

    p = sub.add_parser("intake", help="hash and identify every evidence file")
    p.add_argument("case_folder", type=Path)
    p.add_argument("--add", action="store_true",
                   help="add files new in the evidence folder since intake, such as logs to import; "
                        "listed files stay as they were")

    p = sub.add_parser("copy-case", help="a clean copy of a case: same evidence, intake, and tool runs; none of its journal")
    p.add_argument("source", type=Path, help="the case folder to copy")
    p.add_argument("case_folder", type=Path, help="the new case folder, empty or new")
    p.add_argument("--name", required=True)
    p.add_argument("--analyst", default=getpass.getuser())

    p = sub.add_parser("verify", help="re-hash every evidence file against the manifest, then check the journal")
    p.add_argument("case_folder", type=Path)
    p.add_argument("--journal", action="store_true",
                   help="check only the journal's hash chain: needs no evidence and writes nothing, so it works on a copy")
    p.add_argument("--expect-head", help="a journal head recorded outside the case, such as the one close printed")
    p.add_argument("--file", type=Path, help="a file the case wrote, whose record must come at or before that head")

    for name, help_text in (("tools", "show detected tools and recommendations"),
                            ("runs", "list tool runs"),
                            ("rebuild", "recreate the events database from the successful runs")):
        sub.add_parser(name, help=help_text).add_argument("case_folder", type=Path)

    p = sub.add_parser("serve", help="open the timeline in a browser, served from 127.0.0.1; without a case, the start page")
    p.add_argument("case_folder", type=Path, nargs="?")
    # The default is server.PREFERRED_PORT, written here as its number so this module needn't load the server
    p.add_argument("--port", type=int, default=None,
                   help="port on 127.0.0.1; without it, 47613 when free, else a free one; 0 picks a free one")
    p.add_argument("--no-browser", action="store_true",
                   help="don't open the browser; open the printed link in the browser you choose")

    p = sub.add_parser("rule", help="list, add, change, or remove suggestion rules (kept in the journal)")
    p.add_argument("case_folder", type=Path)
    p.add_argument("op", choices=["list", "add", "change", "remove"])
    p.add_argument("target", nargs="?", help="YAML file for add and change; rule ID for remove")

    p = sub.add_parser("export", help="write a timeline file to the case's exports folder")
    p.add_argument("case_folder", type=Path)
    p.add_argument("--start", help="ISO 8601 UTC; default is the case's first event")
    p.add_argument("--end", help="ISO 8601 UTC; default is just after the case's last event")
    p.add_argument("--format", choices=["csv", "jsonl"], default="csv")
    p.add_argument("--marks", choices=["all", "marked", "flagged"], default="all",
                   help="flagged: only events marked malicious or suspicious")

    sub.add_parser("findings", help="write the Markdown report").add_argument("case_folder", type=Path)

    sub.add_parser("close", help="re-hash every evidence file and record the case as closed in the journal"
                   ).add_argument("case_folder", type=Path)

    p = sub.add_parser("import", help="import text logs from the evidence folder: CSV, JSON lines, W3C, key=value")
    p.add_argument("case_folder", type=Path)
    p.add_argument("files", nargs="*", help="evidence-relative paths; * and ** match several, such as WEB01/**/u_ex*.log")
    p.add_argument("--list", action="store_true", help="list the files to import and what each was imported as")
    p.add_argument("--preview", action="store_true", help="show the mapping and the first events; import nothing")
    p.add_argument("--mapping", help="a saved mapping, a ready-made one (fortinet, sonicwall, windows_firewall, iis, "
                   "apache_access, apache_error, syslog, cisco_asa, snort_fast, timestamped), "
                   "or a .json file; default: guessed from the file")
    p.add_argument("--zone", help="for times written without a zone: UTC, an offset such as -08:00, a zone such as "
                   "Europe/London, or host:NAME for that host's own zone")
    p.add_argument("--host", help="the host lane for the events; with --host-field, the lane for records without one")
    p.add_argument("--host-field", help="take each record's host lane from this field")
    p.add_argument("--time-field", action="append", help="the field holding the time; give it twice for a date "
                   "field and a time field")
    p.add_argument("--time-format", help="ymd, mdy, dmy, epoch, or a strptime format such as %%d.%%m.%%Y %%H:%%M:%%S")
    p.add_argument("--format", choices=["csv", "jsonl", "w3c", "kv", "lines"], help="default: from the file's content")
    p.add_argument("--layout", choices=sorted(LAYOUTS), help="for --format lines: the lines' layout; default: from "
                   "the file's content")
    p.add_argument("--year", type=int, help="for times written without a year, as syslog and Cisco ASA write them: "
                   "the year of the first record; default: the year of the case's latest events")
    p.add_argument("--delimiter", help="a CSV's delimiter; \\t for a tab")
    p.add_argument("--artifact", help="the artifact name for the events, such as palo_alto")
    p.add_argument("--save-as", help="save the mapping under this name, for the next files")

    p = sub.add_parser("run", help="run a tool against each host's evidence and load the output")
    p.add_argument("case_folder", type=Path)
    p.add_argument("--tool", help="registry tool ID, such as evtxecmd")
    p.add_argument("--all", action="store_true",
                   help="every installed tool that has evidence here and hasn't run, then every found output ready "
                        "to load, as the Tools page's Run and load everything ready does")
    p.add_argument("--host", action="append", help="limit to this host; repeat for several")
    p.add_argument("--option", action="append", default=[], metavar="ID=VALUE", help="tool option from the registry")

    p = sub.add_parser("load-output", help="list or load tools' output found in the evidence, such as KAPE's CSVs")
    p.add_argument("case_folder", type=Path)
    p.add_argument("kind", nargs="?", help="what to load, such as evtxecmd_csv; without it, list what's there")
    p.add_argument("--host", action="append", help="limit to this host; repeat for several")
    p.add_argument("--anyway", action="store_true",
                   help="load it for hosts whose raw evidence a tool reads too, which are left out by default")

    args = parser.parse_args(argv)
    try:
        if args.command == "new-case":
            case = create_case(args.case_folder, args.name, args.evidence, args.analyst, args.tools, args.host,
                               client="cli")
            print(f"Created case {case.settings.name!r} at {case.folder}")
            print(f"Evidence: {case.evidence}")
            return 0
        if args.command == "copy-case":
            return cmd_copy_case(args)
        if args.command == "serve" and args.case_folder is None:
            return cmd_serve(None, args)
        return COMMANDS[args.command](open_case(args.case_folder), args)
    # QueryError, RuleError, and MappingError are ValueErrors. A JournalError is a write the journal refused, such as one
    # on a broken chain, whose reason names what to do
    except (CaseError, RunError, ValueError, JournalError) as exc:
        text = str(exc)
        if isinstance(exc, JournalError) and text.startswith(CHANGED):   # a broken chain: say where its breaks are listed
            text += f' "glessner verify {args.case_folder} --journal" lists every break.'
        print(f"Error: {text}", file=sys.stderr)
        return 2


def _require_intake(case: Case) -> None:
    """Refuse a command that reads the intake manifest before the case has one, in add_new's words."""
    if not case.manifest_path.exists():
        raise CaseError("No intake manifest yet; run intake first.")


def cmd_copy_case(args) -> int:
    source = open_case(args.source)
    case = copy_case(source, args.case_folder, args.name, args.analyst, client="cli")
    print(f"Copied {source.settings.name!r} to {case.folder} as {case.settings.name!r}, with none of its journal.")
    case = upgraded_copy(case, source, "cli")   # an older source's copy, upgraded before its rebuild loads
    loaded, left_out = _rebuild(case)
    con = connect(case.db_path, read_only=True)
    try:
        total = con.execute("SELECT count(*) FROM events").fetchone()[0]
    finally:
        con.close()
    if left_out:
        print(f"Rebuilt the events from {plural(len(loaded), 'run')}, leaving out {left_out:,} as noted above: "
              f"{plural(total, 'row')}. Evidence: {case.evidence}")
        return 1
    print(f"Rebuilt the events from {plural(len(loaded), 'run')}: {plural(total, 'row')}. Evidence: {case.evidence}")
    return 0


def cmd_intake(case: Case, args) -> int:
    summary = add_new(case) if args.add else intake(case)
    print(f"{plural(summary.files, 'new file' if args.add else 'file')}, {summary.total_bytes / 1e6:,.1f} MB hashed")
    for artifact, count in summary.by_artifact.items():
        print(f"  {artifact:<14} {count:>6,}")
    if summary.unidentified:
        print(f"Unidentified ({len(summary.unidentified):,}):")
        for path in summary.unidentified[:UNIDENTIFIED_SHOWN]:
            print(f"  {path}")
        if len(summary.unidentified) > UNIDENTIFIED_SHOWN:
            print(f"  ... and {len(summary.unidentified) - UNIDENTIFIED_SHOWN:,} more in manifest.jsonl")
    for error in summary.errors:
        print(f"Unreadable: {error}")
    if summary.missing:
        print(f"Listed in the manifest but gone from the evidence folder ({len(summary.missing):,}); run verify:")
        for path in summary.missing[:UNIDENTIFIED_SHOWN]:
            print(f"  {path}")
    if summary.links:   # all of them: they're recorded nowhere else
        print(f"Links skipped, not followed ({len(summary.links):,}):")
        for link in summary.links:
            print(f"  {link}")
    return 0


def cmd_verify(case: Case, args) -> int:
    """Re-hash every evidence file, then check the journal. A file intake couldn't read is named as
    unverified, never counted as matching; it fails nothing, since no later check can give it a hash, even when it is
    the only file. A manifest with no entry at all leaves nothing to check, which is not a match: the evidence's exit
    is 1.
    With --journal, only the journal, which needs no evidence and writes nothing, journal.lock included."""
    expect, file = getattr(args, "expect_head", None), getattr(args, "file", None)
    if expect is not None and not re.fullmatch(r"[0-9a-fA-F]{64}", expect):
        raise CaseError("--expect-head takes a journal head: 64 hexadecimal characters, as close and exports print it.")
    if file is not None and not file.is_file():   # before minutes of evidence hashing, and an error, not a traceback
        raise CaseError(f"--file {file} is not a file this command can read.")
    if getattr(args, "journal", False):
        lines, code, _ = journal_verify(case, expect, file)
        print("\n".join(lines))
        return code
    _require_intake(case)
    found = check_files(case, reason="manual full verification")
    unread = unverified_text(found.unverified, shown=len(found.unverified))
    code = 0
    if found.problems:
        print(f"{plural(len(found.problems), 'problem')}:")
        for problem in found.problems:
            print(f"  {problem}")
        if unread:
            print(unread)
        code = 1
    elif unread:
        print(f"{matched_text(found.checked)} {unread}")
    elif found.checked:
        print("All evidence files match the manifest.")
    else:
        print("No evidence file to check: the intake manifest lists none.")
        code = 1
    lines, journal_code, unchained = journal_verify(case, expect, file)
    print("\n".join(lines))
    # A case below format 3 has no chain to check until its upgrade, so its exit is the evidence's
    return code if unchained else max(code, journal_code)


def journal_verify(case: Case, expect: str | None, file: Path | None) -> tuple[list[str], int, bool]:
    """The journal's full check in words: every break by line
    and entry, each break on record, where the expected head is, or this computer's recorded head without one, the
    head, and with `file` whether a record of it comes at or before that head. Returns the lines, the exit (0
    only when consistent and the file covered), and whether the journal is a case's below format 3, which has no chain
    yet. Writes nothing: no Journal object, which creates a missing journal file, and journal.check opens journal.lock
    read-only, only when it exists."""
    path = case.folder / JOURNAL_FILE
    if not path.is_file():
        return [f"No {JOURNAL_FILE} in {case.folder}, so there's no journal to check."], 1, False
    record = None if expect else heads.read(case.folder)
    against = expect or (record["head"] if record else None)
    found = check(path, against, keep=True)
    if not found.chain.chained and case.settings.case_format < FIRST_CHAINED:
        return [UNCHAINED.format(case.settings.case_format)], 1, True
    named = "the expected head" if expect else "the head this computer recorded"
    lines = []
    for p in found.problems:
        text = p["text"]
        if p["kind"] == "expected_missing" and record:
            text = (f"the head this computer recorded at {utc_minute(record.get('at', ''))}, entry #{record['seq']}, is no "
                    "line of the journal: its newest entries were removed or changed, or the journal was replaced")
        where = (f"Line {p['line']:,}" + (f", entry #{p['seq']}" if p["seq"] is not None else "") + ": ") if p["line"] else ""
        lines.append(f"{where}{text[0].upper() if not where else text[0]}{text[1:]}.")
    breaks = {e["seq"]: e for e in found.entries if e.get("action") == "chain_break"}
    for held in found.chain.on_record:
        entry = breaks.get(held["seq"], {})
        kinds = ", ".join(f"line {b['line']:,}: {b['kind']}" if b.get("line") else b["kind"] for b in held["breaks"])
        lines.append(f"Break on record: entry #{held['seq']}, by {entry.get('who', '')} at {entry.get('at', '')}, "
                     f"continued with the journal changed ({kinds}). Reason: \"{entry.get('reason', '')}\". Its seal of "
                     "the lines before it still matches.")
    entries = found.chain.nonblank + (found.tail == "missing_lf")
    follow = ""
    if found.expected:
        after = sum(found.after.values())
        follow = (f"{named} is entry #{found.expected[1]}"
                  + (f"; {after:,} {'entry follows' if after == 1 else 'entries follow'} it: "
                     f"{counted_actions(found.after)}." if after else ", the newest."))
    start = found.chain.start
    sealed = (f"Entries #1 to #{start['seq'] - 1} are from before the chain, sealed by #{start['seq']}." if
              start and start.get("action") == "case_upgrade" and isinstance(start.get("seq"), int) and start["seq"] > 1
              else "")
    writing = found.tail == "writing"   # never "Consistent" beside bytes nothing accounts for
    if writing:
        lines.append(f"{found.tail_bytes:,} bytes follow the last line while another process holds journal.lock. They "
                     "are a write in progress, or a lock held by a process that never lets go, so this check can't "
                     "vouch for the journal. Run it again when no Glessner program is writing the case.")
    if found.consistent and not writing:
        if expect:
            lines.append(f"Consistent, and {follow}")
        else:
            lines.append(f"Consistent: each of the {entries:,} entries names the one before it.")
            lines.append(follow[0].upper() + follow[1:] if follow else
                         "No expected head given, so removed newest entries or a rewritten journal wouldn't show.")
        if sealed:
            lines.append(sealed)
    elif follow:
        lines.append(follow[0].upper() + follow[1:])
    lines.append(f"Head: {found.head} (entry #{found.seq}).")
    code = 0 if found.consistent and not writing else 1
    if file is not None:
        text, covered = _file_record(file, found, against, named)
        lines.append(text)
        code = max(code, int(not covered))
    return lines, code, False


def _file_record(file: Path, found, against: str | None, named: str) -> tuple[str, bool]:
    """verify --file: the file's record counts only at or before a head kept outside the case,
    since anyone who can write the case folder can append a chained record after it."""
    from .audit import file_words

    data = file.read_bytes()
    sha = hashlib.sha256(data).hexdigest()
    match = next(((line, seq) for line, seq, h in found.files if h == sha), None)
    if match is None:
        lf = data.replace(b"\r\n", b"\n")
        turned = {hashlib.sha256(d).hexdigest() for d in (lf, lf.replace(b"\n", b"\r\n"))}
        other = next((seq for _, seq, h in found.files if h in turned), None)
        return ("No entry in this journal has this file's SHA-256. The file changed after it was written (a change of "
                "line endings counts), the app stopped before it recorded the file, or another case wrote it."
                + (f" With its line endings converted back, it matches entry #{other}." if other is not None else "")), False
    line, seq = match
    if not against:
        return (f"Entry #{seq} records this file, but no head recorded outside the case was given, so nothing shows the "
                "entry wasn't added later."), False
    if not found.expected:
        return f"Entry #{seq} records this file, but {named} is no entry of this journal, so it vouches for nothing.", False
    if line > found.expected[0]:
        return (f"Entry #{seq} records this file, but it follows {named}, entry #{found.expected[1]}, so that head "
                "doesn't vouch for it. Anyone who can write the case folder can append such an entry."), False
    entry = next((e for e in found.entries if e.get("seq") == seq and e.get("action") == "file_written"), {})
    return (f"Entry #{seq} records this file, at or before {named}, entry #{found.expected[1]}: written "
            f"{utc_minute(entry.get('at', ''))}, recorded as written by {entry.get('who', '')} with "
            f"{entry.get('build', '')}: {file_words(entry)}."), True


def cmd_tools(case: Case, args) -> int:
    specs = load_registry()
    detected = detect(specs.values(), _tools_folder(case))
    print(f"Tools folder: {case.settings.tools_folder or '(not set; PATH only)'}")
    width = max([10, *(len(tool.version) for tool in detected.values())])   # a build such as 0.2.0+abc1234.dirty
    for spec in specs.values():
        tool = detected.get(spec.id)
        state = f"{tool.version:<{width}} {tool.executable}" if tool else "not found"
        print(f"  {spec.name:<10} {state}")
    entries = current_entries(case) if case.manifest_path.exists() else []
    artifacts = {e.artifact for e in entries if e.artifact} | {f"{e.artifact}:{e.detail}" for e in entries if e.artifact}
    for rec in recommend(specs.values(), detected, artifacts):
        print(f"Recommended for {', '.join(rec.artifacts)}: {rec.spec.name} ({rec.spec.license}) from {rec.spec.download_url}")
    return 0


def cmd_run(case: Case, args) -> int:
    _require_intake(case)
    if args.all:
        return _run_all(case)
    if not args.tool:
        raise RunError("Name a tool with --tool, such as evtxecmd, or use --all.")
    specs = load_registry()
    if args.tool not in specs:
        raise RunError(f"Unknown tool {args.tool!r}; registry tools: {sorted(specs)}")
    detected = detect([specs[args.tool]], _tools_folder(case))
    if args.tool not in detected:
        raise RunError(f"{specs[args.tool].name} is not installed. Get it from {specs[args.tool].download_url}")
    options = dict(o.split("=", 1) for o in args.option)
    check_options(specs[args.tool], options)   # before the upgrade: a command that stops here loads nothing
    plans = plan_runs(case, detected[args.tool], args.host)
    if not plans:
        print(f"No evidence for {specs[args.tool].name} (handles {', '.join(specs[args.tool].handles)}).")
        return 0
    return _run_and_load(upgraded(case), plans, [], options)


def _run_and_load(case: Case, plans: list[RunPlan], groups: list[dict], options: dict[str, str] | None = None) -> int:
    """Run the plans and load the groups of found output as the Tools page's jobs do (toolbox.run_and_load), which
    stops at the first step that finds the evidence changed, printing each step. 1 when a step failed or stopped.
    Refused before the first step while another program holds the events database: each load would fail on it after
    its tool had run, and a rebuild loads no failed run. Past that check, any earlier run still recorded as running is
    marked failed (toolbox.close_interrupted), and the command says which."""
    from .toolbox import close_interrupted, run_and_load

    if case.db_path.exists():
        try:
            connect(case.db_path).close()
        except duckdb.Error as exc:   # IOException from another process
            raise CaseError(f"{case.settings.name} can't load events now: another program has its events database open, "
                            "such as glessner serving the case. Stop the server first, or run and load from its Tools "
                            f"page. ({exc})") from exc
    if closed := close_interrupted(case):
        print(f"Marked {plural(len(closed), 'earlier run')} still recorded as running as failed, since "
              f"{'it' if len(closed) == 1 else 'they'} stopped before finishing: {', '.join(r.run_id for r in closed)}.")
    failed = 0

    def started(step) -> None:
        if isinstance(step, RunPlan):
            inputs = plural(len(step.inputs), "input file")
            print(f"{step.tool.spec.name} {step.tool.version} on {step.host} ({inputs}) ...", flush=True)
        else:
            print(f"{step['label']} on {step['host']} ({plural(step['files'], 'file')}) ...",
                  flush=True)

    def finished(step, records) -> None:
        nonlocal failed
        for record in records:
            if isinstance(step, RunPlan):
                _print_run(case, record)
            else:
                _print_load(record, bool(step["preset"]))
            for line in record.notes:   # such as the offset local times were read at, and events without a time
                print(f"  {line}")
            failed += record.status != "ok"

    stopped = run_and_load(case, plans, groups, started, finished, options)
    if stopped:
        print(stopped, file=sys.stderr)
        return 1
    return 1 if failed else 0


def _print_run(case: Case, record) -> None:
    loaded = ""
    if record.loaded_rows is not None:
        loaded = f", {plural(record.loaded_rows, 'row')} loaded in {record.load_seconds}s"
        if record.replaced_rows:
            loaded += f" (replacing {plural(record.replaced_rows, 'row')} from an earlier run)"
    note = f" ({record.reason})" if record.reason else ""
    print(f"  {record.status}: {record.seconds}s{loaded}, evidence {record.evidence_check}{note}")
    if record.working_copy_changes:
        print(f"  The tool changed {len(record.working_copy_changes)} of its working copies, as expected for it; "
              "the evidence is unchanged.")
    if record.run_id:   # a run refused before it started has no folder
        print(f"  run record: {case.runs_folder / record.run_id / 'run.json'}")


def _print_load(record, per_file: bool) -> None:
    """A found output load's record; `per_file` for a network monitor's logs, which import one file a run."""
    replaced = f" (replacing {record.replaced_rows:,})" if record.replaced_rows else ""
    note = f" ({record.reason})" if record.reason else ""
    n = record.loaded_rows or 0
    which = f"{record.inputs[0]}: " if per_file else ""
    print(f"  {which}{record.status}: {plural(n, 'row')}{replaced} in {record.seconds}s, "
          f"evidence {record.evidence_check or NOT_READ}{note}")


def cmd_import(case: Case, args) -> int:
    """Import text logs. Each file is its own run; see imports.py. Before the first load, any earlier run still recorded
    as running is marked failed (toolbox.close_interrupted), and the command says which, as run and load-output do."""
    import fnmatch

    from .imports import MappingError, check_mapping_name, importable, mapping_named, run_import, save_mapping
    from .toolbox import close_interrupted

    _require_intake(case)
    if args.list:
        for f in importable(case):
            done, loaded = f["imported"], f["loaded"]
            state = (f"imported, {plural(done['rows'], 'event')} ({done['mapping'] or 'own mapping'})" if done
                     else f"loaded as found output, {plural(loaded['rows'] or 0, 'event')}" if loaded
                     else "not imported")
            print(f"{f['path']:<60} {f['artifact']:<8} {f['detail']:<18} {state}")
        return 0
    if not args.files:
        raise CaseError("Name the files to import, or use --list to see them.")
    if args.save_as:
        check_mapping_name(args.save_as)   # before the first file is imported
    listed = [e.path for e in read_manifest(case)]
    files: list[str] = []
    for pattern in args.files:
        rel = _evidence_relative(case, pattern)
        matched = [p for p in listed if fnmatch.fnmatchcase(p, rel)] if any(c in rel for c in "*?[") else [rel]
        if not matched:
            raise CaseError(f"No evidence file matches {pattern}")
        files += [m for m in matched if m not in files]
    base = mapping_named(case, args.mapping) if args.mapping else None
    failed = 0
    interrupted_closed = False
    for rel in files:
        mapping = _with_options(_preview(case, rel, base)["mapping"], args)
        shown = _preview(case, rel, mapping)
        print(f"{rel}: {shown['format_label']}{', ' + shown['product'] if shown['product'] else ''}, "
              f"{shown['lines']:,} lines, lane {shown['lane'] or '?'}")
        for warning in shown["warnings"]:
            print(f"  Warning: {warning}")
        for problem in shown["problems"]:
            print(f"  Needs a choice: {problem}")
        if args.preview:
            print("  Mapping: " + json.dumps(shown["mapping"]))
            for ev in shown["events"][:10]:
                when = _fmt_us(ev["ts"]) if ev["ts"] is not None else "(no time)"
                print(f"  {when}  {ev['host']}  {ev['message']}")
            continue
        if shown["problems"]:
            failed += 1
            continue
        case = upgraded(case)   # right before the first load: the mapping and each preview read the case as it is
        if not interrupted_closed:   # once, past the previews, which refuse an events database another program holds
            interrupted_closed = True
            if closed := close_interrupted(case):
                print(f"Marked {plural(len(closed), 'earlier run')} still recorded as running as failed, since "
                      f"{'it' if len(closed) == 1 else 'they'} stopped before finishing: {', '.join(r.run_id for r in closed)}.")
        try:
            record = run_import(case, rel, shown["mapping"])
        except MappingError as exc:
            hint = " Stop the server first, or import from the Import page." if "lock" in str(exc).lower() else ""
            print(f"  failed: {exc}{hint}")
            failed += 1
            continue
        replaced = f", replacing {record.replaced_rows:,}" if record.replaced_rows else ""
        n = record.loaded_rows or 0
        print(f"  {record.status}: {plural(n, 'event')}{replaced} in {record.seconds}s, "
              f"evidence {record.evidence_check}")
        for note in record.notes:
            print(f"  {note}")
        if args.save_as and record.status == "ok":
            save_mapping(case, args.save_as, shown["mapping"])
            print(f"  Saved the mapping as {args.save_as}.")
            args.save_as = None
    return 1 if failed else 0


def _preview(case: Case, rel: str, mapping: dict | None) -> dict:
    """imports.preview, which reads the events database for the hosts' zones. It runs before the case is upgraded,
    so an app holding the database stops it here, as it would stop the upgrade, with the same advice."""
    from .imports import preview

    try:
        return preview(case, rel, mapping)
    except duckdb.Error as exc:
        raise CaseError(f"{case.settings.name} can't be read now: another program has its events database open, such "
                        f"as glessner serving the case. Close it, then try again. ({exc})") from exc


def _with_options(mapping: dict, args) -> dict:
    """The mapping with the command line's choices applied."""
    m = json.loads(json.dumps(mapping))
    if any((args.time_field, args.time_format, args.zone, args.host, args.host_field, args.artifact, args.year)):
        m.pop("saved_as", None)   # no longer the saved mapping as it was
    t = m.setdefault("time", {})
    if args.time_field:
        t["columns"] = args.time_field
    if args.time_format:
        t["format"] = args.time_format
    if args.zone:
        t["zone"] = args.zone
    if args.year:
        t["year"] = args.year
    if args.host_field:
        m["host"] = {"from": "column", "column": args.host_field, "fallback": args.host or ""}
    elif args.host:
        m["host"] = {"from": "name", "name": args.host}
    if args.format:
        m["format"] = args.format
    if args.layout:
        m["layout"] = args.layout
    if args.delimiter:
        m["delimiter"] = "\t" if args.delimiter in ("\\t", "tab") else args.delimiter
    if args.artifact:
        m["artifact"] = args.artifact
    return m


def _evidence_relative(case: Case, text: str) -> str:
    """An import argument as an evidence-relative path with forward slashes. An absolute path and the evidence folder are
    each resolved, and compared in their plain form, so the folder written in extended-length form, as a junction, or as
    both still holds the files in it. A path outside the folder is refused."""
    path = Path(text)
    if not path.is_absolute():
        return text.replace("\\", "/")
    rel = evidence_relative(str(path.resolve()), case.evidence.resolve())
    if PureWindowsPath(rel).anchor:   # evidence_relative leaves a path outside the folder as it was, drive and all
        raise CaseError(f"{text} isn't in the evidence folder {case.evidence}; copy it there and use intake --add.")
    return rel


def _fmt_us(us: int) -> str:
    return f"{from_us(us):%Y-%m-%d %H:%M:%S.%f} UTC"


def _run_all(case: Case) -> int:
    """The path for an evidence folder dropped in whole (run --all): run the ready tools, then load the ready found
    output, as the Tools page's Run and load everything ready does."""
    from .toolbox import everything_ready

    specs = load_registry()
    tools, groups = everything_ready(case, specs, detect(specs.values(), _tools_folder(case)))
    if not tools and not groups:
        print("Nothing is ready: every tool with evidence here has run, and found output is loaded.")
        return 0
    plans = [plan for tool in tools for plan in plan_runs(case, tool)]
    return _run_and_load(upgraded(case), plans, groups)


def cmd_load_output(case: Case, args) -> int:
    """Tools' output found in the evidence: list it, or load one kind of it host by host."""
    from .toolbox import found_outputs

    _require_intake(case)
    specs = load_registry()
    groups = found_outputs(case, specs, detect(specs.values(), _tools_folder(case)))
    if not args.kind:
        if not groups:
            print("No tool output found in the evidence.")
        for g in groups:
            where = f"on {g['host']}" if g["host"] else "in the top level"
            files = plural(g["files"], "file")
            print(f"{g['key']:<16} {g['label']:<22} {files:>9} {where:<20} {g['status']}"
                  + (f": {g['note']}" if g["note"] and g["status"] == "no_parser" else ""))
        return 0
    wanted = {"ready", "raw"} if args.anyway else {"ready"}
    chosen = [g for g in groups if g["key"] == args.kind and g["status"] in wanted
              and (not args.host or g["host"] in args.host)]
    if not chosen:
        print(f"Nothing to load for {args.kind}: it's loaded already, has no parser, or its hosts have raw evidence "
              "to run instead (--anyway loads it for those too).")
        return 0
    return _run_and_load(upgraded(case), [], chosen)


def cmd_runs(case: Case, args) -> int:
    runs = read_runs(case)
    width = max([10, *(len(r.tool_version) for r in runs)])   # an import's is the build, such as 0.2.0+abc1234.dirty
    for r in runs:
        rows = plural(r.loaded_rows, "row") if r.loaded_rows is not None else "not loaded"
        print(f"{r.run_id:<45} {r.status:<7} {r.tool_version:<{width}} {r.seconds:>7.1f}s  {rows}  {r.reason}")
    return 0


def _rebuild(case: Case) -> tuple[list, int]:
    """Rebuild, printing each note it adds to a run: a run it left out, or loaded with output files it recorded no hash
    for. Returns the runs it read and how many it left out, which rebuild and copy-case count apart
    and exit 1 for: a left-out run is not a rebuilt one."""
    left_out = 0

    def note(record, text: str) -> None:
        nonlocal left_out
        print(f"{record.run_id}: {text}")
        if LEFT_OUT in text:
            left_out += 1

    return rebuild(case, report=note), left_out


def plural(n: int, word: str, many: str | None = None) -> str:
    """A count with its noun in the right number, as the page's core.plural does: "1 file", "2 files", "0 files"."""
    return f"{n:,} {word if n == 1 else many or word + 's'}"


def orphan_warning(n: int) -> str:
    """The case open's warning for marks whose events are gone, worded as the page's (main.js) is."""
    if n == 1:
        return "Warning: 1 mark refers to an event that no longer exists."
    return f"Warning: {n:,} marks refer to events that no longer exist."


def cmd_rebuild(case: Case, args) -> int:
    case = upgraded(case)
    loaded, left_out = _rebuild(case)
    con = connect(case.db_path, read_only=True)
    try:
        total = con.execute("SELECT count(*) FROM events").fetchone()[0]
    finally:
        con.close()
    if left_out:
        print(f"Rebuilt {case.db_path.name} from the latest successful run of each tool and host, leaving out "
              f"{left_out:,} of {plural(len(loaded), 'run')} as noted above: {plural(total, 'row')}.")
        return 1
    print(f"Rebuilt {case.db_path.name} from the latest successful run of each tool and host "
          f"({plural(len(loaded), 'run')}): {plural(total, 'row')}.")
    return 0


# The open's own words for the stage App reports after the upgrade (server.App), which covers the journal's checks and
# the rebuild of the derived tables
OPENING = "Opening the case: checking the journal, then building the lanes, marks, and links"


class OpenProgress:
    """The command window's lines while `serve` opens a case, so the window shows progress before the
    link: the first open of a case from an earlier build upgrades it, 24 s on the Szechuan copy's 1.2 million events.
    Each stage the open reports (App's `report`: the upgrade's stages, then "Opening") gets a line as it starts, after
    the seconds since the open began, with its count where it has one. A stage that writes nothing for QUIET seconds
    gets a "still working" line, so a long step still shows the open is running: the upgrade's reload of 67,858
    Suricata events reports once and takes 14 s there. Used as a context manager, whose thread writes those lines."""

    QUIET = 5.0   # seconds without a line before a "still working" one
    TICK = 1.0    # how often the thread looks

    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self.lock = threading.Lock()   # the stage, and the lines, which the open's thread and this one both write
        self.stopped = threading.Event()
        self.thread: threading.Thread | None = None
        self.began = self.last = clock()
        self.stage = ""
        self.done = self.total = self.shown = 0

    def __call__(self, stage: str, done: int = 0, total: int = 0) -> None:
        with self.lock:
            self.done, self.total = done, total
            if stage != self.stage:
                self.stage, self.shown = stage, done
                self._line((OPENING if stage == "Opening" else stage) + (f", {done:,} of {total:,}" if total else ""))

    def tick(self) -> None:
        """After QUIET seconds with no line: how far a stage that counts has got since its last line, or that the stage
        is still running. The seconds at the line's start say for how long; a second count beside them, rounded on
        its own, could read a second off."""
        with self.lock:
            if not self.stage or self.clock() - self.last < self.QUIET:
                return
            if self.total and self.done != self.shown:
                self.shown = self.done
                self._line(f"  still working: {self.done:,} of {self.total:,}")
            else:
                self._line("  still working on this step")

    def finish(self) -> None:
        with self.lock:
            self.stage = ""   # nothing more to say still working about
            self._line("Opened.")

    def _line(self, text: str) -> None:
        now = self.clock()
        print(f"{now - self.began:4.0f} s  {text}", flush=True)
        self.last = now

    def __enter__(self) -> OpenProgress:
        def watch():
            while not self.stopped.wait(self.TICK):
                self.tick()
        self.thread = threading.Thread(target=watch, name="open progress", daemon=True)
        self.thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stopped.set()
        self.thread.join()


def _serve_open(case: Case):
    """The Hub with `case` open, saying in the command window what the open is doing as it goes."""
    from .server import Hub

    print(f"Opening {case.settings.name!r} from {case.folder}.", flush=True)
    if (found := case.settings.case_format) < CASE_FORMAT:
        print(f"It is at case format {found}, from an earlier build, so this open upgrades it to format {CASE_FORMAT} "
              "first. The upgrade runs once, and on a large case it takes a while; each step is listed as it starts.",
              flush=True)
    with OpenProgress() as progress:
        hub = Hub(case, report=progress)
        progress.finish()
    return hub


def cmd_serve(case: Case | None, args) -> int:
    from .server import PREFERRED_PORT, Hub, serve_hub  # imported here so other commands don't load the server

    # Without a case, the start page: recent cases, a new case, or a copy. A case opened later from there,
    # or the one given here, can be switched from the page's Cases button.
    server, hub, url = serve_hub(_serve_open(case) if case is not None else Hub(), args.port)
    what = repr(case.settings.name) if case is not None else "the start page"
    how = ("open it in the browser you choose" if args.no_browser
           else "to open it in another browser, run serve with --no-browser")
    print(f"Serving {what} on 127.0.0.1 only. Start link (it works once; {how}):")
    print(f"  {url}")
    # The browser keeps the page's layout by origin, so a run on another port starts from the defaults
    if args.port is None and (port := server.server_address[1]) != PREFERRED_PORT:
        print(f"Port {PREFERRED_PORT} is in use, so this run is on port {port}. The browser keeps the page's layout per "
              "port, so this run's page won't see the layout saved in earlier runs.")
    if hub.app and hub.app.orphans:
        print(orphan_warning(hub.app.orphans))
    print("Press Ctrl+C to stop. Tool runs from the command line need the server stopped first.", flush=True)
    if not args.no_browser:
        import webbrowser
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        if hub.app:
            hub.app.con.close()
    return 0


def _open_app(case: Case):
    """The server's case state, without HTTP: derived tables, identity, and built-in rules. The case is upgraded first,
    since a format 3 journal takes no entry until its chain has started; while
    another program has the case open, the upgrade or the App's connection refuses, before anything is written."""
    from .server import App

    if not case.db_path.exists():
        raise CaseError("No events yet. Run a tool first.")
    return App(upgraded(case), client="cli")


def cmd_rule(case: Case, args) -> int:
    from .rules import BUILTIN_RULES
    from .server import api_rule, api_rules, parse_rule_request, rule_known

    text = None
    if args.op != "list":   # everything the request can be refused for is checked before the case is upgraded
        if not args.target:
            raise CaseError(f"rule {args.op} needs {'a rule ID' if args.op == 'remove' else 'a YAML file'}")
        if args.op != "remove":
            try:
                text = Path(args.target).read_text(encoding="utf-8")
            except OSError as exc:   # missing, a folder, or held by another program
                raise CaseError(f"rule {args.op} needs a YAML file, and {args.target} is not a file this command can "
                                f"read ({exc.strerror or exc}).") from exc
        parsed = parse_rule_request(args.op, text or "")
        try:
            state = replay(case.folder / JOURNAL_FILE)   # the rules as the open will have them, built-in ones added
        except (JournalError, *REPLAY_ERRORS):
            state = None   # a line before the chain that it can't apply: the open says why, naming the break
        if state is not None:
            rules = {**{rule_id: None for rule_id in BUILTIN_RULES if rule_id not in state.removed_rules}, **state.rules}
            rule_known(rules, args.op, parsed.id if parsed else args.target)
    app = _open_app(case)
    try:
        if args.op == "list":
            result = api_rules(app, {})
        elif args.op == "remove":
            result = api_rule(app, {"op": "remove", "id": args.target})
        else:
            result = api_rule(app, {"op": args.op, "text": text})
        for r in result["rules"]:
            state = f"error: {r['error']}" if r.get("error") else f"suggests {r.get('suggest')}"
            print(f"{r['id']:<32} {state:<24} matched {r['matched']:>8,}  pending {r['pending']:>8,}"
                  f"{'  built-in' if r.get('builtin') else ''}")
    finally:
        app.con.close()
    return 0


def cmd_export(case: Case, args) -> int:
    """A timeline file and its record in the journal, through the server's own export, so the two can't differ; the head
    after the record is printed in full."""
    from .queries import case_range
    from .server import api_export

    start = _parse_utc(args.start) if args.start else None   # checked before the case is upgraded
    end = _parse_utc(args.end) if args.end else None
    app = _open_app(case)
    try:
        first, last, _ = case_range(app.con)
        # The bounds default to the case's first and last times; a marked or flagged export covers the whole case
        body = {"format": args.format, "marks": args.marks}
        if args.marks == "all":
            if first is None and not (args.start and args.end):
                raise CaseError("The case has no events with a time to export.")
            body.update(start=first if start is None else start, end=last + 1 if end is None else end)
        result = api_export(app, body)
    finally:
        app.con.close()
    print(f"Wrote {plural(result['rows'], 'event')} to {result['path']}")
    print(head_after(result))
    return 0


def cmd_findings(case: Case, args) -> int:
    """The report and its record, through the server's own, with its full check of the journal."""
    from .server import api_report

    app = _open_app(case)
    try:
        result = api_report(app, {})
    finally:
        app.con.close()
    print(f"Wrote the report ({plural(result['events'], 'malicious or suspicious event')}) to {result['path']}")
    print(head_after(result))
    return 0


def head_after(result: dict) -> str:
    """The head after a file's record, in full."""
    return (f"Journal head after recording this file: {result['head']} (entry #{result['head_seq']}). Record it with "
            "the file to check the file later.")


def cmd_close(case: Case, args) -> int:
    """Full re-hash of the evidence against the intake manifest at case close, recorded in the journal.

    Closing does not lock the case: the analyst can keep working, and can close again later. An older case is upgraded
    before the re-hash, since a format 3 journal takes no entry until its chain has started; beside a running server of
    this build the case is format 3 already, and the entry takes its turn under the journal's lock.
    """
    if not case.manifest_path.exists():
        raise CaseError("No intake manifest; run intake before closing the case.")
    case = upgraded(case)
    # The open's checks, then the full check and the recorded head, before the re-hash, so a broken chain is refused
    # before minutes of hashing
    journal = Journal(case)
    journal.open_for_work(record_build=False)
    chain, record = journal.full_check()
    if journal.read_only:
        raise JournalError(journal.read_only)
    found = check_files(case, reason="case close")
    problems, entries, unread = found.problems, found.checked, found.unverified
    result = "ok" if not problems else "mismatch"
    # evidence_files counts the files checked. A file intake couldn't read is counted in unverified, not as matching,
    # and a folder walk couldn't list in unlisted_folders; verification.jsonl names each
    since = chain.chain.on_record[-1]["seq"] if chain.chain.on_record else None
    entry = journal.append("case_setting", name="closed",
                           value={"at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"), "evidence_files": entries,
                                  "unverified": len(unread) - found.folders, "unlisted_folders": found.folders,
                                  "hash_check": result, "problems": problems[:50],
                                  "chain": f"consistent since #{since}" if since else "consistent",
                                  "head_record": "matched" if record and chain.expected else "none",
                                  "journal_entries": chain.chain.nonblank + (chain.tail == "missing_lf")})
    unread_text = unverified_text(unread, shown=len(unread))
    head = (f"Journal head after this close: {head_of(entry)} (entry #{entry['seq']}). Record it outside the case "
            "folder, such as in your case notes or ticket.")
    if problems:
        print(f"Case closed with {plural(len(problems), 'evidence problem')}, recorded in the journal:")
        for problem in problems:
            print(f"  {problem}")
        if unread_text:
            print(unread_text)
        print(head)
        return 1
    if unread_text:
        print(f"Case closed. {matched_text(entries)} {unread_text} Recorded in the journal.")
    elif not entries:
        print("Case closed. No evidence file was checked: the intake manifest lists none. Recorded in the journal.")
    else:
        each = "The 1 evidence file matches" if entries == 1 else f"All {entries:,} evidence files match"
        print(f"Case closed. {each} the intake manifest. Recorded in the journal.")
    print(head)
    return 0


def _parse_utc(text: str) -> int:
    from .rules import RuleError, parse_time

    try:
        return parse_time(text)
    except RuleError as exc:
        raise CaseError(str(exc)) from exc


COMMANDS = {"intake": cmd_intake, "verify": cmd_verify, "tools": cmd_tools, "run": cmd_run, "import": cmd_import,
            "runs": cmd_runs, "rebuild": cmd_rebuild, "serve": cmd_serve, "rule": cmd_rule,
            "export": cmd_export, "findings": cmd_findings, "close": cmd_close, "load-output": cmd_load_output}


def _tools_folder(case: Case) -> Path | None:
    return Path(case.settings.tools_folder) if case.settings.tools_folder else None


if __name__ == "__main__":
    sys.exit(main())
