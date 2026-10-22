"""Synthetic evidence and case builders for the tests of what a case promises about its evidence: nothing writes to it, and
a case built again from the same evidence holds the same results.

The evidence has four folders: WS01 with event log, Hayabusa, and prefetch output found in it, Windows event XML, and a
browser history; DC01 with event log output; SENSOR with Suricata EVE; and IDS with a Snort alert log. The builders take
it through intake, the built-in event XML reader's run, a work-on-copies tool's run, loads of the found output, and an
import, as a case is built from a collection. Everything is made from fixtures, so no tool needs to be installed.

Run as a script, the module builds one case and writes what the app shows of it to a file (views_from_new_process starts
it). A build in a process of its own shares nothing with another build that a process holds: the seed of Python's string
hashing and the caches keyed on a path."""

import argparse
import csv
import io
import json
import os
import pickle
import subprocess
import sys
import time
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest
from conftest import FAST_ALERTS, SURICATA_ALERTS, refuse_off_machine
from rekey_fixtures import HISTORY, VISITS, VISITS_CSV, write_rows
from test_event_xml import events_file, rdp_logon
from test_tool_outputs import EVTX_COLUMNS, LOGON_PAYLOAD, PECMD_COLUMNS, evtx_rows

from glessner.case import Case, create_case
from glessner.events import connect
from glessner.imports import preview, run_import
from glessner.intake import intake, sha256_file
from glessner.runner import RunRecord, plan_runs, read_runs, run
from glessner.server import App, api_export, api_indicators, api_mark, api_overview
from glessner.toolbox import found_outputs, load_group
from glessner.tools import DetectedTool, detect, load_registry

HAYABUSA_COLUMNS = ["Timestamp", "RuleTitle", "Level", "Computer", "Channel", "EventID", "RecordID", "Details", "RuleID",
                    "EvtxFile", "MitreTactics", "MitreTags"]
SECURITY_EVTX = r"D:\KAPE\tout\C\Windows\System32\winevt\Logs\Security.evtx"
FAST_LOG = "IDS/fast.log"

# The tables the app derives from the events and the journal when a case opens for work
DERIVED_TABLES = ("hits", "suggestions", "suggested", "logon_links", "hosts", "suricata_alerts", "fast_alerts",
                  "account_domains", "tag_suggestions", "keyless_names", "service_aliases")

# A System 7040 event, which names a service by its display name (param1) and its key name (param4)
SERVICE_PAYLOAD = json.dumps({"EventData": {"Data": [{"@Name": "param1", "#text": "Windows Audio"},
                                                     {"@Name": "param2", "#text": "auto start"},
                                                     {"@Name": "param3", "#text": "demand start"},
                                                     {"@Name": "param4", "#text": "Audiosrv"}]}})

# SQLECmd's stand-in: for each browser history under the host folder it is given, one visit whose SourceFile names that
# database where the tool read it, as SQLECmd's output does. Run on copies, that is a path in the run's folder.
STAND_IN_SQLECMD = f"""
import csv, pathlib, sys
host_dir, out_dir = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
columns = {VISITS!r}
with (out_dir / {VISITS_CSV!r}).open("w", encoding="utf-8-sig", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=columns)
    writer.writeheader()
    for i, path in enumerate(sorted(host_dir.rglob("History")), 1):
        row = dict.fromkeys(columns, "")
        row.update(ID=str(i), VisitID=str(i), URLTitle="Evil", URL="https://evil.example/" + str(i), SourceFile=str(path))
        row["VisitTime (UTC)"] = "2024-05-14 12:10:0" + str(i)
        writer.writerow(row)
"""


def make_evidence(root: Path) -> Path:
    """The evidence folder under `root`, with a folder for each of WS01 (event log, Hayabusa, and prefetch CSVs, a Windows
    event XML file, and Edge's history), DC01 (event log CSV), SENSOR (Suricata EVE), and IDS (a Snort alert log). The
    Hayabusa hit names the event log CSV's first record, so the two join. DC01 has a logon in the domain's dotted spelling,
    which folds with the other spelling into an account_domains row, and a service's start type change, which gives a
    service_aliases row. DC01's CSV writes a record twice, and the EVE file its first alert twice, as a tool can emit a
    record twice, so the repeat takes an ordinal."""
    evidence = root / "evidence"
    logs = Path("Modules") / "EventLogs"
    write_rows(evidence / "WS01" / logs / "20240514_EvtxECmd_Output.csv", EVTX_COLUMNS, evtx_rows("WS01.corp.local"))
    write_rows(evidence / "WS01" / logs / "hayabusa.csv", HAYABUSA_COLUMNS, [
        {"Timestamp": "2024-05-14 12:00:01.000", "RuleTitle": "Logon from outside", "Level": "high",
         "Computer": "WS01.corp.local", "Channel": "Security", "EventID": "4624", "RecordID": "101",
         "Details": "alice", "RuleID": "r-1", "EvtxFile": SECURITY_EVTX, "MitreTactics": "InitAccess",
         "MitreTags": "T1078"}])
    write_rows(evidence / "WS01" / "Modules" / "ProgramExecution" / "20240514_PECmd_Output.csv", PECMD_COLUMNS, [
        {"SourceFilename": r"C:\Windows\Prefetch\EVIL.EXE-1234ABCD.pf", "ExecutableName": "EVIL.EXE", "RunCount": "1",
         "LastRun": "2024-05-14 12:05:00", "Hash": "1234ABCD"}])
    (evidence / "WS01" / "security.xml").write_text(events_file(rdp_logon(7, "WS01.corp.local", "203.0.113.9")),
                                                    encoding="utf-8")
    history = evidence / HISTORY
    history.parent.mkdir(parents=True)
    history.write_bytes(b"SQLite format 3\x00" + b"\x00" * 100)
    dotted = {**evtx_rows("DC01.corp.local", records=(5,))[0], "Payload": LOGON_PAYLOAD.replace('"CORP"', '"CORP.LOCAL"')}
    service = {**evtx_rows("DC01.corp.local", records=(6,))[0], "EventId": "7040", "Channel": "System",
               "Provider": "Service Control Manager", "MapDescription": "Start type changed", "PayloadData1": "",
               "SourceFile": SECURITY_EVTX.replace("Security", "System"), "Payload": SERVICE_PAYLOAD}
    rows = evtx_rows("DC01.corp.local", records=(3, 4))
    write_rows(evidence / "DC01" / logs / "20240514_EvtxECmd_Output.csv", EVTX_COLUMNS, [*rows, rows[0], dotted, service])
    (evidence / "SENSOR").mkdir()
    alerts = [*SURICATA_ALERTS, SURICATA_ALERTS[0]]
    (evidence / "SENSOR" / "eve.json").write_text("".join(json.dumps(r) + "\n" for r in alerts), encoding="utf-8")
    (evidence / "IDS").mkdir()
    (evidence / FAST_LOG).write_text(FAST_ALERTS, newline="\n")
    return evidence


def stand_in_sqlecmd(root: Path) -> DetectedTool:
    """SQLECmd as the registry describes it, running the stand-in script (written under `root`, outside the evidence) with
    this Python. It keeps the registry's work_on_copies, so the run reads copies of the databases in its run folder."""
    script = root / "stand_in_sqlecmd.py"
    script.write_text(STAND_IN_SQLECMD, encoding="utf-8")
    spec = replace(load_registry()["sqlecmd"], args=(str(script), "{host_dir}", "{output_dir}"), executables=("python.exe",),
                   dotnet=0)
    return DetectedTool(spec, Path(sys.executable), "1.0")


def take_in(evidence: Path, folder: Path) -> Case:
    """A new case on the evidence, with the evidence taken in."""
    case = create_case(folder, "Custody", evidence, "cody")
    intake(case)
    return case


def run_tools(case: Case, stand_in: DetectedTool, *, reverse: bool = False) -> list[RunRecord]:
    """The built-in event XML reader on each host with XML, then the stand-in on each host with a history (the plans in
    the opposite order with `reverse`). Each run loads its output; one that fails raises AssertionError with its reason."""
    xml_reader = detect([load_registry()["event_xml"]], None)["event_xml"]
    plans = []
    for tool in (xml_reader, stand_in):
        plans.extend(plan_runs(case, tool))
    records = []
    for plan in reversed(plans) if reverse else plans:
        record = run(case, plan)
        assert record.status == "ok", f"{record.tool} on {record.host}: {record.reason}"
        records.append(record)
    return records


def group_name(group: dict) -> str:
    """A group of found output as load_found_outputs names it, like "evtxecmd_csv:DC01"."""
    return f"{group['key']}:{group['host']}"


def load_found_outputs(case: Case, only: tuple[str, ...] = (), *, reverse: bool = False) -> list[str]:
    """Load the tools' output found in the evidence that is ready to load (all of it, or only the groups named like
    "evtxecmd_csv:DC01"), in the found order or the opposite with `reverse`, and return the groups loaded, sorted. A run
    that fails raises AssertionError with its reason."""
    ready = [g for g in found_outputs(case, load_registry(), {}) if g["status"] == "ready"]
    groups = [g for g in ready if group_name(g) in only] if only else ready
    for group in reversed(groups) if reverse else groups:
        for record in load_group(case, group):
            assert record.status == "ok", f"{group_name(group)}: {record.reason}"
    return sorted(group_name(g) for g in groups)


def import_fast_log(case: Case) -> RunRecord:
    """Import the Snort alert log with its ready-made mapping, its times read as UTC."""
    mapping = preview(case, FAST_LOG)["mapping"]
    record = run_import(case, FAST_LOG, {**mapping, "time": {**mapping["time"], "zone": "UTC"}}, zones={})
    assert record.status == "ok", record.reason
    return record


def build(evidence: Path, folder: Path, stand_in: DetectedTool, *, reverse: bool = False) -> Case:
    """A case built from the evidence: intake, the event XML reader, the stand-in, every group of found output, and the
    alert log import. With `reverse`, everything after intake comes in the opposite order: the import, the groups, then
    the stand-in and the event XML reader."""
    case = take_in(evidence, folder)
    if reverse:
        import_fast_log(case)
        load_found_outputs(case, reverse=True)
        run_tools(case, stand_in, reverse=True)
    else:
        run_tools(case, stand_in)
        load_found_outputs(case)
        import_fast_log(case)
    return case


def wait_for_a_later_second(case: Case) -> None:
    """Return once the clock is past the second of the case's newest run. Run IDs name the second a run started in, so a
    case built after this one has run IDs that share none with it."""
    newest = max(record.run_id.split("_")[0] for record in read_runs(case))
    while datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") <= newest:
        time.sleep(0.05)


def run_identity(record: RunRecord) -> tuple:
    """What a run did, without when: its tool, host, and inputs."""
    return record.tool, record.host, tuple(record.inputs)


def event_rows(case: Case, *, by_identity: bool = False) -> list[tuple]:
    """Every row of the events table in event_uid order, none for a case with no events database yet. With `by_identity`
    the run_id column holds the run's identity (run_identity) in place of its ID, so two builds compare equal when each
    row came from the same run of the same tool on the same host and files, though the runs' IDs differ."""
    if not case.db_path.exists():
        return []
    con = connect(case.db_path, read_only=True)
    try:
        cursor = con.execute("SELECT * FROM events ORDER BY event_uid")
        columns = [d[0] for d in cursor.description]
        rows = cursor.fetchall()
    finally:
        con.close()
    if not by_identity:
        return rows
    identities = {record.run_id: run_identity(record) for record in read_runs(case)}
    at = columns.index("run_id")
    return [(*row[:at], identities[row[at]], *row[at + 1:]) for row in rows]


def snapshot(folder: Path) -> dict[str, tuple]:
    """What a folder holds, for a comparison before and after something that must not write to it. Each file has its
    SHA-256, size, and modification time; each folder, including the top one, the names it lists and its modification
    time, which creating or deleting a file in it changes, so a temporary file made and removed shows. Access times are
    left out: a read changes them."""
    found = {}
    for where, folders, files in folder.walk():
        found[where.relative_to(folder).as_posix()] = ("folder", tuple(sorted(folders)), tuple(sorted(files)),
                                                      where.stat().st_mtime_ns)
        for name in files:
            path = where / name
            stat = path.stat()
            found[path.relative_to(folder).as_posix()] = ("file", sha256_file(path), stat.st_size, stat.st_mtime_ns)
    return found


def without_column(text: str, name: str) -> list[list[str]]:
    """The rows of CSV text without the column `name`."""
    rows = list(csv.reader(io.StringIO(text, newline="")))
    at = rows[0].index(name)
    return [row[:at] + row[at + 1:] for row in rows]


def derived_tables(app: App) -> dict[str, list[tuple]]:
    """The tables the app derives (DERIVED_TABLES) as the open app holds them, each with its rows sorted."""
    return {name: app.con.execute(f"SELECT * FROM {name} ORDER BY ALL").fetchall() for name in DERIVED_TABLES}


def tables_of(case: Case) -> dict[str, list[tuple]]:
    """derived_tables for a case opened for work and closed again."""
    app = App(case, for_work=True)
    try:
        return derived_tables(app)
    finally:
        app.con.close()


def app_views(case: Case, uid: str | None = None) -> dict:
    """Open the case for work and read what the app shows of it, leaving out what differs by design between two builds
    of one evidence folder: times, run IDs, and the journal's head. It also writes the timeline as CSV and JSON lines and
    the indicators file, after marking the event `uid` malicious (the first EvtxECmd event by ID when none is given).

    The result holds the derived tables (derived_tables), the overview's leads, hosts, progress, gaps, and integrity, the
    two timeline files without their run_id, the indicators file's bytes, and the event marked."""
    app = App(case, for_work=True)
    try:
        tables = derived_tables(app)
        overview = api_overview(app, {})
        first, last = app.con.execute("SELECT min(ts_us), max(ts_us) + 1 FROM events").fetchone()
        everything = {"marks": "all", "start": first, "end": last}
        timeline_csv = Path(api_export(app, {"format": "csv", **everything})["path"]).read_text(encoding="utf-8")
        timeline_jsonl = Path(api_export(app, {"format": "jsonl", **everything})["path"]).read_text(encoding="utf-8")
        uid = uid or app.con.execute("SELECT min(event_uid) FROM events WHERE tool = 'evtxecmd'").fetchone()[0]
        api_mark(app, {"uids": [uid], "value": "malicious", "note": "marked"})
        indicators = Path(api_indicators(app, {})["path"]).read_bytes()
    finally:
        app.con.close()
    gaps = {**overview["gaps"], "runs": [{k: v for k, v in gap.items() if k not in ("run_id", "at")}
                                         for gap in overview["gaps"]["runs"]]}
    left_out = ("last_full", "found_at", "journal", "journal_entries")
    return {
        "tables": tables,
        "uid": uid,
        "overview": {"leads": overview["leads"], "hosts": overview["hosts"], "by_host": overview["by_host"],
                     "progress": {k: v for k, v in overview["progress"].items() if k != "last"}, "gaps": gaps,
                     "integrity": {k: v for k, v in overview["integrity"].items() if k not in left_out}},
        "timeline_csv": without_column(timeline_csv, "run_id"),
        "timeline_jsonl": [{k: v for k, v in json.loads(line).items() if k != "run_id"}
                           for line in timeline_jsonl.splitlines() if line],
        "indicators": indicators,
    }


def build_and_view(evidence: Path, folder: Path, *, reverse: bool = False, uid: str | None = None) -> dict:
    """Build a case from the evidence at `folder` (build, with the stand-in written beside it) and return app_views of it."""
    folder.parent.mkdir(parents=True, exist_ok=True)
    return app_views(build(evidence, folder, stand_in_sqlecmd(folder.parent), reverse=reverse), uid)


def views_from_new_process(evidence: Path, folder: Path, *, hash_seed: int, reverse: bool = False,
                           uid: str | None = None) -> dict:
    """build_and_view in a Python process of its own, started with PYTHONHASHSEED set to `hash_seed`. Two builds in one
    process share the seed of Python's string hashing and every cache keyed on a path, so a result that depends on either
    agrees between them; builds in two processes with different seeds and different evidence paths do not. The process
    runs under the tests' refusal of the network (refuse_off_machine), and fails when it made an attempt. The result
    comes back through a pickle file in the case folder's parent."""
    views_file = folder.parent / "views.pickle"
    command = [sys.executable, str(Path(__file__).resolve()), str(evidence), str(folder), str(views_file)]
    if reverse:
        command.append("--reverse")
    if uid:
        command += ["--uid", uid]
    done = subprocess.run(command, env={**os.environ, "PYTHONHASHSEED": str(hash_seed)}, capture_output=True, text=True,
                          timeout=600, check=False)
    assert done.returncode == 0, f"the build process failed:\n{done.stderr}"
    return pickle.loads(views_file.read_bytes())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Build a case from the evidence and write what the app shows of it.")
    parser.add_argument("evidence", type=Path)
    parser.add_argument("folder", type=Path, help="the new case's folder")
    parser.add_argument("views", type=Path, help="the file to write the result to, pickled")
    parser.add_argument("--reverse", action="store_true", help="build in the opposite order")
    parser.add_argument("--uid", help="the event to mark")
    args = parser.parse_args()
    with pytest.MonkeyPatch.context() as monkeypatch:
        refused = refuse_off_machine(monkeypatch)
        views = build_and_view(args.evidence, args.folder, reverse=args.reverse, uid=args.uid)
    if refused:
        sys.exit(f"The build reached past this machine: {refused}")
    args.views.write_bytes(pickle.dumps(views))
