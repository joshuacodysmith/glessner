"""Tools' output found in the evidence, such as KAPE's module output, is recognized by its header and loaded, with raw
evidence first."""

import csv
import json
import os
import time
from dataclasses import replace
from pathlib import Path

from test_recmd import COLUMNS as RECMD_COLUMNS
from test_recmd import sam_account, userassist, write_detail

from glessner.case import create_case
from glessner.events import connect
from glessner.identify import identify_bytes
from glessner.intake import intake
from glessner.parsers.common import DETAILS_NOTE
from glessner.runner import LEFT_OUT, companions, detail_files, load_found_output, read_runs, rebuild, run_problems
from glessner.tool_outputs import BY_KIND, kind_of
from glessner.toolbox import found_outputs, start_load_job
from glessner.tools import DetectedTool, load_registry

EVTX_COLUMNS = ["RecordNumber", "EventRecordId", "TimeCreated", "EventId", "Level", "Provider", "Channel", "Computer",
                "MapDescription", "UserName", "PayloadData1", "PayloadData2", "ExecutableInfo", "SourceFile", "Payload"]
LOGON_PAYLOAD = json.dumps({"EventData": {"Data": [{"@Name": "TargetUserName", "#text": "alice"},
                                                   {"@Name": "TargetDomainName", "#text": "CORP"},
                                                   {"@Name": "LogonType", "#text": "10"},
                                                   {"@Name": "IpAddress", "#text": "203.0.113.9"}]}})
PECMD_COLUMNS = ["Note", "SourceFilename", "SourceCreated", "SourceModified", "SourceAccessed", "ExecutableName", "Hash",
                 "Size", "Version", "RunCount", "LastRun", "PreviousRun0", "FilesLoaded"]
SBE_COLUMNS = ["BagPath", "Slot", "NodeSlot", "MRUPosition", "AbsolutePath", "ShellType", "Value", "ChildBags",
               "CreatedOn", "ModifiedOn", "AccessedOn", "LastWriteTime", "FirstInteracted", "LastInteracted"]


def write_rows(path, columns, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=columns)
        w.writeheader()
        w.writerows(rows)


def evtx_rows(computer, records=(1, 2)):
    return [{"RecordNumber": str(n), "EventRecordId": str(100 + n), "TimeCreated": f"2024-05-14 12:00:0{n}.0000000",
             "EventId": "4624", "Provider": "Microsoft-Windows-Security-Auditing", "Channel": "Security",
             "Computer": computer, "MapDescription": "Successful logon", "PayloadData1": "Target: CORP\\alice",
             "SourceFile": r"D:\KAPE\tout\C\Windows\System32\winevt\Logs\Security.evtx", "Payload": LOGON_PAYLOAD}
            for n in records]


def test_kinds_by_header_and_by_name():
    header = lambda cols: ",".join(cols)
    assert kind_of("20240101_EvtxECmd_Output.csv", header(EVTX_COLUMNS)).kind == "evtxecmd"
    assert kind_of("x.csv", '"Timestamp","RuleTitle","Level","Computer","Channel","EventID","RecordID"').kind == "hayabusa"
    assert kind_of("a.csv", "SourceFile,SourceCreated,AppId,AppIdDescription,DestListVersion,TargetCreated").kind == "jlecmd_auto"
    assert kind_of("a.csv", "SourceFile,SourceCreated,TargetCreated,LocalPath,WorkingDirectory").kind == "lecmd"
    assert kind_of("b.csv", "RunTime,ExecutableName").kind == "pecmd_timeline"
    assert kind_of("c.csv", "Name,Extension,EntryNumber,UpdateSequenceNumber,UpdateTimestamp,UpdateReasons").kind == "mftecmd_j"
    assert kind_of("20241014_Amcache_ProgramEntries.csv", "ProgramID,LastWriteTimestamp").kind == "amcache"
    assert kind_of("1_SrumECmd_NetworkUsages_Output.csv", "Id,Timestamp").kind == "srumecmd"
    assert kind_of("export.csv", "time,user,action") is None
    assert identify_bytes("20240101_EvtxECmd_Output.csv", (header(EVTX_COLUMNS) + "\n").encode()).artifact == "tool_output"
    assert identify_bytes("export.csv", b"time,user,action\n2024-01-01,alice,logon\n").artifact == "csv"


def test_a_first_line_nested_too_deep_is_matched_by_its_keys():
    """A found file's first line is read up to 64 KB, enough to nest past what json.loads reads, and its RecursionError
    must not stop the load. Such a line is matched by its keys as text, as one too long is."""
    deep = '{"timestamp": "2024-05-14T19:00:00+0700", "event_type": "dns", "x": ' + "[" * 30_000
    assert kind_of("eve.json", deep).kind == "suricata_eve"


def kape_case(tmp_path):
    """WS01 brings only KAPE's module output; DC01 brings raw event logs and EvtxECmd's CSV of them."""
    ev = tmp_path / "evidence"
    write_rows(ev / "WS01" / "Modules" / "EventLogs" / "20240514_EvtxECmd_Output.csv", EVTX_COLUMNS, evtx_rows("WS01.corp.local"))
    write_rows(ev / "WS01" / "Modules" / "ProgramExecution" / "20240514_PECmd_Output.csv", PECMD_COLUMNS, [
        {"SourceFilename": r"C:\Windows\Prefetch\EVIL.EXE-1234ABCD.pf", "ExecutableName": "EVIL.EXE", "RunCount": "1",
         "LastRun": "2024-05-14 12:05:00", "Hash": "1234ABCD"}])
    write_rows(ev / "WS01" / "Modules" / "ProgramExecution" / "20240514_PECmd_Output_Timeline.csv",
               ["RunTime", "ExecutableName"], [{"RunTime": "2024-05-14 12:05:00", "ExecutableName": "EVIL.EXE"}])
    write_rows(ev / "WS01" / "Modules" / "FileFolderAccess" / "alice_UsrClass.csv", SBE_COLUMNS, [
        {"BagPath": "BagMRU\\0", "Slot": "1", "AbsolutePath": "Desktop\\This PC\\C:\\Tools", "ShellType": "Directory",
         "FirstInteracted": "2024-05-14 12:06:00"}])
    logs = ev / "DC01" / "Windows" / "System32" / "winevt" / "Logs"
    logs.mkdir(parents=True)
    (logs / "Security.evtx").write_bytes(b"ElfFile\x00raw")
    write_rows(ev / "DC01" / "Modules" / "EventLogs" / "20240514_EvtxECmd_Output.csv", EVTX_COLUMNS, evtx_rows("DC01.corp.local"))
    (ev / "loose_EvtxECmd_Output.csv").write_text(",".join(EVTX_COLUMNS) + "\n", encoding="utf-8")
    case = create_case(tmp_path / "case", "KAPE", ev, "cody")
    intake(case)
    specs = load_registry()
    detected = {"evtxecmd": DetectedTool(specs["evtxecmd"], tmp_path / "EvtxECmd.exe", "1.0")}   # installed for DC01
    return case, specs, detected


def test_found_output_is_listed_with_raw_evidence_first(tmp_path):
    case, specs, detected = kape_case(tmp_path)
    groups = {(g["key"], g["host"]): g for g in found_outputs(case, specs, detected)}
    assert groups[("evtxecmd_csv", "WS01")]["status"] == "ready"
    assert groups[("evtxecmd_csv", "DC01")]["status"] == "raw"          # EvtxECmd runs on DC01's own logs
    assert groups[("evtxecmd_csv", "")]["status"] == "no_host"          # a CSV in the top level
    assert groups[("pecmd_timeline", "WS01")]["status"] == "no_parser"
    assert groups[("sbecmd_csv", "WS01")]["label"] == "SBECmd CSV"
    # Without EvtxECmd installed, DC01's CSV is the only way to its events, so it's ready too.
    assert {g["host"]: g["status"] for g in found_outputs(case, specs, {}) if g["key"] == "evtxecmd_csv"}["DC01"] == "ready"


def test_found_output_loads_as_a_run_that_rebuild_repeats(tmp_path):
    case, _, _ = kape_case(tmp_path)
    csv_path = "WS01/Modules/EventLogs/20240514_EvtxECmd_Output.csv"
    record = load_found_output(case, "evtxecmd", "evtxecmd_csv", "WS01", [csv_path])
    assert (record.status, record.loaded_rows, record.evidence_check, record.from_output) == ("ok", 2, "ok", True)
    again = load_found_output(case, "evtxecmd", "evtxecmd_csv", "WS01", [csv_path])
    assert again.replaced_rows == 2   # the same events, replaced rather than doubled
    con = connect(case.db_path)
    rows = con.execute("SELECT host, tool, tool_version, source_file, user_name, source_ip, artifact FROM events").fetchall()
    con.close()
    assert len(rows) == 2 and rows[0] == ("WS01", "evtxecmd", "found output",
                                          "D:/KAPE/tout/C/Windows/System32/winevt/Logs/Security.evtx", "alice",
                                          "203.0.113.9", "evtx")
    saved = json.loads((case.runs_folder / record.run_id / "run.json").read_text())
    assert saved["from_output"] and saved["inputs"] == [csv_path] and saved["argv"] == []
    assert [r.run_id for r in rebuild(case)] == [again.run_id]
    con = connect(case.db_path)
    assert con.execute("SELECT count(*) FROM events").fetchone()[0] == 2
    con.close()


def test_loading_from_the_page_job_and_sbecmd_without_its_messages_file(tmp_path):
    case, specs, detected = kape_case(tmp_path)
    for key in ("evtxecmd_csv", "pecmd_csv", "sbecmd_csv"):
        job = start_load_job(case, specs, detected, key, None, False, lambda j: None)
        while not job.finished:
            time.sleep(0.05)
        assert not job.error and [r["host"] for r in job.results] == ["WS01"], (key, job.results)
    loaded = {(r.tool, r.host): r for r in read_runs(case) if r.from_output}
    assert set(loaded) == {("evtxecmd", "WS01"), ("pecmd", "WS01"), ("sbecmd", "WS01")}   # not DC01: raw first
    con = connect(case.db_path)
    bag = con.execute("SELECT user_name, file_path, extra FROM events WHERE tool = 'sbecmd'").fetchone()
    assert bag[0] == "alice" and bag[1] == "C:\\Tools" and json.loads(bag[2])["Hive"] == "UsrClass.dat"
    con.close()
    statuses = {(g["key"], g["host"]): g["status"] for g in found_outputs(case, specs, detected)}
    assert statuses[("evtxecmd_csv", "WS01")] == "loaded" and statuses[("evtxecmd_csv", "DC01")] == "raw"
    job = start_load_job(case, specs, detected, "evtxecmd_csv", ["DC01"], True, lambda j: None)   # Load anyway
    while not job.finished:
        time.sleep(0.05)
    assert [(r["host"], r["status"], r["rows"]) for r in job.results] == [("DC01", "ok", 2)]


def test_a_console_log_in_the_evidence_is_no_tool_output(tmp_path):
    """A 2026.10 build's console log is read beside SBECmd's CSVs, but intake identifies it as a console log, not as
    tool output, and found output lists the CSV alone."""
    from sbecmd_log_fixtures import CONSOLE_LOG_NAME, console_log_text

    from glessner.intake import current_entries

    folder = "WS01/Modules/FileFolderAccess"
    csv_path = f"{folder}/alice_UsrClass.csv"
    text = console_log_text(r"D:\Evidence\WS01\Users\alice\AppData\Local\Microsoft\Windows\UsrClass.dat",
                            r"C:\out\alice_UsrClass.csv")
    first_line = text.split("\r\n", 1)[0]
    assert kind_of(CONSOLE_LOG_NAME, first_line) is None
    assert identify_bytes(CONSOLE_LOG_NAME, text.encode()).artifact == "console_log"
    ev = tmp_path / "evidence"
    write_rows(ev / csv_path, SBE_COLUMNS, [{"BagPath": "BagMRU\\0", "Slot": "1", "AbsolutePath": "Desktop\\This PC\\C:\\Tools"}])
    (ev / folder / CONSOLE_LOG_NAME).write_text(text, encoding="utf-8", newline="")
    case = create_case(tmp_path / "case", "Console log", ev, "cody")
    intake(case)
    assert {e.path: e.artifact for e in current_entries(case)}[f"{folder}/{CONSOLE_LOG_NAME}"] == "console_log"
    groups = found_outputs(case, load_registry(), {})
    assert [(g["key"], g["host"], g["paths"]) for g in groups] == [("sbecmd_csv", "WS01", [csv_path])]


def test_command_line_lists_and_loads_found_output(tmp_path, capsys):
    from glessner.cli import main

    case, _, _ = kape_case(tmp_path)
    assert main(["load-output", str(case.folder)]) == 0
    listed = capsys.readouterr().out
    assert "pecmd_csv" in listed and "1 file on WS01" in listed and "no_host" in listed
    assert main(["load-output", str(case.folder), "pecmd_csv"]) == 0
    assert "PECmd CSV on WS01 (1 file) ...\n  ok: 1 row in" in capsys.readouterr().out


def test_the_command_line_stops_and_reports_as_the_page_does(tmp_path, monkeypatch, capsys):
    """`load-output` and `run --all` go through toolbox.run_and_load, as the page's jobs do. They stop loading found
    output after a load finds the evidence changed, and `run --all` prints the load records' notes."""
    from glessner import toolbox
    from glessner.cli import main
    from glessner.intake import add_new

    case, specs, detected = kape_case(tmp_path)
    write_rows(case.evidence / "WS02" / "Modules" / "FileFolderAccess" / "bob_UsrClass.csv", SBE_COLUMNS, [
        {"BagPath": "BagMRU\\1", "Slot": "2", "AbsolutePath": "Desktop\\This PC\\C:\\Temp", "ShellType": "Directory"}])
    add_new(case)
    assert main(["run", str(case.folder), "--all"]) == 0
    out = capsys.readouterr().out
    assert "SBECmd CSV on WS02 (1 file) ...\n  ok: 1 row in " in out
    assert "\n  1 event has no time: off the timeline, and out of search and exports.\n" in out

    real_group, hosts = toolbox.load_group, []

    def changed_first(c, g, entries=None):
        hosts.append(g["host"])
        records = real_group(c, g, entries)
        if len(hosts) == 1:   # the first load finds its file changed
            records[0].status, records[0].evidence_check = "failed", "mismatch"
        return records
    monkeypatch.setattr(toolbox, "load_group", changed_first)
    write_rows(case.evidence / "WS03" / "Modules" / "EventLogs" / "x_EvtxECmd_Output.csv", EVTX_COLUMNS, evtx_rows("WS03"))
    write_rows(case.evidence / "WS04" / "Modules" / "EventLogs" / "x_EvtxECmd_Output.csv", EVTX_COLUMNS, evtx_rows("WS04"))
    add_new(case)
    assert main(["load-output", str(case.folder), "evtxecmd_csv"]) == 1
    assert hosts == ["WS03"] and capsys.readouterr().err == toolbox.STOP_LOAD + "\n"
    hosts.clear()
    job = start_load_job(case, specs, detected, "evtxecmd_csv", None, False, lambda j: None)
    while not job.finished:
        time.sleep(0.05)
    assert hosts == ["WS04"] and job.error == toolbox.STOP_LOAD and len(job.results) == 1


def test_run_and_load_everything_ready_runs_tools_before_loading_output(tmp_path):
    """The one-folder-in path: the ready tools run first, then ready found output loads."""
    from test_runner import fake_spec

    from glessner.toolbox import everything_ready, start_all_job

    case, specs, _ = kape_case(tmp_path)
    fake = fake_spec(tmp_path)   # reads event logs, like EvtxECmd; its mode argument comes last
    fake = DetectedTool(fake.spec.__class__(**{**fake.spec.__dict__, "args": fake.spec.args[:-1] + ("ok",)}),
                        fake.executable, fake.version)
    specs = {**specs, "fake": fake.spec}
    tools, groups = everything_ready(case, specs, {"fake": fake})
    assert [t.spec.id for t in tools] == ["fake"]
    assert {(g["key"], g["host"]) for g in groups} == {("evtxecmd_csv", "WS01"), ("evtxecmd_csv", "DC01"),
                                                        ("pecmd_csv", "WS01"), ("sbecmd_csv", "WS01")}
    job = start_all_job(case, specs, {"fake": fake}, lambda j: None)
    while not job.finished:
        time.sleep(0.05)
    assert not job.error and job.done == job.total == 5
    assert job.results[0]["host"] == "Fake on DC01" and job.results[0]["status"] == "ok"
    assert all(r["status"] == "ok" for r in job.results)
    assert everything_ready(case, specs, {"fake": fake}) == ([], [])


def test_the_tools_page_reads_the_manifest_once_and_each_file_once(tmp_path, monkeypatch):
    """The Tools page reads the manifest once per version of it, and a file once per process, keyed by its size and
    hash in the manifest, the identity verify checks before any run reads it. Every current_entries call reads
    unidentified files with a text log's name again, and the page makes three calls: if each statted every such file,
    a 0.3 s load of 20,000 of them would take 7 s. With more files to read again than the file cache holds, the kept
    result is what stops every call from reading them all."""
    from glessner import intake as intake_module
    from glessner.intake import add_new
    from glessner.server import App, api_tools

    case, specs, detected = kape_case(tmp_path)
    for n in range(3):
        (case.evidence / "WS01" / f"cache_{n}").write_bytes(b"\x01\x02" + bytes(100))   # no name or content to know
    add_new(case)
    app = App(case)
    app.tool_cache = (specs, detected)
    counts = {"manifest": 0, "files": 0}
    real_manifest, real_identify = intake_module.read_manifest, intake_module.identify_file

    def manifest(c):
        counts["manifest"] += 1
        return real_manifest(c)

    def identify(path):
        counts["files"] += 1
        return real_identify(path)

    monkeypatch.setattr(intake_module, "read_manifest", manifest)
    monkeypatch.setattr(intake_module, "identify_file", identify)
    page = api_tools(app, {})
    assert (page["unidentified"], counts) == (3, {"manifest": 1, "files": 3})
    api_tools(app, {})
    assert counts == {"manifest": 1, "files": 3}
    os.utime(case.evidence / "WS01" / "cache_0", ns=(0, 10**18))   # a new time, with the content the manifest records
    (case.evidence / "WS01" / "cache_3").write_bytes(b"\x01\x02" + bytes(101))
    add_new(case)   # reads the manifest and the new file once each
    page = api_tools(app, {})
    assert (page["unidentified"], counts) == (4, {"manifest": 3, "files": 5})   # and the new file once again, alone
    app.con.close()


def test_the_tools_page_lists_console_logs_as_files_no_tool_reads_not_as_unidentified(tmp_path):
    """Each of Eric Zimmerman's tools writes <stamp>_<Tool>_<version>_ConsoleLog.txt beside its output from 2026.10. A case
    whose intake left such a log unidentified reads it as a console log too."""
    from glessner.toolbox import overview

    log = tmp_path / "evidence" / "WS01" / "EventLogs" / "20261026060736_EvtxECmd_2026.10.2_ConsoleLog.txt"
    log.parent.mkdir(parents=True)
    log.write_bytes(b"[13:08:02.051 INF] EvtxECmd version 2026.10.2\r\n\r\nAuthor: Eric Zimmerman\r\n")
    case = create_case(tmp_path / "case", "Console logs", tmp_path / "evidence", "cody")
    intake(case)
    page = overview(case, load_registry(), {})
    assert (page["unidentified"], page["unread"]) == (0, [{"what": "1 Eric Zimmerman console log"}])
    (entry,) = [json.loads(line) for line in case.manifest_path.read_text(encoding="utf-8").splitlines()]
    assert (entry["artifact"], entry["detail"]) == ("console_log", "EvtxECmd")
    older = {**entry, "artifact": None, "method": "unidentified", "detail": ""}   # as an older build's intake recorded it
    case.manifest_path.write_bytes(f"{json.dumps(older)}\n".encode())
    page = overview(case, load_registry(), {})
    assert (page["unidentified"], page["unread"]) == (0, [{"what": "1 Eric Zimmerman console log"}])


def test_the_tools_page_answers_before_intake(tmp_path):
    """The overview reads no manifest before intake, and the page takes both of its passes, tools and found output, from
    that one overview, so a second pass over found output can't fail with FileNotFoundError."""
    from glessner.server import App, api_tools

    (tmp_path / "evidence").mkdir()
    app = App(create_case(tmp_path / "case", "Not taken in", tmp_path / "evidence", "cody"))
    app.tool_cache = (load_registry(), {})
    page = api_tools(app, {})
    assert (page["unidentified"], page["outputs"], page["ready"]) == (0, [], {"tools": [], "outputs": 0})
    app.con.close()


def test_a_load_that_fails_partway_still_refreshes_the_case_and_records_its_run(tmp_path, monkeypatch):
    """A load that raises leaves its run failed, not "running", which the Tools page and rebuild skip without a reason,
    and a fault partway through a job still runs `after`, so loads that committed reach the derived tables without the
    case being opened again."""
    from test_runner import fake_spec

    from glessner import runner, toolbox
    from glessner.toolbox import start_all_job

    case, specs, detected = kape_case(tmp_path)
    real_load, real_group = runner.load, toolbox.load_group

    def broken(*args, **kwargs):
        raise RuntimeError("the database refused it")
    monkeypatch.setattr(runner, "load", broken)
    record = load_found_output(case, "evtxecmd", "evtxecmd_csv", "WS01", ["WS01/Modules/EventLogs/20240514_EvtxECmd_Output.csv"])
    assert (record.status, record.reason) == ("failed", "could not load: RuntimeError: the database refused it")
    assert json.loads((case.runs_folder / record.run_id / "run.json").read_text())["status"] == "failed"
    monkeypatch.setattr(runner, "load", real_load)

    hosts, refreshed = [], []

    def second_fails(c, g, entries=None):
        hosts.append(g["host"])
        return broken() if len(hosts) > 1 else real_group(c, g, entries)
    monkeypatch.setattr(toolbox, "load_group", second_fails)
    after = lambda job: refreshed.append([r["status"] for r in job.results])
    job = start_load_job(case, specs, detected, "evtxecmd_csv", None, True, after)   # Load anyway: DC01, then WS01
    while not job.finished:
        time.sleep(0.05)
    assert hosts == ["DC01", "WS01"] and job.error == "RuntimeError: the database refused it"
    assert refreshed == [["ok"]]

    refreshed.clear()
    fake = fake_spec(tmp_path)
    fake = DetectedTool(fake.spec.__class__(**{**fake.spec.__dict__, "args": fake.spec.args[:-1] + ("ok",)}),
                        fake.executable, fake.version)
    monkeypatch.setattr(toolbox, "load_group", lambda c, g, entries=None: broken())
    job = start_all_job(case, {**specs, "fake": fake.spec}, {"fake": fake}, after)
    while not job.finished:
        time.sleep(0.05)
    assert job.error == "RuntimeError: the database refused it" and refreshed == [["ok"]]   # the tool's run, then the fault


RECMD_FOLDER = "WS01/Modules/Registry"
RECMD_CSV = f"{RECMD_FOLDER}/20240514120000_RECmd_Batch_Kroll_Batch_Output.csv"
RECMD_RAN = "20240514120000"   # the folder RECmd writes its plugin CSVs in, named for when it ran
RECMD_PAIRS = {"UserAssist": userassist("cmd.exe", "2015-03-22 15:52:15.9991623"),
               "UserAccounts": sam_account("1000", "informant", login="2015-03-25 09:58:04.4373155")}


def recmd_detail(plugin):
    """The evidence-relative path of a plugin's detail CSV beside the batch CSV."""
    return f"{RECMD_FOLDER}/{RECMD_RAN}/{Path(RECMD_CSV).stem}_{plugin}.csv"


def recmd_found_case(tmp_path, listed=tuple(RECMD_PAIRS), copies=(), copied=RECMD_PAIRS["UserAccounts"][1], named=()):
    """A case whose evidence holds KAPE's RECmd output for WS01: the batch CSV, with a UserAssist row and a SAM account
    row that name their plugins' CSVs where RECmd wrote them on the collecting machine, and those CSVs in the folder
    RECmd named for its run, the plugins of `listed` before intake and the others after. DC01's folder holds a copy of
    the SAM plugin's CSV, which intake hashes, and each evidence-relative path of `copies` holds the SAM detail row
    `copied`. Each name in `named` is a file in the run's folder that one more UserAssist row names, which the caller
    writes there first."""
    evidence = tmp_path / "evidence"
    rows = [{**{k: v for k, v in main.items() if k != "plugin"},
             "PluginDetailFile": f"C:\\KAPE\\out\\Registry\\{RECMD_RAN}\\{Path(RECMD_CSV).stem}_{plugin}.csv"}
            for plugin, (main, _) in RECMD_PAIRS.items()]
    rows += [{**{k: v for k, v in RECMD_PAIRS["UserAssist"][0].items() if k != "plugin"},
              "PluginDetailFile": f"C:\\KAPE\\out\\Registry\\{RECMD_RAN}\\{name}"} for name in named]
    write_rows(evidence / RECMD_CSV, RECMD_COLUMNS, rows)
    write_detail(evidence / recmd_detail("UserAccounts").replace("WS01", "DC01", 1), [RECMD_PAIRS["UserAccounts"][1]])
    for copy in copies:
        write_detail(evidence / copy, [copied])
    for plugin in listed:
        write_detail(evidence / recmd_detail(plugin), [RECMD_PAIRS[plugin][1]])
    case = create_case(tmp_path / "case", "KAPE", evidence, "cody")
    intake(case)
    for plugin in set(RECMD_PAIRS) - set(listed):
        write_detail(evidence / recmd_detail(plugin), [RECMD_PAIRS[plugin][1]])
    return case


def test_found_output_reads_only_hashed_detail_csvs_of_its_host(tmp_path):
    """A load of RECmd's batch CSV found in the evidence reads a plugin's detail CSV only from the folder RECmd named
    for its run beside the batch CSV, and only when intake hashed it: one put there since is read from nowhere else,
    not another host's copy either, and the run's notes count the rows naming it. The run's input is the batch CSV."""
    case = recmd_found_case(tmp_path, listed=("UserAssist",))
    record = load_found_output(case, "recmd", "recmd_csv", "WS01", [RECMD_CSV])
    assert (record.status, record.evidence_check, record.inputs) == ("ok", "ok", [RECMD_CSV])
    assert record.loaded_rows == 3   # the two rows' LastWrite events and the program's last run
    assert f"{DETAILS_NOTE}1 entry time became an event. 1 row named a detail file the load may not read." in record.notes
    con = connect(case.db_path, read_only=True)
    try:
        assert con.execute("SELECT ts_desc FROM events ORDER BY ts_desc").fetchall() == [
            ("Registry Key LastWrite",), ("Registry Key LastWrite",), ("UserAssist last executed",)]
    finally:
        con.close()


def test_found_output_checks_its_detail_csvs_against_their_intake_hashes(tmp_path):
    """The detail CSVs a load of RECmd's batch CSV reads are checked against their intake hashes before and after it
    reads them and on each rebuild, as the batch CSV is, though the run's inputs are the batch CSV alone, which the
    Tools page shows as loaded. A detail CSV that changed fails the load, and a rebuild leaves the run out."""
    case = recmd_found_case(tmp_path)
    record = load_found_output(case, "recmd", "recmd_csv", "WS01", [RECMD_CSV])
    assert (record.status, record.evidence_check, record.inputs, record.loaded_rows) == ("ok", "ok", [RECMD_CSV], 5)
    groups = {g["key"]: g for g in found_outputs(case, load_registry(), {}) if g["host"] == "WS01"}
    assert groups["recmd_csv"]["status"] == "loaded"
    assert groups["recmd_plugin"]["note"] == BY_KIND["recmd_plugin"].note == (
        "Details from RECmd's plugins, loaded with the batch CSV that names them")
    (saved,) = read_runs(case)
    assert run_problems(case, saved, "test") == ([], [])
    write_detail(case.evidence / recmd_detail("UserAssist"), [userassist("evil.exe", "2015-03-22 15:52:15.9991623")[1]])
    assert run_problems(case, saved, "test") == ([f"{recmd_detail('UserAssist')}: SHA-256 changed"], [])
    rebuild(case)
    (rebuilt,) = read_runs(case)
    assert rebuilt.loaded_rows == 0 and LEFT_OUT in rebuilt.notes[-1]
    again = load_found_output(case, "recmd", "recmd_csv", "WS01", [RECMD_CSV])
    assert (again.status, again.evidence_check) == ("failed", "mismatch")
    assert f"{recmd_detail('UserAssist')}: SHA-256 changed" in again.reason
    assert recmd_detail("UserAccounts") not in again.reason


def test_found_output_checks_only_the_detail_csvs_just_below_its_batch_csv(tmp_path):
    """A load of RECmd's batch CSV checks and may read only the plugin CSVs in a folder directly below the batch CSV's
    folder. A plugin CSV of the same host deeper down or in another folder isn't one of them, so a change to it after
    intake leaves the load as it was."""
    elsewhere = (f"WS01/Other/{RECMD_RAN}/{Path(RECMD_CSV).stem}_UserAccounts.csv",
                 f"{RECMD_FOLDER}/{RECMD_RAN}/older/{Path(RECMD_CSV).stem}_UserAccounts.csv")
    case = recmd_found_case(tmp_path, copies=elsewhere)
    record = load_found_output(case, "recmd", "recmd_csv", "WS01", [RECMD_CSV])
    assert (record.status, record.evidence_check, record.loaded_rows) == ("ok", "ok", 5)
    (saved,) = read_runs(case)
    assert companions(case, saved) == (sorted(recmd_detail(plugin) for plugin in RECMD_PAIRS), [])
    for path in elsewhere:
        write_detail(case.evidence / path, [sam_account("1001", "admin11")[1]])
    assert run_problems(case, saved, "test") == ([], [])
    again = load_found_output(case, "recmd", "recmd_csv", "WS01", [RECMD_CSV])
    assert (again.status, again.evidence_check, again.loaded_rows) == ("ok", "ok", 5)


def test_found_output_reads_no_other_kind_of_csv_beside_its_plugin_csvs(tmp_path):
    """A load of RECmd's batch CSV checks and may read only the files below it that intake identified as RECmd plugin
    output. A CSV in the same folder that intake listed as something else, here a plain CSV named as a plugin's would
    be and EvtxECmd's output, isn't one of them, even where a batch row names it: the notes count those rows as naming
    a file the load may not read, and a change to either file after intake leaves the load as it was."""
    folder = tmp_path / "evidence" / RECMD_FOLDER / RECMD_RAN
    plain, evtx = f"{Path(RECMD_CSV).stem}_Notes.csv", "20240514120000_EvtxECmd_Output.csv"
    write_rows(folder / plain, ["time", "user", "action"], [{"time": "2024-05-14", "user": "alice", "action": "logon"}])
    write_rows(folder / evtx, EVTX_COLUMNS, evtx_rows("WS01.corp.local"))
    case = recmd_found_case(tmp_path, named=(plain, evtx))
    record = load_found_output(case, "recmd", "recmd_csv", "WS01", [RECMD_CSV])
    assert (record.status, record.evidence_check, record.loaded_rows) == ("ok", "ok", 7)
    assert [n for n in record.notes if n.startswith(DETAILS_NOTE)] == [
        f"{DETAILS_NOTE}3 entry times became events. 2 rows named a detail file the load may not read."]
    (saved,) = read_runs(case)
    assert companions(case, saved) == (sorted(recmd_detail(plugin) for plugin in RECMD_PAIRS), [])
    write_rows(folder / plain, ["time", "user", "action"], [{"time": "2024-05-15", "user": "mallory", "action": "logon"}])
    write_rows(folder / evtx, EVTX_COLUMNS, evtx_rows("WS01.corp.local", records=(1,)))
    assert run_problems(case, saved, "test") == ([], [])
    again = load_found_output(case, "recmd", "recmd_csv", "WS01", [RECMD_CSV])
    assert (again.status, again.evidence_check, again.loaded_rows) == ("ok", "ok", 7)


def test_found_output_reads_no_plugin_csv_whose_manifest_entry_has_a_read_error(tmp_path, monkeypatch):
    """A plugin CSV whose manifest entry records a read error has no hash to check it by, so a load of the batch CSV
    found in the evidence may not read it, though the entry names it as RECmd plugin output."""
    from glessner import runner
    from glessner.intake import current_entries

    case = recmd_found_case(tmp_path)
    load_found_output(case, "recmd", "recmd_csv", "WS01", [RECMD_CSV])
    (saved,) = read_runs(case)
    entries, unread = current_entries(case), recmd_detail("UserAssist")
    monkeypatch.setattr(runner, "current_entries", lambda c: [
        replace(e, error="PermissionError: access denied") if e.path == unread else e for e in entries])
    assert detail_files(case, saved) == [recmd_detail("UserAccounts")]


def test_found_output_reads_the_plugin_csv_in_the_folder_its_row_names(tmp_path):
    """Other RECmd runs' folders beside the one a row names can hold a plugin CSV of the same name, which intake hashes
    too. The load reads the row's details from the CSV in the folder the row names, wherever the others sort."""
    siblings = tuple(f"{RECMD_FOLDER}/{ran}/{Path(RECMD_CSV).stem}_UserAccounts.csv"
                     for ran in ("20240514110000", "20240514130000"))
    case = recmd_found_case(tmp_path, copies=siblings, copied={**RECMD_PAIRS["UserAccounts"][1], "TotalLoginCount": "7"})
    record = load_found_output(case, "recmd", "recmd_csv", "WS01", [RECMD_CSV])
    assert (record.status, record.evidence_check, record.loaded_rows) == ("ok", "ok", 5)
    con = connect(case.db_path, read_only=True)
    try:
        counts = con.execute("SELECT ts_desc, json_extract_string(extra, '$.TotalLoginCount') FROM events "
                             "WHERE json_extract_string(extra, '$.UserId') = '1000' ORDER BY ts_desc").fetchall()
    finally:
        con.close()
    assert counts == [("Registry Key LastWrite", "0"), ("SAM account last logon", "0"),
                      ("SAM account name key last write", "0")]


def test_a_rebuild_replaces_the_detail_note(tmp_path):
    """A rebuild loads a run again and replaces its note on what the plugin CSVs added, so the note stands once."""
    case = recmd_found_case(tmp_path)
    record = load_found_output(case, "recmd", "recmd_csv", "WS01", [RECMD_CSV])
    note = [f"{DETAILS_NOTE}3 entry times became events."]
    assert [n for n in record.notes if n.startswith(DETAILS_NOTE)] == note
    rebuild(case)
    rebuild(case)
    (rebuilt,) = read_runs(case)
    assert rebuilt.loaded_rows == 5
    assert [n for n in rebuilt.notes if n.startswith(DETAILS_NOTE)] == note
