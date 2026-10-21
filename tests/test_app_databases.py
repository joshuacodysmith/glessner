"""SQLite application databases: recognition, SQLECmd's browser and notification maps,
WxTCmd's Windows Timeline, nothing-to-report runs, and working copies past Windows' path limit."""

import csv
import os
from pathlib import Path, PureWindowsPath

import pytest

from glessner.identify import identify_bytes
from glessner.long_paths import long_path
from glessner.parsers import PARSERS, ParseContext
from glessner.runner import RunRecord, _status
from glessner.tool_outputs import kind_of
from glessner.tools import load_registry

SQLITE = b"SQLite format 3\x00" + b"\x00" * 84
VISITS = ["ID", "VisitTime (UTC)", "LastVisitedTime (UTC)", "URLTitle", "URL", "VisitCount", "TypedCount", "Hidden",
          "VisitID", "FromVisitID", "VisitDurationInSeconds", "SourceFile"]
DOWNLOADS = ["ID", "GUID", "CurrentPath", "TargetPath", "OriginalMIMEType", "ReceivedBytes", "TotalBytes", "StartTime",
             "EndTime", "Opened", "LastAccessTime", "LastModified", "State", "DangerType", "InterruptReason",
             "ReferrerURL", "SiteURL", "TabURL", "TabReferrerURL", "DownloadURL", "SourceFile"]
NOTIFICATIONS = ["ID", "Order", "HandlerId", "Application", "Parent", "HandlerType", "Type", "Payload", "PayloadType",
                 "Tag", "Group", "ArrivalTime", "ExpirationTime", "SourceFile"]
ACTIVITY = ["Id", "ActivityTypeOrg", "ActivityType", "Executable", "DisplayText", "ContentInfo", "Payload",
            "ClipboardPayload", "StartTime", "EndTime", "Duration", "LastModifiedTime", "LastModifiedOnClient",
            "OriginalLastModifiedOnClient", "ExpirationTime", "CreatedInCloud", "IsLocalOnly", "ETag", "PackageIdHash",
            "PlatformDeviceId", "DevicePlatform", "TimeZone"]
EDGE = "D:\\Evidence\\case\\WS01\\Users\\bob\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\History"


def write(path, columns, rows):
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=columns)
        w.writeheader()
        w.writerows(rows)


def test_databases_and_their_logs_are_recognized():
    assert identify_bytes("History", SQLITE).detail == "Chromium history"
    assert identify_bytes("ActivitiesCache.db", SQLITE).detail == "ActivitiesCache"
    assert identify_bytes("app.db", SQLITE).detail == "SQLite database"
    assert (identify_bytes("ActivitiesCache.db-wal", b"\x37\x7f\x06\x82").artifact,
            identify_bytes("History-journal", b"").artifact) == ("sqlite_log", "sqlite_log")
    assert identify_bytes("random.db-wal", b"\x37\x7f\x06\x82").artifact != "sqlite_log"   # not a known database's log
    assert kind_of("20261014_ChromiumBrowser_HistoryVisits_1f37cc07-2b10-4c80-b845-84708e4f7429.csv", "ID").parser \
        == "sqlecmd_csv"
    assert kind_of("20261014_bob_Activity.csv", ",".join(ACTIVITY)).parser == "wxtcmd_csv"
    specs = load_registry()
    assert specs["sqlecmd"].work_on_copies and specs["sqlecmd"].copy_also == ("sqlite_log",)
    assert specs["wxtcmd"].handles == ("sqlite:ActivitiesCache",) and specs["wxtcmd"].run_in_run_folder


def test_a_databases_logs_count_as_read_when_its_tool_is_installed(tmp_path):
    """The Tools page counts SQLite log files as read when SQLECmd or WxTCmd is installed, since those tools copy them."""
    from glessner.case import create_case
    from glessner.intake import intake
    from glessner.toolbox import overview
    from glessner.tools import DetectedTool

    profile = tmp_path / "evidence" / "WS01" / "Users" / "bob" / "AppData" / "Local" / "ConnectedDevicesPlatform"
    profile.mkdir(parents=True)
    (profile / "ActivitiesCache.db").write_bytes(SQLITE)
    (profile / "ActivitiesCache.db-wal").write_bytes(b"\x37\x7f\x06\x82" + b"\x00" * 28)
    case = create_case(tmp_path / "case", "Timeline", tmp_path / "evidence", "cody")
    intake(case)
    specs = load_registry()
    unread = lambda detected: [u["what"] for u in overview(case, specs, detected)["unread"]]
    assert unread({}) == ["1 SQLite database", "1 SQLite log file"]
    assert unread({"wxtcmd": DetectedTool(specs["wxtcmd"], tmp_path / "WxTCmd.exe", "2026.5.0")}) == []


def test_sqlecmd_maps_become_browser_and_notification_events(tmp_path):
    out = tmp_path / "run" / "output"
    out.mkdir(parents=True)
    copy = str(tmp_path / "run" / "input" / "WS01" / "Users" / "bob" / "AppData" / "Local" / "Microsoft" / "Edge" /
               "User Data" / "Default" / "History")
    write(out / "1_ChromiumBrowser_HistoryVisits_1f37cc07-2b10-4c80-b845-84708e4f7429.csv", VISITS, [
        {"ID": "7", "VisitID": "70", "VisitTime (UTC)": "2024-05-14 12:00:00", "URL": "https://evil.example/x",
         "URLTitle": "Evil", "SourceFile": copy},
        {"ID": "8", "VisitID": "", "VisitTime (UTC)": "", "URL": "https://never.example/", "SourceFile": copy}])
    write(out / "2_ChromiumBrowser_Downloads_0b575bcf-ade3-44e5-8162-eb52a96c2b06.csv", DOWNLOADS, [
        {"ID": "3", "TargetPath": "C:\\Users\\bob\\Downloads\\tool.exe", "StartTime": "2024-05-14 12:01:00",
         "EndTime": "2024-05-14 12:01:05", "Opened": "1601-01-01 00:00:00", "DownloadURL": f"https://evil.example/{n}",
         "SourceFile": EDGE} for n in ("a", "b")])   # a redirected download repeats its row
    write(out / "3_Windows_NotificationsDB-Notifications_cd952d69-7b3e-4d13-9810-8d987155bc58.csv", NOTIFICATIONS, [
        {"ID": "1", "Application": "Microsoft.Windows.Defender", "ArrivalTime": "2024-05-14 12:02:00",
         "Payload": "<toast><visual><binding><text>Threats found</text><text>Action needed</text></binding></visual></toast>",
         "SourceFile": "D:\\Evidence\\case\\WS01\\Users\\bob\\AppData\\Local\\Microsoft\\Windows\\Notifications\\"
                       "wpndatabase.db"}])
    write(out / "4_Windows_ActivitiesCacheDB_d0022b46-3896-4b9f-a9e5-499241eba806.csv", ["Id", "StartTime"],
          [{"Id": "1", "StartTime": "2024-05-14 19:00:00"}])   # a map that writes local time: left out
    events = list(PARSERS["sqlecmd_csv"](ParseContext(out, Path("D:/Evidence/case"))))
    assert [(e.event_code, e.ts_desc) for e in events] == [
        ("visit", "URL visited"), ("download", "Download started"), ("download", "Download finished"),
        ("notification", "Notification arrived")]
    visit, start, _, toast = events
    assert visit.source_file == "WS01/Users/bob/AppData/Local/Microsoft/Edge/User Data/Default/History"   # not the copy
    assert (visit.user_name, visit.message, visit.ts_us) == ("bob", "Edge visit: https://evil.example/x (Evil)",
                                                             1715688000000000)
    assert start.file_path == "C:\\Users\\bob\\Downloads\\tool.exe" and start.message.endswith("from https://evil.example/a")
    assert toast.message == "Notification from Microsoft.Windows.Defender: Threats found | Action needed"
    assert toast.artifact == "notification"


def test_wxtcmd_activities_start_and_end(tmp_path):
    write(tmp_path / "20261014_IEUser_Activity.csv", ACTIVITY, [
        {"Id": "a1", "ActivityType": "InFocus", "Executable": "C:\\Windows\\System32\\cmd.exe",
         "DisplayText": "Command Prompt", "StartTime": "2024-05-14 12:00:00", "EndTime": "2024-05-14 12:10:00"},
        {"Id": "a2", "ActivityType": "ExecuteOpen", "Executable": "Microsoft.Windows.Explorer",
         "ContentInfo": "secret.docx (file:///C:/Users/IEUser/secret.docx)", "StartTime": "2024-05-14 12:05:00"}])
    ctx = ParseContext(tmp_path, Path("D:/Evidence/case"),
                       ("WS01/Users/IEUser/AppData/Local/ConnectedDevicesPlatform/L.IEUser/ActivitiesCache.db",))
    focus_start, focus_end, opened = PARSERS["wxtcmd_csv"](ctx)
    assert (focus_start.ts_desc, focus_end.ts_desc, focus_end.ts_us - focus_start.ts_us) == (
        "Timeline activity started", "Timeline activity ended", 600_000_000)
    assert (focus_start.user_name, focus_start.event_code, focus_start.process_executable) == (
        "IEUser", "InFocus", "C:\\Windows\\System32\\cmd.exe")
    assert opened.message == ("Timeline ExecuteOpen: Microsoft.Windows.Explorer - "
                              "secret.docx (file:///C:/Users/IEUser/secret.docx)")
    found = list(PARSERS["wxtcmd_csv"](ParseContext(tmp_path, Path("D:/Evidence/case"), (),
                                                    (tmp_path / "20261014_IEUser_Activity.csv",))))
    assert {e.user_name for e in found} == {"IEUser"}   # found in the evidence: the user from the file name


def test_nothing_to_report_is_ok_only_where_the_registry_says_so():
    record = RunRecord(run_id="r", tool="t", tool_version="1", executable="", host="h", argv=[], cwd="", inputs=[],
                       started_utc="", exit_code=0, missing_outputs=["*_Activity.csv"])
    assert _status(record, "No activities.") == ("failed", "No activities.")   # the runner turns it ok for empty_ok
    assert load_registry()["wxtcmd"].empty_ok and not load_registry()["rbcmd"].empty_ok


@pytest.mark.skipif(os.name != "nt", reason="Windows' path limit")
def test_working_copies_pass_the_windows_path_limit(tmp_path):
    """A working copy repeats the evidence's own folders, such as AppData/Local/ConnectedDevicesPlatform/L.<user>,
    under the run folder, and the two together can pass Windows' 260-character limit. The runner makes and reads each
    copy through its extended-length path (long_path), which has none."""
    rel = "/".join([*["ConnectedDevicesPlatform_L.Administrator"] * 8, "ActivitiesCache.db"])
    assert len(str(tmp_path / rel)) > 260
    target = long_path(tmp_path, rel)
    target.parent.mkdir(parents=True)
    target.write_bytes(SQLITE)
    assert str(target).startswith("\\\\?\\") and target.read_bytes() == SQLITE


def old_sqlecmd_run(case, run_id="sqlecmd-WS01-1"):
    """A SQLECmd run in a case's run folder as a run made before runs recorded their working copies' folder: its
    output names the copy of bob's Edge history in that folder."""
    import json

    folder = case.runs_folder / run_id
    (folder / "output").mkdir(parents=True)
    history = "WS01/Users/bob/AppData/Local/Microsoft/Edge/User Data/Default/History"
    write(folder / "output" / "1_ChromiumBrowser_HistoryVisits_1f37cc07-2b10-4c80-b845-84708e4f7429.csv", VISITS, [
        {"ID": "7", "VisitID": "70", "VisitTime (UTC)": "2024-05-14 12:00:00", "URL": "https://evil.example/x",
         "SourceFile": str(folder / "input" / PureWindowsPath(history))}])
    (folder / "input").mkdir()
    record = RunRecord(run_id=run_id, tool="sqlecmd", tool_version="1", executable="", host="WS01", argv=[], cwd="",
                       inputs=[history], started_utc="", status="ok", parser="sqlecmd_csv", working_copies=[history])
    record_json = {k: v for k, v in vars(record).items() if k != "input_root"}
    (folder / "run.json").write_text(json.dumps(record_json, indent=2), encoding="utf-8")
    return history


def test_sqlecmd_events_keep_their_source_in_a_copied_or_moved_case(tmp_path):
    """SQLECmd's output names the working copies by where the case was when it ran. A run records that
    folder, so a copy or a move of the case reads the same evidence path, account, and event ID; parsed against the
    new folder alone, the path would be the old case's, the account the analyst's own, and the ID another. A run made before
    runs recorded it reads what follows its run's folder too, and keeps format 1's source in Event.former, for the case
    format upgrade that maps its old IDs to the new."""
    from glessner.events import event_uid

    first = PureWindowsPath("C:/Users/analyst/cases/a/runs/r1")   # where it ran; the test's files lie in tmp_path
    out = tmp_path / "b" / "runs" / "r1" / "output"
    out.mkdir(parents=True)
    history = "WS01/Users/bob/AppData/Local/Microsoft/Edge/User Data/Default/History"
    write(out / "1_ChromiumBrowser_HistoryVisits_1f37cc07-2b10-4c80-b845-84708e4f7429.csv", VISITS, [
        {"ID": "7", "VisitID": "70", "VisitTime (UTC)": "2024-05-14 12:00:00", "URL": "https://evil.example/x",
         "SourceFile": str(first / "input" / PureWindowsPath(history))}])
    parse = lambda **ctx: next(iter(PARSERS["sqlecmd_csv"](ParseContext(out, Path("D:/Evidence/case"), **ctx))))
    moved = parse(input_root=str(first / "input"))
    assert (moved.source_file, moved.user_name) == (history, "bob")
    uid = lambda e: event_uid("WS01", e.artifact, e.source_file, e.source_record, e.ts_desc)
    assert uid(moved) == event_uid("WS01", "browser", history, "visit|70", "URL visited")
    # A run without the record reads the path inside its run's folder, wherever that was; format 1's rule reads the old
    # case's path and the analyst's own account
    before = parse(former=1)
    assert (before.source_file, before.user_name) == (history, "bob") and uid(before) == uid(moved)
    assert before.former == ((first / "input" / PureWindowsPath(history)).as_posix(), "visit|70")


def test_a_moved_evidence_folder_keeps_its_runs_source_files(tmp_path):
    """A tool names the evidence files it read by where the evidence was when it ran, which its run records. After the
    evidence folder moves and case.yaml names the new one, a rebuild reads the same evidence paths and IDs; a run made
    before runs recorded it reads them against the case's evidence folder."""
    import json

    from glessner.case import create_case
    from glessner.events import connect
    from glessner.runner import rebuild

    (tmp_path / "evidence" / "WS01").mkdir(parents=True)
    case = create_case(tmp_path / "case", "Moved", tmp_path / "evidence", "cody")
    history = "WS01/Users/bob/AppData/Local/Microsoft/Edge/User Data/Default/History"
    for n, recorded in enumerate(("D:/Evidence/before-the-move", ""), 1):
        run_id = f"sqlecmd-WS01-{n}"
        (case.runs_folder / run_id / "output").mkdir(parents=True)
        write(case.runs_folder / run_id / "output" / "1_ChromiumBrowser_HistoryVisits_1f37cc07-2b10-4c80-b845-84708e4f7429.csv",
              VISITS, [{"ID": "7", "VisitID": "70", "VisitTime (UTC)": "2024-05-14 12:00:00",
                        "SourceFile": str(PureWindowsPath("D:/Evidence/before-the-move") / history)}])
        record = RunRecord(run_id=run_id, tool="sqlecmd", tool_version="1", executable="", host="WS01", argv=[], cwd="",
                           inputs=[f"{history}-{run_id}"], started_utc="", status="ok", parser="sqlecmd_csv",
                           evidence_root=recorded)
        (case.runs_folder / run_id / "run.json").write_text(json.dumps(vars(record)), encoding="utf-8")
    rebuild(case)
    con = connect(case.db_path, read_only=True)
    got = dict(con.execute("SELECT run_id, source_file FROM events").fetchall())
    con.close()
    assert got == {"sqlecmd-WS01-1": history, "sqlecmd-WS01-2": f"D:/Evidence/before-the-move/{history}"}


def test_a_case_copy_reads_an_older_runs_copies_as_evidence_paths(tmp_path):
    """copy_case names the source's working-copy folder in each copied run that predates the record, so the copy's
    events have the source's evidence paths and IDs."""
    from glessner.case import copy_case, create_case
    from glessner.events import connect
    from glessner.runner import read_runs, rebuild

    (tmp_path / "evidence" / "WS01").mkdir(parents=True)
    source = create_case(tmp_path / "case", "Source", tmp_path / "evidence", "cody")
    history = old_sqlecmd_run(source)
    rebuild(source)
    copy = copy_case(source, tmp_path / "copy", "Copy", "cody")
    rebuild(copy)
    rows = []
    for case in (source, copy):
        con = connect(case.db_path, read_only=True)
        rows.append(con.execute("SELECT event_uid, source_file, user_name FROM events").fetchall())
        con.close()
    assert rows[0] == rows[1] and rows[0][0][1:] == (history, "bob")
    (copied,) = read_runs(copy)
    assert copied.input_root == str(source.runs_folder / copied.run_id / "input")
    assert read_runs(source)[0].input_root == ""   # the source's own run is left as it was


def test_a_stop_inside_a_copied_run_s_record_write_leaves_the_record_as_copied(tmp_path, monkeypatch):
    """copy_case writes an older run's run.json through write_atomically to name the source's working-copy folder, so a
    stop inside the write leaves the copy's record as the source's, not a cut-short one that every later read of the
    copy's runs fails on."""
    from glessner.case import copy_case, create_case

    (tmp_path / "evidence" / "WS01").mkdir(parents=True)
    source = create_case(tmp_path / "case", "Source", tmp_path / "evidence", "cody")
    old_sqlecmd_run(source)
    (record,) = source.runs_folder.glob("*/run.json")
    original = Path.open

    def interrupted(path, mode="r", *args, **kwargs):
        stream = original(path, mode, *args, **kwargs)
        if path.name.startswith("run.json") and mode.startswith("w"):
            stream.close()
            raise OSError("interrupted after opening run.json for writing")
        return stream

    monkeypatch.setattr(Path, "open", interrupted)
    with pytest.raises(OSError, match="interrupted"):
        copy_case(source, tmp_path / "copy", "Copy", "cody")
    monkeypatch.undo()
    copied = tmp_path / "copy" / "runs" / record.parent.name / "run.json"
    assert copied.read_bytes() == record.read_bytes()
    assert not (tmp_path / "copy" / "case.yaml").exists()   # not a case, so nothing opens it half made
