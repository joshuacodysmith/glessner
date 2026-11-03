"""SQLite application databases: recognition, SQLECmd's browser and notification maps and the app's own maps,
WxTCmd's Windows Timeline, nothing-to-report runs, and working copies past Windows' path limit."""

import csv
import os
import re
import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path, PureWindowsPath

import pytest
import yaml

from glessner.identify import identify_bytes
from glessner.long_paths import long_path
from glessner.parsers import PARSERS, ParseContext, sqlecmd
from glessner.runner import RunRecord, _status
from glessner.tool_outputs import kind_of
from glessner.tools import REGISTRY_DIR, load_registry

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
@pytest.mark.usefixtures("tmp_path_removed")
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


APP_MAPS = REGISTRY_DIR / "sqlecmd_maps"
WITHOUT_GUID = APP_MAPS / "Glessner_ChromiumBrowser_DownloadsWithoutGUID.smap"
VISIT_SOURCES = APP_MAPS / "Glessner_ChromiumBrowser_VisitSources.smap"
GUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
# A Chromium History's downloads columns at schema version 29, which has no downloads.guid, and columns added since
# that SQLECmd's downloads map reads
SCHEMA_29_DOWNLOADS = ("id", "current_path", "target_path", "start_time", "received_bytes", "total_bytes", "state",
                       "danger_type", "interrupt_reason", "end_time", "opened", "referrer", "by_ext_id", "by_ext_name",
                       "etag", "last_modified", "mime_type", "original_mime_type")
LATER_DOWNLOADS = ("guid", "tab_url", "tab_referrer_url", "site_url", "last_access_time")
CHROME = "D:\\Evidence\\case\\WS01\\Users\\{user}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History"
CHROME_EVIDENCE = "WS01/Users/{user}/AppData/Local/Google/Chrome/User Data/Default/History"


def app_map(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def history(path: Path, downloads: tuple[str, ...] = SCHEMA_29_DOWNLOADS, chains: bool = True) -> Path:
    """A Chromium History with the five tables SQLECmd's Chromium maps identify it by and visit_source, a downloads
    table of the columns `downloads`, and, with `chains`, the downloads_url_chains table."""
    tables = {"urls": "id, url, title, visit_count, typed_count, last_visit_time, hidden, favicon_id",
              "visits": "id, url, visit_time, from_visit, transition, segment_id, visit_duration",
              "visit_source": "id, source", "segments": "id, name, url_id",
              "keyword_search_terms": "keyword_id, url_id, lower_term, term", "downloads": ", ".join(downloads)}
    if chains:
        tables["downloads_url_chains"] = "id, chain_index, url"
    con = sqlite3.connect(path)
    with closing(con), con:
        for name, columns in tables.items():
            con.execute(f"CREATE TABLE {name} ({columns})")
    return path


def webkit(text: str) -> int:
    """A UTC time as Chromium stores it: microseconds since 1601-01-01."""
    return (int(datetime.fromisoformat(text).replace(tzinfo=UTC).timestamp()) + 11_644_473_600) * 1_000_000


def downloads_history(path: Path) -> Path:
    """A schema 29 History with two downloads: a finished one, opened, whose URL chain of three is stored out of order,
    and one still in progress, with a chain of two."""
    history(path)
    con = sqlite3.connect(path)
    with closing(con), con:
        con.executemany("INSERT INTO downloads (id, current_path, target_path, start_time, received_bytes, total_bytes, "
                        "state, danger_type, interrupt_reason, end_time, opened, referrer) "
                        "VALUES (?, ?, ?, ?, 10, 10, ?, 4, 0, ?, ?, '')", [
                            (1, "C:\\Users\\bob\\Downloads\\tool.exe", "C:\\Users\\bob\\Downloads\\tool.exe",
                             webkit("2015-03-24 20:00:00"), 1, webkit("2015-03-24 20:00:07"), 1),
                            (2, "C:\\Users\\bob\\Downloads\\notes.txt.crdownload", "C:\\Users\\bob\\Downloads\\notes.txt",
                             webkit("2015-03-25 09:00:00"), 0, 0, 0)])
        con.executemany("INSERT INTO downloads_url_chains VALUES (?, ?, ?)", [
            (1, 2, "https://cdn.example/tool.exe"), (1, 0, "https://evil.example/get"), (1, 1, "https://cdn.example/a"),
            (2, 0, "https://files.example/notes"), (2, 1, "https://files.example/notes.txt")])
    return path


def identifies(map_file: Path, database: Path) -> bool:
    """Whether SQLECmd reads `database` with the map: its IdentifyQuery gives its IdentifyValue."""
    found = app_map(map_file)
    with closing(sqlite3.connect(database)) as con:
        return str(con.execute(found["IdentifyQuery"]).fetchone()[0]) == str(found["IdentifyValue"])


def run_map(map_file: Path, database: Path, out: Path, source_file: str) -> list[dict[str, str]]:
    """The rows of the map's one query on `database`, written to `out` as SQLECmd writes them: a CSV named
    <time>_<CSVPrefix>_<BaseFileName>_<Id>.csv, with the database's path, `source_file`, in its SourceFile column and
    an empty field for a NULL."""
    found = app_map(map_file)
    (query,) = found["Queries"]
    with closing(sqlite3.connect(database)) as con:
        cursor = con.execute(query["Query"])
        columns = [column[0] for column in cursor.description]
        rows = [{**dict(zip(columns, ("" if v is None else str(v) for v in row), strict=True)), "SourceFile": source_file}
                for row in cursor]
    write(out / f"20261029000000000000_{found['CSVPrefix']}_{query['BaseFileName']}_{found['Id']}.csv",
          [*columns, "SourceFile"], rows)
    return rows


def parse(out: Path) -> list:
    return list(PARSERS["sqlecmd_csv"](ParseContext(out, Path("D:/Evidence/case"))))


def test_app_map_ids_differ_from_every_tool_map():
    """Each app map is a SQLECmd map, with the fields SQLECmd's guide to maps requires, and an Id of its own: a lowercase
    GUID, as the parser and tool_outputs read a CSV's name, that no SQLECmd map the parser reads has. A BaseFileName
    holds no underscore, since the parser takes the map from the last two parts of a CSV's name, and each query's CSV
    goes to a handler or to the visit join. The lab check compares the Ids with every map in SQLECmd's Maps folder."""
    maps = [app_map(path) for path in sorted(APP_MAPS.glob("*.smap"))]
    ids = {found["Id"] for found in maps}
    assert len(maps) == len(ids) == 2 and all(GUID.fullmatch(map_id) for map_id in ids)
    app_keys = set()
    for found in maps:
        assert {"Description", "Author", "Email", "Id", "Version", "CSVPrefix", "FileName", "IdentifyQuery",
                "IdentifyValue", "Queries"} <= set(found)
        for query in found["Queries"]:
            assert "_" not in query["BaseFileName"] and {"Name", "Query"} <= set(query)
            app_keys.add((query["BaseFileName"], found["Id"]))
            name = f"20261029000000000000_{found['CSVPrefix']}_{query['BaseFileName']}_{found['Id']}.csv"
            assert kind_of(name, "ID").parser == "sqlecmd_csv"
    assert app_keys == {("DownloadsWithoutGUID", app_map(WITHOUT_GUID)["Id"]), sqlecmd.VISIT_SOURCES}
    assert {key for key in sqlecmd.MAPS if key[1] in ids} == app_keys - {sqlecmd.VISIT_SOURCES}


def test_downloads_identify_query_matches_only_a_history_without_guid(tmp_path):
    """The app's downloads map reads a History whose downloads table has each column its query reads and no guid column,
    which SQLECmd's downloads map needs, so the two never read the same History. A History without the URL chain table
    or a column the query reads is left to neither, so the map never fails on a History it reads. The visit sources map
    reads every History with the visit_source table."""
    older, later = history(tmp_path / "older"), history(tmp_path / "later", SCHEMA_29_DOWNLOADS + LATER_DOWNLOADS)
    no_chains = history(tmp_path / "no_chains", chains=False)
    no_opened = history(tmp_path / "no_opened", tuple(c for c in SCHEMA_29_DOWNLOADS if c != "opened"))
    assert [identifies(WITHOUT_GUID, db) for db in (older, later, no_chains, no_opened)] == [True, False, False, False]
    other = tmp_path / "other.db"
    con = sqlite3.connect(other)
    with closing(con), con:
        con.execute("CREATE TABLE downloads (id, guid)")
    assert not identifies(WITHOUT_GUID, other) and not identifies(VISIT_SOURCES, other)
    assert identifies(VISIT_SOURCES, older) and identifies(VISIT_SOURCES, later)


def test_downloads_query_runs_on_a_schema_29_history(tmp_path):
    """The query gives each column a name that SQLECmd's downloads map gives it, and times in UTC, with a row for each
    URL in a download's chain, in the chain's order. downloads.opened is a flag, so it reads Yes or No, not a time."""
    rows = run_map(WITHOUT_GUID, downloads_history(tmp_path / "History"), tmp_path, CHROME.format(user="bob"))
    assert set(rows[0]) <= set(DOWNLOADS)
    assert {"ID", "TargetPath", "DownloadURL", "StartTime", "EndTime", "Opened"} <= set(rows[0])
    assert [(row["ID"], row["DownloadURL"]) for row in rows] == [
        ("1", "https://evil.example/get"), ("1", "https://cdn.example/a"), ("1", "https://cdn.example/tool.exe"),
        ("2", "https://files.example/notes"), ("2", "https://files.example/notes.txt")]
    finished, in_progress = rows[0], rows[3]
    assert [finished[c] for c in ("StartTime", "EndTime", "Opened", "State", "DangerType", "InterruptReason")] == [
        "2015-03-24 20:00:00", "2015-03-24 20:00:07", "Yes", "Complete", "Content May Be Malicious", "No Interrupt"]
    assert [in_progress[c] for c in ("StartTime", "EndTime", "Opened", "State")] == [
        "2015-03-25 09:00:00", "1601-01-01 00:00:00", "No", "In Progress"]


def test_app_downloads_rows_load_through_chromium_downloads():
    """The app's downloads map's CSVs go to the handler of SQLECmd's downloads map, from a run's output folder and from
    output found in the evidence alike."""
    found = app_map(WITHOUT_GUID)
    name = f"20261029000000000000_ChromiumBrowser_{found['Queries'][0]['BaseFileName']}_{found['Id']}.csv"
    assert sqlecmd.MAPS[sqlecmd._map_key(name)] is sqlecmd.chromium_downloads
    assert kind_of(name, ",".join(DOWNLOADS)).parser == "sqlecmd_csv"


def test_schema_29_downloads_give_one_event_per_download(tmp_path):
    """The app's map repeats a download's row for each URL in its chain, as SQLECmd's does, and the parser reads one set
    of events for each download: its start, and its end where it has one, from the first URL of its chain. Opened is a
    flag here, so no event says when the file was opened."""
    out = tmp_path / "output"
    out.mkdir()
    run_map(WITHOUT_GUID, downloads_history(tmp_path / "History"), out, CHROME.format(user="bob"))
    events = parse(out)
    assert [(e.source_record, e.ts_desc) for e in events] == [
        ("download|1|start", "Download started"), ("download|1|end", "Download finished"),
        ("download|2|start", "Download started")]
    started = events[0]
    assert (started.source_file, started.user_name, started.file_path) == (
        CHROME_EVIDENCE.format(user="bob"), "bob", "C:\\Users\\bob\\Downloads\\tool.exe")
    assert started.message == "Chrome download: C:\\Users\\bob\\Downloads\\tool.exe from https://evil.example/get"
    assert started.ts_us == int(datetime(2015, 3, 24, 20, tzinfo=UTC).timestamp()) * 1_000_000
    assert (started.extra["Opened"], started.extra["State"]) == ("Yes", "Complete")


def visits_output(tmp_path: Path, source: str | None = "4") -> Path:
    """A SQLECmd output folder with bob's and alice's Chrome visits, each with visit IDs 70 and 71, and, unless `source`
    is None, the VisitSources CSV of bob's History, which gives his visit 70 that source. The VisitSources CSV comes
    after the visits' CSVs, as a later time in its name puts it."""
    out = tmp_path / f"output-{source}"
    out.mkdir()
    for n, user in enumerate(("bob", "alice")):
        write(out / f"{n}_ChromiumBrowser_HistoryVisits_1f37cc07-2b10-4c80-b845-84708e4f7429.csv", VISITS, [
            {"ID": "7", "VisitID": visit, "VisitTime (UTC)": "2015-03-22 14:00:00", "URL": f"https://site.example/{visit}",
             "URLTitle": "Site", "SourceFile": CHROME.format(user=user)} for visit in ("70", "71")])
    if source is not None:
        base, map_id = sqlecmd.VISIT_SOURCES
        write(out / f"9_ChromiumBrowser_{base}_{map_id}.csv", ["VisitID", "Source", "SourceFile"],
              [{"VisitID": "70", "Source": source, "SourceFile": CHROME.format(user="bob")}])
    return out


def test_visit_source_joins_onto_visits_by_file_and_visit_id(tmp_path):
    """A visit_source row names the visit of its own History with its VisitID: bob's visit 70, not his visit 71 and not
    alice's visit 70."""
    joined = {(e.user_name, e.source_record): (e.extra or {}).get("visit_source") for e in parse(visits_output(tmp_path))}
    assert joined == {("bob", "visit|70"): "4 (imported from Internet Explorer)", ("bob", "visit|71"): None,
                      ("alice", "visit|70"): None, ("alice", "visit|71"): None}


def test_imported_visit_message_names_its_source(tmp_path):
    """An imported visit's message says where it came from, and a visit with no visit_source row reads as before. A
    source value the app has no name for is given as its number."""
    messages = {(e.user_name, e.source_record): e.message for e in parse(visits_output(tmp_path))}
    assert messages[("bob", "visit|70")] == "Chrome visit, imported from Internet Explorer: https://site.example/70 (Site)"
    assert messages[("bob", "visit|71")] == messages[("alice", "visit|71")] == (
        "Chrome visit: https://site.example/71 (Site)")
    unnamed = {(e.user_name, e.source_record): e for e in parse(visits_output(tmp_path, "9"))}[("bob", "visit|70")]
    assert (unnamed.message, unnamed.extra["visit_source"]) == (
        "Chrome visit, from visit source 9: https://site.example/70 (Site)", "9")


def test_visit_ids_unchanged_by_the_join(tmp_path):
    """The join changes a visit's message and extra, not its source record or time description, so its event ID, and any
    mark on it, stays, and it adds no event."""
    from glessner.events import event_uid

    uids = lambda out: [event_uid("WS01", e.artifact, e.source_file, e.source_record, e.ts_desc) for e in parse(out)]
    before, after = uids(visits_output(tmp_path, None)), uids(visits_output(tmp_path))
    assert after == before and len(set(after)) == 4


def sqlecmd_exe(tmp_path: Path, maps: bool = True) -> Path:
    """A SQLECmd folder's executable, and, with `maps`, a Maps folder of two maps and the guide that SQLECmd's Maps
    folder holds beside them."""
    folder = tmp_path / "SQLECmd"
    (folder / "Maps" if maps else folder).mkdir(parents=True)
    if maps:
        for name in ("Windows_ChromiumBrowser_Downloads.smap", "Windows_ChromiumBrowser_HistoryVisits.smap",
                     "!OS_Application_OptionalDescription.guide"):
            (folder / "Maps" / name).write_text(name, encoding="utf-8")
    (folder / "SQLECmd.exe").write_bytes(b"MZ")
    return folder / "SQLECmd.exe"


def test_maps_folder_holds_the_tools_maps_and_the_apps(tmp_path):
    """A run's maps folder holds every file of SQLECmd's Maps folder, then the app's maps."""
    from glessner.runner import composed_files

    exe = sqlecmd_exe(tmp_path)
    files = composed_files(load_registry()["sqlecmd"], exe)
    tool = {f"composed_maps/{p.name}": p for p in (exe.parent / "Maps").iterdir()}
    app = {f"composed_maps/{p.name}": p for p in APP_MAPS.iterdir()}
    assert files == tool | app and set(list(files)[len(tool):]) == set(app)
    assert {p.name for p in APP_MAPS.iterdir()} == {WITHOUT_GUID.name, VISIT_SOURCES.name}


def test_missing_tool_maps_folder_refuses_the_run(tmp_path):
    """Without SQLECmd's Maps folder there is no maps folder to compose, so the run is refused before anything is made
    (runner.run), naming the folder."""
    from glessner.runner import RunError, composed_files

    exe = sqlecmd_exe(tmp_path, maps=False)
    with pytest.raises(RunError, match=re.escape(f"{exe.parent / 'Maps'} can't be listed")):
        composed_files(load_registry()["sqlecmd"], exe)


def test_sqlecmd_argv_passes_the_composed_maps_folder(synthetic_case, tmp_path):
    """SQLECmd reads the maps folder composed in its run's output folder, and its arguments name no folder of its own."""
    from glessner.runner import RunPlan, build_argv
    from glessner.tools import DetectedTool

    tool = DetectedTool(load_registry()["sqlecmd"], sqlecmd_exe(tmp_path), "2026.10.3")
    argv = build_argv(synthetic_case, RunPlan(tool, "DC01", ("DC01/History",)), tmp_path / "out", {})
    assert argv[argv.index("--maps") + 1] == str(tmp_path / "out" / "composed_maps")
    assert not any(str(tool.executable.parent) in arg for arg in argv[1:])


def test_sqlecmd_rules_label_counts_the_apps_maps(tmp_path):
    """The label counts SQLECmd's maps and the app's, which add up to the maps in the folder a run composes."""
    from glessner.runner import composed_files
    from glessner.tools import rules_label

    spec, exe = load_registry()["sqlecmd"], sqlecmd_exe(tmp_path)
    assert rules_label(spec, exe) == "Maps, 2 maps with 2 Glessner maps"
    assert sum(name.endswith(".smap") for name in composed_files(spec, exe)) == 4
