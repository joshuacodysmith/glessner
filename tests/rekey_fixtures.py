"""Synthetic output for the four parsers whose event keys differ between case formats: found Amcache and SRUM CSVs
from two collections of one host, Suricata EVE written in a zone other than UTC, and SQLECmd output naming the working
copies in another case's run folder. Each has a form that keys the same under both formats too: a tool run's Amcache
and SRUM, EVE written at +0000, and copies in this run's folder.

The parse functions take `former`, the case format whose keys each event also carries (ParseContext.former), and pass
it only when it's set, so the same fixtures run through the parsers under the former format's rule."""

import csv
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path, PureWindowsPath

from glessner.parsers import PARSERS, ParseContext

AMCACHE_FILE = ["ApplicationName", "ProgramId", "FileKeyLastWriteTimestamp", "SHA1", "IsOsComponent", "FullPath", "Name"]
AMCACHE_PROGRAM = ["ProgramId", "KeyLastWriteTimestamp", "Name", "Version", "Publisher", "InstallDate", "RootDirPath"]
AMCACHE_SHORTCUT = ["KeyName", "LnkName", "KeyLastWriteTimestamp"]
SRUM_NETWORK = ["Id", "Timestamp", "ExeInfo", "Sid", "UserName", "BytesReceived", "BytesSent"]
SRUM_RESOURCES = ["Id", "Timestamp", "ExeInfo", "ForegroundBytesWritten", "BackgroundBytesWritten"]
VISITS = ["ID", "VisitTime (UTC)", "URLTitle", "URL", "VisitID", "SourceFile"]
NOTIFICATIONS = ["ID", "Application", "Payload", "ArrivalTime", "SourceFile"]
VISITS_CSV = "1_ChromiumBrowser_HistoryVisits_1f37cc07-2b10-4c80-b845-84708e4f7429.csv"
NOTIFICATIONS_CSV = "2_Windows_NotificationsDB-Notifications_cd952d69-7b3e-4d13-9810-8d987155bc58.csv"

TOOL_HIVE = "DESKTOP/Windows/appcompat/Programs/Amcache.hve"
TOOL_SRUDB = "DESKTOP/Windows/System32/sru/SRUDB.dat"
CAPTURE = "SENSOR/capture.pcap"
SQL_RUN = "20261015T010000Z_sqlecmd_WS01"
SQL_EVIDENCE = Path("D:/Evidence/case")
HISTORY = "WS01/Users/bob/AppData/Local/Microsoft/Edge/User Data/Default/History"
# Where another case's copy of this run made its working copies: a case moved, or copied before runs recorded the folder
ELSEWHERE = PureWindowsPath("C:/Users/analyst/cases/a/runs") / SQL_RUN / "input"
HOSTS = {"amcache_found": "DESKTOP", "amcache_tool": "DESKTOP", "srum_found": "DESKTOP", "srum_tool": "DESKTOP",
         "eve": "SENSOR", "eve_found": "SENSOR", "sqlecmd": "WS01"}


def write_rows(path: Path, columns: list[str], rows: list[dict]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=columns)
        w.writeheader()
        w.writerows(rows)
    return path


def context(output: Path, evidence: Path, inputs=(), files=(), former: int = 0, **fields) -> ParseContext:
    return ParseContext(output, evidence, tuple(inputs), tuple(files), **fields, **({"former": former} if former else {}))


def program(pid: str, name: str, written: str) -> dict:
    return {"ProgramId": pid, "KeyLastWriteTimestamp": written, "Name": name, "Version": "1.0", "Publisher": "Vendor",
            "InstallDate": "2020-09-18 10:00:00", "RootDirPath": f"C:\\Program Files\\{name}"}


def amcache_tables(folder: Path) -> list[Path]:
    """One collection of a host's AmcacheParser CSVs: a file entry, a program with its install date, and a shortcut."""
    return [
        write_rows(folder / "2024_Amcache_UnassociatedFileEntries.csv", AMCACHE_FILE, [
            {"FileKeyLastWriteTimestamp": "2020-09-19 03:40:45", "FullPath": "c:\\windows\\coreupdater.exe",
             "SHA1": "fd153c66386ca93ec9993d66a84d6f0d129a3a5c"}]),
        write_rows(folder / "2024_Amcache_ProgramEntries.csv", AMCACHE_PROGRAM, [program("p1", "Tool", "2020-09-19 01:32:10")]),
        write_rows(folder / "2024_Amcache_ShortCuts.csv", AMCACHE_SHORTCUT, [
            {"KeyName": "tool.lnk|a9", "LnkName": "C:\\ProgramData\\Start Menu\\Tool.lnk",
             "KeyLastWriteTimestamp": "2020-09-19 01:32:13"}]),
    ]


def found(evidence: Path, paths: list[Path]) -> tuple[list[str], list[Path]]:
    """A found-output load's inputs, its CSVs' evidence paths sorted, and its files, as runner.load_output gives them."""
    inputs = sorted(p.relative_to(evidence).as_posix() for p in paths)
    return inputs, [evidence / p for p in inputs]


def amcache_found(folder: Path, former: int = 0) -> list:
    """Two collections of DESKTOP's Amcache found in the evidence: K2 complete, and K1 with the same program. Under the
    former rule every row cites the first CSV, K1's, so the two programs share a key and load numbers the second."""
    evidence = folder / "evidence"
    paths = amcache_tables(evidence / "DESKTOP" / "K2")
    paths.append(write_rows(evidence / "DESKTOP" / "K1" / "2024_Amcache_ProgramEntries.csv", AMCACHE_PROGRAM,
                            [program("p1", "Tool", "2020-09-19 01:32:10")]))
    inputs, files = found(evidence, paths)
    return list(PARSERS["amcache_csv"](context(folder / "run" / "output", evidence, inputs, files, former)))


def amcache_tool(folder: Path, former: int = 0) -> list:
    """AmcacheParser's own run on the hive, whose rows cite the hive under both rules."""
    output = folder / "tool" / "output"
    amcache_tables(output)
    return list(PARSERS["amcache_csv"](context(output, folder / "evidence", (TOOL_HIVE,), (), former)))


def srum_tables(folder: Path, rows: list[dict], resources: bool = False) -> list[Path]:
    paths = [write_rows(folder / "2024_SrumECmd_NetworkUsages_Output.csv", SRUM_NETWORK, rows)]
    if resources:
        paths.append(write_rows(folder / "2024_SrumECmd_AppResourceUseInfo_Output.csv", SRUM_RESOURCES, [
            {"Id": "5", "Timestamp": "2020-09-19 04:00:00", "ExeInfo": "b.exe", "ForegroundBytesWritten": "4096"}]))
    return paths


def srum_row(rid: str, exe: str) -> dict:
    return {"Id": rid, "Timestamp": "2020-09-19 04:00:00", "ExeInfo": exe, "Sid": "S-1-5-21-1-500",
            "UserName": "C137\\Administrator", "BytesSent": "1024", "BytesReceived": "2048"}


def srum_found(folder: Path, former: int = 0) -> list:
    """Two collections of one SRUDB found in the evidence, each with a network use record of Id 5, a.exe in K1 and
    b.exe in K2. Under the former rule both cite no file, so the two share a key."""
    evidence = folder / "evidence"
    paths = srum_tables(evidence / "DESKTOP" / "K1", [srum_row("5", "a.exe")])
    paths += srum_tables(evidence / "DESKTOP" / "K2", [srum_row("5", "b.exe"), srum_row("6", "c.exe")], resources=True)
    inputs, files = found(evidence, paths)
    return list(PARSERS["srumecmd_csv"](context(folder / "run" / "output", evidence, inputs, files, former)))


def srum_tool(folder: Path, former: int = 0) -> list:
    output = folder / "tool" / "output"
    srum_tables(output, [srum_row("5", "b.exe"), srum_row("6", "c.exe")], resources=True)
    return list(PARSERS["srumecmd_csv"](context(output, folder / "evidence", (TOOL_SRUDB,), (), former)))


T0 = datetime(2020, 9, 19, 3, 21, 48, tzinfo=UTC)


def at(seconds: int, hours: int) -> str:
    """A time `seconds` after T0 as Suricata writes it on a machine `hours` east of UTC."""
    zone = timedelta(hours=hours)
    local = T0 + timedelta(seconds=seconds) + zone
    sign = "+" if hours >= 0 else "-"
    return local.strftime("%Y-%m-%dT%H:%M:%S.%f") + f"{sign}{abs(hours):02d}00"


def eve_records(hours: int) -> list[dict]:
    """EVE records whose keys take their time by each of the three routes: an HTTP record of a flow, which takes the
    flow's start; an alert with no flow, which takes its own timestamp; and the flow record, which takes flow.start. A
    DNS query written twice gives a repeat. Times to_us can't read, and one before 1971, stay as written."""
    return [
        {"timestamp": at(3, hours), "event_type": "http", "flow_id": 21, "src_ip": "10.0.0.5", "src_port": 49200,
         "dest_ip": "203.0.113.9", "dest_port": 80, "proto": "TCP", "tx_id": 0,
         "http": {"hostname": "evil.example", "url": "/a", "http_method": "GET", "status": 200}},
        {"timestamp": at(5, hours), "event_type": "alert", "src_ip": "203.0.113.9", "src_port": 80, "dest_ip": "10.0.0.5",
         "dest_port": 49201, "proto": "TCP", "alert": {"signature_id": 2000001, "signature": "TEST", "severity": 1}},
        {"timestamp": at(6, hours), "event_type": "dns", "src_ip": "10.0.0.5", "src_port": 5353, "dest_ip": "10.0.0.1",
         "dest_port": 53, "proto": "UDP", "dns": {"type": "query", "rrname": "x.example"}},
        {"timestamp": at(6, hours), "event_type": "dns", "src_ip": "10.0.0.5", "src_port": 5353, "dest_ip": "10.0.0.1",
         "dest_port": 53, "proto": "UDP", "dns": {"type": "query", "rrname": "x.example"}},
        {"timestamp": "not a time", "event_type": "tls", "src_ip": "10.0.0.5", "src_port": 49202, "dest_ip": "10.0.0.2",
         "dest_port": 443, "proto": "TCP", "tls": {"sni": "y.example"}},
        {"timestamp": "1970-01-01T07:00:00.000000+0700", "event_type": "tls", "src_ip": "10.0.0.5", "src_port": 49203,
         "dest_ip": "10.0.0.2", "dest_port": 443, "proto": "TCP", "tls": {"sni": "z.example"}},
        {"timestamp": at(9, hours), "event_type": "flow", "flow_id": 21, "src_ip": "10.0.0.5", "src_port": 49200,
         "dest_ip": "203.0.113.9", "dest_port": 80, "proto": "TCP", "flow": {"start": at(2, hours)}},
    ]


def eve(folder: Path, former: int = 0, hours: int = 7) -> list:
    """Suricata's run on a capture, written by a machine `hours` east of UTC, +0700 by default."""
    output = folder / f"eve{hours:+d}" / "output"
    output.mkdir(parents=True)
    (output / "eve.json").write_text("".join(json.dumps(r) + "\n" for r in eve_records(hours)), encoding="utf-8")
    return list(PARSERS["suricata_eve"](context(output, folder / "evidence", (CAPTURE,), (), former)))


def eve_found(folder: Path, former: int = 0) -> list:
    """Two EVE files found in the evidence, one written at +0700 and the other at -0500, each with its own repeat."""
    evidence = folder / "evidence"
    paths = []
    for name, hours in (("a", 7), ("b", -5)):
        path = evidence / "SENSOR" / name / "eve.json"
        path.parent.mkdir(parents=True)
        path.write_text("".join(json.dumps(r) + "\n" for r in eve_records(hours)), encoding="utf-8")
        paths.append(path)
    inputs, files = found(evidence, paths)
    return list(PARSERS["suricata_eve"](context(folder / "run" / "output", evidence, inputs, files, former)))


def sqlecmd(folder: Path, former: int = 0, **fields) -> list:
    """A SQLECmd run made before runs recorded their working copies' folder, in a case whose run folder is under
    `folder`. Its output names copies in another case's folder for the same run (bob's history and notifications), in
    this run's own folder (the history again, as carol's), the evidence itself (dave's), and another run's folder,
    whose paths no rule can read as evidence paths (erin's)."""
    output = folder / "case" / "runs" / SQL_RUN / "output"
    output.mkdir(parents=True)
    own = PureWindowsPath(output.parent / "input")
    other_run = PureWindowsPath("C:/Users/analyst/cases/a/runs/20261014T000000Z_sqlecmd_WS01/input")
    visit = lambda vid, source: {"ID": vid, "VisitID": vid, "VisitTime (UTC)": f"2024-05-14 12:00:{vid}",
                                 "URL": f"https://evil.example/{vid}", "URLTitle": "Evil", "SourceFile": str(source)}
    write_rows(output / VISITS_CSV, VISITS, [
        visit("10", ELSEWHERE / PureWindowsPath(HISTORY)),
        visit("11", own / PureWindowsPath(HISTORY.replace("/bob/", "/carol/"))),
        visit("12", PureWindowsPath(SQL_EVIDENCE) / PureWindowsPath(HISTORY.replace("/bob/", "/dave/"))),
        visit("13", other_run / PureWindowsPath(HISTORY.replace("/bob/", "/erin/")))])
    write_rows(output / NOTIFICATIONS_CSV, NOTIFICATIONS, [
        {"ID": "1", "Application": "Defender", "ArrivalTime": "2024-05-14 12:02:00",
         "Payload": "<toast><text>Threats found</text></toast>",
         "SourceFile": str(ELSEWHERE / "WS01/Users/bob/AppData/Local/Microsoft/Windows/Notifications/wpndatabase.db")}])
    return list(PARSERS["sqlecmd_csv"](context(output, SQL_EVIDENCE, (), (), former, **fields)))


FIXTURES = {"amcache_found": amcache_found, "amcache_tool": amcache_tool, "srum_found": srum_found,
            "srum_tool": srum_tool, "eve": eve, "eve_found": eve_found, "sqlecmd": sqlecmd}
