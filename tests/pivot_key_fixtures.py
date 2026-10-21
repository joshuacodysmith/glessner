"""Synthetic tool output for the pivot key tests: the forms seen in the Szechuan dataset, written the way the tools write
them, so a test can run the same records through the parsers and compare their IDs with a recorded list. Built as
tests/parser_fix_fixtures.py builds EvtxECmd and EVE records."""

import csv
import io
import json
from dataclasses import replace
from pathlib import Path

from parser_fix_fixtures import EVIDENCE, HOST, SECURITY, event_data, row, write_csv
from parser_fix_fixtures import ids as one_id

from glessner.parsers import PARSERS, ParseContext

SYSTEM = "System"
UTC = "2020-09-19 03:21:48.0000000"
HIVE = "D:\\Evidence\\case\\FIXTURE\\Windows\\System32\\config\\{}"

# EvtxECmd rows whose binary names fold through the shared command reducer and the file key
EVTX_ROWS = {
    "7045 SystemRoot": row(21, "7045", SYSTEM, event_data(ServiceName="Drv", ImagePath="%SystemRoot%\\system32\\drivers\\a.sys")),
    "7045 x86 with a space": row(22, "7045", SYSTEM, event_data(
        ServiceName="Foo", ImagePath="%ProgramFiles(x86)%\\Foo Bar\\x.exe -a")),
    "7045 8.3 path": row(23, "7045", SYSTEM, event_data(
        ServiceName="Imager", ImagePath="C:\\Users\\ADMINI~1\\AppData\\Local\\Temp\\1\\ad_driver.sys")),
    "4688 SystemRoot": row(24, "4688", SECURITY, event_data(
        SubjectUserName="WIN-1$", SubjectDomainName="C137", SubjectLogonId="0x3E7", TargetLogonId="0x0",
        NewProcessName="\\SystemRoot\\System32\\smss.exe")),
}


def csv_file(path: Path, columns: list[str], rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
        for r in rows:
            writer.writerow({c: r.get(c, "") for c in columns})


def run(name: str, folder: Path, inputs: tuple[str, ...] = (), root: Path = EVIDENCE) -> list:
    return list(PARSERS[name](ParseContext(folder, root, inputs)))


def folder_of(parent: Path, name: str) -> Path:
    out = parent / name
    out.mkdir()
    return out


def evtx_events(parent: Path) -> dict:
    out = folder_of(parent, "evtx")
    write_csv(out / "evtxecmd.csv", EVTX_ROWS.values())
    return dict(zip(EVTX_ROWS, run("evtxecmd_csv", out), strict=True))


# ---------- RECmd, one row per plugin in the forms the Szechuan copies hold ----------

RECMD_COLUMNS = ["HivePath", "HiveType", "Description", "Category", "KeyPath", "ValueName", "ValueType", "ValueData",
                 "ValueData2", "ValueData3", "Comment", "Recursive", "Deleted", "LastWriteTimestamp", "PluginDetailFile"]
SHIM = "ROOT\\ControlSet001\\Control\\Session Manager\\AppCompatCache"
BAM = "ROOT\\ControlSet001\\Services\\bam\\State\\UserSettings\\S-1-5-21-2232410529-1445159330-2725690660-1106"
RUN = "ROOT\\Microsoft\\Windows\\CurrentVersion\\Run"
SERVICES = "ROOT\\ControlSet001\\Services"
TASKS = "ROOT\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks"
USERASSIST = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\\Count"


def recmd_row(description, key, name, data, data3="", hive="SYSTEM"):
    return {"HivePath": HIVE.format(hive), "Description": description, "KeyPath": key, "ValueName": name, "ValueData": data,
            "ValueData3": data3, "LastWriteTimestamp": UTC}


RECMD_ROWS = {
    "shim SYSVOL": recmd_row("AppCompatCache", SHIM, "AppCompatCache", "SYSVOL\\Windows\\System32\\services.exe", "Position: 0"),
    "shim drive": recmd_row("AppCompatCache", SHIM, "AppCompatCache", "C:\\Windows\\System32\\cmd.exe", "Position: 1"),
    "shim D drive": recmd_row("AppCompatCache", SHIM, "AppCompatCache", "D:\\setup64.exe", "Position: 2"),
    "shim packaged": recmd_row("AppCompatCache", SHIM, "AppCompatCache",
                               "00000009\t0012076f04800000\t000a00004a610000\t8664\tMicrosoft.MicrosoftOfficeHub\t8wekyb3d8bbwe\t",
                               "Position: 3"),
    "bam device path": recmd_row("Background Activity Moderator (BAM)", BAM,
                                 "\\Device\\HarddiskVolume3\\Windows\\explorer.exe",
                                 "Program: \\Device\\HarddiskVolume3\\Windows\\explorer.exe"),
    "bam app ID": recmd_row("Background Activity Moderator (BAM)", BAM, "Microsoft.Windows.Search_cw5n1h2txyewy",
                            "Program: Microsoft.Windows.Search_cw5n1h2txyewy"),
    "run quoted": recmd_row("Run", RUN, "VMware User Process",
                            "\"C:\\Program Files\\VMware\\VMware Tools\\vmtoolsd.exe\" -n vmusr", hive="SOFTWARE"),
    "run windir": recmd_row("Run", RUN.replace("Run", "RunOnce"), "Health", "%windir%\\system32\\SecurityHealthSystray.exe",
                            hive="SOFTWARE"),
    "run comspec": recmd_row("Run", RUN, "coreupdate", "%COMSPEC% /b /c start /b /min powershell -nop", hive="SOFTWARE"),
    "run appdata": recmd_row("Run", RUN, "Sync", "%APPDATA%\\Sync\\sync.exe /q", hive="SOFTWARE"),
    "run key only": recmd_row("Autoruns", RUN, "", "Created on: 2020-09-19 03:30:01", hive="SOFTWARE"),
    "services svchost": recmd_row("Services", SERVICES, "", "Name: AeLookupSvc Desc: ",
                                  "Image path: %SystemRoot%\\system32\\svchost.exe -k netsvcs ServiceDLL: "
                                  "%SystemRoot%\\System32\\aelupsvc.dll"),
    "services driver": recmd_row("Services", SERVICES, "", "Name: ad_driver Desc: ",
                                 "Image path: \\SystemRoot\\System32\\drivers\\ad_driver.sys ServiceDLL: "),
    "services relative": recmd_row("Services", SERVICES, "", "Name: vmmemctl Desc: ",
                                   "Image path: system32\\drivers\\vmmemctl.sys ServiceDLL: "),
    "services quoted": recmd_row("Services", SERVICES, "", "Name: VGAuthService Desc: ",
                                 "Image path: \"C:\\Program Files\\VMware\\VMware Tools\\VMware VGAuth\\VGAuthService.exe\" "
                                 "ServiceDLL: "),
    "services empty": recmd_row("Services", SERVICES, "", "Name: .NET CLR Data Desc: ", "Image path:  ServiceDLL: "),
    "userassist system": recmd_row("UserAssist", USERASSIST, "{1NP14R77-02R7-4R5Q-O744-2RO1NR5198O7}\\abgrcnq.rkr",
                                   "{System}\\NOTEPAD.EXE", "Run count: 3", hive="NTUSER.DAT"),
    "userassist guid": recmd_row("UserAssist", USERASSIST, "x", "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\cscript.exe",
                                 "Run count: 1", hive="NTUSER.DAT"),
    "userassist programs": recmd_row("UserAssist", USERASSIST, "x", "{Common Programs}\\Accessories\\Paint.lnk",
                                     "Run count: 1", hive="NTUSER.DAT"),
    "userassist app ID": recmd_row("UserAssist", USERASSIST, "x", "Microsoft.Windows.Explorer", "Run count: 7",
                                   hive="NTUSER.DAT"),
    "userassist counter": recmd_row("UserAssist", USERASSIST, "x", "UEME_CTLSESSION", "Run count: 22", hive="NTUSER.DAT"),
    "taskcache": recmd_row("Scheduled Tasks (TaskCache)", TASKS, "", "Created on: 2020-09-19",
                           "Path: \\Evil\\Beacon, Command: x, Arguments: ", hive="SOFTWARE"),
}


def recmd_events(parent: Path) -> dict:
    out = folder_of(parent, "recmd")
    csv_file(out / "recmd.csv", RECMD_COLUMNS, list(RECMD_ROWS.values()))
    return dict(zip(RECMD_ROWS, run("recmd_csv", out), strict=True))


# ---------- Prefetch, Windows Timeline, Autoruns, MFT ----------

PECMD_COLUMNS = ["SourceFilename", "ExecutableName", "RunCount", "LastRun", "FilesLoaded", "Volume0Name", "ParsingError"]
LONG_NAME = "LONGNAMEDINSTALLERPROGRAM_SETUP_V2.EXE"
CUT_NAME = LONG_NAME[:29]   # Prefetch keeps 29 characters of a program's name
VOLUME = "\\VOLUME{01d6}"
TWICE = "OTHERLONGNAMEDINSTALLERPROGRAM.EXE"
NONE = "MISSINGLONGNAMEDPROGRAM_SETUP.EXE"


def prefetch_row(name, loaded, source=None):
    return {"SourceFilename": f"D:\\Evidence\\case\\FIXTURE\\Windows\\Prefetch\\{source or name}-0BD30981.pf",
            "ExecutableName": name, "RunCount": "2", "LastRun": UTC, "FilesLoaded": ", ".join(loaded),
            "Volume0Name": VOLUME, "ParsingError": "False"}


PECMD_ROWS = {
    "prefetch short": prefetch_row("CMD.EXE", [f"{VOLUME}\\WINDOWS\\SYSTEM32\\NTDLL.DLL",
                                               f"{VOLUME}\\WINDOWS\\SYSTEM32\\CMD.EXE"]),
    "prefetch cut": prefetch_row(CUT_NAME, [f"{VOLUME}\\WINDOWS\\SYSTEM32\\NTDLL.DLL",
                                            f"{VOLUME}\\USERS\\PUBLIC\\{LONG_NAME}"], "LONGNAME"),
    "prefetch cut twice": prefetch_row(TWICE[:29], [f"{VOLUME}\\USERS\\A\\{TWICE}",
                                                    f"{VOLUME}\\USERS\\B\\{TWICE.replace('.EXE', '_X.EXE')}"], "OTHER"),
    "prefetch none": prefetch_row(NONE[:29], [f"{VOLUME}\\WINDOWS\\SYSTEM32\\NTDLL.DLL"], "MISSING"),
    "prefetch 28": prefetch_row(LONG_NAME[:28], [f"{VOLUME}\\USERS\\PUBLIC\\{LONG_NAME}"], "LONGNAME28"),
}


def pecmd_events(parent: Path) -> dict:
    out = folder_of(parent, "pecmd")
    csv_file(out / "pecmd.csv", PECMD_COLUMNS, list(PECMD_ROWS.values()))
    return dict(zip(PECMD_ROWS, run("pecmd_csv", out), strict=True))


WXT_COLUMNS = ["Id", "ActivityType", "Executable", "DisplayText", "StartTime", "EndTime"]
WXT_ROWS = {
    "timeline System": ("1", "System\\cmd.exe"),
    "timeline system guid": ("2", "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\cmd.exe"),
    "timeline windows guid": ("3", "{F38BF404-1D43-42F2-9305-67DE0B28FC23}\\explorer.exe"),
    "timeline x64 guid": ("4", "{6D809377-6AF0-444B-8957-A3773F02200E}\\Vendor\\app.exe"),
    "timeline x86 guid": ("5", "{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}\\Vendor\\app.exe"),
    "timeline app ID": ("6", "Microsoft.Windows.Explorer"),
    "timeline drive": ("7", "C:\\Windows\\System32\\notepad.exe"),
}


def wxtcmd_events(parent: Path) -> dict:
    out = folder_of(parent, "wxtcmd")
    csv_file(out / "20200919_rick_Activity.csv", WXT_COLUMNS,
             [{"Id": i, "ActivityType": "ExecuteOpen", "Executable": exe, "StartTime": UTC} for i, exe in WXT_ROWS.values()])
    inputs = ("FIXTURE/Users/rick/AppData/Local/ConnectedDevicesPlatform/L.rick/ActivitiesCache.db",)
    return dict(zip(WXT_ROWS, run("wxtcmd_csv", out, inputs), strict=True))


AUTORUNS_COLUMNS = ["Time", "Entry Location", "Entry", "Enabled", "Category", "Profile", "Description", "Signer", "Company",
                    "Image Path", "Version", "Launch String"]
AUTORUNS_RUN = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
LAUNCH = "%ProgramData%\\x\\y.exe -a"


def autoruns_row(entry, image, launch, when="20200919-032148"):
    return {"Time": when, "Entry Location": AUTORUNS_RUN, "Entry": entry, "Enabled": "enabled", "Category": "Logon",
            "Profile": "System-wide", "Image Path": image, "Launch String": launch}


# A timed row's time description follows its image path's extension (BUILT for a PE file, else WRITTEN), and the ID hashes it
AUTORUNS_ROWS = {
    "autoruns empty image": autoruns_row("NoImage", "", LAUNCH),
    "autoruns fragment image": autoruns_row("Fragment", "File not found: cmd.exe /c x", LAUNCH),
    "autoruns image": autoruns_row("Core", "c:\\windows\\system32\\coreupdater.exe", "C:\\Windows\\System32\\coreupdater.exe"),
    "autoruns script": autoruns_row("Script", "c:\\scripts\\backup.vbs", "wscript.exe c:\\scripts\\backup.vbs"),
    "autoruns no time": autoruns_row("NoTime", "File not found: C:\\Program Files\\x\\y.exe",
                                     "\"C:\\Program Files\\x\\y.exe\" -q", ""),
    "autoruns variable launch": autoruns_row("Var", "File not found: %ProgramData%", "%ProgramFiles(x86)%\\Foo Bar\\z.exe /s"),
}


def autoruns_events(parent: Path) -> dict:
    out = folder_of(parent, "autoruns")
    csv_file(out / "autoruns.csv", AUTORUNS_COLUMNS, list(AUTORUNS_ROWS.values()))
    # The parser names its source file by the CSV's place, which an Autoruns CSV found in the evidence has under the evidence
    # root; here that root is the folder the fixtures sit in, so the IDs don't depend on where a test's folder is
    return dict(zip(AUTORUNS_ROWS, run("autoruns_csv", out, root=parent), strict=True))


MFT_COLUMNS = ["EntryNumber", "SequenceNumber", "ParentEntryNumber", "ParentSequenceNumber", "InUse", "ParentPath", "FileName",
               "IsDirectory", "Created0x10", "LastModified0x10", "LastRecordChange0x10", "LastAccess0x10", "Created0x30",
               "LastModified0x30", "SourceFile"]
MFT_SOURCE = "D:\\Evidence\\case\\{}\\$MFT"


def mft_row(host, entry, parent, name, directory=False, in_use=True):
    """A record of one file, as MFTECmd writes it: its $SI times differ and its $FN times are one, so it gives up to three
    events (several rows per file; a sibling count that counts rows would never find a name once)."""
    return {"EntryNumber": str(entry), "SequenceNumber": "1", "ParentEntryNumber": "5", "ParentSequenceNumber": "5",
            "InUse": str(in_use), "ParentPath": parent, "FileName": name, "IsDirectory": str(directory),
            "Created0x10": "2020-09-19 03:20:00.0000000", "LastModified0x10": "2020-09-19 03:21:00.0000000",
            "LastRecordChange0x10": "2020-09-19 03:22:00.0000000", "LastAccess0x10": "2020-09-19 03:22:00.0000000",
            "Created0x30": "2020-09-19 03:20:00.0000000", "LastModified0x30": "2020-09-19 03:20:00.0000000",
            "SourceFile": MFT_SOURCE.format(host)}


def mft_rows(host, files):
    """MFT rows for (parent, name) pairs; a pair whose name has no extension and ends in a slash is a folder."""
    return [mft_row(host, 100 + n, parent, name.rstrip("/"), directory=name.endswith("/"))
            for n, (parent, name) in enumerate(files)]


MFT_FILES = [(".\\Users", "Administrator/"), (".\\Users", "Public/"),
             (".\\Users\\Administrator\\AppData\\Local\\Temp\\1", "ad_driver.sys")]


def mft_events(parent: Path, host: str = HOST, files=None) -> list:
    out = folder_of(parent, f"mft_{host}")
    csv_file(out / "mftecmd.csv", MFT_COLUMNS, mft_rows(host, files or MFT_FILES))
    return run("mftecmd_csv", out)


# ---------- Suricata ----------

EVE = [
    {"timestamp": "2020-09-19T03:21:48.000000+0000", "event_type": "http", "flow_id": 31, "src_ip": "10.42.85.115",
     "src_port": 49752, "dest_ip": "194.61.24.102", "dest_port": 80, "proto": "TCP",
     "http": {"hostname": "194.61.24.102", "url": "/coreupdater.exe", "http_method": "GET", "status": 200}},
    {"timestamp": "2020-09-19T03:21:49.000000+0000", "event_type": "fileinfo", "flow_id": 31, "src_ip": "194.61.24.102",
     "src_port": 80, "dest_ip": "10.42.85.115", "dest_port": 49752, "proto": "TCP",
     "fileinfo": {"filename": "/coreupdater.exe", "size": 7168, "magic": "PE32 executable"}},
    {"timestamp": "2020-09-19T03:21:50.000000+0000", "event_type": "fileinfo", "flow_id": 32, "src_ip": "10.0.0.5",
     "src_port": 445, "dest_ip": "10.0.0.6", "dest_port": 49200, "proto": "TCP",
     "fileinfo": {"filename": "\\\\fs01\\share\\doc.txt", "size": 12}},
    {"timestamp": "2020-09-19T03:21:51.000000+0000", "event_type": "flow", "flow_id": 33, "src_ip": "10.0.0.5",
     "src_port": 49200, "dest_ip": "10.0.0.1", "dest_port": 445, "proto": "TCP",
     "flow": {"start": "2020-09-19T03:21:47.000000+0000"}},
]


def suricata_events(parent: Path) -> list:
    out = folder_of(parent, "suricata")
    (out / "eve.json").write_text("".join(json.dumps(r) + "\n" for r in EVE), encoding="utf-8")
    return list(PARSERS["suricata_eve"](ParseContext(out, EVIDENCE, ("SENSOR/capture.pcap",))))


# ---------- imports ----------

IMPORT_COLUMNS = ["Time", "Computer", "User", "Path", "Process", "LogonId", "LogonType", "Message"]
IMPORT_ROWS = [
    ["2024-07-01T10:00:00Z", "WEB01", "alice@C137.LOCAL", "C:\\Users\\Public\\x.exe", "C:\\Tools\\y.exe", "0x3e7", "3", "a"],
    ["2024-07-01T10:00:01Z", "WEB01", "C137\\bob", "", "C:\\Tools\\z.exe", "0x0", "", "b"],
    ["2024-07-01T10:00:02Z", "WEB01", "Administrator/C137.LOCAL", "/var/tmp/x", "C:\\Tools\\y.exe", "0x51a", "10", "c"],
    ["2024-07-01T10:00:03Z", "WEB01", "carol", "\\\\fs01\\share\\doc.txt", "sshd", "", "2", "d"],
    ["2024-07-01T10:00:04Z", "WEB01", "dave", "", "/usr/sbin/sshd", "", "", "e"],
]
BASE_FIELDS = {"user": "User", "computer": "Computer", "path": "Path", "process": "Process", "message": "Message"}
LOGON_FIELDS = {"logon_id": "LogonId", "logon_type": "LogonType"}
KERBEROS = [{"ts": 1600485708.0, "uid": "Ck1", "id.orig_h": "10.0.0.9", "id.orig_p": 49200, "id.resp_h": "10.0.0.1",
             "id.resp_p": 88, "client": "mortysmith/C137.LOCAL", "service": "krbtgt/C137.LOCAL", "success": True}]
NTLM = [{"ts": 1600485709.0, "uid": "Cn1", "id.orig_h": "10.0.0.9", "id.orig_p": 49201, "id.resp_h": "10.0.0.1",
         "id.resp_p": 445, "username": "mortysmith", "hostname": "DESKTOP", "domainname": "C137", "success": True}]
FILES = [{"ts": 1600485710.0, "fuid": "F1", "source": "HTTP", "filename": "C:\\Users\\Public\\x.exe",
          "md5": "d41d8cd98f00b204e9800998ecf8427e"}]


def import_case(parent: Path, new_roles: bool):
    """A case with a CSV and three Zeek logs under the host folder FIXTURE, each imported, and the events' IDs by file and
    record. `new_roles` adds the logon role fields (LOGON_FIELDS) to the mapping; without it the mapping holds
    BASE_FIELDS alone."""
    from glessner.case import create_case
    from glessner.events import connect
    from glessner.imports import run_import
    from glessner.intake import intake

    evidence = parent / "evidence"
    (evidence / HOST).mkdir(parents=True)
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(IMPORT_COLUMNS)
    writer.writerows(IMPORT_ROWS)
    (evidence / HOST / "logons.csv").write_text(out.getvalue(), encoding="utf-8", newline="")
    for name, records in (("kerberos", KERBEROS), ("ntlm", NTLM), ("files", FILES)):
        (evidence / HOST / f"{name}.json").write_text("".join(json.dumps(r) + "\n" for r in records), encoding="utf-8")
    case = create_case(parent / "case", "Pivot key fixtures", evidence, "cody")
    intake(case)
    fields = {**BASE_FIELDS, **(LOGON_FIELDS if new_roles else {})}
    mapping = {"format": "csv", "delimiter": ",", "header": True, "artifact": "csv_fixture",
               "time": {"columns": ["Time"], "format": "ymd", "zone": "UTC"}, "fields": fields, "host": {"from": "folder"},
               "message": "{Message}", "ignore": []}
    rec = run_import(case, f"{HOST}/logons.csv", mapping, zones={})
    assert rec.status == "ok", rec.reason
    for name in ("kerberos", "ntlm", "files"):
        rec = run_import(case, f"{HOST}/{name}.json", {"preset": "zeek"}, zones={})
        assert rec.status == "ok", rec.reason
    return case, {f"{src.rsplit('/', 1)[-1]} {rec}": uid for src, rec, uid in _import_ids(connect, case)}


def _import_ids(connect, case):
    con = connect(case.db_path, read_only=True)
    try:
        return con.execute("SELECT source_file, source_record, event_uid FROM events WHERE tool = 'import' "
                           "ORDER BY source_file, CAST(source_record AS INTEGER)").fetchall()
    finally:
        con.close()


def ids(events) -> list[str]:
    """Each event's ID as events.load gives it: a record a tool emits twice (RECmd's AppCompatCache rows share a key, a value
    name, and a description) takes #2, #3, and so on, in the order they come."""
    seen: set[str] = set()
    out = []
    for e in events:
        ordinal, uid = 1, one_id([e])[0]
        while uid in seen:
            ordinal += 1
            uid = one_id([replace(e, source_record=f"{e.source_record}#{ordinal}")])[0]
        seen.add(uid)
        out.append(uid)
    return out


def named_ids(events: dict) -> dict:
    return dict(zip(events, ids(events.values()), strict=True))


def parsed(parent: Path) -> dict[str, list]:
    """Every parser fixture's events by group, in the order the fixtures name them."""
    return {"evtx": evtx_events(parent), "recmd": recmd_events(parent), "pecmd": pecmd_events(parent),
            "wxtcmd": wxtcmd_events(parent), "autoruns": autoruns_events(parent)}


def labeled_ids(parent: Path, new_roles: bool = True) -> dict[str, str]:
    """The ID of every fixture event by a label: the parser fixtures, the MFT and Suricata records, and the imports. What the
    ID test compares with its recorded list; `new_roles` maps the import's logon roles."""
    (parent / "parsers").mkdir()
    (parent / "imports").mkdir()
    out = {label: uid for events in parsed(parent / "parsers").values() for label, uid in named_ids(events).items()}
    mft = mft_events(parent / "parsers")
    out.update({f"mft {e.source_record} {e.ts_desc}": uid for e, uid in zip(mft, ids(mft), strict=True)})
    suricata = suricata_events(parent / "parsers")
    out.update({f"suricata {e.log_channel} {e.file_path or e.source_record[:30]}": uid
                for e, uid in zip(suricata, ids(suricata), strict=True)})
    _, imported = import_case(parent / "imports", new_roles)
    return {**out, **{f"import {label}": uid for label, uid in imported.items()}}
