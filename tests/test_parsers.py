import csv
import html
import json
from pathlib import Path
from xml.etree import ElementTree

import pytest

from glessner.event_xml import row_for
from glessner.events import connect, load
from glessner.parsers import PARSERS, ParseContext
from glessner.parsers.common import evidence_relative, ip_and_port, normalize_ip, payload_fields, payload_text, port_number

EVIDENCE = Path("D:/Evidence/case")
EVTX_COLUMNS = ["RecordNumber", "EventRecordId", "TimeCreated", "EventId", "Level", "Provider", "Channel", "ProcessId",
                "ThreadId", "Computer", "ChunkNumber", "UserId", "MapDescription", "UserName", "RemoteHost",
                "PayloadData1", "PayloadData2", "PayloadData3", "PayloadData4", "PayloadData5", "PayloadData6",
                "ExecutableInfo", "HiddenRecord", "SourceFile", "Keywords", "ExtraDataOffset", "Payload"]


def event_data(**fields):
    return json.dumps({"EventData": {"Data": [{"@Name": k, "#text": v} for k, v in fields.items()]}})


def write_csv(path, columns, rows):
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
        for row in rows:
            writer.writerow({c: row.get(c, "") for c in columns})


def test_payload_fields_eventdata_and_userdata():
    assert payload_fields(event_data(LogonType="10", IpAddress="1.2.3.4")) == {"LogonType": "10", "IpAddress": "1.2.3.4"}
    userdata = json.dumps({"UserData": {"EventXML": {"@xmlns": "x", "Param1": "Administrator", "Param2": "C137",
                                                     "Param3": "194.61.24.102"}}})
    assert payload_fields(userdata) == {"Param1": "Administrator", "Param2": "C137", "Param3": "194.61.24.102"}
    assert payload_fields("") == {} and payload_fields("{broken") == {}


def test_normalize_ip():
    assert normalize_ip("::ffff:10.42.85.10") == "10.42.85.10"
    assert normalize_ip("-") == "" and normalize_ip("") == "" and normalize_ip("fe80::1") == "fe80::1"
    # An address with a port gives the address alone.
    assert normalize_ip("194.61.24.102:58132") == "194.61.24.102"
    assert normalize_ip("[fe80::1]:3389") == "fe80::1" and normalize_ip("[::ffff:10.42.85.10]:3389") == "10.42.85.10"
    assert normalize_ip("999.1.1.1:80") == "" and normalize_ip("host:80") == ""
    assert ip_and_port("194.61.24.102:58132") == ("194.61.24.102", "58132")
    assert ip_and_port("[fe80::1]:3389") == ("fe80::1", "3389") and ip_and_port("10.0.0.1") == ("10.0.0.1", "")
    assert ip_and_port("999.1.1.1:80") == ("", "")   # no address, so no port either
    assert [port_number(p) for p in ("3389", "0", "-", "", "70000", "x")] == ["3389", "", "", "", "", ""]


def test_an_extended_length_path_gives_the_evidence_path_its_plain_form_gives():
    """A found file is opened by its extended-length path, \\\\?\\ or \\\\?\\UNC\\ for a share, and its events' source
    is its path in the evidence folder, kept with a trailing dot, as a plain path's is. A path outside the evidence
    folder is kept as given."""
    share = Path("//server/share/ev")
    assert evidence_relative(r"D:\Evidence\case\HOST\x.csv", EVIDENCE) == "HOST/x.csv"
    assert evidence_relative(r"\\?\D:\Evidence\case\HOST\dir.\x.csv", EVIDENCE) == "HOST/dir./x.csv"
    assert evidence_relative(r"\\?\UNC\server\share\ev\HOST\x.csv", share) == "HOST/x.csv"
    assert evidence_relative(r"\\server\share\ev\HOST\x.csv", share) == "HOST/x.csv"
    assert evidence_relative(r"C:\KAPE\tout\x.csv", EVIDENCE) == "C:/KAPE/tout/x.csv"
    assert evidence_relative(r"\\?\C:\KAPE\tout\x.csv", EVIDENCE) == "//?/C:/KAPE/tout/x.csv"


def test_an_evidence_root_in_extended_length_or_device_form_gives_the_same_evidence_paths():
    """The case keeps its evidence folder as typed, so the root may be in extended-length form, as \\\\?\\D:\\ev or
    \\\\?\\Volume{GUID}\\ev, or in the device form that resolve() gives a volume with no drive letter,
    \\\\.\\Volume{GUID}\\ev. Each root gives a found file's extended-length path, and the plain path a tool's output
    names, the evidence path a plain root gives. A path outside the evidence folder is kept as given."""
    volume = "Volume{00000000-0000-0000-0000-000000000000}"
    for root, paths in (
            (r"\\?\D:\Evidence\case", [r"\\?\D:\Evidence\case\SENSOR\eve.json", r"D:\Evidence\case\SENSOR\eve.json"]),
            (rf"\\.\{volume}\ev", [rf"\\?\{volume}\ev\SENSOR\eve.json", rf"\\.\{volume}\ev\SENSOR\eve.json"]),
            (rf"\\?\{volume}\ev", [rf"\\?\{volume}\ev\SENSOR\eve.json", rf"\\.\{volume}\ev\SENSOR\eve.json"]),
            (r"\\?\UNC\server\share\ev", [r"\\?\UNC\server\share\ev\SENSOR\eve.json", r"\\server\share\ev\SENSOR\eve.json"])):
        for path in paths:
            assert evidence_relative(path, Path(root)) == "SENSOR/eve.json", (root, path)
    assert evidence_relative(r"\\?\C:\KAPE\tout\x.csv", Path(r"\\?\D:\Evidence\case")) == "//?/C:/KAPE/tout/x.csv"
    assert evidence_relative(r"\\?\D:\Other\x.csv", Path(rf"\\.\{volume}\ev")) == "//?/D:/Other/x.csv"


def test_evtxecmd_logon_fields_come_from_payload(tmp_path):
    rows = [
        {"EventRecordId": "4321", "TimeCreated": "2020-09-19 03:21:48.8910870", "EventId": "4624",
         "Provider": "Microsoft-Windows-Security-Auditing", "Channel": "Security", "Computer": "CITADEL-DC01.C137.local",
         "MapDescription": "Successful logon", "PayloadData1": "Target: C137\\Administrator",
         "PayloadData2": "LogonType 10", "SourceFile": "D:\\Evidence\\case\\DC01\\Windows\\System32\\winevt\\Logs\\Security.evtx",
         "Payload": event_data(TargetUserName="Administrator", TargetDomainName="C137", LogonType="10",
                               TargetLogonId="0x6c0b6d", IpAddress="194.61.24.102", WorkstationName="CITADEL-DC01",
                               ProcessName="C:\\Windows\\System32\\svchost.exe")},
        {"EventRecordId": "99", "TimeCreated": "2020-09-19 03:36:22.9809090", "EventId": "4624", "Channel": "Security",
         "Computer": "DESKTOP-SDN1RPT.C137.local", "SourceFile": "D:\\Evidence\\case\\DESKTOP\\Security.evtx",
         "Payload": event_data(TargetUserName="Administrator", TargetDomainName="C137.LOCAL", LogonType="3",
                               IpAddress="::ffff:10.42.85.10", WorkstationName="-")},
    ]
    write_csv(tmp_path / "evtxecmd.csv", EVTX_COLUMNS, rows)
    events = list(PARSERS["evtxecmd_csv"](ParseContext(tmp_path, EVIDENCE)))
    rdp, net = events
    assert rdp.source_file == "DC01/Windows/System32/winevt/Logs/Security.evtx"
    assert (rdp.record_id, rdp.ts_us) == (4321, 1600485708891087)
    assert (rdp.user_domain, rdp.user_name, rdp.logon_type, rdp.logon_id) == ("C137", "Administrator", "10", "0x6c0b6d")
    assert (rdp.source_ip, rdp.source_workstation) == ("194.61.24.102", "CITADEL-DC01")
    assert rdp.process_executable == "C:\\Windows\\System32\\svchost.exe"
    assert rdp.message.startswith("4624 Successful logon | Target: C137\\Administrator | LogonType 10")
    assert rdp.extra["LogonType"] == "10"
    assert (net.source_ip, net.source_workstation) == ("10.42.85.10", "")


def test_sysmon_and_filtering_platform_fields(tmp_path):
    """Sysmon's DOMAIN\\name account, both ends of a network event, and the process."""
    base = {"TimeCreated": "2020-09-19 03:21:40.0000000", "Computer": "LAB", "SourceFile": "D:\\Evidence\\case\\LAB\\x.evtx"}
    sysmon = "Microsoft-Windows-Sysmon/Operational"
    write_csv(tmp_path / "evtxecmd.csv", EVTX_COLUMNS, [
        {**base, "EventRecordId": "1", "EventId": "1", "Channel": sysmon,
         "Payload": event_data(User="LAB\\alice", Image="C:\\Windows\\System32\\cmd.exe", CommandLine="cmd /c whoami")},
        {**base, "EventRecordId": "2", "EventId": "3", "Channel": sysmon,
         "Payload": event_data(User="NT AUTHORITY\\SYSTEM", Image="C:\\x\\beacon.exe", SourceIp="10.0.0.5", SourcePort="49733",
                               DestinationIp="203.0.113.9", DestinationPort="443", Initiated="true")},
        {**base, "EventRecordId": "3", "EventId": "5156", "Channel": "Security",
         "Payload": event_data(Application="\\device\\harddiskvolume2\\windows\\system32\\svchost.exe",
                               SourceAddress="10.0.0.5", SourcePort="135", DestAddress="10.0.0.9", DestPort="50000")},
    ])
    proc, net, wfp = PARSERS["evtxecmd_csv"](ParseContext(tmp_path, EVIDENCE))
    assert (proc.user_domain, proc.user_name, proc.process_command_line) == ("LAB", "alice", "cmd /c whoami")
    assert (net.user_domain, net.user_name) == ("NT AUTHORITY", "SYSTEM")
    assert (net.source_ip, net.source_port, net.dest_ip, net.dest_port) == ("10.0.0.5", "49733", "203.0.113.9", "443")
    assert (wfp.source_ip, wfp.dest_ip, wfp.dest_port) == ("10.0.0.5", "10.0.0.9", "50000")
    assert wfp.file_key == "\\windows\\system32\\svchost.exe"


def test_rdp_connection_client_ip_drops_the_port(tmp_path):
    """RdpCoreTS 131 records ClientIP as IP:port, which the parser splits into the source IP and the source port."""
    write_csv(tmp_path / "evtxecmd.csv", EVTX_COLUMNS, [
        {"EventRecordId": "7", "TimeCreated": "2020-09-19 03:21:40.0000000", "EventId": "131",
         "Channel": "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational", "Computer": "CITADEL-DC01.C137.local",
         "SourceFile": "D:\\Evidence\\case\\DC01\\RdpCoreTS.evtx",
         "Payload": event_data(ConnType="TCP", ClientIP="194.61.24.102:58132")}])
    (event,) = PARSERS["evtxecmd_csv"](ParseContext(tmp_path, EVIDENCE))
    assert (event.source_ip, event.source_port) == ("194.61.24.102", "58132")
    assert event.extra["ClientIP"] == "194.61.24.102:58132"   # the raw field is kept as recorded


def test_logon_source_port_from_ipport(tmp_path):
    """4624 records the source port apart from the address, as IpPort; a 0 or '-' means none."""
    base = {"TimeCreated": "2020-09-19 03:21:48.0000000", "EventId": "4624", "Channel": "Security",
            "Computer": "CITADEL-DC01.C137.local", "SourceFile": "D:\\Evidence\\case\\DC01\\Security.evtx"}
    write_csv(tmp_path / "evtxecmd.csv", EVTX_COLUMNS, [
        {**base, "EventRecordId": "1", "Payload": event_data(LogonType="10", IpAddress="194.61.24.102", IpPort="58132")},
        {**base, "EventRecordId": "2", "Payload": event_data(LogonType="3", IpAddress="10.42.85.115", IpPort="0")}])
    rdp, net = PARSERS["evtxecmd_csv"](ParseContext(tmp_path, EVIDENCE))
    assert (rdp.source_ip, rdp.source_port) == ("194.61.24.102", "58132")
    assert (net.source_ip, net.source_port) == ("10.42.85.115", "")


def test_numbers_in_other_digits_read_as_none(tmp_path):
    """str.isdigit() is true for "²", which int() refuses, so a port or record number written that way must not fail
    the host's whole EvtxECmd or Hayabusa parse. The same holds for more than 4,300 digits, which int() refuses too,
    and for a record number past DuckDB's BIGINT, which would fail the load. Such a value reads as no port and no
    record number; the event keeps its record text, so its ID doesn't change."""
    long, past_bigint = "1" * 5000, "9" * 20
    assert [port_number(p) for p in ("²", "1²", "\uff14\uff14\uff15", long)] == [""] * 4   # 445 in full width
    base = {"TimeCreated": "2020-09-19 03:21:48.0000000", "EventId": "4624", "Channel": "Security",
            "Computer": "CITADEL-DC01.C137.local", "SourceFile": "D:\\Evidence\\case\\DC01\\Security.evtx"}
    logon = lambda port: event_data(LogonType="3", IpAddress="10.42.85.115", IpPort=port)
    write_csv(tmp_path / "evtxecmd.csv", EVTX_COLUMNS, [
        {**base, "EventRecordId": "1", "Payload": logon("58132")},
        {**base, "EventRecordId": "2", "Payload": logon("²")},
        {**base, "EventRecordId": "³", "Payload": logon("58134")},
        {**base, "EventRecordId": "4", "Payload": logon(long)},
        {**base, "EventRecordId": long, "Payload": logon("58136")},
        {**base, "EventRecordId": past_bigint, "Payload": logon("58137")}])
    events = list(PARSERS["evtxecmd_csv"](ParseContext(tmp_path, EVIDENCE)))
    assert [(e.source_record, e.record_id, e.source_port) for e in events] == [
        ("1", 1, "58132"), ("2", 2, ""), ("³", None, "58134"), ("4", 4, ""), (long, None, "58136"),
        (past_bigint, None, "58137")]
    write_csv(tmp_path / "hayabusa.csv", ["Timestamp", "RuleTitle", "Level", "RecordID", "RuleID", "EvtxFile"], [
        {"Timestamp": "2020-09-19T03:21:48Z", "RuleTitle": "Logon", "Level": "low", "RecordID": record, "RuleID": "r1",
         "EvtxFile": "D:\\Evidence\\case\\DC01\\Security.evtx"} for record in ("4321", "²", long, past_bigint)])
    hits = list(PARSERS["hayabusa_csv"](ParseContext(tmp_path, EVIDENCE)))
    assert [(hit.source_record, hit.record_id) for hit in hits] == [
        ("4321:r1", 4321), ("²:r1", None), (f"{long}:r1", None), (f"{past_bigint}:r1", None)]
    db = tmp_path / "events.duckdb"
    connect(db).close()
    loaded = load(db, events + hits, host="DC01", tool="t", tool_version="t", run_id="r", replaces_sources=[],
                  staging_dir=tmp_path)
    assert loaded.rows == 10


def test_hayabusa_rows(tmp_path):
    columns = ["Timestamp", "RuleTitle", "Level", "Computer", "Channel", "EventID", "MitreTactics", "MitreTags",
               "OtherTags", "RecordID", "Details", "ExtraFieldInfo", "RuleFile", "RuleID", "EvtxFile"]
    write_csv(tmp_path / "hayabusa.csv", columns, [{
        "Timestamp": "2020-09-19T03:21:48.891087Z", "RuleTitle": "Logon (RDP)", "Level": "low",
        "Computer": "CITADEL-DC01.C137.local", "Channel": "Security", "EventID": "4624", "RecordID": "4321",
        "Details": "Type: 10 ¦ TgtUser: Administrator ¦ SrcIP: 194.61.24.102", "RuleID": "abc-123",
        "EvtxFile": "D:\\Evidence\\case\\DC01\\Windows\\System32\\winevt\\Logs\\Security.evtx"}])
    (hit,) = PARSERS["hayabusa_csv"](ParseContext(tmp_path, EVIDENCE))
    assert (hit.artifact, hit.record_id, hit.source_record) == ("hayabusa", 4321, "4321:abc-123")
    assert hit.source_file == "DC01/Windows/System32/winevt/Logs/Security.evtx"
    assert (hit.rule_title, hit.rule_level, hit.log_channel) == ("Logon (RDP)", "low", "Security")
    assert hit.message == "Logon (RDP) [low] Type: 10 ¦ TgtUser: Administrator ¦ SrcIP: 194.61.24.102"
    assert hit.extra["RuleID"] == "abc-123"


SYSMON_GUID = "{747f3d96-1d3c-5f68-0000-0010a3b10f00}"
RUN_KEY = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater"
DLL = "rundll32.exe C:\\Users\\Public\\u.dll,Start"
REG = "C:\\Windows\\system32\\reg.exe"
W3WP = "C:\\Windows\\System32\\inetsrv\\w3wp.exe"


def sysmon_row(record, code, description, payload, **columns):
    """A Sysmon row, with the message columns EvtxECmd's map for that event ID writes given in columns."""
    return {"EventRecordId": str(record), "TimeCreated": "2020-09-19 03:21:40.0000000", "EventId": str(code),
            "Provider": "Microsoft-Windows-Sysmon", "Channel": "Microsoft-Windows-Sysmon/Operational", "Computer": "LAB",
            "SourceFile": "D:\\Evidence\\case\\LAB\\Sysmon.evtx", "MapDescription": description,
            "Payload": event_data(**payload), **columns}


def security_row(record, code, description, payload, **columns):
    return {"EventRecordId": str(record), "TimeCreated": "2020-09-19 03:21:40.0000000", "EventId": str(code),
            "Provider": "Microsoft-Windows-Security-Auditing", "Channel": "Security", "Computer": "LAB",
            "SourceFile": "D:\\Evidence\\case\\LAB\\Security.evtx", "MapDescription": description,
            "Payload": event_data(**payload), **columns}


def test_sysmon_messages_lead_with_the_target(tmp_path):
    """Sysmon's maps put the target in PayloadData3 to 6, after the process ID, GUID, and rule name, so the message
    leads with the target: the 160 characters lists show would otherwise hold none of it. The GUID and an empty rule
    name stay in extra."""
    pid = f"ProcessID: 4321, ProcessGUID: {SYSMON_GUID}"
    write_csv(tmp_path / "evtxecmd.csv", EVTX_COLUMNS, [
        sysmon_row(1, 13, "Registry value set",
                   {"Image": REG, "TargetObject": RUN_KEY, "Details": DLL, "ProcessGuid": SYSMON_GUID},
                   PayloadData1=pid, PayloadData2="RuleName: -", PayloadData3=f"Image: {REG}",
                   PayloadData4="EventType: SetValue", PayloadData5=f"TargetObject: {RUN_KEY}", PayloadData6=f"Details: {DLL}"),
        sysmon_row(2, 3, "Network connection", {"SourceIp": "10.0.0.5", "DestinationIp": "10.0.0.9"},
                   PayloadData1=pid, PayloadData2="RuleName: -", PayloadData3="SourceHostname: WS01.corp.local",
                   PayloadData4="SourceIp: 10.0.0.5", PayloadData5="DestinationHostname: DC01.corp.local",
                   PayloadData6="DestinationIp: 10.0.0.9"),
        # Sysmon 10's map differs: no PayloadData1, the access mask in PayloadData2, the call trace in ExecutableInfo.
        # Older Sysmon versions leave a GUID empty.
        sysmon_row(3, 10, "Process access", {"SourceImage": "C:\\Tools\\t.exe"}, PayloadData2="GrantedAccess: 0x1010",
                   PayloadData3=f"SourceProcessID: 4321, SourceProcessGUID: {SYSMON_GUID}",
                   PayloadData4="SourceImage: C:\\Tools\\t.exe",
                   PayloadData5="TargetProcessID: 612, TargetProcessGUID: ",
                   PayloadData6="TargetImage: C:\\Windows\\system32\\lsass.exe",
                   ExecutableInfo="CallTrace: C:\\Windows\\SYSTEM32\\ntdll.dll+9c584"),
        # Other events keep their start, and take PayloadData3 to 6 after it.
        security_row(4, 4624, "Successful logon", {"TargetUserName": "alice", "TargetDomainName": "CORP",
                                                   "LogonType": "3", "AuthenticationPackageName": "NTLM"},
                     PayloadData1="Target: CORP\\alice", PayloadData2="LogonType 3", PayloadData3="LogonId: 0x3e7a1",
                     ExecutableInfo="C:\\Windows\\System32\\lsass.exe"),
        # A 4688 from before Windows 10 has no parent name, and the empty label is left out.
        security_row(5, 4688, "A new process has been created", {"NewProcessName": "C:\\Windows\\System32\\calc.exe"},
                     PayloadData1="Parent process: ", PayloadData2="PID: 0xae8", PayloadData3="Parent PID: 0x600",
                     PayloadData4="Mandatory label: S-1-16-12288", PayloadData5="Target User: \\",
                     ExecutableInfo="C:\\Windows\\System32\\calc.exe "),
    ])
    reg, net, access, logon, created = PARSERS["evtxecmd_csv"](ParseContext(tmp_path, EVIDENCE))
    assert reg.message == (f"13 Registry value set | Details: {DLL} | TargetObject: {RUN_KEY} | Image: {REG} | "
                           "ProcessID: 4321 | EventType: SetValue")
    assert DLL in reg.message[:160] and SYSMON_GUID not in reg.message and reg.extra["ProcessGuid"] == SYSMON_GUID
    assert net.message == ("3 Network connection | Source: 10.0.0.5 | Destination: 10.0.0.9 | "
                           "SourceHostname: WS01.corp.local | DestinationHostname: DC01.corp.local | ProcessID: 4321")
    assert access.message == ("10 Process access | SourceImage: C:\\Tools\\t.exe | TargetImage: C:\\Windows\\system32\\lsass.exe"
                              " | GrantedAccess: 0x1010 | CallTrace: C:\\Windows\\SYSTEM32\\ntdll.dll+9c584 | "
                              "SourceProcessID: 4321 | TargetProcessID: 612")
    # 4624 names its authentication package, which sets an NTLM network logon apart.
    assert logon.message == ("4624 Successful logon | Target: CORP\\alice | LogonType 3 | AuthenticationPackage: NTLM | "
                             "C:\\Windows\\System32\\lsass.exe | LogonId: 0x3e7a1")
    assert created.message == ("4688 A new process has been created | PID: 0xae8 | C:\\Windows\\System32\\calc.exe | "
                               "Parent PID: 0x600 | Mandatory label: S-1-16-12288 | Target User: \\")


def test_sysmon_13_data_comes_before_a_long_user_key(tmp_path):
    """A user's RunMRU key runs to 110 characters, so the data comes before the key: with the key first, the command
    typed over RDP would start after the 160 characters lists show."""
    from glessner.search import SHOWN_MESSAGE

    key = ("HKU\\S-1-5-21-3463664321-2923530833-3546627382-1000\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer"
           "\\RunMRU\\a")
    typed = "cmd.exe /c whoami\\1"
    write_csv(tmp_path / "evtxecmd.csv", EVTX_COLUMNS, [
        sysmon_row(1, 13, "Registry value set", {"EventType": "SetValue", "TargetObject": key, "Details": typed},
                   PayloadData1=f"ProcessID: 4321, ProcessGUID: {SYSMON_GUID}", PayloadData2="RuleName: -",
                   PayloadData3="Image: C:\\Windows\\explorer.exe", PayloadData4="EventType: SetValue",
                   PayloadData5=f"TargetObject: {key}", PayloadData6=f"Details: {typed}"),
    ])
    [value_set] = PARSERS["evtxecmd_csv"](ParseContext(tmp_path, EVIDENCE))
    # Measured from the label, since a short value such as "a" is found earlier in the line.
    start = value_set.message.index(" | Details: ") + len(" | Details: ")
    assert len(key) == 110 and value_set.message[start:start + len(typed)] == typed
    assert start + len(typed) <= SHOWN_MESSAGE
    assert value_set.message.index(f"TargetObject: {key}") > start


DECODED_LAYOUT = pytest.mark.parametrize("decoded", [False, True], ids=["as the event's XML holds them", "decoded"])


def evtx_layout(decoded):
    """The columns of EvtxECmd's CSV, and how it writes a value that the event's XML holds as `value`. Before 2026.10 it
    writes the XML's text as it is. From 2026.10 it writes the event's own text, with each entity decoded once, and ends
    the row with a RenderingInfo column."""
    return ([*EVTX_COLUMNS, "RenderingInfo"], html.unescape) if decoded else (EVTX_COLUMNS, str)


@DECODED_LAYOUT
def test_xml_entities_are_unescaped_once(tmp_path, decoded):
    """In the older layout one unescape gives the event's own text: the redirection in a command line, and task XML that
    keeps its own entities. In the newer layout the value is that text already, so a row with the RenderingInfo column
    is not unescaped again, and the events come out the same."""
    columns, text = evtx_layout(decoded)
    written = text("cmd.exe /Q /c dir 1&gt; \\\\127.0.0.1\\ADMIN$\\out 2&gt;&amp;1")
    command = "cmd.exe /Q /c dir 1> \\\\127.0.0.1\\ADMIN$\\out 2>&1"
    task_written = text("&lt;Exec&gt;&lt;Command&gt;cmd.exe&lt;/Command&gt;&lt;Arguments&gt;/c dir &amp;gt; x.txt"
                        "&lt;/Arguments&gt;&lt;/Exec&gt;")
    task = "<Exec><Command>cmd.exe</Command><Arguments>/c dir &gt; x.txt</Arguments></Exec>"
    audit = text("Raw Audit Event: statement:EXEC sp_configure &apos;xp_cmdshell&apos;, 1 &lt;ok&gt;")
    write_csv(tmp_path / "evtxecmd.csv", columns, [
        sysmon_row(1, 1, "Process creation", {"Image": "C:\\Windows\\System32\\cmd.exe", "CommandLine": written},
                   ExecutableInfo=written),
        security_row(2, 4698, "Scheduled task created", {"TaskName": "\\Updater", "TaskContent": task_written},
                     PayloadData1="TaskName: \\Updater", PayloadData2=f"TaskContent: {task_written}"),
        # MSSQL writes unnamed data, which EvtxECmd joins into one string; it's unescaped like named data.
        {"EventRecordId": "3", "TimeCreated": "2020-09-19 03:21:40.0000000", "EventId": "33205",
         "Provider": "MSSQLSERVER", "Channel": "Application", "SourceFile": "D:\\Evidence\\case\\LAB\\Application.evtx",
         "MapDescription": "SQL audit event", "PayloadData1": audit,
         "Payload": json.dumps({"EventData": {"Data": text("audit &lt;ok&gt;")}})},
        sysmon_row(4, 3, "Network connection", {"Image": text("&lt;unknown process&gt;"), "SourceIp": "10.0.0.5"}),
    ])
    proc, created, sql, net = PARSERS["evtxecmd_csv"](ParseContext(tmp_path, EVIDENCE))
    assert proc.process_command_line == command and proc.extra["CommandLine"] == command and command in proc.message
    assert created.extra["TaskContent"] == task and task in created.message
    assert sql.extra == {"Data": "audit <ok>"} and sql.message == (
        "33205 SQL audit event | Raw Audit Event: statement:EXEC sp_configure 'xp_cmdshell', 1 <ok>")
    assert net.process_executable == "<unknown process>"


def test_registry_data_from_sysmon_13_details(tmp_path):
    """Sysmon 13's Details is the value's data, in registry_data. registry_value stays a
    value's name, as RECmd fills it; Sysmon's "Binary Data" stand-in is kept as written."""
    key = "HKLM\\System\\CurrentControlSet\\Services\\LanmanServer\\Shares"
    write_csv(tmp_path / "evtxecmd.csv", EVTX_COLUMNS, [
        sysmon_row(1, 13, "Registry value set", {"EventType": "SetValue", "TargetObject": RUN_KEY, "Details": DLL}),
        sysmon_row(2, 13, "Registry value set", {"EventType": "SetValue", "TargetObject": f"{key}\\staging",
                                                 "Details": "Binary Data"}),
        sysmon_row(3, 12, "Registry object added or deleted", {"EventType": "CreateKey", "TargetObject": key}),
    ])
    value_set, binary, created = PARSERS["evtxecmd_csv"](ParseContext(tmp_path, EVIDENCE))
    assert (value_set.registry_path, value_set.registry_value, value_set.registry_data) == (RUN_KEY, "", DLL)
    assert (binary.registry_data, binary.extra["Details"]) == ("Binary Data", "Binary Data")
    assert (created.registry_path, created.registry_data) == (key, "")


def test_parent_process_columns_and_message(tmp_path):
    """Sysmon 1's ParentImage and ParentCommandLine, and 4688's ParentProcessName, are
    columns. Sysmon 1's message names the parent ahead of the command line; 4688's map already leads with it. Sysmon's
    "?" for a parent it couldn't resolve is no parent: as a View value, it matched unrelated events."""
    w3wp_command = 'c:\\windows\\system32\\inetsrv\\w3wp.exe -ap "DefaultAppPool"'
    wmi = "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe"
    write_csv(tmp_path / "evtxecmd.csv", EVTX_COLUMNS, [
        sysmon_row(1, 1, "Process creation",
                   {"Image": "C:\\Windows\\System32\\cmd.exe", "CommandLine": "cmd.exe /c whoami", "ParentImage": W3WP,
                    "ParentCommandLine": w3wp_command},
                   PayloadData1=f"ProcessID: 4321, ProcessGUID: {SYSMON_GUID}", PayloadData2="RuleName: -",
                   PayloadData3="SHA1=0000000000000000000000000000000000000000", PayloadData4=f"ParentProcess: {W3WP}",
                   PayloadData5=f"ParentProcessID: 2200, ParentProcessGUID: {SYSMON_GUID}",
                   PayloadData6=f"ParentCommandLine: {w3wp_command}", ExecutableInfo="cmd.exe /c whoami"),
        security_row(2, 4688, "A new process has been created",
                     {"NewProcessName": "C:\\Windows\\System32\\calc.exe", "ParentProcessName": wmi},
                     PayloadData1=f"Parent process: {wmi}", PayloadData2="PID: 0xae8", PayloadData3="Parent PID: 0x600",
                     ExecutableInfo="C:\\Windows\\System32\\calc.exe "),
        sysmon_row(3, 11, "File created", {"Image": W3WP, "TargetFilename": "C:\\inetpub\\wwwroot\\x.aspx"}),
        sysmon_row(4, 1, "Process creation",
                   {"Image": "C:\\Windows\\System32\\cmd.exe", "ParentImage": "?", "ParentCommandLine": "?"},
                   PayloadData4="ParentProcess: ?", PayloadData6="ParentCommandLine: ?"),
    ])
    shell, calc, written, orphan = PARSERS["evtxecmd_csv"](ParseContext(tmp_path, EVIDENCE))
    assert (shell.process_parent_executable, shell.process_parent_command_line) == (W3WP, w3wp_command)
    assert shell.message == ("1 Process creation | parent w3wp.exe | cmd.exe /c whoami | "
                             f"ParentCommandLine: {w3wp_command} | ParentProcess: {W3WP} | ProcessID: 4321 | "
                             "SHA1=0000000000000000000000000000000000000000 | ParentProcessID: 2200")
    assert (calc.process_parent_executable, calc.process_parent_command_line) == (wmi, "")
    assert calc.message == (f"4688 A new process has been created | Parent process: {wmi} | PID: 0xae8 | "
                            "C:\\Windows\\System32\\calc.exe | Parent PID: 0x600")
    assert (written.process_parent_executable, written.process_executable) == ("", W3WP)
    assert (orphan.process_parent_executable, orphan.process_parent_command_line) == ("", "")
    assert orphan.extra["ParentImage"] == "?" and "| parent " not in orphan.message


def system_row(record, code, description, payload, **columns):
    return {"EventRecordId": str(record), "TimeCreated": "2020-09-19 03:21:40.0000000", "EventId": str(code),
            "Provider": "Service Control Manager", "Channel": "System", "Computer": "LAB",
            "SourceFile": "D:\\Evidence\\case\\LAB\\System.evtx", "MapDescription": description,
            "Payload": event_data(**payload), **columns}


SHARE_FIELDS = {"SubjectUserName": "jlee", "SubjectLogonId": "0x4A7F3B", "IpAddress": "10.20.4.15", "IpPort": "51846"}


def test_share_access_names_its_file_and_rights(tmp_path):
    """A 5145 joins the share's local folder to the path under it, so Same file reaches the copied tool, and its
    rights read by name; EvtxECmd writes "Unknown code" for a list of them."""
    write_csv(tmp_path / "evtxecmd.csv", EVTX_COLUMNS, [
        security_row(1, 5145, "Network share object access",
                     {**SHARE_FIELDS, "ShareName": "\\\\*\\ADMIN$", "ShareLocalPath": "\\??\\C:\\Windows",
                      "RelativeTargetName": "PSEXESVC.exe", "AccessMask": "0x120196",
                      "AccessList": "%%1538, %%1541, %%4417, %%4418, %%4420, %%4423, %%4424, "},
                     PayloadData1="Share: \\\\*\\ADMIN$ (\\??\\C:\\Windows)", PayloadData2="Object: PSEXESVC.exe",
                     PayloadData3="AccessList: Unknown code (%%1538 | %%1541 | %%4417 | %%4418)",
                     PayloadData4="AccessMask: Unknown code (0x120196)"),
        security_row(2, 5145, "Network share object access",
                     {**SHARE_FIELDS, "ShareName": "\\\\*\\IPC$", "ShareLocalPath": "", "RelativeTargetName": "svcctl",
                      "AccessList": "%%4416, %%4417, "},
                     PayloadData1="Share: \\\\*\\IPC$ ()", PayloadData2="Object: svcctl",
                     PayloadData3="AccessList: Unknown code (%%4416 | %%4417)"),
        security_row(3, 5145, "Network share object access",
                     {**SHARE_FIELDS, "ShareName": "\\\\*\\C$", "ShareLocalPath": "\\??\\C:\\", "RelativeTargetName": "\\",
                      "AccessList": "%%4416, "},
                     PayloadData1="Share: \\\\*\\C$ (\\??\\C:\\)", PayloadData2="Object: \\",
                     PayloadData3="AccessList: ReadData (or ListDirectory)"),
        # 4663 names its rights too, but its map has no AccessList part: the message gains nothing.
        security_row(4, 4663, "An attempt was made to access an object",
                     {"ObjectName": "C:\\Secret\\plan.docx", "AccessList": "%%4416, "},
                     PayloadData1="ObjectName: C:\\Secret\\plan.docx"),
    ])
    copied, pipe, root, accessed = PARSERS["evtxecmd_csv"](ParseContext(tmp_path, EVIDENCE))
    assert (copied.file_path, copied.file_key) == ("C:\\Windows\\PSEXESVC.exe", "\\windows\\psexesvc.exe")
    assert copied.extra["AccessNames"] == ("READ_CONTROL, SYNCHRONIZE, WriteData, AppendData, WriteEA, "
                                           "ReadAttributes, WriteAttributes")
    assert copied.message.startswith("5145 Network share object access | Share: \\\\*\\ADMIN$ (\\??\\C:\\Windows) | "
                                     "Object: PSEXESVC.exe | Access: READ_CONTROL, SYNCHRONIZE, WriteData")
    assert "Unknown code (%%" not in copied.message and "AccessMask: Unknown code (0x120196)" in copied.message
    assert (pipe.file_path, pipe.extra["AccessNames"]) == ("", "ReadData, WriteData")   # a pipe isn't a file
    assert pipe.message.endswith("| Object: svcctl | Access: ReadData, WriteData")
    # IPC$ has no local folder, so no empty parentheses after it
    assert pipe.message.startswith("5145 Network share object access | Share: \\\\*\\IPC$ | Object: svcctl")
    assert root.file_path == "" and root.message.endswith("| Object: \\ | Access: ReadData")   # nor the share's root
    assert accessed.message == "4663 An attempt was made to access an object | ObjectName: C:\\Secret\\plan.docx"
    assert accessed.extra["AccessNames"] == "ReadData"


def test_loaded_dlls_and_service_binaries_are_files(tmp_path):
    """Sysmon 7's loaded DLL and a service's binary are the file the event is about, so Same file reaches
    them; the service's arguments are left off and %SystemRoot% is written out."""
    lsass = "C:\\Windows\\System32\\lsass.exe"
    dll = "\\\\10.0.2.17\\share\\evil.dll"
    write_csv(tmp_path / "evtxecmd.csv", EVTX_COLUMNS, [
        sysmon_row(1, 7, "Image loaded", {"Image": lsass, "ImageLoaded": dll}),
        system_row(2, 7045, "A service was installed in the system",
                   {"ServiceName": "remotesvc", "ImagePath": "%SystemRoot%\\remotesvc.exe -k netsvcs"}),
        system_row(3, 7045, "A service was installed in the system",
                   {"ServiceName": "spaced", "ImagePath": "\"C:\\Program Files\\App\\svc.exe\" /run"}),
        system_row(4, 7045, "A service was installed in the system",
                   {"ServiceName": "drv", "ImagePath": "system32\\drivers\\evil.sys"}),
        system_row(5, 7045, "A service was installed in the system", {"ServiceName": "spoolfool", "ImagePath": "cmd.exe"}),
        # A driver installed from \??\, smbexec's command service, and a folder variable.
        system_row(6, 7045, "A service was installed in the system",
                   {"ServiceName": "vuln", "ImagePath": "\\??\\C:\\Windows\\Temp\\vuln.sys"}),
        system_row(7, 7045, "A service was installed in the system",
                   {"ServiceName": "BTOBTO", "ImagePath": "%COMSPEC% /Q /c echo dir > %TEMP%\\execute.bat & "
                                                          "%COMSPEC% /Q /c %TEMP%\\execute.bat"}),
        system_row(8, 7045, "A service was installed in the system",
                   {"ServiceName": "app", "ImagePath": "%ProgramFiles%\\App\\svc.exe -k run"}),
    ])
    loaded, remote, spaced, driver, bare, vuln, smbexec, app = PARSERS["evtxecmd_csv"](ParseContext(tmp_path, EVIDENCE))
    assert (vuln.file_path, vuln.file_key) == ("C:\\Windows\\Temp\\vuln.sys", "\\windows\\temp\\vuln.sys")
    assert (smbexec.file_path, smbexec.file_key) == ("%COMSPEC%", "")   # the first word, not a fragment of the line
    assert (app.file_path, app.file_key) == ("C:\\Program Files\\App\\svc.exe", "\\program files\\app\\svc.exe")
    assert (loaded.file_path, loaded.process_executable) == (dll, lsass)
    assert (remote.file_path, remote.file_key) == ("C:\\Windows\\remotesvc.exe", "\\windows\\remotesvc.exe")
    assert spaced.file_path == "C:\\Program Files\\App\\svc.exe"
    assert driver.file_path == "C:\\Windows\\system32\\drivers\\evil.sys"
    assert (bare.file_path, bare.file_key) == ("cmd.exe", "")   # a bare name isn't a path to join on


TASK_XML = ('<?xml version="1.0" encoding="UTF-16"?>'
            '<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">'
            '<Principals><Principal id="LocalSystem"><UserId>S-1-5-18</UserId></Principal></Principals>'
            '<Actions Context="LocalSystem"><Exec><Command>cmd.exe</Command>'
            "<Arguments>/C tasklist &gt; %windir%\\Temp\\CYAlyNSS.tmp 2&gt;&amp;1</Arguments></Exec></Actions></Task>")


@DECODED_LAYOUT
def test_scheduled_task_xml_gives_the_command(tmp_path, decoded):
    """What a remote task runs is only in its escaped XML. The older EvtxECmd layout writes the XML escaped once more, as
    the event holds it, and after one unescape it parses. The newer layout writes it unescaped once already, and a second
    unescape would break it: the task's own &amp; would become a bare &. Either way the action becomes the process and
    command line. XML that declares a DTD is left alone."""
    columns, text = evtx_layout(decoded)
    # As EvtxECmd delivers it: escaped, with the XML's lines joined by ", ".
    escaped = text(html.escape(TASK_XML.replace("><", ">, <"), quote=False))
    bomb = text(html.escape('<?xml version="1.0"?><!DOCTYPE t [<!ENTITY a "aa">]><Task><Actions><Exec><Command>&a;'
                            "</Command></Exec></Actions></Task>", quote=False))
    write_csv(tmp_path / "evtxecmd.csv", columns, [
        security_row(1, 4698, "Scheduled Task created", {"TaskName": "\\CYAlyNSS", "TaskContent": escaped},
                     PayloadData1="TaskName: \\CYAlyNSS", PayloadData2=escaped),
        security_row(2, 4702, "A scheduled task was updated", {"TaskName": "\\LMST", "TaskContentNew": escaped},
                     PayloadData1="TaskName: \\LMST", PayloadData2=escaped),
        security_row(3, 4698, "Scheduled Task created", {"TaskName": "\\odd", "TaskContent": bomb},
                     PayloadData1="TaskName: \\odd", PayloadData2=bomb),
    ])
    created, updated, odd = PARSERS["evtxecmd_csv"](ParseContext(tmp_path, EVIDENCE))
    command = "/C tasklist > %windir%\\Temp\\CYAlyNSS.tmp 2>&1"
    assert (created.process_executable, created.process_command_line) == ("cmd.exe", f"cmd.exe {command}")
    assert (created.extra["TaskCommand"], created.extra["TaskPrincipal"]) == ("cmd.exe", "S-1-5-18")
    assert created.message == f"4698 Scheduled Task created | TaskName: \\CYAlyNSS | Runs: cmd.exe {command}"
    assert updated.process_command_line == f"cmd.exe {command}" and updated.message.startswith(
        "4702 A scheduled task was updated | TaskName: \\LMST | Runs: cmd.exe")
    assert odd.process_executable == "" and "TaskCommand" not in odd.extra and "<Task>" in odd.message


def test_a_task_with_several_actions_keeps_each_command_with_its_arguments(tmp_path):
    """Each action of a task keeps its own command and arguments: the second's arguments don't join the first's command."""
    two = html.escape('<?xml version="1.0" encoding="UTF-16"?><Task xmlns="http://schemas.microsoft.com/windows/2004/02'
                      '/mit/task"><Actions><Exec><Command>%windir%\\System32\\notepad.exe</Command></Exec>'
                      "<Exec><Command>C:\\Users\\Public\\x.exe</Command><Arguments>-run</Arguments></Exec></Actions>"
                      "</Task>", quote=False)
    write_csv(tmp_path / "evtxecmd.csv", EVTX_COLUMNS, [
        security_row(1, 4698, "Scheduled Task created", {"TaskName": "\\two", "TaskContent": two},
                     PayloadData1="TaskName: \\two", PayloadData2=two)])
    (task,) = PARSERS["evtxecmd_csv"](ParseContext(tmp_path, EVIDENCE))
    # %windir% written out, so Same file reaches the program's other records
    assert (task.process_executable, task.file_key) == ("C:\\Windows\\System32\\notepad.exe",
                                                        "\\windows\\system32\\notepad.exe")
    assert task.process_command_line == "%windir%\\System32\\notepad.exe"   # the first action's own, no arguments
    assert task.message.endswith("| Runs: %windir%\\System32\\notepad.exe (+1 more action)")
    assert "TaskMore" not in task.extra and task.extra["TaskCommand"] == "%windir%\\System32\\notepad.exe"


USER_SID = "S-1-5-21-3623811015-3361044348-30300820-1013"


def winrm_payload(text):
    """WinRM's EventPayload as EvtxECmd writes it: the UTF-16 bytes as hex pairs joined with hyphens."""
    return "-".join(f"{b:02X}" for b in (text + "\0").encode("utf-16-le"))


def test_accounts_from_the_events_system_userid(tmp_path):
    """A remote service's installer is only in the event's System UserID. A user's SID is
    the account where the data names none; LocalSystem's isn't, and an account the data names stays."""
    write_csv(tmp_path / "evtxecmd.csv", EVTX_COLUMNS, [
        system_row(1, 7045, "Service installed", {"ServiceName": "PSEXESVC", "ImagePath": "%SystemRoot%\\PSEXESVC.exe"},
                   UserId=USER_SID),
        system_row(2, 7045, "Service installed", {"ServiceName": "Spooler", "ImagePath": "spoolsv.exe"},
                   UserId="S-1-5-18"),
        security_row(3, 4624, "Successful logon", {"TargetUserName": "alice", "TargetDomainName": "CORP"},
                     UserId=USER_SID),
        system_row(4, 7045, "Service installed", {"ServiceName": "x"}, UserId="S-1-12-1-1234-5678-9012-3456"),   # Entra ID
        system_row(5, 7045, "Service installed", {"ServiceName": "y"}, UserId="S-1-5-80-1234"),   # a service's SID
    ])
    remote, local, logon, entra, service = PARSERS["evtxecmd_csv"](ParseContext(tmp_path, EVIDENCE))
    assert (remote.user_name, remote.user_domain, remote.extra["SecurityUserID"]) == (USER_SID, "", USER_SID)
    assert local.user_name == "" and "SecurityUserID" not in local.extra
    assert (logon.user_name, logon.extra["SecurityUserID"]) == ("alice", USER_SID)
    assert (entra.user_name, service.user_name) == ("S-1-12-1-1234-5678-9012-3456", "")


def test_sysmon_logon_id_gives_the_session_but_not_a_system_one(tmp_path):
    """Sysmon 1's LogonId ties a process to the logon that started it. LocalSystem's session, which every service
    shares, is left out, as is another provider's LogonId; Security's own logon IDs stay as they are."""
    write_csv(tmp_path / "evtxecmd.csv", EVTX_COLUMNS, [
        sysmon_row(1, 1, "Process creation", {"Image": "C:\\Windows\\System32\\cmd.exe", "LogonId": "0x5C1D2"}),
        sysmon_row(2, 1, "Process creation", {"Image": "C:\\Windows\\System32\\svchost.exe", "LogonId": "0x3E7"}),
        {**system_row(3, 1, "Other", {"LogonId": "0x5C1D2"}), "Provider": "Microsoft-Windows-Other"},
        security_row(4, 4688, "Process created", {"SubjectLogonId": "0x3e7", "LogonId": "0x5C1D2"}),
        sysmon_row(5, 1, "Process creation", {"LogonId": "0x3e4"}),   # NetworkService
        sysmon_row(6, 1, "Process creation", {"LogonId": "0x3E5"}),   # LocalService
        {**sysmon_row(7, 1, "Process creation", {"LogonId": "0x7A2B"}), "Provider": ""},   # Sysmon by its channel
    ])
    user, system, other, security, network, local, by_channel = PARSERS["evtxecmd_csv"](ParseContext(tmp_path, EVIDENCE))
    assert (user.logon_id, system.logon_id, other.logon_id, security.logon_id) == ("0x5C1D2", "", "", "0x3e7")
    assert (network.logon_id, local.logon_id, by_channel.logon_id) == ("", "", "0x7A2B")


def test_unnamed_data_and_unmapped_events(tmp_path):
    """MSSQL's unnamed strings and WinRM's ProcessingErrorData are kept, so a search for xp_cmdshell finds the
    15281. An event without a map shows its first fields after the provider."""
    statement = "xp_cmdshell, Database: master,  sp_configure"
    uri = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd"
    long_value = "x" * 200
    write_csv(tmp_path / "evtxecmd.csv", EVTX_COLUMNS, [
        {**system_row(1, 15281, "", {}), "Provider": "MSSQL$SQLEXPRESS", "Channel": "Application",
         "Payload": json.dumps({"EventData": {"Data": statement, "Binary": "D13B0000"}})},
        {**system_row(2, 91, "", {}), "Provider": "Microsoft-Windows-WinRM", "Channel": "WinRM/Operational",
         "UserId": USER_SID, "Payload": json.dumps({"ProcessingErrorData": {
             "ErrorCode": "15005", "DataItemName": "shellId", "EventPayload": winrm_payload(uri)}})},
        {**system_row(3, 10016, "", {"param1": "application-specific", "param2": "Local", "param3": "Activation",
                                     "param4": long_value, "param5": "not shown"}),
         "Provider": "Microsoft-Windows-DistributedCOM"},
        # A mapped event's message is the map's, however few parts it has.
        system_row(4, 7036, "Service state changed", {"param1": "Print Spooler", "param2": "stopped"}),
    ])
    sql, winrm, dcom, mapped = PARSERS["evtxecmd_csv"](ParseContext(tmp_path, EVIDENCE))
    assert sql.extra == {"Data": statement} and sql.message == f"15281 MSSQL$SQLEXPRESS | {' '.join(statement.split())}"
    assert winrm.extra["EventPayloadText"] == uri and winrm.extra["ErrorCode"] == "15005"
    assert winrm.message == (f"91 Microsoft-Windows-WinRM | ErrorCode: 15005 | DataItemName: shellId | "
                             f"EventPayloadText: {uri}")
    assert winrm.user_name == USER_SID   # from the same event's System UserID
    assert dcom.message == ("10016 Microsoft-Windows-DistributedCOM | param1: application-specific | param2: Local | "
                            f"param3: Activation | param4: {'x' * 117}...")
    assert mapped.message == "7036 Service state changed"


def test_payload_fields_number_a_list_of_unnamed_values():
    listed = json.dumps({"EventData": {"Data": ["first", {"@Name": "Named", "#text": "n"}, "third"]}})
    assert payload_fields(listed) == {"Data1": "first", "Named": "n", "Data3": "third"}
    error = json.dumps({"ProcessingErrorData": {"ErrorCode": "15005", "EventPayload": "63-00"}})
    assert payload_fields(error) == {"ErrorCode": "15005", "EventPayload": "63-00"}


def test_payload_text_finds_utf16_strings_and_nothing_in_binary():
    """Decoding every byte pair as UTF-16 would let binary through as CJK text, so only runs of ASCII characters as
    UTF-16 count, as strings -el finds them."""
    wide = lambda text: "".join(f"{b:02X}" for b in text.encode("utf-16-le"))
    assert payload_text(wide("cmd\0")) == "cmd"   # the event XML's form, no hyphens
    length_prefixed = "07-00-" + winrm_payload("shellId")[:-6] + "-0E-00-00-00-" + winrm_payload("http://x/shell")
    assert payload_text(length_prefixed) == "shellId | http://x/shell"
    assert payload_text("68-74-74-70") == ""      # ASCII bytes, not UTF-16: "http" would read as two CJK characters
    assert payload_text("2D-4E-41-00") == ""      # a number, then one letter
    assert payload_text("01-00-02-00") == ""
    assert payload_text("6800-7400-7400") == ""   # one separator or none, not both
    assert payload_text("not hex") == "" and payload_text("") == ""


def test_the_xml_reader_s_message_parts_are_never_unescaped_and_an_older_row_s_are():
    """The message decides from its own arguments whether a part is unescaped: the built-in XML reader's rows hold text
    its parser decoded, as do rows with the RenderingInfo column, and an older EvtxECmd row holds the XML's entities."""
    from glessner.parsers.evtxecmd import _message

    row = {"MapDescription": "Process created", "PayloadData1": "cmd /c dir 1&gt; x &amp; ver"}
    assert _message("4688", row, {}, "", xml_reader=True) == "4688 Process created | cmd /c dir 1&gt; x &amp; ver"
    assert _message("4688", {**row, "RenderingInfo": ""}, {}, "", xml_reader=False) == (
        "4688 Process created | cmd /c dir 1&gt; x &amp; ver")
    assert _message("4688", row, {}, "", xml_reader=False) == "4688 Process created | cmd /c dir 1> x & ver"


def test_decoded_payload_text_is_not_unescaped_again(tmp_path):
    """The text decoded from hex is literal, so the unescape for EvtxECmd's values doesn't apply."""
    write_csv(tmp_path / "evtxecmd.csv", EVTX_COLUMNS, [
        {**system_row(1, 91, "", {}), "Provider": "Microsoft-Windows-WinRM", "Payload": json.dumps(
            {"ProcessingErrorData": {"DataItemName": "a &amp; b", "EventPayload": winrm_payload("x &lt; y")}})},
    ])
    (event,) = PARSERS["evtxecmd_csv"](ParseContext(tmp_path, EVIDENCE))
    assert (event.extra["DataItemName"], event.extra["EventPayloadText"]) == ("a & b", "x &lt; y")


def test_sysmon_network_messages_name_the_direction_and_ports(tmp_path):
    """Older Sysmon writes the local side as the source either way, so an inbound connection's remote address
    is the destination. The message says which way the connection went and gives each end its port, under Sysmon's
    own labels; the recorded source and destination are kept as they are."""
    ends = {"SourceIp": "10.0.2.15", "SourcePort": "445", "DestinationIp": "10.0.2.17", "DestinationPort": "52000"}
    write_csv(tmp_path / "evtxecmd.csv", EVTX_COLUMNS, [
        sysmon_row(1, 3, "Network connection", {"Image": "System", "Initiated": "False", **ends},
                   PayloadData3="SourceHostname: -", PayloadData4="SourceIp: 10.0.2.15",
                   PayloadData5="DestinationHostname: -", PayloadData6="DestinationIp: 10.0.2.17", ExecutableInfo="System"),
        sysmon_row(2, 3, "Network connection", {"Initiated": "true", "SourceIp": "fe80::1", "SourcePort": "49712",
                                                "DestinationIp": "fe80::2", "DestinationPort": "443"}),
        # No port (0), and an end only the map's column names: the map's own part stands in.
        sysmon_row(3, 3, "Network connection", {"Initiated": "true", "DestinationIp": "10.0.2.17", "DestinationPort": "0"},
                   PayloadData4="SourceIp: 10.0.2.15"),
    ])
    inbound, outbound, partial = PARSERS["evtxecmd_csv"](ParseContext(tmp_path, EVIDENCE))
    assert partial.message == "3 Network connection | outbound | SourceIp: 10.0.2.15 | Destination: 10.0.2.17"
    assert inbound.message == "3 Network connection | inbound | Source: 10.0.2.15:445 | Destination: 10.0.2.17:52000 | System"
    assert (inbound.source_ip, inbound.dest_ip, inbound.dest_port) == ("10.0.2.15", "10.0.2.17", "52000")
    assert outbound.message == "3 Network connection | outbound | Source: [fe80::1]:49712 | Destination: [fe80::2]:443"


def test_a_logon_names_its_authentication_package_once(tmp_path):
    """EvtxECmd's 4624 map from 2026.10 writes the authentication package as a part of its own, so the parser adds its
    part only to a row whose map part is absent or holds no value."""
    payload = {"TargetUserName": "alice", "TargetDomainName": "CORP", "LogonType": "3",
               "AuthenticationPackageName": "NTLM"}
    write_csv(tmp_path / "evtxecmd.csv", [*EVTX_COLUMNS, "RenderingInfo"], [
        security_row(1, 4624, "Successful logon", payload, PayloadData1="Target: CORP\\alice",
                     PayloadData2="LogonType 3", PayloadData4="AuthenticationPackageName: NTLM",
                     PayloadData5="LogonProcessName: NtLmSsp"),
        security_row(2, 4624, "Successful logon", payload, PayloadData1="Target: CORP\\alice",
                     PayloadData2="LogonType 3", PayloadData4="AuthenticationPackageName: -"),
        security_row(3, 4625, "Failed logon", payload, PayloadData1="Target: CORP\\alice"),
    ])
    mapped, bare_label, failed = PARSERS["evtxecmd_csv"](ParseContext(tmp_path, EVIDENCE))
    assert mapped.message == ("4624 Successful logon | Target: CORP\\alice | LogonType 3 | "
                              "AuthenticationPackageName: NTLM | LogonProcessName: NtLmSsp")
    assert bare_label.message == ("4624 Successful logon | Target: CORP\\alice | LogonType 3 | "
                                  "AuthenticationPackage: NTLM")
    assert failed.message == "4625 Failed logon | Target: CORP\\alice | AuthenticationPackage: NTLM"


LRM, RLM = "\u200e", "\u200f"


def test_bidi_marks_leave_a_windows_date_and_stay_elsewhere(tmp_path):
    """Windows writes a date for the reader's locale with a left-to-right mark before each part, as Task Scheduler's 800
    and CAPI2's 4111 hold it, so a search for the date as shown would miss it. The marks leave a value that is a date
    without them, in a field whose name holds Date or Time or in the unnamed data of CAPI2 or EventLog, and a message
    part that repeats such a value. Anywhere else they stay, and the pages show them, since they can disguise a name."""
    run_date = f"{LRM}9/{LRM}17/{LRM}2020 9:43 AM"
    long_date = f"{LRM}Wednesday, {LRM}September {LRM}2, {LRM}2020 6:21:26 PM"
    disguised = f"C:\\Users\\Public\\{RLM}invoice{LRM}.pdf.exe"
    write_csv(tmp_path / "evtxecmd.csv", [*EVTX_COLUMNS, "RenderingInfo"], [
        {**system_row(1, 800, "Task Scheduler service", {"LastRunDateTime": run_date}),
         "Provider": "Microsoft-Windows-TaskScheduler", "PayloadData1": f"LastRunDateTime: {run_date}"},
        {**system_row(2, 4111, "", {}), "Provider": "Microsoft-Windows-CAPI2",
         "Payload": json.dumps({"EventData": {"Data": long_date}})},
        sysmon_row(3, 1, "Process creation", {"Image": disguised, "CommandLine": f"{disguised} {run_date}"},
                   ExecutableInfo=disguised),
        # EvtxECmd writes the marks as characters, not as JSON escapes.
        {**system_row(4, 800, "Task Scheduler service", {}), "Provider": "Microsoft-Windows-TaskScheduler",
         "Payload": json.dumps({"EventData": {"Data": [{"@Name": "LastRunDateTime", "#text": run_date}]}},
                               ensure_ascii=False)},
    ])
    task, capi, proc, written = PARSERS["evtxecmd_csv"](ParseContext(tmp_path, EVIDENCE))
    assert written.extra["LastRunDateTime"] == "9/17/2020 9:43 AM"
    assert task.extra["LastRunDateTime"] == "9/17/2020 9:43 AM"
    assert task.message == "800 Task Scheduler service | LastRunDateTime: 9/17/2020 9:43 AM"
    assert capi.extra == {"Data": "Wednesday, September 2, 2020 6:21:26 PM"} and LRM not in capi.message
    assert proc.extra["Image"] == disguised and disguised in proc.message
    assert proc.process_command_line == f"{disguised} {run_date}"


@pytest.mark.parametrize("text", [
    f"{LRM}1.2.3", f"1.{LRM}2.3", f"{LRM}6.1.7601", f"{LRM}123-45-6789", f"Windows {LRM}10 2004", f"1 of {LRM}2048",
    f"admin{RLM} 12 2024", f"evil{RLM}gpj 12 2020", f"{LRM}1.2.3 4:56 evil", f"{LRM}9/{LRM}17/{LRM}2020 9:43 evil",
    f"cmd /c echo {RLM}x: {LRM}9/{LRM}17/{LRM}2020 9:43 AM", f"Target: CORP\\admin{RLM} 12 2024",
])
def test_bidi_marks_stay_in_text_that_is_not_a_windows_date(text):
    from glessner.parsers.evtxecmd import _unmarked_date

    assert _unmarked_date(text) == text


@pytest.mark.parametrize(("text", "shown"), [
    (f"{LRM}17.{LRM}09.{LRM}2020 09:43", "17.09.2020 09:43"),
    (f"{LRM}2020-{LRM}09-{LRM}17", "2020-09-17"),
    (f"{LRM}2 {LRM}September {LRM}2020", "2 September 2020"),
    (f"{LRM}Mittwoch, {LRM}2. {LRM}September {LRM}2020 18:21:26", "Mittwoch, 2. September 2020 18:21:26"),
    (f"{RLM}9/{RLM}17/{RLM}2020 9:43 p.m.", "9/17/2020 9:43 p.m."),
])
def test_bidi_marks_leave_each_form_of_a_windows_date(text, shown):
    from glessner.parsers.evtxecmd import _unmarked_date

    assert _unmarked_date(text) == shown


CRAFTED = f"{LRM}Mallory {LRM}12 {LRM}2024"   # a name built in the shape of a marked date
DATED_FOLDER = f"{LRM}2020-{LRM}09-{LRM}17"


RUN_DATE = f"{RLM}9/{RLM}17/{RLM}2020 9:43 p.m."


@pytest.mark.parametrize(("part", "shown"), [
    (f"LastRunDateTime: {RUN_DATE}", "LastRunDateTime: 9/17/2020 9:43 p.m."),
    (RUN_DATE, "9/17/2020 9:43 p.m."),
    (f"Time: {CRAFTED}", f"Time: {CRAFTED}"),
    (f"Object: {DATED_FOLDER}", f"Object: {DATED_FOLDER}"),
    (f"LastRunDateTime: {RUN_DATE} evil", f"LastRunDateTime: {RUN_DATE} evil"),
    (f"cmd /c echo {RUN_DATE}", f"cmd /c echo {RUN_DATE}"),
])
def test_a_map_part_loses_only_the_marks_a_payload_value_lost(part, shown):
    """A map part loses marks only where the whole part, or its value after the label, is a payload value that lost
    them, so text that reads like a label, as a command line can, keeps its marks."""
    from glessner.parsers.evtxecmd import _unmarked_part

    assert _unmarked_part(part, {RUN_DATE: "9/17/2020 9:43 p.m."}) == shown


def test_a_message_part_keeps_marks_that_a_field_with_its_value_keeps(tmp_path):
    """When a field that keeps its marks holds the same text as a date field that lost them, the message keeps the
    marks in that text, so it never shows a value without marks that a field still has."""
    run_date = f"{LRM}9/{LRM}17/{LRM}2020 9:43 AM"
    write_csv(tmp_path / "evtxecmd.csv", [*EVTX_COLUMNS, "RenderingInfo"], [
        {**system_row(1, 800, "Task Scheduler service", {"LastRunDateTime": run_date, "TaskName": run_date}),
         "Provider": "Microsoft-Windows-TaskScheduler", "PayloadData1": f"TaskName: {run_date}"},
    ])
    (task,) = PARSERS["evtxecmd_csv"](ParseContext(tmp_path, EVIDENCE))
    assert task.extra == {"LastRunDateTime": "9/17/2020 9:43 AM", "TaskName": run_date}
    assert task.message == f"800 Task Scheduler service | TaskName: {run_date}"


def xml_reader_row(record, code, provider, *unnamed, **named):
    """A row as the built-in XML reader writes one, for an event with its unnamed values first, then its named ones."""
    data = "".join(f"<Data>{v}</Data>" for v in unnamed) + "".join(f'<Data Name="{k}">{v}</Data>'
                                                                  for k, v in named.items())
    xml = (f'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="{provider}"/>'
           f"<EventID>{code}</EventID><EventRecordID>{record}</EventRecordID><Channel>System</Channel>"
           f"<Computer>LAB</Computer></System><EventData>{data}</EventData></Event>")
    return row_for(ElementTree.fromstring(xml), "D:\\Evidence\\case\\LAB\\System.evtx")


def test_bidi_marks_leave_a_date_written_with_right_to_left_marks_as_characters(tmp_path):
    """EvtxECmd writes the marks as characters. CAPI2's unnamed data is a date in its 4111 to 4113."""
    run_date = f"{RLM}9/{RLM}17/{RLM}2020 9:43 PM"
    long_date = f"{RLM}Wednesday, {RLM}September {RLM}2, {RLM}2020 6:21:26 PM"
    task_payload = {"EventData": {"Data": [{"@Name": "LastRunDateTime", "#text": run_date}]}}
    write_csv(tmp_path / "evtxecmd.csv", [*EVTX_COLUMNS, "RenderingInfo"], [
        {**system_row(1, 800, "Task Scheduler service", {}), "Provider": "Microsoft-Windows-TaskScheduler",
         "Payload": json.dumps(task_payload, ensure_ascii=False)},
        {**system_row(2, 4112, "", {}), "Provider": "Microsoft-Windows-CAPI2",
         "Payload": json.dumps({"EventData": {"Data": long_date}}, ensure_ascii=False)},
    ])
    task, capi = PARSERS["evtxecmd_csv"](ParseContext(tmp_path, EVIDENCE))
    assert RLM in (tmp_path / "evtxecmd.csv").read_text(encoding="utf-8-sig")
    assert task.extra["LastRunDateTime"] == "9/17/2020 9:43 PM"
    assert capi.extra == {"Data": "Wednesday, September 2, 2020 6:21:26 PM"} and RLM not in capi.message


def test_bidi_marks_leave_a_field_whose_name_holds_date_or_time_in_that_case(tmp_path):
    """A name holding Date or Time, with those capitals, marks a field that can hold a date: DriverDate and StartTime
    lose their marks, and updateTitle and Runtime keep them."""
    run_date = f"{LRM}9/{LRM}17/{LRM}2020 9:43 AM"
    write_csv(tmp_path / "evtxecmd.csv", [*EVTX_COLUMNS, "RenderingInfo"], [
        system_row(1, 7000, "Service start failed",
                   {"DriverDate": run_date, "StartTime": run_date, "updateTitle": run_date, "Runtime": run_date}),
    ])
    (event,) = PARSERS["evtxecmd_csv"](ParseContext(tmp_path, EVIDENCE))
    assert event.extra == {"DriverDate": "9/17/2020 9:43 AM", "StartTime": "9/17/2020 9:43 AM",
                           "updateTitle": run_date, "Runtime": run_date}


def test_bidi_marks_leave_unnamed_dates_in_the_xml_readers_rows(tmp_path):
    """The built-in XML reader numbers unnamed values Data1 to DataN, so CAPI2's date and the date of EventLog's 6008,
    an unexpected shutdown, lose their marks there too. A command line keeps them, label-like text and all."""
    long_date = f"{RLM}Wednesday, {RLM}September {RLM}2, {RLM}2020 6:21:26 PM"
    rows = [
        xml_reader_row(1, 4111, "Microsoft-Windows-CAPI2", long_date),
        xml_reader_row(2, 6008, "EventLog", "PM 3:32:54", DATED_FOLDER, "", "", "520643"),
        xml_reader_row(3, 4688, "Microsoft-Windows-Security-Auditing", NewProcessName="C:\\Windows\\System32\\cmd.exe",
                       CommandLine=f"cmd Time: {CRAFTED}"),
    ]
    write_csv(tmp_path / "event_xml.csv", list(rows[0]), rows)
    capi, shutdown, created = PARSERS["event_xml_csv"](ParseContext(tmp_path, EVIDENCE))
    assert capi.extra == {"Data1": "Wednesday, September 2, 2020 6:21:26 PM"} and RLM not in capi.message
    assert shutdown.extra["Data2"] == "2020-09-17" and LRM not in shutdown.message
    assert created.process_command_line == f"cmd Time: {CRAFTED}" and f"cmd Time: {CRAFTED}" in created.message


def test_bidi_marks_stay_in_a_date_shaped_value_whose_field_names_no_date(tmp_path):
    """An account, a service, a folder, registry data, a rule name, or a command line can take the shape of a marked
    date, or read like a labeled one, to disguise itself. A field keeps its marks unless its name holds Date or Time,
    or it is the unnamed data of CAPI2 or EventLog, and then only a marked date loses them; a message part keeps them
    unless its value is one that lost them."""
    run_date = f"{LRM}9/{LRM}17/{LRM}2020 9:43 AM"
    capi2 = "Microsoft-Windows-CAPI2"
    write_csv(tmp_path / "evtxecmd.csv", [*EVTX_COLUMNS, "RenderingInfo"], [
        security_row(1, 4624, "Successful logon",
                     {"TargetUserName": CRAFTED, "TargetDomainName": "CORP", "LogonType": "3"},
                     PayloadData1=f"Target: {CRAFTED}"),
        system_row(2, 7045, "A service was installed in the system", {"ServiceName": CRAFTED, "ImagePath": "cmd.exe"}),
        security_row(3, 5145, "Network share object access",
                     {**SHARE_FIELDS, "ShareName": "\\\\*\\C$", "ShareLocalPath": "\\??\\C:\\",
                      "RelativeTargetName": DATED_FOLDER},
                     PayloadData2=f"Object: {DATED_FOLDER}"),
        sysmon_row(4, 13, "Registry value set",
                   {"RuleName": CRAFTED, "TargetObject": "HKLM\\Software\\Example\\When", "Details": DATED_FOLDER}),
        {**system_row(5, 4111, "", {}), "Payload": json.dumps({"EventData": {"Data": run_date}}, ensure_ascii=False)},
        sysmon_row(6, 1, "Process creation", {"UtcTime": run_date, "CommandLine": f"Time: {CRAFTED}"},
                   ExecutableInfo=f"Time: {CRAFTED}"),
        {**system_row(7, 400, "Engine state changed", {"HostApplication": f"powershell Time: {CRAFTED}"}),
         "Provider": "PowerShell", "Channel": "Windows PowerShell", "PayloadData1": f"powershell Time: {CRAFTED}"},
        {**system_row(8, 800, "Task Scheduler service", {"LastRunDateTime": f"{CRAFTED} evil"}),
         "Provider": "Microsoft-Windows-TaskScheduler"},
        {**system_row(9, 4111, "", {}), "Provider": capi2,
         "Payload": json.dumps({"EventData": {"Data": f"{LRM}1.2.3"}}, ensure_ascii=False)},
        {**system_row(10, 4111, "", {"Subject": CRAFTED}), "Provider": capi2},
    ])
    (logon, service, share, registry, unnamed, process, engine, task, capi_version,
     capi_named) = PARSERS["evtxecmd_csv"](ParseContext(tmp_path, EVIDENCE))
    assert logon.user_name == CRAFTED and logon.extra["TargetUserName"] == CRAFTED
    assert f"Target: {CRAFTED}" in logon.message
    assert service.extra["ServiceName"] == CRAFTED
    assert share.file_path == f"C:\\{DATED_FOLDER}" and DATED_FOLDER in share.file_key
    assert share.extra["RelativeTargetName"] == DATED_FOLDER and f"Object: {DATED_FOLDER}" in share.message
    assert registry.registry_data == DATED_FOLDER and registry.extra["RuleName"] == CRAFTED
    assert unnamed.extra == {"Data": run_date}   # unnamed data from a provider other than CAPI2 or EventLog
    assert process.extra["UtcTime"] == "9/17/2020 9:43 AM" and f"Time: {CRAFTED}" in process.message
    assert process.process_command_line == f"Time: {CRAFTED}"
    assert f"powershell Time: {CRAFTED}" in engine.message
    assert task.extra["LastRunDateTime"] == f"{CRAFTED} evil"
    assert capi_version.extra == {"Data": f"{LRM}1.2.3"} and capi_named.extra == {"Subject": CRAFTED}
