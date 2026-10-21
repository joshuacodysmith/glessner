"""Synthetic records for the parser fields the Event page shows: a 4688 whose target logon is 0x0, a failed logon, RDP
session events, a Defender detection, object access, an NTLM validation, a group change, and Suricata records with IPv6
addresses. Built the way tests/test_parsers.py builds EvtxECmd rows and tests/test_suricata.py builds EVE, so the ID test
can run the same records through the parsers and compare the event IDs they give."""

import csv
import json
from pathlib import Path

from glessner.events import event_uid
from glessner.parsers import PARSERS, ParseContext

EVIDENCE = Path("D:/Evidence/case")
HOST = "FIXTURE"
EVTX_COLUMNS = ["RecordNumber", "EventRecordId", "TimeCreated", "EventId", "Level", "Provider", "Channel", "ProcessId",
                "ThreadId", "Computer", "ChunkNumber", "UserId", "MapDescription", "UserName", "RemoteHost",
                "PayloadData1", "PayloadData2", "PayloadData3", "PayloadData4", "PayloadData5", "PayloadData6",
                "ExecutableInfo", "HiddenRecord", "SourceFile", "Keywords", "ExtraDataOffset", "Payload"]
SECURITY, DEFENDER = "Security", "Microsoft-Windows-Windows Defender/Operational"
LSM = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"
LOG = "D:\\Evidence\\case\\FIXTURE\\Windows\\System32\\winevt\\Logs\\{}.evtx"


def event_data(**fields):
    return json.dumps({"EventData": {"Data": [{"@Name": k, "#text": v} for k, v in fields.items()]}})


def user_data(**fields):
    return json.dumps({"UserData": {"EventXML": {"@xmlns": "x", **fields}}})


def row(record, code, channel, payload, when="2020-09-19 03:21:48.0000000"):
    return {"EventRecordId": str(record), "TimeCreated": when, "EventId": code, "Channel": channel,
            "Computer": "FIXTURE.C137.local", "SourceFile": LOG.format(channel.split("/")[0].replace("Microsoft-Windows-", "")),
            "Payload": payload}


# Each record's name says the parser behavior it exercises.
EVTX_ROWS = {
    # Windows 10 writes TargetLogonId 0x0 when the creator and target share a logon; the session is the Subject's
    "4688 shared logon": row(1, "4688", SECURITY, event_data(
        SubjectUserName="WIN-1$", SubjectDomainName="C137", SubjectLogonId="0x3E7", NewProcessName="C:\\Windows\\a.exe",
        TargetUserName="-", TargetLogonId="0x0")),
    "4688 own logon": row(2, "4688", SECURITY, event_data(
        SubjectUserName="alice", SubjectDomainName="C137", SubjectLogonId="0x1111", TargetUserName="bob",
        TargetDomainName="C137", TargetLogonId="0x2222", NewProcessName="C:\\Windows\\b.exe")),
    "4688 empty target": row(3, "4688", SECURITY, event_data(
        SubjectUserName="alice", SubjectDomainName="C137", SubjectLogonId="0x1111", TargetLogonId="",
        NewProcessName="C:\\Windows\\c.exe")),
    "4625 no logon": row(4, "4625", SECURITY, event_data(
        SubjectUserName="WIN-1$", SubjectDomainName="C137", SubjectLogonId="0x0", TargetUserName="admin",
        TargetDomainName="C137", TargetLogonId="0x0", IpAddress="203.0.113.7", LogonType="3")),
    "4624 hex digits": row(5, "4624", SECURITY, event_data(
        TargetUserName="alice", TargetDomainName="C137", TargetLogonId="0x6c0b6d", LogonType="3", IpAddress="10.0.0.9")),
    # RDP session events, from the Security log and the Terminal Services session manager log
    "4778 reconnect": row(6, "4778", SECURITY, event_data(
        AccountName="Administrator", AccountDomain="C137", LogonID="0x510986", SessionName="RDP-Tcp#2",
        ClientName="KALI", ClientAddress="194.61.24.102")),
    "4779 disconnect": row(7, "4779", SECURITY, event_data(
        AccountName="Administrator", AccountDomain="C137", LogonID="0x510986", SessionName="RDP-Tcp#2",
        ClientName="KALI", ClientAddress="LOCAL")),
    "LSM 21": row(8, "21", LSM, user_data(User="C137\\Administrator", SessionID="2", Address="194.61.24.102")),
    "LSM 24 local": row(9, "24", LSM, user_data(User="C137\\Administrator", SessionID="2", Address="LOCAL")),
    # Defender detections, object access, and an NTLM validation
    "Defender 1116": row(10, "1116", DEFENDER, event_data(**{
        "Product Name": "Microsoft Defender Antivirus", "Threat Name": "Trojan:Win32/Bad",
        "Process Name": "C:\\Windows\\Explorer.EXE", "Detection User": "C137\\Administrator",
        "Path": "file:_C:\\Users\\Public\\coreupdater.exe"})),
    "Defender 1117 container": row(11, "1117", DEFENDER, event_data(**{
        "Process Name": "Unknown", "Detection User": "NT AUTHORITY\\SYSTEM",
        "Path": "containerfile:_C:\\x\\a.zip; file:_C:\\x\\a.zip->b.exe; webfile:_C:\\x\\a.zip|http://e.example/a.zip"})),
    "4663 file": row(12, "4663", SECURITY, event_data(
        SubjectUserName="alice", SubjectDomainName="C137", SubjectLogonId="0x1111", ObjectType="File",
        ObjectName="C:\\Data\\secret.docx", ProcessName="C:\\Windows\\explorer.exe", AccessList="%%4416")),
    "4663 key": row(13, "4663", SECURITY, event_data(
        SubjectUserName="alice", SubjectDomainName="C137", SubjectLogonId="0x1111", ObjectType="Key",
        ObjectName="\\REGISTRY\\MACHINE\\SOFTWARE\\x", ProcessName="C:\\Windows\\regedit.exe")),
    "4776 workstation": row(14, "4776", SECURITY, event_data(
        PackageName="MICROSOFT_AUTHENTICATION_PACKAGE_V1_0", TargetUserName="Administrator", Workstation="KALI",
        Status="0x0")),
    # A group membership change and an account creation
    "4732 group": row(15, "4732", SECURITY, event_data(
        MemberName="-", MemberSid="S-1-5-21-1-2-3-1105", TargetUserName="Administrators", TargetDomainName="Builtin",
        TargetSid="S-1-5-32-544", SubjectUserSid="S-1-5-21-1-2-3-500", SubjectUserName="Administrator",
        SubjectDomainName="C137", SubjectLogonId="0x510986", PrivilegeList="-")),
    "4720 account": row(16, "4720", SECURITY, event_data(
        TargetUserName="newuser", TargetDomainName="C137", SubjectUserName="Administrator", SubjectDomainName="C137",
        SubjectLogonId="0x510986")),
}

EVE_RECORDS = [
    {"timestamp": "2020-09-19T03:21:49.000000+0000", "event_type": "alert", "flow_id": 11,
     "src_ip": "fe80:0000:0000:0000:2dcf:e660:be73:d220", "src_port": 546,
     "dest_ip": "ff02:0000:0000:0000:0000:0000:0001:0002", "dest_port": 547, "proto": "UDP",
     "alert": {"signature_id": 2000001, "signature": "TEST v6 alert", "category": "Test", "severity": 2}},
    {"timestamp": "2020-09-19T03:21:50.000000+0000", "event_type": "dns", "flow_id": 12,
     "src_ip": "::ffff:10.0.0.5", "src_port": 5353, "dest_ip": "2001:0DB8:0000:0000:0000:0000:0000:0001", "dest_port": 53,
     "proto": "UDP", "dns": {"type": "request", "queries": [{"rrname": "x.example", "rrtype": "AAAA"}]}},
    {"timestamp": "2020-09-19T03:21:51.000000+0000", "event_type": "flow", "flow_id": 13, "src_ip": "10.0.0.5",
     "src_port": 49200, "dest_ip": "10.0.0.1", "dest_port": 445, "proto": "TCP",
     "flow": {"start": "2020-09-19T03:21:47.000000+0000"}},
]


def write_csv(path, rows):
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=EVTX_COLUMNS)
        writer.writeheader()
        for r in rows:
            writer.writerow({c: r.get(c, "") for c in EVTX_COLUMNS})


def evtx_events(folder: Path) -> dict:
    """The EVTX_ROWS parsed by EvtxECmd's parser, by their names."""
    write_csv(folder / "evtxecmd.csv", EVTX_ROWS.values())
    return dict(zip(EVTX_ROWS, PARSERS["evtxecmd_csv"](ParseContext(folder, EVIDENCE)), strict=True))


def suricata_events(folder: Path) -> list:
    out = folder / "suricata"
    out.mkdir()
    (out / "eve.json").write_text("".join(json.dumps(r) + "\n" for r in EVE_RECORDS), encoding="utf-8")
    return list(PARSERS["suricata_eve"](ParseContext(out, EVIDENCE, ("SENSOR/capture.pcap",))))


def ids(events) -> list[str]:
    """Each event's ID as events.load gives it, for a collection host HOST."""
    return [event_uid(HOST, e.artifact, e.source_file, e.source_record, e.ts_desc) for e in events]
