"""The built-in Windows event XML reader: identification, conversion, and a run."""

import csv
import json

from conftest import links_in

from glessner.analysis import build_identity, build_tables
from glessner.case import create_case
from glessner.event_xml import OUTPUT_FILE, convert, main
from glessner.events import connect
from glessner.identify import identify_bytes
from glessner.intake import intake
from glessner.journal import Journal
from glessner.parsers import PARSERS, ParseContext
from glessner.runner import plan_runs, run
from glessner.tools import detect, load_registry

NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def event(code, record, computer, data, provider="Microsoft-Windows-Security-Auditing", channel="Security",
          time="2024-05-14T12:00:35.6620140Z", extra=""):
    fields = "".join(f'<Data Name="{k}">{v}</Data>' for k, v in data.items())
    return (f'<Event xmlns="{NS}"><System><Provider Name="{provider}"/><EventID>{code}</EventID>'
            f'<TimeCreated SystemTime="{time}"/><EventRecordID>{record}</EventRecordID><Channel>{channel}</Channel>'
            f'<Computer>{computer}</Computer><Security/></System><EventData>{fields}</EventData>{extra}</Event>')


def rdp_logon(record, computer, ip, user="nina.kapoor"):
    return event("4624", record, computer, {"TargetUserName": user, "TargetDomainName": "NORTHSTAR", "LogonType": "10",
                                            "IpAddress": ip, "IpPort": "50123", "WorkstationName": "-",
                                            "TargetLogonId": "0x3e7"})


def events_file(*events, declaration=True):
    head = '<?xml version="1.0" encoding="utf-8"?>\n' if declaration else ""
    return head + "<Events>\n" + "\n".join(events) + "\n</Events>\n"


def rows(folder):
    with (folder / OUTPUT_FILE).open(encoding="utf-8") as f:
        return list(csv.DictReader(f))


def test_identified_by_namespace_and_event_element_in_utf8_and_utf16():
    xml = events_file(rdp_logon(1, "WS-01", "10.0.0.5"))
    assert identify_bytes("windows_event_security.xml", xml.encode()).artifact == "event_xml"
    assert identify_bytes("bare.xml", rdp_logon(1, "WS-01", "10.0.0.5").encode()).artifact == "event_xml"   # wevtutil
    assert identify_bytes("viewer.xml", b"\xff\xfe" + xml.encode("utf-16-le")).artifact == "event_xml"
    assert identify_bytes("events.txt", xml.encode()).artifact != "event_xml"   # the name has to say XML
    other = '<?xml version="1.0"?><configuration><Event name="x"/></configuration>'
    assert identify_bytes("app.config.xml", other.encode()).artifact != "event_xml"


def test_intake_takes_as_event_xml_only_what_the_reader_decodes(tmp_path):
    """UTF-16 without a byte order mark is event XML only when the text starts with '<', the rule the reader applies. A
    file starting with a line break is not taken as event XML, so its run can't fail with "not well-formed". Intake and
    the reader both use identify.text_encoding."""
    xml = events_file(rdp_logon(1, "WS-01", "10.0.0.5"), declaration=False)
    out = tmp_path / "out"
    out.mkdir()
    for name, data, readable in (("le.xml", xml.encode("utf-16-le"), True), ("be.xml", xml.encode("utf-16-be"), True),
                                 ("break.xml", ("\r\n" + xml).encode("utf-16-le"), False)):
        assert (identify_bytes(name, data).artifact == "event_xml") is readable, name
        (tmp_path / name).write_bytes(data)
        if readable:
            assert convert([tmp_path / name], out) == 1


def test_events_convert_with_the_fields_event_logs_have(tmp_path):
    sysmon = event("3", 77, "WS-01.corp.local", {"Image": "C:\\Windows\\System32\\svchost.exe", "User": "CORP\\nina",
                                                 "SourceIp": "10.0.0.5", "SourcePort": "53712",
                                                 "DestinationIp": "10.0.0.10", "DestinationPort": "53"},
                   provider="Microsoft-Windows-Sysmon", channel="Microsoft-Windows-Sysmon/Operational")
    source = tmp_path / "evidence" / "WS-01" / "events.xml"
    source.parent.mkdir(parents=True)
    source.write_text(events_file(rdp_logon(5, "WS-01.corp.local", "10.0.0.9"), sysmon), encoding="utf-8")
    out = tmp_path / "out"
    out.mkdir()
    assert convert([source], out) == 2
    first = rows(out)[0]
    assert (first["EventId"], first["MapDescription"], first["PayloadData1"], first["PayloadData2"]) == (
        "4624", "Successful logon", "Target: NORTHSTAR\\nina.kapoor", "LogonType 10, from 10.0.0.9:50123")

    logon, conn = PARSERS["event_xml_csv"](ParseContext(out, tmp_path / "evidence"))
    assert (logon.artifact, logon.source_file, logon.source_record, logon.host_name_recorded) == (
        "evtx", "WS-01/events.xml", "5", "WS-01.corp.local")
    assert (logon.user_domain, logon.user_name, logon.logon_type, logon.source_ip, logon.source_port) == (
        "NORTHSTAR", "nina.kapoor", "10", "10.0.0.9", "50123")
    assert logon.message == "4624 Successful logon | Target: NORTHSTAR\\nina.kapoor | LogonType 10, from 10.0.0.9:50123"
    assert (conn.source_ip, conn.dest_ip, conn.dest_port, conn.user_name, conn.log_channel) == (
        "10.0.0.5", "10.0.0.10", "53", "nina", "Microsoft-Windows-Sysmon/Operational")
    assert conn.process_executable == "C:\\Windows\\System32\\svchost.exe"


def test_bare_events_utf16_userdata_unnamed_data_and_rendered_messages(tmp_path):
    user_data = event("1149", 9, "SRV", {}, provider="Microsoft-Windows-TerminalServices-RemoteConnectionManager",
                      channel="RCM/Operational").replace(
        "<EventData></EventData>", "<UserData><EventXML><Param1>admin</Param1><Param2>CORP</Param2>"
                                   "<Param3>10.0.0.7</Param3></EventXML></UserData>")
    unnamed = event("7036", 10, "SRV", {}, provider="Service Control Manager", channel="System",
                    extra="<RenderingInfo><Message>The Print Spooler service entered the stopped state.\nMore"
                          "</Message></RenderingInfo>").replace("<EventData></EventData>",
                                                                "<EventData><Data>Print Spooler</Data></EventData>")
    bare = tmp_path / "bare.xml"
    bare.write_text(user_data + "\n" + unnamed, encoding="utf-8")   # wevtutil writes events without a root
    wide = tmp_path / "wide.xml"
    wide.write_bytes(b"\xff\xfe" + events_file(rdp_logon(3, "SRV", "10.0.0.8")).replace(
        'encoding="utf-8"', 'encoding="UTF-16"').encode("utf-16-le"))
    out = tmp_path / "out"
    out.mkdir()
    assert convert([bare, wide], out) == 3
    rdp, service, logon = rows(out)
    assert json.loads(rdp["Payload"])["UserData"]["EventXML"]["Param3"] == "10.0.0.7"
    (ev,) = [e for e in PARSERS["event_xml_csv"](ParseContext(out, tmp_path)) if e.event_code == "1149"]
    assert (ev.user_name, ev.user_domain, ev.source_ip) == ("admin", "CORP", "10.0.0.7")
    assert service["MapDescription"] == "The Print Spooler service entered the stopped state."
    assert json.loads(service["Payload"])["EventData"]["Data"] == [{"@Name": "Data1", "#text": "Print Spooler"}]
    assert logon["SourceFile"] == str(wide) and logon["PayloadData2"] == "LogonType 10, from 10.0.0.8:50123"


def test_decoded_text_stays_as_written_and_the_parent_leads_the_message(tmp_path):
    """The XML parser has already decoded the reader's text, so an entity the event's own text holds stays, as in
    EvtxECmd's rows, which are unescaped once. A process's parent leads its message."""
    shell = event("1", 3, "WS-01", {"Image": "C:\\Windows\\System32\\cmd.exe", "CommandLine": "echo &amp;lt;b&amp;gt; &gt; x",
                                    "ParentImage": "C:\\Windows\\System32\\inetsrv\\w3wp.exe", "User": "CORP\\iis"},
                  provider="Microsoft-Windows-Sysmon", channel="Microsoft-Windows-Sysmon/Operational")
    calc = event("4688", 4, "WS-01", {"NewProcessName": "C:\\Windows\\System32\\calc.exe", "SubjectUserName": "nina",
                                      "ParentProcessName": "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe"})
    source = tmp_path / "evidence" / "WS-01" / "events.xml"
    source.parent.mkdir(parents=True)
    source.write_text(events_file(shell, calc), encoding="utf-8")
    out = tmp_path / "out"
    out.mkdir()
    convert([source], out)
    proc, created = PARSERS["event_xml_csv"](ParseContext(out, tmp_path / "evidence"))
    assert proc.process_command_line == "echo &lt;b&gt; > x" and proc.extra["CommandLine"] == "echo &lt;b&gt; > x"
    assert proc.message == "1 Process creation | parent w3wp.exe | User: CORP\\iis | echo &lt;b&gt; > x"
    assert proc.process_parent_executable == "C:\\Windows\\System32\\inetsrv\\w3wp.exe"
    assert created.message == "4688 Process created | parent WmiPrvSE.exe | Subject: nina | C:\\Windows\\System32\\calc.exe"


def test_unreadable_xml_fails_the_run_and_names_the_file(tmp_path, capsys):
    good, bad, doctype = tmp_path / "good.xml", tmp_path / "bad.xml", tmp_path / "doctype.xml"
    good.write_text(events_file(rdp_logon(1, "SRV", "10.0.0.8")), encoding="utf-8")
    bad.write_text(events_file(rdp_logon(2, "SRV", "10.0.0.8"))[:-30], encoding="utf-8")   # cut off mid-event
    doctype.write_text('<!DOCTYPE x [<!ENTITY a "aaaa">]>' + events_file(declaration=False), encoding="utf-8")
    for broken in (bad, doctype):
        listing = tmp_path / "inputs.txt"
        listing.write_text(f"{good}\n{broken}\n", encoding="utf-8")
        out = tmp_path / f"out_{broken.stem}"
        out.mkdir()
        assert main([str(listing), str(out)]) == 3
        assert str(broken) in capsys.readouterr().err


def test_runs_like_a_tool_and_feeds_host_names_and_logon_links(tmp_path):
    evidence = tmp_path / "evidence"
    for host, computer, peer, peer_ip in (("DC-01", "DC-01.corp.local", "WS-01", "10.0.0.5"),
                                          ("WS-01", "WS-01.corp.local", "DC-01", "10.0.0.10")):
        (evidence / host).mkdir(parents=True)
        (evidence / host / "security.xml").write_text(events_file(
            event("4624", 1, computer, {"TargetUserName": f"{peer}$", "TargetDomainName": "CORP", "LogonType": "3",
                                        "IpAddress": "-", "WorkstationName": peer}),
            rdp_logon(2, computer, peer_ip, user="admin")), encoding="utf-8")
    (evidence / "WS-01" / "notes.xml").write_text("<notes>not events</notes>", encoding="utf-8")
    case = create_case(tmp_path / "case", "XML", evidence, "cody")
    intake(case)
    tool = detect([load_registry()["event_xml"]], None)["event_xml"]
    plans = plan_runs(case, tool)
    assert [(p.host, p.inputs) for p in plans] == [("DC-01", ("DC-01/security.xml",)), ("WS-01", ("WS-01/security.xml",))]
    for plan in plans:
        record = run(case, plan)
        assert (record.status, record.loaded_rows, record.evidence_check) == ("ok", 2, "ok")
        listed = (case.runs_folder / record.run_id / "inputs.txt").read_text(encoding="utf-8")
        assert listed == f"{evidence / plan.host / 'security.xml'}\n"   # exactly the run's inputs: not notes.xml
        assert record.argv[1:4] == ["-I", "-m", "glessner.event_xml"]

    con = connect(case.db_path)
    journal = Journal(case)
    identity = build_identity(con, journal.state)
    build_tables(con, journal.state, identity)
    assert identity.hosts["WS-01"].names == ["WS-01"] and identity.resolve_name("dc-01.corp.local") == "DC-01"
    # Host IPs come from the registry, which this case lacks, so the RDP logons' sources stay as IPs.
    links = {(link.source, link.target, link.kind, link.via) for link in links_in(con, 0, 2**62)}
    assert links == {("WS-01", "DC-01", "4624 type 3", "name"), ("10.0.0.5", "DC-01", "4624 type 10", "ip"),
                     ("DC-01", "WS-01", "4624 type 3", "name"), ("10.0.0.10", "WS-01", "4624 type 10", "ip")}


def test_error_data_system_userid_and_sysmon_direction(tmp_path):
    """Through the XML reader: WinRM's ProcessingErrorData, read as text, and its System UserID as the account; a Sysmon
    connection's direction, without an arrow Sysmon's labels don't support, worded as the EvtxECmd parser words it."""
    sid = "S-1-5-21-3623811015-3361044348-30300820-1013"
    uri = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd"
    hexed = "".join(f"{b:02X}" for b in (uri + "\0").encode("utf-16-le"))
    winrm = (f'<Event xmlns="{NS}"><System><Provider Name="Microsoft-Windows-WinRM"/><EventID>91</EventID>'
             '<TimeCreated SystemTime="2024-05-14T12:00:35.6620140Z"/><EventRecordID>5</EventRecordID>'
             f'<Channel>Microsoft-Windows-WinRM/Operational</Channel><Computer>WS-01</Computer>'
             f'<Security UserID="{sid}"/></System><ProcessingErrorData><ErrorCode>15005</ErrorCode>'
             f'<DataItemName>shellId</DataItemName><EventPayload>{hexed}</EventPayload></ProcessingErrorData></Event>')
    inbound = event("3", 6, "WS-01", {"Image": "System", "Initiated": "false", "SourceIp": "10.0.2.15",
                                      "SourcePort": "445", "DestinationIp": "10.0.2.17", "DestinationPort": "52000"},
                    provider="Microsoft-Windows-Sysmon", channel="Microsoft-Windows-Sysmon/Operational")
    outbound = event("3", 7, "WS-01", {"Initiated": "true", "SourceIp": "fe80::1", "SourcePort": "49712",
                                       "DestinationIp": "fe80::2", "DestinationPort": "443"},
                     provider="Microsoft-Windows-Sysmon", channel="Microsoft-Windows-Sysmon/Operational")
    source = tmp_path / "events.xml"
    source.write_text(events_file(winrm, inbound, outbound), encoding="utf-8")
    out = tmp_path / "out"
    out.mkdir()
    convert([source], out)
    shell, conn, v6 = PARSERS["event_xml_csv"](ParseContext(out, tmp_path))
    assert v6.message == "3 Network connection | outbound | Source: [fe80::1]:49712 | Destination: [fe80::2]:443"
    assert (shell.user_name, shell.extra["EventPayloadText"], shell.extra["DataItemName"]) == (sid, uri, "shellId")
    assert shell.message == f"91 Microsoft-Windows-WinRM | ErrorCode: 15005 | DataItemName: shellId | EventPayloadText: {uri}"
    assert conn.message == "3 Network connection | inbound | Source: 10.0.2.15:445 | Destination: 10.0.2.17:52000 | System"
    assert (conn.source_ip, conn.dest_ip) == ("10.0.2.15", "10.0.2.17")


def test_a_sysmon_connection_reads_alike_from_either_reader(tmp_path):
    """A Sysmon 3 reads the same from either reader, so a search for "inbound | Source" finds both: each leads with the
    direction and the ends, as the EvtxECmd parser words them, and the reader's account follows."""
    from test_parsers import EVTX_COLUMNS, sysmon_row, write_csv

    data = {"Image": "System", "User": "NT AUTHORITY\\SYSTEM", "Initiated": "false", "SourceIp": "10.0.2.15",
            "SourcePort": "445", "DestinationIp": "10.0.2.17", "DestinationPort": "52000"}
    source = tmp_path / "events.xml"
    source.write_text(events_file(event("3", 6, "LAB", data, provider="Microsoft-Windows-Sysmon",
                                        channel="Microsoft-Windows-Sysmon/Operational")), encoding="utf-8")
    xml_out, csv_out = tmp_path / "xml", tmp_path / "csv"
    xml_out.mkdir()
    csv_out.mkdir()
    convert([source], xml_out)
    (from_xml,) = PARSERS["event_xml_csv"](ParseContext(xml_out, tmp_path))
    write_csv(csv_out / "evtxecmd.csv", EVTX_COLUMNS, [sysmon_row(6, 3, "Network connection", data, ExecutableInfo="System")])
    (from_csv,) = PARSERS["evtxecmd_csv"](ParseContext(csv_out, tmp_path))
    lead = "3 Network connection | inbound | Source: 10.0.2.15:445 | Destination: 10.0.2.17:52000 | "
    assert (from_xml.message, from_csv.message) == (lead + "User: NT AUTHORITY\\SYSTEM | System", lead + "System")
    assert rows(xml_out)[0]["PayloadData2"] == ""   # the reader's detail leaves the ends to the parser

    # A run stored by an earlier reader holds the ends in the reader's detail too, and a rebuild or a case copy parses
    # that stored output again without running the reader, so the parser words the detail from the fields.
    (old,) = rows(xml_out)
    old["PayloadData2"] = "inbound, Source: 10.0.2.15:445, Destination: 10.0.2.17:52000"   # as the reader wrote it
    with (xml_out / OUTPUT_FILE).open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(old))
        writer.writeheader()
        writer.writerow(old)
    (rebuilt,) = PARSERS["event_xml_csv"](ParseContext(xml_out, tmp_path))
    assert rebuilt.message == from_xml.message
