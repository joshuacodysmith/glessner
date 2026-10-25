"""Importing text logs (CSV, JSON lines, W3C, key=value) as runs."""

import json

import duckdb
import pytest
from chain_fixtures import format3_case
from conftest import nested_list

from glessner.case import create_case, open_case
from glessner.events import connect
from glessner.imports import (
    MappingError,
    Stats,
    _flat,
    guess_mapping,
    guess_time_format,
    importable,
    preview,
    records,
    run_import,
    save_mapping,
    sniff,
)
from glessner.intake import add_new, intake, read_manifest, sha256_file
from glessner.rekey import upgraded
from glessner.runner import read_runs, rebuild
from glessner.timezones import ZoneClock, ZoneError, parse_time, resolve_zone

US = 1_000_000
FIREWALL_LOG = (
    "#Version: 1.5\r\n#Software: Microsoft Windows Firewall\r\n#Time Format: Local\r\n"
    "#Fields: date time action protocol src-ip dst-ip src-port dst-port size tcpflags tcpsyn tcpack tcpwin icmptype "
    "icmpcode info path pid\r\n\r\n"
    "2024-07-01 10:21:48 ALLOW TCP 203.0.113.9 10.0.0.12 51544 3389 0 - 0 0 0 - - - RECEIVE 1234\r\n"
    "2024-07-01 10:21:51 DROP UDP 10.0.0.12 10.0.0.255 137 137 78 - - - - - - - RECEIVE 4\r\n")
FORTI_LOG = (
    '<189>date=2023-05-25 time=00:45:16 devname="FGT60E" devid="FGT60E0000000001" eventtime=1685000716783695562 '
    'tz="-0700" logid="0000000013" type="traffic" subtype="forward" level="notice" srcip=10.100.91.100 srcport=52937 '
    'srcintf="port3" dstip=10.100.88.201 dstport=443 dstintf="port2" policyid=7 service="HTTPS" action="deny" '
    'user="alice" msg="Denied by policy"\n'
    'date=2023-05-25 time=00:45:20 devname="FGT60E" devid="FGT60E0000000001" eventtime=1685000720000000000 '
    'tz="-0700" logid="0100032001" '
    'type="event" subtype="system" logdesc="Admin login successful" user="admin" srcip=10.100.91.5\n')
SONIC_LOG = ('<134>id=firewall sn=0017C5000000 time="2024-02-05 10:21:48 UTC" fw=203.0.113.1 pri=6 c=1024 m=537 '
             'msg="Connection Closed" src=10.0.0.12:49733:X0 dst=198.51.100.4:443:X1 proto=tcp/https usr="bob"\n')


@pytest.fixture
def case(tmp_path):
    ev = tmp_path / "evidence"
    for folder in ("DC01", "FIREWALL", "SIEM"):
        (ev / folder).mkdir(parents=True)
    (ev / "DC01" / "pfirewall.log").write_bytes(FIREWALL_LOG.encode())
    (ev / "FIREWALL" / "fortigate.log").write_text(FORTI_LOG, newline="\n")
    (ev / "FIREWALL" / "sonicwall.log").write_text(SONIC_LOG, newline="\n")
    (ev / "SIEM" / "logons.csv").write_text(
        'TimeGenerated,Computer,EventID,Account,IpAddress,IpPort,Activity\n'
        '02/13/2024 10:00:00 PM,WEB01,4624,"CORP\\alice",203.0.113.9,51544,"An account was successfully logged on"\n'
        '02/14/2024 01:30:00 AM,,4625,CORP\\bob,203.0.113.9,51550,"An account failed to log on"\n', newline="\n")
    (ev / "SIEM" / "alerts.jsonl").write_text(
        '{"@timestamp": "2024-02-05T10:21:48.123Z", "host": {"name": "WEB01"}, "source": {"ip": "10.0.0.5", "port": 4444}, '
        '"destination": {"ip": "10.0.0.9", "port": 445}, "event": {"code": "3"}, "tags": ["a", "b"]}\n'
        'not json\n'
        '{"@timestamp": "2024-02-05T10:21:49+01:00", "host": {"name": "WEB02"}, "source": {"ip": "10.0.0.6"}}\n',
        newline="\n")
    (ev / "notes.csv").write_text("time,what\n2024-02-05 10:00:00Z,top level\n", newline="\n")
    c = create_case(tmp_path / "case", "Imports", ev, "cody")
    intake(c)
    return c


def test_times_in_every_supported_format():
    assert parse_time("2024-07-01T10:21:48.5Z", "ymd").us == 1719829308_500000
    assert parse_time("2024-07-01 12:21:48+02:00", "ymd").us == 1719829308 * US
    assert parse_time("2024/07/01 10:21:48", "ymd").zoned is False
    assert parse_time("07/01/2024 10:21:48 AM", "mdy").us == parse_time("01/07/2024 10:21:48", "dmy").us == 1719829308 * US
    assert parse_time("07/01/2024 12:00:00 AM", "mdy").us == parse_time("2024-07-01 00:00:00", "ymd").us
    assert [parse_time(v, "epoch").us for v in ("1719829308", "1719829308500", "1719829308500000",
                                                "1719829308500000123", "1719829308.5")] == \
        [1719829308 * US] + [1719829308_500000] * 4
    assert parse_time("01-Jul-2024 10:21:48", "%d-%b-%Y %H:%M:%S").us == 1719829308 * US
    assert parse_time("2024-02-30 10:00:00", "ymd") is None
    assert parse_time("13/13/2024", "mdy") is None


def test_time_format_guess_and_date_order():
    assert guess_time_format(["2024-07-01T10:21:48Z"]).format == "ymd"
    assert guess_time_format(["2024-07-01T10:21:48Z"]).zoned is True
    assert guess_time_format(["13/02/2024 10:00"]).format == "dmy"
    assert guess_time_format(["02/13/2024 10:00"]).format == "mdy"
    ambiguous = guess_time_format(["02/05/2024 10:00"])
    assert ambiguous.format == "" and "day/month" in ambiguous.problem
    assert guess_time_format(["1685000716783695562"]).format == "epoch"


def test_zones_resolve_and_convert():
    assert resolve_zone("", {}) is None
    assert resolve_zone("UTC", {})["kind"] == "utc"
    assert resolve_zone("-08:00", {}) == {"kind": "offset", "minutes": -480, "label": "UTC-08:00"}
    london = resolve_zone("Europe/London", {})
    summer, winter = parse_time("2024-07-01 10:00:00", "ymd").us, parse_time("2024-01-01 10:00:00", "ymd").us
    clock = ZoneClock(london)
    assert clock.to_utc(summer) == summer - 3600 * US and clock.to_utc(winter) == winter
    clock.close()
    zones = {"DC01": {"windows": "GMT Standard Time", "iana": "Europe/London", "bias_minutes": 0},
             "WS01": {"windows": "Pacific Standard Time", "iana": "", "bias_minutes": 480}}
    assert resolve_zone("host:DC01", zones)["name"] == "Europe/London"
    assert resolve_zone("host:WS01", zones)["minutes"] == -480
    for bad in ("host:NOPE", "Mars/Olympus"):
        with pytest.raises(ZoneError):
            resolve_zone(bad, zones)


def test_readers(case):
    ev = case.evidence
    w3c = dict(records(ev / "DC01/pfirewall.log", {"format": "w3c"}))
    assert w3c["6"]["src-ip"] == "203.0.113.9" and w3c["7"]["pid"] == "4"   # numbered by line
    stats = Stats()
    jl = list(records(ev / "SIEM/alerts.jsonl", {"format": "jsonl"}, stats))
    assert [n for n, _ in jl] == ["1", "3"] and stats.skipped == 1
    assert jl[0][1]["source.port"] == "4444" and jl[0][1]["tags"] == '["a", "b"]'
    kv = dict(records(ev / "FIREWALL/sonicwall.log", {"format": "kv"}))["1"]
    assert kv["msg"] == "Connection Closed" and kv["src"] == "10.0.0.12:49733:X0" and "syslog_header" not in kv
    csv_rec = dict(records(ev / "SIEM/logons.csv", {"format": "csv", "delimiter": ","}))
    assert csv_rec["2"]["Account"] == "CORP\\alice" and csv_rec["3"]["Computer"] == ""


def test_presets_are_chosen_from_the_product(case):
    forti = guess_mapping(sniff(case, "FIREWALL/fortigate.log"))
    assert forti["preset"] == "fortinet" and forti["time"]["columns"] == ["eventtime"]
    assert forti["fields"]["source_ip"] == "srcip" and forti["fields"]["user"] == "user"
    assert guess_mapping(sniff(case, "FIREWALL/sonicwall.log"))["preset"] == "sonicwall"
    assert guess_mapping(sniff(case, "DC01/pfirewall.log"))["preset"] == "windows_firewall"
    siem = guess_mapping(sniff(case, "SIEM/logons.csv"))
    assert siem["time"] == {"columns": ["TimeGenerated"], "format": "mdy", "zone": ""}
    assert siem["fields"] == {"source_ip": "IpAddress", "source_port": "IpPort", "user": "Account",
                              "computer": "Computer", "code": "EventID"}
    jl = guess_mapping(sniff(case, "SIEM/alerts.jsonl"))
    assert jl["time"]["columns"] == ["@timestamp"] and jl["time"]["zone"] == "UTC"
    assert jl["fields"]["dest_port"] == "destination.port" and jl["fields"]["computer"] == "host.name"


def test_preview_asks_for_a_zone_and_shows_events(case):
    first = preview(case, "DC01/pfirewall.log", zones={})
    assert first["guessed"] and any("carry no zone" in p for p in first["problems"]) and not first["events"]
    london = {**first["mapping"], "time": {**first["mapping"]["time"], "zone": "Europe/London"}}
    ready = preview(case, "DC01/pfirewall.log", london, zones={})
    assert not ready["problems"] and ready["lane"] == "DC01" and ready["lines"] == 7
    ev = ready["events"][0]
    assert ev["ts"] == parse_time("2024-07-01 09:21:48", "ymd").us   # 10:21:48 BST
    assert ev["message"] == "ALLOW TCP 203.0.113.9:51544 -> 10.0.0.12:3389 RECEIVE pid 1234"
    assert ev["fields"] == {"source_ip": "203.0.113.9", "source_port": "51544", "dest_ip": "10.0.0.12",
                            "dest_port": "3389", "code": "ALLOW"}
    root = preview(case, "notes.csv", zones={})
    assert any("belongs to no host" in p for p in root["problems"])


def test_import_is_a_run_that_rebuild_repeats(case):
    before = sha256_file(case.evidence / "FIREWALL/fortigate.log")
    record = run_import(case, "FIREWALL/fortigate.log", {"preset": "fortinet"}, zones={})
    assert (record.status, record.loaded_rows, record.evidence_check) == ("ok", 2, "ok")
    assert record.tool == "import" and record.mapping["preset"] == "fortinet" and record.host == "FIREWALL"
    con = connect(case.db_path)
    rows = con.execute("SELECT ts_us, host, artifact, source_ip, source_port, dest_ip, dest_port, user_name, event_code, "
                       "host_name_recorded, log_channel, message, json_extract_string(extra, '$.policyid') "
                       "FROM events ORDER BY source_record").fetchall()
    con.close()
    # eventtime is Unix time in nanoseconds, so the device's own clock and tz aren't needed.
    assert rows[0][:11] == (1685000716783695, "FIREWALL", "fortinet", "10.100.91.100", "52937", "10.100.88.201", "443",
                            "alice", "0000000013", "FGT60E", "traffic")
    assert rows[0][11] == ("traffic/forward deny 10.100.91.100:52937 -> 10.100.88.201:443 HTTPS user alice policy 7: "
                           "Denied by policy")
    assert rows[0][12] == "7"
    assert rows[1][0] == parse_time("2023-05-25 07:45:20", "ymd").us
    assert rows[1][11] == "event/system 10.100.91.5 user admin Admin login successful"
    again = run_import(case, "FIREWALL/fortigate.log", {"preset": "fortinet"}, zones={})
    assert again.replaced_rows == 2
    assert [r.run_id for r in rebuild(case)] == [again.run_id]
    con = connect(case.db_path, read_only=True)
    assert con.execute("SELECT count(*) FROM events WHERE tool = 'import'").fetchone()[0] == 2
    con.close()
    assert sha256_file(case.evidence / "FIREWALL/fortigate.log") == before
    saved = json.loads((case.runs_folder / again.run_id / "run.json").read_text())
    assert saved["mapping"]["time"]["columns"] == ["eventtime"] and saved["inputs"] == ["FIREWALL/fortigate.log"]


def test_fortinet_time_from_the_device_clock_and_tz(case):
    m = guess_mapping(sniff(case, "FIREWALL/fortigate.log"))
    m["time"] = {"columns": ["date", "time"], "format": "ymd", "zone": "", "zone_column": "tz"}
    out = preview(case, "FIREWALL/fortigate.log", m, zones={})
    assert not out["problems"]
    assert out["events"][0]["ts"] == parse_time("2023-05-25 07:45:16", "ymd").us   # 00:45:16 at -07:00


def test_host_lanes_from_a_field_and_a_recorded_zone(case):
    m = guess_mapping(sniff(case, "SIEM/logons.csv"))
    m["host"] = {"from": "column", "column": "Computer", "fallback": "SIEM-UNKNOWN"}
    m["time"]["zone"] = "host:DC01"
    zones = {"DC01": {"windows": "Eastern Standard Time", "iana": "America/New_York", "bias_minutes": 300}}
    record = run_import(case, "SIEM/logons.csv", m, zones=zones)
    assert record.mapping["time"]["zone_resolved"]["name"] == "America/New_York"
    assert record.notes[0].startswith("Times without a zone read as DC01's zone")
    con = connect(case.db_path, read_only=True)
    rows = con.execute("SELECT host, ts_us, user_domain, user_name, source_port FROM events ORDER BY ts_us").fetchall()
    con.close()
    assert rows == [("WEB01", parse_time("2024-02-14 03:00:00", "ymd").us, "CORP", "alice", "51544"),
                    ("SIEM-UNKNOWN", parse_time("2024-02-14 06:30:00", "ymd").us, "CORP", "bob", "51550")]
    # A rebuild uses the zone the import recorded, without the hosts' zones.
    rebuild(case)
    con = connect(case.db_path, read_only=True)
    assert con.execute("SELECT min(ts_us) FROM events").fetchone()[0] == rows[0][1]
    con.close()


def test_a_lone_surrogate_in_a_record_s_host_loads_as_u_fffd(case):
    """json.loads makes a lone surrogate from a \\ud83d escape in cut UTF-16 text. One in the field that names each
    record's host, which is part of the event's ID and so must encode as UTF-8, loads as U+FFFD and the import
    completes."""
    (case.evidence / "SIEM" / "cut.jsonl").write_text(
        '{"@timestamp": "2024-02-05T10:21:48Z", "computer": "WS\\ud83d", "CommandLine": "cmd \\udc00"}\n'
        '{"@timestamp": "2024-02-05T10:21:49Z", "computer": "WS01", "CommandLine": "cmd"}\n', newline="\n")
    add_new(case)
    m = guess_mapping(sniff(case, "SIEM/cut.jsonl"))
    m["host"] = {"from": "column", "column": "computer", "fallback": "SIEM-UNKNOWN"}
    m["fields"]["command_line"] = "CommandLine"
    assert len(preview(case, "SIEM/cut.jsonl", m, zones={})["events"]) == 2
    assert run_import(case, "SIEM/cut.jsonl", m, zones={}).status == "ok"
    con = connect(case.db_path, read_only=True)
    rows = con.execute("SELECT host, origin_host, process_command_line FROM events WHERE source_file = ? "
                       "ORDER BY ts_us", ["SIEM/cut.jsonl"]).fetchall()
    con.close()
    assert rows == [("WS\ufffd", "WS\ufffd", "cmd \ufffd"), ("WS01", "WS01", "cmd")]


def test_a_port_in_other_digits_imports_as_no_port(case):
    """A port written in digits int() refuses, such as "²" or more than 4,300 digits, imports as no port, and the
    preview and the import go on."""
    lines = [json.dumps({"@timestamp": f"2024-02-05T10:21:4{i}Z", "source": {"ip": "10.0.0.5", "port": port}})
             for i, port in enumerate(("4444", "²", "4446", "1" * 5000))]
    (case.evidence / "SIEM" / "ports.jsonl").write_text("\n".join(lines) + "\n", newline="\n")
    add_new(case)
    m = guess_mapping(sniff(case, "SIEM/ports.jsonl"))
    assert m["fields"]["source_port"] == "source.port"
    assert len(preview(case, "SIEM/ports.jsonl", m, zones={})["events"]) == 4
    run = run_import(case, "SIEM/ports.jsonl", m, zones={})
    assert (run.status, run.loaded_rows) == ("ok", 4), run.reason
    con = connect(case.db_path, read_only=True)
    ports = con.execute("SELECT source_port FROM events WHERE source_file = 'SIEM/ports.jsonl' ORDER BY ts_us").fetchall()
    con.close()
    assert ports == [("4444",), ("",), ("4446",), ("",)]


def test_the_preview_counts_a_json_array_by_its_records(case):
    """A JSON array of many records on one line is named a JSON array and counted by its records, not as 1 line; JSON
    lines keep their line count."""
    records = [{"@timestamp": f"2024-02-05T10:2{i}:48Z", "user": f"u{i}"} for i in range(3)]
    (case.evidence / "SIEM" / "export.json").write_text(json.dumps(records), newline="\n")
    add_new(case)
    p = preview(case, "SIEM/export.json")
    assert (p["format_label"], p["product"], p["array_records"], p["lines"]) == ("JSON array", "JSON array", 3, 1)
    p = preview(case, "SIEM/alerts.jsonl")
    assert (p["format_label"], p["array_records"]) == ("JSON lines", None) and p["lines"] > 1


def test_records_nested_too_deep_are_skipped_and_the_import_finishes(case):
    """Nesting is read with a stack of its own, so a record nested 1,000 deep raises no RecursionError, and the import's
    run finishes even when the record is past the 200 records the preview reads. A line too deep for json.loads is
    skipped and counted, as a line that isn't JSON is, and so is an object holding a list too deep to write back as
    JSON text. A JSON array too deep to read is refused."""
    record = '{"@timestamp": "2024-02-05T10:%02d:00Z", "user": "u%d"}'
    deep = '{"@timestamp": "2024-02-05T11:00:00Z", "user": "deep", "x": ' + '{"a": ' * 2000 + "1" + "}" * 2001
    too_deep = '{"@timestamp": "2024-02-05T11:00:01Z", "x": ' + "[" * 50_000 + "]" * 50_000 + "}"
    lines = [record % (i % 60, i) for i in range(250)] + [deep, too_deep]
    (case.evidence / "SIEM" / "deep.jsonl").write_text("\n".join(lines) + "\n", newline="\n")
    add_new(case)
    run = run_import(case, "SIEM/deep.jsonl", guess_mapping(sniff(case, "SIEM/deep.jsonl")), zones={})
    assert (run.status, run.loaded_rows) == ("ok", 251) and "1 line wasn't a record" in " ".join(run.notes)
    con = connect(case.db_path, read_only=True)
    extra = con.execute("SELECT extra FROM events WHERE source_file = 'SIEM/deep.jsonl' AND source_record = '251'")
    assert json.loads(extra.fetchone()[0])["x" + ".a" * 2000] == "1"
    con.close()
    assert _flat({"x": nested_list(100_000)}) is None
    (case.evidence / "SIEM" / "deep.json").write_text("[" * 50_000 + "]" * 50_000)
    with pytest.raises(MappingError, match="too deep"):
        list(records(case.evidence / "SIEM" / "deep.json", {"format": "jsonl"}))


def test_saved_mappings_are_offered_for_files_with_the_same_fields(case):
    m = guess_mapping(sniff(case, "SIEM/logons.csv"))
    m["time"]["zone"] = "UTC"
    m["artifact"] = "siem_logons"
    save_mapping(case, "siem-logons", m)
    (case.evidence / "SIEM" / "more.csv").write_text(
        'TimeGenerated,Computer,EventID,Account,IpAddress,IpPort,Activity,Extra\n'
        '02/15/2024 10:00:00 PM,WEB01,4624,CORP\\carol,203.0.113.7,50000,logged on,x\n', newline="\n")
    add_new(case)
    out = preview(case, "SIEM/more.csv", zones={})
    assert out["mapping"]["saved_as"] == "siem-logons" and out["mapping"]["artifact"] == "siem_logons"
    assert not out["problems"]
    with pytest.raises(MappingError):
        save_mapping(case, "../escape", m)


def test_import_refuses_files_outside_the_manifest(case):
    (case.evidence / "SIEM" / "late.csv").write_text("time,x\n2024-02-05T10:00:00Z,1\n")
    with pytest.raises(MappingError, match="Add new evidence"):
        preview(case, "SIEM/late.csv", zones={})
    with pytest.raises(MappingError, match="Not an evidence file"):
        preview(case, "../case/case.yaml", zones={})


def test_files_to_import_and_their_state(case):
    listed = {f["path"]: f for f in importable(case)}
    assert set(listed) == {"DC01/pfirewall.log", "FIREWALL/fortigate.log", "FIREWALL/sonicwall.log",
                           "SIEM/logons.csv", "SIEM/alerts.jsonl", "notes.csv"}
    assert listed["FIREWALL/sonicwall.log"]["detail"] == "SonicWall" and listed["SIEM/logons.csv"]["imported"] is None
    run_import(case, "FIREWALL/sonicwall.log", {"preset": "sonicwall"}, zones={})
    after = {f["path"]: f for f in importable(case)}["FIREWALL/sonicwall.log"]["imported"]
    assert after["rows"] == 1 and after["mapping"] == "sonicwall"
    con = connect(case.db_path, read_only=True)
    assert con.execute("SELECT source_ip, source_port, dest_ip, dest_port, user_name, event_code, ts_us FROM events"
                       ).fetchone() == ("10.0.0.12", "49733", "198.51.100.4", "443", "bob", "537",
                                        parse_time("2024-02-05 10:21:48", "ymd").us)
    con.close()


def test_a_case_from_before_the_import_finds_its_text_logs(case):
    """Text logs a manifest records as unidentified are recognized when the list is built."""
    lines = case.manifest_path.read_text().splitlines()
    old = [json.dumps({**json.loads(line), "artifact": None, "method": "unidentified", "detail": ""}) for line in lines]
    case.manifest_path.write_text("\n".join(old) + "\n")
    assert all(e.artifact is None for e in read_manifest(case))
    listed = {f["path"]: f["artifact"] for f in importable(case)}
    assert listed["DC01/pfirewall.log"] == "w3c_log" and listed["SIEM/logons.csv"] == "csv"


def test_the_tools_and_import_pages_read_older_identifications_again_alike(case):
    """The Import page and the Tools page read a manifest's text logs again by one rule: both read the manifest through
    intake.current_entries, so a log intake took for key=value lines before its layout was known is identified the same
    on both, and a file that can't be read again keeps its identification on both."""
    from test_line_logs import SYSLOG

    from glessner.intake import _current_entries, _identify_cached, current_entries

    (case.evidence / "SIEM" / "ufw.log").write_text((SYSLOG.splitlines()[0] + "\n") * 3, newline="\n")
    add_new(case)
    lines = case.manifest_path.read_text().splitlines()
    old = {"artifact": "kv_log", "method": "content", "detail": "key=value"}   # as intake read UFW's KEY=value pairs
    case.manifest_path.write_text("\n".join(
        json.dumps({**e, **old} if e["path"] == "SIEM/ufw.log" else e) for e in map(json.loads, lines)) + "\n")
    tools = {e.path: (e.artifact, e.detail) for e in current_entries(case)}
    listed = {f["path"]: (f["artifact"], f["detail"]) for f in importable(case)}
    assert tools["SIEM/ufw.log"] == listed["SIEM/ufw.log"] == ("line_log", "Syslog")
    assert {path: tools[path] for path in listed} == listed
    (case.evidence / "SIEM" / "logons.csv").unlink()
    _current_entries.cache_clear()   # as in a new process, which hasn't read the file
    _identify_cached.cache_clear()
    assert {e.path: e.artifact for e in current_entries(case)}["SIEM/logons.csv"] == "csv"
    assert {f["path"]: f["artifact"] for f in importable(case)}["SIEM/logons.csv"] == "csv"


def test_icu_needs_no_download():
    con = duckdb.connect(":memory:", config={"autoinstall_known_extensions": False, "autoload_known_extensions": False})
    assert con.execute("SELECT install_mode FROM duckdb_extensions() WHERE extension_name = 'icu'").fetchone()[0] == \
        "STATICALLY_LINKED"
    con.close()


def test_command_line_import(case, capsys):
    from glessner.cli import main

    folder = str(case.folder)
    assert main(["import", folder, "--list"]) == 0
    assert "FIREWALL/sonicwall.log" in capsys.readouterr().out
    # Without a zone, the firewall log isn't imported, and says what to choose.
    assert main(["import", folder, "DC01/pfirewall.log"]) == 1
    assert "Needs a choice: The times carry no zone" in capsys.readouterr().out
    assert main(["import", folder, "DC01/pfirewall.log", "--zone", "Europe/London", "--preview"]) == 0
    out = capsys.readouterr().out
    assert "2024-07-01 09:21:48.000000 UTC  DC01  ALLOW TCP 203.0.113.9:51544" in out and not read_runs(case)
    assert main(["import", folder, "FIREWALL/*.log", "--save-as", "fw"]) == 0
    out = capsys.readouterr().out
    assert "ok: 2 events" in out and "ok: 1 event " in out and "Saved the mapping as fw" in out
    assert {r.inputs[0] for r in read_runs(case)} == {"FIREWALL/fortigate.log", "FIREWALL/sonicwall.log"}
    assert (case.folder / "mappings" / "fw.json").is_file()
    # A date field and a time field, with the lane named on the command line.
    assert main(["import", folder, "DC01/pfirewall.log", "--zone", "UTC", "--host", "EDGE", "--time-field", "date",
                 "--time-field", "time"]) == 0
    con = connect(case.db_path, read_only=True)
    assert con.execute("SELECT DISTINCT host FROM events WHERE source_file = 'DC01/pfirewall.log'").fetchall() == [("EDGE",)]
    con.close()
    assert main(["import", folder, "nothing/*.csv"]) == 2


def test_command_line_adds_new_evidence(case, capsys):
    from glessner.cli import main

    (case.evidence / "FIREWALL" / "extra.csv").write_text("time,src\n2024-02-05T10:00:00Z,10.0.0.1\n")
    assert main(["intake", str(case.folder), "--add"]) == 0
    out = capsys.readouterr().out
    assert "1 new file," in out and "csv" in out


def test_preview_guesses_the_format_of_a_newly_chosen_time_field(case):
    m = guess_mapping(sniff(case, "SIEM/logons.csv"))
    m["time"] = {"columns": ["TimeGenerated"], "format": "", "zone": "UTC"}
    assert preview(case, "SIEM/logons.csv", m, zones={})["mapping"]["time"]["format"] == "mdy"
    (case.evidence / "SIEM" / "ambiguous.csv").write_text("when,src\n02/05/2024 10:00,10.0.0.1\n")
    add_new(case)
    out = preview(case, "SIEM/ambiguous.csv", zones={})
    assert any("month/day/year or day/month/year" in p for p in out["problems"])


def test_an_edr_export_fills_the_parent_process(case):
    """An export's ParentImage and ParentCommandLine fill the parent columns, as Image and CommandLine fill the process
    ones, so parent: search and the View value reach imported events too."""
    (case.evidence / "SIEM" / "processes.csv").write_text(
        "UtcTime,Image,CommandLine,ParentImage,ParentCommandLine\n"
        "2024-02-05 10:00:00Z,C:\\Windows\\System32\\cmd.exe,cmd.exe /c whoami,C:\\Windows\\System32\\inetsrv\\w3wp.exe,"
        "w3wp.exe -ap DefaultAppPool\n", newline="\n")
    add_new(case)
    m = guess_mapping(sniff(case, "SIEM/processes.csv"))
    assert {r: m["fields"].get(r) for r in ("process", "command_line", "parent", "parent_command_line")} == {
        "process": "Image", "command_line": "CommandLine", "parent": "ParentImage",
        "parent_command_line": "ParentCommandLine"}
    shown = preview(case, "SIEM/processes.csv", m, zones={})["events"][0]["fields"]
    assert shown["parent"] == "C:\\Windows\\System32\\inetsrv\\w3wp.exe"
    assert run_import(case, "SIEM/processes.csv", m, zones={}).loaded_rows == 1
    con = connect(case.db_path, read_only=True)
    assert con.execute("SELECT process_parent_executable, process_parent_command_line FROM events").fetchall() == [
        ("C:\\Windows\\System32\\inetsrv\\w3wp.exe", "w3wp.exe -ap DefaultAppPool")]
    con.close()


def test_a_lane_of_firewall_logs_is_guessed_a_network_device(case):
    from glessner.analysis import guess_role, role_evidence

    run_import(case, "FIREWALL/sonicwall.log", {"preset": "sonicwall"}, zones={})
    run_import(case, "SIEM/logons.csv", {**guess_mapping(sniff(case, "SIEM/logons.csv")),
                                         "time": {"columns": ["TimeGenerated"], "format": "mdy", "zone": "UTC"}}, zones={})
    con = connect(case.db_path, read_only=True)
    evidence = role_evidence(con)
    con.close()
    assert guess_role(["FIREWALL"], evidence["FIREWALL"]) == ("Network devices", "Its events all come from SonicWall logs")
    assert "SIEM" not in evidence or not evidence["SIEM"].network_device


def test_rebuild_leaves_out_an_import_whose_file_changed(case):
    record = run_import(case, "FIREWALL/sonicwall.log", {"preset": "sonicwall"}, zones={})
    (case.evidence / "FIREWALL" / "sonicwall.log").write_text(SONIC_LOG + SONIC_LOG, newline="\n")
    [again] = rebuild(case)
    assert again.run_id == record.run_id and again.loaded_rows == 0 and "SHA-256 changed" in again.notes[-1]
    con = connect(case.db_path, read_only=True)
    assert con.execute("SELECT count(*) FROM events").fetchone()[0] == 0
    con.close()


def test_an_import_that_commits_and_then_fails_its_check_refreshes_the_case(tmp_path, monkeypatch):
    """An import whose file changes while it is read fails its run, but by then events.load has committed its rows.
    api_import builds the derived tables again after that run too, so the host, the hits, and a search saved before the
    import include the new events."""
    from glessner import imports
    from glessner.server import App, api_import, api_search

    ev = tmp_path / "evidence"
    (ev / "FW01").mkdir(parents=True)
    (ev / "FW01" / "fw.csv").write_text("time,msg\n2024-01-01T00:00:00Z,hello\n", newline="\n")
    case = create_case(tmp_path / "case", "Changing", ev, "cody")
    intake(case)
    mapping = {**preview(case, "FW01/fw.csv")["mapping"]}
    mapping["time"] = {**mapping["time"], "zone": "UTC"}
    real = imports.load_import

    def read_while_it_changes(c, record, folder):
        real(c, record, folder)
        with (c.evidence / "FW01" / "fw.csv").open("a", newline="\n") as f:
            f.write("2024-01-01T00:00:01Z,later\n")

    app = App(case)
    try:
        assert api_search(app, {"q": ["hello"]})["total"] == 0   # saved before the import
        loads = app.loads
        monkeypatch.setattr(imports, "load_import", read_while_it_changes)
        out = api_import(app, {"paths": ["FW01/fw.csv"], "mapping": mapping})
        assert [(r["status"], r["rows"], r["reason"]) for r in out["runs"]] == [
            ("failed", 1, "evidence changed during the import")]
        assert app.loads == loads + 1 and "FW01" in app.identity.hosts
        assert api_search(app, {"q": ["hello"]})["total"] == 1
    finally:
        app.con.close()


def test_an_import_records_the_lines_that_were_not_records_once_the_case_is_at_format_4(case):
    """alerts.jsonl holds one line that isn't JSON. A case below format 4 keeps run.json in the shape the builds of its
    format read, so an import or a rebuild there records no count; at format 4 a rebuild records it for the import made
    before, and a new import records its own, 0 for a file whose every line is a record."""
    below = format3_case(case)
    mapping = guess_mapping(sniff(below, "SIEM/alerts.jsonl"))
    alerts = run_import(below, "SIEM/alerts.jsonl", mapping, zones={})
    assert (alerts.status, alerts.loaded_rows, alerts.rows_skipped) == ("ok", 2, None)
    rebuild(below)
    saved = lambda record: json.loads((case.runs_folder / record.run_id / "run.json").read_text(encoding="utf-8"))
    assert not {"tool_files", "rows_skipped", "tool_check"} & set(saved(alerts))
    at_4 = upgraded(open_case(case.folder))
    assert at_4.settings.case_format == 4
    rebuild(at_4)
    assert saved(alerts)["rows_skipped"] == 1 and "tool_files" not in saved(alerts)
    forti = run_import(at_4, "FIREWALL/fortigate.log", {"preset": "fortinet"}, zones={})
    assert (forti.status, forti.rows_skipped, saved(forti)["rows_skipped"]) == ("ok", 0, 0)
