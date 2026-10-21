"""Suricata on packet captures: EVE parsing, the registry entry's Npcap check and rule set, raw first for
found EVE files, and, in the lab, a real run on a synthetic capture."""

import json
import shutil
import tempfile
from pathlib import Path

import pytest
from conftest import nested_list
from pcap_maker import write_pcap

from glessner import tools
from glessner.case import create_case
from glessner.events import connect
from glessner.intake import intake
from glessner.parsers import PARSERS, ParseContext
from glessner.runner import RunError, build_argv, plan_runs, read_runs, run
from glessner.toolbox import found_outputs
from glessner.tools import DetectedTool, load_registry

EVE = [
    {"timestamp": "2024-05-14T19:00:00.000000+0700", "event_type": "dns", "src_ip": "10.0.0.5", "src_port": 53000,
     "dest_ip": "10.0.0.1", "dest_port": 53, "proto": "UDP",
     "dns": {"type": "request", "queries": [{"rrname": "update.evil.example", "rrtype": "A"}]}},
    {"timestamp": "2024-05-14T19:00:01.250000+0700", "event_type": "alert", "src_ip": "203.0.113.80", "src_port": 80,
     "dest_ip": "10.0.0.5", "dest_port": 49200, "proto": "TCP", "app_proto": "http",
     "alert": {"signature_id": 2100498, "signature": "GPL ATTACK_RESPONSE id check returned root",
               "category": "Potentially Bad Traffic", "severity": 2}, "payload": "bW9zdA=="},
    {"timestamp": "2024-05-14T19:00:01.300000+0700", "event_type": "fileinfo", "src_ip": "203.0.113.80",
     "dest_ip": "10.0.0.5", "fileinfo": {"filename": "/payload.exe", "size": 126}},
    {"timestamp": "2024-05-14T19:00:02.000000+0700", "event_type": "stats", "stats": {"uptime": 8}},
    {"timestamp": "2024-05-14T19:00:03.000000+0700", "event_type": "http", "src_ip": "10.0.0.5", "src_port": 49200,
     "dest_ip": "203.0.113.80", "dest_port": 80,
     "http": {"hostname": "update.evil.example", "url": "/payload.exe", "http_method": "GET", "status": 200}},
]
SURICATA = Path("D:/DFIR-Lab/tools/suricata-8.0.7/PFiles/Suricata/suricata.exe")


def test_eve_records_become_events_in_utc(tmp_path):
    (tmp_path / "eve.json").write_text("".join(json.dumps(r) + "\n" for r in EVE) + "not json\n", encoding="utf-8")
    events = list(PARSERS["suricata_eve"](ParseContext(tmp_path, Path("D:/Evidence"), ("SENSOR/capture.pcap",))))
    assert [e.log_channel for e in events] == ["dns", "alert", "fileinfo", "http"]   # stats and bad lines left out
    dns, alert, seen, http = events
    assert dns.ts_us == 1715688000000000 and dns.source_file == "SENSOR/capture.pcap"   # 19:00 +07:00 is 12:00 UTC
    assert dns.message == "DNS request update.evil.example A (10.0.0.5:53000 -> 10.0.0.1:53)"
    assert (alert.event_code, alert.source_ip, alert.dest_port, alert.artifact) == ("2100498", "203.0.113.80", "49200",
                                                                                     "suricata")
    assert alert.message.startswith("Alert: GPL ATTACK_RESPONSE id check returned root (Potentially Bad Traffic")
    assert "payload" not in alert.extra and alert.extra["alert.category"] == "Potentially Bad Traffic"
    assert seen.file_path == "/payload.exe" and seen.extra["eve_line"] == "3"
    # Known by content, not line number, so a rerun keeps marks on it, and by its time in UTC, so a rerun in
    # another zone does too
    assert seen.source_record == "eve|fileinfo|2024-05-14T12:00:01.300000+0000|203.0.113.80||10.0.0.5|||||/payload.exe"
    reordered = tmp_path / "again"
    reordered.mkdir()
    (reordered / "eve.json").write_text("".join(json.dumps(r) + "\n" for r in reversed(EVE)), encoding="utf-8")
    again = PARSERS["suricata_eve"](ParseContext(reordered, Path("D:/Evidence"), ("SENSOR/capture.pcap",)))
    assert {e.source_record for e in again} == {e.source_record for e in events}
    assert http.message == "HTTP GET update.evil.example/payload.exe 200 (10.0.0.5:49200 -> 203.0.113.80:80)"


def test_records_nested_too_deep_are_skipped(tmp_path, monkeypatch):
    """_flatten reads nesting with a stack of its own, so one EVE record nested 1,000 deep, in a file found in the
    evidence, doesn't stop the whole load with RecursionError. A line too deep for json.loads, or a record holding a
    list too deep to write back as JSON text, is skipped, as a bad line is."""
    deep = {**EVE[0], "dns": {**EVE[0]["dns"], "x": json.loads('{"a":' * 2000 + "1" + "}" * 2000)}}
    lines = [json.dumps(EVE[1]), json.dumps(deep), '{"event_type": "dns", "x": ' + "[" * 50_000 + "]" * 50_000 + "}"]
    (tmp_path / "eve.json").write_text("\n".join(lines) + "\n", encoding="utf-8")
    events = list(PARSERS["suricata_eve"](ParseContext(tmp_path, Path("D:/Evidence"), ("SENSOR/capture.pcap",))))
    assert [e.log_channel for e in events] == ["alert", "dns"]
    assert events[1].extra["dns.x" + ".a" * 2000] == "1"
    from glessner.parsers import suricata
    monkeypatch.setattr(suricata, "_records", lambda path: iter([(1, {**EVE[1], "x": nested_list(100_000)}),
                                                                (2, EVE[1])]))
    assert len(list(PARSERS["suricata_eve"](ParseContext(tmp_path, Path("D:/Evidence"), ("SENSOR/capture.pcap",))))) == 1


def test_flows_sit_at_their_start_and_late_records_at_their_flows(tmp_path):
    """In its default mode, reading a file, Suricata logs flows and TLS records with the capture's first packet time, as
    in the Szechuan case. Flows go at their start; a record logged before its flow began takes the flow's start. An
    unnamed protocol shows as the transport, not as "failed"."""
    first = "2020-09-19T04:58:07.470323+0700"   # the capture's first packet
    flow = {"timestamp": first, "flow_id": 7, "event_type": "flow", "src_ip": "10.42.85.10", "src_port": 62414,
            "dest_ip": "203.78.103.109", "dest_port": 443, "proto": "TCP", "app_proto": "failed",
            "flow": {"start": "2020-09-19T09:25:18.000000+0700", "end": "2020-09-19T09:40:00.000000+0700",
                     "bytes_toserver": 51044, "bytes_toclient": 932653}}
    tls = {"timestamp": first, "flow_id": 7, "event_type": "tls", "src_ip": "10.42.85.10", "dest_ip": "203.78.103.109",
           "proto": "TCP", "tls": {"version": "TLS 1.2"}}
    alert = {"timestamp": "2020-09-19T09:25:19.071794+0700", "flow_id": 7, "event_type": "alert", "proto": "TCP",
             "app_proto": "failed", "src_ip": "203.78.103.109", "src_port": 443, "dest_ip": "10.42.85.10",
             "dest_port": 62414, "alert": {"signature_id": 2025644, "signature": "ET MALWARE Possible Metasploit Payload",
                                           "category": "A Network Trojan was detected", "severity": 1}}
    (tmp_path / "eve.json").write_text("".join(json.dumps(r) + "\n" for r in (tls, alert, flow)), encoding="utf-8")
    late, on_time, connection = PARSERS["suricata_eve"](ParseContext(tmp_path, Path("D:/Evidence"), ("NET/c.pcap",)))
    start = 1600482318000000   # 2020-09-19 02:25:18 UTC
    assert (connection.ts_us, connection.ts_desc) == (start, "Suricata flow started")
    assert connection.extra["timestamp"] == first and connection.message.startswith("Flow TCP 10.42.85.10:62414")
    assert (late.ts_us, late.extra["time_note"]) == (start, "logged before its flow began; placed at the flow's start")
    assert late.ts_desc == "Suricata tls"   # the record's ID stays the same whether or not its time was moved
    assert on_time.ts_us == 1600482319071794 and "time_note" not in on_time.extra
    assert "failed" not in on_time.message and on_time.message.endswith("severity 1) TCP 203.78.103.109:443 -> "
                                                                         "10.42.85.10:62414")


def suricata_install(tmp_path, with_rules=True):
    folder = tmp_path / "tools" / "suricata" / "PFiles" / "Suricata"
    (folder / "rules").mkdir(parents=True)
    (folder / "suricata.exe").write_bytes(b"MZ")
    if with_rules:
        (folder / "rules" / "suricata.rules").write_text("alert ip any any -> any any (sid:1;)\n", encoding="utf-8")
        (folder / "rules" / "et-open-version.txt").write_text("ET Open 11310\n", encoding="utf-8")
    return folder


def capture_case(tmp_path):
    ev = tmp_path / "evidence"
    (ev / "SENSOR").mkdir(parents=True)
    write_pcap(ev / "SENSOR" / "capture.pcap")
    (ev / "SENSOR" / "eve.json").write_text(json.dumps(EVE[0]) + "\n", encoding="utf-8")
    case = create_case(tmp_path / "case", "Captures", ev, "cody")
    intake(case)
    return case


def test_registry_entry_loads_the_rule_set_beside_the_tool_and_needs_npcap(tmp_path, monkeypatch):
    spec = load_registry()["suricata"]
    assert spec.npcap and spec.handles == ("pcap",) and spec.input == "each_file"
    folder = suricata_install(tmp_path)
    monkeypatch.setattr(tools, "npcap_folder", lambda: tmp_path)   # Npcap present; the version check fails harmlessly
    found = tools.detect([spec], tmp_path / "tools")["suricata"]
    assert (found.rules, found.missing) == ("ET Open 11310", "")
    assert tools.tool_env(found)["PATH"].startswith(str(tmp_path))
    case = capture_case(tmp_path)
    (plan,) = plan_runs(case, found)
    argv = build_argv(case, plan, tmp_path / "out", {})
    assert argv[argv.index("-S") + 1] == str(folder / "rules" / "suricata.rules")
    assert f"classification-file={folder}\\rules\\classification.config" in argv
    assert argv[argv.index("-r") + 1] == str(case.evidence / "SENSOR" / "capture.pcap")
    assert argv[argv.index("--runmode") + 1] == "single"   # one thread logs each record at its own time

    (folder / "rules" / "suricata.rules").unlink()   # without a rule set it runs without rules
    bare = tools.detect([spec], tmp_path / "tools")["suricata"]
    assert bare.rules == "" and "-S" not in build_argv(case, plan_runs(case, bare)[0], tmp_path / "out", {})

    monkeypatch.setattr(tools, "npcap_folder", lambda: None)   # no Npcap: no version check, and no run
    blocked = tools.detect([spec], tmp_path / "tools")["suricata"]
    assert blocked.missing.startswith("Needs Npcap")
    with pytest.raises(RunError, match="can't run here: Needs Npcap"):
        run(case, plan_runs(case, blocked)[0])
    assert read_runs(case) == []


def test_found_eve_waits_behind_captures_suricata_can_read(tmp_path):
    case = capture_case(tmp_path)
    specs = load_registry()
    exe = suricata_install(tmp_path) / "suricata.exe"
    runnable = {"suricata": DetectedTool(specs["suricata"], exe, "8.0.7")}
    blocked = {"suricata": DetectedTool(specs["suricata"], exe, "unknown", missing=tools.NPCAP_MISSING)}
    status = lambda detected: {g["key"]: g["status"] for g in found_outputs(case, specs, detected)}["suricata_eve"]
    assert status(runnable) == "raw"     # Suricata runs on the capture itself
    assert status(blocked) == "ready"    # it can't here, so the EVE file found beside it is the way in
    assert status({}) == "ready"
    listed = lambda detected: {g["key"] for g in found_outputs(case, specs, detected)}
    assert "pcap" not in listed(runnable)   # Suricata's own row covers the capture
    assert "pcap" in listed(blocked) and "pcap" in listed({})


def test_a_lane_of_sensor_output_is_guessed_a_network_device(tmp_path):
    """A lane of sensor output, such as the Szechuan case's capture lane, is guessed a network device, not a workstation."""
    from glessner.analysis import guess_role, role_evidence
    from glessner.events import load

    case = capture_case(tmp_path)
    (tmp_path / "out").mkdir()
    (tmp_path / "out" / "eve.json").write_text("".join(json.dumps(r) + "\n" for r in EVE), encoding="utf-8")
    events = PARSERS["suricata_eve"](ParseContext(tmp_path / "out", case.evidence, ("SENSOR/capture.pcap",)))
    load(case.db_path, events, host="SENSOR", tool="suricata", tool_version="8.0.7", run_id="r1",
         replaces_sources=["SENSOR/capture.pcap"], staging_dir=tmp_path / "out")
    con = connect(case.db_path, read_only=True)
    evidence = role_evidence(con)
    con.close()
    assert guess_role(["SENSOR"], evidence["SENSOR"]) == ("Network devices", "Its events all come from Suricata logs")


@pytest.mark.lab
@pytest.mark.skipif(not SURICATA.is_file() or tools.npcap_folder() is None, reason="lab Suricata or Npcap not present")
def test_lab_suricata_reads_a_capture_with_et_open():
    """The real Suricata with ET Open, through the runner, on the synthetic capture: DNS, HTTP, the file, and the
    planted rule hit. Takes about 10 seconds, most of it loading 52,000 rules."""
    folder = Path(tempfile.mkdtemp(prefix="suricata_", dir="D:/DFIR-Lab/test-cases"))
    try:
        _lab_run(folder)
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def _lab_run(folder):
    (folder / "evidence" / "SENSOR").mkdir(parents=True)
    write_pcap(folder / "evidence" / "SENSOR" / "capture.pcap")
    case = create_case(folder / "case", "Suricata", folder / "evidence", "test", SURICATA.parents[2].parent)
    intake(case)
    tool = tools.detect([load_registry()["suricata"]], Path("D:/DFIR-Lab/tools"))["suricata"]
    (plan,) = plan_runs(case, tool)
    record = run(case, plan)
    assert (record.status, record.evidence_check) == ("ok", "ok") and record.rules.startswith("ET Open")
    con = connect(case.db_path)
    channels = {c for (c,) in con.execute("SELECT DISTINCT log_channel FROM events").fetchall()}
    alert = con.execute("SELECT event_code, ts_us FROM events WHERE log_channel = 'alert'").fetchone()
    con.close()
    assert {"dns", "http", "fileinfo", "flow", "alert"} <= channels
    assert alert[0] == "2100498" and 1715688000000000 < alert[1] < 1715688010000000
