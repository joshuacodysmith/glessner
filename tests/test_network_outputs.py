"""Network monitors' output in the evidence (Zeek, Suricata) and packet captures."""

import json

import pytest

from glessner.case import create_case
from glessner.events import connect
from glessner.identify import identify_bytes
from glessner.intake import intake
from glessner.tool_outputs import kind_of
from glessner.toolbox import found_outputs, load_group
from glessner.tools import load_registry

ZEEK_TSV = ("#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n#path\tconn\n"
            "#open\t2024-05-14-12-00-00\n"
            "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\tconn_state\n"
            "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tstring\n"
            "1715688016.238760\tCJDro\t45.33.63.235\t63730\t45.83.220.5\t80\ttcp\t-\t-\tS0\n"
            "1715688048.855508\tCrVLu\t10.44.10.22\t53712\t10.44.20.10\t53\tudp\tdns\t0.004043\tSF\n"
            "#close\t2024-05-14-13-00-00\n")
X509 = {"ts": 1715688240.585, "id": "FqWDuc7", "fingerprint": "abc", "certificate.subject": "CN=styles.fullstory.co"}
EVE = [
    {"timestamp": "2024-05-14T12:55:09.776777+0000", "flow_id": 1, "event_type": "alert", "src_ip": "185.199.110.42",
     "src_port": 51750, "dest_ip": "45.83.220.5", "dest_port": 80, "proto": "TCP",
     "alert": {"action": "allowed", "gid": 1, "signature_id": 2002677, "rev": 14,
               "signature": "ET SCAN Nikto Web App Scan in Progress", "category": "Web Application Attack", "severity": 1}},
    {"timestamp": "2024-05-14T12:55:10.000000+0000", "event_type": "stats", "stats": {"uptime": 8}},
    {"timestamp": "2024-05-14T12:56:00.000000+0000", "flow_id": 2, "event_type": "dns", "src_ip": "10.0.0.5",
     "src_port": 5353, "dest_ip": "10.0.0.1", "dest_port": 53, "proto": "UDP",
     "dns": {"type": "query", "rrname": "evil.example", "rrtype": "A"}},
]
PCAP_HEADER = bytes.fromhex("d4c3b2a1020004000000000000000000ffff000001000000")


def test_network_monitor_output_and_captures_are_recognized():
    assert kind_of("conn.log", ZEEK_TSV.split("\n", 1)[0]).kind == "zeek_tsv"
    conn = json.dumps({"ts": 1715688016.2, "uid": "C1", "id.orig_h": "10.0.0.5", "id.resp_h": "10.0.0.1"})
    assert kind_of("conn.json", conn).kind == "zeek_json"
    assert kind_of("x509.json", json.dumps(X509)).kind == "zeek_json"       # only an id: its name settles it
    assert kind_of("app.json", json.dumps({"ts": 1, "id": "x"})) is None    # an app's own log with ts and id isn't Zeek
    assert kind_of("eve.json", json.dumps(EVE[0])).kind == "suricata_eve"
    assert kind_of("eve.json", json.dumps(EVE[0])[:120]).kind == "suricata_eve"   # cut off by the sniff
    assert identify_bytes("capture.pcap", PCAP_HEADER).artifact == "pcap"
    assert identify_bytes("capture.pcapng", bytes.fromhex("0a0d0d0a1c0000004d3c2b1a")).detail == "pcapng"
    assert identify_bytes("eve.json", (json.dumps(EVE[0]) + "\n").encode()).detail == "suricata_eve"


@pytest.mark.parametrize("sep", [".", "_"])
def test_a_zeek_json_log_is_recognized_by_its_originator_in_either_name_form(sep):
    """Zeek writes id.orig_h, or id_orig_h when set to join names with an underscore. A record whose keys are exactly
    ts and the two endpoints, with no connection or file ID, in a file whose name is no Zeek log's, is known by its
    originator, whole or cut off."""
    orig = f"id{sep}orig_h"
    flows = {"ts": 1715688016.2, orig: "10.0.0.5", f"id{sep}resp_h": "10.0.0.1"}
    assert kind_of("flows.json", json.dumps(flows)).kind == "zeek_json"
    cut = json.dumps(flows)[:50]   # a first line cut off by the sniff
    assert f'"{orig}"' in cut and '"uid"' not in cut
    assert kind_of("flows.json", cut).kind == "zeek_json"


def test_zeek_and_suricata_load_from_the_tools_page_and_captures_wait(tmp_path):
    ev = tmp_path / "evidence"
    (ev / "ZEEK").mkdir(parents=True)
    (ev / "ZEEK" / "conn.log").write_text(ZEEK_TSV, encoding="utf-8", newline="\n")
    (ev / "ZEEK" / "x509.json").write_text(json.dumps(X509) + "\n", encoding="utf-8")
    (ev / "SENSOR").mkdir()
    (ev / "SENSOR" / "eve.json").write_text("".join(json.dumps(r) + "\n" for r in EVE), encoding="utf-8")
    (ev / "SENSOR" / "capture.pcap").write_bytes(PCAP_HEADER)
    case = create_case(tmp_path / "case", "Network", ev, "cody")
    intake(case)
    specs = load_registry()
    groups = {(g["key"], g["host"]): g for g in found_outputs(case, specs, {})}
    assert (groups[("zeek", "ZEEK")]["files"], groups[("zeek", "ZEEK")]["tool_name"]) == (2, "Zeek")
    assert groups[("suricata_eve", "SENSOR")]["status"] == "ready"
    assert (groups[("pcap", "SENSOR")]["label"], groups[("pcap", "SENSOR")]["status"]) == ("Capture files", "no_parser")

    zeek = load_group(case, groups[("zeek", "ZEEK")])
    eve = load_group(case, groups[("suricata_eve", "SENSOR")])
    assert [(r.status, r.loaded_rows) for r in zeek] == [("ok", 2), ("ok", 1)]
    assert [(r.status, r.loaded_rows, r.evidence_check) for r in eve] == [("ok", 2, "ok")]   # stats left out
    con = connect(case.db_path)
    conn = con.execute("SELECT ts_us, source_ip, source_port, dest_ip, dest_port, log_channel, message FROM events "
                       "WHERE artifact = 'zeek' AND event_code = 'dns'").fetchone()
    assert conn == (1715688048855508, "10.44.10.22", "53712", "10.44.20.10", "53", "conn",
                    "conn: 10.44.10.22:53712 -> 10.44.20.10:53 udp dns SF")
    alert = con.execute("SELECT ts_us, source_ip, dest_port, event_code, log_channel, message, host FROM events "
                        "WHERE artifact = 'suricata' AND log_channel = 'alert'").fetchone()
    assert alert[:5] == (1715691309776777, "185.199.110.42", "80", "2002677", "alert")
    assert alert[5].startswith("Alert: ET SCAN Nikto Web App Scan in Progress (Web Application Attack, severity 1)")
    assert alert[6] == "SENSOR"
    x509 = con.execute("SELECT message FROM events WHERE log_channel = 'x509'").fetchone()[0]
    con.close()
    assert x509 == "x509: CN=styles.fullstory.co"
    statuses = {(g["key"], g["host"]): g["status"] for g in found_outputs(case, specs, {})}
    assert statuses[("zeek", "ZEEK")] == statuses[("suricata_eve", "SENSOR")] == "loaded"


def test_zeek_logs_with_underscore_names_load_their_endpoints_and_name_a_pe_files_sections(tmp_path):
    """A Zeek export that writes id_orig_h, id_orig_p, id_resp_h, id_resp_p, and certificate_subject fills the same
    event fields and message parts as id.orig_h and the rest. A pe record's message names its sections."""
    conn = {"ts": 1715688048.855508, "uid": "CrVLu", "id_orig_h": "10.44.10.22", "id_orig_p": 53712,
            "id_resp_h": "10.44.20.10", "id_resp_p": 53, "proto": "udp", "service": "dns", "duration": 0.004043,
            "conn_state": "SF"}
    pe = {"ts": 1715688240.585, "id": "FpE1", "machine": "AMD64", "os": "Windows XP x64 or Server 2003",
          "subsystem": "WINDOWS_CUI", "is_exe": True, "is_64bit": True, "section_names": ["UPX0", "UPX1", ".rsrc"]}
    x509 = {"ts": 1715688240.585, "id": "FqWDuc7", "fingerprint": "abc", "certificate_subject": "CN=styles.fullstory.co"}
    ev = tmp_path / "evidence"
    (ev / "ZEEK").mkdir(parents=True)
    for name, record in (("conn", conn), ("pe", pe), ("x509", x509)):
        (ev / "ZEEK" / f"{name}.json").write_text(json.dumps(record) + "\n", encoding="utf-8")
    case = create_case(tmp_path / "case", "Network", ev, "cody")
    intake(case)
    group = next(g for g in found_outputs(case, load_registry(), {}) if g["key"] == "zeek")
    assert [(r.status, r.loaded_rows) for r in load_group(case, group)] == [("ok", 1)] * 3
    with connect(case.db_path) as con:
        found = con.execute("SELECT log_channel, source_ip, source_port, dest_ip, dest_port, message FROM events "
                            "WHERE artifact = 'zeek'").fetchall()
    rows = {channel: rest for channel, *rest in found}
    assert rows["conn"] == ["10.44.10.22", "53712", "10.44.20.10", "53",
                            "conn: 10.44.10.22:53712 -> 10.44.20.10:53 udp dns SF"]
    assert rows["pe"][4] == 'pe: AMD64 sections ["UPX0", "UPX1", ".rsrc"]'
    assert rows["x509"][4] == "x509: CN=styles.fullstory.co"


def test_a_zeek_tsv_pe_log_names_its_sections_as_zeek_wrote_them(tmp_path):
    """A tab-separated pe.log writes section_names joined with its set separator, a comma, and "(empty)" for none, so
    the message shows the sections comma-separated and leaves the part out when there are none."""
    pe_tsv = ("#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n#path\tpe\n"
              "#fields\tts\tid\tmachine\tsection_names\n"
              "#types\ttime\tstring\tstring\tvector[string]\n"
              "1715688240.585000\tFpE1\tAMD64\tUPX0,UPX1,.rsrc\n"
              "1715688241.585000\tFpE2\tAMD64\t(empty)\n")
    ev = tmp_path / "evidence"
    (ev / "ZEEK").mkdir(parents=True)
    (ev / "ZEEK" / "pe.log").write_text(pe_tsv, encoding="utf-8", newline="\n")
    case = create_case(tmp_path / "case", "Network", ev, "cody")
    intake(case)
    group = next(g for g in found_outputs(case, load_registry(), {}) if g["key"] == "zeek")
    assert [(r.status, r.loaded_rows) for r in load_group(case, group)] == [("ok", 2)]
    with connect(case.db_path) as con:
        found = con.execute("SELECT message FROM events WHERE artifact = 'zeek' ORDER BY ts_us").fetchall()
    messages = [message for (message,) in found]
    assert messages == ["pe: AMD64 sections UPX0,UPX1,.rsrc", "pe: AMD64"]


def test_a_failed_group_member_does_not_hide_a_committed_load(tmp_path):
    """A group of found output fails when any of its runs does, and App.after_job builds the derived tables again even
    after a step that failed. A Zeek folder whose weird.log holds only its header fails that log's import, with no
    evidence changed and the job going on, while conn.log's events commit: the case gets a host, hits, and saved
    searches for them without being opened again."""
    import time

    from glessner.server import App
    from glessner.toolbox import start_load_job

    ev = tmp_path / "evidence"
    (ev / "ZEEK").mkdir(parents=True)
    (ev / "ZEEK" / "conn.log").write_text(ZEEK_TSV, encoding="utf-8", newline="\n")
    header = "".join(line + "\n" for line in ZEEK_TSV.replace("#path\tconn", "#path\tweird").splitlines()
                     if line.startswith("#"))
    (ev / "ZEEK" / "weird.log").write_text(header, encoding="utf-8", newline="\n")
    case = create_case(tmp_path / "case", "Network", ev, "cody")
    intake(case)
    app = App(case)
    try:
        loads = app.loads
        job = start_load_job(case, load_registry(), {}, "zeek", None, False, app.after_job)
        for _ in range(200):
            if job.finished:
                break
            time.sleep(0.05)
        state = job.state()
        assert [(r["status"], r["rows"], r["loaded"]) for r in state["results"]] == [("failed", 2, True)], state
        assert "weird.log" in state["results"][0]["reason"] and not state["error"]
        assert app.loads == loads + 1 and "ZEEK" in app.identity.hosts
    finally:
        app.con.close()


def test_an_import_whose_check_cannot_re_read_its_file_is_not_called_changed(tmp_path, monkeypatch):
    """An import whose check before or after the read can't read its file, as when another program holds it open,
    compared no hash, so it fails saying the file could not be re-read, not that the file doesn't match or changed, and
    a load of found output goes on to the next host's logs."""
    from test_runner import finish, refuse_reads

    from glessner import imports
    from glessner.imports import run_import
    from glessner.toolbox import start_load_job

    ev = tmp_path / "evidence"
    for host, name in (("ZEEK1", "conn"), ("ZEEK2", "dns")):
        (ev / host).mkdir(parents=True)
        (ev / host / f"{name}.log").write_text(ZEEK_TSV.replace("#path\tconn", f"#path\t{name}"), encoding="utf-8",
                                               newline="\n")
    case = create_case(tmp_path / "case", "Network", ev, "cody")
    intake(case)
    with monkeypatch.context() as m:
        refuse_reads(m, "conn.log")
        job = finish(start_load_job(case, load_registry(), {}, "zeek", None, False, lambda job: None))
    assert job.error == ""
    assert [(r["host"], r["status"], r["evidence"]) for r in job.results] == [("ZEEK1", "failed", "unreadable"),
                                                                              ("ZEEK2", "ok", "ok")]
    with monkeypatch.context() as m:
        refuse_reads(m, "conn.log")
        record = run_import(case, "ZEEK1/conn.log", {"preset": "zeek"}, zones={})
    assert (record.status, record.evidence_check, record.loaded_rows) == ("failed", "unreadable", None)
    assert record.reason == ("the check before the import could not re-read 1 file, so it compared no hash with "
                             "intake's: ZEEK1/conn.log: unreadable (Permission denied). Another program, such as "
                             "antivirus, may have held it open; import it again.")
    with monkeypatch.context() as m:
        real = imports.load_import

        def load_then_hold(*args):
            real(*args)
            refuse_reads(m, "conn.log")
        m.setattr(imports, "load_import", load_then_hold)
        record = run_import(case, "ZEEK1/conn.log", {"preset": "zeek"}, zones={})
    assert (record.status, record.evidence_check, record.loaded_rows) == ("failed", "unreadable", 2)
    assert record.reason.startswith("the check after the import could not re-read 1 file, so it compared no hash")


def test_a_fault_after_a_group_member_committed_still_refreshes_the_case(tmp_path, monkeypatch):
    """A group's step result, which says a load committed, is recorded only once the whole group has loaded. When a
    later member raises what its import doesn't catch, after an earlier member's load committed, the job ends with the
    error and no result, and after_job still refreshes the case: conn.log's events get their host without the case
    being opened again. RecursionError stands in for such a fault, as from a deeply nested record."""
    import time

    from glessner import imports
    from glessner.server import App
    from glessner.toolbox import start_load_job

    ev = tmp_path / "evidence"
    (ev / "ZEEK").mkdir(parents=True)
    for name in ("conn", "dns"):
        (ev / "ZEEK" / f"{name}.log").write_text(ZEEK_TSV.replace("#path\tconn", f"#path\t{name}"), encoding="utf-8",
                                                newline="\n")
    case = create_case(tmp_path / "case", "Network", ev, "cody")
    intake(case)
    real = imports.load_import

    def load_import(case, record, folder):
        if record.inputs[0].endswith("dns.log"):
            raise RecursionError("maximum recursion depth exceeded")
        return real(case, record, folder)

    monkeypatch.setattr(imports, "load_import", load_import)
    app = App(case)
    try:
        loads = app.loads
        job = start_load_job(case, load_registry(), {}, "zeek", None, False, app.after_job)
        for _ in range(200):
            if job.finished:
                break
            time.sleep(0.05)
        state = job.state()
        assert state["results"] == [] and state["error"].startswith("RecursionError"), state
        assert app.reader().execute("SELECT count(*) FROM events WHERE host = 'ZEEK'").fetchone()[0] == 2   # conn.log's
        assert app.loads == loads + 1 and "ZEEK" in app.identity.hosts
    finally:
        app.con.close()
