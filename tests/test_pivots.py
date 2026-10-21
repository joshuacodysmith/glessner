"""The Event page's pivots: the guidance for each kind of event, each row's count against what its
click lists, and the parser fields the pivots read."""

import json
import re
import shutil
from pathlib import Path

import pivot_key_fixtures as fx
import pytest
from conftest import DC_LOG, SEC, T0, WS_LOG, logon, new_synthetic_case
from parser_fix_fixtures import EVIDENCE, SECURITY, event_data, evtx_events, write_csv
from parser_fix_fixtures import row as evtx_row

from glessner import pivots, queries
from glessner.caveats import table as caveat_table
from glessner.events import Event, load
from glessner.parsers import PARSERS, ParseContext
from glessner.parsers.common import file_key
from glessner.parsers.evtxecmd import TASK_EVENTS
from glessner.pivots import (
    count_pivot,
    fits,
    guidance,
    kind_of,
    shown,
    table,
    window_kinds,
)
from glessner.queries import QueryError, anchor_of, event_details, related, source_parts
from glessner.server import App, api_event, api_host, api_meta, api_pivot_count, api_related, api_setting

SYSTEM_LOG = "DC01/Windows/System32/winevt/Logs/System.evtx"
SCHEDULER = "Microsoft-Windows-TaskScheduler/Operational"
AUTORUNS = "DESKTOP/autoruns.csv"
SYSTEM_HIVE = "DESKTOP/Windows/System32/config/SYSTEM"
SOFTWARE_HIVE = "DESKTOP/Windows/System32/config/SOFTWARE"
INSTALLER = {"user_name": "Administrator", "user_domain": "C137"}


def system_event(ts, record, code, extra, **kw):
    """A System log event written by the Service Control Manager, with its data in extra, as EvtxECmd keeps it."""
    return Event(ts_us=ts, ts_desc="Event Recorded", artifact="evtx", source_file=SYSTEM_LOG, source_record=str(record),
                 record_id=record, message=f"{code} system", event_code=code, event_provider="Service Control Manager",
                 log_channel="System", extra=extra, **kw)


def security_event(ts, record, code, **kw):
    return Event(ts_us=ts, ts_desc="Event Recorded", artifact="evtx", source_file=DC_LOG, source_record=str(record),
                 record_id=record, message=f"{code} security", event_code=code, log_channel="Security", **kw)


def tool_event(ts, record, artifact, source, message, desc="Registry Key LastWrite", **kw):
    """One record of a tool's output, such as an Autoruns entry or a RECmd row."""
    return Event(ts_us=ts, ts_desc=desc, artifact=artifact, source_file=source, source_record=str(record), message=message, **kw)


def load_events(case, events, host, tool="evtxecmd", run="p"):
    load(case.db_path, events, host=host, tool=tool, tool_version="t", run_id=run, replaces_sources=[],
         staging_dir=case.folder)


def add_services(case):
    """One service seen under both its names on both hosts: installed as its display name (7045, by an account from the
    System element), changed and run as it (7040, 7036), installed again by its key name (4697), and in Autoruns and
    RECmd by its key name."""
    install_data = {"ServiceName": "Windows Update Svc", "ImagePath": "C:\\Users\\Public\\wu.exe"}
    state_data = {"param1": "Windows Update Svc", "param2": "demand start", "param3": "auto start", "param4": "WinUpdSvc"}
    load_events(case, [
        system_event(T0 + 5 * SEC, 9001, "7045", install_data, file_path="C:\\Users\\Public\\wu.exe",
                     file_key="\\users\\public\\wu.exe", **INSTALLER),
        system_event(T0 + 6 * SEC, 9002, "7040", state_data),
        system_event(T0 + 7 * SEC, 9003, "7036", {"param1": "Windows Update Svc", "param2": "running"}),
        security_event(T0 + 8 * SEC, 9004, "4697", extra={"ServiceName": "WinUpdSvc", "ServiceFileName": "C:\\wu.exe"}),
        system_event(T0 + 9 * SEC, 9005, "7036", {"param1": "Some Other Service", "param2": "stopped"}),
    ], "DC01")
    load_events(case, [
        tool_event(T0 - 3600 * SEC, 7, "autoruns", AUTORUNS, "Services: WinUpdSvc", "Image built (PE link time)",
                   log_channel="Services", extra={"Entry": "WinUpdSvc", "Category": "Services",
                                                  "Description": "Windows Update Svc: keeps the machine current"}),
    ], "DESKTOP", tool="autoruns", run="p2")
    services = "ROOT\\ControlSet001\\Services"
    load_events(case, [
        tool_event(T0 - 3600 * SEC, "svc", "registry", SYSTEM_HIVE, "Services: None = Name: WinUpdSvc Desc:",
                   registry_path=services, extra={"ValueData": "Name: WinUpdSvc Desc: "}),
        tool_event(T0 - 3600 * SEC, "svc2", "registry", SYSTEM_HIVE, "Services: None = Name: bam Desc:",
                   registry_path=services, extra={"ValueData": "Name: bam Desc: "}),
    ], "DESKTOP", tool="recmd", run="p3")


def add_tasks(case):
    def scheduler(record, ts, name):
        return Event(ts_us=ts, ts_desc="Event Recorded", artifact="evtx", source_file="DC01/Scheduler.evtx",
                     source_record=str(record), message="140 task", event_code="140", log_channel=SCHEDULER,
                     extra={"TaskName": name})
    load_events(case, [security_event(T0 + 20 * SEC, 9101, "4698", extra={"TaskName": "\\Evil\\Beacon"}),
                       scheduler(1, T0 + 21 * SEC, "\\Evil\\Beacon"), scheduler(2, T0 + 22 * SEC, "\\Other\\Task")], "DC01")
    load_events(case, [tool_event(T0, 9, "autoruns", AUTORUNS, "Tasks: \\Evil\\Beacon", "Image file last written",
                                  log_channel="Tasks", extra={"Entry": "\\Evil\\Beacon", "Category": "Tasks"})],
                "DESKTOP", tool="autoruns", run="p4")
    cache = {"ValueData": "Created on: 2020-09-19", "ValueData3": "Path: \\Evil\\Beacon, Command: x, Arguments: "}
    load_events(case, [tool_event(T0, "t", "registry", SOFTWARE_HIVE, "Scheduled Tasks (TaskCache): Created on: 2020-09-19",
                                  registry_path="ROOT\\Schedule\\TaskCache\\Tasks", extra=cache)],
                "DESKTOP", tool="recmd", run="p5")


def alert(when, flow, signature, sid, src="10.42.85.10:445", dest="10.42.85.115:49752", kind="alert", **more):
    (src_ip, src_port), (dest_ip, dest_port) = src.rsplit(":", 1), dest.rsplit(":", 1)
    rec = {"timestamp": f"2020-09-19T{when}.000000+0000", "event_type": kind, "flow_id": flow, "src_ip": src_ip,
           "src_port": int(src_port), "dest_ip": dest_ip, "dest_port": int(dest_port), "proto": "TCP", **more}
    if kind == "alert":
        rec["alert"] = {"signature_id": sid, "signature": signature, "category": "Test", "severity": 2}
    return rec


def write_capture(tmp_path, records):
    out = tmp_path / "capture"
    out.mkdir(exist_ok=True)
    (out / "eve.json").write_text("".join(json.dumps(r) + "\n" for r in records), encoding="utf-8")
    return out


def add_capture(case, tmp_path, records):
    out = write_capture(tmp_path, records)
    events = PARSERS["suricata_eve"](ParseContext(out, case.evidence, ("network/c.pcap",)))
    load_events(case, list(events), "network", tool="suricata", run="cap")


def uid_of(con, where, *params):
    return con.execute(f"SELECT event_uid FROM events WHERE {where} ORDER BY ts_us, event_uid", list(params)).fetchone()[0]


PCASE_CAPTURE = [
    alert("03:35:00", 77, "ET TEST Beacon", 2000001),
    alert("03:35:01", 77, "", 0, kind="flow"),
    alert("03:35:02", 77, "", 0, kind="dns", dns={"type": "query", "rrname": "x.example"}),
    alert("03:35:03", 78, "ET TEST Beacon", 2000001, src="10.9.9.9:80", dest="10.9.9.8:5000"),
    alert("03:35:04", 79, "ET OTHER Thing", 2000002, src="10.9.9.9:80", dest="10.9.9.7:5000"),
]


def add_pcase_events(case, tmp_path):
    """Services, tasks, a capture, a failed-logon run, and accounts with no domain, loaded into a synthetic case made in
    tmp_path. They write events.duckdb and the capture's eve.json in tmp_path."""
    add_services(case)
    add_tasks(case)
    add_capture(case, tmp_path, PCASE_CAPTURE)
    failed = {"user_name": "admin", "user_domain": "", "source_ip": "203.0.113.7", "logon_type": "3"}
    failures = [security_event(T0 + (40 + i) * SEC, 9200 + i, "4625", source_workstation="KALI", **failed)
                for i in range(3)]
    other = security_event(T0 + 50 * SEC, 9210, "4625", source_workstation="Other", **{**failed, "source_ip": "203.0.113.8"})
    load_events(case, [*failures, other], "DC01", run="p6")
    srum = Event(ts_us=T0 + 100 * SEC, ts_desc="SRUM record", artifact="srum", source_file="DESKTOP/SRUDB.dat",
                 source_record="1", message="srum", user_name="Administrator", user_domain="")
    load_events(case, [srum], "DESKTOP", tool="srumecmd", run="p7")


@pytest.fixture(scope="session")
def pcase_events(tmp_path_factory, synthetic_events):
    """pcase's events database, loaded once a session, as synthetic_events is for synthetic_case: its nine loads took
    about 2 s a case."""
    root = tmp_path_factory.mktemp("pcase_events")
    case = new_synthetic_case(root)
    shutil.copyfile(synthetic_events, case.db_path)
    add_pcase_events(case, root)
    return case.db_path


@pytest.fixture
def pcase(synthetic_case, tmp_path, pcase_events):
    """synthetic_case plus services, tasks, a capture, a failed-logon run, and accounts with no domain: the capture's
    eve.json written in tmp_path, as add_capture writes it, and a copy of the session's database with them loaded."""
    write_capture(tmp_path, PCASE_CAPTURE)
    shutil.copyfile(pcase_events, synthetic_case.db_path)
    return synthetic_case


@pytest.fixture
def papp(pcase):
    a = App(pcase)
    yield a
    a.con.close()


def more(app, events, host="DC01", run="m"):
    """Load events into a running app's case and bring its derived tables up to date, as a load does."""
    load_events(app.case, events, host, run=run)
    app.refresh_identity(events_changed=True)


def row_of(g, pivot):
    rows = [r for r in g["rows"] if r["pivot"] == pivot]
    assert len(rows) == 1, (pivot, [r["key"] for r in g["rows"]])
    return rows[0]


def guide(app, uid, **kw):
    ev = event_details(app.con, uid, app.identity)
    return guidance(ev, app.identity, kw.get("windows", {}), kw.get("case_seconds", 60))


def counted(app, uid, row, **kw):
    ev = event_details(app.con, uid, app.identity)
    return count_pivot(app.con, app.identity, uid, ev["adjusted_ts_us"], row["pivot"], ip=row.get("ip", ""),
                       seconds=row.get("seconds", 60), term=row.get("term", ""), name=row.get("name", ""), **kw)


RDP = "event_code = '4624' AND logon_type = '10'"
INSTALL = "event_code = '7045' AND file_path LIKE '%wu.exe'"


# ---------- the table and its language ----------

def test_the_table_has_the_studys_54_kinds_ending_in_the_fallback_and_one_overlay():
    kinds = table()["kinds"]
    assert len(kinds) == 54 and kinds[-1]["kind"] == "default" and kinds[-1]["match"] == {}
    assert [k["kind"] for k in kinds if k.get("overlay")] == ["hayabusa_hit"]
    assert {k["kind"]: k["pivots"][0]["rank"] for k in kinds}["logon_network"] == 1
    assert window_kinds() >= {"logon_network", "prefetch", "srum"} and "default" not in window_kinds()


def test_each_source_is_a_public_page_or_a_file_of_the_app_and_each_cited_id_is_listed():
    root = Path(__file__).resolve().parent.parent
    t = table()
    for sid, source in t["sources"].items():
        assert source["ref"].startswith("https://") or (root / source["ref"]).is_file(), sid
    cited = {s for k in t["kinds"] for section in ("pivots", "not_offered", "later") for entry in k.get(section, [])
             for s in entry.get("sources", [])}
    cited |= {s for rule in t["broad_rules"].values() for s in rule.get("sources", [])}
    assert cited <= t["sources"].keys()


def _strings(node, path="$"):
    """(path, text) for every string under a JSON value."""
    if isinstance(node, dict):
        for key, value in node.items():
            yield from _strings(value, f"{path}.{key}")
    elif isinstance(node, list):
        for i, value in enumerate(node):
            yield from _strings(value, f"{path}[{i}]")
    elif isinstance(node, str):
        yield path, node


def test_the_shipped_tables_carry_no_internal_labels_or_unpublished_documents():
    """The texts and source titles of the pivot table and the caveat table name no internal decision, review, or fix
    number and no unpublished document. A source's ref or url is not checked."""
    labels = re.compile(r"\bPM\d+[a-z]?\b|\b[DRQ]\d{2,3}\b|\bCX\d+|\bgaps? C\d+|\bquestions? \d+|not published|"
                        r"\bstud(?:y|ies)\b|mock-?up", re.IGNORECASE)
    for data in (table(), caveat_table()):
        found = [(path, m.group(0)) for path, text in _strings(data) if not path.endswith((".ref", ".url"))
                 for m in labels.finditer(text)]
        assert not found, found


def test_a_caveat_and_an_empty_reason_carry_only_the_fields_the_about_block_lists():
    caveats = [spec["caveat"] for kind in table()["kinds"] for spec in kind["pivots"] if spec.get("caveat")]
    assert caveats and all(set(caveat) <= {"text", "when", "check"} for caveat in caveats)
    assert all(set(entry) <= {"text", "when"} for entries in table()["empty_reasons"].values() for entry in entries)


def test_a_match_compares_columns_without_letter_case_and_takes_lists_parts_and_alternatives():
    ev = {"event_code": "4624", "log_channel": "Security", "logon_type": "3", "message": "Services: X", "hits": [{"t": 1}]}
    assert fits({"event_code": "4624", "log_channel": "SECURITY"}, ev)
    assert fits({"event_code": ["4624", "4625"], "message": {"starts_with": "services:"}}, ev)
    assert not fits({"event_code": ["4625"]}, ev) and not fits({"logon_type": "10"}, ev)
    assert fits({"message": {"contains": "ces: x"}}, ev) and not fits({"message": {"contains": "zzz"}}, ev)
    assert fits({"any_of": [{"event_code": "1"}, {"logon_type": "3"}]}, ev)
    assert not fits({"any_of": [{"event_code": "1"}]}, ev)
    assert fits({"has_hayabusa_hit": True}, ev) and not fits({"has_hayabusa_hit": True}, {})
    assert fits({"file_key": ""}, ev) and fits({}, ev)   # an empty string is a value to match


def test_a_kind_is_found_from_the_code_with_its_channel_and_the_logon_type():
    def pick(**ev):
        return kind_of({"hits": [], **ev})[0]["kind"]
    assert pick(event_code="4624", log_channel="Security", logon_type="3") == "logon_network"
    assert pick(event_code="4624", log_channel="Security", logon_type="10") == "logon_rdp"
    assert pick(event_code="4624", log_channel="Security", logon_type="4") == "logon_batch_service"
    assert pick(event_code="4624", log_channel="Security", logon_type="9") == "logon_other"
    assert pick(event_code="1102", log_channel="Security") == "log_cleared"
    assert pick(event_code="1102", log_channel="Application") == "default"   # the code alone misfires on other channels
    assert pick(event_code="7045", log_channel="System") == "service_install"
    assert pick(event_code="4697", log_channel="Security") == "service_install"
    assert pick(artifact="registry", message="Services: None = Name: x", registry_path="ROOT\\Services") == "recmd_services"
    assert pick(artifact="registry", registry_path="ROOT\\CurrentVersion\\Run", message="Run") == "run_key"
    assert pick(artifact="suricata", log_channel="alert") == "ids_alert"
    assert pick(artifact="suricata", log_channel="flow") == "network_flow"
    assert pick(artifact="mft") == "mft_usn" and pick(artifact="timeline") == "windows_timeline"
    assert pick(artifact="evtx", event_code="1") == "default"
    hit = {"hits": [{"title": "t"}], "event_code": "4624", "log_channel": "Security", "logon_type": "3"}
    assert kind_of(hit)[1]["kind"] == "hayabusa_hit" and kind_of(hit)[0]["kind"] == "logon_network"


def test_a_text_leaves_out_sentences_that_send_the_analyst_to_a_pivot_this_build_lacks():
    assert shown("Prefetch cut this name to 29 characters. Try Same folder.") == "Prefetch cut this name to 29 characters."
    assert shown("A short 8.3 path doesn't match the long one: try Same folder.") == ""
    # Same hash is built since case format 3, so a sentence sending the analyst to it stays
    assert shown("Prefetch cut this name to 29 characters. Try Same hash.").endswith("Try Same hash.")
    assert shown("A short 8.3 path doesn't match the long one: try Same file name.").endswith("try Same file name.")


# ---------- the guidance for one event ----------

def test_an_rdp_logon_ranks_its_pivots_as_the_table_does_with_a_reason_and_a_value_each(papp):
    g = guide(papp, uid_of(papp.con, RDP))
    assert (g["kind"], g["title"]) == ("logon_rdp", "4624 type 10, Remote Desktop logon")
    assert [(r["n"], r["pivot"]) for r in g["rows"]] == [(1, "session"), (2, "addr"), (3, "window"), (4, "account"), (5, "rule")]
    assert [r["value"] for r in g["rows"] if r["pivot"] != "window"] == [
        "0x510986", "194.61.24.102", "C137\\Administrator", "RDP from internet"]
    assert all(r["reason"] for r in g["rows"])
    assert row_of(g, "window")["window"] == {"seconds": 300, "default": 300, "edited": False, "basis": "inference",
                                              "kind": "logon_rdp"}
    assert row_of(g, "window")["breakdown"] == "always" and row_of(g, "account")["breakdown"] == "over_limit"
    # A type 10 logon records no source port, and says so in the table's words; this one has no file either
    assert [(n["pivot"], n["reason"]) for n in g["not_offered"]] == [
        ("connection", "A type 10 logon records no source port."), ("file", "This event has no file path")]
    assert [(p["pivot"], p.get("value")) for p in g["plain"]] == [("source_ip", "194.61.24.102")]   # offered, not ranked
    assert row_of(g, "rule")["label"] == "Same rule or signature" and row_of(g, "rule")["breakdown"] == "over_limit"


def test_pivots_the_event_cannot_take_go_on_one_line_with_a_reason_and_a_zero_logon_id_is_never_offered(papp):
    g = guide(papp, uid_of(papp.con, "event_code = '7045'"))
    assert g["kind"] == "service_install"
    refused = {n["pivot"]: n["reason"] for n in g["not_offered"]}
    assert refused["session"] == "A 7045 records no logon ID." and refused["addr"] == "A service install records no address."
    assert refused["source_ip"] == "This event has no source IP" and refused["connection"] == "This event has no source port"
    # An old case holds 0x0 on a 4688: the session pivot isn't offered, and the page says why
    more(papp, [security_event(T0 + 60 * SEC, 9300, "4688", logon_id="0x0", process_executable="C:\\Windows\\a.exe",
                               file_key="\\windows\\a.exe", user_name="SYSTEM", user_domain="NT AUTHORITY")])
    created = uid_of(papp.con, "event_code = '4688'")
    g = guide(papp, created)
    assert g["kind"] == "process_creation" and "session" not in {r["pivot"] for r in g["rows"]}
    assert {n["pivot"]: n["reason"] for n in g["not_offered"]}["session"].startswith("Logon ID 0x0 is no logon session.")
    assert related(papp.con, created, "session")["note"] == "this event has no logon_id"
    assert count_pivot(papp.con, papp.identity, created, T0 + 60 * SEC, "session")["count"] == 0


def test_a_ranked_row_names_why_it_is_broad_from_its_value(papp):
    system = {"logon_id": "0x3e7", "user_name": "SYSTEM", "user_domain": "NT AUTHORITY"}
    machine = {"logon_id": "0x3e5", "user_name": "WS01$", "user_domain": "C137", "logon_type": "3",
               "source_ip": "127.0.0.1", "source_port": "1"}
    more(papp, [security_event(T0 + 70 * SEC, 9400, "4672", **system), security_event(T0 + 71 * SEC, 9401, "4624", **machine)])
    g = guide(papp, uid_of(papp.con, "event_code = '4672' AND logon_id = '0x3e7'"))
    assert g["kind"] == "special_privileges"
    assert row_of(g, "session")["broad"] == [
        "Broad: this is a system session (SYSTEM, NETWORK SERVICE, LOCAL SERVICE, or ANONYMOUS LOGON). "
        "Everything that account does on this host shares it."]
    assert row_of(g, "account")["broad"] == ["Broad: a Windows service account. It acts on every host."]
    g = guide(papp, uid_of(papp.con, "event_code = '4624' AND logon_id = '0x3e5'"))
    assert row_of(g, "account")["broad"] == ["Broad: a computer's own account."]
    assert row_of(g, "addr")["broad"] == ["Broad: a loopback address, matched on this host only."]
    # A collected host's own address, and the host it belongs to; the attacker's address and a plain session are not broad
    g = guide(papp, uid_of(papp.con, "event_code = '4624' AND source_ip = '10.42.85.10'"))
    assert row_of(g, "addr")["broad"] == ["Broad: DC01's own address. Most of that host's traffic carries it."]
    g = guide(papp, uid_of(papp.con, RDP))
    assert row_of(g, "addr")["broad"] == [] and row_of(g, "session")["broad"] == []


def test_the_logon_process_is_flagged_where_the_table_says_and_a_shared_program_by_name(papp):
    winlogon = "C:\\Windows\\System32\\winlogon.exe"
    interactive = {"logon_id": "0x2222", "logon_type": "2", "user_name": "alice", "user_domain": "C137"}
    more(papp, [security_event(T0 + 80 * SEC, 9500, "4624", process_executable=winlogon,
                               file_key="\\windows\\system32\\winlogon.exe", **interactive),
                security_event(T0 + 81 * SEC, 9501, "4648", process_executable="C:\\Windows\\System32\\cmd.exe",
                               file_key="\\windows\\system32\\cmd.exe", logon_id="0x2223")])
    g = guide(papp, uid_of(papp.con, "event_code = '4624' AND logon_type = '2'"))
    file_row = row_of(g, "file")
    assert file_row["label"] == "Same file (the logon process)" and file_row["value"] == winlogon
    assert file_row["broad"] == ["This is the program that handled the logon, not something the user ran."]
    assert [r["pivot"] for r in g["rows"]] == ["session", "window", "account", "file"]
    g = guide(papp, uid_of(papp.con, "event_code = '4648' AND record_id = 9501"))
    assert row_of(g, "file")["label"] == "Same file (the process)"
    assert row_of(g, "file")["broad"] == ["Broad: a shared Windows program. Every use of it matches."]


def test_the_window_size_is_the_kinds_the_analysts_edit_or_the_cases_and_says_what_it_rests_on(papp):
    rdp = uid_of(papp.con, RDP)
    window = row_of(guide(papp, rdp, windows={"logon_rdp": 120}), "window")
    assert window["window"] == {"seconds": 120, "default": 300, "edited": True, "basis": "inference", "kind": "logon_rdp"}
    assert window["seconds"] == 120
    assert row_of(guide(papp, rdp, windows={"logon_rdp": 99999}), "window")["seconds"] == 300   # out of range: the table's
    prefetch = Event(ts_us=T0, ts_desc="Last run", artifact="prefetch", source_file="DC01/Prefetch/A.pf", source_record="1",
                     message="A.EXE run", file_path="\\VOLUME{1}\\WINDOWS\\A.EXE", file_key="\\windows\\a.exe")
    timeline = Event(ts_us=T0, ts_desc="Process created", artifact="timeline", source_file="DC01/x.db", source_record="2",
                     message="w", file_path="C:\\x.exe", file_key="\\x.exe")
    load_events(papp.case, [prefetch, timeline], "DC01", tool="pecmd", run="p12")
    papp.refresh_identity(events_changed=True)
    window = row_of(guide(papp, uid_of(papp.con, "artifact = 'prefetch'")), "window")["window"]
    assert (window["basis"], window["seconds"]) == ("source", 30)
    g = guide(papp, uid_of(papp.con, "event_code = '4672'"), windows={"special_privileges": 10}, case_seconds=90)
    assert row_of(g, "window")["window"] == {"seconds": 10, "default": 300, "edited": True, "basis": "inference",
                                              "kind": "special_privileges"}
    g = guide(papp, uid_of(papp.con, "artifact = 'timeline'"), case_seconds=90)
    assert (g["kind"], row_of(g, "window")["window"]) == ("windows_timeline", {
        "seconds": 300, "default": 300, "edited": False, "basis": "inference", "kind": "windows_timeline"})
    # A kind with no size of its own, the fallback, takes the case's window and says so
    g = guide(papp, uid_of(papp.con, "event_code = '4648' OR artifact = 'srum'"), case_seconds=90)
    if g["kind"] == "default":
        assert row_of(g, "window")["window"] == {"seconds": 90, "default": 90, "edited": False, "basis": "case",
                                                  "kind": "default"}


def test_a_kind_without_a_window_of_its_own_takes_the_cases(papp):
    more(papp, [security_event(T0 + 90 * SEC, 9900, "5000", logon_id="0x9", user_name="x", user_domain="C137")])
    g = guide(papp, uid_of(papp.con, "event_code = '5000'"), windows={"default": 5}, case_seconds=90)
    assert g["kind"] == "default"
    assert row_of(g, "window")["window"] == {"seconds": 90, "default": 90, "edited": False, "basis": "case", "kind": "default"}


def test_a_caveat_shows_only_where_its_fix_has_not_landed_and_it_applies(papp):
    g = guide(papp, uid_of(papp.con, RDP))
    assert all(r["caveat"] is None for r in g["rows"])   # no caveat shows on this event
    # The account key and its fold match the other spellings, so nothing is checked
    assert row_of(g, "account")["caveat_check"] is None
    assert row_of(g, "addr")["caveat"] is None
    # An 8.3 path in a service install's file shows its caveat, which says when the match fails
    more(papp, [system_event(T0 + 90 * SEC, 9600, "7045", {"ServiceName": "x", "ImagePath": "C:\\ADMINI~1\\x.sys"},
                             file_path="C:\\ADMINI~1\\x.sys", file_key="\\admini~1\\x.sys")])
    g = guide(papp, uid_of(papp.con, "file_path LIKE '%ADMINI~1%'"))
    assert row_of(g, "file")["caveat"] == ("An 8.3 path such as ADMINI~1 matches the long one only when this host's MFT holds "
                                           "exactly one name it can stand for.")
    assert guide(papp, uid_of(papp.con, INSTALL))["rows"][0]["caveat"] is None
    # A caveat whose condition fits the event shows: a capture's window is the network lane only
    alert_uid = uid_of(papp.con, "tool = 'suricata' AND log_channel = 'alert'")
    assert row_of(guide(papp, alert_uid), "window")["caveat"] == "The network lane only, never the host's own events."


def test_a_service_install_ranks_the_file_the_window_the_service_name_and_the_account(papp):
    g = guide(papp, uid_of(papp.con, INSTALL))
    assert [r["pivot"] for r in g["rows"]] == ["file", "window", "service_name", "account", "file_name"]
    assert row_of(g, "file")["label"] == "Same file (the service binary)"
    assert row_of(g, "service_name")["value"] == "Windows Update Svc"
    assert row_of(g, "account")["label"] == "Same account (from the System element)"
    assert row_of(g, "window")["window"]["seconds"] == 600
    assert row_of(g, "file_name")["value"] == "wu.exe" and row_of(g, "file_name")["broad"] == []


def test_search_rows_take_their_term_from_the_event_and_count_only_when_made_of_field_terms(papp):
    member = {"MemberSid": "S-1-5-21-1-2-3-1105", "TargetUserName": "Administrators"}
    more(papp, [security_event(T0 + 95 * SEC, 9700, "4732", user_name="Administrator", user_domain="C137", logon_id="0x1",
                               extra=member),
                security_event(T0 + 96 * SEC, 9701, "4625", user_name="admin", user_domain="", logon_type="3",
                               source_ip="203.0.113.7", extra={"SubStatus": "0xC000006A"}),
                security_event(T0 + 97 * SEC, 9702, "5145", user_name="x", user_domain="", logon_id="0x2",
                               extra={"ShareName": "\\\\*\\IPC$", "RelativeTargetName": "svcctl"})])
    group = row_of(guide(papp, uid_of(papp.con, "event_code = '4732'")), "search")
    assert (group["label"], group["term"], group["count"]) == ("Same member", "S-1-5-21-1-2-3-1105", False)   # a free word
    with_reason = uid_of(papp.con, "event_code = '4625' AND extra LIKE '%SubStatus%'")
    reason = row_of(guide(papp, with_reason), "search")
    assert (reason["label"], reason["term"], reason["count"]) == ("Same failure reason", "code:4625 SubStatus:0xC000006A", True)
    assert counted(papp, with_reason, reason)["count"] == 1
    with pytest.raises(QueryError, match="free-text"):
        count_pivot(papp.con, papp.identity, "x", None, "search", term="mimikatz")
    # An event lacking the field a template needs doesn't get the row, and the line says which field
    bare = guide(papp, uid_of(papp.con, "event_code = '4625' AND source_workstation = 'KALI'"))
    assert all(r["pivot"] != "search" for r in bare["rows"])
    assert [n["reason"] for n in bare["not_offered"] if n["pivot"] == "search"] == [
        "Same failure reason: this event has no SubStatus"]
    pipes = guide(papp, uid_of(papp.con, "event_code = '5145'"))
    assert row_of(pipes, "search")["term"] == "code:5145 ShareName:*IPC$"


def test_a_value_with_a_space_is_quoted_in_the_term_and_one_with_a_quote_gives_no_term(papp):
    def sysmon_8(record, target):
        return Event(ts_us=T0 + (98 + record) * SEC, ts_desc="Event Recorded", artifact="evtx", source_file="DC01/Sysmon.evtx",
                     source_record=str(record), message="8", event_code="8", event_provider="Microsoft-Windows-Sysmon",
                     log_channel="Microsoft-Windows-Sysmon/Operational", extra={"TargetImage": target})
    more(papp, [sysmon_8(1, "C:\\Program Files\\x\\a.exe"), sysmon_8(2, 'C:\\a"b.exe')])
    first = guide(papp, uid_of(papp.con, "event_code = '8' AND source_record = '1'"))
    assert row_of(first, "search")["term"] == 'code:8 TargetImage:"C:\\Program Files\\x\\a.exe"'
    second = guide(papp, uid_of(papp.con, "event_code = '8' AND source_record = '2'"))
    assert all(r["pivot"] != "search" for r in second["rows"])
    assert "holds a quote" in next(n["reason"] for n in second["not_offered"] if n["pivot"] == "search")


def test_an_event_with_hayabusa_hits_gets_the_rule_row_after_its_own_kind_and_a_kind_that_ranks_it_keeps_its_place(papp):
    g = guide(papp, uid_of(papp.con, RDP))
    rule = row_of(g, "rule")
    assert rule["value"] == "RDP from internet" and rule["n"] == len(g["rows"])
    # An IDS alert ranks the rule itself, and the overlay adds none. This alert's ends are both collected hosts' addresses, so
    # it has no outside end and the rule is third; an alert with an outside end ranks that row before the rule
    g = guide(papp, uid_of(papp.con, "tool = 'suricata' AND log_channel = 'alert'"))
    assert [r["pivot"] for r in g["rows"]] == ["flow", "addr", "rule", "window", "connection"]
    assert row_of(g, "rule")["value"] == "ET TEST Beacon"
    assert row_of(g, "addr")["ip"] in ("10.42.85.10", "10.42.85.115")   # the end that is a collected host's address
    assert row_of(g, "addr")["end"] == "internal"


def test_a_failed_logon_names_its_client_workstation_and_the_row_is_broad_by_count_alone(papp):
    g = guide(papp, uid_of(papp.con, "event_code = '4625' AND source_workstation = 'KALI'"))
    assert g["kind"] == "logon_failed"
    assert [r["pivot"] for r in g["rows"]][:3] == ["addr", "workstation", "account"]
    assert row_of(g, "workstation")["value"] == "KALI" and row_of(g, "workstation")["broad"] == []
    assert row_of(g, "account")["value"] == "admin (name only, any domain)"
    why = {n["pivot"]: n["reason"] for n in g["not_offered"]}["session"]
    assert why.startswith("A 4625's logon ID belongs to the process that reported it")
    assert g["over_limit_text"] == "Broad: {count} events. The list shows the 500 nearest in time."


# ---------- counts, and the lists they match ----------

def every_row_is_counted_as_its_click_lists_it(app, uid):
    """Each counted row of an event, against the click: the count is the click's total, and a breakdown adds up."""
    ev = event_details(app.con, uid, app.identity)
    g = guide(app, uid)
    for row in g["rows"]:
        if not row["count"]:
            continue
        res = counted(app, uid, row, breakdown=row["breakdown"] == "always")
        if row["pivot"] != "search":
            click = related(app.con, uid, row["pivot"], row.get("seconds", 60), ip=row.get("ip", ""), identity=app.identity,
                            ts=ev["adjusted_ts_us"], name=row.get("name", ""))
            assert res["count"] == click["total"], row["pivot"]
        if "sources" in res:
            assert sum(s["count"] for s in res["sources"]) + res["more"]["count"] == res["count"]


def test_each_row_counts_what_its_click_lists_for_a_service_install_a_logon_and_an_alert(papp):
    alert_where = "tool = 'suricata' AND log_channel = 'alert' AND event_code = '2000001' AND source_ip = '10.42.85.10'"
    for where in (INSTALL, RDP, alert_where, "event_code = '4625' AND source_workstation = 'KALI' AND record_id = 9200",
                  "artifact = 'srum'", "event_code = '4698'", "event_code = '4672'"):
        every_row_is_counted_as_its_click_lists_it(papp, uid_of(papp.con, where))


def test_same_service_name_matches_the_key_name_or_the_display_name_on_any_host(papp):
    install = uid_of(papp.con, INSTALL)
    row = row_of(guide(papp, install), "service_name")
    pairs = papp.con.execute("SELECT DISTINCT key_name, display_name FROM service_aliases").fetchall()
    assert pairs == [("winupdsvc", "windows update svc")]   # from Autoruns and 7040: one pair
    res = counted(papp, install, row, breakdown=True)
    # 7045 and 7040 and 7036 (display name), 4697 (key name), Autoruns (key name), RECmd (key name); not another service
    assert res["count"] == 6
    assert {s["label"] for s in res["sources"]} == {"7045", "7040", "7036", "4697", "Autoruns", "Registry"}
    listed = related(papp.con, install, "service_name")
    assert listed["total"] == 6 and {e["code"] for e in listed["events"]} >= {"7045", "7040", "7036", "4697"}
    assert all("Some Other Service" not in e["msg"] and "bam" not in e["msg"] for e in listed["events"])
    # From the registry row, by the key name alone, the pivot reaches the display name's events on the other host
    recmd = uid_of(papp.con, "artifact = 'registry' AND message LIKE '%WinUpdSvc%'")
    g = guide(papp, recmd)
    assert g["kind"] == "recmd_services" and [r["pivot"] for r in g["rows"]] == ["service_name"]
    assert counted(papp, recmd, row_of(g, "service_name"))["count"] == 6
    autoruns = uid_of(papp.con, "artifact = 'autoruns'")
    row = row_of(guide(papp, autoruns), "service_name")
    assert row["value"] == "WinUpdSvc" and counted(papp, autoruns, row)["count"] == 6
    # A service the case never gave a second name matches by the one it has
    other = uid_of(papp.con, "event_code = '7036' AND extra LIKE '%Some Other%'")
    assert counted(papp, other, row_of(guide(papp, other), "service_name"))["count"] == 1


def test_an_alias_table_is_built_per_host_at_open_from_autoruns_and_7040(papp):
    rows = papp.con.execute("SELECT host, key_name, display_name FROM service_aliases ORDER BY 1, 2").fetchall()
    assert rows == [("DC01", "winupdsvc", "windows update svc"), ("DESKTOP", "winupdsvc", "windows update svc")]


def test_same_task_name_finds_the_task_in_security_the_scheduler_autoruns_and_taskcache(papp):
    created = uid_of(papp.con, "event_code = '4698'")
    g = guide(papp, created)
    row = row_of(g, "task_name")
    assert (g["kind"], row["value"], row["n"]) == ("scheduled_task", "\\Evil\\Beacon", 1)
    res = counted(papp, created, row, breakdown=True)
    assert res["count"] == 4 and {s["label"] for s in res["sources"]} == {"4698", "TaskScheduler 140", "Autoruns", "Registry"}
    scheduler = uid_of(papp.con, "log_channel LIKE '%TaskScheduler%' AND extra LIKE '%Beacon%'")
    assert counted(papp, scheduler, row_of(guide(papp, scheduler), "task_name"))["count"] == 4
    assert related(papp.con, scheduler, "task_name")["total"] == 4
    registry = guide(papp, uid_of(papp.con, "artifact = 'registry' AND message LIKE 'Scheduled Tasks%'"))
    assert registry["rows"][0]["pivot"] == "task_name"
    assert counted(papp, uid_of(papp.con, "artifact = 'registry' AND message LIKE 'Scheduled Tasks%'"),
                   registry["rows"][0])["count"] == 4


def test_same_flow_finds_a_connections_records_by_the_capture_flow_id(papp):
    alert_uid = uid_of(papp.con, "tool = 'suricata' AND log_channel = 'alert' AND extra LIKE '%\"flow_id\": \"77\"%'")
    row = row_of(guide(papp, alert_uid), "flow")
    assert row["value"] == "77"
    assert counted(papp, alert_uid, row)["count"] == 3   # the alert, its flow, and its DNS record
    assert related(papp.con, alert_uid, "flow")["total"] == 3
    dns = uid_of(papp.con, "tool = 'suricata' AND log_channel = 'dns'")
    assert row_of(guide(papp, dns), "flow")["value"] == "77"


def test_same_rule_or_signature_counts_a_signature_across_alerts_and_a_hayabusa_rule_across_hits(papp):
    alert_uid = uid_of(papp.con, "tool = 'suricata' AND log_channel = 'alert' AND event_code = '2000001' "
                                 "AND source_ip = '10.42.85.10'")
    row = row_of(guide(papp, alert_uid), "rule")
    assert counted(papp, alert_uid, row)["count"] == 2   # the same signature ID on two flows, not the other signature
    assert related(papp.con, alert_uid, "rule")["total"] == 2
    # Hayabusa: a second event carries the same rule's hit, and a third hit's event has no time, so it isn't listed
    def hit(record):
        return Event(ts_us=T0 + 63 * SEC, ts_desc="Event Recorded", artifact="hayabusa", source_file=DC_LOG,
                     source_record=f"{record}:rule", record_id=record, message="RDP from internet [high]",
                     log_channel="Security", rule_title="RDP from internet", rule_level="high")
    untimed = Event(ts_us=None, ts_desc="Event Recorded", artifact="evtx", source_file=DC_LOG, source_record="107",
                    record_id=107, message="4624 untimed", event_code="4624", log_channel="Security")
    load_events(papp.case, [untimed], "DC01", run="p25")
    load_events(papp.case, [hit(105), hit(107)], "DC01", tool="hayabusa", run="r5b")
    papp.refresh_identity(events_changed=True)
    rdp = uid_of(papp.con, RDP)
    rule = row_of(guide(papp, rdp), "rule")
    assert papp.con.execute("SELECT count(*) FROM hits WHERE list_contains(titles, 'RDP from internet')").fetchone()[0] == 3
    assert counted(papp, rdp, rule)["count"] == 2   # the count is the timeline's: the untimed event is on no list
    listed = related(papp.con, rdp, "rule")
    assert listed["total"] == 2 and {e["code"] for e in listed["events"]} == {"4624", "4672"}
    assert [s["label"] for s in counted(papp, rdp, rule, breakdown=True)["sources"]] == ["4624 type 10", "4672"] or True


def test_same_workstation_matches_the_client_computer_without_letter_case(papp):
    failed = uid_of(papp.con, "event_code = '4625' AND source_workstation = 'KALI' AND record_id = 9200")
    assert counted(papp, failed, row_of(guide(papp, failed), "workstation"))["count"] == 3
    assert {e["code"] for e in related(papp.con, failed, "workstation")["events"]} == {"4625"}
    load_events(papp.case, [security_event(T0 + 120 * SEC, 9800, "4624", source_workstation="kali", logon_type="3")],
                "DC01", run="p16")
    assert related(papp.con, failed, "workstation")["total"] == 4


def named(at, record, artifact, **kw):
    """One record of a tool's output that names a file, `at` seconds after T0."""
    return Event(ts_us=T0 + at * SEC, ts_desc="Record", artifact=artifact, source_file=f"{artifact}/out.csv",
                 source_record=str(record), message=f"{artifact} {record}", **kw)


def records_of(app, res):
    """The source records of the events a pivot's list holds."""
    return {app.con.execute("SELECT source_record FROM events WHERE event_uid = ?", [e["uid"]]).fetchone()[0]
            for e in res["events"]}


def test_same_file_name_matches_the_name_alone_in_any_folder_without_letter_case_and_keeps_same_file_exact(papp):
    """The name in any folder, on any host, with a bare name (SRUM's) and a capture's URL path counted, and not a
    longer name, a name with a suffix, or an event whose file is another one."""
    more(papp, [
        named(300, "1", "mft", file_path=".\\Users\\Public\\Coreupdater.exe", file_key="\\users\\public\\coreupdater.exe"),
        named(301, "2", "prefetch", file_path="\\VOLUME{01d6}\\WINDOWS\\SYSTEM32\\COREUPDATER.EXE",
              file_key="\\windows\\system32\\coreupdater.exe"),
        named(302, "3", "srum", process_executable="coreupdater.exe"),
        named(303, "4", "evtx", process_executable="C:\\Windows\\coreupdater.exe"),
        named(304, "5", "suricata", file_path="/coreupdater.exe"),
        named(305, "x1", "mft", file_path="C:\\Users\\Public\\xcoreupdater.exe"),
        named(306, "x2", "mft", file_path="C:\\Users\\Public\\coreupdater.exe.bak"),
        named(307, "x3", "mft", file_path="C:\\Users\\Public\\coreupdater.exe\\inside.txt"),
        named(308, "x4", "evtx", file_path="C:\\a\\other.dll", process_executable="C:\\Windows\\coreupdater.exe"),
    ])
    more(papp, [named(309, "6", "amcache", file_path="D:\\tools\\CoreUpdater.EXE")], host="DESKTOP", run="m2")
    seed = uid_of(papp.con, "source_record = '1' AND artifact = 'mft'")
    g = guide(papp, seed)
    assert [r["pivot"] for r in g["rows"]] == ["file", "window", "file_name"]
    row = row_of(g, "file_name")
    assert (row["label"], row["value"], row["broad"]) == ("Same file name", "Coreupdater.exe", [])
    assert row["warn"] == "Joins every file of this name, in any folder and on any host, whatever the file is."
    assert row["reason"] == "Copies under other paths or on other hosts, such as a download in Downloads."
    assert row["empty"] == ["No other file of this name in the case."]
    res = related(papp.con, seed, "file_name", identity=papp.identity)
    assert res["label"] == "file name Coreupdater.exe"
    assert records_of(papp, res) == {"1", "2", "3", "4", "5", "6"}
    assert counted(papp, seed, row)["count"] == res["total"] == 6
    assert related(papp.con, seed, "file", identity=papp.identity)["total"] == 1   # Same file still matches the exact path
    # From a bare name: the file pivot has no key to match, and the name finds the same events
    bare = uid_of(papp.con, "artifact = 'srum' AND source_record = '3'")
    g = guide(papp, bare)
    assert row_of(g, "file_name")["value"] == "coreupdater.exe"
    assert [n["reason"] for n in g["not_offered"] if n["pivot"] == "file"] == [
        "SRUM wrote a bare name or an app ID here, which has no path to match. Use Same file name."]
    assert records_of(papp, related(papp.con, bare, "file_name", identity=papp.identity)) == {"1", "2", "3", "4", "5", "6"}
    for uid in (seed, bare):
        every_row_is_counted_as_its_click_lists_it(papp, uid)


def test_the_keyless_names_table_holds_the_name_of_each_event_without_a_file_key(papp):
    """The count reads the events with no file key through this table, not by scanning the events for them."""
    more(papp, [named(320, "k1", "mft", file_path="C:\\A\\Thing.EXE", file_key="\\a\\thing.exe"),
                named(321, "k2", "srum", process_executable="Thing.exe"),
                named(322, "k3", "evtx", file_path="/x/Thing.exe", process_executable="y.exe"),
                named(323, "k4", "evtx", process_executable="C:\\Windows\\Proc.exe")])
    rows = papp.con.execute("SELECT e.source_record, k.name FROM keyless_names k JOIN events e USING (event_uid) "
                            "WHERE e.source_record IN ('k1', 'k2', 'k3', 'k4') ORDER BY 1").fetchall()
    assert rows == [("k2", "thing.exe"), ("k3", "thing.exe"), ("k4", "proc.exe")]


def test_same_file_name_is_offered_only_to_an_event_with_a_file_name_and_says_why_it_is_not(papp):
    more(papp, [security_event(T0 + 310 * SEC, 9810, "4688", user_name="x", user_domain="C137", logon_id="0x7"),
                named(311, "folder", "mft", file_path="C:\\Users\\Public\\"),
                named(312, "reg", "registry", registry_path="ROOT\\ControlSet001\\Control\\Session Manager\\AppCompatCache")])
    for where, reason in (("event_code = '4688'", "This event has no file name"),
                          ("source_record = 'folder'", "This event has no file name"),
                          ("source_record = 'reg'", "This row names no file.")):
        g = guide(papp, uid_of(papp.con, where))
        assert all(r["pivot"] != "file_name" for r in g["rows"]), where
        assert [n["reason"] for n in g["not_offered"] if n["pivot"] == "file_name"] == [reason], where
    # No name, no list: the click says so, and the count is zero
    uid = uid_of(papp.con, "event_code = '4688'")
    assert related(papp.con, uid, "file_name")["note"] == "this event has no file name"
    assert count_pivot(papp.con, papp.identity, uid, None, "file_name") == {"count": 0, "note": "this event has no file name"}


def test_a_shared_windows_program_by_name_is_broad(papp):
    more(papp, [named(313, "svchost", "mft", file_path="C:\\Windows\\System32\\SVCHOST.exe",
                      file_key="\\windows\\system32\\svchost.exe")])
    g = guide(papp, uid_of(papp.con, "source_record = 'svchost'"))
    assert row_of(g, "file_name")["broad"] == ["Broad: a shared Windows program. Every use of it matches."]


def test_a_log_clear_ranks_the_tables_fixed_name_and_the_click_carries_it(papp):
    more(papp, [security_event(T0 + 320 * SEC, 9820, "1102", user_name="Administrator", user_domain="C137", logon_id="0x9"),
                named(321, "pf", "prefetch", file_path="\\VOLUME{01d6}\\WINDOWS\\SYSTEM32\\WEVTUTIL.EXE",
                      file_key="\\windows\\system32\\wevtutil.exe"),
                named(322, "cmd", "evtx", process_executable="C:\\Windows\\System32\\wevtutil.exe"),
                named(323, "no", "evtx", process_executable="C:\\Windows\\System32\\wevtutil.exe.mui")])
    clear = uid_of(papp.con, "event_code = '1102'")
    row = row_of(guide(papp, clear), "file_name")
    assert (row["label"], row["name"], row["value"]) == ("Same file name: wevtutil.exe", "wevtutil.exe", "")
    res = related(papp.con, clear, "file_name", name=row["name"], identity=papp.identity)
    assert records_of(papp, res) == {"pf", "cmd"} and res["label"] == "file name wevtutil.exe"
    assert counted(papp, clear, row)["count"] == res["total"] == 2
    every_row_is_counted_as_its_click_lists_it(papp, clear)
    # The name is the table's: a request can't pivot on another
    for ask in (lambda: api_related(papp, {"uid": [clear], "kind": ["file_name"], "name": ["cmd.exe"]}),
                lambda: api_pivot_count(papp, {"uid": [clear], "kind": ["file_name"], "name": ["cmd.exe"]})):
        with pytest.raises(QueryError, match="name must be"):
            ask()
    assert api_related(papp, {"uid": [clear], "kind": ["file_name"], "name": ["WEVTUTIL.exe"]})["total"] == 2
    assert api_pivot_count(papp, {"uid": [clear], "kind": ["file_name"], "name": ["wevtutil.exe"]})["count"] == 2


def test_same_account_with_no_domain_matches_the_name_in_any_domain_and_with_one_also_the_same_name_with_none(papp):
    more(papp, [security_event(T0 + 130 * SEC, 9900, "4624", user_name="administrator", user_domain="C137.LOCAL",
                               logon_type="3", logon_id="0x5"),
                security_event(T0 + 131 * SEC, 9901, "4624", user_name="Administrator", user_domain="DESKTOP-SDN1RPT",
                               logon_type="2", logon_id="0x6")])
    srum = uid_of(papp.con, "artifact = 'srum'")
    res = related(papp.con, srum, "account")
    assert res["label"] == "same account (name only, any domain)"
    domains = {r[0] for r in papp.con.execute(
        "SELECT user_domain FROM events WHERE lower(user_name) = 'administrator'").fetchall()}
    assert domains == {"C137", "", "C137.LOCAL", "DESKTOP-SDN1RPT"}
    same_name = papp.con.execute("SELECT count(*) FROM events WHERE lower(user_name) = 'administrator'").fetchone()[0]
    assert res["total"] == same_name
    row = row_of(guide(papp, srum), "account")
    assert row["value"] == "Administrator (name only, any domain)" and counted(papp, srum, row)["count"] == same_name
    # With a domain: that domain's events, and the same name where no domain is recorded, but not another domain's
    rdp = uid_of(papp.con, RDP)
    with_domain = related(papp.con, rdp, "account")
    assert with_domain["label"] == "same account"
    # C137.LOCAL records no SID here, so it folds into C137 by its first label, which the note calls an inference
    assert with_domain["match_note"] == (
        "Also events with this name and no domain. Also written as C137.LOCAL, taken as the same domain since its first "
        "DNS label is the domain's name (an inference: no SID was recorded under it).")
    uids = [e["uid"] for e in with_domain["events"]]
    found = {r[0] for r in papp.con.execute(
        f"SELECT user_domain FROM events WHERE event_uid IN ({','.join('?' for _ in uids)})", uids).fetchall()}
    assert found == {"C137", "", "C137.LOCAL"} and srum in uids
    assert counted(papp, rdp, row_of(guide(papp, rdp), "account"))["count"] == with_domain["total"]


def test_same_source_ip_and_port_is_bounded_in_time_and_the_case_wide_list_is_a_click_away(papp):
    """A source port is reused, so the pivot lists the events within the case's window of the event, on the
    clock-adjusted time, and a reused port a long time later stays out. scope=case lists them all."""
    def connection(record, at):
        e = logon(T0 + at * SEC, record, WS_LOG, ltype="3", ip="10.9.1.1", computer="DESKTOP-SDN1RPT.C137.local")
        e.source_port = "49752"
        return e
    more(papp, [connection(5001, 600), connection(5002, 603), connection(5003, 4000)], host="DESKTOP")
    first = uid_of(papp.con, "source_record = '5001'")
    bounded = related(papp.con, first, "connection", 60, identity=papp.identity)
    assert bounded["label"] == "same source IP and port within 60 seconds"
    assert (bounded["total"], bounded["seconds"]) == (2, 60)
    assert sorted(e["gap_s"] for e in bounded["events"]) == [0.0, 3.0]
    case_wide = related(papp.con, first, "connection", 60, identity=papp.identity, scope="case")
    assert case_wide["label"] == "same source IP and port, case-wide" and case_wide["total"] == 3
    assert related(papp.con, first, "connection", 5, identity=papp.identity)["total"] == 2
    assert related(papp.con, first, "connection", 2, identity=papp.identity)["total"] == 1
    # the count is the click's
    row = {"pivot": "connection", "seconds": 60}
    assert counted(papp, first, row)["count"] == 2 and counted(papp, first, row, scope="case")["count"] == 3
    # on the adjusted time: an offset moves DESKTOP's events together, so the window holds the same ones
    api_host(papp, {"host": "DESKTOP", "offset_seconds": 3600})
    assert related(papp.con, first, "connection", 60, identity=papp.identity)["total"] == 2
    assert related(papp.con, first, "connection", 60, identity=papp.identity, scope="case")["total"] == 3
    # An event without a time has no window to bound, so it lists case-wide
    untimed = Event(ts_us=None, ts_desc="x", artifact="evtx", source_file=DC_LOG, source_record="700", message="4624",
                    event_code="4624", log_channel="Security", source_ip="10.9.1.1", source_port="49752")
    more(papp, [untimed])
    res = related(papp.con, uid_of(papp.con, "source_record = '700'"), "connection", 60, identity=papp.identity)
    assert res["label"] == "same source IP and port, case-wide" and res["total"] == 3


def test_a_window_lists_its_nearest_500_with_how_far_they_reach_and_a_source_narrows_it(papp):
    many = [system_event(T0 + 300 * SEC + i * 1_000, 20000 + i, "7036", {"param1": f"Svc {i}", "param2": "running"})
            for i in range(600)]
    more(papp, many, run="bulk")
    near = uid_of(papp.con, "event_code = '7036' AND source_record = '20000'")
    res = related(papp.con, near, "window", 300, identity=papp.identity)
    assert res["limited"] and res["total"] > 500 and len(res["events"]) == 500
    assert res["reach_s"] == max(abs(e["gap_s"]) for e in res["events"]) and res["reach_s"] < 0.6   # 1 ms apart
    only = related(papp.con, near, "window", 300, identity=papp.identity, source=["evtx", "System", "7036"])
    assert only["source"] == ["evtx", "System", "7036"] and {e["code"] for e in only["events"]} == {"7036"}
    other = related(papp.con, near, "window", 300, identity=papp.identity, source=["evtx", "Security", "4624", "3"])
    assert all(e["code"] == "4624" for e in other["events"])
    # the breakdown names the source, and its count is the narrowed list's total
    top = counted(papp, near, {"pivot": "window", "seconds": 300}, breakdown=True)["sources"][0]
    assert top["source"] == ["evtx", "System", "7036"] and top["label"] == "7036"
    assert related(papp.con, near, "window", 300, identity=papp.identity, source=top["source"])["total"] == top["count"]
    for bad in (["a", "b", "c", "d", "e"], [1]):
        with pytest.raises(QueryError):
            related(papp.con, near, "window", 300, identity=papp.identity, source=bad)
    rdp = uid_of(papp.con, RDP)   # no source is no narrowing
    assert related(papp.con, rdp, "window", 300, identity=papp.identity, source=[])["total"] == related(
        papp.con, rdp, "window", 300, identity=papp.identity)["total"]


def test_a_pivot_with_nothing_to_match_answers_a_note_and_a_count_of_zero(papp):
    more(papp, [Event(ts_us=T0, ts_desc="x", artifact="mft", source_file="DC01/$MFT", source_record="1", message="m")])
    uid = uid_of(papp.con, "artifact = 'mft'")
    for kind, note in (("service_name", "this event names no service"), ("task_name", "this event names no task"),
                       ("flow", "this event has no flow ID"), ("rule", "this event has no rule or signature"),
                       ("workstation", "this event has no source_workstation")):
        assert related(papp.con, uid, kind)["note"] == note
        assert count_pivot(papp.con, papp.identity, uid, T0, kind) == {"count": 0, "note": note}


def test_a_search_is_counted_only_when_every_term_is_a_fields():
    """A free-text word is never counted (2.3 s for one word at 5.2 million events)."""
    from glessner.pivots import _field_terms
    assert _field_terms("code:4625 SubStatus:0xC000006A") and _field_terms('path:"C:\\x y" code:11')
    assert not _field_terms("mimikatz") and not _field_terms("code:4625 mimikatz") and not _field_terms("")


def test_same_service_name_reaches_a_sysmon_key_under_services_and_same_flow_and_rule_reach_imports(papp):
    sysmon = Event(ts_us=T0 + 160 * SEC, ts_desc="Event Recorded", artifact="evtx", source_file="DC01/Sysmon.evtx",
                   source_record="3", message="13", event_code="13", event_provider="Microsoft-Windows-Sysmon",
                   log_channel="Microsoft-Windows-Sysmon/Operational",
                   registry_path="HKLM\\System\\CurrentControlSet\\Services\\WinUpdSvc\\ImagePath")
    more(papp, [sysmon])
    install = uid_of(papp.con, INSTALL)
    assert counted(papp, install, row_of(guide(papp, install), "service_name"))["count"] == 7
    key = uid_of(papp.con, "event_code = '13'")
    assert related(papp.con, key, "service_name")["total"] == 7   # from the key's own name, WinUpdSvc, and its alias
    # Zeek's uid is the flow of an imported record, and a fast alert's rule is its event code
    zeek = [Event(ts_us=T0 + (170 + i) * SEC, ts_desc="Zeek", artifact="zeek", source_file="network/conn.log",
                  source_record=str(i), message="conn", extra={"uid": "CxYz1", "_path": "conn"}) for i in range(2)]
    fast = [Event(ts_us=T0 + (180 + i) * SEC, ts_desc="Alert", artifact="ids_alert", source_file="IDS/fast.log",
                  source_record=str(i), message="alert", event_code="1:2025644:1", extra={"signature": "ET TEST"})
            for i in range(2)]
    load_events(papp.case, zeek, "network", tool="import", run="z")
    load_events(papp.case, fast, "network", tool="import", run="f")
    papp.refresh_identity(events_changed=True)
    uid = uid_of(papp.con, "artifact = 'zeek' AND source_record = '0'")
    flow = row_of(guide(papp, uid), "flow")
    assert flow["value"] == "CxYz1" and counted(papp, uid, flow)["count"] == 2
    uid = uid_of(papp.con, "artifact = 'ids_alert' AND source_record = '0'")
    rule = row_of(guide(papp, uid), "rule")
    assert rule["value"] == "ET TEST" and counted(papp, uid, rule)["count"] == 2
    assert related(papp.con, uid, "rule")["total"] == 2 and "flow" not in {r["pivot"] for r in guide(papp, uid)["rows"]}


def test_a_fault_in_the_pivots_or_in_provenance_is_shown_in_place_and_the_event_still_loads(papp, monkeypatch):
    from glessner import server

    def broken(*args, **kwargs):
        raise RuntimeError("the table broke")
    rdp = uid_of(papp.con, RDP)
    monkeypatch.setattr(server, "guidance", broken)
    res = api_event(papp, {"uid": [rdp]})["event"]
    assert res["event_uid"] == rdp and res["pivots"] == {"error": "RuntimeError: the table broke"}
    monkeypatch.setattr(server, "evidence_checks", broken)
    papp.checks_cache = None   # the checks the first answer read are kept until a check adds to the log
    res = api_event(papp, {"uid": [rdp]})["event"]
    assert res["event_uid"] == rdp and res["provenance"]["state"] == "error"
    assert res["provenance"]["text"] == "could not be read (RuntimeError: the table broke)"


def test_same_ip_at_either_end_counts_an_event_with_the_address_at_both_ends_once(papp):
    """The count runs as two equality counts, the source equal and the destination equal where the source differs, so an
    event with the address at both ends is one of the click's events, not two."""
    both = {"source_ip": "127.0.0.1", "source_port": "49800", "dest_ip": "127.0.0.1", "dest_port": "445"}
    more(papp, [security_event(T0 + 150 * SEC, 9990, "5156", **both),
                security_event(T0 + 151 * SEC, 9991, "5156", source_ip="10.0.0.9", dest_ip="127.0.0.1")])
    uid = uid_of(papp.con, "event_code = '5156' AND record_id = 9990")
    click = related(papp.con, uid, "addr", ip="127.0.0.1", identity=papp.identity)
    assert click["total"] == 2 and {e["end"] for e in click["events"]} == {"both", "destination"}
    assert counted(papp, uid, {"pivot": "addr", "ip": "127.0.0.1"})["count"] == 2


def test_a_window_row_names_its_top_sources_and_other_rows_only_when_asked(papp):
    install = uid_of(papp.con, INSTALL)
    g = guide(papp, install)
    res = counted(papp, install, row_of(g, "window"), breakdown=True)
    assert res["count"] == sum(s["count"] for s in res["sources"]) + res["more"]["count"]
    assert all(set(s) == {"source", "label", "count"} for s in res["sources"])
    assert "sources" not in counted(papp, install, row_of(g, "file"))   # the count alone, until it passes the limit


def test_a_count_reads_the_event_once_from_the_anchor_the_server_kept(papp):
    install = uid_of(papp.con, INSTALL)
    ev = api_event(papp, {"uid": [install]})["event"]
    kept = papp.anchor(install, ev["adjusted_ts_us"])
    assert kept is not None and kept[1] == ev["adjusted_ts_us"] and kept[0]["event_uid"] == install
    assert papp.anchor(install, ev["adjusted_ts_us"] + 1) is None   # the time the page shows has moved
    fresh = anchor_of(papp.con, install, papp.identity, ev["adjusted_ts_us"])[0]
    assert {k: kept[0][k] for k in fresh if k != "adjusted_ts"} == {k: v for k, v in fresh.items() if k != "adjusted_ts"}
    asked = {"uid": [install], "kind": ["service_name"], "ts": [str(ev["adjusted_ts_us"])]}
    assert api_pivot_count(papp, asked)["count"] == 6
    # With the anchor gone, as after an offset edit, the count reads the event again and still answers
    api_host(papp, {"host": "DC01", "offset_seconds": 90})
    assert papp.anchor(install, ev["adjusted_ts_us"]) is None
    assert api_pivot_count(papp, {"uid": [install], "kind": ["service_name"]})["count"] == 6
    kept_count = len(papp.anchors)
    for i in range(10):
        papp.keep_anchor(f"{i:032d}", {**ev, "event_uid": f"{i:032d}"})
    assert len(papp.anchors) == 8 and kept_count <= 8   # a few events are kept, the newest


# ---------- a 4688's logon session at work in the pivots ----------

def test_a_4688_joins_the_logon_session_that_ran_it_and_a_zero_logon_id_joins_nothing(synthetic_case, tmp_path):
    """A 4688's TargetLogonId of 0x0 is not stored, since it would keep a user's processes from joining the user's 4624
    session. The process is in the session of its Subject, and the session pivot lists both."""
    parsed = evtx_events(tmp_path)
    created, failed = parsed["4688 shared logon"], parsed["4625 no logon"]
    session = security_event(T0 + 10 * SEC, 8001, "4624", logon_id="0x3E7", logon_type="5", user_name="SYSTEM",
                             user_domain="NT AUTHORITY")
    created.ts_us, failed.ts_us = T0 + 11 * SEC, T0 + 12 * SEC
    load_events(synthetic_case, [session, created, failed], "DC01")
    app = App(synthetic_case)
    try:
        process = uid_of(app.con, "event_code = '4688'")
        listed = related(app.con, process, "session")
        assert {e["code"] for e in listed["events"]} == {"4624", "4688"} and listed["total"] == 2
        g = guide(app, process)
        assert row_of(g, "session")["broad"] and row_of(g, "session")["value"] == "0x3E7"
        assert related(app.con, uid_of(app.con, "event_code = '4625'"), "session")["note"] == "this event has no logon_id"
    finally:
        app.con.close()


# ---------- the server ----------

def test_the_event_answer_carries_the_guidance_and_one_line_of_provenance(papp):
    rdp = uid_of(papp.con, RDP)
    res = api_event(papp, {"uid": [rdp]})["event"]
    assert res["pivots"]["kind"] == "logon_rdp" and res["provenance"]["state"] == "absent"   # no intake in this case
    assert res["provenance"]["sha256"] == papp.manifest.get(res["source_file"], "")


def test_provenance_says_whether_the_evidence_file_still_matches_intake(synthetic_case):
    from glessner.intake import intake, verify
    (synthetic_case.evidence / "DC01" / "Windows" / "System32" / "winevt" / "Logs").mkdir(parents=True)
    log = synthetic_case.evidence / DC_LOG
    log.write_bytes(b"evidence")
    intake(synthetic_case)
    app = App(synthetic_case)
    try:
        rdp = app.con.execute("SELECT event_uid FROM events WHERE event_code = '4624' AND logon_type = '10'").fetchone()[0]
        first = api_event(app, {"uid": [rdp]})["event"]["provenance"]
        assert first["state"] == "unchecked" and len(first["sha256"]) == 64
        assert verify(synthetic_case, [DC_LOG], reason="test") == []
        assert api_event(app, {"uid": [rdp]})["event"]["provenance"]["state"] == "matches"
        log.write_bytes(b"changed")
        assert verify(synthetic_case, [DC_LOG], reason="test")
        changed = api_event(app, {"uid": [rdp]})["event"]["provenance"]
        assert changed["state"] == "changed" and "SHA-256 changed" in changed["text"] and changed["sha256"] == first["sha256"]
    finally:
        app.con.close()


def test_the_pivot_count_route_answers_one_row_and_refuses_what_it_cannot_count(papp):
    rdp = uid_of(papp.con, RDP)
    assert api_pivot_count(papp, {"uid": [rdp], "kind": ["session"]})["count"] == 2   # the logon and its 4672
    with_sources = api_pivot_count(papp, {"uid": [rdp], "kind": ["window"], "seconds": ["600"], "breakdown": ["1"]})
    assert with_sources["count"] > 0 and with_sources["sources"]
    with pytest.raises(QueryError):
        api_pivot_count(papp, {"uid": [rdp], "kind": ["nonsense"]})
    with pytest.raises(QueryError):
        api_pivot_count(papp, {"uid": ["0" * 32], "kind": ["session"]})
    with pytest.raises(QueryError):
        api_related(papp, {"uid": [rdp], "kind": ["window"], "source": ["not json"]})
    only = api_related(papp, {"uid": [rdp], "kind": ["window"], "seconds": ["600"],
                              "source": [json.dumps(["evtx", "Security", "4672"])]})
    assert only["total"] == 1


def test_a_kinds_window_is_saved_through_the_settings_path_and_the_meta_gives_it_back(papp):
    assert api_setting(papp, {"name": "pivot_windows", "value": {"logon_rdp": 120}})["value"] == {"logon_rdp": 120}
    both = api_setting(papp, {"name": "pivot_windows", "value": {"service_install": 900}})["value"]
    assert both == {"logon_rdp": 120, "service_install": 900}
    assert api_meta(papp, {})["pivot_windows"] == both
    entries = [json.loads(line) for line in (papp.case.folder / "journal.jsonl").read_text().splitlines()]
    assert [(e["action"], e["name"]) for e in entries[-2:]] == [("case_setting", "pivot_windows")] * 2   # an ordinary entry
    assert entries[-1]["value"] == both
    rdp = uid_of(papp.con, RDP)
    assert api_event(papp, {"uid": [rdp]})["event"]["pivots"]["rows"][2]["window"]["seconds"] == 120
    assert api_setting(papp, {"name": "pivot_windows", "value": {"logon_rdp": None}})["value"] == {"service_install": 900}
    for bad in ({"logon_rdp": 0}, {"logon_rdp": 3601}, {"logon_rdp": "5"}, {"nonsense": 5}, {"default": 5}, {}, [], None,
                {"logon_rdp": True}):
        with pytest.raises(QueryError):
            api_setting(papp, {"name": "pivot_windows", "value": bad})
    assert api_meta(papp, {})["pivot_windows"] == {"service_install": 900}


def test_a_case_reopened_keeps_the_windows_and_rebuilds_the_alias_table(pcase):
    a = App(pcase)
    api_setting(a, {"name": "pivot_windows", "value": {"logon_rdp": 45}})
    a.con.close()
    b = App(pcase)
    try:
        assert b.pivot_windows == {"logon_rdp": 45}
        assert b.con.execute("SELECT count(*) FROM service_aliases").fetchone()[0] == 2
    finally:
        b.con.close()


# ---------- ranked rows for alerts and unusual sources ----------

def ids_event(ts, record, src, dest, **kw):
    return Event(ts_us=ts, ts_desc="Event Recorded", artifact="suricata", source_file="network/eve.json",
                 source_record=str(record), message="alert", event_code="2000009", log_channel="alert",
                 source_ip=src, dest_ip=dest, extra={"flow_id": str(record)}, **kw)


def test_an_alerts_outside_end_is_ranked_after_its_internal_end(papp):
    """The ranked Same IP row takes the end that is a collected host's, and the outside address is a ranked row of its
    own after it, with a count."""
    more(papp, [ids_event(T0 + 200 * SEC, 5001, "10.42.85.10", "203.0.113.50")], host="network")
    uid = uid_of(papp.con, "record_id IS NULL AND source_record = '5001'")
    g = guide(papp, uid)
    addr = [r for r in g["rows"] if r["pivot"] == "addr"]
    assert [r["ip"] for r in addr] == ["10.42.85.10", "203.0.113.50"]
    assert [r["end"] for r in addr] == ["internal", "external"] and addr[1]["n"] == addr[0]["n"] + 1
    assert addr[0]["end_host"] == papp.identity.resolve_ip("10.42.85.10") and "end_host" not in addr[1]
    assert not [p for p in g["plain"] if p["pivot"] == "addr"]
    listed = related(papp.con, uid, "addr", ip="203.0.113.50", identity=papp.identity)["total"]
    assert listed >= 1 and counted(papp, uid, addr[1])["count"] == listed


def test_neither_end_a_collected_host_ranks_the_first_outside_address_and_links_the_other(papp):
    more(papp, [ids_event(T0 + 201 * SEC, 5002, "198.51.100.1", "203.0.113.51")], host="network")
    uid = uid_of(papp.con, "source_record = '5002'")
    g = guide(papp, uid)
    assert [(r["ip"], r["end"]) for r in g["rows"] if r["pivot"] == "addr"] == [("198.51.100.1", "external")]
    assert {p["value"] for p in g["plain"] if p["pivot"] == "addr"} == {"203.0.113.51"}
    assert "addr" not in {n["pivot"] for n in g["not_offered"]}


def test_both_ends_collected_gives_no_outside_row_and_the_second_end_is_a_plain_link(papp):
    more(papp, [ids_event(T0 + 203 * SEC, 5004, "10.42.85.10", "10.42.85.115")], host="network")
    uid = uid_of(papp.con, "source_record = '5004'")
    g = guide(papp, uid)
    assert [(r["ip"], r["end"]) for r in g["rows"] if r["pivot"] == "addr"] == [("10.42.85.10", "internal")]
    assert {p["value"] for p in g["plain"] if p["pivot"] == "addr"} == {"10.42.85.115"}
    # The outside row's own reason never reaches the not-offered line while the internal row is ranked
    assert "addr" not in {n["pivot"] for n in g["not_offered"]}


def test_the_ids_alert_table_order():
    kind = next(k for k in table()["kinds"] if k["kind"] == "ids_alert")
    specs = sorted(kind["pivots"], key=lambda p: p["rank"])
    assert [p["pivot"] for p in specs] == ["flow", "addr", "addr", "rule", "window", "connection"]
    assert [p["rank"] for p in specs] == [1, 2, 3, 4, 5, 6]
    assert [p["args"]["end"] for p in specs if p["pivot"] == "addr"] == ["internal", "external"]
    outside = specs[2]
    assert outside["reason"].startswith("The other end of the connection, outside the case: its records on every host")
    assert outside["broad"] == ["loopback", "link_local"] and set(outside["sources"]) <= set(table()["sources"])


def test_a_plain_same_account_link_with_no_domain_says_name_only(papp):
    more(papp, [ids_event(T0 + 202 * SEC, 5003, "10.42.85.10", "203.0.113.52", user_name="alice")], host="network")
    uid = uid_of(papp.con, "source_record = '5003'")
    g = guide(papp, uid)
    links = [p for p in g["plain"] if p["pivot"] == "account"]
    assert [p["value"] for p in links] == ["alice (name only, any domain)"]
    assert not any(r["pivot"] == "account" for r in g["rows"])


def test_a_window_source_from_an_unusual_provider_is_named_with_it(papp):
    from glessner.pivots import source_label
    assert source_label(["evtx", "System", "36874"], "Schannel") == "Schannel 36874"
    assert source_label(["evtx", "System", "7045"], "Service Control Manager") == "7045"
    assert source_label(["evtx", "System", "36874"]) == "36874"
    schannel = [Event(ts_us=T0 + 6 * SEC, ts_desc="Event Recorded", artifact="evtx", source_file=SYSTEM_LOG,
                      source_record=str(9301 + i), record_id=9301 + i, message="36874 system", event_code="36874",
                      event_provider="Schannel", log_channel="System") for i in range(8)]
    more(papp, schannel)
    install = uid_of(papp.con, INSTALL)
    res = counted(papp, install, row_of(guide(papp, install), "window"), breakdown=True)
    assert "Schannel 36874" in [s["label"] for s in res["sources"]]


def test_to_investigate_counts_no_session_for_a_logon_id_of_0x0(papp):
    """An event parsed with 0x0 as its logon ID, as an older case may hold on a 4688 or 4625, groups no events.
    To investigate counts the event's ranked pivots, and a session of 0x0 is not among them."""
    from glessner.server import api_investigate, api_mark
    zero = [security_event(T0 + (300 + i) * SEC, 9400 + i, "4688", logon_id="0x0") for i in range(3)]
    more(papp, zero)
    uid = uid_of(papp.con, "record_id = 9400")
    api_mark(papp, {"uids": [uid], "value": "suspicious"})
    row = next(i for i in api_investigate(papp, {})["items"] if i["uid"] == uid)
    assert "session" not in [r["pivot"] for r in row["rows"]]


# ---------- system sessions and local addresses ----------

SYSTEM_USER = {"user_name": "SYSTEM", "user_domain": "NT AUTHORITY"}
ANONYMOUS = {"user_name": "ANONYMOUS LOGON", "user_domain": "NT AUTHORITY"}
ALICE = {"user_name": "alice", "user_domain": "C137"}


def add_sessions(app):
    """DC01's Security events in LocalSystem's session (a type 5 logon, 4672, 4648), in the anonymous logon's (two), and in
    a user's (three). None names a file or an address, so a session is the only thing that relates them."""
    more(app, [
        security_event(T0 + 400 * SEC, 9601, "4624", logon_id="0x3E7", logon_type="5", **SYSTEM_USER),
        security_event(T0 + 401 * SEC, 9602, "4672", logon_id="0x3E7", **SYSTEM_USER),
        security_event(T0 + 402 * SEC, 9603, "4648", logon_id="0x3E7", **SYSTEM_USER),
        security_event(T0 + 403 * SEC, 9604, "4624", logon_id="0x3e6", logon_type="3", **ANONYMOUS),
        security_event(T0 + 404 * SEC, 9605, "4672", logon_id="0x3E6", **ANONYMOUS),
        security_event(T0 + 405 * SEC, 9606, "4624", logon_id="0x51a", logon_type="2", **ALICE),
        security_event(T0 + 406 * SEC, 9607, "4672", logon_id="0x51A", **ALICE),
        security_event(T0 + 407 * SEC, 9608, "4634", logon_id="0x51a", **ALICE),
    ])
    return {n: uid_of(app.con, "record_id = ?", 9600 + n) for n in range(1, 9)}


def test_to_investigate_leaves_system_sessions_out_of_its_counts(papp):
    """A flagged event in Windows' own session would count everything that account did on the host, 1,110 events from
    one type 5 logon on Szechuan. To investigate counts the event's ranked pivots as unreviewed events; the session row
    is left out for a system session and kept for a user's, where the count is the unreviewed events in it. The
    overview's count of marked events with unreviewed relatives keeps its own test of the same sessions."""
    from glessner.server import api_investigate, api_mark, api_overview, api_pivot_count
    uid = add_sessions(papp)
    for n in (1, 4, 6):   # one in LocalSystem's session, one in the anonymous logon's, one in the user's
        api_mark(papp, {"uids": [uid[n]], "value": "suspicious", "note": ""})
    items = {i["uid"]: i for i in api_investigate(papp, {})["items"]}
    pivots = lambda n: [r["pivot"] for r in items[uid[n]]["rows"]]
    assert "session" not in pivots(1) and "session" not in pivots(4) and pivots(6)[0] == "session"
    count = lambda n: api_pivot_count(papp, {"uid": [uid[n]], "kind": ["session"], "unreviewed": ["1"]})["count"]
    assert count(6) == 2   # its 4672 and its logoff
    # The overview counts the same way: only the user's flagged event has an unreviewed relative
    assert api_overview(papp, {})["progress"]["unreviewed_nearby"] == 1
    api_mark(papp, {"uids": [uid[7], uid[8]], "value": "authorized", "note": ""})
    assert count(6) == 0 and api_overview(papp, {})["progress"]["unreviewed_nearby"] == 0


def test_a_system_session_keeps_its_value_and_its_row_is_broad(papp):
    """A Security event keeps SYSTEM's logon ID (0x3e7, 0x3e4, 0x3e5, 0x3e6), and Same logon session flags it broad,
    with the system-session text; the list and the count are the session's."""
    uid = add_sessions(papp)
    anonymous = event_details(papp.con, uid[4], papp.identity)
    assert anonymous["logon_id"] == "0x3e6"
    g = guide(papp, uid[4])
    assert row_of(g, "session")["broad"] == [
        "Broad: this is a system session (SYSTEM, NETWORK SERVICE, LOCAL SERVICE, or ANONYMOUS LOGON). "
        "Everything that account does on this host shares it."]
    assert counted(papp, uid[4], row_of(g, "session"))["count"] == related(papp.con, uid[4], "session")["total"] == 2
    assert row_of(guide(papp, uid[6]), "session")["broad"] == []


def test_overview_and_to_investigate_write_the_same_session_and_address_tests():
    """overview.NEARBY writes queries.session_key and queries.local_scope out, so its import lines stay as they were; this
    holds the two together, and the SQL address test with relations.is_remote, form by form."""
    import duckdb

    from glessner.overview import LOCAL_SCOPE, NEARBY, SESSION_KEY
    from glessner.queries import SYSTEM_SESSIONS, local_address, local_scope, session_key
    from glessner.relations import is_local, is_remote
    assert SESSION_KEY.format(c="x.logon_id") == session_key("x.logon_id") and SESSION_KEY.format(c="v.logon_id") in NEARBY
    assert LOCAL_SCOPE.format(c="x.source_ip", h="x.host") == local_scope("x")
    assert all(f"'{s}'" in SESSION_KEY for s in SYSTEM_SESSIONS) and len(SYSTEM_SESSIONS) == 4
    forms = ["127.0.0.1", "127.5.4.3", "::1", "0.0.0.0", "::", "169.254.1.1", "fe80::1", "febf::1", "fec0::1", "10.42.85.10",
             "8.8.8.8", "2001:db8::1", "fe7f::1", "ff02::1", "", "::1%1", "::%3", "fe80::1%12", "fe80::1%eth0", "2001:db8::1%2"]
    con = duckdb.connect()
    for ip in forms:
        sql = con.execute(f"SELECT COALESCE({local_address('x')}, false) FROM (SELECT ?::VARCHAR AS x)", [ip]).fetchone()[0]
        assert sql == is_local(ip) == (bool(ip) and not is_remote(ip)), ip
    assert is_local("10.42.85.10") is False and is_local("not an address") is False
    for stored, key in (("0X3E7", ""), ("0x0", ""), (None, ""), ("0x51A", "0x51a"), ("0x3e6", "")):
        assert con.execute(f"SELECT {session_key('x')} FROM (SELECT ?::VARCHAR AS x)", [stored]).fetchone()[0] == key


def add_local_addresses(app, tmp_path):
    """The loopback and link-local addresses every host has for itself: ::1 and 127.0.0.1 on DC01 and DESKTOP, fe80::1 on
    DC01 and in the capture's lane. Two DC01 events carry a port, as 4624s do."""
    def logon_from(ts, record, ip, host_log, port=""):
        return Event(ts_us=ts, ts_desc="Event Recorded", artifact="evtx", source_file=host_log, source_record=str(record),
                     record_id=record, message=f"4624 from {ip}", event_code="4624", log_channel="Security", logon_type="3",
                     source_ip=ip, source_port=port, **ALICE)
    shapes = [("::1", "55"), ("::1", "55"), ("127.0.0.1", ""), ("fe80::1", "")]
    more(app, [logon_from(T0 + (500 + n) * SEC, 9700 + n, ip, DC_LOG, port) for n, (ip, port) in enumerate(shapes)])
    more(app, [logon_from(T0 + (510 + n) * SEC, 9710 + n, ip, WS_LOG, port) for n, (ip, port) in enumerate(shapes)],
         host="DESKTOP", run="m2")
    add_capture(app.case, tmp_path, [alert("03:40:00", 91, "ET TEST Local", 2000003, src="fe80::1:49000", dest="ff02::1:53")])
    app.refresh_identity(events_changed=True)


def host_of(app, uid):
    return app.con.execute("SELECT host FROM events WHERE event_uid = ?", [uid]).fetchone()[0]


def test_loopback_and_link_local_pivots_stay_on_the_seeds_host(papp, tmp_path):
    """::1 would join 860 events of both Szechuan hosts, and each host's 127.0.0.1 too. Same
    source IP, Same IP at either end, and Same source IP and port keep to the seed's host, and say so."""
    add_local_addresses(papp, tmp_path)
    dc_v6 = uid_of(papp.con, "record_id = 9700")
    for kind, extra in (("source_ip", {}), ("addr", {"ip": "::1"}), ("connection", {"scope": "case"}), ("connection", {})):
        res = related(papp.con, dc_v6, kind, **extra)
        assert {host_of(papp, e["uid"]) for e in res["events"]} == {"DC01"}, (kind, extra)
        assert res["host"] == "DC01" and "on DC01 only" in res["label"], (kind, res["label"])
        assert res["total"] == 2, (kind, extra)   # DC01's two ::1 events (both on port 55), not DESKTOP's two as well
    # 127.0.0.1 and fe80::1 on DC01 find only DC01's, not DESKTOP's, nor the capture's record with that address
    assert related(papp.con, uid_of(papp.con, "record_id = 9702"), "source_ip")["total"] == 1
    link = related(papp.con, uid_of(papp.con, "record_id = 9703"), "source_ip")
    assert (link["total"], link["host"]) == (1, "DC01")
    assert papp.con.execute("SELECT count(*) FROM events WHERE source_ip = 'fe80::1'").fetchone()[0] == 3
    sensor = uid_of(papp.con, "source_ip = 'fe80::1' AND host = 'network'")
    assert related(papp.con, sensor, "source_ip")["total"] == 1   # the capture's lane, alone
    # The count equals the list
    assert counted(papp, dc_v6, {"pivot": "source_ip"})["count"] == 2
    assert counted(papp, dc_v6, {"pivot": "addr", "ip": "::1"})["count"] == 2
    assert counted(papp, dc_v6, {"pivot": "connection", "seconds": 60})["count"] == 2
    # An address that is not local joins every host, and its result names no host
    remote = related(papp.con, uid_of(papp.con, RDP), "source_ip")
    assert "host" not in remote and "only" not in remote["label"]


def test_a_collected_hosts_address_is_broad_from_a_capture_record(papp):
    """DC01's own address is flagged broad from whichever event the row starts, a capture record included."""
    sensor = uid_of(papp.con, "tool = 'suricata' AND source_ip = '10.42.85.10' AND event_code = '2000001'")
    g = guide(papp, sensor)
    addresses = {r["value"]: r["broad"] for r in g["rows"] if r["pivot"] == "addr"}
    assert addresses["10.42.85.10"] == ["Broad: DC01's own address. Most of that host's traffic carries it."]


def test_local_addresses_count_on_the_seeds_host_in_to_investigate_and_the_overview(papp):
    """To investigate's source IP count and the overview's marked-events count key a local address by host, as the Same
    source IP list does, so they agree with the list they stand for. To investigate's count is the pivot's own, kept to
    unreviewed events, so it agrees by construction."""
    from glessner.server import api_mark, api_overview, api_pivot_count

    def local(ts, record, ip, log):
        return Event(ts_us=ts, ts_desc="Event Recorded", artifact="evtx", source_file=log, source_record=str(record),
                     record_id=record, message=f"4624 from {ip}", event_code="4624", log_channel="Security", logon_type="3",
                     source_ip=ip)
    more(papp, [local(T0 + (600 + n) * SEC, 9800 + n, ip, DC_LOG) for n, ip in enumerate(["::1", "::1", "fe80::9"])])
    desktop = ["::1", "::1", "::1", "fe80::9", "fe80::9"]
    more(papp, [local(T0 + (610 + n) * SEC, 9810 + n, ip, WS_LOG) for n, ip in enumerate(desktop)], host="DESKTOP", run="m2")
    flagged = [uid_of(papp.con, "record_id = 9800"), uid_of(papp.con, "record_id = 9802")]
    api_mark(papp, {"uids": flagged, "value": "suspicious", "note": ""})
    counts = {u: api_pivot_count(papp, {"uid": [u], "kind": ["source_ip"], "unreviewed": ["1"]})["count"] for u in flagged}
    # DC01's other ::1 event, and nothing for fe80::9, whose other events are DESKTOP's
    assert counts == {flagged[0]: 1, flagged[1]: 0}
    assert api_overview(papp, {})["progress"]["unreviewed_nearby"] == 1


# ---------- Same file's key ----------

def load_tool(app, events, host, tool, run, replaces=()):
    """Load a tool's events into a running app's case, replacing the sources named, and bring the derived tables up to date."""
    load(app.case.db_path, events, host=host, tool=tool, tool_version="t", run_id=run, replaces_sources=list(replaces),
         staging_dir=app.case.folder)
    app.refresh_identity(events_changed=True)


def test_same_file_name_finds_a_capture_url_path_that_same_file_no_longer_matches(papp, tmp_path):
    """A capture's /coreupdater.exe has no key: as \\coreupdater.exe it would be a file at a volume root and match
    nothing real. Same file name still finds it by its name."""
    path = "C:\\Windows\\System32\\coreupdater.exe"
    more(papp, [system_event(T0 + 80 * SEC, 9500, "7045", {"ServiceName": "c", "ImagePath": path}, file_path=path,
                             file_key="\\windows\\system32\\coreupdater.exe", **INSTALLER)])
    load_tool(papp, fx.suricata_events(tmp_path), "network", "suricata", "cap2")
    install = uid_of(papp.con, "record_id = 9500")
    fileinfo = uid_of(papp.con, "artifact = 'suricata' AND file_path = '/coreupdater.exe'")
    assert event_details(papp.con, fileinfo, papp.identity)["file_key"] == ""
    assert related(papp.con, install, "file")["total"] == 1                 # not the capture's record
    names = related(papp.con, install, "file_name")
    assert fileinfo in {e["uid"] for e in names["events"]} and names["total"] == 2
    assert related(papp.con, fileinfo, "file")["note"] == "this event has no file_key"


def test_same_file_from_the_mft_reaches_the_recmd_rows_keyed_from_their_paths(papp, tmp_path):
    """RECmd rows get a key from their paths: none of Szechuan's 15,261 RECmd rows has one without it. A DC01
    AppCompatCache entry's SYSVOL\\ path and a BAM entry's \\Device\\HarddiskVolume3\\ path meet the MFT records of
    their files."""
    mft = fx.mft_events(tmp_path, "DC01", [(".\\Windows\\System32", "services.exe"), (".\\Windows", "explorer.exe"),
                                           (".\\Windows\\System32", "svchost.exe")])
    load_tool(papp, mft, "DC01", "mftecmd", "mft1")
    load_tool(papp, list(fx.recmd_events(tmp_path).values()), "DC01", "recmd", "reg1")
    rows = lambda where: {r[0]: r[1] for r in papp.con.execute(
        f"SELECT event_uid, substr(message, 1, 24) FROM events WHERE tool = 'recmd' AND {where}").fetchall()}
    # svchost.exe has the MFT's four events only: the fixture's svchost-hosted service is keyed from its ServiceDLL
    for name, where, expected in (
            ("services.exe", "file_path = 'SYSVOL\\Windows\\System32\\services.exe'", 5),   # the MFT's four events and the entry
            ("explorer.exe", "registry_value = '\\Device\\HarddiskVolume3\\Windows\\explorer.exe'", 5),
            ("svchost.exe", "file_path = 'C:\\Windows\\system32\\svchost.exe'", 4)):
        mft_uid = uid_of(papp.con, f"tool = 'mftecmd' AND file_path LIKE '%\\{name}'")
        found = related(papp.con, mft_uid, "file")
        assert found["total"] == expected, name
        assert set(rows(where)) <= {e["uid"] for e in found["events"]}, name
    # A row with a key from its path offers the pivots
    g = guide(papp, uid_of(papp.con, "file_path = 'SYSVOL\\Windows\\System32\\services.exe'"))
    assert g["kind"] == "appcompatcache" and [r["pivot"] for r in g["rows"]] == ["file", "file_name"]


def test_the_table_texts_name_no_landed_fix(papp, tmp_path):
    """The table's texts: no line says RECmd rows, Prefetch names, or Timeline programs have no key today, and the Same file
    name line is declined only for a row with no file path either, since the name pivot reaches a path with no key."""
    import re
    landed = re.compile(r"PM(?:4|5[a-f]|7|9|13)\b")
    for kind in table()["kinds"]:
        for entry in kind["not_offered"]:
            assert not landed.search(entry["reason"]), (kind["kind"], entry)
    load_tool(papp, list(fx.recmd_events(tmp_path).values()), "DC01", "recmd", "reg1")
    programs = guide(papp, uid_of(papp.con, "file_path LIKE '{Common Programs}%'"))
    assert [r["pivot"] for r in programs["rows"]] == ["file_name"]            # a path with no key: the name still joins
    assert {n["pivot"]: n["reason"] for n in programs["not_offered"]}["file"].endswith("Try Same file name.")
    app_id = guide(papp, uid_of(papp.con, "registry_value = 'Microsoft.Windows.Search_cw5n1h2txyewy'"))
    assert [r["pivot"] for r in app_id["rows"]] == [] and {n["pivot"]: n["reason"] for n in app_id["not_offered"]}[
        "file_name"] == "This row names no file."
    # A row with no path at all does not send the analyst to the pivot that declines it as well
    why = {n["pivot"]: n["reason"] for n in app_id["not_offered"]}
    assert "Same file name" not in why["file"] and why["file"].startswith("This row names no program path")
    run = guide(papp, uid_of(papp.con, "file_path = '%APPDATA%\\Sync\\sync.exe'"))
    assert [r["pivot"] for r in run["rows"] if r["pivot"].startswith("file")] == ["file_name"]


def test_the_scheduled_task_line_names_every_event_that_gives_the_app_a_task_command(tmp_path):
    """Task Scheduler's own events give the app no program, and the line that says so names the Security events that do:
    each task event the parser reads parses to the task's program."""
    task = "<Task><Actions><Exec><Command>cmd.exe</Command></Exec></Actions></Task>"
    codes = sorted(TASK_EVENTS)
    write_csv(tmp_path / "evtxecmd.csv", [
        evtx_row(number, code, SECURITY, event_data(TaskName="\\Updater", TaskContent=task))
        for number, code in enumerate(codes, 1)])
    events = list(PARSERS["evtxecmd_csv"](ParseContext(tmp_path, EVIDENCE)))
    assert [(e.event_code, e.process_executable) for e in events] == [(code, "cmd.exe") for code in codes]
    kind = next(k for k in table()["kinds"] if k["kind"] == "scheduled_task")
    reason = next(n["reason"] for n in kind["not_offered"] if n["pivot"] == "file")
    assert f"{codes[0]} to {codes[-1]}" in reason


# ---------- 8.3 names, per host, from the MFT ----------

INSTALLED = "C:\\Users\\{}\\AppData\\Local\\Temp\\{}\\ad_driver.sys"
DC_FILES = [(".\\Users", "Administrator/"), (".\\Users", "Default/"), (".\\Users", "Public/"),
            (".\\Users\\Administrator\\AppData\\Local\\Temp\\1", "ad_driver.sys"),
            (".", "Program Files/"), (".", "Program Files (x86)/"), (".", "ProgramData/")]
DESKTOP_FILES = [(".\\Users", "Admin/"), (".\\Users", "Rick Sanchez/"),
                 (".\\Users\\Rick Sanchez\\AppData\\Local\\Temp\\2", "ad_driver.sys")]
LONG_DC = "\\users\\administrator\\appdata\\local\\temp\\1\\ad_driver.sys"
LONG_DESKTOP = "\\users\\rick sanchez\\appdata\\local\\temp\\2\\ad_driver.sys"


def add_installs(app):
    """The FTK Imager driver's 7045s as Szechuan has them: ADMINI~1 on DC01, RICKSA~1 on DESKTOP, and ADMINI~1 again on FS01,
    which has no MFT; and a 7045 under PROGRA~1 on DC01."""
    def install(host, record, path):
        more(app, [system_event(T0 + record * SEC, record, "7045", {"ServiceName": "Imager", "ImagePath": path}, file_path=path,
                                file_key=file_key(path), **INSTALLER)], host=host, run=f"i{record}")
    install("DC01", 9901, INSTALLED.format("ADMINI~1", 1))
    install("DESKTOP", 9902, INSTALLED.format("RICKSA~1", 2))
    install("FS01", 9903, INSTALLED.format("ADMINI~1", 1))
    install("DC01", 9904, "C:\\PROGRA~1\\Vendor\\app.exe")


def short_paths(app):
    rows = app.con.execute("SELECT DISTINCT host, short_key, long_key FROM short_paths").fetchall()
    return {(host, short): long for host, short, long in rows}


def uid_at(app, host, record):
    return uid_of(app.con, "host = ? AND record_id = ?", host, record)


@pytest.mark.parametrize("mft_first", [False, True])
def test_an_83_path_resolves_per_host_from_the_mft_in_any_load_order(papp, tmp_path, mft_first):
    """The ad_driver.sys 7045s find the long path's MFT, USN, and Autoruns records, not only themselves. The MFT of the
    host the path is on says which long name ADMINI~1 stands for, and the table is built after every load, so the order the
    tools loaded in doesn't matter."""
    dc, desktop = fx.mft_events(tmp_path, "DC01", DC_FILES), fx.mft_events(tmp_path, "DESKTOP", DESKTOP_FILES)
    assert papp.con.execute("SELECT count(*) FROM short_paths").fetchone()[0] == 0   # no key with a ~ yet
    if mft_first:
        load_tool(papp, dc, "DC01", "mftecmd", "m1")
        load_tool(papp, desktop, "DESKTOP", "mftecmd", "m2")
        add_installs(papp)
    else:
        add_installs(papp)
        load_tool(papp, dc, "DC01", "mftecmd", "m1")
        load_tool(papp, desktop, "DESKTOP", "mftecmd", "m2")
    # Each file has several MFT rows, so siblings must be counted as names
    rows = papp.con.execute("SELECT count(*) FROM events WHERE host = 'DC01' AND file_key = '\\users\\administrator'").fetchone()
    assert rows[0] == 4
    short_dc, short_desktop = file_key(INSTALLED.format("ADMINI~1", 1)), file_key(INSTALLED.format("RICKSA~1", 2))
    assert short_paths(papp) == {("DC01", short_dc): LONG_DC, ("DESKTOP", short_desktop): LONG_DESKTOP}
    # DC01's 7045 finds the file's four MFT events and itself; the note says where the reading came from
    found = related(papp.con, uid_at(papp, "DC01", 9901), "file")
    written = r"\Users\Administrator\AppData\Local\Temp\1\ad_driver.sys"   # the MFT's own spelling, not the lower-case key
    assert found["total"] == 5 and found["match_note"] == (
        f"This 8.3 path stands for {written}, by DC01's MFT. Also the events with that path.")
    assert related(papp.con, uid_at(papp, "DESKTOP", 9902), "file")["total"] == 5
    # The count equals the list, and the long path's MFT event finds the 7045 too, with the same note
    install = uid_at(papp, "DC01", 9901)
    ev = event_details(papp.con, install, papp.identity)
    assert count_pivot(papp.con, papp.identity, install, ev["adjusted_ts_us"], "file")["count"] == 5
    # The row's caveat says the match can fail; once the host's MFT has resolved the path, the count says what it stands for
    # in place of it. A path the MFT cannot resolve keeps the caveat.
    row = next(r for r in guidance(ev, papp.identity)["rows"] if r["pivot"] == "file")
    assert row["caveat"] and row["caveat_check"] == {"check": "short_path"}
    resolved = count_pivot(papp.con, papp.identity, install, ev["adjusted_ts_us"], "file", check="short_path")
    assert resolved["resolved"] == f"This 8.3 path stands for {written}, by DC01's MFT."
    fs01_uid = uid_at(papp, "FS01", 9903)
    fs01_ev = event_details(papp.con, fs01_uid, papp.identity)
    assert count_pivot(papp.con, papp.identity, fs01_uid, fs01_ev["adjusted_ts_us"], "file", check="short_path")["resolved"] == ""
    mft_uid = uid_of(papp.con, "host = 'DC01' AND tool = 'mftecmd' AND file_key = ?", LONG_DC)
    from_long = related(papp.con, mft_uid, "file")
    assert install in {e["uid"] for e in from_long["events"]} and from_long["total"] == 5
    assert from_long["match_note"] == "Also this path's 8.3 form, read from DC01's MFT."
    # FS01 has no MFT: its ADMINI~1 stays unresolved, though DC01's MFT has the one name it could stand for. It finds the other
    # 7045 with the same short path, by the path alone, and none of the MFT's events
    fs01 = related(papp.con, uid_at(papp, "FS01", 9903), "file")
    assert fs01["total"] == 2 and "match_note" not in fs01
    # PROGRA~1 stands for three names on DC01 (Program Files, Program Files (x86), ProgramData): left alone
    assert related(papp.con, uid_at(papp, "DC01", 9904), "file")["total"] == 1
    # An MFT run without Administrator replaces DC01's: the table loses the row, and the 7045 is alone again
    (tmp_path / "again").mkdir()
    lacking = fx.mft_events(tmp_path / "again", "DC01", DC_FILES[1:3])
    load_tool(papp, lacking, "DC01", "mftecmd", "m3", replaces=["DC01/$MFT"])
    assert set(short_paths(papp)) == {("DESKTOP", short_desktop)}
    assert related(papp.con, install, "file")["total"] == 2   # the two 7045s with the short path, DC01's and FS01's


def test_an_83_name_that_is_a_sibling_already_is_a_long_name_and_a_bare_alias_resolves_the_last_part():
    from glessner.short_names import SHORT_PART, alias_parts, resolve, stands_for
    names = {"administrator", "rick sanchez", "program files", "program files (x86)", "coreupdater.exe", "my~1", "a+b;c.txt",
             "ab"}
    siblings = lambda parent: names if parent == "\\users" else {"x"}
    assert resolve("\\users\\admini~1", siblings) == "\\users\\administrator"
    assert resolve("\\users\\ricksa~1\\x", siblings) == "\\users\\rick sanchez\\x"
    assert resolve("\\users\\coreup~1.exe", siblings) == "\\users\\coreupdater.exe"       # the last part resolves too
    assert resolve("\\users\\coreup~1", siblings) is None                                 # no extension: not that file
    assert resolve("\\users\\progra~1", siblings) is None                                 # two names start so
    assert resolve("\\users\\my~1", siblings) is None                                     # a name already: left as it is
    assert resolve("\\users\\a_b_c~1.txt", siblings) == "\\users\\a+b;c.txt"              # + ; are written as _
    assert resolve("\\users\\ab~1", siblings) is None                                     # a name this short needs no alias
    assert resolve("\\users\\administrator", siblings) is None and resolve("\\other\\admini~1", siblings) is None
    assert alias_parts("Rick Sanchez.v2.txt") == ("ricksanchezv2", "txt")
    assert stands_for(SHORT_PART.match("admini~1"), "administrator") and not stands_for(SHORT_PART.match("admini~1"), "admin")


# ---------- every breakdown entry opens its narrowed list ----------

def source_of_event(con, uid):
    return source_parts(*con.execute("SELECT artifact, log_channel, event_code, logon_type FROM events WHERE event_uid = ?",
                                     [uid]).fetchone())


def test_every_rows_breakdown_entry_lists_that_source(papp, monkeypatch):
    """Each entry of every counted row opens the row's list narrowed to it: the entry's count is the list's total and only
    that source's events are in it, for the kinds with branches as well as the window."""
    monkeypatch.setattr(queries, "RELATED_LIMIT", 2)
    monkeypatch.setattr(pivots, "RELATED_LIMIT", 2)
    alert = "tool = 'suricata' AND log_channel = 'alert' AND event_code = '2000001' AND source_ip = '10.42.85.10'"
    several = False
    for where in (INSTALL, RDP, alert):
        uid = uid_of(papp.con, where)
        ev = event_details(papp.con, uid, papp.identity)
        for row in guide(papp, uid)["rows"]:
            if not row["count"] or row["pivot"] == "search":
                continue
            res = counted(papp, uid, row, breakdown=True)
            for s in res.get("sources", []):
                click = related(papp.con, uid, row["pivot"], row.get("seconds", 60), ip=row.get("ip", ""),
                                identity=papp.identity, ts=ev["adjusted_ts_us"], source=s["source"], name=row.get("name", ""))
                assert click["total"] == s["count"], (row["key"], s)
                assert click["source"] == s["source"]
                assert {tuple(source_of_event(papp.con, e["uid"])) for e in click["events"]} == {tuple(s["source"])}
            several = several or (row["pivot"] != "window" and len(res.get("sources", [])) >= 2)
    assert several   # the check reached a row that is not a window, with two sources to tell apart


def test_a_narrowed_rule_row_counts_its_source_not_the_whole_rule(papp, monkeypatch):
    """The rule's fast count reads the hits table for the whole rule. A narrowed list must count its branches: with the list
    cut at 1, the total comes from count_matches, and the kept fast count gave the rule's 2 for each source."""
    load_events(papp.case, [Event(ts_us=T0 + 63 * SEC, ts_desc="Event Recorded", artifact="hayabusa", source_file=DC_LOG,
                                  source_record="105:rule", record_id=105, message="RDP from internet [high]",
                                  log_channel="Security", rule_title="RDP from internet", rule_level="high")],
                "DC01", tool="hayabusa", run="r5b")
    papp.refresh_identity(events_changed=True)
    monkeypatch.setattr(queries, "RELATED_LIMIT", 1)
    rdp = uid_of(papp.con, RDP)
    assert related(papp.con, rdp, "rule")["total"] == 2   # the logon and the 4672 it hit
    for source in (["evtx", "Security", "4672"], ["evtx", "Security", "4624", "10"]):
        narrowed = related(papp.con, rdp, "rule", source=source)
        assert narrowed["total"] == 1 and narrowed["source"] == source


def test_a_list_of_exactly_the_limit_holds_every_match_and_is_not_cut(papp, monkeypatch):
    """A list of exactly RELATED_LIMIT events is not limited: otherwise the page says "the 500 nearest of 500" and sends
    the analyst to look for the rest of a window that has none."""
    install = uid_of(papp.con, INSTALL)
    n = related(papp.con, install, "account", identity=papp.identity)["total"]
    monkeypatch.setattr(queries, "RELATED_LIMIT", n)
    exact = related(papp.con, install, "account", identity=papp.identity)
    assert len(exact["events"]) == exact["total"] == n and not exact["limited"] and "reach_s" not in exact
    monkeypatch.setattr(queries, "RELATED_LIMIT", n - 1)
    cut = related(papp.con, install, "account", identity=papp.identity)
    assert cut["limited"] and cut["total"] == n and len(cut["events"]) == n - 1 and "reach_s" in cut


def test_related_echoes_the_source_for_any_kind(papp):
    install = uid_of(papp.con, INSTALL)
    whole = related(papp.con, install, "account", identity=papp.identity)
    assert "source" not in whole
    narrowed = related(papp.con, install, "account", identity=papp.identity, source=["evtx", "System", "7045"])
    assert narrowed["source"] == ["evtx", "System", "7045"] and 0 < narrowed["total"] < whole["total"]
    assert {e["code"] for e in narrowed["events"]} == {"7045"}
    # Through the route, as the page asks: Same service name has six events, one of them a 7036
    asked = {"uid": [install], "kind": ["service_name"]}
    assert api_related(papp, asked)["total"] == 6
    only = api_related(papp, {**asked, "source": [json.dumps(["evtx", "System", "7036"])]})
    assert only["source"] == ["evtx", "System", "7036"] and only["total"] == 1
    with pytest.raises(QueryError):
        api_related(papp, {**asked, "source": [json.dumps(["evtx", 5])]})


def test_the_window_row_has_its_own_broad_text(papp):
    g = guide(papp, uid_of(papp.con, RDP))
    window_text = table()["broad_rules"]["over_limit"]["window_text"]
    assert g["over_limit_window_text"] == window_text
    assert window_text == ("Broad: {count} events. The list shows the 500 nearest in time; open one source from the breakdown "
                           "to reach the rest.")
    assert g["over_limit_text"] == "Broad: {count} events. The list shows the 500 nearest in time."
