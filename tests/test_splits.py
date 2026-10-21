"""Splitting a host whose event logs record several computers: detection, the preview, the split and its undo, and every
reference that must survive them."""

import json

import pytest
from test_parsers import EVTX_COLUMNS, event_data, write_csv

from glessner.analysis import orphan_marks
from glessner.audit import AuditError, describe, plan_undo, read_entries, rows
from glessner.case import copy_case, create_case
from glessner.events import Event, connect, load
from glessner.journal import Journal, JournalError, host_layout
from glessner.queries import event_details, pending_events, related
from glessner.runner import RunRecord, _write_record, load_output, rebuild
from glessner.search import save_hits
from glessner.server import (
    App,
    api_event,
    api_host,
    api_host_split,
    api_mark,
    api_note,
    api_suggestion,
    api_tag,
    api_tag_suggestion,
)
from glessner.splits import Routes, SplitError, apply_layout, computer_key, machines, proposal

HAYABUSA_COLUMNS = ["Timestamp", "RuleTitle", "Level", "Computer", "Channel", "EventID", "MitreTactics", "MitreTags",
                    "OtherTags", "RecordID", "Details", "ExtraFieldInfo", "RuleFile", "RuleID", "EvtxFile"]
PC01_SEC, PC01_SYS = "LM/PC01_Security.evtx", "LM/PC01_Sysmon.evtx"
EDGE_SEC, DC1_SEC = "LM/msedge_Security.evtx", "LM/DC1_Security.evtx"
SID = "S-1-5-21-3623811015-3361044348-30300820-1013"


def security(case, record, code, computer, file, minute, **payload):
    return {"EventRecordId": str(record), "TimeCreated": f"2020-09-19 03:{minute:02}:00.0000000", "EventId": str(code),
            "Provider": "Microsoft-Windows-Security-Auditing", "Channel": "Security", "Computer": computer,
            "SourceFile": str(case.evidence / file), "MapDescription": "", "Payload": event_data(**payload)}


def hit(case, record, computer, file, minute, title, tactics=""):
    return {"Timestamp": f"2020-09-19T03:{minute:02}:00Z", "RuleTitle": title, "Level": "high", "Computer": computer,
            "Channel": "Security", "EventID": "4624", "RecordID": str(record), "RuleID": f"rule-{record}",
            "MitreTactics": tactics, "EvtxFile": str(case.evidence / file)}


def make_run(case, tool, parser, name, columns, rows, inputs, stamp):
    """A tool's run on LAB as the runner leaves it: run.json and the output, loaded."""
    run_id = f"20261015T0{stamp}0000Z_{tool}_LAB"
    folder = case.runs_folder / run_id
    (folder / "output").mkdir(parents=True)
    write_csv(folder / "output" / name, columns, rows)
    record = RunRecord(run_id=run_id, tool=tool, tool_version="t", executable="", host="LAB", argv=[], cwd="",
                       inputs=list(inputs), started_utc="2026-10-15T00:00:00Z", status="ok", parser=parser)
    _write_record(folder, record)
    load_output(case, record, folder)
    return record, folder


def lab_case(tmp_path, *, extra_rows=()):
    """A one-folder collection, LAB, of loose event logs from three computers, as in EVTX-ATTACK-SAMPLES: PC01 (two
    files), MSEDGEWIN10 (bare name), and DC1, which logged a Kerberos ticket request. PC01 and MSEDGEWIN10 each have a
    logon in the system session 0x3E7. Hayabusa hit one event of each; the hit on DC1's records no Computer."""
    (tmp_path / "evidence" / "LM").mkdir(parents=True)
    case = create_case(tmp_path / "case", "Samples", tmp_path / "evidence", "cody", single_host="LAB")
    pc01, edge, dc1 = "PC01.example.corp", "MSEDGEWIN10", "DC1.insecurebank.local"
    evtx = [
        security(case, 1, 4624, pc01, PC01_SEC, 1, TargetUserName="alice", TargetDomainName="CORP", LogonType="3",
                 TargetLogonId="0x3E7", IpAddress="10.0.2.15", TargetUserSid=SID),
        security(case, 2, 4688, pc01, PC01_SEC, 2, NewProcessName="C:\\Windows\\System32\\cmd.exe"),
        security(case, 1, 4688, pc01, PC01_SYS, 3, NewProcessName="C:\\Windows\\System32\\whoami.exe"),
        security(case, 1, 4624, edge, EDGE_SEC, 4, TargetUserName="bob", LogonType="3", TargetLogonId="0x3E7",
                 IpAddress="10.0.2.15"),
        security(case, 2, 4104, edge, EDGE_SEC, 5, ScriptBlockText="whoami"),
        security(case, 1, 4768, dc1, DC1_SEC, 6, TargetUserName="carol"),
        *extra_rows,
    ]
    evtx[4]["UserId"] = SID   # a 4104 known only by its SID, which only PC01's logon names
    runs = {"evtx": make_run(case, "evtxecmd", "evtxecmd_csv", "evtxecmd.csv", EVTX_COLUMNS, evtx,
                             [PC01_SEC, PC01_SYS, EDGE_SEC, DC1_SEC], 1)}
    hits = [hit(case, 1, pc01, PC01_SEC, 1, "Logon from PC01", "LatMov"), hit(case, 1, edge, EDGE_SEC, 4, "Logon"),
            hit(case, 1, "", DC1_SEC, 6, "Kerberos TGT")]
    runs["hayabusa"] = make_run(case, "hayabusa", "hayabusa_csv", "hayabusa.csv", HAYABUSA_COLUMNS, hits,
                                [PC01_SEC, PC01_SYS, EDGE_SEC, DC1_SEC], 2)
    return case, runs


def rows_of(con, where="true"):
    """Each row's ID, lane, and origin, sorted, for comparing tables."""
    return con.execute(f"SELECT event_uid, host, origin_host FROM events WHERE {where} ORDER BY ALL").fetchall()


def lane(con, uid):
    return con.execute("SELECT host FROM events WHERE event_uid = ?", [uid]).fetchone()[0]


def uid_of(con, file, record, tool="evtxecmd"):
    return con.execute("SELECT event_uid FROM events WHERE tool = ? AND source_file = ? AND record_id = ?",
                       [tool, file, record]).fetchone()[0]


def split(app, host="LAB"):
    plan = api_host_split(app, {"host": [host]})
    return api_host(app, {"split": host, "basis": plan["basis"]}), plan


def test_a_folder_of_three_computers_raises_the_notice(tmp_path):
    """LAB's event logs name three computers, so it's flagged with the numbers the notice gives. One host folder per
    machine, as in the synthetic case, never is."""
    case, _ = lab_case(tmp_path)
    app = App(case)
    try:
        assert app.identity.mixed == {"LAB": {"host": "LAB", "computers": 3, "names": 3, "role": "Domain controllers",
                                              "role_source": "guess", "forwarded": 0}}
        assert "Its event logs were recorded by 3 computers" in app.identity.hosts["LAB"].review
        found = machines(app.con)["LAB"]
        assert [(m.names, m.events, len(m.files)) for m in found] == [
            (["PC01.example.corp"], 3, 2), (["MSEDGEWIN10"], 2, 1), (["DC1.insecurebank.local"], 1, 1)]
    finally:
        app.con.close()


def test_the_synthetic_case_raises_no_notice(synthetic_case):
    app = App(synthetic_case)
    try:
        assert app.identity.mixed == {} and machines(app.con)["DC01"][0].names == ["CITADEL-DC01.C137.local"]
    finally:
        app.con.close()


def test_one_machine_under_several_names_is_one_computer(tmp_path):
    """A host renamed within one log (WIN-OLD, later PC07.corp.local), and a name beside its qualified form (PC07 in
    another file), are one computer. Forwarded events join nothing: the collector WEC01's ForwardedEvents.evtx holds
    two other computers', so WEC01 has three, and its own stays on it."""
    db = tmp_path / "events.duckdb"

    def ev(record, computer, file, channel="Security"):
        return Event(1600485708000000 + record, "Event Recorded", "evtx", file, str(record), "x",
                     host_name_recorded=computer, log_channel=channel, record_id=record)

    load(db, [ev(1, "WIN-OLD", "PC07/Security.evtx"), ev(2, "PC07.corp.local", "PC07/Security.evtx"),
              ev(3, "PC07", "PC07/System.evtx")], host="PC07", tool="evtxecmd", tool_version="t", run_id="r1",
         replaces_sources=[], staging_dir=tmp_path)
    load(db, [ev(1, "WEC01.corp.local", "WEC01/Security.evtx"),
              ev(2, "PC08.corp.local", "WEC01/ForwardedEvents.evtx"), ev(3, "PC09.corp.local", "WEC01/ForwardedEvents.evtx"),
              ev(4, "WEC01.corp.local", "WEC01/ForwardedEvents.evtx")],
         host="WEC01", tool="evtxecmd", tool_version="t", run_id="r2", replaces_sources=[], staging_dir=tmp_path)
    con = connect(db)
    try:
        found = machines(con)
        assert [sorted(m.names) for m in found["PC07"]] == [["PC07", "PC07.corp.local", "WIN-OLD"]]
        assert found["PC07"][0].newest == "PC07"
        wec = {m.names[0]: m for m in found["WEC01"]}
        assert sorted(wec) == ["PC08.corp.local", "PC09.corp.local", "WEC01.corp.local"]
        assert (wec["PC08.corp.local"].forwarded, wec["WEC01.corp.local"].forwarded) == (1, 1)
        from glessner.analysis import build_identity
        from glessner.journal import State

        state = State()
        plan = proposal(con, state, build_identity(con, state), "WEC01", found, {"PC07", "WEC01"})
        assert [(g["lane"], g["forwarded"]) for g in plan["groups"]] == [("PC08", 1), ("PC09", 1)]
        assert plan["stays"]["computers"] == [{"names": ["WEC01.corp.local"], "events": 2,
                                               "reason": "the host folder's name"}]
        assert plan["hosts_after"] == 3
    finally:
        con.close()


def test_a_collector_s_custom_log_and_its_own_logs_under_an_evidence_id(tmp_path):
    """A subscription writing to a custom log, WEC-Security.evtx, holds its computers' events as they
    arrived, interleaved, so the log joins nothing and each computer stays itself; a renamed host's own log, one name
    and then the other, still joins. A collector in a folder named by evidence ID, with no SYSTEM hive, keeps its own
    logs: it's the one computer whose events weren't all forwarded."""
    from glessner.analysis import build_identity
    from glessner.journal import State

    db = tmp_path / "events.duckdb"

    def ev(record, computer, file):
        return Event(1600485708000000 + record, "Event Recorded", "evtx", file, str(record), "x",
                     host_name_recorded=computer, log_channel="Security", record_id=record)

    load(db, [ev(1, "WEC02.corp.local", "WEC02/Security.evtx"),
              *(ev(n, ("PC10.corp.local", "PC11.corp.local")[n % 2], "WEC02/WEC-Security.evtx") for n in range(2, 8)),
              ev(1, "WIN-OLD", "WEC02/Renamed/Security.evtx"), ev(2, "WIN-OLD", "WEC02/Renamed/Security.evtx"),
              ev(3, "PC12.corp.local", "WEC02/Renamed/Security.evtx")],
         host="WEC02", tool="evtxecmd", tool_version="t", run_id="r1", replaces_sources=[], staging_dir=tmp_path)
    load(db, [ev(1, "WEC01.corp.local", "E01/Security.evtx"), ev(2, "WEC01.corp.local", "E01/System.evtx"),
              ev(3, "PC08.corp.local", "E01/ForwardedEvents.evtx"), ev(4, "PC09.corp.local", "E01/ForwardedEvents.evtx")],
         host="E01", tool="evtxecmd", tool_version="t", run_id="r2", replaces_sources=[], staging_dir=tmp_path)
    con = connect(db)
    try:
        found = machines(con)
        assert sorted(sorted(m.names) for m in found["WEC02"]) == [
            ["PC10.corp.local"], ["PC11.corp.local"], ["PC12.corp.local", "WIN-OLD"], ["WEC02.corp.local"]]
        assert {m.names[0]: m.forwarded for m in found["WEC02"]}["PC10.corp.local"] == 3
        state = State()
        plan = proposal(con, state, build_identity(con, state), "E01", found, {"E01", "WEC02"})
        assert [g["lane"] for g in plan["groups"]] == ["PC08", "PC09"]
        assert plan["stays"]["computers"] == [{"names": ["WEC01.corp.local"], "events": 2,
                                               "reason": "the only event logs here that weren't forwarded from other "
                                                         "computers"}]
    finally:
        con.close()


def test_names_a_split_leaves_on_purpose_raise_no_notice(tmp_path):
    """A bare PC01 beside PC01.a.corp and PC01.b.corp could be either, so the split leaves it on LAB with
    LAB's own name, and says why. The notice doesn't come straight back for the two computers left there; it returns
    after the undo."""
    (tmp_path / "evidence").mkdir()
    case = create_case(tmp_path / "case", "Bare", tmp_path / "evidence", "cody", single_host="LAB")
    load(case.db_path, [Event(1600485708000000 + i, "Event Recorded", "evtx", f"LAB/f{i}.evtx", "1", "x",
                              host_name_recorded=n) for i, n in enumerate(["LAB", "PC01.a.corp", "PC01.b.corp", "PC01"])],
         host="LAB", tool="evtxecmd", tool_version="t", run_id="r1", replaces_sources=[], staging_dir=case.folder)
    app = App(case)
    try:
        payload, plan = split(app)
        assert sorted(c["names"][0] for c in plan["stays"]["computers"]) == ["LAB", "PC01"]
        assert app.identity.mixed == {} and payload["kept"] == [] and app.journal.state.kept["LAB"] == {"lab", "pc01"}
        api_host(app, {"unsplit": "LAB"})
        assert app.identity.mixed["LAB"]["computers"] == 4
    finally:
        app.con.close()


def test_a_split_waiting_on_the_lock_sees_a_job_started_meanwhile(tmp_path, monkeypatch):
    """A split checks for a running tool under the app's lock, and the run endpoints start their jobs
    under it, so a split that waited behind an import can't go ahead while a job's load is in flight."""
    import threading

    from glessner import server

    case, _ = lab_case(tmp_path)
    app = App(case)
    try:
        plan = api_host_split(app, {"host": ["LAB"]})
        inner, waiting = app.lock, threading.Event()

        class Watched:   # says when another thread waits for the lock
            def __enter__(self):
                if threading.current_thread() is not threading.main_thread():
                    waiting.set()
                return inner.__enter__()

            def __exit__(self, *exc):
                return inner.__exit__(*exc)

        app.lock = Watched()
        failed = []

        def make_split():
            try:
                api_host(app, {"split": "LAB", "basis": plan["basis"]})
            except ValueError as exc:
                failed.append(str(exc))

        with inner:   # as an import holds it
            worker = threading.Thread(target=make_split)
            worker.start()
            assert waiting.wait(10)
            app.job = type("Job", (), {"finished": False, "tool": "EvtxECmd"})()
        worker.join(10)
        assert failed == ["EvtxECmd is still running; split, keep, or undo once it finishes."]
        assert not any(e["action"] == "host_split" for e in read_entries(app.journal.path))
        # Each run endpoint sets the job while it holds the lock
        app.lock, app.job, held = inner, None, []

        def try_lock():
            got = inner.acquire(blocking=False)
            if got:
                inner.release()
            held.append(not got)

        def start(*args, **kwargs):
            probe = threading.Thread(target=try_lock)
            probe.start()
            probe.join()
            return type("Job", (), {"finished": True, "tool": "t", "state": lambda self: {}})()

        monkeypatch.setattr(server, "_tools", lambda app: ({"t": None}, {"t": None}))
        for name in ("start_tool_job", "start_load_job", "start_all_job"):
            monkeypatch.setattr(server, name, start)
        server.api_run_tool(app, {"tool": "t"})
        server.api_load_output(app, {"key": "k"})
        server.api_run_all(app, {})
        assert held == [True, True, True]
    finally:
        app.con.close()


def test_routes_go_by_name_then_by_a_label_only_one_domain_routed():
    routes = Routes({"pc01.example.corp": "PC01", "pc01": "PC01", "msedgewin10": "MSEDGEWIN10"})
    assert routes.lane(" PC01.Example.Corp ") == "PC01" and routes.lane("PC01") == "PC01"
    assert routes.lane("pc01.other.corp") is None        # another domain: another machine
    assert routes.lane("MSEDGEWIN10.lab.local") == "MSEDGEWIN10"   # the routed name had no domain
    assert routes.lane("") is None and routes.lane(None) is None and computer_key(" A.B ") == "a.b"


def test_the_preview_names_counts_and_what_stays(tmp_path):
    """The preview of LAB: a new host per computer with its event log events, Hayabusa rows, and files. The Hayabusa
    row with no Computer stays on LAB, so LAB stays a host. Marks, notes, and tags on moving events are counted, and
    the analyst's role for LAB is named as staying with it."""
    case, _ = lab_case(tmp_path)
    app = App(case)
    try:
        x = uid_of(app.con, PC01_SEC, 1)
        api_mark(app, {"uids": [x], "value": "malicious"})
        api_note(app, {"uid": x, "text": "first look"})
        api_host(app, {"host": "LAB", "role": "Workstations"})
        plan = api_host_split(app, {"host": ["LAB"]})
        assert [(g["lane"], g["names"], g["events"], g["hayabusa"], g["files"]) for g in plan["groups"]] == [
            ("PC01", ["PC01.example.corp"], 3, 1, 2), ("MSEDGEWIN10", ["MSEDGEWIN10"], 2, 1, 1),
            ("DC1", ["DC1.insecurebank.local"], 1, 0, 1)]
        assert plan["stays"] == {"total": 1, "computers": [], "rows": [{"tool": "hayabusa", "artifact": "hayabusa",
                                                                         "count": 1}]}
        assert (plan["computers"], plan["hosts_after"], plan["moving"]) == (3, 4, {"marks": 1, "notes": 1, "tags": 0})
        assert plan["edits"] == ["its role, Workstations"] and "routes" not in plan
        with pytest.raises(SplitError, match="one computer"):
            api_host_split(app, {"host": ["NOPE"]})
    finally:
        app.con.close()


def test_new_host_names(tmp_path):
    """A computer with the folder's name, in any case, stays. Names another host, a host folder, or another computer
    here has take the folder's name as a suffix. One label in two domains takes the domain; a bare one beside them
    stays. A hostile name is cleaned, and one with nothing left is numbered."""
    db = tmp_path / "events.duckdb"
    names = ["lab.corp.local", "DC01.corp.local", "pc01.a.corp", "pc01.b.corp", "PC01", "WS9.corp.local",
             "<script>alert(1)</script>", "....", "x" * 80 + ".corp"]
    load(db, [Event(1600485708000000 + i, "Event Recorded", "evtx", f"LAB/f{i}.evtx", "1", "x", host_name_recorded=n)
              for i, n in enumerate(names)], host="LAB", tool="evtxecmd", tool_version="t", run_id="r1",
         replaces_sources=[], staging_dir=tmp_path)
    load(db, [Event(1600485708000000, "Event Recorded", "evtx", "DC01/a.evtx", "1", "x", host_name_recorded="DC01")],
         host="DC01", tool="evtxecmd", tool_version="t", run_id="r2", replaces_sources=[], staging_dir=tmp_path)
    con = connect(db)
    try:
        from glessner.analysis import build_identity
        from glessner.journal import State

        state = State()
        identity = build_identity(con, state)
        plan = proposal(con, state, identity, "LAB", machines(con), {"LAB", "DC01", "WS9"})
        lanes = {g["names"][0]: (g["lane"], g["note"]) for g in plan["groups"]}
        assert lanes["DC01.corp.local"] == ("DC01-LAB", "DC01 is already a host here")
        assert lanes["WS9.corp.local"] == ("WS9-LAB", "a host folder is named WS9")
        assert (lanes["pc01.a.corp"][0], lanes["pc01.b.corp"][0]) == ("PC01-A", "PC01-B")
        assert lanes["<script>alert(1)</script>"][0] == "SCRIPT-ALERT-1-SCRIPT"
        assert lanes["...."][0] == "LAB-COMPUTER-1"
        assert lanes["x" * 80 + ".corp"][0] == "X" * 63
        stays = {c["names"][0]: c["reason"] for c in plan["stays"]["computers"]}
        assert stays == {"lab.corp.local": "the host folder's name",
                         "PC01": "a name without a domain that two other computers share"}
        assert plan["routes"]["pc01.a.corp"] == "PC01-A" and "pc01" not in plan["routes"]
    finally:
        con.close()


def test_marks_notes_and_tags_survive_a_split_reruns_rebuilds_and_its_undo(tmp_path):
    """Five steps on event X, PC01's logon, loaded from LAB: #10 marks it; #11 splits, X shows on PC01
    with the same ID; #12 marks it again from PC01's lane; #13 undoes the split; #14 marks it. A rerun of EvtxECmd and a
    rebuild after the split and after the undo leave every ID and lane as they were. Undoing #10 keeps #12's mark.
    Notes, tags, a rejected suggestion, and a dismissed suggested tag stay on their events throughout."""
    case, runs = lab_case(tmp_path)
    con = connect(case.db_path)
    before = rows_of(con)
    con.close()
    app = App(case)
    x = uid_of(app.con, PC01_SEC, 1)
    y = uid_of(app.con, EDGE_SEC, 1)
    kerberos = uid_of(app.con, DC1_SEC, 1)
    first = api_mark(app, {"uids": [x], "value": "suspicious"})["seq"]
    api_note(app, {"uid": x, "text": "looks like lateral movement"})
    api_tag(app, {"uids": [x], "add": ["lateral-movement"]})
    api_suggestion(app, {"decision": "reject", "source": "hayabusa", "uids": [y]})
    api_tag_suggestion(app, {"uids": [x], "tags": ["tactic:TA0008"], "decision": "dismissed"})
    hits = app.con.execute("SELECT count(*) FROM hits").fetchone()[0]
    payload, _ = split(app)
    assert sorted(h["host"] for h in payload["hosts"]) == ["DC1", "LAB", "MSEDGEWIN10", "PC01"]
    assert payload["mixed"] == [] and payload["splits"][0]["lanes"] == ["DC1", "MSEDGEWIN10", "PC01"]
    assert lane(app.con, x) == "PC01" and lane(app.con, y) == "MSEDGEWIN10"
    second = api_mark(app, {"uids": [x], "value": "malicious"})["seq"]

    def check(con, lanes):
        assert sorted(u for u, *_ in rows_of(con)) == sorted(u for u, *_ in before)
        assert (lane(con, x), lane(con, y)) == lanes
        assert orphan_marks(con) == 0
        assert con.execute("SELECT label FROM marks WHERE event_uid = ?", [x]).fetchone() == ("Malicious",)
        assert con.execute("SELECT count(*) FROM hits").fetchone()[0] == hits
        # The hit that records no computer stays on LAB and still finds DC1's event, on its page and the Suggestions page
        assert event_details(con, kerberos)["hits"] == [{"title": "Kerberos TGT", "level": "high"}]
        assert "Kerberos TGT" in {g["key"] for g in pending_events(con, "hayabusa", "rule")["groups"]}
        assert con.execute("SELECT tag FROM tags WHERE event_uid = ?", [x]).fetchall() == [("tag:lateral-movement",)]
        assert con.execute("SELECT count(*) FROM tag_suggestions WHERE event_uid = ?", [x]).fetchone()[0] == 0
        assert con.execute("SELECT count(*) FROM suggested WHERE event_uid = ?", [y]).fetchone()[0] == 0

    check(app.con, ("PC01", "MSEDGEWIN10"))
    app.con.close()
    load_output(case, *runs["evtx"])   # a rerun of EvtxECmd on the split host
    rebuild(case)
    app = App(case)
    check(app.con, ("PC01", "MSEDGEWIN10"))
    assert app.journal.state.notes[x][0]["text"] == "looks like lateral movement"
    plan = plan_undo(read_entries(app.journal.path), first)
    assert (plan["changes"], plan["kept"]) == ([], [x])   # #12 marked X since
    api_host(app, {"unsplit": "LAB"})
    assert rows_of(app.con) == before
    api_mark(app, {"uids": [x], "value": "malicious", "note": "after the undo"})
    check(app.con, ("LAB", "LAB"))
    app.con.close()
    load_output(case, *runs["evtx"])
    rebuild(case)
    con = connect(case.db_path)
    assert rows_of(con) == before
    con.close()
    entries = read_entries(case.folder / "journal.jsonl")
    assert [e["op"] for e in entries if e["action"] == "host_split"] == ["split", "undo"]
    assert second > first


def test_a_split_applied_to_loaded_rows_equals_a_rebuild_with_it(tmp_path):
    """The UPDATE and the loader route alike: the case split in place, and rebuilt from its runs with the split in the
    journal, have the same rows in the same lanes. A journal entry whose update never ran, as after a crash, is made
    when the case opens, and the searches saved on the old lanes go with it."""
    from glessner.analysis import build_identity
    from glessner.journal import replay

    case, _ = lab_case(tmp_path)
    app = App(case)
    plan = api_host_split(app, {"host": ["LAB"]})
    save_hits(app.con, "host:LAB")
    app.con.close()
    con = connect(case.db_path)
    state = replay(case.folder / "journal.jsonl")
    found = proposal(con, state, build_identity(con, state), "LAB", machines(con), {"LAB"})   # as the server journals it
    con.close()
    assert found["basis"] == plan["basis"]
    routes = found["routes"]
    Journal(case).append("host_split", op="split", host="LAB", routes=routes)   # written, not applied
    app = App(case)
    applied = rows_of(app.con)
    assert lane(app.con, uid_of(app.con, DC1_SEC, 1)) == "DC1"
    assert app.con.execute("SELECT count(*) FROM search_runs").fetchone()[0] == 0
    assert apply_layout(app.con, app.journal.state) == set()   # nothing left to change
    app.con.close()
    assert host_layout(case) == {"LAB": routes}
    rebuild(case)
    con = connect(case.db_path)
    try:
        assert rows_of(con) == applied
        assert rows_of(con, "tool = 'hayabusa' AND host_name_recorded = ''") == [
            (uid_of(con, DC1_SEC, 1, "hayabusa"), "LAB", "LAB")]
    finally:
        con.close()


def test_pivots_and_the_sid_lookup_stay_within_one_machine(tmp_path):
    """Before the split, the logon session pivot joins PC01's and MSEDGEWIN10's 0x3E7 logons, and MSEDGEWIN10's 4104,
    known only by its SID, takes the name PC01's logon records. After it, each is on its own machine; the IP pivot,
    case-wide by design, still joins them. After the undo the lookup names the 4104 again."""
    case, _ = lab_case(tmp_path)
    app = App(case)
    try:
        x, y = uid_of(app.con, PC01_SEC, 1), uid_of(app.con, EDGE_SEC, 1)
        block = uid_of(app.con, EDGE_SEC, 2)
        account = lambda: app.con.execute("SELECT user_name FROM events WHERE event_uid = ?", [block]).fetchone()[0]
        session = lambda: sorted(e["uid"] for e in related(app.con, x, "session")["events"])
        assert session() == sorted([x, y]) and account() == "alice"
        split(app)
        assert session() == [x] and account() == SID
        assert sorted(e["uid"] for e in related(app.con, x, "source_ip")["events"]) == sorted([x, y])
        api_host(app, {"unsplit": "LAB"})
        assert session() == sorted([x, y]) and account() == "alice"
    finally:
        app.con.close()


def test_keep_hides_the_notice_until_another_computer_appears_and_a_second_split_adds_to_the_first(tmp_path):
    """Keep as one host moves no lane, so saved searches and the clock measurement stay, and the Hosts panel still
    offers the split from the kept host's line. A second split adds to the first, and the Event page names the split
    that moved each event."""
    case, runs = lab_case(tmp_path)
    app = App(case)
    try:
        x = uid_of(app.con, PC01_SEC, 1)
        save_hits(app.con, "whoami")
        app.clock_cache["probe"] = True   # a key the clock check doesn't use
        payload = api_host(app, {"keep_host": "LAB"})
        assert app.identity.mixed == {} and app.journal.state.kept["LAB"] == {
            "pc01.example.corp", "msedgewin10", "dc1.insecurebank.local"}
        assert not any("computers" in r for r in app.identity.hosts["LAB"].review)
        assert app.con.execute("SELECT count(*) FROM search_runs").fetchone()[0] == 1 and "probe" in app.clock_cache
        keep = read_entries(app.journal.path)[-1]
        assert payload["kept"] == [{"host": "LAB", "computers": 3,
                                    "entry": {"seq": keep["seq"], "at": keep["at"], "who": keep["who"]}}]
        payload, _ = split(app)   # kept, but a split is still the analyst's to make
        first = read_entries(app.journal.path)[-1]["seq"]
        assert payload["kept"] == [] and app.con.execute("SELECT count(*) FROM search_runs").fetchone()[0] == 0
    finally:
        app.con.close()
    # A rerun that records a fourth computer: it stays on LAB, which is mixed again only if two computers remain on it
    record, folder = runs["evtx"]
    rows = [security(case, 9, 4624, "WS9.corp.local", PC01_SEC, 7), security(case, 10, 4624, "WS10", PC01_SYS, 8)]
    with (folder / "output" / "evtxecmd.csv").open("a", encoding="utf-8", newline="") as f:
        import csv
        writer = csv.DictWriter(f, fieldnames=EVTX_COLUMNS)
        for row in rows:
            writer.writerow({c: row.get(c, "") for c in EVTX_COLUMNS})
    load_output(case, record, folder)
    app = App(case)
    try:
        assert app.identity.mixed["LAB"]["computers"] == 2   # WS9 and WS10, on LAB's own lane
        split(app)
        second = read_entries(app.journal.path)[-1]["seq"]
        assert sorted(app.journal.state.splits["LAB"].values()) == sorted(
            ["PC01", "PC01", "MSEDGEWIN10", "DC1", "DC1", "WS9", "WS9", "WS10"])
        assert len(app.journal.state.split_info["LAB"]) == 2 and app.identity.mixed == {}
        ws9 = uid_of(app.con, PC01_SEC, 9)
        assert [api_event(app, {"uid": [u]})["event"]["split"]["seq"] for u in (x, ws9)] == [first, second]
        # What the analyst sets on a new host is listed for the Undo split confirm, since the undo stops it applying
        payload = api_host(app, {"host": "PC01", "offset_seconds": 3600})
        assert payload["splits"][0]["edits"] == {"PC01": ["its clock offset of +3600 s"]}
        api_host(app, {"unsplit": "LAB"})
        entry = read_entries(app.journal.path)[-1]
        assert describe(entry) == f"Undid the splits of LAB at #{entry['undoes'][0]} and #{entry['undoes'][1]}"
        assert app.con.execute("SELECT count(*) FROM events WHERE host <> 'LAB'").fetchone()[0] == 0
    finally:
        app.con.close()


def test_a_host_with_nothing_left_leaves_the_list_but_offers_undo_and_its_registry_rows_stay(tmp_path):
    """With every row moved, LAB isn't a host any more, and the Splits section still lists it. A hive's rows never
    move, so a LAB with them keeps its OS."""
    case, _ = lab_case(tmp_path)
    con = connect(case.db_path)
    con.execute("DELETE FROM events WHERE tool = 'hayabusa' AND host_name_recorded = ''")
    con.close()
    app = App(case)
    try:
        payload, _ = split(app)
        assert "LAB" not in {h["host"] for h in payload["hosts"]} and payload["splits"][0]["host"] == "LAB"
        api_host(app, {"unsplit": "LAB"})
        assert "LAB" in app.identity.hosts
    finally:
        app.con.close()
    key = "ROOT\\Microsoft\\Windows NT\\CurrentVersion"
    load(case.db_path, [Event(1600485708000000, "Registry Key LastWrite", "registry", "SOFTWARE", f"{key}|ProductName",
                              "ProductName = Windows 10 Pro", registry_path=key, registry_value="ProductName",
                              extra={"ValueData": "Windows 10 Pro"}, host_name_recorded="PC01")],
         host="LAB", tool="recmd", tool_version="t", run_id="r9", replaces_sources=["SOFTWARE"], staging_dir=case.folder)
    app = App(case)
    try:
        split(app)
        assert app.identity.hosts["LAB"].os["product"] == "Windows 10 Pro"
        assert app.con.execute("SELECT host FROM events WHERE tool = 'recmd'").fetchall() == [("LAB",)]
    finally:
        app.con.close()


def test_saved_searches_run_again_and_a_copy_starts_unsplit(tmp_path):
    case, _ = lab_case(tmp_path)
    app = App(case)
    try:
        save_hits(app.con, "PC01")   # a word search reads the host, which the split changes
        assert app.con.execute("SELECT count(*) FROM search_runs").fetchone()[0] == 1
        split(app)
        assert app.con.execute("SELECT count(*) FROM search_runs").fetchone()[0] == 0
    finally:
        app.con.close()
    copy = copy_case(case, tmp_path / "copy", "Copy", "cody")
    rebuild(copy)
    con = connect(copy.db_path)
    try:
        assert con.execute("SELECT count(*) FROM events WHERE host <> origin_host").fetchone()[0] == 0
        assert host_layout(copy) == {}
    finally:
        con.close()


def test_split_keep_and_undo_are_refused_while_a_tool_runs_and_from_a_stale_preview(tmp_path):
    case, _ = lab_case(tmp_path)
    app = App(case)
    try:
        plan = api_host_split(app, {"host": ["LAB"]})
        app.job = type("Job", (), {"finished": False, "tool": "EvtxECmd"})()
        for body in ({"split": "LAB", "basis": plan["basis"]}, {"keep_host": "LAB"}, {"unsplit": "LAB"}):
            with pytest.raises(ValueError, match="EvtxECmd is still running"):
                api_host(app, body)
        app.job = None
        with pytest.raises(ValueError, match="changed since the preview"):
            api_host(app, {"split": "LAB", "basis": "0" * 16})
        with pytest.raises(ValueError, match="isn't split"):
            api_host(app, {"unsplit": "LAB"})
        assert not any(e["action"] == "host_split" for e in read_entries(app.journal.path))
    finally:
        app.con.close()


def test_the_journal_checks_splits_and_the_trail_words_them(tmp_path):
    """A split's lanes are host names; the generic undo refuses a split and points to the Hosts panel; the trail says
    what each entry did, and shows the split undone."""
    case, _ = lab_case(tmp_path)
    j = Journal(case)
    for payload in ({"op": "split", "host": "LAB", "routes": {"pc01": "pc 01"}},
                    {"op": "split", "host": "LAB", "routes": {"pc01": "LAB"}},
                    {"op": "split", "host": "LAB", "routes": {"pc01": "PC01"}, "stays": "lab"},
                    {"op": "split", "host": "LAB", "routes": {}}, {"op": "undo", "host": "LAB", "undoes": []},
                    {"op": "keep", "host": "LAB", "computers": "pc01"}, {"op": "merge", "host": "LAB"}):
        with pytest.raises(JournalError):
            j.append("host_split", **payload)
    routes = {"pc01.example.corp": "PC01", "msedgewin10": "MSEDGEWIN10", "a": "A", "b": "B"}
    s = j.append("host_split", op="split", host="LAB", routes=routes)
    k = j.append("host_split", op="keep", host="LAB", computers=["ws9.corp.local"])
    u = j.append("host_split", op="undo", host="LAB", undoes=[s["seq"]])
    assert describe(s) == "Split LAB into 4 new hosts by recorded computer: A, B, MSEDGEWIN10, and 1 more"
    assert describe(k) == "Kept LAB as one host (1 computer name)"
    assert describe(u) == f"Undid the split of LAB at #{s['seq']}"
    trail = {r["seq"]: r for r in rows(read_entries(j.path), {})["rows"]}
    assert trail[s["seq"]]["undone_by"] == u["seq"] and trail[s["seq"]]["kind"] == "Hosts"
    assert not trail[s["seq"]]["undoable"] and trail[s["seq"]]["panel"] == "hosts"
    with pytest.raises(AuditError, match="Undo split on the Hosts panel"):
        plan_undo(read_entries(j.path), s["seq"])
    # A keep and an undo are made again, not undone: the trail says where
    with pytest.raises(AuditError, match="To split LAB after all, use Split LAB by recorded computer on the Hosts panel"):
        plan_undo(read_entries(j.path), k["seq"])
    with pytest.raises(AuditError, match="To split LAB again, use Split LAB by recorded computer"):
        plan_undo(read_entries(j.path), u["seq"])
    # The undo puts LAB back to before any choice, so the notice can return
    state = Journal(case).state
    assert (state.splits, state.kept, state.kept_info) == ({}, {}, {})
    lines = (case.folder / "journal.jsonl").read_text(encoding="utf-8").splitlines()
    assert all(json.loads(line)["action"] == "host_split" for line in lines[1:])   # after case_created


def test_exports_name_the_host_folder_and_the_split(tmp_path):
    """The timeline export gives each event's host folder as labels.collection_host; the findings summary lists each run
    once, under the host it ran on, and names the split."""
    import csv

    from glessner.export import export_timeline, write_report

    case, _ = lab_case(tmp_path)
    app = App(case)
    try:
        x = uid_of(app.con, PC01_SEC, 1)
        api_mark(app, {"uids": [x], "value": "malicious"})
        split(app)
        path, _ = export_timeline(app.con, case, app.identity, 0, 2**62, "csv", "all")
        with path.open(encoding="utf-8", newline="") as f:
            exported = {r["event_uid"]: r for r in csv.DictReader(f)}
        assert (exported[x]["host.name"], exported[x]["labels.collection_host"]) == ("PC01", "LAB")
        path, _ = write_report(app.con, case, app.identity, app.manifest, app.journal.state)
        text = path.read_text(encoding="utf-8")
        assert "LAB's event logs were split by the computer each event records, into DC1, MSEDGEWIN10, PC01." in text
        runs = [line for line in text.splitlines() if line.startswith("| `20261015")]
        assert len(runs) == 2 and all("| LAB |" in line for line in runs)
    finally:
        app.con.close()


def test_the_hosts_panel_s_split_readers_loop_over_copies_of_the_journal_s_rules_and_splits(tmp_path):
    """The Hosts panel's readers run without the lock, and loop over the journal's rules and splits, which a rule edit
    or a split changes in place: a loop over the originals raises "dictionary changed size during iteration" and the
    panel answers 500. They loop over copies. Here a rule's text, a lane's name, and a computer's key each
    journal a write the first time the reader uses them, as a request would between the reader's steps."""
    from glessner.splits import _edits_left

    case, _ = lab_case(tmp_path)
    app = App(case)
    try:
        state = app.journal.state
        fired = set()

        def once(name):
            if name in fired:
                return False
            fired.add(name)
            return True

        class Rule(dict):   # read for its text by the rules that name a host
            def get(self, key, default=None):
                if once("rule"):
                    state.rules["added meanwhile"] = {"text": "", "builtin": False, "seq": 0, "who": ""}
                return super().get(key, default)

        class Lane(str):   # read when the lanes taken are named: a split adds a host, and a route to this host
            def upper(self):
                if once("lane"):
                    state.splits["SPLIT"] = {}
                    state.splits["OTHER"]["added meanwhile"] = "SOMEWHERE"
                return super().upper()

        class Computer(str):   # read for its label when the labels an earlier split routed are named
            def partition(self, sep):
                if once("computer"):
                    state.splits["LAB"]["added meanwhile"] = "SOMEWHERE"
                return super().partition(sep)

        state.rules["names LAB"] = Rule(text="- where: host is LAB")
        assert _edits_left(state, "LAB") == ["the rules that name it: names LAB"]   # as the loop began
        assert "added meanwhile" in state.rules

        state.splits["OTHER"] = {"a": Lane("OTHER-A")}
        state.splits["LAB"] = {Computer("pc01"): "PC01"}   # an earlier split of this host
        plan = api_host_split(app, {"host": ["LAB"]})
        assert [g["lane"] for g in plan["groups"]] == ["PC01-LAB", "MSEDGEWIN10", "DC1"]   # PC01 is the earlier split's
        assert fired == {"rule", "lane", "computer"} and "SPLIT" in state.splits
    finally:
        app.con.close()
