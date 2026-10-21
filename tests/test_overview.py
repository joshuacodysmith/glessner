"""The Case overview and the state line's counts, on a synthetic case whose alerts, suggestions,
marks, decisions, clock, runs, and log clears are known, so every figure is checked exactly."""

import json
from dataclasses import asdict

import pytest
from chain_fixtures import AT, MARKS, UID, chained, note, unchained
from conftest import DC_LOG, FAST_ALERTS, SEC, T0, WS_LOG, logon, registry
from test_clock import AHEAD, accepted, flow
from test_splits import lab_case, split

from glessner import cli, imports, server
from glessner import intake as intake_module
from glessner.events import Event, load
from glessner.intake import add_new, intake, verify
from glessner.journal import SYSTEM, entries, replay
from glessner.overview import _last_action
from glessner.queries import investigate
from glessner.runner import RUN_FILE, RunRecord
from glessner.server import (
    App,
    api_case_state,
    api_event,
    api_filter,
    api_host,
    api_lanes,
    api_lead_events,
    api_mark,
    api_overview,
    api_report,
    api_shown_counts,
)

MIN = 60 * SEC
C1 = T0 + 62 * SEC + 30 * MIN          # 30 minutes after 104 exactly: still the first DC01 cluster
C2 = C1 + 30 * MIN + SEC               # more than 30 minutes after: a cluster of its own
DESKTOP_SYSTEM = "DESKTOP/Windows/System32/winevt/Logs/System.evtx"
EVENTLOG = "Microsoft-Windows-Eventlog"
ADMIN_RDP = """id: admin-rdp
description: RDP logons, logon type 10.
suggest: suspicious
when:
  all:
    - {field: event_code, equals: "4624"}
    - {field: logon_type, equals: "10"}
"""


def hit(record, title, level, source=DC_LOG, ts=T0):
    return Event(ts_us=ts, ts_desc="Event Recorded", artifact="hayabusa", source_file=source,
                 source_record=f"{record}:{title}", record_id=record, message=f"{title} [{level}]", log_channel="Security",
                 rule_title=title, rule_level=level)


def cleared(ts, record, code, channel, source, provider=EVENTLOG):
    return Event(ts_us=ts, ts_desc="Event Recorded", artifact="evtx", source_file=source, source_record=str(record),
                 record_id=record, message=f"{code} The {channel} log file was cleared.", event_code=code,
                 log_channel=channel, event_provider=provider)


def run_record(case, run_id, tool, host, status, rows, reason="", inputs=("x",), rules=""):
    folder = case.runs_folder / run_id
    folder.mkdir(parents=True)
    record = RunRecord(run_id=run_id, tool=tool, tool_version="1", executable="", host=host, argv=[], cwd="",
                       inputs=list(inputs), started_utc="2026-10-16T01:00:00Z", status=status, reason=reason,
                       finished_utc="2026-10-16T01:00:05Z", loaded_rows=rows, rules=rules)
    (folder / RUN_FILE).write_text(json.dumps(asdict(record)), encoding="utf-8")


@pytest.fixture
def overview_case(suricata_case):
    """suricata_case plus Hayabusa hits in two DC01 clusters and one on DESKTOP, log clears, a host without event logs,
    DESKTOP's clock 3,599.5 s ahead of the capture, an unidentified evidence file, and runs that failed or loaded
    nothing. The marks, decisions, rules, and notes are added by app_with_work."""
    case = suricata_case
    load(case.db_path, [logon(C1, 106, DC_LOG, code="4625"), logon(C2, 107, DC_LOG, code="4625"),
                        cleared(T0 + 300 * SEC, 108, "1102", "Security", DC_LOG),
                        cleared(T0 + 301 * SEC, 109, "1102", "Security", DC_LOG, provider="Other-Provider")],
         host="DC01", tool="evtxecmd", tool_version="t", run_id="r7", replaces_sources=[], staging_dir=case.folder)
    load(case.db_path, [hit(104, "Critical rule", "critical", ts=T0 + 62 * SEC), hit(106, "Service installed", "high", ts=C1),
                        hit(107, "Service installed", "high", ts=C2), hit(102, "Low rule", "low", ts=T0 + 60 * SEC)],
         host="DC01", tool="hayabusa", tool_version="3.6.0", run_id="r8", replaces_sources=[], staging_dir=case.folder)
    load(case.db_path, [hit(201, "Medium rule", "medium", source=WS_LOG, ts=T0 + 874 * SEC)],
         host="DESKTOP", tool="hayabusa", tool_version="3.6.0", run_id="r9", replaces_sources=[], staging_dir=case.folder)
    pairs = [(T0 - 3400 * SEC + i * 20 * SEC, f"194.61.24.102:{52000 + i}") for i in range(10)]
    load(case.db_path, [cleared(T0 + 950 * SEC, 301, "104", "System", DESKTOP_SYSTEM),
                        *(accepted(t + AHEAD, client, "DESKTOP") for t, client in pairs)],
         host="DESKTOP", tool="evtxecmd", tool_version="t", run_id="r10", replaces_sources=[], staging_dir=case.folder)
    load(case.db_path, [flow(t, client, "10.42.85.115:3389") for t, client in pairs],
         host="network", tool="suricata", tool_version="8.0.7", run_id="r11", replaces_sources=[], staging_dir=case.folder)
    load(case.db_path, [registry("WS03/Windows/System32/config/SYSTEM", "ROOT\\ControlSet001\\Control\\ComputerName"
                                 "\\ComputerName", "ComputerName", "WS03")],
         host="WS03", tool="recmd", tool_version="t", run_id="r12", replaces_sources=[], staging_dir=case.folder)
    (case.evidence / "DC01" / "unknown.bin").write_bytes(b"\x01\x02 nothing known")
    intake(case)
    run_record(case, "20261016T010000Z_suricata_network", "suricata", "network", "ok", 4, rules="ET Open 11310")
    run_record(case, "20261016T010100Z_srumecmd_DESKTOP", "srumecmd", "DESKTOP", "failed", None, reason="exit code 1")
    run_record(case, "20261016T010200Z_rbcmd_DC01", "rbcmd", "DC01", "ok", 0)
    run_record(case, "20261016T010300Z_jlecmd_DC01", "jlecmd", "DC01", "failed", None, reason="exit code 2")
    run_record(case, "20261016T010400Z_jlecmd_DC01", "jlecmd", "DC01", "ok", 3)   # loaded since: no gap
    # The Suricata events' run is the record above, for the rule set chip
    import duckdb
    con = duckdb.connect(str(case.db_path))
    con.execute("UPDATE events SET run_id = '20261016T010000Z_suricata_network' WHERE run_id = 'r6'")
    con.close()
    return case


def app_with_work(case):
    """The case opened, with an analyst rule, marks, a rejected decision, notes, and a close."""
    from glessner.server import api_note, api_note_retract, api_rule, api_suggestion

    app = App(case)
    # The RdpCoreTS events take their record ids from test_clock's counter, which the tests run before on the same worker
    # advance, so they could take 101 to 109 and swap an event below. The Security and System logs' ids are set here.
    rows = app.con.execute("SELECT event_uid, record_id FROM events WHERE tool = 'evtxecmd' AND artifact = 'evtx' "
                           "AND log_channel IN ('Security', 'System')").fetchall()
    uid = {r[1]: r[0] for r in rows}
    assert len(uid) == len(rows)
    api_rule(app, {"op": "add", "text": ADMIN_RDP})
    api_mark(app, {"uids": [uid[101]], "value": "malicious", "note": ""})
    api_mark(app, {"uids": [uid[201]], "value": "suspicious", "note": ""})
    api_suggestion(app, {"decision": "reject", "source": "hayabusa", "uids": [uid[104]]})
    api_note(app, {"uid": uid[101], "text": "RDP from the internet"})
    seq = api_note(app, {"uid": uid[201], "text": "retracted"})["seq"]
    api_note_retract(app, {"uid": uid[201], "note_seq": seq})
    problems = verify(case, reason="case close")
    app.journal.append("case_setting", name="closed", value={"at": "2026-10-16T02:00:00Z", "evidence_files": 1,
                                                             "hash_check": "ok", "problems": problems})
    return app, uid


def test_the_overview_ranks_its_leads_and_counts_each_section_exactly(overview_case):
    app, _ = app_with_work(overview_case)
    try:
        ov = api_overview(app, {})
        leads = ov["leads"]
        assert [(lead["kind"], lead.get("host") or lead.get("rule"), lead["level"]) for lead in leads] == [
            ("alerts", "DC01", "critical"), ("alerts", "network", "high"), ("alerts", "DC01", "high"),
            ("alerts", "DESKTOP", "medium"), ("suggestions", "admin-rdp", "suggestion"),
            ("suggestions", "machine-accounts-authorized", "suggestion"), ("clock", "DESKTOP", "clock")]
        first, suricata, second, desktop, rdp, machine, clock = leads
        # 101 (high, marked), 104 (critical, rejected), and 106, 30 minutes after 104: one cluster, with 106 open
        assert first["title"] == ("Hayabusa, critical and high: 3 events on DC01, "
                                  "2020-09-19 03:21:48 to 03:52:50 UTC")
        assert first["why"] == ("Rules: Critical rule (1 event), RDP from internet (1 event), "
                                "Service installed (1 event).")
        assert (first["count"], first["open"], first["worked"]) == (3, 1, False)
        assert first["chips"] == ["Hayabusa 3.6.0, t"]
        assert (second["count"], second["start"], second["end"]) == (1, C2, C2)
        assert second["title"] == "Hayabusa, high: 1 event on DC01, 2020-09-19 04:22:51 UTC"
        assert suricata["title"] == ("Suricata, severity 1 and 2: 3 alerts on network, "
                                     "2020-09-19 03:41:48 to 03:43:48 UTC")
        assert suricata["chips"] == ["Suricata 8.0.7", "ET Open 11310"]
        assert suricata["why"] == ("Signatures: ET INFO Executable Download from dotted-quad Host (2 alerts), ET MALWARE "
                                   "Possible Metasploit Payload Common Construct Bind_API (from server) (1 alert).")
        assert (desktop["open"], desktop["worked"]) == (0, True)
        assert (rdp["count"], rdp["open"], rdp["worked"], rdp["hosts"]) == (2, 0, True, ["DC01", "DESKTOP"])
        assert rdp["why"] == "RDP logons, logon type 10."
        assert rdp["title"] == "admin-rdp suggests Suspicious for 2 events: all decided"
        assert machine["title"] == "machine-accounts-authorized suggests Authorized for 1 event: 1 pending"
        assert (machine["count"], machine["open"], machine["worked"]) == (1, 1, False)
        assert clock["title"] == "DESKTOP's clock ran 59 m 59.5 s ahead of the capture" and not clock["worked"]
        assert clock["why"] == ("The page shows DESKTOP's times as its clock recorded them until it is aligned. Measured "
                                "against network, from 10 RDP connections; 10 of 10 pairs within 2 s.")
        assert ov["ranking"].startswith("Ranked by severity: critical alerts, then high, then medium")

        p = ov["progress"]
        assert p["marks"] == {"Malicious": 1, "Suspicious": 1, "Authorized": 0} and p["marked"] == 2
        assert p["in_case"] == p["marks"] and p["orphans"] == 0
        assert (p["leads"], p["leads_worked"]) == (7, 2)
        # Events with a suggestion: 101, 104, 106, 107, 201, three Suricata alerts, and 103; pending are the unmarked
        # ones with a suggestion not rejected: 106, 107, the alerts, and 103
        assert (p["decided"], p["pending"]) == (3, 6)
        assert (p["flagged"], p["unreviewed_nearby"], p["notes"]) == (2, 2, 1)
        # The flagged events To investigate lists; the overview counts their unreviewed relatives its own way (overview.NEARBY)
        assert len(investigate(app.reader())) == 2
        assert (p["last"]["who"], p["last"]["text"]) == ("cody", "Closed the case. Its 1 evidence file matches the intake "
                                                             "manifest.")

        assert ov["by_host"] == [
            {"host": "DC01", "marks": 1, "pending": 3, "leads": 4, "leads_worked": 1},
            {"host": "DESKTOP", "marks": 1, "pending": 0, "leads": 3, "leads_worked": 2},
            {"host": "WS03", "marks": 0, "pending": 0, "leads": 0, "leads_worked": 0},
            {"host": "network", "marks": 0, "pending": 3, "leads": 1, "leads_worked": 0}]

        hosts = {h["host"]: h for h in ov["hosts"]}
        # Events with a Hayabusa hit: 101, 102, 104, 106, and 107, each matched by one hit row loaded under DC01
        assert (hosts["DC01"]["events"], hosts["DC01"]["hits"], hosts["DC01"]["hit_rows"]) == (11, 5, 5)
        assert [k["artifact"] for k in hosts["DC01"]["kinds"]] == ["evtx", "registry"]
        assert hosts["DESKTOP"]["clock"]["text"] == "59 m 59.5 s ahead of the capture, not aligned"
        assert hosts["network"]["clock"]["text"] == "the reference clock"

        gaps = ov["gaps"]
        assert [(c["host"], c["code"], c["ts"]) for c in gaps["clears"]] == [
            ("DC01", "1102", T0 + 300 * SEC), ("DESKTOP", "104", T0 + 950 * SEC)]
        assert gaps["no_event_logs"] == ["WS03"]
        assert gaps["unidentified"] == 1 and gaps["unreadable"] == []
        assert [(g["tool"], g["host"], g["status"], g["rows"]) for g in gaps["runs"]] == [
            ("srumecmd", "DESKTOP", "failed", 0), ("rbcmd", "DC01", "ok", 0)]

        integrity = ov["integrity"]
        assert (integrity["evidence_files"], integrity["added_files"], integrity["unreadable"], integrity["algorithm"]) == (
            1, 0, 0, "SHA-256")
        assert {k: v for k, v in integrity["last_full"].items() if k != "at"} == {
            "reason": "case close", "files_checked": 1, "result": "ok", "problems": 0}
        assert (integrity["changed_files"], integrity["problems"]) == (0, [])
        assert integrity["journal_entries"] == sum(1 for _ in app.journal.path.open(encoding="utf-8"))
        assert integrity["times"] == "UTC, as each host's clock recorded them"
    finally:
        app.con.close()


def test_a_hayabusa_lead_carries_the_rules_its_why_names(overview_case):
    """The page links each rule a lead's why line names, so the lead carries them with their event counts, the same
    top three in the same order; a lead of another tool carries none. The why text itself doesn't change."""
    app, _ = app_with_work(overview_case)
    try:
        leads = api_overview(app, {})["leads"]
        first = leads[0]
        assert first["rules"] == [{"title": "Critical rule", "count": 1}, {"title": "RDP from internet", "count": 1},
                                  {"title": "Service installed", "count": 1}] and first["rules_more"] == 0
        for lead in (lead for lead in leads if lead["kind"] == "alerts" and lead["tool"] == "hayabusa"):
            said = ", ".join(f"{r['title']} ({r['count']:,} {'event' if r['count'] == 1 else 'events'})" for r in lead["rules"])
            assert lead["why"] == f"Rules: {said}" + (f", and {lead['rules_more']} more" if lead["rules_more"] else "") + "."
        assert all("rules" not in lead for lead in leads if lead["kind"] != "alerts" or lead["tool"] != "hayabusa")
    finally:
        app.con.close()


def test_a_lead_is_worked_once_each_event_is_marked_or_decided_and_the_cache_follows(overview_case, monkeypatch):
    app, uid = app_with_work(overview_case)
    computed = []
    real = server.case_overview
    monkeypatch.setattr(server, "case_overview", lambda *a, **k: computed.append(1) or real(*a, **k))
    try:
        first = api_overview(app, {})["leads"][0]
        api_overview(app, {})
        assert len(computed) == 1   # nothing changed, so it isn't read again
        lead = {"tool": ["hayabusa"], "host": ["DC01"], "start": [str(first["start"])], "end": [str(first["end"])]}
        found = api_lead_events(app, lead)
        assert (found["uids"], found["hidden_sources"], found["hidden_view"]) == ([uid[101], uid[104], uid[106]], 0, 0)
        # Under the page's filter, how many it hides: the Sources hiding DC01 hide all three; a View of
        # Malicious events hides the two not marked so, 104 (rejected) and 106
        hide = api_filter(app, {"only": [], "hide": [{"host": "DC01"}], "show": []})["id"]
        found = api_lead_events(app, {**lead, "filter": [hide]})
        assert (found["hidden_sources"], found["hidden_view"]) == (3, 0)
        malicious = api_filter(app, {"only": [], "hide": [], "show": [], "view": {"marks": ["Malicious"], "values": []}})["id"]
        found = api_lead_events(app, {**lead, "filter": [malicious]})
        assert (found["hidden_sources"], found["hidden_view"]) == (0, 2)
        # A request between a mark's journal entry and its rows' rewrite reads the marks as they were; what it keeps
        # mustn't outlast the rewrite
        rewrite = app.rewrite
        monkeypatch.setattr(app, "rewrite", lambda **kw: (api_overview(app, {}), rewrite(**kw)))
        api_mark(app, {"uids": [uid[106]], "value": "suspicious", "note": ""})
        assert len(computed) == 2
        lead = api_overview(app, {})["leads"][0]
        assert len(computed) == 3 and (lead["open"], lead["worked"]) == (0, True)
        # Aligning DESKTOP works its clock lead and changes which times the page shows
        api_host(app, {"align": "capture", "host": "DESKTOP"})
        ov = api_overview(app, {})
        clock = next(lead for lead in ov["leads"] if lead["kind"] == "clock")
        assert clock["worked"] and ov["integrity"]["times"] == "UTC, aligned to the capture"
        assert ov["progress"]["leads_worked"] == 4
    finally:
        app.con.close()


def test_the_case_state_keeps_a_mismatch_until_a_full_re_hash_matches(overview_case):
    """The header's line and Integrity read every evidence check. A close outranks no later check, a run's check that
    matched clears no earlier problem, and only a full re-hash that matches clears one. The report's and the verify
    command's re-hashes are full ones, and a close the command line journals beside the server shows."""
    app = App(overview_case)
    unknown = overview_case.evidence / "DC01" / "unknown.bin"
    try:
        state = api_case_state(app, {})
        assert (state["closed"], state["intake"], state["evidence_files"], state["checks"]["newest"]) == (None, True, 1, None)
        api_report(app, {})
        state = api_case_state(app, {})
        assert state["checks"]["last_full"]["reason"] == "full check when writing the report"
        assert api_overview(app, {})["integrity"]["last_full"]["result"] == "ok"
        # The close command, beside the server, whose own journal state reads it only at its next entry
        assert cli.cmd_close(overview_case, None) == 0
        assert app.journal.state.settings.get("closed") is None and api_case_state(app, {})["closed"]["at"]
        # The evidence changes after the close, and the report's re-hash finds it
        unknown.write_bytes(b"changed")
        api_report(app, {})
        state = api_case_state(app, {})
        assert state["closed"] and (state["checks"]["files"], state["checks"]["problems"]) == (
            1, ["DC01/unknown.bin: SHA-256 changed"])
        integrity = api_overview(app, {})["integrity"]
        assert (integrity["changed_files"], integrity["last_full"]["result"], integrity["last_full"]["problems"]) == (
            1, "mismatch", 1)
        # A run's check of another file matches, and clears nothing
        (overview_case.evidence / "DESKTOP" / "later.txt").write_text("added later")
        add_new(overview_case)
        assert verify(overview_case, ["DESKTOP/later.txt"], reason="after run r13") == []
        state = api_case_state(app, {})
        assert (state["checks"]["newest"]["result"], state["checks"]["files"], state["added_files"]) == ("ok", 1, 1)
        assert api_overview(app, {})["integrity"]["changed_files"] == 1
        # The file restored, the verify command's full re-hash matches, and clears it
        unknown.write_bytes(b"\x01\x02 nothing known")
        assert cli.cmd_verify(overview_case, None) == 0
        state = api_case_state(app, {})
        assert (state["checks"]["files"], state["checks"]["last_full"]["reason"]) == (0, "manual full verification")
        assert api_overview(app, {})["integrity"]["changed_files"] == 0   # a check alone renews the cached overview
    finally:
        app.con.close()


def test_files_intake_could_not_read_are_a_gap_and_no_hashed_file(synthetic_case, monkeypatch):
    """Intake keeps a file it could not read with its error and no hash. It isn't an evidence file
    "hashed at intake", and the Gaps list it with the error."""
    (synthetic_case.evidence / "DC01" / "locked.bin").write_bytes(b"locked")
    (synthetic_case.evidence / "DC01" / "open.bin").write_bytes(b"open")
    real = intake_module.sha256_file

    def sha256_file(path):
        if path.name == "locked.bin":
            raise PermissionError(13, "The process cannot access the file")
        return real(path)

    monkeypatch.setattr(intake_module, "sha256_file", sha256_file)
    intake(synthetic_case)
    app = App(synthetic_case)
    try:
        ov = api_overview(app, {})
        assert (ov["integrity"]["evidence_files"], ov["integrity"]["unreadable"], ov["gaps"]["unidentified"]) == (1, 1, 1)
        assert ov["gaps"]["unreadable"] == [{"path": "DC01/locked.bin", "added": "",
                                             "error": "PermissionError: [Errno 13] The process cannot access the file"}]
        state = api_case_state(app, {})
        assert (state["evidence_files"], state["unreadable"]) == (1, 1)
    finally:
        app.con.close()


def test_integrity_counts_the_lines_of_the_check_log_it_cannot_read(synthetic_case):
    """A run of 0x00 that a crash left at the end of verification.jsonl becomes a whole line once the next check
    appends. Integrity counts it, since it may have held a problem, and still reads the checks around it."""
    intake(synthetic_case)
    assert verify(synthetic_case, reason="manual full verification") == []
    app = App(synthetic_case)
    try:
        assert api_overview(app, {})["integrity"]["unreadable_lines"] == 0
        with synthetic_case.verification_path.open("ab") as f:
            f.write(b"\0" * 64)
        assert verify(synthetic_case, reason="after a run") == []
        integrity = api_overview(app, {})["integrity"]
        assert (integrity["unreadable_lines"], integrity["last_full"]["result"]) == (1, "ok")
    finally:
        app.con.close()


def evidence_log(case):
    """The case's DC01 Security log, the source file of its DC01 logons, written into its evidence."""
    log = case.evidence / DC_LOG
    log.parent.mkdir(parents=True)
    log.write_bytes(b"evidence")
    return log


def held_open(name):
    """intake.sha256_file, refusing the files named `name` as Windows does one another program holds open with no
    sharing."""
    real = intake_module.sha256_file

    def sha256_file(path):
        if path.name == name:
            raise PermissionError(13, "Permission denied")
        return real(path)

    return sha256_file


def test_a_file_a_check_could_not_re_read_is_not_counted_as_changed(synthetic_case, monkeypatch):
    """A check that can't read a file compares no hash, so the header's line, Integrity, and the Event page count the
    file as not re-read, not changed. A file a check found changed is changed, whatever another check found of it."""
    log = evidence_log(synthetic_case)
    other = synthetic_case.evidence / "DC01" / "other.bin"
    other.write_bytes(b"other")
    intake(synthetic_case)
    app = App(synthetic_case)
    try:
        uid = app.con.execute("SELECT event_uid FROM events WHERE source_file = ? LIMIT 1", [DC_LOG]).fetchone()[0]

        def counts():
            checks, integrity = api_case_state(app, {})["checks"], api_overview(app, {})["integrity"]
            provenance = api_event(app, {"uid": [uid]})["event"]["provenance"]
            return ((checks["files"], checks["changed_files"], checks["not_reread"]),
                    (integrity["changed_files"], integrity["not_reread"]), (provenance["state"], provenance["text"]))

        with monkeypatch.context() as m:
            m.setattr(intake_module, "sha256_file", held_open("Security.evtx"))
            assert verify(synthetic_case, [DC_LOG], reason="after run r1") == [f"{DC_LOG}: unreadable (Permission denied)"]
        assert counts() == ((1, 0, 1), (0, 1), ("unreadable", "could not be re-read (Permission denied), so not compared "
                                                              "with intake"))
        other.write_bytes(b"changed")
        assert verify(synthetic_case, ["DC01/other.bin"], reason="after run r2") == ["DC01/other.bin: SHA-256 changed"]
        assert counts()[:2] == ((2, 1, 1), (1, 1))
        log.write_bytes(b"changed")
        assert verify(synthetic_case, [DC_LOG], reason="after run r3") == [f"{DC_LOG}: SHA-256 changed"]
        assert counts() == ((2, 2, 0), (2, 0), ("changed", "differs from intake (SHA-256 changed)"))
    finally:
        app.con.close()


def test_the_event_page_says_no_match_while_a_line_of_the_check_log_cannot_be_read(synthetic_case):
    """A line of verification.jsonl that can't be read may have held a problem with the file, so the Event page doesn't
    say the file matches intake: it says no readable check found it changed, and how many lines couldn't be read."""
    evidence_log(synthetic_case)
    intake(synthetic_case)
    assert verify(synthetic_case, reason="manual full verification") == []
    app = App(synthetic_case)
    try:
        uid = app.con.execute("SELECT event_uid FROM events WHERE source_file = ? LIMIT 1", [DC_LOG]).fetchone()[0]
        provenance = api_event(app, {"uid": [uid]})["event"]["provenance"]
        assert (provenance["state"], provenance["text"], provenance["unreadable_lines"]) == ("matches", "matches intake", 0)
        for _ in range(2):
            with synthetic_case.verification_path.open("ab") as f:
                f.write(b"\0" * 64)
            assert verify(synthetic_case, [DC_LOG], reason="after a run") == []
        provenance = api_event(app, {"uid": [uid]})["event"]["provenance"]
        assert (provenance["state"], provenance["text"], provenance["unreadable_lines"]) == (
            "uncounted", "no readable check found it changed; 2 check-log lines unreadable", 2)
    finally:
        app.con.close()


def test_full_checks_do_not_count_files_intake_could_not_read(tmp_path, monkeypatch, capsys):
    """Every full check, the findings summary's, the verify command's, and close's, counts only the files it re-hashed
    and names the others as unverified, a file intake couldn't read among them, also when it is the only one. Counted as
    checked, that file would make the summary say "Every evidence file (2) ... all match", close journal 2 evidence
    files that matched, and the verify command say all evidence files match, while the overview counts 1 hashed. Once
    the file can be read, it still has no intake hash, and stays unverified."""
    from glessner.audit import describe, read_entries
    from glessner.case import create_case

    real = intake_module.sha256_file

    def sha256_file(path):   # as when another program holds the file open with no sharing
        if path.name == "locked.bin":
            raise PermissionError(13, "The process cannot access the file")
        return real(path)

    for name, files in (("both", ("readable.txt", "locked.bin")), ("alone", ("locked.bin",))):
        evidence = tmp_path / name / "evidence" / "WS01"
        evidence.mkdir(parents=True)
        for file in files:
            (evidence / file).write_bytes(file.encode())
        case = create_case(tmp_path / name / "case", "Unreadable", evidence.parent, "cody")
        with monkeypatch.context() as m:
            m.setattr(intake_module, "sha256_file", sha256_file)
            intake(case)
        hashed = len(files) - 1
        app = App(case)
        try:
            summary = (case.folder / api_report(app, {})["path"]).read_text(encoding="utf-8")
        finally:
            app.con.close()
        assert "Every evidence file" not in summary and "all match" not in summary, name
        assert ("1 evidence file could not be read at intake, so it has no hash to check and is unverified: "
                "WS01/locked.bin.") in summary, name
        assert ("1 of the 2 evidence files was re-hashed when this report was written, and none differs" if hashed
                else "No evidence file was re-hashed when this report was written.") in summary, name
        assert cli.cmd_verify(case, None) == 0
        out = capsys.readouterr().out
        assert "All evidence files match" not in out and "is unverified: WS01/locked.bin." in out, (name, out)
        assert cli.cmd_close(case, None) == 0
        out = capsys.readouterr().out
        assert "All" not in out and "is unverified: WS01/locked.bin." in out, (name, out)
        close = read_entries(case.folder / "journal.jsonl")[-1]
        assert (close["value"]["evidence_files"], close["value"]["unverified"]) == (hashed, 1), name
        assert describe(close).startswith(
            "Closed the case. " + ("The 1 evidence file intake hashed matches the intake manifest." if hashed else
                                   "No evidence file has an intake hash to check.")
            + " 1 evidence file could not be read at intake and is unverified. The journal's "), name
        records = [json.loads(line) for line in case.verification_path.read_text(encoding="utf-8").splitlines()]
        full = [r for r in records if r["reason"] in intake_module.FULL_CHECKS]
        assert [(r["files_checked"], r["unverified"]) for r in full] == [(hashed, ["WS01/locked.bin"])] * 3, name
        # Readable now, it has no intake hash to check against
        assert intake_module.check_files(case).unverified == ["WS01/locked.bin"]


def test_your_last_action_leaves_out_the_apps_own_entries(overview_case):
    """A build journals its case open as the app, which answers no "where was I"."""
    app, _ = app_with_work(overview_case)
    try:
        app.journal.append("case_open", who=SYSTEM)   # a chained case_open names its build in the envelope
        last = api_overview(app, {})["progress"]["last"]
        assert (last["who"], last["text"]) == ("cody", "Closed the case. Its 1 evidence file matches the intake manifest.")
    finally:
        app.con.close()


def repeated_prev(entry: dict) -> bytes:
    """An entry's line that names prev twice, which strict parsing refuses and format 2's reader reads."""
    return json.dumps({"prev": "y", **entry}).replace('"prev": "y"', '"prev": "x", "prev": "y"', 1).encode() + b"\n"


def test_your_last_action_reads_a_line_that_repeats_prev_as_the_shared_reader_does(tmp_path):
    """Before the chain, a line that names prev but repeats a key is read as format 2 read it: the shared reader gives it,
    and as a rekey it re-points the entries before it. After the chain starts, the same line is unreadable and re-points
    nothing. The last action reads each line as the shared reader does."""
    new = "a" * 32
    rekey = {"seq": 2, "at": AT, "who": SYSTEM, "action": "case_upgrade", "from_format": 3, "to_format": 4, "text": "x",
             "rekey": {"pairs": {UID: new}}}
    cases = {
        "a rekey before the chain": (chained([], before=unchained(note(1)) + repeated_prev(rekey)), new, "looked at it"),
        "a note before the chain": (chained([], before=unchained(note(1)) + repeated_prev(note(2, text="crafted"))), UID,
                                    "crafted"),
        "a rekey after the chain": (chained([MARKS[1]]) + repeated_prev({**rekey, "seq": 3}), UID, "first look"),
    }
    for n, (name, (data, target, text)) in enumerate(cases.items()):
        path = tmp_path / f"{n}.jsonl"
        path.write_bytes(data)
        last = _last_action(path)
        assert (last["target"], last["text"]) == (target, text), name
        given = [e for e in entries(path) if e.get("action") == "note"]
        assert (given[-1]["target"], given[-1]["text"]) == (target, text), name   # the shared reader agrees
        assert replay(path).notes.get(target), name


def test_the_overview_counts_notes_from_a_copy_of_the_journal_s(overview_case):
    """The overview reads without the lock, and counts the notes from a copy of the journal's dict of them, since a
    note journaled meanwhile changes the dict, and a loop over it would raise "dictionary changed size during
    iteration" and answer 500. Here reading a note journals a note on another event, as a request would mid-loop."""
    app, uid = app_with_work(overview_case)
    notes = app.journal.state.notes

    class Journaling(dict):
        def get(self, key, default=None):
            if key == "retracted" and uid[102] not in notes:
                app.journal.append("note", target=uid[102], text="written meanwhile")
            return super().get(key, default)

    try:
        notes[uid[101]][:] = [Journaling(n) for n in notes[uid[101]]]   # the first of the two events with a note
        app.overview_cache = None
        assert api_overview(app, {})["progress"]["notes"] == 1   # as the loop began
        assert uid[102] in notes
    finally:
        app.con.close()


def test_the_mark_bar_leaves_out_marks_on_events_no_longer_in_the_case(overview_case):
    """The counts include a mark whose event a rerun dropped, the bar doesn't, as its note says."""
    app, uid = app_with_work(overview_case)
    app.con.execute("DELETE FROM events WHERE event_uid = ?", [uid[201]])
    app.con.close()
    app = App(overview_case)
    try:
        p = api_overview(app, {})["progress"]
        assert (p["marks"]["Suspicious"], p["in_case"]["Suspicious"], p["orphans"]) == (1, 0, 1)
    finally:
        app.con.close()


def test_what_the_case_holds_counts_hits_by_the_lane_of_the_event_they_matched(tmp_path):
    """After a split, the Hayabusa row whose record names no computer stays on LAB while the event it
    matched moves to DC1's lane, so a lane's hits are its events with a hit, and LAB holds a hit row and no events."""
    case, _ = lab_case(tmp_path)
    app = App(case)
    try:
        split(app)
        hosts = {h["host"]: (h["events"], h["hits"], h["hit_rows"]) for h in api_overview(app, {})["hosts"]}
        assert hosts == {"DC1": (1, 1, 0), "LAB": (0, 0, 1), "MSEDGEWIN10": (2, 1, 1), "PC01": (3, 1, 1)}
    finally:
        app.con.close()


def test_an_import_that_fails_shows_in_the_gaps_though_its_record_changed_in_place(synthetic_case, monkeypatch):
    """An import rewrites its run's record inside the run's own folder, which leaves the runs folder's time unchanged,
    so an overview read and kept while the import ran must still show the failed run."""
    (synthetic_case.evidence / "IDS").mkdir()
    log = synthetic_case.evidence / "IDS" / "fast.log"
    log.write_text(FAST_ALERTS, newline="\n")
    intake(synthetic_case)
    mapping = imports.preview(synthetic_case, "IDS/fast.log")["mapping"]   # it reads the database on a connection of its own
    app = App(synthetic_case)
    try:
        log.write_text(FAST_ALERTS + FAST_ALERTS, newline="\n")   # changed since intake, so the import fails
        finish = imports.finish_run
        monkeypatch.setattr(imports, "finish_run", lambda folder, record: (api_overview(app, {}), finish(folder, record)))
        done = server.api_import(app, {"paths": ["IDS/fast.log"],
                                       "mapping": {**mapping, "time": {**mapping["time"], "zone": "UTC"}}})
        assert done["runs"][0]["status"] == "failed"
        assert [(g["tool"], g["status"]) for g in api_overview(app, {})["gaps"]["runs"]] == [("import", "failed")]
    finally:
        app.con.close()


def test_marked_events_with_unreviewed_related_events_count_each_relation(synthetic_case):
    """The overview counts To investigate's relations its own way (overview.NEARBY). A marked event
    related only by its source IP, and one related only by its file, each count."""
    source = "WS05/Windows/System32/winevt/Logs/Security.evtx"

    def event(record, ip="", file_key=""):
        return Event(ts_us=T0 + record * SEC, ts_desc="Event Recorded", artifact="evtx", source_file=source,
                     source_record=str(record), record_id=record, message=f"5156 record {record}", event_code="5156",
                     log_channel="Security", source_ip=ip, file_key=file_key)

    load(synthetic_case.db_path, [event(1, ip="203.0.113.9"), event(2, ip="203.0.113.9"),
                                  event(3, file_key="c:/temp/drop.exe"), event(4, file_key="c:/temp/drop.exe")],
         host="WS05", tool="evtxecmd", tool_version="t", run_id="r20", replaces_sources=[source],
         staging_dir=synthetic_case.folder)
    app = App(synthetic_case)
    try:
        uid = {r[1]: r[0] for r in app.con.execute("SELECT event_uid, record_id FROM events WHERE host = 'WS05'").fetchall()}
        api_mark(app, {"uids": [uid[1]], "value": "suspicious", "note": ""})
        api_mark(app, {"uids": [uid[3]], "value": "malicious", "note": ""})
        p = api_overview(app, {})["progress"]
        assert (p["flagged"], p["unreviewed_nearby"]) == (2, 2)
        assert [i["mark"] for i in investigate(app.reader())] == ["Suspicious", "Malicious"]
        api_mark(app, {"uids": [uid[2], uid[4]], "value": "authorized", "note": ""})
        assert api_overview(app, {})["progress"]["unreviewed_nearby"] == 0
    finally:
        app.con.close()


def test_the_state_lines_counts_come_from_the_lanes_and_one_scan_after_them(overview_case):
    """The lanes give the events shown, their own sum, at no extra cost; what they can't
    count, by tactic or with both the Sources and a View on, comes from one scan the redraw doesn't wait on."""
    app = App(overview_case)
    try:
        total = app.con.execute("SELECT count(*) FROM events WHERE tool <> 'hayabusa' AND ts_us IS NOT NULL").fetchone()[0]
        lanes = api_lanes(app, {})
        assert set(lanes) == {"lanes", "names", "shown", "machine_links"}
        assert (lanes["shown"], lanes["machine_links"]) == (total, 1)   # DC01's record 103, from DESKTOP-SDN1RPT$
        hide = api_filter(app, {"only": [], "hide": [{"host": "network"}], "show": []})["id"]
        assert api_lanes(app, {"filter": [hide]})["shown"] == api_shown_counts(app, {"filter": [hide]})["shown"] == total - 14
        both = api_filter(app, {"only": [], "hide": [{"host": "network"}], "show": [],
                                "view": {"marks": ["Suggested"], "values": []}})["id"]
        assert api_lanes(app, {"filter": [both]})["shown"] == 6
        # Pending outside the network lane: 101, 104, 106, 107, 201, and 103, none of them marked yet; the View alone
        # also shows the network lane's 3 Suricata alerts at severity 1 or 2
        assert api_shown_counts(app, {"filter": [both]}) == {"shown": 6, "sources_shown": total - 14, "view_shown": 9}
        assert api_lanes(app, {"filter": [both], "groupby": ["tactic,host"]})["shown"] is None
        assert api_shown_counts(app, {"filter": [both], "groupby": ["tactic,host"]})["shown"] == 6
        # A show pred alone hides nothing, so with it the View is the only part on
        shows = api_filter(app, {"only": [], "hide": [], "show": [{"host": "DC01"}],
                                 "view": {"marks": ["Suggested"], "values": []}})["id"]
        assert api_shown_counts(app, {"filter": [shows]}) == {"shown": 9}
    finally:
        app.con.close()
