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
from glessner.audit import markdown
from glessner.events import Event, load, to_us
from glessner.export import _md
from glessner.heads import forget
from glessner.identity import HostIdentity
from glessner.intake import add_new, intake, verify
from glessner.journal import SYSTEM, entries, replay
from glessner.overview import _clock_text, _last_action
from glessner.parsers.autoruns import BUILT
from glessner.queries import investigate
from glessner.runner import RUN_FILE, RunRecord, _write_record
from glessner.server import (
    App,
    api_audit,
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


def run_record(case, run_id, tool, host, status, rows, reason="", inputs=("x",), rules="", tool_files=None, **fields):
    """A run's record in the case's runs folder. `tool_files` is format 4's key, None for a run made before it, and
    `fields` are any other of the record's own, such as rows_skipped or from_output."""
    folder = case.runs_folder / run_id
    folder.mkdir(parents=True)
    record = RunRecord(run_id=run_id, tool=tool, tool_version="1", executable="", host=host, argv=[], cwd="",
                       inputs=list(inputs), started_utc="2026-10-16T01:00:00Z", status=status, reason=reason,
                       finished_utc="2026-10-16T01:00:05Z", loaded_rows=rows, rules=rules, tool_files=tool_files, **fields)
    (folder / RUN_FILE).write_text(json.dumps(asdict(record)), encoding="utf-8")


def rewrite_record(case, run_id, **changes):
    """A run's record as it is, with `changes` to its keys."""
    path = case.runs_folder / run_id / RUN_FILE
    path.write_text(json.dumps({**json.loads(path.read_text(encoding="utf-8")), **changes}), encoding="utf-8")


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


def case_with_a_locked_file(root, files, monkeypatch):
    """A case whose evidence is `files` under WS01, intake having read all of them but locked.bin, as when another program
    holds that file open with no sharing."""
    from glessner.case import create_case

    real = intake_module.sha256_file

    def sha256_file(path):
        if path.name == "locked.bin":
            raise PermissionError(13, "The process cannot access the file")
        return real(path)

    evidence = root / "evidence" / "WS01"
    evidence.mkdir(parents=True)
    for file in files:
        (evidence / file).write_bytes(file.encode())
    case = create_case(root / "case", "Unreadable", evidence.parent, "cody")
    with monkeypatch.context() as m:
        m.setattr(intake_module, "sha256_file", sha256_file)
        intake(case)
    return case


def test_full_checks_do_not_count_files_intake_could_not_read(tmp_path, monkeypatch, capsys):
    """Every full check, the findings summary's, the verify command's, and close's, counts only the files it re-hashed
    and names the others as unverified, a file intake couldn't read among them, also when it is the only one. Counted as
    checked, that file would make the summary say "Every evidence file (2) ... all match", close journal 2 evidence
    files that matched, and the verify command say all evidence files match, while the overview counts 1 hashed. Once
    the file can be read, it still has no intake hash, and stays unverified. With no file checked at all, the verify
    command's exit is 1, as it is for a manifest that lists no file, since nothing was verified."""
    from glessner.audit import describe, read_entries

    for name, files in (("both", ("readable.txt", "locked.bin")), ("alone", ("locked.bin",))):
        case = case_with_a_locked_file(tmp_path / name, files, monkeypatch)
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
        assert cli.cmd_verify(case, None) == (0 if hashed else 1), name   # with no file checked, nothing was verified
        out = capsys.readouterr().out
        assert "All evidence files match" not in out and "is unverified: WS01/locked.bin." in out, (name, out)
        assert ("No evidence file has an intake hash to check." in out) == (not hashed), (name, out)
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


def test_verify_exits_0_when_some_files_were_read_and_others_were_not(tmp_path, monkeypatch, capsys):
    """One file hashed and matching, one that intake couldn't read: the exit is 0, and the output names the other as
    unverified without the line for a check that found no file to check."""
    case = case_with_a_locked_file(tmp_path, ("readable.txt", "locked.bin"), monkeypatch)
    assert cli.cmd_verify(case, None) == 0
    out = capsys.readouterr().out
    assert "The 1 evidence file intake hashed matches the intake manifest." in out
    assert "is unverified: WS01/locked.bin." in out and "has an intake hash to check" not in out


def test_verify_exits_1_when_intake_could_not_read_any_file(tmp_path, monkeypatch, capsys):
    """Every file of the manifest unreadable at intake: no later check can give one a hash, so nothing was verified. The
    exit is 1 and a line says no file has an intake hash to check, as close's does, ahead of the files named as
    unverified."""
    case = case_with_a_locked_file(tmp_path, ("locked.bin",), monkeypatch)
    assert cli.cmd_verify(case, None) == 1
    out = capsys.readouterr().out
    assert "No evidence file has an intake hash to check." in out and "All evidence files match" not in out
    assert out.index("No evidence file has an intake hash to check.") < out.index("is unverified: WS01/locked.bin.")


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
    rekey = {"seq": 2, "at": AT, "who": SYSTEM, "action": "case_upgrade", "from_format": 4, "to_format": 5, "text": "x",
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


@pytest.mark.parametrize(("who", "listed"), [(["cody", "ann"], '["cody", "ann"]'), ({"by": "cody"}, '{"by": "cody"}'),
                                              (5, "5"), (None, "null")], ids=["list", "object", "number", "null"])
def test_the_overview_and_the_audit_trail_read_a_who_under_the_seal_that_is_not_a_string(overview_case, who, listed):
    """Format 2's reader gives a line as written, so a line under the seal can hold a who that is a list, an object, a
    number, or null. Such a line is someone's entry, not the app's. The overview builds, and its last action is that line
    with the who as the audit trail lists it, its JSON text. The audit page that button opens lists the row, offers the
    text as an analyst, filters by it, and the exported trail names it."""
    folder = overview_case.folder
    (folder / "journal.jsonl").write_bytes(chained([], before=unchained({**note(1), "who": who})))
    forget(folder)
    app = App(overview_case)
    try:
        last = api_overview(app, {})["progress"]["last"]
        assert (last["seq"], last["who"]) == (1, listed) and "looked at it" in last["text"]
        shown = api_audit(app, {})
        assert [(r["seq"], r["who"]) for r in shown["rows"] if r["seq"] == 1] == [(1, listed)]
        assert listed in shown["analysts"] and all(isinstance(name, str) for name in shown["analysts"])
        assert [r["seq"] for r in api_audit(app, {"who": [listed]})["rows"]] == [1]
        assert f"UTC, {_md(listed)}:" in markdown(entries(app.journal.path), "Test", {})
    finally:
        app.con.close()


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


FILES = {"hayabusa.exe": "ab" * 32, "rules/": "cd" * 32, "config/": "ef" * 32}   # what a format 4 run of Hayabusa records


def hayabusa_chips(app):
    """The chips of each Hayabusa lead, in the overview's order of leads, with its host."""
    leads = api_overview(app, {})["leads"]
    return [(lead["host"], lead["chips"]) for lead in leads if lead["kind"] == "alerts" and lead["tool"] == "hayabusa"]


@pytest.mark.parametrize(("desktop_run", "desktop_chips"), [
    ({}, ["Hayabusa 3.6.0", "Hayabusa rules not recorded"]),   # a run made before format 4: no tool_files
    ({"from_output": True}, ["Hayabusa 3.6.0"]),                 # found output: no tool ran, so nothing was to record
    ({"tool_files": FILES}, ["Hayabusa 3.6.0"]),                 # recorded, and its rules folder gave no label
])
def test_a_hayabusa_lead_names_the_rules_of_the_run_that_made_its_hits(overview_case, desktop_run, desktop_chips):
    """The chip reads the label of the Hayabusa run whose hits the lead holds. The events the hits matched are
    EvtxECmd's, whose run has a label of its own, so reading their run's would give the maps. A tool run without
    tool_files didn't record its rules; found output, and a run without a record, say nothing. The lead's rules are the
    titles its page links, and take no label."""
    run_record(overview_case, "r7", "evtxecmd", "DC01", "ok", 11, rules="Maps, 456 maps",
               tool_files={"EvtxECmd.exe": "12" * 32, "Maps/": "34" * 32})
    run_record(overview_case, "r8", "hayabusa", "DC01", "ok", 4, rules="Hayabusa rules fffbdd1", tool_files=FILES)
    run_record(overview_case, "r9", "hayabusa", "DESKTOP", "ok", 1, **desktop_run)
    app, _ = app_with_work(overview_case)
    try:
        # The first DC01 lead's hits are of two versions, the second's of one
        assert hayabusa_chips(app) == [("DC01", ["Hayabusa 3.6.0, t", "Hayabusa rules fffbdd1"]),
                                       ("DC01", ["Hayabusa 3.6.0", "Hayabusa rules fffbdd1"]),
                                       ("DESKTOP", desktop_chips)]
        titles = [t["title"] for lead in api_overview(app, {})["leads"] for t in lead.get("rules", [])]
        assert titles and not any("fffbdd1" in title or "Maps" in title for title in titles)
    finally:
        app.con.close()


def test_a_hayabusa_lead_names_each_rule_set_its_runs_used_and_says_nothing_for_a_run_with_no_record(overview_case):
    """After an update-rules between two runs, a lead whose hits came from both names both labels, in order. Runs with
    no run.json, such as the case's others, add no chip."""
    run_record(overview_case, "r5", "hayabusa", "DC01", "ok", 1, rules="Hayabusa rules 0a0a0a0", tool_files=FILES)
    run_record(overview_case, "r8", "hayabusa", "DC01", "ok", 4, rules="Hayabusa rules fffbdd1", tool_files=FILES)
    app, _ = app_with_work(overview_case)
    try:
        first, second, desktop = hayabusa_chips(app)
        assert first == ("DC01", ["Hayabusa 3.6.0, t", "Hayabusa rules 0a0a0a0", "Hayabusa rules fffbdd1"])
        assert second == ("DC01", ["Hayabusa 3.6.0", "Hayabusa rules fffbdd1"])   # its hits are all of the later run
        assert desktop == ("DESKTOP", ["Hayabusa 3.6.0"])
    finally:
        app.con.close()


def test_a_suricata_lead_never_says_its_rules_are_not_recorded(overview_case):
    """Suricata's rule set has been in the run record since format 3, and its registry entry has no rules_label, so a
    run with no label and no tool_files, such as one whose rules folder was missing, adds no chip."""
    run = "20261016T010000Z_suricata_network"
    rewrite_record(overview_case, run, rules="")
    app, _ = app_with_work(overview_case)
    try:
        leads = api_overview(app, {})["leads"]
        suricata = next(lead for lead in leads if lead["kind"] == "alerts" and lead["tool"] == "suricata")
        assert suricata["chips"] == ["Suricata 8.0.7"]
    finally:
        app.con.close()


def test_a_lead_of_imported_alerts_never_says_its_rules_are_not_recorded(synthetic_case):
    """An import has no registry entry and records no tool_files, so its lead's chips name the build that imported the
    alerts and nothing about rules."""
    fast = Event(ts_us=T0 + 70 * SEC, ts_desc="Alert", artifact="ids_alert", source_file="fast.log", source_record="1",
                 message="[1:2001:1] ET TEST Leak", log_channel="Attempted Information Leak",
                 extra={"signature": "ET TEST Leak", "sid": "2001", "priority": "2"})
    load(synthetic_case.db_path, [fast], host="network", tool="import", tool_version="t", run_id="r7",
         replaces_sources=["fast.log"], staging_dir=synthetic_case.folder)
    run_record(synthetic_case, "r7", "import", "network", "ok", 1, parser="import")
    app = App(synthetic_case)
    try:
        lead = next(lead for lead in api_overview(app, {})["leads"] if lead["kind"] == "alerts" and lead["tool"] == "import")
        assert lead["chips"] == ["imported by glessner t"]
    finally:
        app.con.close()


def skipped_by_host(app):
    return {h["host"]: h["skipped"] for h in api_overview(app, {})["hosts"]}


def test_what_the_case_holds_counts_the_rows_each_host_s_latest_runs_skipped(overview_case):
    """A host's skipped count is the sum over the latest successful run of each tool and, for a tool that runs once per
    file, of each file. An earlier run of a file, a failed run, a parser that doesn't count, and an import, which can
    load several hosts in one run, add nothing."""
    run_record(overview_case, "20261016T020000Z_mftecmd_DC01", "mftecmd", "DC01", "ok", 5, inputs=("DC01/C/$MFT",),
               rows_skipped=4)   # replaced by the next run of the same file
    run_record(overview_case, "20261016T020100Z_mftecmd_DC01", "mftecmd", "DC01", "ok", 5, inputs=("DC01/C/$MFT",),
               rows_skipped=2)
    run_record(overview_case, "20261016T020200Z_mftecmd_DC01", "mftecmd", "DC01", "ok", 5, inputs=("DC01/D/$MFT",),
               rows_skipped=3)
    run_record(overview_case, "20261016T020300Z_pecmd_DC01", "pecmd", "DC01", "ok", 5)   # it doesn't count them
    run_record(overview_case, "20261016T020400Z_mftecmd_DESKTOP", "mftecmd", "DESKTOP", "failed", None,
               reason="exit code 1", inputs=("DESKTOP/C/$MFT",), rows_skipped=9)
    run_record(overview_case, "20261016T020500Z_import_DC01", "import", "DC01", "ok", 5, rows_skipped=6)
    rewrite_record(overview_case, "20261016T010000Z_suricata_network", rows_skipped=1)
    app, _ = app_with_work(overview_case)
    try:
        assert skipped_by_host(app) == {"DC01": 5, "DESKTOP": 0, "WS03": 0, "network": 1}
    finally:
        app.con.close()


def test_what_the_case_holds_shows_a_split_host_s_skipped_rows_once_on_its_first_lane(tmp_path):
    """A run's count belongs to the host folder it ran on. After a split by recorded computer, that host's events sit in
    lanes, and the count shows on the first lane that holds them, not on each."""
    case, runs = lab_case(tmp_path)
    record, folder = runs["evtx"]
    record.rows_skipped = 7
    _write_record(folder, record)
    app = App(case)
    try:
        assert skipped_by_host(app) == {"LAB": 7}
        split(app)
        assert skipped_by_host(app) == {"DC1": 7, "LAB": 0, "MSEDGEWIN10": 0, "PC01": 0}
    finally:
        app.con.close()


DAY = 86_400 * SEC
LOW = to_us("1990-01-01T00:00:00Z")
NEWEST = to_us("2026-10-16T01:00:05Z")   # run_record's finish
HIGH = NEWEST + DAY                       # the latest time a host's span takes when that run is the newest
STRAY = to_us("3320-11-16T08:35:52Z")
LOG = {"DC01": DC_LOG, "DESKTOP": WS_LOG}
RUN = "20261016T010000Z_evtxecmd_DC01"


def timed(case, host, times, run="r20"):
    """One event log event of the host at each time in `times`, loaded as a run of its own."""
    events = [logon(ts, 500 + n, LOG.get(host, f"{host}/Security.evtx")) for n, ts in enumerate(times)]
    load(case.db_path, events, host=host, tool="evtxecmd", tool_version="t", run_id=run, replaces_sources=[],
         staging_dir=case.folder)


def link_times(case, host, times, run):
    """Autoruns PE link times, which say when an image was built and set no span, one event at each time."""
    events = [Event(ts_us=ts, ts_desc=BUILT, artifact="autoruns", source_file=f"{host}/autoruns.csv", source_record=str(n),
                    message=f"image {n}") for n, ts in enumerate(times)]
    load(case.db_path, events, host=host, tool="autoruns", tool_version="t", run_id=run, replaces_sources=[],
         staging_dir=case.folder)


def rule_hit(case, host, ts, run):
    """A Hayabusa hit on the host at `ts`. Its rows are counted apart from the host's events and set no span."""
    load(case.db_path, [hit("900", "Time stomping", "medium", LOG[host], ts)], host=host, tool="hayabusa", tool_version="t",
         run_id=run, replaces_sources=[], staging_dir=case.folder)


def spans(app):
    """Each host's first and last time, and the note on the events outside them, as the overview gives them."""
    return {h["host"]: (h["first"], h["last"], h["outside"]) for h in api_overview(app, {})["hosts"]}


def test_a_host_s_span_leaves_out_a_time_beyond_a_day_past_the_newest_run_and_names_it(synthetic_case):
    """A file whose $FN time is dated 3320 does not set the host's last time. The span takes the host's other events,
    the note counts the one outside with its time, and the host's event count includes it. A Hayabusa hit on that event
    is not a second event outside."""
    timed(synthetic_case, "DC01", [STRAY])
    rule_hit(synthetic_case, "DC01", STRAY, "r25")
    run_record(synthetic_case, RUN, "evtxecmd", "DC01", "ok", 6)
    app = App(synthetic_case)
    try:
        found = spans(app)
        assert found["DC01"] == (T0 - 3600 * SEC, T0 + 63 * SEC, {"count": 1, "first": STRAY, "last": STRAY})
        assert found["DESKTOP"][2] is None
        assert {h["host"]: h["events"] for h in api_overview(app, {})["hosts"]}["DC01"] == 8
    finally:
        app.con.close()


def test_the_events_outside_the_span_are_counted_with_the_first_and_last_of_their_times(synthetic_case):
    """Times before 1990, which are file times among the activity, and times past the newest run are outside together,
    and the note gives how many with the earliest and the latest."""
    early, late = to_us("1980-01-01T00:00:00Z"), to_us("2099-01-01T00:00:00Z")
    timed(synthetic_case, "DESKTOP", [STRAY, early, late, early + 5 * SEC])
    run_record(synthetic_case, RUN, "evtxecmd", "DC01", "ok", 9)
    app = App(synthetic_case)
    try:
        assert spans(app)["DESKTOP"] == (T0 - 3600 * SEC, T0 + 910 * SEC, {"count": 4, "first": early, "last": STRAY})
    finally:
        app.con.close()


def test_the_bound_takes_its_edges_and_the_host_s_offset(synthetic_case):
    """Both ends of the bound are inside it: 1990-01-01 00:00:00 and one day after the newest run, as the host's clock
    shows them, which is the recorded time plus its offset. A microsecond past either end is outside."""
    timed(synthetic_case, "DC01", [LOW - 1, LOW, HIGH, HIGH + 1])
    timed(synthetic_case, "DESKTOP", [HIGH - 3600 * SEC, HIGH - 3600 * SEC + 1], run="r21")
    run_record(synthetic_case, RUN, "evtxecmd", "DC01", "ok", 9)
    app = App(synthetic_case)
    try:
        api_host(app, {"host": "DESKTOP", "offset_seconds": 3600})
        found = spans(app)
        assert found["DC01"] == (LOW, HIGH, {"count": 2, "first": LOW - 1, "last": HIGH + 1})
        assert found["DESKTOP"][1:] == (HIGH, {"count": 1, "first": HIGH + 1, "last": HIGH + 1})
    finally:
        app.con.close()


def test_a_run_with_no_finish_bounds_the_span_by_its_start(synthetic_case):
    """The newest run is by its finish, or by its start when it has none, as a run still going has not."""
    started = to_us("2026-10-16T01:00:00Z")
    timed(synthetic_case, "DC01", [started + DAY, started + DAY + 1])
    run_record(synthetic_case, RUN, "evtxecmd", "DC01", "ok", 6)
    rewrite_record(synthetic_case, RUN, finished_utc="")
    app = App(synthetic_case)
    try:
        assert spans(app)["DC01"][1:] == (started + DAY, {"count": 1, "first": started + DAY + 1, "last": started + DAY + 1})
    finally:
        app.con.close()


def test_a_run_s_finish_outranks_its_start_in_finding_the_newest_run(synthetic_case):
    """A run that started earlier and finished later is the newest, and a run with no finish does not make an earlier
    start the newest."""
    after = to_us("2026-10-19T00:00:00Z")   # the finish of 2026-10-18, and one day
    timed(synthetic_case, "DC01", [after, after + 1])
    run_record(synthetic_case, RUN, "evtxecmd", "DC01", "ok", 6)
    rewrite_record(synthetic_case, RUN, finished_utc="")
    run_record(synthetic_case, "20261014T000000Z_evtxecmd_DESKTOP", "evtxecmd", "DESKTOP", "ok", 1)
    rewrite_record(synthetic_case, "20261014T000000Z_evtxecmd_DESKTOP", started_utc="2026-10-14T00:00:00Z",
                   finished_utc="2026-10-18T00:00:00Z")
    app = App(synthetic_case)
    try:
        assert spans(app)["DC01"][1:] == (after, {"count": 1, "first": after + 1, "last": after + 1})
    finally:
        app.con.close()


def test_a_time_before_the_newest_run_stays_in_the_span_though_it_follows_the_case_s_creation(synthetic_case):
    """Evidence can be added to a case for as long as it is worked, so a time after the case was created is no stray:
    only the newest run bounds the span."""
    later = to_us(synthetic_case.settings.created_utc) + 400 * DAY
    timed(synthetic_case, "DC01", [later])
    run_record(synthetic_case, RUN, "evtxecmd", "DC01", "ok", 6)
    rewrite_record(synthetic_case, RUN, finished_utc="2099-06-01T00:00:00Z")
    app = App(synthetic_case)
    try:
        assert spans(app)["DC01"][1:] == (later, None)
    finally:
        app.con.close()


def test_a_case_with_no_run_has_no_upper_bound_but_keeps_the_lower_one(synthetic_case):
    """Without a run record nothing says when the evidence was read, so a time in 3320 stays in the span; the lower
    bound needs no run."""
    early = to_us("1980-01-01T00:00:00Z")
    timed(synthetic_case, "DC01", [STRAY, early])
    app = App(synthetic_case)
    try:
        assert spans(app)["DC01"] == (T0 - 3600 * SEC, STRAY, {"count": 1, "first": early, "last": early})
    finally:
        app.con.close()


def test_a_link_time_sets_no_span_and_counts_as_no_stray_unless_the_host_holds_nothing_else(synthetic_case):
    """Windows 10 hashes the PE link times of its own binaries into 1902 to 2037, so on a host with other events they
    are in neither the span nor the count outside, whether or not the host has an event outside the bound of its own.
    A host with nothing else takes its span from them, with the same bound."""
    in_2085 = to_us("2085-05-05T00:00:00Z")
    timed(synthetic_case, "DC01", [STRAY], "r24")
    link_times(synthetic_case, "DC01", [in_2085, to_us("1975-01-01T00:00:00Z")], "r22")
    link_times(synthetic_case, "BUILDS", [to_us("2010-03-01T00:00:00Z"), to_us("2012-04-02T00:00:00Z"), in_2085], "r23")
    run_record(synthetic_case, RUN, "evtxecmd", "DC01", "ok", 5)
    app = App(synthetic_case)
    try:
        found = spans(app)
        assert found["DC01"] == (T0 - 3600 * SEC, T0 + 63 * SEC, {"count": 1, "first": STRAY, "last": STRAY})
        assert found["BUILDS"] == (to_us("2010-03-01T00:00:00Z"), to_us("2012-04-02T00:00:00Z"),
                                   {"count": 1, "first": in_2085, "last": in_2085})
    finally:
        app.con.close()


def test_a_link_time_inside_the_bound_stays_out_of_a_host_s_span(synthetic_case):
    """Most PE link times fall between 1990 and the newest run. One before the host's first event and one after its
    last, both inside the bound, leave its span, and its note, as its other events give them."""
    link_times(synthetic_case, "DC01", [to_us("2010-03-01T00:00:00Z"), to_us("2023-01-01T00:00:00Z")], "r22")
    run_record(synthetic_case, RUN, "evtxecmd", "DC01", "ok", 5)
    app = App(synthetic_case)
    try:
        assert spans(app)["DC01"] == (T0 - 3600 * SEC, T0 + 63 * SEC, None)
    finally:
        app.con.close()


def test_a_host_with_nothing_inside_the_bound_keeps_the_span_of_all_its_events(synthetic_case):
    """With no event inside the bound there is no rest for the others to lie outside of, so the host reads from its
    first to its last time, with no note."""
    timed(synthetic_case, "WS9", [STRAY, STRAY + 5 * SEC], run="r24")
    run_record(synthetic_case, RUN, "evtxecmd", "DC01", "ok", 6)
    app = App(synthetic_case)
    try:
        assert spans(app)["WS9"] == (STRAY, STRAY + 5 * SEC, None)
    finally:
        app.con.close()


def test_the_overview_words_each_clock_state_from_the_shared_words_with_the_offset_where_it_has_one():
    """The Hosts table's clock cell gives each state in the clock check's words: the offset follows an aligned host in
    parentheses and a host not measured after a semicolon, and a reference lane has no offset in it."""
    def text(state, offset=0.0, host="DC01", **clock):
        ident = HostIdentity(host=host, role="Servers", role_source="guess", offset_seconds=offset)
        return _clock_text(ident, {"state": state, "reference": "network", **clock})

    assert text("suggest", skew_seconds=-3599.5, skew_text="59 m 59.5 s") == {
        "state": "suggest", "text": "59 m 59.5 s behind the capture, not aligned", "flag": True, "reason": ""}
    assert text("suggest", 2, skew_seconds=3599.5, skew_text="59 m 59.5 s")["text"] == (
        "59 m 59.5 s ahead of the capture, not aligned")
    assert text("agrees")["text"] == "matches the capture"
    assert text("agrees", -3599.5)["text"] == "aligned to the capture (-3,599.5 s)"
    assert text("disagree", 5)["text"] == "pairs with the capture disagree" and text("disagree")["flag"]
    assert text("none")["text"] == "not measured" and text("none", 90)["text"] == "not measured; offset +90 s"
    assert _clock_text(None, {}) == {"state": "none", "text": "not measured", "flag": False, "reason": ""}
    assert text("none", 90, host="network", reference="network")["text"] == "the reference clock"
    assert text("none", host="network", reference="network")["flag"] is False


RLO = "\u202e"   # right-to-left override
ODD_TOOL = f"evil|*_{RLO}tool"   # a tool ID in a run.json that holds a pipe, Markdown characters, and a bidi control
CHECK_WHERE = ("The Tools page shows the check of each tool's latest successful run. "
               "Each run's record names up to 20 of the paths that differed.")


def recorded_checks(root):
    """The tool_check that check_tool writes for each result a run can record, from a fake tools folder under `root`: a
    tool's files against its pin before and after a change, a tool the manifest lacks, a folder with no manifest, and a
    folder whose manifest is not JSON. The keys are the result words."""
    from test_tools_manifest import checked, evtx, hayabusa, pinned

    tool = evtx(root)
    pinned(root, tool)
    matches = checked(root, tool)
    tool.executable.write_bytes(b"MZ changed")
    bare, broken = root / "bare", root / "broken"
    bare.mkdir()
    broken.mkdir()
    (broken / "tools_manifest.json").write_text("{not json", encoding="utf-8")
    return {"matches": matches, "differs": checked(root, tool), "not pinned": checked(root, hayabusa(root)),
            "no manifest": checked(root, tool, bare), "unreadable": checked(root, tool, broken)}


def tool_check_line(case):
    """The overview's Integrity line about runs whose tools differed from their pins, from a new app on the case."""
    app = App(case)
    try:
        return api_overview(app, {})["integrity"]["tool_check"]
    finally:
        app.con.close()


def test_the_fake_tools_folder_records_each_result_word_check_tool_writes(tmp_path):
    """The records the tool check tests use are check_tool's own output, so a result word it changes shows here."""
    checks = recorded_checks(tmp_path / "fake_tools")
    assert {word: check["result"] for word, check in checks.items()} == {word: word for word in checks}
    assert list(checks) == ["matches", "differs", "not pinned", "no manifest", "unreadable"]
    assert [f["path"] for f in checks["differs"]["files"]] == ["EvtxECmd.exe"]


def test_the_integrity_section_has_no_tool_check_line_unless_a_run_recorded_a_difference(synthetic_case, tmp_path):
    """No run records, a run made before the check (tool_check null), and runs whose check matched, found no pin, found no
    manifest, or couldn't read it give no line. Only the result differs counts."""
    checks = recorded_checks(tmp_path / "fake_tools")
    assert tool_check_line(synthetic_case) is None
    run_record(synthetic_case, "r1", "evtxecmd", "DC01", "ok", 5, tool_check=checks["matches"])
    run_record(synthetic_case, "r2", "evtxecmd", "DESKTOP", "ok", 5, tool_check=checks["not pinned"])
    run_record(synthetic_case, "r3", "recmd", "DC01", "ok", 1, tool_check=checks["no manifest"])
    run_record(synthetic_case, "r4", "recmd", "DESKTOP", "ok", 1, tool_check=checks["unreadable"])
    run_record(synthetic_case, "r5", "hayabusa", "DC01", "ok", 1)
    assert tool_check_line(synthetic_case) is None


def test_the_integrity_section_counts_one_differing_run_and_names_its_tool(synthetic_case, tmp_path):
    """One run whose check differs gives the line, with the run in the singular, the tool by its registry name, and the
    sentence that says where the checks are shown."""
    checks = recorded_checks(tmp_path / "fake_tools")
    run_record(synthetic_case, "r1", "evtxecmd", "DC01", "ok", 5, tool_check=checks["differs"])
    run_record(synthetic_case, "r2", "evtxecmd", "DESKTOP", "ok", 5, tool_check=checks["matches"])
    assert tool_check_line(synthetic_case) == {
        "runs": 1, "tools": ["EvtxECmd"],
        "text": f"1 run used tool files that differed from the pin: EvtxECmd. {CHECK_WHERE}"}


def test_the_integrity_section_counts_every_differing_run_and_names_each_tool_once(synthetic_case, tmp_path):
    """A later run that matched doesn't erase an earlier run's difference, and each tool is named once however many of its
    runs differed. Five runs of three tools: EvtxECmd's earlier run differed and its newer one matched, and RECmd's two
    runs and Hayabusa's one differed, so four count."""
    checks = recorded_checks(tmp_path / "fake_tools")
    run_record(synthetic_case, "r1", "evtxecmd", "DC01", "ok", 5, tool_check=checks["differs"])
    run_record(synthetic_case, "r2", "evtxecmd", "DC01", "ok", 5, tool_check=checks["matches"])
    rewrite_record(synthetic_case, "r2", started_utc="2026-10-17T01:00:00Z", finished_utc="2026-10-17T01:00:05Z")
    run_record(synthetic_case, "r3", "recmd", "DC01", "ok", 1, tool_check=checks["differs"])
    run_record(synthetic_case, "r4", "recmd", "DESKTOP", "ok", 1, tool_check=checks["differs"])
    run_record(synthetic_case, "r5", "hayabusa", "DC01", "ok", 1, tool_check=checks["differs"])
    assert tool_check_line(synthetic_case) == {
        "runs": 4, "tools": ["EvtxECmd", "Hayabusa", "RECmd"],
        "text": f"4 runs used tool files that differed from the pin: EvtxECmd, Hayabusa, and RECmd. {CHECK_WHERE}"}


def test_the_integrity_section_counts_a_differing_run_the_tools_page_no_longer_shows(synthetic_case, tmp_path):
    """A run differs, the tool is pinned again, and a rerun on the same host matches. The Tools page shows the check of
    each tool's latest successful run, here the rerun's match, so the line counts the first run from its record and says
    where the page's check and the run's record each stand."""
    from glessner.toolbox import overview
    from glessner.tools import load_registry

    checks = recorded_checks(tmp_path / "fake_tools")
    run_record(synthetic_case, "r1", "evtxecmd", "DC01", "ok", 5, tool_check=checks["differs"])
    run_record(synthetic_case, "r9", "evtxecmd", "DC01", "ok", 5, tool_check=checks["matches"])
    rewrite_record(synthetic_case, "r9", started_utc="2026-10-17T01:00:00Z", finished_utc="2026-10-17T01:00:05Z")
    (evtxecmd,) = [t for t in overview(synthetic_case, load_registry(), {})["tools"] if t["id"] == "evtxecmd"]
    assert evtxecmd["last_run"]["latest"]["run_id"] == "r9"
    assert evtxecmd["last_run"]["latest"]["text"] == "tool check matches"
    assert tool_check_line(synthetic_case) == {
        "runs": 1, "tools": ["EvtxECmd"],
        "text": f"1 run used tool files that differed from the pin: EvtxECmd. {CHECK_WHERE}"}


def test_the_integrity_section_counts_a_differing_run_that_failed_after_a_matching_one(synthetic_case, tmp_path):
    """A tool file goes missing, so the tool's newer run records differs and fails. The Tools page shows the check of the
    latest successful run, the earlier match, and lists the failed run under its gaps without a check, so the line counts
    the failed run from its record and its pointer says the page shows the latest successful run's check."""
    from glessner.toolbox import overview
    from glessner.tools import load_registry

    checks = recorded_checks(tmp_path / "fake_tools")
    run_record(synthetic_case, "r1", "evtxecmd", "DC01", "ok", 5, tool_check=checks["matches"])
    run_record(synthetic_case, "r9", "evtxecmd", "DC01", "failed", 0, reason="exit code 1", tool_check=checks["differs"])
    rewrite_record(synthetic_case, "r9", started_utc="2026-10-17T01:00:00Z", finished_utc="2026-10-17T01:00:05Z")
    page = overview(synthetic_case, load_registry(), {})
    (evtxecmd,) = [t for t in page["tools"] if t["id"] == "evtxecmd"]
    assert evtxecmd["last_run"]["latest"]["run_id"] == "r1"
    assert evtxecmd["last_run"]["latest"]["text"] == "tool check matches"
    assert [(gap["run_id"], gap["status"]) for gap in page["gaps"]] == [("r9", "failed")]
    assert "tool_check" not in page["gaps"][0]
    assert tool_check_line(synthetic_case) == {
        "runs": 1, "tools": ["EvtxECmd"],
        "text": f"1 run used tool files that differed from the pin: EvtxECmd. {CHECK_WHERE}"}


def test_the_integrity_section_names_two_tools_with_and(synthetic_case, tmp_path):
    checks = recorded_checks(tmp_path / "fake_tools")
    run_record(synthetic_case, "r1", "evtxecmd", "DC01", "ok", 5, tool_check=checks["differs"])
    run_record(synthetic_case, "r3", "recmd", "DC01", "ok", 1, tool_check=checks["differs"])
    assert tool_check_line(synthetic_case)["text"] == (
        f"2 runs used tool files that differed from the pin: EvtxECmd and RECmd. {CHECK_WHERE}")


def test_the_integrity_section_names_a_tool_the_registry_lacks_by_its_id_as_recorded(synthetic_case, tmp_path):
    """The overview holds the name as the record has it. The page draws it through el, which shows a bidi control as
    [U+XXXX] (test_browser_overview_tool_check.py)."""
    checks = recorded_checks(tmp_path / "fake_tools")
    run_record(synthetic_case, "r1", ODD_TOOL, "DC01", "ok", 5, tool_check=checks["differs"])
    assert tool_check_line(synthetic_case) == {
        "runs": 1, "tools": [ODD_TOOL],
        "text": f"1 run used tool files that differed from the pin: {ODD_TOOL}. {CHECK_WHERE}"}
