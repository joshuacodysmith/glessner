"""Attack-phase and technique tags: journaled tags, Hayabusa's as suggestions, Tactic lanes,
the View filter's tag fields, exports, and the findings summary."""

import csv
import json

import pytest
from conftest import DC_LOG, SEC, T0, serving
from test_analysis_relations import open_case
from test_server import login, request

from glessner.analysis import refresh_tags
from glessner.events import Event, load
from glessner.filters import normalize, where_sql
from glessner.journal import JOURNAL_FILE, JournalError, State, replay
from glessner.queries import lanes
from glessner.server import api_report_preview
from glessner.tags import TagError, normalize_tag

ATTACK_HIT = Event(ts_us=T0, ts_desc="Event Recorded", artifact="hayabusa", source_file=DC_LOG, source_record="101:attack",
                   record_id=101, message="RDP from internet [high]", log_channel="Security",
                   rule_title="RDP logon", rule_level="high",
                   extra={"MitreTactics": "LatMov ¦ CredAccess", "MitreTags": "T1021.001"})


def rdp_uid(con):
    return con.execute("SELECT event_uid FROM events WHERE tool = 'evtxecmd' AND ts_us = ?", [T0]).fetchone()[0]


def test_tags_normalize():
    assert [normalize_tag(t) for t in ("Lateral Movement", "ta0008", "LatMov", "C2", "t1021.001", "  Beach  Head ")] == [
        "tactic:TA0008", "tactic:TA0008", "tactic:TA0008", "tactic:TA0011", "technique:T1021.001", "tag:beach head"]
    assert normalize_tag("tag:Lateral Movement") == "tag:lateral movement"   # explicitly the analyst's own
    for bad in ("", "tactic:TA9999", "technique:T12", "x" * 41):
        with pytest.raises(TagError):
            normalize_tag(bad)
    # An added technique must be in ATT&CK v20.0's list, and a revoked one names its replacement; the journal's replay
    # and a removal check the ID's form alone
    with pytest.raises(TagError, match=r"^T9999 isn't in ATT&CK v20\.0\.$"):
        normalize_tag("T9999")
    with pytest.raises(TagError, match=r"^T1086 is revoked in ATT&CK v20\.0; it's now T1059\.001\.$"):
        normalize_tag("technique:t1086")
    assert normalize_tag("T9999", listed=False) == "technique:T9999"
    assert normalize_tag("t1086", listed=False) == "technique:T1086"


def test_hayabusa_fields_suggest_known_tactics_and_techniques(synthetic_case):
    """A hit's MitreTactics and MitreTags, split on Hayabusa's separator: an abbreviation the app doesn't know and a
    technique ID that isn't one are left out, and a sub-technique and a lower-case ID are kept. The cases run the SQL
    itself, not a Python copy of it."""
    hit = Event(ts_us=T0, ts_desc="Event Recorded", artifact="hayabusa", source_file=DC_LOG, source_record="101:edges",
                record_id=101, message="Edge cases [high]", log_channel="Security", rule_title="Edge cases",
                rule_level="high", extra={"MitreTactics": "PrivEsc ¦ Stealth ¦ Nope", "MitreTags": "T1133 ¦ t1078.002 ¦ T12"})
    load(synthetic_case.db_path, [hit], host="DC01", tool="hayabusa", tool_version="t", run_id="r6",
         replaces_sources=[], staging_dir=synthetic_case.folder)
    con, _, _ = open_case(synthetic_case)
    rows = con.execute("SELECT tag, kind, label FROM tag_suggestions WHERE event_uid = ? ORDER BY ord, tag",
                       [rdp_uid(con)]).fetchall()
    assert rows == [("tactic:TA0004", "tactic", "Privilege Escalation"), ("tactic:TA0005", "tactic", "Stealth"),
                    ("technique:T1078.002", "technique", "T1078.002"), ("technique:T1133", "technique", "T1133")]


def test_hayabusa_suggests_a_revoked_technique_as_its_replacement(synthetic_case):
    """A rule's revoked ID is suggested as the technique MITRE revoked it in favor of, with the revoked ID kept as the
    suggestion's origin for its hover; an ID not in ATT&CK v20.0 isn't suggested, since the server would refuse its
    Accept. A dismissal journaled for the revoked ID holds, and a rule naming the replacement itself as well gives one
    suggestion."""
    def hit(record, tags):
        return Event(ts_us=T0, ts_desc="Event Recorded", artifact="hayabusa", source_file=DC_LOG, source_record=record,
                     record_id=101, message="Revoked [high]", log_channel="Security", rule_title="Old rule",
                     rule_level="high", extra={"MitreTags": tags})

    load(synthetic_case.db_path, [hit("101:old", "T1086 ¦ T9999 ¦ T1133")], host="DC01", tool="hayabusa",
         tool_version="t", run_id="r6", replaces_sources=[], staging_dir=synthetic_case.folder)
    con, journal, _ = open_case(synthetic_case)
    uid = rdp_uid(con)
    rows = lambda: con.execute("SELECT tag, label, origin FROM tag_suggestions WHERE event_uid = ? ORDER BY tag",
                               [uid]).fetchall()
    assert rows() == [("technique:T1059.001", "T1059.001", "T1086"), ("technique:T1133", "T1133", None)]
    # A T1086 tag already in the journal shows flagged, and its replacement stays suggested beside it for the swap
    journal.append("tag", targets=[uid], add=["technique:T1086"], via="hayabusa")
    refresh_tags(con, journal.state, [uid])
    assert rows() == [("technique:T1059.001", "T1059.001", "T1086"), ("technique:T1133", "T1133", None)]
    journal.append("tag_suggestion", targets=[uid], tags=["technique:T1086"], decision="dismissed")
    refresh_tags(con, journal.state, [uid])
    assert rows() == [("technique:T1133", "T1133", None)]
    con.close()
    load(synthetic_case.db_path, [hit("101:new", "T1059.001")], host="DC01", tool="hayabusa", tool_version="t",
         run_id="r7", replaces_sources=[], staging_dir=synthetic_case.folder)
    con, journal, _ = open_case(synthetic_case)
    assert rows() == [("technique:T1059.001", "T1059.001", None), ("technique:T1133", "T1133", None)]
    journal.append("tag_suggestion", targets=[uid], tags=["technique:T1086"], decision="restored")
    refresh_tags(con, journal.state, [uid])
    assert rows() == [("technique:T1059.001", "T1059.001", "T1086"), ("technique:T1133", "T1133", None)]


def test_journal_records_tags_and_dismissals(synthetic_case):
    con, journal, _ = open_case(synthetic_case)
    uid = rdp_uid(con)
    journal.append("tag", targets=[uid], add=["tactic:TA0001", "tactic:TA0008", "tag:beachhead"])
    journal.append("tag", targets=[uid], remove=["tag:beachhead"])
    journal.append("tag_suggestion", targets=[uid], tags=["tactic:TA0006"], decision="dismissed")
    state = replay(journal.path)
    assert set(state.tags[uid]) == {"tactic:TA0001", "tactic:TA0008"} and state.tags[uid]["tactic:TA0008"]["who"] == "cody"
    assert state.dismissed_tags == {(uid, "tactic:TA0006")}
    for bad in ({"targets": [uid], "add": ["Lateral Movement"]}, {"targets": [], "add": ["tactic:TA0008"]},
                {"targets": [uid]}):
        with pytest.raises(JournalError):
            journal.append("tag", **bad)


def test_suggestions_lanes_filters_and_exports(synthetic_case):
    from glessner.export import export_timeline, write_report

    load(synthetic_case.db_path, [ATTACK_HIT], host="DC01", tool="hayabusa", tool_version="t", run_id="r6",
         replaces_sources=[], staging_dir=synthetic_case.folder)
    con, journal, identity = open_case(synthetic_case)
    uid = rdp_uid(con)
    suggested = lambda: {r[0] for r in con.execute("SELECT tag FROM tag_suggestions WHERE event_uid = ?", [uid]).fetchall()}
    assert suggested() == {"tactic:TA0008", "tactic:TA0006", "technique:T1021.001"}
    # Applying a tag takes it out of the suggestions; dismissing does too, and restoring brings it back.
    journal.append("tag", targets=[uid], add=["tactic:TA0008", "tactic:TA0001"], via="hayabusa")
    journal.append("tag_suggestion", targets=[uid], tags=["tactic:TA0006"], decision="dismissed")
    refresh_tags(con, journal.state, [uid])
    assert suggested() == {"technique:T1021.001"}
    journal.append("tag_suggestion", targets=[uid], tags=["tactic:TA0006"], decision="restored")
    refresh_tags(con, journal.state, [uid])
    assert suggested() == {"tactic:TA0006", "technique:T1021.001"}
    # Tactic lanes: the event sits in both of its tactics' lanes; every other event is Untagged.
    by_lane = {tuple(lane["keys"]): lane["count"] for lane in lanes(con, ["tactic", "host"])}
    assert by_lane[("Initial Access", "DC01")] == 1 and by_lane[("Lateral Movement", "DC01")] == 1
    assert by_lane[("Untagged", "DC01")] == 6 and ("Untagged", "DESKTOP") in by_lane
    # Filter fields: one tag, any tag, a tactic lane, and the Untagged lane.
    shown = lambda pred: {u for (u,) in con.execute(
        f"SELECT e.event_uid FROM events e WHERE e.tool <> 'hayabusa'{where_sql(normalize({'only': [pred]}))}").fetchall()}
    assert shown({"tag": "tactic:TA0008"}) == shown({"tag": "*"}) == shown({"tactic": "Lateral Movement"}) == {uid}
    assert uid not in shown({"tactic": "Untagged"}) and len(shown({"tactic": "Untagged"})) == 11   # 12 events, 1 tagged
    # Exports carry ECS threat fields; the findings summary lists tactics and groups the marked events by them.
    path, _ = export_timeline(con, synthetic_case, identity, T0 - SEC, T0 + SEC, "csv", "all")
    with path.open(encoding="utf-8", newline="") as f:
        row = next(r for r in csv.DictReader(f) if r["event_uid"] == uid)
    assert (row["threat.tactic.name"], row["threat.tactic.id"]) == ("Initial Access; Lateral Movement", "TA0001; TA0008")
    journal.append("mark", targets=[uid], value="malicious")
    from glessner.analysis import replace_marks
    replace_marks(con, journal.state, [uid])
    summary, _ = write_report(con, synthetic_case, identity, {}, State())
    text = summary.read_text(encoding="utf-8")
    assert "ATT&CK: Initial Access, Lateral Movement" in text
    assert "### By ATT&CK tactic" in text and "- **Lateral Movement**: events 1" in text


def test_tag_api(running):
    app, port, _ = running
    session = login(port, app)
    uid = rdp_uid(app.con)
    res, body = request(port, "POST", "/api/tag", session=session,
                        body={"uids": [uid], "add": ["Lateral Movement", "T1021.001", "Staging"]})
    out = json.loads(body)
    assert res.status == 200 and [t["label"] for t in out["tags"]] == ["Lateral Movement", "T1021.001", "staging"]
    event = json.loads(request(port, "GET", f"/api/event?uid={uid}", session=session)[1])["event"]
    assert {t["key"] for t in event["tags"]} == {"tactic:TA0008", "technique:T1021.001", "tag:staging"}
    counts = json.loads(request(port, "GET", "/api/tags", session=session)[1])
    assert counts["any"] == 1 and counts["tags"][0]["label"] == "Lateral Movement"
    meta = json.loads(request(port, "GET", "/api/meta", session=session)[1])
    assert len(meta["tactics"]) == 15 and meta["tactics"][6] == {"id": "TA0005", "name": "Stealth"}
    res, body = request(port, "POST", "/api/tag", session=session, body={"uids": [uid], "add": ["tactic:TA9999"]})
    assert res.status == 400 and "isn't an ATT&CK tactic" in json.loads(body)["error"]


def test_technique_tags_take_only_listed_ids_and_an_old_one_is_flagged(running):
    """Over HTTP: an add of a technique not in ATT&CK v20.0 is refused with the reason and writes nothing, and a revoked
    one names its replacement. A tag in the journal that the list would refuse, as an old case holds it, is kept: the
    Event page and the View panel's counts flag it as a finding's techniques are flagged, the report writes the flag
    beside it, and it can be removed, with or without its prefix."""
    app, port, _ = running
    session = login(port, app)
    uid = rdp_uid(app.con)
    journal_lines = lambda: len((app.case.folder / JOURNAL_FILE).read_text(encoding="utf-8").splitlines())

    def tag(body):
        res, payload = request(port, "POST", "/api/tag", session=session, body={"uids": [uid], **body})
        return res.status, json.loads(payload)

    before = journal_lines()
    status, answer = tag({"add": ["T9999"]})
    assert status == 400 and answer["error"] == "T9999 isn't in ATT&CK v20.0."
    status, answer = tag({"add": ["Lateral Movement", "t1086"]})
    assert status == 400 and answer["error"] == "T1086 is revoked in ATT&CK v20.0; it's now T1059.001."
    assert journal_lines() == before
    status, answer = tag({"add": ["T1059.001"]})
    assert status == 200 and answer["tags"] == [{**answer["tags"][0], "label": "T1059.001",
                                                 "name": "Command and Scripting Interpreter: PowerShell"}]
    assert "flag" not in answer["tags"][0]
    with app.lock:   # the journal's own check is the ID's form, so an old case's tags replay
        app.journal.append("tag", targets=[uid], add=["technique:T1086", "technique:T9999"])
        app.rewrite(tags=[uid])
    flagged = {"T1059.001": "", "T1086": "revoked; now T1059.001", "T9999": "not in ATT&CK v20.0"}
    event = json.loads(request(port, "GET", f"/api/event?uid={uid}", session=session)[1])["event"]
    assert {t["label"]: t.get("flag", "") for t in event["tags"]} == flagged
    counts = json.loads(request(port, "GET", "/api/tags", session=session)[1])["tags"]
    assert {t["label"]: t.get("flag", "") for t in counts} == flagged
    res, _ = request(port, "POST", "/api/mark", session=session, body={"uids": [uid], "value": "malicious"})
    assert res.status == 200
    report = api_report_preview(app, {})["text"]
    assert "   - ATT&CK: T1059.001, T1086 (revoked; now T1059.001), T9999 (not in ATT&CK v20.0)" in report
    status, answer = tag({"remove": ["technique:T9999", "T1086"]})
    assert status == 200 and [t["label"] for t in answer["tags"]] == ["T1059.001"]
    # Undoing the removal brings the old tags back, flagged: the undo's changes take the journal's form check too
    res, _ = request(port, "POST", "/api/undo", session=session, body={"seq": answer["seq"], "note": "slip"})
    assert res.status == 200
    event = json.loads(request(port, "GET", f"/api/event?uid={uid}", session=session)[1])["event"]
    assert {t["label"]: t.get("flag", "") for t in event["tags"]} == flagged


def test_accepting_a_revoked_suggestion_tags_its_replacement(synthetic_case):
    """End to end over HTTP: a rule's revoked T1086 shows as the suggestion T1059.001 with its origin, its Accept (via
    Hayabusa) tags T1059.001, which the server takes, and the suggestion goes."""
    load(synthetic_case.db_path, [Event(ts_us=T0, ts_desc="Event Recorded", artifact="hayabusa", source_file=DC_LOG,
                                        source_record="101:old", record_id=101, message="Old rule [high]",
                                        log_channel="Security", rule_title="Old rule", rule_level="high",
                                        extra={"MitreTags": "T1086"})],
         host="DC01", tool="hayabusa", tool_version="t", run_id="r6", replaces_sources=[], staging_dir=synthetic_case.folder)
    for app, port, _ in serving(synthetic_case):
        session = login(port, app)
        uid = rdp_uid(app.con)
        event = lambda: json.loads(request(port, "GET", f"/api/event?uid={uid}", session=session)[1])["event"]  # noqa: B023
        assert [(s["key"], s.get("origin")) for s in event()["tag_suggestions"]] == [("technique:T1059.001", "T1086")]
        res, body = request(port, "POST", "/api/tag", session=session,
                            body={"uids": [uid], "add": ["technique:T1059.001"], "via": "hayabusa"})
        assert res.status == 200 and [(t["key"], t["via"]) for t in json.loads(body)["tags"]] == [
            ("technique:T1059.001", "hayabusa")]
        assert event()["tag_suggestions"] == []
