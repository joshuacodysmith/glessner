"""The audit trail and undo: reversing entries recorded as corrections of accidents,
never rewriting the journal, and never undoing what a later entry changed."""

import json
from pathlib import Path

import pytest
from test_analysis_relations import open_case
from test_server import login, request

from glessner.audit import AuditError, describe, markdown, plan_undo, read_entries, rows
from glessner.journal import replay


def evtx_uids(con, n=3):
    return [u for (u,) in con.execute("SELECT event_uid FROM events WHERE tool = 'evtxecmd' ORDER BY ts_us LIMIT ?",
                                      [n]).fetchall()]


def undo(journal, seq, note=""):
    plan = plan_undo(read_entries(journal.path), seq)
    return journal.append("undo", undoes=seq, correction="accident", changes=plan["changes"], kept=len(plan["kept"]),
                          note=note), plan


def test_undo_restores_marks_but_keeps_later_changes(synthetic_case):
    con, journal, _ = open_case(synthetic_case)
    a, b, c = evtx_uids(con)
    journal.append("mark", targets=[c], value="authorized", note="machine account")       # 2: c had a mark before
    journal.append("mark", targets=[a, b, c], value="malicious", note="")                # 3: the accident
    journal.append("mark", targets=[b], value="suspicious", note="on second look")        # 4: b changed later
    _, plan = undo(journal, 3, note="wrong group")
    assert plan["kept"] == [b] and sorted(plan["changed"]) == sorted([a, c])
    state = replay(journal.path)   # the journal alone gives the same state
    assert a not in state.marks and state.marks[b].value == "suspicious"
    assert (state.marks[c].value, state.marks[c].note) == ("authorized", "machine account")
    entries = read_entries(journal.path)
    assert len(entries) == 5 and entries[2]["value"] == "malicious"   # the original stays
    assert describe(entries[4]) == ('Undo of #3: 2 events back to how they were; 1 changed since #3 kept its later state. '
                                    'Note: "wrong group"')
    with pytest.raises(AuditError, match="already undone by #5"):
        plan_undo(entries, 3)
    with pytest.raises(AuditError):
        plan_undo(entries, 5)   # an undo isn't itself undone here


def test_undo_tags_decisions_and_tag_suggestions(synthetic_case):
    con, journal, _ = open_case(synthetic_case)
    a, b, _ = evtx_uids(con)
    journal.append("tag", targets=[a], add=["tactic:TA0001"])                                       # 2
    journal.append("tag", targets=[a, b], add=["tactic:TA0001", "tactic:TA0008"])                   # 3
    journal.append("suggestion_decision", targets=[a, b], source="hayabusa", decision="rejected")   # 4
    journal.append("tag_suggestion", targets=[a], tags=["tactic:TA0006"], decision="dismissed")     # 5
    undo(journal, 3)
    state = replay(journal.path)
    assert set(state.tags[a]) == {"tactic:TA0001"} and b not in state.tags   # a's earlier tag stays
    undo(journal, 4)
    undo(journal, 5)
    state = replay(journal.path)
    assert not state.rejected and not state.dismissed_tags


def test_trail_rows_filters_and_markdown(synthetic_case):
    con, journal, _ = open_case(synthetic_case)
    a, b, _ = evtx_uids(con)
    journal.append("mark", targets=[a, b], value="suspicious", note="Accepted suggestion from hayabusa")   # 2
    journal.append("note", target=a, text="first look")                                                  # 3
    journal.append("host_role", host="DC01", role="Domain controllers")                                  # 4
    undo(journal, 2)                                                                                      # 5
    journal.append("note_retract", target=a, note_seq=3)                                                 # 6
    entries = read_entries(journal.path)
    out = rows(entries, {a: "DC01 4624: logon"})
    by_seq = {r["seq"]: r for r in out["rows"]}
    assert [r["seq"] for r in out["rows"]] == [6, 5, 4, 3, 2, 1]   # newest first, case_created last
    assert by_seq[2]["text"] == "Marked 2 events Suspicious (accepted hayabusa suggestions)" and by_seq[2]["undone_by"] == 5
    assert not by_seq[2]["undoable"] and by_seq[4]["panel"] == "hosts" and by_seq[3]["retracted_by"] == 6
    assert by_seq[3]["text"] == 'Note on DC01 4624: logon: "first look"'
    assert [r["seq"] for r in rows(entries, {}, corrections=True)["rows"]] == [5]
    assert [r["seq"] for r in rows(entries, {}, kind="Notes")["rows"]] == [6, 3]
    assert [r["seq"] for r in rows(entries, {}, event=b)["rows"]] == [5, 2]   # b's history includes the undo
    assert replay(journal.path).notes[a][0]["retracted"]["seq"] == 6
    text = markdown(entries, "Synthetic", {})
    assert "**#5**" in text and "*(correction of an accident)*" in text and "*(undone by #5)*" in text


def test_an_accept_with_a_note_reads_as_both():
    """An accept's note follows its fixed text, and the trail shows the source and the note apart."""
    entry = {"action": "mark", "targets": ["a"], "value": "suspicious",
             "note": "Accepted suggestion from print-spooler-pipe: spooler pipe from the admin host"}
    assert describe(entry, {"a": "MSEDGEWIN10 5145: share"}) == (
        'Marked MSEDGEWIN10 5145: share Suspicious (accepted print-spooler-pipe suggestions). '
        'Note: "spooler pipe from the admin host"')


def test_the_command_line_close_reads_as_what_the_re_hash_found(synthetic_case):
    """The CLI's close shows in the trail, and in its Markdown export, as what the re-hash found, for a match and for a
    mismatch, not as raw JSON such as 'Set closed to {"at": ..., "hash_check": "ok", ...}'."""
    from glessner.cli import main
    from glessner.intake import intake

    for name in ("Security.evtx", "System.evtx"):
        (synthetic_case.evidence / "DC01" / name).write_bytes(b"ElfFile\x00" + name.encode())
    intake(synthetic_case)
    assert main(["close", str(synthetic_case.folder)]) == 0
    (synthetic_case.evidence / "DC01" / "System.evtx").write_bytes(b"ElfFile\x00changed")
    assert main(["close", str(synthetic_case.folder)]) == 1
    entries = read_entries(synthetic_case.folder / "journal.jsonl")
    matched, mismatched = describe(entries[-2]), describe(entries[-1])
    # Then what the close's full check of the journal found
    chain = lambda n: (f" The journal's {n} {'entry' if n == 1 else 'entries'} before this one {'was' if n == 1 else 'were'} "
                       "consistent: each names the one before it. They match the head this app recorded.")
    # Then what it found of manifest.jsonl, which intake took in here without the journal
    none = " No journal entry recorded manifest.jsonl's hash."
    assert matched == "Closed the case. All 2 evidence files match the intake manifest." + chain(entries[-2]["seq"] - 1) + none
    assert mismatched == ("Closed the case. The evidence doesn't match the intake manifest: DC01/System.evtx: SHA-256 "
                          "changed. The case folder's verification.jsonl lists every problem." + chain(entries[-1]["seq"] - 1)
                          + none)
    text = markdown(entries, "Synthetic", {})
    assert matched in text and mismatched in text and '"hash_check"' not in text
    # One file, more than three problems, and a value from before the close recorded its file count
    one = {"action": "case_setting", "name": "closed", "value": {"hash_check": "ok", "evidence_files": 1}}
    assert describe(one) == "Closed the case. Its 1 evidence file matches the intake manifest."
    many = {**one, "value": {"hash_check": "mismatch", "problems": [f"f{i}: missing" for i in range(5)]}}
    assert describe(many) == ("Closed the case. The evidence doesn't match the intake manifest: f0: missing; f1: missing; "
                              "f2: missing; and more. The case folder's verification.jsonl lists every problem.")
    assert describe({**one, "value": {"hash_check": "ok"}}) == "Closed the case. The evidence matches the intake manifest."
    grown = {**one, "value": {"hash_check": "ok", "evidence_files": 1, "manifest": {"state": "grew", "seq": 4}}}
    assert describe(grown) == ("Closed the case. Its 1 evidence file matches the intake manifest. manifest.jsonl had grown "
                               "past its record in the journal, entry #4.")


def test_an_undo_of_one_event_reads_in_the_singular(synthetic_case):
    """An undo of one event reads "1 event back to how it was", not "how they were", and one event kept reads "its"
    later state, not "their"."""
    con, journal, _ = open_case(synthetic_case)
    a, b, _ = evtx_uids(con)
    journal.append("mark", targets=[a, b], value="malicious", note="")   # 2
    journal.append("mark", targets=[b], value="suspicious", note="")     # 3: b changed later
    undo(journal, 2)
    assert describe(read_entries(journal.path)[-1]) == (
        "Undo of #2: 1 event back to how it was; 1 changed since #2 kept its later state")


def test_audit_markdown_escapes_event_text(synthetic_case):
    """The trail's Markdown escapes event messages, as the findings summary does, so a viewer that renders HTML or
    links, such as VS Code's preview, doesn't show an attacker's markup and links."""
    con, journal, _ = open_case(synthetic_case)
    a = evtx_uids(con, 1)[0]
    journal.append("mark", targets=[a], value="malicious", note="see `x`")
    names = {a: "WS01 4688: <img src=//x.invalid/a.png> [click](http://x.invalid) Malicious"}
    text = markdown(read_entries(journal.path), "Case <b>", names)
    assert ("Marked WS01 4688: \\<img src=//x.invalid/a.png\\> \\[click\\](http://x.invalid) Malicious Malicious. "
            'Note: "see \\`x\\`"') in text
    assert "# Audit trail: Case \\<b\\>" in text and "<img" not in text.replace("\\<img", "")


def test_the_exported_trail_shows_bidi_controls_as_code_points(synthetic_case):
    """An event named by its message, a note, and the case's name can hold a right-to-left override, which would draw
    report[U+202E]fdp.scr as reportrcs.pdf. The trail's Markdown writes it as [U+202E], where the report does, and its
    code spans keep the code point literal."""
    rlo = "\u202e"
    con, journal, _ = open_case(synthetic_case)
    a, b, _ = evtx_uids(con)
    journal.append("mark", targets=[a], value="malicious", note=f"see report{rlo}fdp.scr")
    journal.append("mark", targets=[a, b], value="suspicious", note="")
    entries = read_entries(journal.path)
    text = markdown(entries, f"Case{rlo}", {a: f"WS01 4688: report{rlo}fdp.scr"},
                    listed={3: (2, [{"ts": None, "host": f"WS{rlo}1", "code": "4688", "uid": f"x{rlo}y"}])})
    assert rlo not in text
    assert r"# Audit trail: Case\[U+202E\]" in text
    assert r'Marked WS01 4688: report\[U+202E\]fdp.scr Malicious. Note: "see report\[U+202E\]fdp.scr"' in text
    assert r"No time recorded, WS\[U+202E\]1, 4688, ID `x[U+202E]y`" in text


def test_the_exported_trail_prints_a_character_reference_in_evidence_text_as_written(synthetic_case):
    """A Markdown reader turns &rlm; into a right-to-left mark and &lt; into <, so the trail escapes the ampersand that
    begins a named reference, as the report does. An ampersand with no reference after it stays."""
    con, journal, _ = open_case(synthetic_case)
    a, _, _ = evtx_uids(con)
    journal.append("mark", targets=[a], value="malicious", note="report&rlm;fdp.scr")
    text = markdown(read_entries(journal.path), "Case", {a: "cmd /c a && b &lt;x&gt;"})
    assert r'Marked cmd /c a && b \&lt;x\&gt; Malicious. Note: "report\&rlm;fdp.scr"' in text


def test_audit_api_undo_and_export(running):
    app, port, _ = running
    session = login(port, app)
    uids = [u for (u,) in app.con.execute("SELECT event_uid FROM events WHERE tool = 'evtxecmd' AND event_code = '4624'")
            .fetchall()]
    request(port, "POST", "/api/mark", session=session, body={"uids": uids, "value": "malicious"})
    lanes = lambda: {tuple(lane["keys"])
                     for lane in json.loads(request(port, "GET", "/api/lanes?groupby=mark", session=session)[1])["lanes"]}
    assert ("Malicious",) in lanes()
    trail = json.loads(request(port, "GET", "/api/audit", session=session)[1])
    seq = trail["rows"][0]["seq"]
    assert trail["rows"][0]["undoable"] and trail["rows"][0]["text"] == f"Marked {len(uids)} events Malicious"
    plan = json.loads(request(port, "GET", f"/api/undo_plan?seq={seq}", session=session)[1])
    assert (plan["changed"], plan["kept"]) == (len(uids), 0)
    res, body = request(port, "POST", "/api/undo", session=session, body={"seq": seq, "note": "slip"})
    assert res.status == 200 and json.loads(body)["changed"] == len(uids)
    assert ("Malicious",) not in lanes()   # the marks table follows the undo
    res, body = request(port, "POST", "/api/undo", session=session, body={"seq": seq})
    assert res.status == 400 and "already undone" in json.loads(body)["error"]
    events = json.loads(request(port, "GET", f"/api/audit_events?seq={seq}", session=session)[1])
    assert events["total"] == len(uids) and all(e["mark"] != "Malicious" for e in events["events"])
    res, body = request(port, "POST", "/api/audit_export", session=session, body={})
    path = Path(json.loads(body)["path"])
    assert path.exists() and "correction of an accident" in path.read_text(encoding="utf-8")


def test_the_exported_trail_lists_the_events_of_an_entry_of_several(synthetic_case, monkeypatch):
    """The trail's Markdown export doesn't stop at "Marked 6 events Suspicious" with none of them named: like the page,
    which lists them under the entry's "6 events", it lists them in time order, by time, host, event code, and ID, up
    to the page's limit, and says how many more there are."""
    from datetime import UTC, datetime

    from glessner import server
    from glessner.server import App, api_audit_export, api_mark

    a = App(synthetic_case)
    try:
        logons = a.con.execute("SELECT event_uid, ts_us, host FROM events WHERE tool = 'evtxecmd' AND event_code = '4624' "
                               "ORDER BY ts_us").fetchall()
        api_mark(a, {"uids": [u for u, _, _ in reversed(logons)], "value": "suspicious"})
        api_mark(a, {"uids": [logons[0][0]], "value": "malicious"})
        at = lambda us: datetime.fromtimestamp(us / 1e6, UTC).strftime("%Y-%m-%d %H:%M:%S.%f")
        export = lambda: Path(api_audit_export(a, {})["path"]).read_text(encoding="utf-8").splitlines()
        lines = export()
        i = next(n for n, line in enumerate(lines) if line.endswith(f"Marked {len(logons)} events Suspicious"))
        assert lines[i + 1:i + 1 + len(logons)] == [f"  - {at(ts)} UTC, {host}, 4624, ID `{uid}`" for uid, ts, host in logons]
        assert len(lines) == i + 2 + len(logons) and lines[-1].startswith("- **#")   # the one-event mark lists nothing
        monkeypatch.setattr(server, "LISTED_EVENTS", 2)
        lines = export()
        assert lines[i + 1:i + 4] == [f"  - {at(ts)} UTC, {host}, 4624, ID `{uid}`" for uid, ts, host in logons[:2]] + [
            f"  - and {len(logons) - 2} more"]
    finally:
        a.con.close()
