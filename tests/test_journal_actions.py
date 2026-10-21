"""The journal's analyst actions and the head on every surface: follow-up, findings, a Reject's note, the file entries and
the heads shown after them, verify --journal with --expect-head and --file, Integrity's Journal row, Continue with the
break on record, the report under app.lock, and the writes through case.write_atomically. Journals are synthetic; the
cases are conftest's."""

import json
import os
import re
import shutil
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest
from chain_fixtures import add, lines, run_checker, sha
from test_rekey_journal import evtx_uids, new_id, rekey
from test_server import login, request

from glessner import case as case_module
from glessner import heads
from glessner.audit import AuditError, describe, plan_undo, read_entries
from glessner.cli import main
from glessner.imports import save_mapping
from glessner.intake import intake
from glessner.journal import Journal, JournalError, head_of, replay
from glessner.server import (
    App,
    api_audit,
    api_audit_export,
    api_chain_break,
    api_event,
    api_export,
    api_filter,
    api_finding,
    api_followup,
    api_host,
    api_journal_check,
    api_mark,
    api_note,
    api_overview,
    api_report,
    api_suggestion,
    api_undo,
    api_undo_plan,
)
from glessner.start import remember

PRINTED = re.compile(r"Journal head when written: `([0-9a-f]{64})` \(entry #(\d+)\)")
HEAD_LINE = re.compile(r"^Head: ([0-9a-f]{64}) \(entry #(\d+)\)\.$", re.MULTILINE)
WRITES = "The journal was changed after it was written: "
END = 4_102_444_800_000_000   # 2100-01-01, in microseconds


def journal_path(case) -> Path:
    return case.folder / "journal.jsonl"


def worked(case) -> App:
    """The server's open for work; the caller closes its connection."""
    return App(case, for_work=True)


def with_evidence(case) -> None:
    """Two evidence files and the intake, so close and the report re-hash something."""
    for name in ("Security.evtx", "System.evtx"):
        (case.evidence / "DC01" / name).write_bytes(b"ElfFile\x00" + name.encode())
    intake(case)


def verify(capsys, case, *args) -> tuple[int, str]:
    code = main(["verify", str(case.folder), *args])
    return code, capsys.readouterr().out


def printed_head(path: Path) -> tuple[str, int]:
    found = PRINTED.search(path.read_text(encoding="utf-8"))
    return found.group(1), int(found.group(2))


def entry(case, seq: int) -> dict:
    return next(e for e in read_entries(journal_path(case)) if e["seq"] == seq)


# ---------- Actions: followup ----------

def test_followup_sets_clears_replays_and_undoes_keeping_a_later_change(synthetic_case):
    """Follow-up: set, clear, replay, undo with a later change kept, and the trail's words. A later mark leaves the
    tick."""
    a, b, c = evtx_uids(synthetic_case)
    app = worked(synthetic_case)
    try:
        ticked = api_followup(app, {"uids": [a, b, c], "done": True})["seq"]
        assert set(app.journal.state.followed) == {a, b, c}
        assert app.journal.state.followed[a] == {"seq": ticked, "at": entry(synthetic_case, ticked)["at"], "who": "cody"}
        api_mark(app, {"uids": [a], "value": "malicious"})
        assert a in app.journal.state.followed and api_event(app, {"uid": [a]})["event"]["followup"]["seq"] == ticked
        cleared = api_followup(app, {"uids": [b], "done": False})["seq"]
        assert set(app.journal.state.followed) == {a, c}
        assert replay(journal_path(synthetic_case)).followed == app.journal.state.followed
        assert describe(entry(synthetic_case, ticked)) == "Marked 3 events followed up"
        assert describe(entry(synthetic_case, cleared)) == "Cleared Followed up on 1 event"
        rows = api_audit(app, {"kind": ["Follow-up"]})["rows"]
        assert [(r["seq"], r["undoable"]) for r in rows] == [(cleared, True), (ticked, True)]
        # b was cleared later, so it keeps that; a mark is no follow-up change, so a and c go back to unticked
        plan = api_undo_plan(app, {"seq": [str(ticked)]})
        assert (plan["changed"], plan["kept"]) == (2, 1)
        api_undo(app, {"seq": ticked})
        assert app.journal.state.followed == {}
        assert replay(journal_path(synthetic_case)).followed == {}
        for bad in ({"uids": [a], "done": "yes"}, {"uids": [], "done": True}):
            with pytest.raises((JournalError, ValueError)):
                api_followup(app, bad)
    finally:
        app.con.close()


# ---------- Actions: finding ----------

def test_each_finding_op_replays_reads_and_is_refused_where_the_note_says(synthetic_case):
    """Findings: each op's replay and words; refusals for an unknown or retired finding; replay of an edit on a retired
    finding as written; the trail's Undo names the Findings page."""
    a, b, c = evtx_uids(synthetic_case)
    app = worked(synthetic_case)
    try:
        title = "A dropped binary installed as a service on DC01"
        fid = api_finding(app, {"op": "add", "title": title, "severity": "High", "narrative": "",
                                "techniques": ["T1543.003"], "targets": [a, b, a]})["finding"]
        found = app.journal.state.findings[fid]
        assert (found["title"], found["severity"], found["targets"], found["retired"]) == (title, "High", [a, b], None)
        edit = api_finding(app, {"op": "edit", "finding": fid, "severity": "Critical", "narrative": "Seen at 02:14."})
        link = api_finding(app, {"op": "link", "finding": fid, "targets": [c]})
        unlink = api_finding(app, {"op": "unlink", "finding": fid, "targets": [a]})
        retire = api_finding(app, {"op": "retire", "finding": fid, "reason": "A test binary."})
        found = app.journal.state.findings[fid]
        assert (found["severity"], found["targets"], found["edited"]["seq"]) == ("Critical", [b, c], edit["seq"])
        assert found["retired"]["reason"] == "A test binary."
        refusals = [({"op": "edit", "finding": fid, "title": "x"}, "Restore it first"),
                    ({"op": "link", "finding": fid, "targets": [a]}, "Restore it first"),
                    ({"op": "unlink", "finding": fid, "targets": [b]}, "Restore it first"),
                    ({"op": "retire", "finding": fid}, "retired already"),
                    ({"op": "edit", "finding": 999, "title": "x"}, "no finding #999"),
                    ({"op": "edit", "finding": True, "title": "x"}, "no finding #True"),
                    ({"op": "add", "title": "x", "severity": "Low", "techniques": ["T15"]}, "T15 isn't in ATT&CK v20.0")]
        size = journal_path(synthetic_case).stat().st_size
        for body, words in refusals:
            with pytest.raises(ValueError, match=words):
                api_finding(app, body)
        assert journal_path(synthetic_case).stat().st_size == size
        restore = api_finding(app, {"op": "restore", "finding": fid})
        assert app.journal.state.findings[fid]["retired"] is None
        with pytest.raises(ValueError, match="is not retired"):
            api_finding(app, {"op": "restore", "finding": fid})
        for bad in ({"op": "add", "title": "x", "severity": "Severe"}, {"op": "add", "title": "x" * 201, "severity": "Low"},
                    {"op": "add", "title": "x", "severity": "Low", "techniques": "T1543.003"}, {"op": "drop", "finding": fid}):
            with pytest.raises(JournalError):
                api_finding(app, bad)
        words = {e["seq"]: describe(e, lookup=None) for e in read_entries(journal_path(synthetic_case))}
        trail = {r["seq"]: r for r in api_audit(app, {"kind": ["Findings"]})["rows"]}
        assert trail[fid]["text"] == f'Added the finding "{title}" (High, T1543.003) with 2 events'
        assert trail[edit["seq"]]["text"] == f'Edited the finding "{title}": severity, narrative'
        linked = trail[link["seq"]]["text"]
        assert linked.startswith("Linked ") and linked.endswith(f'to the finding "{title}"')
        assert trail[unlink["seq"]]["text"].startswith("Unlinked ")
        assert trail[retire["seq"]]["text"] == f'Retired the finding "{title}". Reason: "A test binary."'
        assert trail[restore["seq"]]["text"] == f'Restored the finding "{title}"'
        assert words[fid].startswith("Added the finding")
        assert all(not r["undoable"] and r["panel"] == "findings" for r in trail.values())
        with pytest.raises(AuditError, match="Findings page"):
            plan_undo(read_entries(journal_path(synthetic_case)), edit["seq"])
    finally:
        app.con.close()
    # An edit on a retired finding, written by hand or by another build, is applied as written
    journal = Journal(synthetic_case)
    journal.append("finding", op="retire", finding=fid)
    journal.append("finding", op="edit", finding=fid, title="Renamed while retired")
    state = replay(journal_path(synthetic_case))
    assert state.findings[fid]["title"] == "Renamed while retired" and state.findings[fid]["retired"]
    journal.append("finding", op="edit", finding=12345, title="No such finding")   # replay ignores it
    assert 12345 not in replay(journal_path(synthetic_case)).findings


# ---------- Actions: a Reject's note ----------

def test_a_reject_s_note_is_kept_cleared_by_a_restore_and_brought_back_by_an_undo_grouped_by_note(synthetic_case):
    """A Reject's note in the entry, the trail, and the Event page; a restore clears it; an undo of the reject
    restores; an undo of the restore rejects again with the note each event's earlier rejection carried, two notes
    grouped apart, each taking the undo's seq, at, and who."""
    a, b, c, d = evtx_uids(synthetic_case, 4)
    app = worked(synthetic_case)
    source = "hayabusa"
    try:
        first = api_suggestion(app, {"decision": "reject", "source": source, "uids": [a], "note": " a test account "})
        assert first["changed"] == 1
        rejected = read_entries(journal_path(synthetic_case))[-1]
        assert rejected["note"] == "a test account"
        assert describe(rejected).endswith('. Note: "a test account"')
        assert api_event(app, {"uid": [a]})["event"]["rejection_notes"][source]["text"] == "a test account"
        api_suggestion(app, {"decision": "reject", "source": source, "uids": [b], "note": "the backup job"})
        api_suggestion(app, {"decision": "reject", "source": source, "uids": [c]})   # no note
        assert {k[0] for k in app.journal.state.decision_notes} == {a, b}
        restore = api_suggestion(app, {"decision": "restore", "source": source, "uids": [a, b, c]})
        assert restore["changed"] == 3 and app.journal.state.decision_notes == {}
        restored = read_entries(journal_path(synthetic_case))[-1]
        undo = api_undo(app, {"seq": restored["seq"]})
        written = read_entries(journal_path(synthetic_case))[-1]
        notes = sorted((c.get("note", ""), c["targets"]) for c in written["changes"])
        assert notes == [("", [c]), ("a test account", [a]), ("the backup job", [b])]
        state = app.journal.state
        assert state.decision_notes[(a, source)] == {"text": "a test account", "seq": undo["seq"], "at": written["at"],
                                                     "who": written["who"]}
        assert state.decision_notes[(b, source)]["text"] == "the backup job" and (c, source) not in state.decision_notes
        # An undo of a reject restores, which clears its note
        again = api_suggestion(app, {"decision": "reject", "source": source, "uids": [d], "note": "noise"})
        assert again["changed"] == 1 and app.journal.state.decision_notes[(d, source)]["text"] == "noise"
        api_undo(app, {"seq": read_entries(journal_path(synthetic_case))[-1]["seq"]})
        assert (d, source) not in app.journal.state.decision_notes and (d, source) not in app.journal.state.rejected
    finally:
        app.con.close()


# ---------- Actions: file_written, and the heads shown after each ----------

def file_sha(path: Path) -> str:
    return sha(path.read_bytes())


def test_each_writer_records_its_file_and_answers_with_the_head_after_it(synthetic_case, capsys):
    """file_written: a timeline export from the page and the command line, for each scope, with and without filters; the
    report; the audit trail export: sha256 and bytes match the file, rows match, the path is relative; the summary's
    printed head is a chained line before its entry, and its replay gives what the summary prints; each answer's head
    is the head after the entry; verify --file finds the file with that head."""
    a, _, _ = evtx_uids(synthetic_case)
    app = worked(synthetic_case)
    try:
        api_mark(app, {"uids": [a], "value": "malicious"})
        api_note(app, {"uid": a, "text": "first look"})
        fid = api_filter(app, {"hide": [{"host": "DESKTOP"}]})["id"]
        answers = [("timeline", api_export(app, {"start": 0, "end": END, "format": "csv", "marks": marks}))
                   for marks in ("all", "marked", "flagged")]
        answers.append(("timeline", api_export(app, {"start": 0, "end": END, "format": "jsonl", "marks": "all",
                                                     "filter": fid})))
        answers.append(("report", api_report(app, {})))
        answers.append(("audit_trail", api_audit_export(app, {})))
        for kind, res in answers:
            path = Path(res["path"])
            written = entry(synthetic_case, res["head_seq"])
            assert written["action"] == "file_written" and written["kind"] == kind
            assert written["path"] == path.relative_to(synthetic_case.folder).as_posix() and "\\" not in written["path"]
            assert (written["sha256"], written["bytes"]) == (file_sha(path), path.stat().st_size)
            assert res["head"] == head_of(written) and res["head_short"] == f"{res['head'][:8]}...{res['head'][-4:]}"
            assert written["rows"] == res.get("rows", res.get("events", res.get("entries")))
        assert answers[-1][1]["head"] == heads.read(synthetic_case.folder)["head"]   # the record moves with each entry
        timeline = entry(synthetic_case, answers[0][1]["head_seq"])
        assert timeline["scope"] == {"marks": "all", "start": 0, "end": END} and timeline["filters"] is None
        assert "journal_head" not in timeline   # a timeline export reads without the lock, so it prints no head
        filtered = entry(synthetic_case, answers[3][1]["head_seq"])
        assert filtered["filters"]["text"] == answers[3][1]["filter"] and filtered["format"] == "jsonl"
        summary_res = answers[4][1]
        summary = Path(summary_res["path"])
        written = entry(synthetic_case, summary_res["head_seq"])
        head, seq = printed_head(summary)
        assert (written["journal_head"], written["head_seq"]) == (head, seq) and seq < written["seq"]
        chain = lines(journal_path(synthetic_case).read_bytes())
        assert sha(chain[seq - 1]) == head   # a chained line before the summary's entry
        # Replaying to the printed head gives the marks and notes the summary prints
        state = replay_to(journal_path(synthetic_case), seq)
        assert {u for u, m in state.marks.items() if m.value == "malicious"} == {a}
        assert [n["text"] for n in state.notes[a]] == ["first look"] and "first look" in summary.read_text(encoding="utf-8")
        assert "Journal: " in summary.read_text(encoding="utf-8") and "consistent: each names the one before it." in \
            summary.read_text(encoding="utf-8")
        trail = Path(answers[5][1]["path"]).read_text(encoding="utf-8")
        audit_entry = entry(synthetic_case, answers[5][1]["head_seq"])
        assert f"from the journal whose head is {audit_entry['journal_head']} (entry #{audit_entry['head_seq']})" in trail
        assert describe(audit_entry).startswith(f"Wrote {Path(answers[5][1]['path']).name}: audit trail, whole case, ")
        assert describe(timeline).startswith(f"Wrote {Path(answers[0][1]['path']).name}: timeline, all events from ")
    finally:
        app.con.close()
    # The command line's export and findings record theirs and print the head after the entry, in full
    assert main(["export", str(synthetic_case.folder), "--marks", "flagged"]) == 0
    out = capsys.readouterr().out
    last = read_entries(journal_path(synthetic_case))[-1]
    assert last["action"] == "file_written" and last["kind"] == "timeline" and last["scope"]["marks"] == "flagged"
    assert (f"Journal head after recording this file: {head_of(last)} (entry #{last['seq']}). Record it with the file "
            "to check the file later.") in out
    assert main(["findings", str(synthetic_case.folder)]) == 0
    out = capsys.readouterr().out
    last = read_entries(journal_path(synthetic_case))[-1]
    assert last["kind"] == "report" and f"{head_of(last)} (entry #{last['seq']})" in out
    report = synthetic_case.folder / last["path"]
    code, said = verify(capsys, synthetic_case, "--journal", "--expect-head", head_of(last), "--file", str(report))
    assert code == 0 and f"Entry #{last['seq']} records this file, at or before the expected head" in said, said
    assert "recorded as written by cody with " in said and ": report, whole case, 1 event." in said
    changed = report.with_name("changed.md")
    changed.write_bytes(report.read_bytes() + b" ")
    code, said = verify(capsys, synthetic_case, "--journal", "--expect-head", head_of(last), "--file", str(changed))
    assert code == 1 and "No entry in this journal has this file's SHA-256" in said
    converted = report.with_name("converted.md")
    data = report.read_bytes()
    converted.write_bytes(data.replace(b"\r\n", b"\n") if b"\r\n" in data else data.replace(b"\n", b"\r\n"))
    code, said = verify(capsys, synthetic_case, "--journal", "--expect-head", head_of(last), "--file", str(converted))
    assert code == 1 and f"With its line endings converted back, it matches entry #{last['seq']}." in said


def test_a_file_entry_names_its_file_inside_the_case_folder():
    from glessner.journal import _validate

    good = {"path": "exports/a.csv", "kind": "timeline", "format": "csv", "rows": 1, "bytes": 2, "sha256": "0" * 64}
    _validate("file_written", good)
    for path in ("exports\\a.csv", "/exports/a.csv", "C:/a.csv", "../a.csv", ""):
        with pytest.raises(JournalError):
            _validate("file_written", {**good, "path": path})
    with pytest.raises(JournalError):
        _validate("file_written", {**good, "journal_head": "0" * 64})   # without its head_seq


# ---------- Tamper: a forged file record ----------

def forged(case, summary: Path, after: bytes) -> tuple[bytes, Path]:
    """`after`, journal bytes, with a correctly chained file_written entry for a changed copy of the summary appended,
    as anyone who can write the case folder could append one: prev, journal_head, and who as the app sets them. The
    genuine entry is read from the journal as it stands."""
    copy = summary.with_name("changed.md")
    copy.write_bytes(summary.read_bytes().replace(b"# Report", b"# Reprot"))
    genuine = next(e for e in read_entries(journal_path(case)) if e.get("action") == "file_written"
                   and e.get("kind") == "report")
    payload = {k: genuine[k] for k in ("path", "kind", "format", "scope", "filters", "rows")}
    payload.update(bytes=copy.stat().st_size, sha256=file_sha(copy), journal_head=genuine["journal_head"],
                   head_seq=genuine["head_seq"])
    return add(after, "file_written", client="server", **payload), copy


def test_a_forged_file_record_after_a_head_kept_outside_the_case_counts_for_nothing(synthetic_case, capsys):
    """A forged file record, in its four cases, in verify and the checker."""
    with_evidence(synthetic_case)
    a, _, _ = evtx_uids(synthetic_case)
    app = worked(synthetic_case)
    try:
        api_mark(app, {"uids": [a], "value": "malicious"})
        res = api_report(app, {})
    finally:
        app.con.close()
    summary, after_entry = Path(res["path"]), res["head"]
    printed, _ = printed_head(summary)
    assert main(["close", str(synthetic_case.folder)]) == 0
    closed = re.search(r"Journal head after this close: ([0-9a-f]{64}) \(entry #(\d+)\)", capsys.readouterr().out)
    h = closed.group(1)
    path = journal_path(synthetic_case)
    genuine = path.read_bytes()
    assert sha(lines(genuine)[-1]) == h

    def both(head, file, code, words):
        args = ["--journal", *(["--expect-head", head] if head else []), "--file", str(file)]
        found, said = verify(capsys, synthetic_case, *args)
        assert found == code and words in said, (args, said)
        if head:
            assert run_checker(path, head, "--file", str(file))[0] == code

    # First: the forged entry follows H, so H doesn't vouch for it; the genuine summary still passes against H
    data, changed = forged(synthetic_case, summary, genuine)
    path.write_bytes(data)
    both(h, changed, 1, "but it follows the expected head")
    both(h, summary, 0, "at or before the expected head")
    # Fourth: no --expect-head on the machine that wrote the case: the head record is H, which the entry follows
    both(None, changed, 1, "but it follows the head this computer recorded")
    # Second: the journal cut back to the head the summary prints, and the forged entry appended there
    cut = b"".join(line + b"\n" for line in lines(genuine)[:next(i for i, line in enumerate(lines(genuine), 1)
                                                                 if sha(line) == printed)])
    path.write_bytes(genuine)
    data_cut = forged(synthetic_case, summary, cut)[0]
    path.write_bytes(data_cut)
    both(printed, changed, 1, "but it follows the expected head")
    both(after_entry, changed, 1, "the expected head is no entry of this journal")
    # Third: the genuine summary against the head it prints itself fails, and against the head shown after it passes
    path.write_bytes(genuine)
    both(printed, summary, 1, "but it follows the expected head")
    both(after_entry, summary, 0, "at or before the expected head")
    # Fourth, after the app opens the case again: Integrity names the entry as written without updating the record
    path.write_bytes(data)
    app = worked(synthetic_case)
    try:
        row = api_overview(app, {})["integrity"]["journal"]
    finally:
        app.con.close()
    assert row["state"] == "consistent" and any(
        "The 1 entry after it was written without updating that record: 1 file record." in t for t in row["text"]), row


# ---------- Torn: verify writes nothing ----------

def listing(folder: Path) -> dict[str, tuple[int, int]]:
    return {str(p.relative_to(folder)): (p.stat().st_size, p.stat().st_mtime_ns) for p in sorted(folder.rglob("*"))
            if p.is_file()}


def test_verify_journal_writes_nothing_even_on_a_read_only_copy(synthetic_case, tmp_path, capsys):
    """verify writes nothing: verify --journal on a torn journal reports it and exits 1; the file's bytes and time and
    the folder's listing are as they were, with no journal.lock created; it also runs on a read-only copy."""
    app = worked(synthetic_case)
    app.con.close()
    copy = tmp_path / "copy"
    shutil.copytree(synthetic_case.folder, copy)
    (copy / "journal.lock").unlink()
    with (copy / "journal.jsonl").open("ab") as f:
        f.write(b'{"seq": 99, "prev": "ab')
    for p in copy.rglob("*"):
        if p.is_file():
            p.chmod(stat.S_IREAD)
    before = listing(copy)
    try:
        code = main(["verify", str(copy), "--journal"])
        out = capsys.readouterr().out
        assert code == 1 and "bytes after the last whole line, most likely a write a crash cut short" in out, out
        assert listing(copy) == before and not (copy / "journal.lock").exists()
    finally:
        for p in copy.rglob("*"):
            if p.is_file():
                p.chmod(stat.S_IREAD | stat.S_IWRITE)


def test_verify_says_a_case_below_format_3_has_no_chain_yet(synthetic_case, capsys):
    """verify on a case below format 3 reports the evidence as usual and says the journal has no chain until the
    upgrade, with the evidence's exit; verify --journal exits 1 with the same sentence."""
    from chain_fixtures import as_format, note, unchained

    with_evidence(synthetic_case)
    as_format(synthetic_case.folder, 2, unchained(note(1)))
    code, out = verify(capsys, synthetic_case)
    assert code == 0 and "All evidence files match the manifest." in out and "no hash chain yet: this case is format 2" in out
    code, out = verify(capsys, synthetic_case, "--journal")
    assert code == 1 and "no hash chain yet" in out
    assert case_module.open_case(synthetic_case.folder).settings.case_format == 2   # verify upgraded nothing


def test_verify_journal_says_consistent_and_where_each_head_is(synthetic_case, capsys):
    """Checking a copy: the words for a consistent chain with and without an expected head, and with the head this
    computer recorded; a head that isn't 64 hex characters is refused before anything is read."""
    a, _, _ = evtx_uids(synthetic_case)
    app = worked(synthetic_case)
    try:
        early = app.journal.chain.head
        api_mark(app, {"uids": [a], "value": "malicious"})
        api_note(app, {"uid": a, "text": "x"})
    finally:
        app.con.close()
    seq = next(e["seq"] for e in read_entries(journal_path(synthetic_case)) if head_of(e) == early)
    code, out = verify(capsys, synthetic_case, "--journal", "--expect-head", early.upper())
    assert code == 0 and f"Consistent, and the expected head is entry #{seq}; 2 entries follow it: 1 mark, 1 note." in out
    code, out = verify(capsys, synthetic_case, "--journal")
    total = len(read_entries(journal_path(synthetic_case)))
    assert code == 0 and f"Consistent: each of the {total} entries names the one before it." in out
    assert f"The head this computer recorded is entry #{total}, the newest." in out
    heads.forget(synthetic_case.folder)
    code, out = verify(capsys, synthetic_case, "--journal")
    assert "No expected head given, so removed newest entries or a rewritten journal wouldn't show." in out
    assert main(["verify", str(synthetic_case.folder), "--journal", "--expect-head", "abc"]) == 2


def test_verify_names_bytes_after_the_last_line_while_the_lock_is_held_and_exits_1(synthetic_case, capsys):
    """With journal.lock held, bytes after the last line are not called a write in progress: verify doesn't say
    Consistent, exit 0, beside garbage. It says what it found and can't vouch for, and exits 1."""
    with Journal(synthetic_case).held():
        with journal_path(synthetic_case).open("ab") as f:
            f.write(b'{"seq": 99, "prev": "garbage')
        code, out = verify(capsys, synthetic_case, "--journal")
    assert code == 1 and "28 bytes follow the last line while another process holds journal.lock" in out, out
    assert "Consistent" not in out
    code, out = verify(capsys, synthetic_case, "--journal")   # the lock free: the bytes are a torn line
    assert code == 1 and "bytes after the last whole line, most likely a write a crash cut short" in out


def test_verify_says_which_entries_are_from_before_the_chain(synthetic_case, capsys):
    """On an upgraded case verify says each entry names the one before it and which entries are from before the chain,
    the first ones being sealed unchained lines; the sentence Integrity gives follows."""
    from chain_fixtures import MARKS, chained, note, unchained

    journal_path(synthetic_case).write_bytes(chained(MARKS, before=unchained(note(1), note(2))))
    heads.forget(synthetic_case.folder)
    code, out = verify(capsys, synthetic_case, "--journal")
    assert code == 0 and "Consistent: each of the 7 entries names the one before it." in out
    assert "Entries #1 to #2 are from before the chain, sealed by #3." in out


def test_verify_file_that_does_not_exist_is_an_error_not_a_traceback(synthetic_case, tmp_path, capsys):
    """A missing --file is exit 2, with the file named, before any evidence is re-hashed. Exit 1 is for a file the
    journal doesn't cover."""
    assert main(["verify", str(synthetic_case.folder), "--journal", "--file", str(tmp_path / "nowhere.md")]) == 2
    assert "nowhere.md is not a file this command can read" in capsys.readouterr().err


def test_a_file_stays_when_its_entry_was_written_even_though_the_append_failed_after(synthetic_case, monkeypatch):
    """record_file keeps the file when the journal grew, also when the append raised after the entry was fsynced, since
    deleting it would leave a record of a file that is gone. A refused entry that wrote nothing still removes it."""
    from glessner.export import record_file

    path = synthetic_case.folder / "exports" / "x.csv"
    path.parent.mkdir(exist_ok=True)
    payload = {"path": "exports/x.csv", "kind": "timeline", "format": "csv", "rows": 0, "bytes": 1, "sha256": sha(b"x")}
    journal = Journal(synthetic_case)
    path.write_bytes(b"x")
    monkeypatch.setattr(Journal, "_record_head", lambda self: (_ for _ in ()).throw(RuntimeError("after the write")))
    with pytest.raises(RuntimeError):
        record_file(journal, payload, path)
    assert path.exists() and read_entries(journal_path(synthetic_case))[-1]["action"] == "file_written"
    monkeypatch.undo()
    path.unlink()
    path.write_bytes(b"x")
    journal_path(synthetic_case).write_bytes(journal_path(synthetic_case).read_bytes().replace(b'"seq": 1,', b'"seq":  1,', 1))
    refusing = Journal(synthetic_case)
    with pytest.raises(JournalError):
        record_file(refusing, payload, path)
    assert not path.exists()


# ---------- Head: printed heads ----------

def test_every_printed_head_is_verify_s_at_that_point(synthetic_case, capsys):
    """Printed heads: the close's, the summary's, the audit export's, Integrity's, and the head record's heads each
    equal verify's at that point."""
    with_evidence(synthetic_case)

    def verified() -> str:
        code, out = verify(capsys, synthetic_case, "--journal")
        assert code == 0, out
        return HEAD_LINE.search(out).group(1)

    app = worked(synthetic_case)
    try:
        assert api_overview(app, {})["integrity"]["journal"]["head"] == verified() == heads.read(synthetic_case.folder)["head"]
        assert api_report(app, {})["head"] == verified()
        assert api_audit_export(app, {})["head"] == verified()
        assert api_journal_check(app, {})["journal"]["head"] == verified()
        assert api_overview(app, {})["integrity"]["journal"]["head"] == verified()
    finally:
        app.con.close()
    assert main(["close", str(synthetic_case.folder)]) == 0
    closed = re.search(r"Journal head after this close: ([0-9a-f]{64})", capsys.readouterr().out).group(1)
    assert closed == verified() == heads.read(synthetic_case.folder)["head"]
    value = read_entries(journal_path(synthetic_case))[-1]["value"]
    assert (value["chain"], value["head_record"]) == ("consistent", "matched")
    assert value["journal_entries"] == len(read_entries(journal_path(synthetic_case))) - 1


# ---------- Integrity, Check now, and Continue with the break on record ----------

def test_check_now_finds_an_edit_made_while_the_app_runs_and_continue_puts_it_on_record(synthetic_case):
    """Undo after an edit: an older line edited while the server runs: the audit trail reports the break and the undo
    is refused. Check now finds it too, the header says "Journal changed", and Continue with the break on record seals
    it, after which the case takes changes again, and the row says "consistent since"."""
    a, b, _ = evtx_uids(synthetic_case)
    app = worked(synthetic_case)
    try:
        marked = api_mark(app, {"uids": [a], "value": "suspicious"})["seq"]
        api_note(app, {"uid": a, "text": "first look"})
        api_mark(app, {"uids": [b], "value": "authorized"})
        assert api_overview(app, {})["integrity"]["journal"]["state"] == "consistent"
        path = journal_path(synthetic_case)
        path.write_bytes(path.read_bytes().replace(b"first look", b"first lock"))
        trail = api_audit(app, {})
        assert trail["journal"]["state"] == "broken" and trail["journal"]["text"][0].startswith(
            f"{len(read_entries(path))} entries. The journal was changed after it was written: line ")
        with pytest.raises(JournalError, match=WRITES):
            api_undo_plan(app, {"seq": [str(marked)]})
        with pytest.raises(JournalError, match=WRITES):
            api_undo(app, {"seq": marked})
        state = api_journal_check(app, {})["state"]
        assert state["broken"] and state["can_continue"] and state["read_only"].startswith(WRITES)
        with pytest.raises(JournalError, match="needs a reason"):
            api_chain_break(app, {"reason": "  "})
        done = api_chain_break(app, {"reason": "A test edit."})
        assert not done["state"]["broken"]
        row = api_overview(app, {})["integrity"]["journal"]
        assert row["state"] == "on_record" and row["text"][0].endswith(
            f"consistent since #{done['seq']}: each names the one before it, and the break before #{done['seq']} is "
            "on record.")
        assert api_mark(app, {"uids": [a], "value": "malicious"})["seq"] == done["seq"] + 1
        assert describe(entry(synthetic_case, done["seq"])).startswith("Continued with the journal changed at line ")
    finally:
        app.con.close()


def test_continue_with_the_break_on_record_holds_the_lock(synthetic_case, monkeypatch):
    """Continue with the break on record writes under app.lock, then the journal's held context, as every other writer
    does (the lock test in test_server.py finds it by reading server.py)."""
    app = worked(synthetic_case)
    try:
        path = journal_path(synthetic_case)
        data = lines(path.read_bytes())
        data[1] = data[1].replace(b'"seq": 2', b'"seq":  2')
        path.write_bytes(b"".join(line + b"\n" for line in data))
        api_journal_check(app, {})
        real, unlocked = app.journal.record_break, []

        def record_break(reason, who=None):
            def probe():
                if app.lock.acquire(blocking=False):
                    app.lock.release()
                    unlocked.append(reason)
            thread = threading.Thread(target=probe)
            thread.start()
            thread.join()
            return real(reason, who)

        monkeypatch.setattr(app.journal, "record_break", record_break)
        api_chain_break(app, {"reason": "checked"})
        assert unlocked == [] and read_entries(path)[-1]["action"] == "chain_break"
    finally:
        app.con.close()


def test_an_export_on_a_broken_chain_is_refused_before_its_file_is_written(synthetic_case, monkeypatch):
    """On a break each export is refused before it writes anything, not written and then removed when its file entry is
    refused, so no file is ever there without its record."""
    from glessner import server as server_module

    app = worked(synthetic_case)
    try:
        path = journal_path(synthetic_case)
        path.write_bytes(path.read_bytes().replace(b'"seq": 2', b'"seq":  2', 1))
        api_journal_check(app, {})

        def wrote(*_args, **_kwargs):
            raise AssertionError("an export began writing on a broken chain")

        for name in ("export_timeline", "write_report", "export_path"):
            monkeypatch.setattr(server_module, name, wrote)
        for route, body in ((api_export, {"start": 0, "end": END, "format": "csv", "marks": "all"}),
                            (api_report, {}), (api_audit_export, {})):
            with pytest.raises(JournalError, match=WRITES):
                route(app, body)
    finally:
        app.con.close()


def test_the_header_says_journal_changed_only_on_a_break(synthetic_case):
    app = worked(synthetic_case)
    app.con.close()
    for app, port, _ in __import__("conftest").serving(synthetic_case):
        cookie = login(port, app)
        state = json.loads(request(port, "GET", "/api/case_state", cookie=cookie)[1])
        assert state["journal"]["broken"] is False and state["journal"]["seq"] == app.journal.chain.seq
        path = journal_path(synthetic_case)
        data = lines(path.read_bytes())
        data[1] = data[1].replace(b'"seq": 2', b'"seq":  2')
        path.write_bytes(b"".join(line + b"\n" for line in data))
        assert request(port, "POST", "/api/journal_check", cookie=cookie, body={})[0].status == 200
        state = json.loads(request(port, "GET", "/api/case_state", cookie=cookie)[1])
        assert state["journal"]["broken"] is True and state["journal"]["read_only"].startswith(WRITES)
        res, body = request(port, "POST", "/api/followup", cookie=cookie, body={"uids": ["a" * 32], "done": True})
        assert res.status == 400 and json.loads(body)["error"].startswith(WRITES)


# ---------- Remap: followup and a finding link through a chained rekey ----------

def test_a_followup_and_a_finding_link_read_through_a_chained_rekey(synthetic_case):
    """ID_FIELDS: a followup and a finding's link on an event before a synthetic chained rekey read the new ID in
    replay and the trail."""
    x, _, _ = evtx_uids(synthetic_case)
    y = new_id("y")
    journal = Journal(synthetic_case)
    ticked = journal.append("followup", targets=[x], done=True)["seq"]
    fid = journal.append("finding", op="add", title="Lateral movement", severity="Medium", targets=[])["seq"]
    linked = journal.append("finding", op="link", finding=fid, targets=[x])["seq"]
    rekey(synthetic_case, journal, {x: y})
    state = replay(journal_path(synthetic_case))
    assert set(state.followed) == {y} and state.findings[fid]["targets"] == [y]
    app = App(synthetic_case)
    try:
        assert {r["seq"] for r in api_audit(app, {"event": [y]})["rows"]} >= {ticked, linked}
    finally:
        app.con.close()


# ---------- Concurrency: the report under app.lock ----------

def test_a_mark_made_during_the_summary_s_re_hash_follows_its_head(synthetic_case, monkeypatch):
    """Report and marks: a mark sent during the report's evidence re-hash waits for it; the summary's head, its listed
    events, and its notes agree, and the mark's entry follows the head."""
    from glessner import export as export_module

    with_evidence(synthetic_case)
    a, b, _ = evtx_uids(synthetic_case)
    app = worked(synthetic_case)
    real, answers = export_module.check_files, {}

    def slow(case, **kw):
        thread = threading.Thread(target=lambda: answers.update(mark=api_mark(app, {"uids": [b], "value": "malicious"})))
        thread.start()
        thread.join(0.5)
        answers["waited"] = thread.is_alive()
        answers["thread"] = thread
        return real(case, **kw)

    try:
        api_mark(app, {"uids": [a], "value": "malicious"})
        monkeypatch.setattr(export_module, "check_files", slow)
        res = api_report(app, {})
        answers["thread"].join(10)
        _, seq = printed_head(Path(res["path"]))
        text = Path(res["path"]).read_text(encoding="utf-8")
        assert answers["waited"] and answers["mark"]["seq"] > res["head_seq"] > seq
        at_head = replay_to(journal_path(synthetic_case), seq)
        flagged = {u for u, m in at_head.marks.items() if m.value == "malicious"}
        assert flagged == {a} and b not in text and a in text
    finally:
        app.con.close()


def replay_to(path: Path, seq: int):
    """The state the journal held at entry `seq`, by replaying its lines up to that one."""
    from glessner.journal import State, _apply

    state = State()
    for e in read_entries(path):
        if e["seq"] > seq:
            break
        _apply(state, e)
    return state


def test_host_edits_sent_while_the_lock_is_held_land_before_or_after_the_summary_never_inside(synthetic_case):
    """Report and host edits: a host offset, a role, and an added name, each sent while another request holds app.lock,
    then a report: replaying the journal to the report's printed head gives the role, names, and offset its Hosts
    table prints."""
    app = worked(synthetic_case)
    try:
        threads = []
        with app.lock:
            for body in ({"host": "DC01", "offset_seconds": 5}, {"host": "DC01", "role": "Servers"},
                         {"host": "DC01", "op": "add_name", "value": "DC-ONE"}):
                threads.append(threading.Thread(target=api_host, args=(app, body)))
                threads[-1].start()
            time.sleep(0.3)
            assert all(t.is_alive() for t in threads)
        for t in threads:
            t.join(10)
        res = api_report(app, {})
        _, seq = printed_head(Path(res["path"]))
        host = replay_to(journal_path(synthetic_case), seq).hosts["DC01"]
        row = next(line for line in Path(res["path"]).read_text(encoding="utf-8").splitlines()
                   if line.startswith("| DC01 |"))
        assert (host.role, host.offset_seconds, "DC-ONE" in host.add_names) == ("Servers", 5.0, True)
        assert "| Servers |" in row and "DC-ONE" in row and row.endswith("| +5 s |")
    finally:
        app.con.close()


# ---------- Atomic writes ----------

def test_the_manifest_keeps_its_bytes_ends_its_lines_in_lf_and_survives_a_refused_replace(synthetic_case, monkeypatch):
    """Manifest: intake --add keeps the earlier manifest's bytes and writes LF lines; a replace refused once succeeds on
    the retry, and one always refused leaves the old manifest and no temporary file."""
    with_evidence(synthetic_case)
    manifest = synthetic_case.manifest_path
    before = manifest.read_bytes()
    (synthetic_case.evidence / "DC01" / "Added.evtx").write_bytes(b"ElfFile\x00added")
    real, refused = os.replace, []

    def once(src, dst):
        if not refused:
            refused.append(dst)
            raise PermissionError(13, "in use")
        return real(src, dst)

    monkeypatch.setattr(os, "replace", once)
    monkeypatch.setattr(case_module, "REPLACE_WAIT", 0.01)
    from glessner.intake import add_new

    add_new(synthetic_case)
    after = manifest.read_bytes()
    assert refused and after.startswith(before) and len(after) > len(before) and b"\r\n" not in after
    (synthetic_case.evidence / "DC01" / "More.evtx").write_bytes(b"ElfFile\x00more")
    monkeypatch.setattr(os, "replace", lambda src, dst: (_ for _ in ()).throw(PermissionError(13, "in use")))
    with pytest.raises(PermissionError):
        add_new(synthetic_case)
    assert manifest.read_bytes() == after and not list(manifest.parent.glob("manifest.jsonl*.tmp"))


REMEMBER = """
import json, sys, types
from pathlib import Path
from glessner.start import config_dir, remember
name, folder = sys.argv[1], Path(sys.argv[2])
case = types.SimpleNamespace(folder=folder, settings=types.SimpleNamespace(name=name, evidence_path="e", tools_folder=""))
done = 0
for i in range(int(sys.argv[3])):
    try:
        remember(case, i)
        done += 1
    except PermissionError:   # Windows refuses a read or a replace while the other process has the file: a missed update
        pass
    while True:
        try:
            text = (config_dir() / "recent.json").read_text(encoding="utf-8")
        except PermissionError:   # Windows refuses an open while another process replaces the file; load_recent skips it
            continue
        json.loads(text)   # whole, never cut short
        break
print(done)
"""


def test_two_processes_remember_cases_at_once_without_losing_the_file(tmp_path):
    """Recent cases: two processes call remember at once; every read of recent.json parses,
    and neither raises FileNotFoundError, since each names its temporary file with its process and thread IDs
    (shared=True). Windows refuses a read or a replace while the other process has the file, and write_atomically tries
    a refused replace for about 1 s and then raises PermissionError: the list accepts a lost update, so a process may
    miss some. Each makes at least one, and a missed one never empties the list: the entry seeded before survives."""
    config = tmp_path / "config"
    config.mkdir()
    seed = {"folder": str(tmp_path / "seed"), "name": "seed", "events": 0, "evidence": "e", "tools_folder": "",
            "opened_utc": "2026-10-18T00:00:00Z"}
    (config / "recent.json").write_text(json.dumps([seed]), encoding="utf-8")
    env = {**os.environ, "GLESSNER_CONFIG_DIR": str(config)}
    procs = [subprocess.Popen([sys.executable, "-c", REMEMBER, name, str(tmp_path / name), "150"], env=env,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for name in ("one", "two")]
    results = [p.communicate(timeout=120) for p in procs]
    assert [p.returncode for p in procs] == [0, 0], results
    assert all(int(out) >= 1 for out, _ in results), results
    names = {r["name"] for r in json.loads((config / "recent.json").read_text(encoding="utf-8"))}
    assert "seed" in names and names <= {"seed", "one", "two"}
    assert not list(config.glob("*.tmp"))


def test_each_temporary_file_write_reaches_the_disk_before_it_takes_its_name(synthetic_case, tmp_path, monkeypatch):
    """save_mapping, remember, the manifest, and the head record each fsync before they replace, checked with a
    patched os.fsync."""
    order = []
    real_fsync, real_replace = os.fsync, os.replace
    names = {}

    def fsync(fd):
        order.append(("fsync", fd))
        return real_fsync(fd)

    def replace(src, dst):
        order.append(("replace", Path(dst).name))
        return real_replace(src, dst)

    with_evidence(synthetic_case)
    (synthetic_case.evidence / "DC01" / "Added.evtx").write_bytes(b"ElfFile\x00added")
    (synthetic_case.evidence / "DC01" / "logons.csv").write_text("TimeGenerated,Account\n2024-02-13 22:00:00,alice\n",
                                                                 newline="\n")
    monkeypatch.setattr(os, "fsync", fsync)
    monkeypatch.setattr(os, "replace", replace)
    from glessner.imports import guess_mapping, sniff
    from glessner.intake import add_new

    add_new(synthetic_case)   # the manifest, which then lists the CSV the mapping is for
    mapping = guess_mapping(sniff(synthetic_case, "DC01/logons.csv"))
    mapping["time"]["zone"] = "UTC"
    names["mapping"] = save_mapping(synthetic_case, "my-mapping", mapping) + ".json"
    remember(synthetic_case, 3)
    heads.write(synthetic_case.folder, 1, "0" * 64, "test")
    names.update(recent="recent.json", manifest="manifest.jsonl", head=heads.path_for(synthetic_case.folder).name)
    for what, name in names.items():
        at = order.index(("replace", name))
        assert at > 0 and order[at - 1][0] == "fsync", (what, order)
