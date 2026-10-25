"""Case format 4 and its upgrade: the 3 to 4 step, which writes one chained case_upgrade entry and changes nothing else;
a case whose journal is read-only, which stays at format 3 and opens read-only; a crash in the step; a copy's journal
order; the serve command's lines; close beside a running server; and the rekey rule a format 4 journal keeps. The format
3 step's tests are test_format3.py's."""

import hashlib
import json
import os
import runpy
import subprocess
import sys
from dataclasses import replace

import pytest
import yaml
from chain_fixtures import (
    BUILD,
    CHECKER,
    OTHER,
    UID,
    add,
    as_format,
    chained,
    created,
    envelope,
    format3_case,
    last_seq,
    note,
    run_checker,
    unchained,
    worked_at_format_3,
)
from conftest import junction
from test_format3 import (
    builtin_rules,
    cut_before_its_lf,
    entries_of,
    format2,
    journal_path,
    listing,
    opened,
    settings_of,
    tamper_cases,
    tampered,
    wait,
)
from test_found_output_sources import (
    EVE_A,
    EVE_B,
    link_evidence,
    linked_evidence_case,
    loaded_under_the_written_root,
    write_eve,
)
from test_rekey import HOLD, found_eve_case

from glessner import case as case_module
from glessner import heads
from glessner import rekey as rekey_module
from glessner.case import CASE_FORMAT, Case, CaseError, open_case
from glessner.cli import main
from glessner.events import connect
from glessner.intake import intake
from glessner.journal import (
    ENVELOPE,
    SYSTEM,
    ZERO,
    Journal,
    JournalError,
    check,
    last_action,
    line_bytes,
    parse_line,
    replay,
    start_chain,
)
from glessner.overview import AFTER_HEAD_WORDS, journal_row
from glessner.rekey import FORMAT_4_TEXT, upgraded
from glessner.runner import _write_record, load_found_output, read_runs, rebuild
from glessner.server import App
from glessner.start import start_copy
from glessner.version import build_id

CHECKED = "2026-10-22T09:00:00Z"
UPGRADES_IT = "It is at case format 3, from an earlier build, so this open upgrades it to format 4 first."
NOW_4 = "It is now at case format 4, which older builds can't open."
KEPT_3 = "Its journal is read-only, so it stays at case format 3 and opens read-only; the Case overview says why."
NO_CHAIN = ("missing chain", "empty")   # the journals with no chained line, which Continue can't put on record


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def steps_to_4(case: Case) -> list[dict]:
    """The chained case_upgrade entries from format 3 to 4, by the rule every reader parses a line with, so a line a
    tamper case left unreadable is skipped."""
    found = (parse_line(line) for line in journal_path(case).read_bytes().split(b"\n"))
    return [e for e in found if e is not None and "prev" in e and e.get("action") == "case_upgrade"
            and (e.get("from_format"), e.get("to_format")) == (3, 4)]


def written_after(case: Case, before: bytes) -> list[dict]:
    after = journal_path(case).read_bytes()
    assert after.startswith(before)
    return [json.loads(line) for line in after[len(before):].split(b"\n")[:-1]]


def open_reason(case: Case) -> str:
    """Why an open for work of a format 3 build, which upgrades nothing, finds the journal read-only."""
    journal = Journal(open_case(case.folder), "server")
    journal.open_for_work()
    return journal.read_only


@pytest.mark.parametrize("route", ["the server's open", "upgraded"])
def test_a_case_whose_journal_is_read_only_stays_at_format_3(synthetic_case, route):
    """Each tamper case on a format 3 case with an events database, and a journal with no chain: the server's open and
    the command line's upgrade leave case.yaml at 3, the journal's bytes and the folder's listing as they were, and the
    read-only reason the same as a format 3 build's open gives. A journal with no chained line offers no Continue. For
    the others, Continue writes its chain_break, and the next open reaches format 4."""
    case = format3_case(synthetic_case)
    data = worked_at_format_3(case)
    record = heads.path_for(case.folder).read_bytes()
    settings = (case.folder / "case.yaml").read_bytes()
    journals = {**tamper_cases(data), "missing chain": unchained(note(1), note(2, OTHER))}
    for name, changed in journals.items():
        (case.folder / "case.yaml").write_bytes(settings)
        journal_path(case).write_bytes(changed)
        if name == "missing chain":
            heads.forget(case.folder)
        else:
            heads.path_for(case.folder).write_bytes(record)
        reason = open_reason(case)
        files = listing(case.folder)
        assert reason, name
        if route == "upgraded":
            assert upgraded(open_case(case.folder)).settings.case_format == 3, name
            journal = Journal(open_case(case.folder), "server")
            journal.open_for_work()
        else:
            app = opened(open_case(case.folder))
            assert app.case.settings.case_format == 3, name
            journal = app.journal
        assert settings_of(case)["case_format"] == 3, name
        assert journal_path(case).read_bytes() == changed and listing(case.folder) == files, name
        assert journal.read_only == reason, name
        if name in NO_CHAIN:
            assert not journal_row(journal, CHECKED)["can_continue"], name
            with pytest.raises(JournalError, match="no hash chain yet"):
                journal.record_break("looked at it")
            assert journal_path(case).read_bytes() == changed, name
            continue
        assert journal_row(journal, CHECKED)["can_continue"], name
        assert journal.record_break("looked at it")["action"] == "chain_break", name
        reopened = upgraded(open_case(case.folder)) if route == "upgraded" else opened(open_case(case.folder)).case
        assert reopened.settings.case_format == settings_of(case)["case_format"] == 4, name
        assert len(steps_to_4(case)) == 1 and not Journal(reopened).read_only, name


def test_a_sound_format_3_case_takes_one_chained_entry_then_format_4(synthetic_case):
    """A format 3 case whose newest case_open names another build: the open writes one chained case_upgrade from 3 to 4,
    the app's own, with no rekey, seal, pins, or recovered, then case.yaml takes 4, and the open's case_yaml and
    case_open follow. The chain is consistent to the app and to the checker, and the head recorded outside the case is
    the newest line."""
    case = format3_case(synthetic_case)
    before = worked_at_format_3(case, marks=1)
    app = opened(open_case(case.folder))
    assert not app.journal.read_only and app.case.settings.case_format == settings_of(case)["case_format"] == 4
    written = written_after(case, before)
    assert [e["action"] for e in written] == ["case_upgrade", "case_yaml", "case_open"]
    step, recorded, opened_by = written
    assert set(step) == {*ENVELOPE, "from_format", "to_format", "text"}
    assert (step["from_format"], step["to_format"], step["who"], step["seq"]) == (3, 4, SYSTEM, before.count(b"\n") + 1)
    assert step["prev"] == sha(before.split(b"\n")[-2]) and step["text"] and "run.json" not in step["text"]
    assert recorded["settings"]["case_format"] == 4 and recorded["sha256"] == sha((case.folder / "case.yaml").read_bytes())
    assert opened_by["build"] == build_id() != BUILD
    path = journal_path(case)
    assert check(path).consistent and run_checker(path)[0] == 0
    assert heads.read(case.folder)["head"] == sha(path.read_bytes().split(b"\n")[-2])


def test_a_crash_between_the_entry_and_case_yaml_writes_only_the_number_next(synthetic_case, monkeypatch):
    """A crash after the 3 to 4 entry and before case.yaml takes 4: case.yaml stays as it was. Broken after the crash,
    the journal keeps the case at 3, as the step's journaled check runs the read-only check too. Sound, the next open
    writes only the number: no second entry."""
    case = format3_case(synthetic_case)
    worked_at_format_3(case)
    settings = (case.folder / "case.yaml").read_bytes()

    def crashed(folder, values):
        raise OSError("stopped before case.yaml")

    monkeypatch.setattr(case_module, "_write_settings", crashed)
    with pytest.raises(CaseError, match=r"case\.yaml"):
        App(open_case(case.folder), for_work=True)
    monkeypatch.undo()
    data = journal_path(case).read_bytes()
    assert (case.folder / "case.yaml").read_bytes() == settings and len(steps_to_4(case)) == 1
    broken, _ = tampered(data, "payload")
    journal_path(case).write_bytes(broken)
    app = opened(open_case(case.folder))
    assert app.journal.read_only and app.case.settings.case_format == settings_of(case)["case_format"] == 3
    assert journal_path(case).read_bytes() == broken
    journal_path(case).write_bytes(data)
    app = opened(open_case(case.folder))
    assert not app.journal.read_only and settings_of(case)["case_format"] == 4
    assert [e["action"] for e in written_after(case, data)] == ["case_yaml", "case_open"]
    assert len(steps_to_4(case)) == 1 and check(journal_path(case)).consistent


def test_a_crash_after_an_entry_that_follows_a_break_on_record_writes_only_the_number_next(synthetic_case, monkeypatch):
    """A break the analyst Continued at format 3, then a crash after the 3 to 4 entry and before case.yaml takes 4. The
    chain_break comes before the entry, so the entry stays the step's: the next open writes only the number."""
    case = format3_case(synthetic_case)
    data = worked_at_format_3(case)
    journal_path(case).write_bytes(tampered(data, "payload")[0])
    app = opened(open_case(case.folder))
    assert app.journal.read_only and settings_of(case)["case_format"] == 3
    assert app.journal.record_break("looked at it")["action"] == "chain_break"
    settings = (case.folder / "case.yaml").read_bytes()
    continued = journal_path(case).read_bytes()

    def crashed(folder, values):
        raise OSError("stopped before case.yaml")

    monkeypatch.setattr(case_module, "_write_settings", crashed)
    with pytest.raises(CaseError, match=r"case\.yaml"):
        App(open_case(case.folder), for_work=True)
    monkeypatch.undo()
    data = journal_path(case).read_bytes()
    assert (case.folder / "case.yaml").read_bytes() == settings
    assert [e["action"] for e in written_after(case, continued)] == ["case_upgrade"]
    app = opened(open_case(case.folder))
    assert not app.journal.read_only and settings_of(case)["case_format"] == 4
    assert [e["action"] for e in written_after(case, data)] == ["case_yaml", "case_open"]
    [step] = steps_to_4(case)
    assert (step["who"], step["text"]) == (SYSTEM, FORMAT_4_TEXT) and not check(journal_path(case)).problems


def test_a_connection_holding_the_events_database_stops_the_step_with_nothing_written(synthetic_case):
    """Another process holding the events database, as a running app does, stops the 3 to 4 step before it writes,
    through the command line's upgrade and the server's open: the journal and case.yaml are as they were."""
    case = format3_case(synthetic_case)
    worked_at_format_3(case)
    before = (journal_path(case).read_bytes(), (case.folder / "case.yaml").read_bytes())
    holder = subprocess.Popen([sys.executable, "-c", HOLD, str(case.db_path)], stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, text=True)
    try:
        assert holder.stdout.readline().strip() == "held"
        for refused in (lambda: upgraded(open_case(case.folder)), lambda: App(open_case(case.folder), for_work=True)):
            with pytest.raises(CaseError, match="needs a case format upgrade, and another program has its events database"):
                refused()
            assert (journal_path(case).read_bytes(), (case.folder / "case.yaml").read_bytes()) == before
    finally:
        holder.communicate("", timeout=60)
    assert settings_of(case)["case_format"] == 3


def test_a_format_4_entry_cut_before_its_lf_is_completed_at_the_next_open(synthetic_case, monkeypatch):
    """The 3 to 4 entry's write stops one byte short, so case.yaml still says 3. The entry is whole, so the server's
    next open counts it as journaled: it ends the line, journals that, and writes only the number. The open's own
    Journal ends the line, so the entry names the server, and Integrity counts the cut entry after the recorded head and
    says it added the line end."""
    case = format3_case(synthetic_case)
    old = worked_at_format_3(case)
    cut_before_its_lf(monkeypatch)
    with pytest.raises((OSError, CaseError)):
        upgraded(open_case(case.folder))
    monkeypatch.undo()
    path = journal_path(case)
    cut = path.read_bytes()
    assert settings_of(case)["case_format"] == 3 and cut.startswith(old) and not cut.endswith(b"\n")
    step = json.loads(cut[len(old):])
    assert (step["action"], step["from_format"], step["to_format"]) == ("case_upgrade", 3, 4)
    assert check(path).tail == "missing_lf"
    app = opened(open_case(case.folder))
    assert not app.journal.read_only and settings_of(case)["case_format"] == 4
    written = written_after(case, cut + b"\n")
    assert [e["action"] for e in written] == ["journal_recovered", "case_yaml", "case_open"]
    assert all(e["client"] == "server" for e in written)
    assert (written[0]["completed"], written[0]["entry"]) == (True, {"action": "case_upgrade", "seq": step["seq"]})
    assert len(steps_to_4(case)) == 1 and check(path).consistent and run_checker(path)[0] == 0
    assert app.journal.recorded["after"] == {"case_upgrade": 1}
    text = journal_row(app.journal, CHECKED)["text"]
    assert f"Added the line end missing from entry #{step['seq']} (entry #{written[0]['seq']})." in text, text


def test_the_checks_before_a_journaled_step_run_on_the_open_s_own_journal(synthetic_case):
    """A format 3 case with entries after the head recorded outside the case, a chained case_upgrade from 3 to 4 by
    someone else among them, a side file no entry names, and a changed case.yaml. The step finds its entry journaled,
    and the server's open runs the checks before it writes the number through its own Journal: the entries those checks
    write name the server, and Integrity counts every entry after the recorded head, warns about the case_upgrade, and
    names the side file."""
    case = format3_case(synthetic_case)
    data = worked_at_format_3(case, marks=1)
    for target in (UID, OTHER):
        data = add(data, "mark", who="mallory", targets=[target], value="benign")
    data = add(data, "case_upgrade", who="mallory", from_format=3, to_format=4, text="Upgraded.")
    journal_path(case).write_bytes(data)
    side = case.folder / "journal_torn_20261022T090000Z.bin"
    side.write_bytes(b"left here")
    settings = (case.folder / "case.yaml").read_text(encoding="utf-8")
    (case.folder / "case.yaml").write_text(settings.replace("analyst: ", "analyst: x"), encoding="utf-8")
    app = opened(open_case(case.folder))
    assert not app.journal.read_only and settings_of(case)["case_format"] == 4 and len(steps_to_4(case)) == 1
    written = written_after(case, data)
    assert [e["action"] for e in written] == ["journal_recovered", "case_yaml", "case_yaml", "case_open"]
    assert all(e["client"] == "server" for e in written)
    assert [e["settings"]["case_format"] for e in written if e["action"] == "case_yaml"] == [3, 4]
    assert app.journal.recorded["after"] == {"mark": 2, "case_upgrade": 1}
    text = journal_row(app.journal, CHECKED)["text"]
    assert any("The 3 entries after it were written without updating that record" in t for t in text), text
    assert AFTER_HEAD_WORDS["case_upgrade"] in text
    assert f"Found {side.name} with no entry naming it, unexplained (entry #{written[0]['seq']})." in text, text


@pytest.mark.parametrize("forged", ["rekey", "prev"])
def test_a_3_to_4_entry_before_a_break_on_record_is_not_the_step_s_entry(synthetic_case, forged):
    """A chained case_upgrade from 3 to 4 that no build wrote, a rekey or one whose prev names no line, is a break, and
    the case stays at 3. Once the analyst Continues, the chain_break puts it on record, so it no longer stands for the
    step's entry: the next open writes the app's own after the chain_break, then case.yaml takes 4."""
    case = format3_case(synthetic_case)
    data = worked_at_format_3(case, marks=1)
    fields = {"who": "mallory", "from_format": 3, "to_format": 4, "text": "Upgraded."}
    if forged == "rekey":
        data = add(data, "case_upgrade", rekey={"pairs": {UID: OTHER}}, **fields)
    else:
        data += line_bytes(envelope(last_seq(data) + 1, "1" * 64, "case_upgrade", **fields))
    journal_path(case).write_bytes(data)
    app = opened(open_case(case.folder))
    assert app.journal.read_only and app.case.settings.case_format == settings_of(case)["case_format"] == 3
    app.journal.record_break("looked at it")
    app = opened(open_case(case.folder))
    assert not app.journal.read_only and settings_of(case)["case_format"] == 4
    assert [e["action"] for e in written_after(case, data)] == ["chain_break", "case_upgrade", "case_yaml", "case_open"]
    theirs, own = steps_to_4(case)
    assert theirs["who"] == "mallory"
    assert (own["who"], own["client"], own["text"]) == (SYSTEM, "server", FORMAT_4_TEXT) and "rekey" not in own


def test_a_format_1_case_reaches_format_4_in_one_open(tmp_path):
    """One open of a format 1 case: format 2's step unchained, the seal, the open's case_yaml for format 3, the 3 to 4
    entry, a case_yaml for format 4, and case_open, then the built-in rules. The mark's event has its new ID."""
    f, uid = found_eve_case(tmp_path)
    app = App(f.case, for_work=True)
    try:
        entries = entries_of(f.case)
        kinds = [(e["action"], e.get("from_format"), e.get("to_format"), "prev" in e) for e in entries]
        assert kinds[:7] == [("mark", None, None, False), ("case_upgrade", 1, 2, False), ("case_upgrade", 2, 3, True),
                             ("case_yaml", None, None, True), ("case_upgrade", 3, 4, True),
                             ("case_yaml", None, None, True), ("case_open", None, None, True)]
        assert {kind[0] for kind in kinds[7:]} == {"rule_add"}
        assert [e["settings"]["case_format"] for e in entries if e["action"] == "case_yaml"] == [3, 4]
        new = entries[1]["rekey"]["pairs"][uid]
        assert app.journal.state.marks[new].value == "malicious"
    finally:
        app.con.close()
    assert settings_of(f.case)["case_format"] == 4 and check(journal_path(f.case)).consistent


def copy_source(case: Case, fmt: int) -> Case:
    """A case of format `fmt` to copy, with notes in its journal."""
    if fmt == 3:
        case = format3_case(case)
        Journal(case).append("note", target=UID, text="looked at it")
        return case
    as_format(case.folder, fmt, unchained(note(1), note(2, OTHER)))
    return open_case(case.folder)


@pytest.mark.parametrize("route", ["cli", "page"])
@pytest.mark.parametrize("fmt", [3, 2, 1])
def test_a_copy_writes_case_created_before_the_chained_steps(tmp_path, synthetic_case, fmt, route):
    """A copy by copy-case or the start page's Copy runs the steps from before the chain, then case_created, then the 3
    to 4 entry: of a format 1 source, format 2's step unchained, the seal, case_created, then the entry; of a format 2
    source, the seal, case_created, then the entry; of a format 3 source, case_created at byte 0, then the entry. The
    copy's next open writes a case_yaml for format 4 first. The source stays as it was."""
    source = copy_source(synthetic_case, fmt)
    before = journal_path(source).read_bytes()
    target = tmp_path / "copy"
    if route == "cli":
        assert main(["copy-case", str(source.folder), str(target), "--name", "Copy", "--analyst", "tester"]) == 0
    else:
        wait(start_copy({"source": str(source.folder), "case_folder": str(target), "name": "Copy"}, "tester"))
    copy = open_case(target)
    client = "cli" if route == "cli" else "server"
    entries = entries_of(copy)
    kinds = [(e["action"], e.get("from_format"), e.get("to_format")) for e in entries]
    expected = {1: [("case_upgrade", 1, 2), ("case_upgrade", 2, 3)], 2: [("case_upgrade", 2, 3)], 3: []}[fmt]
    assert kinds == [*expected, ("case_created", None, None), ("case_upgrade", 3, 4)]
    created, step = entries[-2:]
    assert created["client"] == step["client"] == client and created["analyst"] == "tester"
    assert created["case_format"] == 3   # the copy's format when its chain starts, the step's to come
    if fmt == 3:
        assert (created["prev"], created["seq"]) == (ZERO, 1)
        assert created["copied_from"]["head"] == sha(before.split(b"\n")[-2])
    else:
        assert created["copied_from"] == {"folder": str(source.folder), "bytes": len(before), "sha256": sha(before)}
    assert set(step) == {*ENVELOPE, "from_format", "to_format", "text"}
    assert settings_of(copy)["case_format"] == 4 and check(journal_path(copy)).consistent
    assert run_checker(journal_path(copy))[0] == 0 and journal_path(source).read_bytes() == before
    assert heads.read(copy.folder)["head"] == sha(journal_path(copy).read_bytes().split(b"\n")[-2])
    copied = journal_path(copy).read_bytes()
    opened(open_case(target))
    written = written_after(copy, copied)
    assert [e["action"] for e in written[:2]] == ["case_yaml", "case_open"]
    assert written[0]["settings"]["case_format"] == 4 and check(journal_path(copy)).consistent


def serve_lines(case: Case, monkeypatch, capsys) -> list[str]:
    """What `serve` prints for the case up to its link, with the server's loop left out."""
    from glessner import server

    monkeypatch.setattr(server.Server, "serve_forever", lambda self: None)
    assert main(["serve", str(case.folder), "--no-browser", "--port", "0"]) == 0
    return capsys.readouterr().out.splitlines()


def test_the_serve_command_says_what_the_open_did_to_the_format(synthetic_case, monkeypatch, capsys):
    """serve's open of a format 3 case says that it upgrades the case, without the words about a long upgrade, which
    only a format 1 or 2 case's seal and reload take, then, after the open, that the case is now format 4. For one
    whose journal is read-only, that it stays at 3."""
    case = format3_case(synthetic_case)
    data = worked_at_format_3(case)
    journal_path(case).write_bytes(tampered(data, "payload")[0])
    for expected in (KEPT_3, NOW_4):
        lines = serve_lines(case, monkeypatch, capsys)
        assert lines[1] == UPGRADES_IT and not any("takes a while" in line for line in lines)
        opened_at = next(i for i, line in enumerate(lines) if line.endswith("  Opened."))
        assert lines[opened_at + 1] == expected and lines[opened_at + 2].startswith("Serving ")
        journal_path(case).write_bytes(data)
    assert settings_of(case)["case_format"] == 4


def test_an_unchained_format_4_line_sealed_before_the_chain_is_not_the_step_s_entry(synthetic_case):
    """A format 2 journal holding an unchained case_upgrade from 3 to 4, which the seal covers: it isn't the step's
    entry, so the step writes its chained one and case.yaml takes 4."""
    line = {"seq": 99, "at": "", "who": SYSTEM, "action": "case_upgrade", "from_format": 3, "to_format": 4, "text": "x"}
    case = format2(synthetic_case, journal=unchained(*builtin_rules(), line))
    opened(case)
    assert [e["seq"] for e in entries_of(case) if e.get("to_format") == 4 and "prev" not in e] == [99]
    assert len(steps_to_4(case)) == 1 and settings_of(case)["case_format"] == 4
    assert check(journal_path(case)).consistent


def test_integrity_still_counts_an_entry_after_the_recorded_head_once_the_open_reaches_4(synthetic_case):
    """A format 3 case with one entry after the head recorded outside the case, as another computer or a failed write
    of the record leaves it. The 3 to 4 entry moves the record, and the open's checks run again after the step; the
    Integrity row still names the entry the open found after the recorded head."""
    case = format3_case(synthetic_case)
    data = worked_at_format_3(case, marks=1)
    journal_path(case).write_bytes(add(data, "note", target=UID, text="written elsewhere"))
    app = opened(open_case(case.folder))
    assert not app.journal.read_only and settings_of(case)["case_format"] == 4 and len(steps_to_4(case)) == 1
    assert app.journal.recorded["after"] == {"note": 1}
    text = journal_row(app.journal, CHECKED)["text"]
    assert any("The 1 entry after it was written without updating that record: 1 note." in t for t in text), text


def test_close_beside_an_app_holding_a_case_kept_at_3_exits_0(synthetic_case):
    """A case kept at 3 by a break, then Continued in an App that keeps its events database open: glessner close in
    another process doesn't run the 3 to 4 step, which would need that database, and exits 0. The case stays at 3 until
    it is opened again."""
    case = format3_case(synthetic_case)
    (case.evidence / "DC01" / "notes.txt").write_text("evidence", encoding="utf-8")
    intake(case)
    data = worked_at_format_3(case)
    journal_path(case).write_bytes(tampered(data, "payload")[0])
    app = App(open_case(case.folder), for_work=True)
    try:
        assert app.journal.read_only and app.case.settings.case_format == 3
        app.journal.record_break("looked at it")
        done = subprocess.run([sys.executable, "-m", "glessner", "close", str(case.folder)], capture_output=True,
                              text=True, encoding="utf-8", check=False)
        assert done.returncode == 0, done.stdout + done.stderr
    finally:
        app.con.close()
    assert entries_of(case)[-1]["value"]["hash_check"] == "ok" and settings_of(case)["case_format"] == 3
    opened(open_case(case.folder))
    assert settings_of(case)["case_format"] == 4 and len(steps_to_4(case)) == 1


def test_close_upgrades_a_format_2_case_to_format_4_as_verify_says(synthetic_case, capsys):
    """verify on a format 2 case says that the next command that writes upgrades it to format 4. glessner close is one:
    its journal takes no entry until the chain starts, so close writes the seal, a case_yaml for format 3, the 3 to 4
    entry, and a case_yaml for format 4, then its own entry, all by the command line, and exits 0."""
    (synthetic_case.evidence / "DC01" / "notes.txt").write_text("evidence", encoding="utf-8")
    intake(synthetic_case)
    case = format2(synthetic_case)
    before = journal_path(case).read_bytes()
    assert main(["verify", str(case.folder), "--journal"]) == 1
    assert capsys.readouterr().out.splitlines() == [
        "The journal has no hash chain yet: this case is format 2, and its next open for work, or a command that "
        "writes, upgrades it to format 4, which starts the chain."]
    assert main(["close", str(case.folder)]) == 0
    written = written_after(case, before)
    assert [(e["action"], e.get("to_format")) for e in written] == [
        ("case_upgrade", 3), ("case_yaml", None), ("case_upgrade", 4), ("case_yaml", None), ("case_setting", None)]
    assert [e["settings"]["case_format"] for e in written if e["action"] == "case_yaml"] == [3, 4]
    assert all(e["client"] == "cli" for e in written) and written[-1]["value"]["hash_check"] == "ok"
    assert settings_of(case)["case_format"] == 4 and check(journal_path(case)).consistent


def test_a_chained_rekey_to_format_4_is_a_break_in_a_format_4_case(synthetic_case):
    """No build writes a rekey of event IDs from format 3 to 4, so a chained one in a format 4 journal is a "rekey" break
    to the app and to the checker, and it translates nothing. A rekey to a later format still follows. The checker's
    format is the app's."""
    path = journal_path(synthetic_case)
    heads.forget(synthetic_case.folder)
    base = chained([("mark", {"targets": [UID], "value": "suspicious"})])
    pairs = {"pairs": {UID: OTHER}}
    path.write_bytes(add(base, "case_upgrade", who=SYSTEM, from_format=3, to_format=4, text="x", rekey=pairs))
    journal = Journal(synthetic_case)
    assert [b["kind"] for b in journal.breaks] == ["rekey"] and journal.read_only
    assert set(journal.state.marks) == {UID} and not journal.state.rekeys
    assert [p["kind"] for p in check(path).problems] == ["rekey"]
    code, out = run_checker(path)
    assert code == 1 and "a rekey of event IDs, from format 3 to 4" in out
    path.write_bytes(add(base, "case_upgrade", who=SYSTEM, from_format=4, to_format=5, text="x", rekey=pairs))
    assert check(path).consistent and run_checker(path)[0] == 0 and set(replay(path).marks) == {OTHER}
    assert runpy.run_path(str(CHECKER))["CASE_FORMAT"] == CASE_FORMAT == 4


# ---------- found output loaded while case.yaml named the evidence through a link ----------

def linked_case_at_format_3(tmp_path, monkeypatch, files=(EVE_A,), loaded=True, link=True, single_host=""):
    """A format 3 case whose found output was loaded with the evidence root as case.yaml writes it, which names the
    evidence through a junction: the events name their files by extended-length paths, and the IDs hash those."""
    case = format3_case(linked_evidence_case(tmp_path, files, link=link, single_host=single_host))
    if loaded:
        with loaded_under_the_written_root(monkeypatch):
            assert load_found_output(case, "suricata", "suricata_eve", "SENSOR", list(files)).status == "ok"
    return case


def suricata_rows(case) -> dict[str, str]:
    """Each Suricata event's ID with the file it names."""
    con = connect(case.db_path, read_only=True)
    try:
        return dict(con.execute("SELECT event_uid, source_file FROM events WHERE tool = 'suricata'").fetchall())
    finally:
        con.close()


def test_the_format_4_step_rekeys_found_output_loaded_under_a_linked_evidence_path(tmp_path, monkeypatch):
    """A mark on an event of found output that was loaded while case.yaml named the evidence through a junction. Its
    IDs hashed the extended-length path of the file it names; this build's hash the path under the
    evidence folder. The step journals the old IDs' new ones and loads the output again, so the rows are the ones a
    rebuild gives, the mark finds its event, and the journal is consistent to the app and to the checker."""
    case = linked_case_at_format_3(tmp_path, monkeypatch)
    before = suricata_rows(case)
    assert before and all(source.startswith("//?/") for source in before.values())
    marked = sorted(before)[:2]
    Journal(case).append("mark", targets=marked, value="malicious", note="")
    case = upgraded(open_case(case.folder))
    assert settings_of(case)["case_format"] == 4
    [step] = steps_to_4(case)
    pairs = step["rekey"]["pairs"]
    assert set(pairs) == set(marked) and not set(pairs.values()) & set(before)
    after = suricata_rows(case)
    assert set(pairs.values()) <= set(after) and len(after) == len(before) and set(after.values()) == {EVE_A}
    assert set(step["rekey"]["runs"]) == {r.name for r in case.runs_folder.iterdir()}
    assert step["rekey"]["map_size"] == len(before) and "2 journal references now name" in step["text"]
    app = App(case)
    try:
        assert app.orphans == 0 and set(pairs.values()) == set(app.journal.state.marks)
        assert all(app.journal.state.marks[new].value == "malicious" for new in pairs.values())
    finally:
        app.con.close()
    path = journal_path(case)
    assert check(path).consistent and run_checker(path)[0] == 0 and not Journal(case).breaks
    rebuild(case)
    assert suricata_rows(case) == after


def test_the_format_4_step_adds_no_rekey_when_no_found_output_took_a_new_id(tmp_path, monkeypatch):
    """The entry is the step's usual one, with no rekey, for a case whose evidence is named through a junction and holds
    no found output; for one whose found output was loaded under the evidence path in its resolved form; and for one
    with no events database."""
    plain = linked_case_at_format_3(tmp_path / "nothing", monkeypatch, loaded=False)
    resolved = linked_case_at_format_3(tmp_path / "resolved", monkeypatch, link=False)
    unloaded = linked_case_at_format_3(tmp_path / "unloaded", monkeypatch, loaded=False)
    unloaded.db_path.unlink(missing_ok=True)
    for case in (plain, resolved, unloaded):
        upgraded(open_case(case.folder))
        [step] = steps_to_4(case)
        assert (step["text"], "rekey" in step) == (FORMAT_4_TEXT, False), case.folder


def test_the_format_4_step_reads_no_output_when_the_evidence_is_named_by_its_resolved_path(tmp_path, monkeypatch):
    """The two roots give the same sources unless case.yaml names the evidence through a link, so the step parses no run
    in the common case."""
    case = linked_case_at_format_3(tmp_path, monkeypatch, link=False)

    def refused(*args, **kwargs):
        raise AssertionError("the step read a run's output")

    monkeypatch.setattr(rekey_module, "_renamed_ids", refused, raising=False)
    assert upgraded(open_case(case.folder)).settings.case_format == 4


def test_the_format_4_step_names_a_run_it_cannot_check_and_leaves_its_rows(tmp_path, monkeypatch):
    """Two runs of found output under a link, the output of one changed since it was loaded. The step doesn't stop: the
    run whose output no longer matches its record keeps its rows and IDs and is named, and the other takes new IDs."""
    case = linked_case_at_format_3(tmp_path, monkeypatch, files=(EVE_A, EVE_B), loaded=False)
    with loaded_under_the_written_root(monkeypatch):
        first = load_found_output(case, "suricata", "suricata_eve", "SENSOR", [EVE_A])
        second = load_found_output(case, "suricata", "suricata_eve", "SENSOR", [EVE_B])
    before = suricata_rows(case)
    with (case.evidence / EVE_B).open("a", encoding="utf-8") as f:
        f.write("{}")
    upgraded(open_case(case.folder))
    [step] = steps_to_4(case)
    assert set(step["rekey"]["runs"]) == {first.run_id} and set(step["rekey"]["skipped_runs"]) == {second.run_id}
    after = suricata_rows(case)
    kept = {uid: source for uid, source in before.items() if source.endswith(EVE_B)}
    assert kept and {uid: source for uid, source in after.items() if source.startswith("//?/")} == kept
    assert sum(source == EVE_A for source in after.values()) == len(before) - len(kept)


def test_a_stop_while_the_step_loads_the_output_again_leaves_format_3_and_the_next_open_finishes(tmp_path, monkeypatch):
    """The step loads the runs again before it journals anything, so a stop in the load leaves case.yaml at 3 and no
    entry, and the next open gives the entry it would have given."""
    case = linked_case_at_format_3(tmp_path, monkeypatch)
    marked = sorted(suricata_rows(case))[0]
    Journal(case).append("mark", targets=[marked], value="malicious", note="")
    journal = journal_path(case).read_bytes()

    def stopped(*args, **kwargs):
        raise KeyboardInterrupt

    with monkeypatch.context() as patched:
        patched.setattr(rekey_module, "reload_run", stopped)
        with pytest.raises(KeyboardInterrupt):
            upgraded(open_case(case.folder))
    assert settings_of(case)["case_format"] == 3 and journal_path(case).read_bytes() == journal
    case = upgraded(open_case(case.folder))
    [step] = steps_to_4(case)
    assert settings_of(case)["case_format"] == 4 and step["rekey"]["pairs"][marked] in suricata_rows(case)


def run_files(case: Case) -> dict[str, bytes]:
    """Each run's record file, by the run's folder name."""
    return {path.parent.name: path.read_bytes() for path in case.runs_folder.glob("*/run.json")}


def mark_one(case: Case, uid: str) -> None:
    Journal(case).append("mark", targets=[uid], value="malicious", note="")


def test_the_format_4_step_rekeys_found_output_by_its_rows_whatever_case_yaml_names_now(tmp_path, monkeypatch):
    """case.yaml was edited after the load to name the folder the junction leads to. The rows still name their files by
    extended-length path, so the step reads them, not case.yaml, to find the output it must rekey, and the mark on one
    of them finds its event after the upgrade."""
    case = linked_case_at_format_3(tmp_path, monkeypatch)
    before = suricata_rows(case)
    assert all(source.startswith("//?/") for source in before.values())
    marked = sorted(before)[0]
    mark_one(case, marked)
    data = settings_of(case)
    data["evidence_path"] = str((tmp_path / "moved").resolve())
    (case.folder / "case.yaml").write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    case = upgraded(open_case(case.folder))
    [step] = steps_to_4(case)
    after = suricata_rows(case)
    assert set(step["rekey"]["pairs"]) == {marked} and step["rekey"]["pairs"][marked] in after
    assert set(after.values()) == {EVE_A} and len(after) == len(before)


def test_the_format_4_step_adds_no_rekey_for_found_output_loaded_before_the_evidence_was_linked(tmp_path, monkeypatch):
    """Found output loaded while case.yaml named the evidence by its own path has plain rows. The evidence was linked
    afterward, so case.yaml now names it through a junction, but no ID changed: the entry is the usual one, and the
    rows and run records are as they were."""
    case = linked_case_at_format_3(tmp_path, monkeypatch, link=False)
    before, runs = suricata_rows(case), run_files(case)
    assert before and not any(source.startswith("//?/") for source in before.values())
    mark_one(case, sorted(before)[0])
    link_evidence(tmp_path)
    upgraded(open_case(case.folder))
    [step] = steps_to_4(case)
    assert (step["text"], "rekey" in step, "skipped_runs" in step) == (FORMAT_4_TEXT, False, False)
    assert suricata_rows(case) == before and run_files(case) == runs


def test_the_format_4_step_leaves_the_rows_of_a_run_a_rebuild_does_not_load(tmp_path, monkeypatch):
    """A run that failed but kept the rows it loaded is not one a rebuild loads, so the step leaves its rows and IDs, and
    the mark on one of its events still finds it."""
    case = linked_case_at_format_3(tmp_path, monkeypatch)
    before, [run] = suricata_rows(case), read_runs(case)
    _write_record(case.runs_folder / run.run_id, replace(run, status="failed"))
    mark_one(case, sorted(before)[0])
    case = upgraded(open_case(case.folder))
    [step] = steps_to_4(case)
    assert (step["text"], "rekey" in step) == (FORMAT_4_TEXT, False)
    assert suricata_rows(case) == before
    app = App(case)
    try:
        assert app.orphans == 0
    finally:
        app.con.close()


def test_the_format_4_step_names_the_runs_it_cannot_check_when_no_run_moved(tmp_path, monkeypatch):
    """The only run's output changed after it was loaded, so the step can't tell which IDs a rebuild gives its events.
    The entry names the run and says its events keep the IDs they have, and its rows are as they were."""
    case = linked_case_at_format_3(tmp_path, monkeypatch)
    before, [run] = suricata_rows(case), read_runs(case)
    with (case.evidence / EVE_A).open("a", encoding="utf-8") as f:
        f.write("{}")
    upgraded(open_case(case.folder))
    [step] = steps_to_4(case)
    assert "rekey" not in step and set(step["skipped_runs"]) == {run.run_id}
    assert step["text"].startswith(FORMAT_4_TEXT) and run.run_id in step["text"] and "keep the IDs they have" in step["text"]
    assert suricata_rows(case) == before and check(journal_path(case)).consistent


def test_the_format_4_step_names_the_runs_it_cannot_read_while_the_evidence_is_offline(tmp_path, monkeypatch):
    """The junction case.yaml names is gone at the first open with this build, so no run's output can be read. The step
    still runs, names the run, and keeps its rows and IDs rather than saying nothing changed."""
    case = linked_case_at_format_3(tmp_path, monkeypatch)
    before, [run] = suricata_rows(case), read_runs(case)
    mark_one(case, sorted(before)[0])
    os.rmdir(tmp_path / "evidence")
    upgraded(open_case(case.folder))
    [step] = steps_to_4(case)
    assert "rekey" not in step and set(step["skipped_runs"]) == {run.run_id}
    assert suricata_rows(case) == before


def test_the_format_4_step_leaves_found_output_and_marks_alone_when_the_journal_has_a_break(tmp_path, monkeypatch):
    """The journal's checks come before the step touches the events database. A linked format 3 case whose journal has a
    break stays at 3 with its rows, run records, and journal exactly as they were."""
    case = linked_case_at_format_3(tmp_path, monkeypatch)
    before, runs = suricata_rows(case), run_files(case)
    journal = Journal(case)
    for uid in sorted(before)[:3]:
        journal.append("mark", targets=[uid], value="malicious", note="first look")
    broken = tampered(journal_path(case).read_bytes(), "payload")[0]
    journal_path(case).write_bytes(broken)
    assert upgraded(open_case(case.folder)).settings.case_format == 3
    assert suricata_rows(case) == before and run_files(case) == runs
    assert journal_path(case).read_bytes() == broken and settings_of(case)["case_format"] == 3


def test_the_format_4_step_moves_no_event_id_once_the_journal_holds_a_line_that_closes_its_place(tmp_path, monkeypatch):
    """A case.yaml at format 3 over a journal that holds a manifest record, which only a case at format 4 has, as when
    case.yaml was set back by hand: a rekey now would be a break to every reader. The step moves no ID and loads nothing
    again, names the runs it left as they are, and the journal it writes stays consistent."""
    case, marked = two_linked_runs(tmp_path, monkeypatch)
    before, runs = suricata_rows(case), read_runs(case)
    Journal(case).append("manifest_recorded", who=SYSTEM, sha256="1" * 64, bytes=10, lines=1, via="intake")
    case = upgraded(open_case(case.folder))
    [step] = steps_to_4(case)
    assert settings_of(case)["case_format"] == 4 and "rekey" not in step
    assert set(step["skipped_runs"]) == {r.run_id for r in runs} and "Output found in the evidence" not in step["text"]
    assert suricata_rows(case) == before and not (case.folder / RENAMED_FILE).exists()
    path = journal_path(case)
    assert check(path).consistent and run_checker(path)[0] == 0
    journal = Journal(case)
    assert not journal.breaks and set(journal.state.marks) == set(marked)


def test_the_format_4_step_pairs_only_the_events_its_rows_hold(tmp_path, monkeypatch):
    """The run's output gives events that have no row in the table, such as ones a load left out. They take no pair and
    aren't counted among the events whose IDs changed, and the load again brings them in."""
    case = linked_case_at_format_3(tmp_path, monkeypatch)
    before = suricata_rows(case)
    kept, dropped = sorted(before)[:-2], sorted(before)[-2:]
    con = connect(case.db_path)
    try:
        con.execute("DELETE FROM events WHERE event_uid IN (?, ?)", dropped)
    finally:
        con.close()
    mark_one(case, kept[0])
    upgraded(open_case(case.folder))
    [step] = steps_to_4(case)
    [counts] = step["rekey"]["runs"].values()
    assert set(step["rekey"]["pairs"]) == {kept[0]}
    assert (counts["events"], counts["changed"], step["rekey"]["map_size"]) == (len(kept),) * 3
    assert len(suricata_rows(case)) == len(before)


def test_the_format_4_step_pairs_both_files_of_a_single_host_case_with_a_folder_named_like_the_root(tmp_path, monkeypatch):
    """The evidence resolves to a folder named `moved`, and one run read `eve.json` and `moved/eve.json`, so the top-level
    file's rows end in `moved/eve.json` too. The root that explains both files' rows tells them apart: the step pairs
    the marked event of each file, reloads both, and names no run it left."""
    files = ("eve.json", "moved/eve.json")
    case = linked_case_at_format_3(tmp_path, monkeypatch, files=files, loaded=False, single_host="SENSOR")
    with loaded_under_the_written_root(monkeypatch):
        assert load_found_output(case, "suricata", "suricata_eve", "SENSOR", list(files)).status == "ok"
    rows = suricata_rows(case)
    deeper = {uid for uid, source in rows.items() if source.endswith("/moved/moved/eve.json")}
    top = set(rows) - deeper
    assert deeper and top
    marked = [min(top), min(deeper)]
    for uid in marked:
        mark_one(case, uid)
    case = upgraded(open_case(case.folder))
    [step] = steps_to_4(case)
    assert set(step["rekey"]["pairs"]) == set(marked) and step["rekey"]["skipped_runs"] == {}
    after = suricata_rows(case)
    assert sorted(after.values()) == sorted([*(["eve.json"] * len(top)), *(["moved/eve.json"] * len(deeper))])
    app = App(case)
    try:
        assert app.orphans == 0
    finally:
        app.con.close()


def test_the_format_4_step_names_a_run_none_of_whose_events_its_rows_hold(tmp_path, monkeypatch):
    """No event the output gives has a row under the IDs the stored names make, such as rows another build wrote with
    other IDs. The step leaves the rows and names the run rather than reload it for nothing."""
    case = linked_case_at_format_3(tmp_path, monkeypatch)
    [run] = read_runs(case)
    con = connect(case.db_path)
    try:
        con.execute("UPDATE events SET event_uid = md5(event_uid) WHERE tool = 'suricata'")
    finally:
        con.close()
    before = suricata_rows(case)
    upgraded(open_case(case.folder))
    [step] = steps_to_4(case)
    assert "rekey" not in step and "none of the events" in step["skipped_runs"][run.run_id]
    assert suricata_rows(case) == before


@pytest.mark.parametrize("named", [True, False])
def test_the_format_4_step_finishes_a_run_whose_rows_a_stop_took_only_when_the_journal_names_its_ids(
        tmp_path, monkeypatch, named):
    """A stop between the step's delete of a run's rows and its load leaves the run with no rows. The next open still
    knows the run was loaded under the link when the journal holds an ID the old naming gives it, and loads it again
    with the pairs. With no such ID there is nothing to rekey and no sign the run was loaded that way."""
    case = linked_case_at_format_3(tmp_path, monkeypatch)
    marked = sorted(suricata_rows(case))[0]
    if named:
        mark_one(case, marked)
    con = connect(case.db_path)
    try:
        con.execute("DELETE FROM events WHERE tool = 'suricata'")
    finally:
        con.close()
    upgraded(open_case(case.folder))
    [step] = steps_to_4(case)
    if named:
        assert step["rekey"]["pairs"][marked] in suricata_rows(case)
    else:
        assert (step["text"], "rekey" in step) == (FORMAT_4_TEXT, False) and not suricata_rows(case)


@pytest.mark.parametrize("remapped", [True, False])
def test_add_new_evidence_after_the_format_4_step_ends_with_a_row_per_record(tmp_path, monkeypatch, remapped):
    """One file was loaded under a link, a second was taken in with Add new evidence, and both were loaded again. The
    total is the two files' events once each, none under an extended-length name, whether or not the step rekeyed the
    first file's rows."""
    case = linked_case_at_format_3(tmp_path, monkeypatch)
    per_file = len(suricata_rows(case))
    if not remapped:
        monkeypatch.setattr(rekey_module, "_remap_found_output", lambda case, con, closed: None)
    case = upgraded(open_case(case.folder))
    assert {s.startswith("//?/") for s in suricata_rows(case).values()} == {not remapped}
    write_eve(tmp_path / "evidence", EVE_B)
    assert main(["intake", str(case.folder), "--add"]) == 0
    assert load_found_output(case, "suricata", "suricata_eve", "SENSOR", [EVE_A, EVE_B]).status == "ok"
    rows = suricata_rows(case)
    assert sorted(rows.values()) == [EVE_A] * per_file + [EVE_B] * per_file


def rekey_of_found_output(pairs: dict, **fields) -> dict:
    """What the 3 to 4 step writes for a rekey, the fields of its entry."""
    runs = {"20261001T000000Z_suricata_SENSOR": {"parser": "suricata_eve", "events": len(pairs), "changed": len(pairs)}}
    return {"from_format": 3, "to_format": 4, "text": "x", "rekey": {
        "pairs": pairs, "runs": runs, "map_size": len(pairs), "map_sha256": "0" * 64, **fields}}


def test_a_chained_rekey_to_format_4_that_describes_its_map_translates_and_one_that_does_not_is_a_break(synthetic_case):
    """After the chain starts, a rekey from format 3 to 4 is the step's when it names the runs it read, its pairs as a map,
    and the size and SHA-256 of its map, which holds at least its pairs. One missing any of them is a "rekey" break to the
    app and to the checker. The step's own rekey translates, and both readers agree."""
    path = journal_path(synthetic_case)
    heads.forget(synthetic_case.folder)
    base = chained([("mark", {"targets": [UID], "value": "suspicious"})])
    described = rekey_of_found_output({UID: OTHER})
    path.write_bytes(add(base, "case_upgrade", who=SYSTEM, **described))
    assert check(path).consistent and run_checker(path)[0] == 0 and set(replay(path).marks) == {OTHER}
    journal = Journal(synthetic_case)
    assert not journal.breaks and set(journal.state.marks) == {OTHER} and [r["seq"] for r in journal.state.rekeys] == [3]
    damaged = {
        "no runs": {"runs": {}}, "runs not a map": {"runs": []}, "no size": {"map_size": None},
        "a size under its pairs": {"map_size": 0}, "a size that isn't a number": {"map_size": "1"},
        "a size that is a boolean": {"map_size": True}, "no SHA-256": {"map_sha256": None},
        "a SHA-256 that isn't one": {"map_sha256": "x"},
        "no pairs": {"pairs": None}, "pairs that aren't a map": {"pairs": [UID]},
    }
    for name, change in damaged.items():
        entry = {**described, "rekey": {**described["rekey"], **change}}
        path.write_bytes(add(base, "case_upgrade", who=SYSTEM, **entry))
        assert [p["kind"] for p in check(path).problems] == ["rekey"], name
        code, out = run_checker(path)
        assert code == 1 and "a rekey of event IDs, from format 3 to 4" in out, name
        assert set(replay(path).marks) == {UID}, name


# ---------- a stop anywhere in the step before its entry is journaled ----------

RENAMED_FILE = "upgrade_renamed_ids.json"


def two_linked_runs(tmp_path, monkeypatch, marking=(0, 1)):
    """A format 3 case with two runs of found output loaded under a link, an event marked in each run whose position is in
    `marking`: the case, and the ID of the event chosen in each run."""
    case = linked_case_at_format_3(tmp_path, monkeypatch, files=(EVE_A, EVE_B), loaded=False)
    with loaded_under_the_written_root(monkeypatch):
        for rel in (EVE_A, EVE_B):
            assert load_found_output(case, "suricata", "suricata_eve", "SENSOR", [rel]).status == "ok"
    rows = suricata_rows(case)
    marked = [min(uid for uid, source in rows.items() if source.endswith(rel)) for rel in (EVE_A, EVE_B)]
    for index in marking:
        mark_one(case, marked[index])
    return case, marked


def stopped(*args, **kwargs):
    raise KeyboardInterrupt


def stop_after_the_last_reload(patched):
    patched.setattr(rekey_module, "_unreached", stopped)


def stop_before_the_first_reload_loads(patched):
    patched.setattr(rekey_module, "reload_run", stopped)


def stop_between_two_runs_reloads(patched):
    real, reloaded = rekey_module.reload_run, []

    def reload_run(case, record, layout):
        if reloaded:
            raise KeyboardInterrupt
        reloaded.append(record.run_id)
        return real(case, record, layout)

    patched.setattr(rekey_module, "reload_run", reload_run)


def refuse_the_entry(patched):
    real = Journal.append

    def append(self, action, *args, **kwargs):
        if action == "case_upgrade":
            raise JournalError("The journal is busy")
        return real(self, action, *args, **kwargs)

    patched.setattr(Journal, "append", append)


STOPS = {"after the last run's reload": (stop_after_the_last_reload, False, False),
         "before any run's load": (stop_before_the_first_reload_loads, False, False),
         "between two runs' reloads": (stop_between_two_runs_reloads, False, False),
         "in the journal's append of the entry": (refuse_the_entry, False, False),
         "before any run's load, with case.yaml naming the resolved path": (stop_before_the_first_reload_loads, True, False),
         "after the last run's reload, with case.yaml naming the resolved path": (stop_after_the_last_reload, True, False),
         "after the last run's reload, with the evidence moved again": (stop_after_the_last_reload, True, True)}


def name_evidence(case, folder) -> None:
    """case.yaml names the evidence by the resolved path of `folder`."""
    data = settings_of(case)
    data["evidence_path"] = str(folder.resolve())
    (case.folder / "case.yaml").write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


@pytest.mark.parametrize("stop", STOPS)
def test_a_stop_anywhere_before_the_entry_is_journaled_leaves_format_3_and_the_next_open_rekeys_every_run(
        tmp_path, monkeypatch, stop):
    """The step deletes and loads the runs again before it journals, so a stop can come after any run's rows are plain.
    The next open still gives every run's marked event its new ID, whatever case.yaml names by then and wherever the
    evidence is, and leaves no mark pointing at nothing."""
    case, marked = two_linked_runs(tmp_path, monkeypatch)
    before = suricata_rows(case)
    stops, resolved, moved_again = STOPS[stop]
    if resolved:
        name_evidence(case, tmp_path / "moved")
    journal = journal_path(case).read_bytes()
    with monkeypatch.context() as patched:
        stops(patched)
        with pytest.raises((KeyboardInterrupt, JournalError)):
            upgraded(open_case(case.folder))
    assert settings_of(case)["case_format"] == 3 and not steps_to_4(case)
    assert journal_path(case).read_bytes().startswith(journal)
    if moved_again:
        (tmp_path / "moved").rename(tmp_path / "moved2")
        name_evidence(case, tmp_path / "moved2")
    case = upgraded(open_case(case.folder))
    [step] = steps_to_4(case)
    assert settings_of(case)["case_format"] == 4 and set(step["rekey"]["pairs"]) == set(marked)
    assert set(step["rekey"]["runs"]) == {r.name for r in case.runs_folder.iterdir()}
    after = suricata_rows(case)
    assert len(after) == len(before) and set(after.values()) == {EVE_A, EVE_B}
    assert not (case.folder / RENAMED_FILE).exists()
    rebuild(case)
    assert suricata_rows(case) == after
    app = App(case)
    try:
        assert app.orphans == 0 and set(app.journal.state.marks) == set(step["rekey"]["pairs"].values())
    finally:
        app.con.close()
    path = journal_path(case)
    assert check(path).consistent and run_checker(path)[0] == 0


def stop_in_the_reload(patched):
    """A stop after the old names are kept and before the first row is deleted."""
    patched.setattr(rekey_module, "_reload_found", stopped)


def stopped_in_the_step(tmp_path, monkeypatch, stop=stop_after_the_last_reload):
    """A format 3 case with two linked runs, an event of each marked, whose upgrade stopped at `stop`: the case and the
    marks' IDs."""
    case, marked = two_linked_runs(tmp_path, monkeypatch)
    with monkeypatch.context() as patched:
        stop(patched)
        with pytest.raises(KeyboardInterrupt):
            upgraded(open_case(case.folder))
    return case, marked


def test_a_stop_in_the_step_keeps_what_the_next_open_needs_in_the_case_folder(tmp_path, monkeypatch):
    """The names the events carried before the step are written beside the case before the first row is deleted, each by
    the name the events carry now, so a stop leaves them there, and the entry's journaling removes the file."""
    case, _ = stopped_in_the_step(tmp_path, monkeypatch)
    kept = json.loads((case.folder / RENAMED_FILE).read_text(encoding="utf-8"))
    assert len(kept) == 2
    for names in kept.values():
        [(now, old)] = names.items()
        assert now in (EVE_A, EVE_B) and old.startswith("//?/") and old.endswith(f"/{now}")
    upgraded(open_case(case.folder))
    assert not (case.folder / RENAMED_FILE).exists()


@pytest.mark.parametrize("marking", [(0,), (1,)], ids=["the first run marked", "the second run marked"])
def test_a_second_stop_leaves_the_names_of_the_runs_the_first_stop_kept(tmp_path, monkeypatch, marking):
    """A stop between two runs' reloads leaves one run with plain rows, which a later open leaves as they are when the
    journal names none of its IDs. The names of both runs stay in the file until the entry is journaled, so a stop in that
    open leaves the file as the first stop did, and the open after it finishes with the pairs of the marked run."""
    case, marked = two_linked_runs(tmp_path, monkeypatch, marking)
    path = case.folder / RENAMED_FILE
    with monkeypatch.context() as patched:
        stop_between_two_runs_reloads(patched)
        with pytest.raises(KeyboardInterrupt):
            upgraded(open_case(case.folder))
    first = path.read_bytes()
    with monkeypatch.context() as patched:
        stop_before_the_first_reload_loads(patched)
        with pytest.raises(KeyboardInterrupt):
            upgraded(open_case(case.folder))
    assert len(json.loads(first)) == 2 and path.read_bytes() == first
    case = upgraded(open_case(case.folder))
    [step] = steps_to_4(case)
    assert settings_of(case)["case_format"] == 4 and set(step["rekey"]["pairs"]) == {marked[i] for i in marking}
    assert not path.exists()


def test_the_entry_after_a_stop_describes_only_the_runs_whose_events_the_journal_names(tmp_path, monkeypatch):
    """A stop after the last reload leaves both runs with the rows a rebuild gives. The next open pairs the IDs the journal
    names, which are the marked run's, and its entry describes that run alone: the unmarked run's events took new IDs in
    the stopped open, which the entry doesn't count. Every event has its rebuild ID either way."""
    case, marked = two_linked_runs(tmp_path, monkeypatch, marking=(0,))
    with monkeypatch.context() as patched:
        stop_after_the_last_reload(patched)
        with pytest.raises(KeyboardInterrupt):
            upgraded(open_case(case.folder))
    case = upgraded(open_case(case.folder))
    [step] = steps_to_4(case)
    assert set(step["rekey"]["pairs"]) == {marked[0]} and len(step["rekey"]["runs"]) == 1
    assert set(suricata_rows(case).values()) == {EVE_A, EVE_B}
    rows = suricata_rows(case)
    rebuild(case)
    assert suricata_rows(case) == rows


def test_a_run_a_stop_left_with_no_rows_is_loaded_again_though_the_journal_names_none_of_its_events(tmp_path, monkeypatch):
    """The step deleted the rows of both runs before it stopped, so no row remains for the journal to name. The next open
    loads both runs again from the names in the file, and their events come back under the IDs a rebuild gives."""
    case, _ = two_linked_runs(tmp_path, monkeypatch, marking=())
    with monkeypatch.context() as patched:
        stop_before_the_first_reload_loads(patched)
        with pytest.raises(KeyboardInterrupt):
            upgraded(open_case(case.folder))
    assert not suricata_rows(case)
    case = upgraded(open_case(case.folder))
    assert settings_of(case)["case_format"] == 4 and set(suricata_rows(case).values()) == {EVE_A, EVE_B}
    assert not (case.folder / RENAMED_FILE).exists()


RUN = "20261001T000000Z_suricata_SENSOR"
KEPT_FILES = {
    "not JSON": "{",
    "a list": "[]",
    "a run's names as a list": json.dumps({RUN: [EVE_A]}),
    "a name that is a number": json.dumps({RUN: {EVE_A: 1}}),
    "a file name that is a number": json.dumps({RUN: {"1": "//?/D:/ev/1", "2": 2}}),
    "a run with no names": json.dumps({RUN: {}}),
}


@pytest.mark.parametrize("name", KEPT_FILES)
def test_a_file_of_kept_names_that_is_not_a_map_of_runs_to_names_stops_the_step(tmp_path, monkeypatch, name):
    """The kept names are read as the name every file of a stopped run's events carried, so a file that holds anything
    else, such as one cut short or edited, stops the step with the case unchanged at format 3 and the file in place,
    rather than a map the entry then journals."""
    case, _ = two_linked_runs(tmp_path, monkeypatch)
    (case.folder / RENAMED_FILE).write_text(KEPT_FILES[name], encoding="utf-8")
    journal = journal_path(case).read_bytes()
    rows = suricata_rows(case)
    with pytest.raises(CaseError, match=RENAMED_FILE):
        upgraded(open_case(case.folder))
    assert settings_of(case)["case_format"] == 3 and not steps_to_4(case)
    assert journal_path(case).read_bytes() == journal and suricata_rows(case) == rows
    assert (case.folder / RENAMED_FILE).read_text(encoding="utf-8") == KEPT_FILES[name]


# What a hand edit of the names a stop kept for a run that read both files can do: the names as kept, EVE_A's and EVE_B's
DAMAGED_NAMES = {
    "a name that isn't extended-length": lambda a, b: {EVE_A: a.removeprefix("//?/"), EVE_B: b},
    "names that aren't extended-length": lambda a, b: {EVE_A: a.removeprefix("//?/"), EVE_B: b.removeprefix("//?/")},
    "a name that doesn't end in its file": lambda a, b: {EVE_A: f"{a}x", EVE_B: b},
    "names that don't end in their files": lambda a, b: {EVE_A: f"{a}x", EVE_B: f"{b}x"},
    "a file the run didn't read": lambda a, b: {EVE_A: a, EVE_B: b, "SENSOR/c/eve.json": b},
    "names under two roots": lambda a, b: {EVE_A: a, EVE_B: f"//?/E:/elsewhere/{EVE_B}"},
}


def one_run_of_two_files(tmp_path, monkeypatch, files=(EVE_A, EVE_B)):
    """A format 3 case with one run of found output that read the two linked `files`, an event of each marked, whose
    upgrade stopped after the run's reload."""
    case = linked_case_at_format_3(tmp_path, monkeypatch, files=files, loaded=False)
    with loaded_under_the_written_root(monkeypatch):
        assert load_found_output(case, "suricata", "suricata_eve", "SENSOR", list(files)).status == "ok"
    rows = suricata_rows(case)
    for rel in files:
        mark_one(case, min(uid for uid, source in rows.items() if source.endswith(rel)))
    with monkeypatch.context() as patched:
        stop_after_the_last_reload(patched)
        with pytest.raises(KeyboardInterrupt):
            upgraded(open_case(case.folder))
    return case


@pytest.mark.parametrize("damage", DAMAGED_NAMES)
def test_names_a_stop_kept_that_do_not_fit_the_run_stop_the_step(tmp_path, monkeypatch, damage):
    """The names for a run whose rows the stop left plain are checked against what the run read: each is the
    extended-length name of one of its files, as that file's events carry it now, and the files share a root. Otherwise
    the step stops with the case at format 3, the file in place, and the rows as they were."""
    case = one_run_of_two_files(tmp_path, monkeypatch)
    path = case.folder / RENAMED_FILE
    [names] = json.loads(path.read_text(encoding="utf-8")).values()
    [run] = [r.name for r in case.runs_folder.iterdir()]
    path.write_text(json.dumps({run: DAMAGED_NAMES[damage](names[EVE_A], names[EVE_B])}), encoding="utf-8")
    journal, rows, kept = journal_path(case).read_bytes(), suricata_rows(case), path.read_bytes()
    with pytest.raises(CaseError, match=RENAMED_FILE):
        upgraded(open_case(case.folder))
    assert settings_of(case)["case_format"] == 3 and not steps_to_4(case)
    assert journal_path(case).read_bytes() == journal and suricata_rows(case) == rows and path.read_bytes() == kept


def test_a_stopped_run_that_read_a_file_whose_name_lengthens_in_case_folding_finishes_at_the_next_open(
        tmp_path, monkeypatch):
    """Case folding turns the German sharp s into two letters, so a kept name is cut from its root by the length of the
    folded input, as the load that gave the names cut them. A run that read such a file and another has one root for
    both, and the next open gives each marked event its new ID."""
    sharp = "SENSOR/Straße/eve.json"
    case = one_run_of_two_files(tmp_path, monkeypatch, files=(EVE_A, sharp))
    case = upgraded(open_case(case.folder))
    [step] = steps_to_4(case)
    assert settings_of(case)["case_format"] == 4 and len(step["rekey"]["pairs"]) == 2
    assert set(suricata_rows(case).values()) == {EVE_A, sharp} and not (case.folder / RENAMED_FILE).exists()
    app = App(case)
    try:
        assert app.orphans == 0
    finally:
        app.con.close()


def test_a_stopped_step_stops_again_when_the_rows_of_a_run_are_not_the_ones_its_output_gives(tmp_path, monkeypatch):
    """A run the stop left with plain rows is accepted when every row has an ID its output gives now. Rows with other IDs
    are not what a stop leaves, so the step stops with the case unchanged and the file in place."""
    case, _ = stopped_in_the_step(tmp_path, monkeypatch)
    con = connect(case.db_path)
    try:
        con.execute("UPDATE events SET event_uid = md5(event_uid) WHERE tool = 'suricata'")
    finally:
        con.close()
    journal, rows, kept = journal_path(case).read_bytes(), suricata_rows(case), (case.folder / RENAMED_FILE).read_bytes()
    with pytest.raises(CaseError, match=RENAMED_FILE):
        upgraded(open_case(case.folder))
    assert settings_of(case)["case_format"] == 3 and not steps_to_4(case)
    assert journal_path(case).read_bytes() == journal and suricata_rows(case) == rows
    assert (case.folder / RENAMED_FILE).read_bytes() == kept


def evidence_goes_offline(tmp_path):
    """The junction case.yaml names is removed; the answer puts it back."""
    os.rmdir(tmp_path / "evidence")
    return lambda: junction(tmp_path / "evidence", tmp_path / "moved")


def output_changes(tmp_path):
    """One evidence file gains bytes; the answer restores it."""
    changed = tmp_path / "moved" / EVE_B
    original = changed.read_bytes()
    changed.write_bytes(original + b"{}")
    return lambda: changed.write_bytes(original)


@pytest.mark.parametrize("cause", [evidence_goes_offline, output_changes], ids=["the evidence is offline", "the output changed"])
def test_a_stopped_step_holds_at_format_3_while_a_run_it_began_to_load_again_cannot_be_read(tmp_path, monkeypatch, cause):
    """A stop between two runs' reloads leaves one run with plain rows and the other with none, so the old IDs are in no
    row and only the output gives them again. While a run can't be read, the step stops with the case at format 3, the
    file in place, and the journal and rows as they were, and the error names a run. With the evidence back as it was,
    the next open finishes: every marked event has its new ID."""
    case, marked = stopped_in_the_step(tmp_path, monkeypatch, stop_between_two_runs_reloads)
    journal, rows, kept = journal_path(case).read_bytes(), suricata_rows(case), (case.folder / RENAMED_FILE).read_bytes()
    restore = cause(tmp_path)
    with pytest.raises(CaseError, match=RENAMED_FILE) as held:
        upgraded(open_case(case.folder))
    assert any(r.name in str(held.value) for r in case.runs_folder.iterdir())
    assert settings_of(case)["case_format"] == 3 and not steps_to_4(case)
    assert journal_path(case).read_bytes() == journal and suricata_rows(case) == rows
    assert (case.folder / RENAMED_FILE).read_bytes() == kept
    restore()
    case = upgraded(open_case(case.folder))
    [step] = steps_to_4(case)
    assert set(step["rekey"]["pairs"]) == set(marked) and not (case.folder / RENAMED_FILE).exists()
    app = App(case)
    try:
        assert app.orphans == 0
    finally:
        app.con.close()


def test_a_run_whose_rows_a_stop_left_in_the_old_form_is_named_when_its_output_cannot_be_read(tmp_path, monkeypatch):
    """A stop after the old names are kept and before any row is deleted leaves the rows as they were, so a run that
    can't be read at the next open is left with its rows and IDs and named, as a run the step never touched is."""
    case, _ = stopped_in_the_step(tmp_path, monkeypatch, stop_in_the_reload)
    before = suricata_rows(case)
    assert before and all(source.startswith("//?/") for source in before.values())
    evidence_goes_offline(tmp_path)
    upgraded(open_case(case.folder))
    [step] = steps_to_4(case)
    assert "rekey" not in step and set(step["skipped_runs"]) == {r.name for r in case.runs_folder.iterdir()}
    assert suricata_rows(case) == before and not (case.folder / RENAMED_FILE).exists()


def test_a_stopped_step_holds_at_format_3_when_the_journal_has_since_closed_the_rekey_s_place(tmp_path, monkeypatch):
    """The runs a stop loaded again carry their new IDs, and the old ones are in the file alone, which is removed when the
    entry is journaled. A journal that holds a line only a case at format 4 has can't take the rekey that would carry
    them, so the step stops with the case unchanged and the file in place, rather than lose the only map."""
    case, _ = stopped_in_the_step(tmp_path, monkeypatch)
    Journal(case).append("manifest_recorded", who=SYSTEM, sha256="1" * 64, bytes=10, lines=1, via="intake")
    journal, rows, kept = journal_path(case).read_bytes(), suricata_rows(case), (case.folder / RENAMED_FILE).read_bytes()
    with pytest.raises(CaseError, match=RENAMED_FILE):
        upgraded(open_case(case.folder))
    assert settings_of(case)["case_format"] == 3 and not steps_to_4(case)
    assert journal_path(case).read_bytes() == journal and suricata_rows(case) == rows
    assert (case.folder / RENAMED_FILE).read_bytes() == kept


# What a file planted in a case whose runs were never moved holds, by the run, a marked event's ID, and another event's;
# and whether the step refuses it
PLANTED = {
    "names that fit the run": (lambda run, marked, other: {run: {EVE_A: f"//?/D:/elsewhere/{EVE_A}"}}, False),
    "the pairs of IDs": (lambda run, marked, other: {run: {marked: other}}, True),
}


@pytest.mark.parametrize("plant", PLANTED)
def test_a_file_planted_in_a_case_whose_runs_were_never_moved_moves_no_mark(tmp_path, monkeypatch, plant):
    """Found output loaded under the resolved path has plain rows and nothing to rename. A file in the case folder that
    names its run is checked against the run and the rows: it can't make the step journal a pair that moves a mark to
    another event. Names that fit the run are inert, since no event the journal names has such an ID; pairs of IDs are
    not names, so the step stops."""
    case = linked_case_at_format_3(tmp_path, monkeypatch, link=False)
    [run] = read_runs(case)
    rows = suricata_rows(case)
    marked, other = sorted(rows)[:2]
    mark_one(case, marked)
    make, refused = PLANTED[plant]
    path = case.folder / RENAMED_FILE
    path.write_text(json.dumps(make(run.run_id, marked, other)), encoding="utf-8")
    if refused:
        with pytest.raises(CaseError, match=RENAMED_FILE):
            upgraded(open_case(case.folder))
        assert settings_of(case)["case_format"] == 3 and path.exists()
    else:
        case = upgraded(open_case(case.folder))
        [step] = steps_to_4(case)
        assert (step["text"], "rekey" in step) == (FORMAT_4_TEXT, False) and not path.exists()
    assert suricata_rows(case) == rows and set(Journal(case).state.marks) == {marked}
    app = App(case)
    try:
        assert app.orphans == 0
    finally:
        app.con.close()


@pytest.mark.parametrize("content", [
    lambda run: json.dumps({run: {EVE_A: f"//?/D:/elsewhere/{EVE_A}"}}),
    lambda run: "{"], ids=["names under another root", "not JSON"])
def test_a_file_of_kept_names_is_not_used_when_the_case_has_no_events_database(tmp_path, monkeypatch, content):
    """A stop that kept names had an events database, and a case with none has no run with rows to finish. A file of
    names found there is stale or foreign, so the step takes the names from case.yaml's link as it does without it: the
    mark on an event follows its event, and the file goes with the entry."""
    case = linked_case_at_format_3(tmp_path, monkeypatch)
    [run] = read_runs(case)
    marked = sorted(suricata_rows(case))[0]
    mark_one(case, marked)
    case.db_path.unlink()
    (case.folder / RENAMED_FILE).write_text(content(run.run_id), encoding="utf-8")
    case = upgraded(open_case(case.folder))
    [step] = steps_to_4(case)
    assert settings_of(case)["case_format"] == 4 and set(step["rekey"]["pairs"]) == {marked}
    assert not (case.folder / RENAMED_FILE).exists()
    rebuild(case)
    assert set(suricata_rows(case).values()) == {EVE_A}
    app = App(case)
    try:
        assert app.orphans == 0 and set(app.journal.state.marks) == set(step["rekey"]["pairs"].values())
    finally:
        app.con.close()


def test_the_format_4_step_tells_two_files_a_folder_named_like_the_root_makes_alike_by_where_the_evidence_is(
        tmp_path, monkeypatch):
    """A single-host case's evidence folder is `moved`, and its run read `eve.json` and `moved/eve.json`, an empty file
    with no rows. The one name its rows carry, `.../moved/eve.json`, is the first file under the root `.../moved` or the
    second under that root's parent. Where the evidence is decides, so the marked event of `eve.json` takes its new ID."""
    (tmp_path / "evidence" / "moved").mkdir(parents=True)
    (tmp_path / "evidence" / "moved" / "eve.json").write_text("", encoding="utf-8")
    case = format3_case(linked_evidence_case(tmp_path, files=("eve.json",), single_host="SENSOR"))
    with loaded_under_the_written_root(monkeypatch):
        assert load_found_output(case, "suricata", "suricata_eve", "SENSOR", ["eve.json", "moved/eve.json"]).status == "ok"
    before = suricata_rows(case)
    assert before and all(source.startswith("//?/") for source in before.values())
    marked = sorted(before)[0]
    mark_one(case, marked)
    case = upgraded(open_case(case.folder))
    [step] = steps_to_4(case)
    assert set(step["rekey"]["pairs"]) == {marked} and not step["rekey"]["skipped_runs"]
    assert set(suricata_rows(case).values()) == {"eve.json"}
    app = App(case)
    try:
        assert app.orphans == 0
    finally:
        app.con.close()


def test_a_stop_after_the_entry_is_journaled_and_before_case_yaml_takes_4_removes_the_file_at_the_next_open(
        tmp_path, monkeypatch):
    """The file goes once the entry is journaled and case.yaml has the number. A stop between the two leaves the entry
    and the file; the next open finds the entry journaled, writes only the number, and removes the file."""
    case, _ = two_linked_runs(tmp_path, monkeypatch)

    def crashed(folder, values):
        raise OSError("stopped before case.yaml")

    with monkeypatch.context() as patched:
        patched.setattr(case_module, "_write_settings", crashed)
        with pytest.raises(CaseError, match=r"case\.yaml"):
            upgraded(open_case(case.folder))
    assert settings_of(case)["case_format"] == 3 and len(steps_to_4(case)) == 1 and (case.folder / RENAMED_FILE).exists()
    case = upgraded(open_case(case.folder))
    assert settings_of(case)["case_format"] == 4 and len(steps_to_4(case)) == 1
    assert not (case.folder / RENAMED_FILE).exists()


# ---------- the one place a rekey from format 3 to 4 can stand ----------

THIRD = "ab" * 16
MARK = ("mark", {"targets": [UID], "value": "suspicious"})
STEP = ("case_upgrade", {"who": SYSTEM, **rekey_of_found_output({UID: OTHER})})
SECOND_STEP = ("case_upgrade", {"who": SYSTEM, **rekey_of_found_output({OTHER: THIRD})})
STEP_WITHOUT_A_MAP = ("case_upgrade", {"who": SYSTEM, "from_format": 3, "to_format": 4, "text": "x"})
MANIFEST_RECORD = ("manifest_recorded", {"who": SYSTEM, "sha256": "1" * 64, "bytes": 10, "lines": 1, "via": "intake"})


def began_at(case_format, items) -> bytes:
    """A chain that starts with the case_created of a case of `case_format` (None: no format named, as a case_created
    from before the entry named one), then `items`, each naming the line before it."""
    named = {} if case_format is None else {"case_format": case_format}
    data = line_bytes(envelope(1, ZERO, "case_created", who="glessner", **created(**named)))
    for action, payload in items:
        data = add(data, action, **payload)
    return data


# Each place a rekey from 3 to 4 that describes its map is put: the format its case_created names, the lines, the
# breaks the journal has, and whether the marks end up on the first rekey's new ID
PLACES = {
    "a case that began at format 3": (3, [MARK, STEP], 0, True),
    "a case whose case_created names no format": (None, [MARK, STEP], 0, True),
    "a case that began at format 4": (4, [MARK, STEP], 1, False),
    "a case that holds a manifest record": (None, [MANIFEST_RECORD, MARK, STEP], 1, False),
    "a case that began at format 4, with a manifest record": (4, [MANIFEST_RECORD, MARK, STEP], 1, False),
    "a case whose step from 3 to 4 carries no map": (None, [MARK, STEP_WITHOUT_A_MAP, STEP], 1, False),
    "a second step from 3 to 4 after the first": (None, [MARK, STEP, SECOND_STEP], 1, True),
}


@pytest.mark.parametrize("place", PLACES)
def test_a_rekey_from_3_to_4_that_describes_its_map_stands_only_in_the_step_s_place(synthetic_case, place):
    """The step's rekey stands once, before any line a case at format 4 has: a case_created that names format 4, a
    manifest_recorded, or a case_upgrade from 3 to 4. Anywhere else a hand-made one that describes its map is a "rekey"
    break to the app and to the checker, and it translates nothing, whatever reader follows it: the replay, the journal,
    and the newest entry read from the file's end."""
    case_format, items, breaks, moved = PLACES[place]
    path = journal_path(synthetic_case)
    heads.forget(synthetic_case.folder)
    path.write_bytes(began_at(case_format, items))
    all_readers_agree(synthetic_case, path, breaks, moved)


# The lines a journal holds when it is first read, the rekey appended after them, and the marks that stay
CATCH_UPS = {
    "a manifest record": ([MANIFEST_RECORD, MARK], UID, STEP, {UID}),
    "the step's own entry": ([MARK, STEP], OTHER, SECOND_STEP, {OTHER}),
}


@pytest.mark.parametrize("place", CATCH_UPS)
def test_a_journal_that_read_past_the_line_that_closes_the_step_s_place_refuses_a_rekey_appended_after_it(
        synthetic_case, place):
    """A reader that catches up with the lines added since its last read finds the place closed by what it read before,
    as one that reads from the start does: a rekey from 3 to 4 appended after a manifest record, or after the step's own
    entry, is a "rekey" break and moves no mark, in the live state, in a fresh read, and in the replay, including the mark
    added in the same catch-up before the rekey."""
    lines, target, (action, payload), marks = CATCH_UPS[place]
    path = journal_path(synthetic_case)
    heads.forget(synthetic_case.folder)
    path.write_bytes(began_at(3, lines))
    journal = Journal(synthetic_case)
    assert set(journal.state.marks) == marks
    path.write_bytes(add(add(path.read_bytes(), "mark", targets=[target], value="malicious"), action, **payload))
    journal.refresh()
    assert [b["kind"] for b in journal.breaks] == ["rekey"] and set(journal.state.marks) == marks
    assert set(Journal(synthetic_case).state.marks) == marks == set(replay(path).marks)


def all_readers_agree(case, path, breaks: int, moved: bool) -> None:
    """The checker, check, the journal, the replay, and the newest entry from the file's end give `breaks` "rekey" breaks
    for the journal at `path`, and the marks on the first rekey's new ID when `moved`, on the old one otherwise."""
    code, out = run_checker(path)
    journal = Journal(case)
    assert [p["kind"] for p in check(path).problems] == ["rekey"] * breaks and (code == 0) == (not breaks), out
    assert ("a rekey of event IDs, from format 3 to 4" in out) == bool(breaks)
    assert [b["kind"] for b in journal.breaks] == ["rekey"] * breaks and bool(journal.read_only) == bool(breaks)
    assert set(replay(path).marks) == set(journal.state.marks) == ({OTHER} if moved else {UID})
    assert last_action(path)["targets"] == ([OTHER] if moved else [UID])
    assert len(journal.state.rekeys) == moved


# Each line that closes the step's place, with its action spelled by a \u escape that parses to the same word: the lines up
# to it, the action as written and as spelled, the lines after it, and whether the marks end up on the first rekey's new ID
SPELLED = {
    "a manifest record": ([MARK, MANIFEST_RECORD], (b'"manifest_recorded"', b'"manifest\\u005frecorded"'), [STEP], False),
    "the step's own entry": ([MARK, STEP], (b'"case_upgrade"', b'"case\\u005fupgrade"'), [SECOND_STEP], True),
}


@pytest.mark.parametrize("closer", SPELLED)
def test_a_line_that_closes_the_step_s_place_closes_it_whatever_way_it_spells_its_action(synthetic_case, closer):
    """A rekey after a manifest_recorded or after a first rekey from 3 to 4 is a "rekey" break whether or not the action
    is spelled with an escape, to every reader: the newest entry read from the file's end finds the same place as the
    checker, the journal, and the replay, and translates nothing through the rekey the others refuse."""
    before, (word, spelled), after, moved = SPELLED[closer]
    path = journal_path(synthetic_case)
    heads.forget(synthetic_case.folder)
    data = began_at(None, before).replace(word, spelled)
    assert data.count(spelled) == 1
    for action, payload in after:
        data = add(data, action, **payload)
    path.write_bytes(data)
    all_readers_agree(synthetic_case, path, 1, moved)


def test_a_hand_made_rekey_from_3_to_4_is_a_break_in_a_case_this_build_made(synthetic_case):
    """The case_created of a case this build made names its format, so a rekey from 3 to 4 appended to its journal, which
    no step of this case wrote, is a break to the app and to the checker."""
    path = journal_path(synthetic_case)
    first = json.loads(path.read_bytes().splitlines()[0])
    assert (first["action"], first["case_format"]) == ("case_created", 4)
    heads.forget(synthetic_case.folder)
    path.write_bytes(add(path.read_bytes(), "case_upgrade", who=SYSTEM, **rekey_of_found_output({UID: OTHER})))
    assert [p["kind"] for p in check(path).problems] == ["rekey"] and run_checker(path)[0] == 1
    journal = Journal(synthetic_case)
    assert [b["kind"] for b in journal.breaks] == ["rekey"] and not journal.state.rekeys


def test_case_created_names_the_format_of_the_case_it_starts(synthetic_case, tmp_path):
    """A new case names format 4; a case set back to format 3 names 3 when its chain starts; a case_created whose format
    isn't an integer is refused as an entry."""
    assert entries_of(synthetic_case)[0]["case_format"] == 4
    assert entries_of(format3_case(open_case(synthetic_case.folder)))[0]["case_format"] == 3
    for bad in ("4", 0, True):
        with pytest.raises(JournalError, match="case_format"):
            start_chain(synthetic_case, "cli", case_format=bad)


@pytest.mark.parametrize(("case_format", "whole"), [(3, True), (4, False)])
def test_a_rekey_from_3_to_4_lacking_its_lf_follows_the_chain_only_in_the_step_s_place(synthetic_case, case_format, whole):
    """The last line, without its LF, is the chain's next line when it is whole and could follow with one: the app adds
    the LF at its next write. A rekey from 3 to 4 that comes after a case_created naming format 4 couldn't follow, so it
    is not a line the app completes, and the checker says so in the same way."""
    path = journal_path(synthetic_case)
    heads.forget(synthetic_case.folder)
    path.write_bytes(began_at(case_format, [MARK, STEP])[:-1])
    found = check(path)
    code, out = run_checker(path)
    assert (found.tail == "missing_lf") == whole and not found.consistent and code == 1
    assert ("The entry is whole and follows the line before it" in out) == whole, out
