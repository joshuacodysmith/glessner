"""Case format 3 and its upgrade: a new case's chain, a copy's, case.yaml on record, the seal over a format 2 journal
and its tail, the open for work's order and read-only mode, the upgrade before every command that writes, the head
record of each writer, and two Apps or a command beside the server. The journal core's own tests are
test_journal_chain.py's; the format 2 step's, test_rekey.py's."""

import dataclasses
import hashlib
import itertools
import json
import os
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest
import yaml
from chain_fixtures import (
    AT,
    OTHER,
    UID,
    add,
    as_format,
    chained,
    created,
    envelope,
    format3_case,
    note,
    run_checker,
    seal,
    unchained,
    worked_at_format_3,
)
from conftest import serving
from test_rekey import HOLD, LOADS, found_eve_case
from test_server import login, request

from glessner import audit, heads
from glessner import case as case_module
from glessner import journal as journal_module
from glessner.case import CASE_FORMAT, CaseError, copy_case, create_case, open_case
from glessner.cli import main
from glessner.events import connect
from glessner.intake import intake
from glessner.journal import (
    DAMAGED,
    ENVELOPE,
    SYSTEM,
    ZERO,
    Journal,
    JournalError,
    check,
    host_layout,
    line_bytes,
    replay,
    start_chain,
)
from glessner.overview import journal_row
from glessner.queries import QueryError
from glessner.rekey import upgrade_chain, upgraded, upgraded_copy
from glessner.rules import BUILTIN_RULES
from glessner.server import (
    App,
    Hub,
    _journal_state,
    api_audit,
    api_audit_events,
    api_audit_export,
    api_event,
    api_undo_plan,
)
from glessner.start import start_copy
from glessner.version import build_id

RULE = "id: dc-logons\nsuggest: suspicious\nwhen: {field: event_code, equals: '4624'}\n"
CHANGED = "id: dc-logons\nsuggest: malicious\nwhen: {field: event_code, equals: '4624'}\n"
WRITES = "The journal was changed after it was written: "


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def journal_path(case) -> Path:
    return case.folder / "journal.jsonl"


def lines_of(case) -> list[bytes]:
    return journal_path(case).read_bytes().split(b"\n")[:-1]


def entries_of(case) -> list[dict]:
    return [json.loads(line) for line in lines_of(case) if line.strip()]


def settings_of(case) -> dict:
    return yaml.safe_load((case.folder / "case.yaml").read_text(encoding="utf-8"))


def opened(case) -> App:
    """The server's open for work, its connection closed, since the tests read the files."""
    app = App(case, for_work=True)
    app.con.close()
    return app


def builtin_rules(start: int = 1) -> list[dict]:
    """The built-in rules as a format 2 build's open journaled them."""
    return [{"seq": start + i, "at": AT, "who": "glessner", "action": "rule_add", "id": rule_id, "text": text,
             "builtin": True} for i, (rule_id, text) in enumerate(BUILTIN_RULES.items())]


def format2(case, *entries: dict, journal: bytes | None = None):
    """The case as a format 2 build left it: an unchained journal of the built-in rules and `entries`, or `journal`."""
    as_format(case.folder, 2, unchained(*builtin_rules(), *entries) if journal is None else journal)
    return open_case(case.folder)


def chain_links(case) -> list[bytes]:
    """The chained lines, after checking that each names the one before it and carries the whole envelope."""
    found = [line for line in lines_of(case) if b'"prev"' in line]
    for before, line in itertools.pairwise(found):
        entry = json.loads(line)
        assert entry["prev"] == sha(before) and entry["build"] and entry["client"] in ("server", "cli"), entry
    return found


def wait(job):
    for _ in range(600):
        if job.finished:
            break
        time.sleep(0.1)
    assert job.finished and not job.error, job.error
    return job


def listing(folder: Path) -> list[str]:
    return sorted(p.relative_to(folder).as_posix() for p in folder.rglob("*"))


# ---------- Format ----------

def test_a_new_case_starts_its_chain_and_every_writer_names_its_build_and_client(tmp_path, synthetic_case, monkeypatch,
                                                                                capsys):
    """A new case: line 1 is case_created with prev of 64 zeros and case.yaml's SHA-256, and each later line names the
    one before it and carries build and client, from the server and from each command-line writer, a built-in rule's
    update included."""
    (tmp_path / "ev" / "PC1").mkdir(parents=True)
    assert main(["new-case", str(tmp_path / "new"), "--evidence", str(tmp_path / "ev"), "--name", "N",
                 "--analyst", "cody"]) == 0
    new = open_case(tmp_path / "new")
    (line,) = lines_of(new)
    first = json.loads(line)
    assert list(first)[:7] == ["seq", "prev", "at", "who", "build", "client", "action"]
    assert (first["seq"], first["prev"], first["action"], first["who"], first["client"]) == (
        1, ZERO, "case_created", SYSTEM, "cli")
    assert first["case_yaml"] == sha((new.folder / "case.yaml").read_bytes()) and first["build"] == build_id()
    assert (first["name"], first["analyst"], first["evidence_path"]) == ("N", "cody", str(new.evidence))

    case = synthetic_case
    intake(case)
    opened(case)   # the server: case_open and the built-in rules
    monkeypatch.setitem(BUILTIN_RULES, "machine-accounts-authorized", BUILTIN_RULES["machine-accounts-authorized"]
                        + "# changed by a later build\n")
    assert main(["rule", str(case.folder), "list"]) == 0   # the command line: the built-in rule's update
    assert main(["close", str(case.folder)]) in (0, 1)
    entries = entries_of(case)
    assert entries[0]["action"] == "case_created" and len(chain_links(case)) == len(entries)
    by = {(e["action"], e["client"]) for e in entries}
    assert {("case_open", "server"), ("rule_add", "server"), ("rule_change", "cli"), ("case_setting", "cli")} <= by
    assert all(e["build"] == build_id() for e in entries)
    assert check(journal_path(case)).consistent


def source_case(tmp_path, synthetic_case, fmt: int):
    """A case of format `fmt` to copy, with a note in its journal: of this build's format, of format 3 as a format 3
    build made it, or of an older format."""
    case = synthetic_case
    if fmt < 3:
        as_format(case.folder, fmt, unchained(note(1), note(2, OTHER)))
        return open_case(case.folder)
    if fmt == 3:
        case = format3_case(case)
    Journal(case).append("note", target=UID, text="looked at it")
    return case


@pytest.mark.parametrize("route", ["cli", "page"])
@pytest.mark.parametrize("fmt", [CASE_FORMAT, 3, 2, 1])
def test_a_copy_starts_its_chain_naming_its_source(tmp_path, synthetic_case, fmt, route):
    """A copy made by copy-case or the start page's Copy: of a case with the chain, case_created at byte 0 naming the
    source and its head; of a format 2 case, a seal of 0 bytes, then case_created naming the source journal's bytes; of
    a format 1 case, the rekey case_upgrade unchained, a seal whose sealed.bytes is that line's length with its LF, then
    case_created. A copy of a source below format 4 then takes the 3 to 4 entry, so its case.yaml differs from the one
    case_created names only in the format. The source stays as it was."""
    source = source_case(tmp_path, synthetic_case, fmt)
    before = journal_path(source).read_bytes()
    target = tmp_path / "copy"
    if route == "cli":
        assert main(["copy-case", str(source.folder), str(target), "--name", "Copy", "--analyst", "tester"]) == 0
    else:
        wait(start_copy({"source": str(source.folder), "case_folder": str(target), "name": "Copy"}, "tester"))
    copy = open_case(target)
    client = "cli" if route == "cli" else "server"
    lines, entries = lines_of(copy), entries_of(copy)
    record = heads.read(copy.folder)
    assert (record["seq"], record["head"]) == (entries[-1]["seq"], sha(lines[-1]))
    settings = (copy.folder / "case.yaml").read_bytes()
    if fmt < CASE_FORMAT:   # the 3 to 4 step, after case_created
        *lines, _ = lines
        *entries, step = entries
        assert (step["action"], step["from_format"], step["to_format"], step["client"]) == ("case_upgrade", 3, 4, client)
        assert step["prev"] == sha(lines[-1]) and set(step) == {*ENVELOPE, "from_format", "to_format", "text"}
        settings = settings.replace(b"case_format: 4", b"case_format: 3")
    created = entries[-1]
    assert created["action"] == "case_created" and created["client"] == client
    assert created["case_yaml"] == sha(settings) and created["analyst"] == "tester"
    if fmt >= 3:
        (only,) = entries
        assert only["prev"] == ZERO and only["seq"] == 1
        assert created["copied_from"] == {"folder": str(source.folder), "head": sha(before.split(b"\n")[-2]),
                                          "seq": json.loads(before.split(b"\n")[-2])["seq"]}
    else:
        assert created["copied_from"] == {"folder": str(source.folder), "bytes": len(before), "sha256": sha(before)}
        seal = entries[-2]
        assert (seal["action"], seal["from_format"], seal["to_format"], seal["prev"]) == ("case_upgrade", 2, 3, ZERO)
        assert seal["client"] == client and created["prev"] == sha(lines[-2])
        if fmt == 2:
            assert len(entries) == 2 and seal["sealed"] == {"lines": 0, "bytes": 0, "sha256": sha(b"")}
        else:
            rekey = entries[0]
            assert len(entries) == 3 and "prev" not in rekey and (rekey["from_format"], rekey["to_format"]) == (1, 2)
            assert seal["sealed"] == {"lines": 1, "bytes": len(lines[0]) + 1, "sha256": sha(lines[0] + b"\n")}
    assert settings_of(copy)["case_format"] == CASE_FORMAT and check(journal_path(copy)).consistent
    assert journal_path(source).read_bytes() == before


def test_case_yaml_changed_by_hand_is_recorded_at_the_next_open(synthetic_case):
    """case.yaml on record: the analyst changed by hand gives a case_yaml entry at the next open, naming the new
    settings; an unchanged case.yaml writes none, and case_created records the first."""
    case = synthetic_case
    opened(case)
    assert not [e for e in entries_of(case) if e["action"] == "case_yaml"]
    path = case.folder / "case.yaml"
    path.write_text(path.read_text(encoding="utf-8").replace("analyst: cody", "analyst: tester"), encoding="utf-8")
    app = opened(open_case(case.folder))
    (entry,) = [e for e in entries_of(case) if e["action"] == "case_yaml"]
    assert entry["sha256"] == sha(path.read_bytes()) and entry["settings"]["analyst"] == "tester"
    assert entry["who"] == SYSTEM and app.journal.append("note", target=UID, text="x")["who"] == "tester"
    before = journal_path(case).read_bytes()
    opened(open_case(case.folder))
    assert journal_path(case).read_bytes() == before


# ---------- Tamper ----------

def at_format(synthetic_case, fmt: int):
    """synthetic_case as a build of format `fmt` made it: this build's, or format 3."""
    return format3_case(synthetic_case) if fmt == 3 else synthetic_case


def marked(case, n: int = 4) -> bytes:
    """The case opened for work by a build of its format, this build's or format 3, with `n` marks after it; the
    journal's bytes."""
    if case.settings.case_format == 3:
        worked_at_format_3(case, marks=0)
    else:
        opened(case)
    journal = Journal(case)
    for i in range(n):
        journal.append("mark", targets=[f"{i:032x}"], value="suspicious", note="first look")
    return journal_path(case).read_bytes()


def tampered(data: bytes, how: str) -> tuple[bytes, int]:
    """`data` with its third-from-last line changed, and the line whose prev no longer matches."""
    lines = data.split(b"\n")[:-1]
    i = len(lines) - 3
    line = lines[i]
    if how == "payload":
        lines[i] = line.replace(b"first look", b"first lock")
    elif how == "prev":
        at = line.index(b'"prev": "') + 9
        lines[i] = line[:at] + (b"0" if line[at:at + 1] != b"0" else b"1") + line[at + 1:]
    else:
        lines[i] = line.replace(b'"seq": ', b'"seq":  ', 1)
    return b"".join(x + b"\n" for x in lines), (i + 1 if how == "prev" else i + 2)


@pytest.mark.parametrize("fmt", [3, CASE_FORMAT])
@pytest.mark.parametrize("how", ["payload", "prev", "spacing"])
def test_a_changed_line_opens_the_case_read_only(synthetic_case, how, fmt):
    """A changed line: one byte changed in a middle line's payload, in its prev, or in its spacing is a break at the
    line whose prev names it (or, for its own prev, at that line), and the open writes nothing. A format 3 case stays
    at 3."""
    case = at_format(synthetic_case, fmt)
    data = marked(case)
    changed, line = tampered(data, how)
    journal_path(case).write_bytes(changed)
    app = opened(case)
    assert app.journal.read_only.startswith(f"{WRITES}line {line}: prev doesn't match line {line - 1}")
    assert journal_path(case).read_bytes() == changed and settings_of(case)["case_format"] == fmt


UNDO = {"undoes": 1, "correction": "accident",
        "changes": [{"action": "mark", "targets": [UID], "value": "unreviewed"}]}
UNDO_TWO = {**UNDO, "changes": [{"action": "mark", "targets": [UID], "value": "suspicious"},
                                {"action": "mark", "targets": [OTHER], "value": "suspicious"}]}
# Entries the writer validated, and the change that leaves a whole line replay can't apply: each action's
# payload read the way _apply reads it, and an undo whose first change applies before its second one fails
UNREPLAYABLE = {
    "mark targets null": ("mark", {"targets": [UID], "value": "suspicious"}, lambda e: e.update(targets=None)),
    "mark without value": ("mark", {"targets": [UID], "value": "suspicious"}, lambda e: e.pop("value")),
    "mark value that is no mark value": ("mark", {"targets": [UID], "value": "suspicious"},
                                         lambda e: e.update(value=["x"])),
    "followup targets null": ("followup", {"targets": [UID], "done": True}, lambda e: e.update(targets=None)),
    "finding add without title": ("finding", {"op": "add", "title": "T", "severity": "High"},
                                  lambda e: e.pop("title")),
    "undo changes null": ("undo", UNDO, lambda e: e.update(changes=None)),
    "undo second change targets null": ("undo", UNDO_TWO, lambda e: e["changes"][1].update(targets=None)),
    "host_split routes null": ("host_split", {"host": "DC01", "op": "split", "routes": {"pc-a": "PCA"}},
                               lambda e: e.update(routes=None)),
}


def with_a_changed_payload(case, name: str, table: dict | None = None) -> tuple[int, int]:
    """The case opened for work, then an action and a note after it, journaled as the app writes them, and the action's
    line changed by `table`[name] (UNREPLAYABLE) with the note's left as it was: the number of the changed entry, and the
    line of the note, which no longer follows it."""
    action, payload, change = (table or UNREPLAYABLE)[name]
    opened(case)
    journal = Journal(case)
    seq = journal.append(action, **payload)["seq"]
    journal.append("note", target=UID, text="after the change")
    found = journal_path(case).read_bytes().split(b"\n")[:-1]
    entry = json.loads(found[-2])
    change(entry)
    found[-2] = json.dumps(entry, ensure_ascii=False).encode("utf-8")
    journal_path(case).write_bytes(b"".join(x + b"\n" for x in found))
    return seq, len(found)


@pytest.mark.parametrize("name", list(UNREPLAYABLE))
def test_a_changed_payload_replay_cannot_apply_opens_read_only(synthetic_case, name):
    """A changed line whose envelope is whole but whose payload _apply can't apply opens the case read-only, and Continue
    writes its chain_break without stranding the case. The state is built again without the line, whatever _apply had
    done to it before it failed: nothing of the entry is applied, the note after it is, and the trail shows the entry
    marked, worded as one replay can't apply."""
    case = synthetic_case
    seq, last = with_a_changed_payload(case, name)
    path = journal_path(case)
    assert [(p["line"], p["kind"]) for p in check(path).problems] == [(last, "prev")]
    app = opened(case)
    assert app.journal.read_only.startswith(f"{WRITES}line {last}: prev doesn't match")
    for state in (app.journal.state, replay(path)):
        assert [n["text"] for n in state.notes[UID]] == ["after the change"]
        assert not (state.marks or state.followed or state.findings or state.splits), name
    assert host_layout(case) == {}
    found = check(path, keep=True)
    assert [e["seq"] for e in found.entries if e.get(DAMAGED)] == [seq] and found.problems == check(path).problems
    shown = {r["seq"]: r for r in audit.rows(found.entries, {})["rows"]}
    assert "stored payload can't be replayed" in shown[seq]["text"] and not shown[seq]["undoable"]
    assert "stored payload can't be replayed" in audit.markdown(found.entries, "Synthetic", {})
    with pytest.raises(audit.AuditError, match="can't be undone"):
        audit.plan_undo(found.entries, seq)
    entry = app.journal.record_break("looked at the change")   # Continue: it wrote its line, and the case still opens
    assert entry["action"] == "chain_break"
    assert [n["text"] for n in app.journal.state.notes[UID]] == ["after the change"] and not app.journal.state.marks
    assert not Journal(case).read_only


@pytest.mark.parametrize("name", list(UNREPLAYABLE))
def test_the_trail_and_its_export_list_an_entry_replay_cannot_apply(synthetic_case, name):
    """After Continue the trail, its filter by event, and its Markdown export read every entry, a damaged one too, and
    name it by what it is, so the chain_break's line doesn't point at an entry the trail doesn't show."""
    case = synthetic_case
    seq, _ = with_a_changed_payload(case, name)
    app = App(case, for_work=True)
    try:
        app.journal.record_break("looked at the change")
        words = "stored payload can't be replayed"
        assert words in {r["seq"]: r for r in api_audit(app, {})["rows"]}[seq]["text"]
        assert seq not in {r["seq"] for r in api_audit(app, {"event": [UID]})["rows"]}
        exported = api_audit_export(app, {})
        assert words in Path(exported["path"]).read_text(encoding="utf-8")
    finally:
        app.con.close()


@pytest.mark.parametrize("fmt", [3, CASE_FORMAT])
def test_every_write_is_refused_on_a_broken_chain(synthetic_case, tmp_path, capsys, fmt):
    """A changed line, end to end: the case opens read-only, and every write path through the API and the command line
    is refused with the reason, the journal's bytes unchanged. A format 3 case stays at 3."""
    case = at_format(synthetic_case, fmt)
    intake(case)
    marked(case, 0)
    con = connect(case.db_path, read_only=True)
    uid = con.execute("SELECT event_uid FROM events LIMIT 1").fetchone()[0]
    con.close()
    journal = Journal(case)
    noted = journal.append("note", target=uid, text="first look")["seq"]
    mark = journal.append("mark", targets=[uid], value="suspicious")["seq"]
    for i in range(3):
        journal.append("mark", targets=[f"{i:032x}"], value="suspicious", note="first look")
    changed, line = tampered(journal_path(case).read_bytes(), "payload")
    journal_path(case).write_bytes(changed)
    rule_file = tmp_path / "rule.yaml"
    rule_file.write_text(RULE, encoding="utf-8")
    for app, port, _ in serving(case):
        assert app.journal.read_only
        session = login(port, app)
        writes = {"/api/mark": {"uids": [uid], "value": "malicious"}, "/api/note": {"uid": uid, "text": "x"},
                  "/api/tag": {"uids": [uid], "add": ["tactic:TA0008"]},
                  "/api/tag_suggestion": {"uids": [uid], "tags": ["tactic:TA0008"], "decision": "dismissed"},
                  "/api/setting": {"name": "event_threshold", "value": 20000},
                  "/api/host": {"host": "DC01", "role": "Domain controllers"},
                  "/api/rule": {"op": "add", "text": RULE},
                  "/api/suggestion": {"decision": "reject", "source": "hayabusa", "uids": [uid]},
                  "/api/undo": {"seq": mark}, "/api/note_retract": {"uid": uid, "note_seq": noted},
                  # The writers that append to the journal, and the exports, refused before they write their files
                  "/api/followup": {"uids": [uid], "done": True},
                  "/api/finding": {"op": "add", "title": "x", "severity": "Low"},
                  "/api/export": {"start": 0, "end": 2**53, "format": "csv", "marks": "all"},
                  "/api/report": {}, "/api/audit_export": {}}
        for path, body in writes.items():
            res, answer = request(port, "POST", path, session=session, body=body)
            error = json.loads(answer).get("error", "")
            assert res.status == 400 and error.startswith(f"{WRITES}line {line}"), (path, error)
    for argv in (["close", str(case.folder)], ["rule", str(case.folder), "add", str(rule_file)],
                 ["rule", str(case.folder), "remove", "machine-accounts-authorized"], ["export", str(case.folder)],
                 ["findings", str(case.folder)]):
        assert main(argv) == 2, argv
        err = capsys.readouterr().err
        assert f"Error: {WRITES}line {line}" in err and f'"glessner verify {case.folder} --journal" lists' in err, err
    assert journal_path(case).read_bytes() == changed and settings_of(case)["case_format"] == fmt
    assert not any((case.folder / "exports").glob("*"))   # no file without its record


def tamper_cases(data: bytes) -> dict[str, bytes]:
    """The tamper cases on a chained journal, each the bytes as they would stand at the next open."""
    lines = data.split(b"\n")[:-1]
    join = lambda found: b"".join(x + b"\n" for x in found)
    forged = json.loads(lines[-3])
    forged.update(seq=forged["seq"], prev=sha(lines[-4]), note="forged")
    return {
        "payload": tampered(data, "payload")[0], "prev": tampered(data, "prev")[0],
        "deleted": join(lines[:-3] + lines[-2:]), "swapped": join(lines[:-3] + [lines[-2], lines[-3], lines[-1]]),
        "inserted": join(lines[:-3] + [journal_module.line_bytes(forged)[:-1]] + lines[-3:]),
        "blank": join(lines[:-2] + [b""] + lines[-2:]), "empty": b"", "moved": unchained(note(1)) + data,
        "second zeros": join(lines[:1] + [lines[1].replace(json.loads(lines[1])["prev"].encode(), ZERO.encode())]
                             + lines[2:]),
        "newest edited": join(lines[:-1] + [lines[-1].replace(b"first look", b"first lock")]),
        "newest removed": join(lines[:-2]), "crlf": data.replace(b"\n", b"\r\n"),
        "nul tail": data[:-20] + b"\0" * 19 + b"\n", "nul tail without lf": data[:-21] + b"\0" * 20,
    }


@pytest.mark.parametrize("fmt", [3, CASE_FORMAT])
def test_the_checks_come_before_any_write(synthetic_case, fmt):
    """Checks before writes: for each tamper case, the journal's bytes and the case folder's listing are the same after
    an open for work as before it, and the case is read-only. A format 3 case stays at 3."""
    case = at_format(synthetic_case, fmt)
    data = marked(case)
    for name, changed in tamper_cases(data).items():
        journal_path(case).write_bytes(changed)
        files = listing(case.folder)
        app = opened(case)
        assert app.journal.read_only and settings_of(case)["case_format"] == fmt, name
        assert journal_path(case).read_bytes() == changed and listing(case.folder) == files, name
    journal_path(case).write_bytes(data)
    assert not opened(case).journal.read_only


def rekey_line(seq: int) -> dict:
    return {"seq": seq, "at": AT, "who": "glessner", "action": "case_upgrade", "from_format": 1, "to_format": 2,
            "text": "Event IDs no longer depend on where or in which time zone a tool ran.",
            "rekey": {"pairs": {UID: OTHER}}}


def sealed_case(synthetic_case):
    """A format 2 case with a mark, a note, and the rekey line format 2's step wrote, opened for work, so sealed and at
    format 4."""
    rules = builtin_rules(3)
    case = format2(synthetic_case, journal=unchained(
        {"seq": 1, "at": AT, "who": "cody", "action": "mark", "targets": [UID], "value": "malicious"},
        rekey_line(2), *rules, note(len(rules) + 3, OTHER)))
    app = opened(case)
    assert not app.journal.read_only and settings_of(case)["case_format"] == 4
    return open_case(case.folder)


def test_a_change_to_the_unchained_region_is_a_break_of_its_kind(synthetic_case):
    """The unchained region, on an upgraded case: the unchained lines deleted, or replaced by other bytes of the same
    length; a byte changed before the seal, in a format 2 line and in the rekey line; the seal removed; a line without
    prev appended after the chain began, as a format 2 build would; case.yaml at 4 with the chained lines cut. Each is a
    break of its kind, and the open writes nothing."""
    case = sealed_case(synthetic_case)
    data = journal_path(case).read_bytes()
    lines = data.split(b"\n")[:-1]
    seal = next(i for i, line in enumerate(lines) if b'"prev"' in line)
    unchained_part = b"".join(x + b"\n" for x in lines[:seal])
    rest = data[len(unchained_part):]
    other = unchained_part.replace(b"cody", b"eve!")
    assert len(other) == len(unchained_part) and other != unchained_part
    cases = {"deleted": (rest, "chain_missing"), "replaced": (other + rest, "chain_missing"),
             "format 2 line": (data.replace(b"looked at it", b"looked at if", 1), "chain_missing"),
             "rekey line": (data.replace(OTHER.encode(), UID.encode(), 1), "chain_missing"),
             "seal removed": (unchained_part + b"".join(x + b"\n" for x in lines[seal + 1:]), "chain_missing"),
             "no prev": (data + unchained(note(99)), "no_prev"),
             "chained lines cut": (unchained_part, "chain_missing")}
    for name, (changed, kind) in cases.items():
        journal_path(case).write_bytes(changed)
        app = opened(case)
        assert kind in [b["kind"] for b in app.journal.breaks], name
        assert journal_path(case).read_bytes() == changed, name


def test_a_case_set_back_to_format_2_is_refused_with_the_head_record_and_sealed_again_without(synthetic_case):
    """case.yaml set back to 2 and the chained lines cut. With the head this app recorded, the seal step stops before
    writing, naming the record's file; without it, the open seals the journal again, which the chain alone can't
    show."""
    case = sealed_case(synthetic_case)
    Journal(case).append("mark", targets=[OTHER], value="suspicious")
    data = journal_path(case).read_bytes()
    seal = json.loads(next(line for line in data.split(b"\n") if b'"prev"' in line))
    cut = data[:seal["sealed"]["bytes"]]
    path = case.folder / "case.yaml"
    path.write_text(path.read_text(encoding="utf-8").replace("case_format: 4", "case_format: 2"), encoding="utf-8")
    journal_path(case).write_bytes(cut)
    settings = path.read_bytes()
    with pytest.raises(CaseError, match="recorded the head of its chain") as caught:
        Hub(open_case(case.folder))
    assert str(heads.path_for(case.folder)) in str(caught.value)
    assert journal_path(case).read_bytes() == cut and path.read_bytes() == settings
    heads.forget(case.folder)
    app = opened(open_case(case.folder))
    assert not app.journal.read_only and settings_of(case)["case_format"] == 4
    assert journal_path(case).read_bytes().startswith(cut) and len(chain_links(case)) > 1


def table_columns(case) -> list[str]:
    con = connect(case.db_path, read_only=True)
    try:
        return [name for name, *_ in con.execute("DESCRIBE events").fetchall()]
    finally:
        con.close()


def as_an_older_build_left_it(case) -> list[str]:
    """The events table without format 3's two columns, as a format 1 or 2 build leaves it; the columns it has."""
    con = connect(case.db_path)
    try:
        for column in ("account_key", "hashes"):
            con.execute(f"ALTER TABLE events DROP COLUMN {column}")
    finally:
        con.close()
    return table_columns(case)


def files_of(folder: Path) -> dict[str, bytes]:
    """Every file of the case folder but the events database, whose bytes change when it is opened for writing."""
    return {p.relative_to(folder).as_posix(): p.read_bytes() for p in sorted(folder.rglob("*"))
            if p.is_file() and not p.name.startswith("events.duckdb")}


@pytest.mark.parametrize("older", [1, 2])
def test_a_set_back_case_is_refused_before_a_step_writes_anything(synthetic_case, older):
    """The head-record check comes before format 2's step, the pins, and the fill, so a refusal that says "Nothing was
    changed" has added no table columns, written no format 2, and pinned no runs. It holds for a case set back to
    format 2 and to format 1: the files and the table are as they were."""
    case = sealed_case(synthetic_case)
    data = journal_path(case).read_bytes()
    cut = data[:json.loads(next(line for line in data.split(b"\n") if b'"prev"' in line))["sealed"]["bytes"]]
    path = case.folder / "case.yaml"
    path.write_text(path.read_text(encoding="utf-8").replace("case_format: 4", f"case_format: {older}" if older > 1 else ""),
                    encoding="utf-8")
    journal_path(case).write_bytes(cut)
    columns = as_an_older_build_left_it(case)
    before = files_of(case.folder)
    with pytest.raises(CaseError, match="recorded the head of its chain"):
        upgraded(open_case(case.folder))
    assert files_of(case.folder) == before and table_columns(case) == columns
    assert "account_key" not in columns and case_module.open_case(case.folder).settings.case_format == older


def test_an_unreadable_journal_refuses_the_seal_step_before_it_writes_anything(synthetic_case):
    """The same order for the journal check: a line format 2's reader can't read stops the step before its connection
    adds the columns, not after the pins and the fill."""
    case = format2(synthetic_case, journal=unchained(note(1)) + b"{not json\n" + unchained(note(3)))
    columns = as_an_older_build_left_it(case)
    before = files_of(case.folder)
    with pytest.raises(CaseError, match="its journal can't be read"), upgrade_chain(case):
        pass
    assert files_of(case.folder) == before and table_columns(case) == columns


def test_a_whole_unchained_line_the_reader_cant_apply_refuses_the_seal_step_before_it_writes_anything(synthetic_case):
    """A whole line that parses but that _apply refuses stops the step with the CaseError of a journal that can't be
    read, not a bare TypeError, and the seal step's check is the one that says so."""
    bad = {"seq": 2, "at": AT, "who": "cody", "action": "mark", "targets": None, "value": "suspicious"}
    case = format2(synthetic_case, journal=unchained(note(1), bad, note(3)))
    columns = as_an_older_build_left_it(case)
    before = files_of(case.folder)
    with pytest.raises(CaseError, match="its journal can't be read"), upgrade_chain(case):
        pass
    assert files_of(case.folder) == before and table_columns(case) == columns


UNENDED = {
    "a seq no integer reads": unchained(note("x"))[:-1],
    "a mark without targets": unchained({"seq": 2, "at": AT, "who": "cody", "action": "mark", "targets": None,
                                         "value": "suspicious"})[:-1],
    "an array": b"[1, 2]",
}


@pytest.mark.parametrize("name", list(UNENDED))
@pytest.mark.parametrize("older", [1, 2])
def test_an_unended_entry_the_reader_cant_apply_refuses_before_any_write(synthetic_case, older, name):
    """The reader that stops at the last LF never sees a last line without one, so the preflight must catch a complete
    JSON object that _mend refuses, before the connection adds the two columns and the step fills them. Both steps ask
    first, in a format 1 case and a format 2 case, through the command line's upgrade and the server's open: the files,
    the table's columns, and the format are as they were."""
    as_format(synthetic_case.folder, older, unchained(note(1)) + UNENDED[name])
    case = open_case(synthetic_case.folder)
    columns = as_an_older_build_left_it(case)
    before = files_of(case.folder)
    for refused in (lambda: upgraded(open_case(case.folder)), lambda: App(open_case(case.folder), for_work=True)):
        with pytest.raises(CaseError, match="Nothing was changed"):
            refused()
        assert files_of(case.folder) == before and table_columns(case) == columns
        assert "account_key" not in columns and open_case(case.folder).settings.case_format == older


# ---------- Upgrade ----------

def journals_of_format_2() -> dict[str, tuple[bytes, bool]]:
    """Synthetic format 2 journals, each with whether its last entry lacks its LF."""
    marks = unchained(
        {"seq": 1, "at": AT, "who": "cody", "action": "mark", "targets": [UID, OTHER], "value": "suspicious"},
        note(2), {"seq": 3, "at": AT, "who": "cody", "action": "undo", "undoes": 1, "correction": "accident",
                  "changes": [{"action": "mark", "targets": [OTHER], "value": "unreviewed"}]},
        {"seq": 4, "at": AT, "who": "cody", "action": "host_split", "host": "DC01", "op": "split",
         "routes": {"pc-a": "PCA"}, "stays": []})
    return {
        "marks, notes, undo, a split, blank lines": (marks[:40] + marks[40:].replace(b"\n", b"\n\n", 1) + b"   \n", False),
        "empty": (b"", False),
        "last entry without its LF": (unchained(note(1), note(2, OTHER))[:-1], True),
        "a rekey after marks": (unchained({"seq": 1, "at": AT, "who": "cody", "action": "mark", "targets": [UID],
                                           "value": "malicious"}, rekey_line(2)), False),
    }


def state(path: Path) -> dict:
    """The replayed state of what analysts did: the built-in rules and numbers aside, which the open adds."""
    found = dataclasses.asdict(replay(path))
    for name in ("rules", "removed_rules", "last_seq"):
        found.pop(name)
    return found


@pytest.mark.parametrize("name", list(journals_of_format_2()))
def test_a_format_2_journal_is_sealed_as_it_stands(tmp_path, synthetic_case, name):
    """A format 2 journal is sealed as it stands: the unchained bytes are the same after the open, apart from an LF
    added to a last entry without one; the seal's fields are right and cover the rekey line; case.yaml says 4; the
    replayed state, translated IDs included, is the same before and after, apart from the new entries. The open's
    case_yaml for format 3, the 3 to 4 entry, and its case_yaml for format 4 follow the seal, then case_open."""
    data, open_end = journals_of_format_2()[name]
    case = format2(synthetic_case, journal=data)
    as_read = tmp_path / "as_format_2_read_it.jsonl"   # format 2's reader applied a last line without its LF
    as_read.write_bytes(data + b"\n" if open_end else data)
    expected = state(as_read)
    app = opened(case)
    whole = data + b"\n" if open_end else data
    after = journal_path(case).read_bytes()
    assert after.startswith(whole) and not app.journal.read_only and settings_of(case)["case_format"] == 4
    seal, *written = [json.loads(line) for line in after[len(whole):].split(b"\n")[:-1]]
    assert [(e["action"], e.get("from_format"), e.get("to_format")) for e in written[:4]] == [
        ("case_yaml", None, None), ("case_upgrade", 3, 4), ("case_yaml", None, None), ("case_open", None, None)]
    assert [e["settings"]["case_format"] for e in written if e["action"] == "case_yaml"] == [3, 4]
    nonblank = sum(1 for line in whole.split(b"\n") if line.strip())
    assert (seal["action"], seal["from_format"], seal["to_format"], seal["prev"], seal["who"]) == (
        "case_upgrade", 2, 3, ZERO, SYSTEM)
    assert seal["sealed"] == {"lines": nonblank, "bytes": len(whole), "sha256": sha(whole)}
    assert seal["seq"] == max([json.loads(x)["seq"] for x in whole.split(b"\n") if x.strip()], default=0) + 1
    assert seal["recovered"] == [{"completed": True, "entry": {"action": "note", "seq": 2}}] if open_end else (
        "recovered" not in seal)
    assert seal["text"].startswith("Sealed the" if whole else "Started the hash chain")
    assert state(journal_path(case)) == expected and check(journal_path(case)).consistent
    if name == "a rekey after marks":
        assert set(app.journal.state.marks) == {OTHER}


def test_a_format_1_case_goes_to_format_3_in_one_open(tmp_path):
    """A format 1 case goes to format 3 in one open, and on to 4: format 2's step journals its rekey entry unchained,
    then the seal covers it, the 3 to 4 entry follows the open's case_yaml, and the mark's event has its new ID in
    replay, the trail, and the Event page."""
    f, uid = found_eve_case(tmp_path)
    app = App(f.case, for_work=True)
    try:
        lines = lines_of(f.case)
        rekey, seal = json.loads(lines[1]), json.loads(lines[2])
        assert "prev" not in rekey and (rekey["from_format"], rekey["to_format"]) == (1, 2)
        assert (seal["from_format"], seal["to_format"]) == (2, 3)
        assert seal["sealed"]["bytes"] == len(lines[0]) + len(lines[1]) + 2
        after = [json.loads(line) for line in lines[3:6]]
        assert [(e["action"], e.get("from_format"), e.get("to_format")) for e in after] == [
            ("case_yaml", None, None), ("case_upgrade", 3, 4), ("case_yaml", None, None)]
        new = rekey["rekey"]["pairs"][uid]
        assert new != uid and app.journal.state.marks[new].value == "malicious"
        assert replay(journal_path(f.case)).marks.keys() == {new}
        assert api_audit(app, {"event": [new]})["total"] == 1
        assert api_event(app, {"uid": [new]})["event"]["mark"]["label"] == "Malicious"
    finally:
        app.con.close()
    assert settings_of(f.case)["case_format"] == 4 and check(journal_path(f.case)).consistent


TAILS = {"seq 1.0": b'{"seq": 1.0, "at": "", "who": "cody", "action": "note", "target": "x", "text": "y"}',
         'seq "1"': b'{"seq": "1", "at": "", "who": "cody", "action": "note", "target": "x", "text": "y"}',
         "no seq": b'{"at": "", "who": "cody", "action": "case_setting", "name": "event_threshold", "value": 5}',
         "spaces": b"    "}


@pytest.mark.parametrize("name", list(TAILS))
def test_an_unchained_tail_format_2_s_reader_applies_gets_its_line_end(tmp_path, synthetic_case, name):
    """Unchained tails format 2's reader accepts: a last line without its LF that format 2's reader applied, or one of
    only spaces, gets its LF; the seal's recovered names it, no side file is written, and the replayed state is the same
    as format 2's reader gave."""
    tail = TAILS[name]
    data = unchained(note(1, OTHER)) + tail
    case = format2(synthetic_case, journal=data)
    as_read = tmp_path / "as_read.jsonl"
    as_read.write_bytes(data + b"\n")
    expected = state(as_read)
    opened(case)
    after = journal_path(case).read_bytes()
    seal = json.loads(after[len(data) + 1:].split(b"\n")[0])
    held = json.loads(tail) if tail.strip() else None
    entry = {"action": held.get("action"), "seq": held.get("seq")} if held else None
    assert after.startswith(data + b"\n") and seal["recovered"] == [{"completed": True, "entry": entry}]
    assert not list(case.folder.glob("journal_torn_*")) and state(journal_path(case)) == expected


def test_an_unchained_tail_format_2_s_reader_failed_on_stops_the_upgrade(synthetic_case):
    """A last line that parses but that format 2's reader fails on stops the upgrade with the line's number, and the
    journal's bytes and case.yaml are unchanged."""
    data = unchained(note(1, OTHER)) + b'{"seq": "x", "at": "", "who": "cody", "action": "note", "target": "x"}'
    case = format2(synthetic_case, journal=data)
    settings = (case.folder / "case.yaml").read_bytes()
    with pytest.raises(CaseError, match="line 2 is JSON that the journal's reader can't apply"):
        Hub(case)
    assert journal_path(case).read_bytes() == data and (case.folder / "case.yaml").read_bytes() == settings


def test_a_torn_format_2_journal_is_sealed_with_its_torn_line_aside_well_within_the_lock_wait(synthetic_case):
    """A torn format 2 journal, and the journal lock: the torn bytes are saved byte for byte, the seal covers the whole
    lines, and its recovered names the side file; the open, whose seal step holds the journal's context while the record
    and the mend take it again, ends well within the 10 s an append waits."""
    whole = unchained(*builtin_rules(), note(5))
    torn = b'{"seq": 6, "at": "2026-10-17T02:1'
    case = format2(synthetic_case, journal=whole + torn)
    started = time.monotonic()
    opened(case)
    assert time.monotonic() - started < journal_module.LOCK_WAIT / 2
    (side,) = case.folder.glob("journal_torn_*.bin")
    assert side.read_bytes() == torn
    after = journal_path(case).read_bytes()
    seal = json.loads(after[len(whole):].split(b"\n")[0])
    assert after.startswith(whole) and seal["sealed"]["bytes"] == len(whole)
    assert seal["recovered"] == [{"saved_as": side.name, "bytes": len(torn), "sha256": sha(torn)}]


def test_a_crash_after_the_seal_writes_case_yaml_and_no_second_seal(synthetic_case, monkeypatch):
    """An interrupted upgrade: a crash after the seal and before case.yaml, then the next open writes case.yaml and no
    second seal, and the 3 to 4 step follows. A fault between the temporary file and the replace leaves the old
    case.yaml whole."""
    case = format2(synthetic_case, note(5))
    real = case_module._write_settings
    path = case.folder / "case.yaml"
    before = path.read_bytes()

    def crashed(folder, settings):
        raise OSError("stopped before case.yaml")

    real_replace = os.replace

    def refused(src, dst):
        if Path(dst).name == "case.yaml":
            raise PermissionError(13, "The process cannot access the file because it is being used by another process")
        return real_replace(src, dst)

    for fault in (lambda: monkeypatch.setattr(case_module, "_write_settings", crashed),
                  lambda: monkeypatch.setattr(os, "replace", refused)):
        fault()
        with pytest.raises(CaseError, match=r"case\.yaml"):
            Hub(open_case(case.folder))
        monkeypatch.undo()
        assert path.read_bytes() == before and settings_of(case)["case_format"] == 2
        assert case_module._write_settings is real
    seals = [e for e in entries_of(case) if e["action"] == "case_upgrade"]
    assert len(seals) == 1 and seals[0]["to_format"] == 3
    app = opened(open_case(case.folder))
    assert settings_of(case)["case_format"] == 4 and not app.journal.read_only
    assert [e["to_format"] for e in entries_of(case) if e["action"] == "case_upgrade"] == [3, 4]


def cut_before_its_lf(monkeypatch) -> None:
    """The next write to the journal reaches the file one byte short, its LF missing, and fails: a line cut just before
    its end. Undo the patch with monkeypatch.undo()."""
    real = Journal._write

    def short(self, data):
        real(self, data[:-1])
        raise OSError("stopped before the line end")

    monkeypatch.setattr(Journal, "_write", short)


def a_cut_seal(case, monkeypatch) -> bytes:
    """A format 2 case whose seal was cut just before its LF: case.yaml still says 2. The journal's bytes."""
    cut_before_its_lf(monkeypatch)
    with pytest.raises((OSError, CaseError)):
        upgraded(case)
    monkeypatch.undo()
    return journal_path(case).read_bytes()


def test_a_seal_cut_just_before_its_lf_is_completed_at_the_next_open(synthetic_case, tmp_path, monkeypatch):
    """The seal's write stops one byte short, so case.yaml still says 2. The next open writes format 3 through
    has_chain, and the shared reader, which stops before a line without its LF, would then find no chain: the case would
    open read-only, "chain missing", with Continue refused. The seal is the chain's start as it would be with its LF (its
    `sealed` names every byte before it), so the open ends it, journals that, and the case opens for work, after the 3
    to 4 step."""
    case = format2(synthetic_case, note(5))
    path = journal_path(case)
    old = path.read_bytes()
    cut = a_cut_seal(case, monkeypatch)
    assert settings_of(case)["case_format"] == 2 and cut.startswith(old) and not cut.endswith(b"\n")
    assert check(path).tail == "missing_lf" and [p["kind"] for p in check(path).problems] == ["missing_lf"]   # no "chain missing"
    code, out = run_checker(path)   # the checker names a seal missing only its LF so, and not as a missing chain
    assert code == 1 and "has no line end" in out and "no chained line" not in out
    app = opened(open_case(case.folder))
    after = path.read_bytes()
    assert settings_of(case)["case_format"] == 4 and not app.journal.read_only and app.journal.chain.chained
    assert after.startswith(cut + b"\n") and len(after) > len(cut) + 1
    upgrades = [e for e in entries_of(case) if e["action"] == "case_upgrade"]
    assert [e["to_format"] for e in upgrades] == [3, 4]
    seals = upgrades[:1]
    assert seals[0]["sealed"]["bytes"] == len(old)
    recovered = json.loads(after[len(cut) + 1:].split(b"\n")[0])
    assert (recovered["action"], recovered["completed"], recovered["entry"]) == (
        "journal_recovered", True, {"action": "case_upgrade", "seq": seals[0]["seq"]})
    result = check(path)
    assert result.consistent and result.chain.start["action"] == "case_upgrade"
    code, out = run_checker(path)
    assert code == 0 and f"head {result.head} (entry #{result.seq})" in out
    before = tmp_path / "before_the_seal.jsonl"   # the journal as format 2's reader applied it
    before.write_bytes(old)
    assert state(path) == state(before)


@pytest.mark.parametrize("build_format", [3, CASE_FORMAT])
def test_a_command_s_first_append_completes_a_seal_cut_just_before_its_lf(synthetic_case, monkeypatch, build_format):
    """The command line's upgrade and first append after the same cut aren't refused with "until the case is
    upgraded". A format 3 build's upgrade ends at the seal, still cut, so the command's note is the first append: it
    ends the seal, journals that, and takes its own number. In this build the 3 to 4 step's checks end the seal before
    its entry, and the note follows the step."""
    case = format2(synthetic_case, note(5))
    cut = a_cut_seal(case, monkeypatch)
    monkeypatch.setattr(case_module, "CASE_FORMAT", build_format)
    case = upgraded(open_case(case.folder))
    assert case.settings.case_format == build_format
    entry = Journal(case).append("note", target=UID, text="after the cut")
    kinds = [(e["action"], e.get("to_format")) for e in entries_of(case)]
    step = [("case_upgrade", 4), ("case_yaml", None)] if build_format == 4 else []
    assert kinds[kinds.index(("case_upgrade", 3)) + 1:] == [
        ("journal_recovered", None), ("case_yaml", None), *step, ("note", None)]
    assert journal_path(case).read_bytes().startswith(cut + b"\n") and entry["seq"] == entries_of(case)[-1]["seq"]
    assert check(journal_path(case)).consistent


@pytest.mark.parametrize("then", ["an open for work", "a command's first append"])
@pytest.mark.parametrize("how", ["a new case", "a copy of a format 3 case", "a copy of a format 4 case"])
def test_a_case_created_cut_just_before_its_lf_is_completed_at_the_next_open(synthetic_case, tmp_path, monkeypatch,
                                                                              how, then):
    """start_chain's path: a new case, and a copy of a format 3 or 4 case, write case_created at byte 0 with seq 1. Cut
    just before its LF it is the chain's start too, and the case, which says its source's format or this build's,
    opens for work."""
    folder = tmp_path / "made"
    source = format3_case(synthetic_case) if how == "a copy of a format 3 case" else synthetic_case
    cut_before_its_lf(monkeypatch)
    with pytest.raises(OSError, match="before the line end"):
        if how == "a new case":
            create_case(folder, "Made", synthetic_case.evidence, "cody")
        else:
            copy_case(source, folder, "Copy", "cody")
    monkeypatch.undo()
    case = open_case(folder)
    path = journal_path(case)
    cut = path.read_bytes()
    assert settings_of(case)["case_format"] == (3 if how == "a copy of a format 3 case" else CASE_FORMAT)
    assert b"\n" not in cut and check(path).tail == "missing_lf"
    journal = Journal(case)
    if then == "an open for work":
        journal.open_for_work()
    else:
        journal.append("note", target=UID, text="after the cut")
    assert not journal.read_only and journal.chain.chained
    after = path.read_bytes()
    assert after.startswith(cut + b"\n")
    recovered = json.loads(after[len(cut) + 1:].split(b"\n")[0])
    assert (recovered["action"], recovered["completed"], recovered["entry"]) == (
        "journal_recovered", True, {"action": "case_created", "seq": 1})
    assert check(path).consistent and run_checker(path)[0] == 0
    assert (how == "a new case") == ("copied_from" not in json.loads(cut))


def test_a_copy_of_a_format_2_case_whose_seal_was_cut_just_before_its_lf_is_completed_at_the_next_open(
        synthetic_case, tmp_path, monkeypatch):
    """upgraded_copy's path: a copy of an older case keeps its format and an empty journal, and its upgrade seals
    that. The seal over no bytes is the chain's start as well."""
    source = format2(synthetic_case, note(5))
    copy = copy_case(source, tmp_path / "copy", "Copy", "cody")
    assert journal_path(copy).read_bytes() == b""
    cut_before_its_lf(monkeypatch)
    with pytest.raises((OSError, CaseError)):
        upgraded_copy(copy, source)
    monkeypatch.undo()
    path = journal_path(copy)
    cut = path.read_bytes()
    assert settings_of(copy)["case_format"] == 2 and cut and not cut.endswith(b"\n") and check(path).tail == "missing_lf"
    reopened = upgraded(open_case(copy.folder))
    journal = Journal(reopened)
    journal.open_for_work()
    assert reopened.settings.case_format == 4 and not journal.read_only and check(path).consistent
    assert path.read_bytes().startswith(cut + b"\n") and run_checker(path)[0] == 0
    assert [e["to_format"] for e in entries_of(reopened) if e["action"] == "case_upgrade"] == [3, 4]


def test_start_chain_ends_a_seal_cut_just_before_its_lf_before_it_appends_case_created(synthetic_case, monkeypatch):
    """start_chain, which follows a copy's seal, treats a first line missing only its LF as the chain: the append
    ends it, journals that, and then writes case_created."""
    case = format2(synthetic_case, note(5))
    cut = a_cut_seal(case, monkeypatch)
    entry = start_chain(open_case(case.folder), "cli")
    kinds = [e["action"] for e in entries_of(case)]
    assert kinds[-3:] == ["case_upgrade", "journal_recovered", "case_created"] and entry["action"] == "case_created"
    assert journal_path(case).read_bytes().startswith(cut + b"\n") and check(journal_path(case)).consistent


def forged_starts() -> dict[str, bytes]:
    """A format 3 journal whose only unended line looks like the chain's first and isn't: its journal's bytes."""
    first = envelope(1, ZERO, "case_created", who=SYSTEM, **created())
    before = unchained(note(1), note(2))
    seal_fields = seal(before)
    return {
        "case_created with another prev": line_bytes({**first, "prev": "1" * 64})[:-1],
        "case_created with seq 2": line_bytes({**first, "seq": 2})[:-1],
        "case_created below another line": unchained(note(1)) + line_bytes(first)[:-1],
        "a note at byte 0": line_bytes(envelope(1, ZERO, "note", target=UID, text="x"))[:-1],
        "a seal of other bytes": before + line_bytes(envelope(3, ZERO, "case_upgrade", who=SYSTEM, **{
            **seal_fields, "sealed": {**seal_fields["sealed"], "bytes": 5}}))[:-1],
        "a seal that carries a rekey": before + line_bytes(envelope(3, ZERO, "case_upgrade", who=SYSTEM, **seal_fields,
                                                                    rekey={"pairs": {UID: OTHER}}))[:-1],
        "a first line without its envelope": line_bytes({k: v for k, v in first.items() if k != "build"})[:-1],
    }


@pytest.mark.parametrize("name", list(forged_starts()))
def test_a_lone_unended_line_that_starts_nothing_stays_a_break(synthetic_case, name):
    """Only a line the start rule takes (prev of 64 zeros, and case_created at byte 0 with seq 1 or a seal that matches
    every byte before it, whole and with no foreign rekey) is the chain when it lacks its LF. Any other is "chain
    missing": read-only, nothing written, Continue refused, the checker's exit 1 with the same head. A forged seal that
    carries a rekey is the one that must not raise out of the open."""
    case = synthetic_case
    path = journal_path(case)
    data = forged_starts()[name]
    as_format(case.folder, 3, data)
    journal = Journal(case)
    journal.open_for_work()
    assert journal.read_only and "chain_missing" in [p["kind"] for p in journal.problems] and not journal.started()
    assert path.read_bytes() == data
    result = check(path)
    kinds = [p["kind"] for p in result.problems]
    assert result.tail == "not_entry" and "chain_missing" in kinds and "tail" in kinds
    code, out = run_checker(path)
    assert code == 1 and f"head {result.head} (entry #{result.seq})" in out
    with pytest.raises(JournalError, match="no hash chain yet"):
        journal.record_break("looked at it")
    with pytest.raises(JournalError):
        Journal(case).append("note", target=UID, text="refused")
    assert path.read_bytes() == data


def test_an_unended_rekey_no_build_writes_opens_read_only_in_a_started_chain_too(synthetic_case):
    """A last line missing its LF that follows the chain but carries a rekey of format 2 to 3 is not taken as the next
    entry, since the open would raise out of _recover when its LF made it a break. It is a break at once, the tail's,
    and nothing is written."""
    base = chained([("mark", {"targets": [UID], "value": "suspicious"})])
    data = add(base, "case_upgrade", who=SYSTEM, from_format=2, to_format=3, text="x", rekey={"pairs": {UID: OTHER}})[:-1]
    as_format(synthetic_case.folder, 3, data)
    journal = Journal(synthetic_case)
    journal.open_for_work()
    assert [p["kind"] for p in journal.problems] == ["tail"] and journal.read_only
    assert journal_path(synthetic_case).read_bytes() == data and set(journal.state.marks) == {UID}
    assert check(journal_path(synthetic_case)).tail == "not_entry" and run_checker(journal_path(synthetic_case))[0] == 1


def test_continue_applies_to_a_seal_cut_just_before_its_lf_under_a_head_record_that_names_no_line(synthetic_case,
                                                                                                  monkeypatch):
    """With a head record that is no line of the journal, the open of a first line missing its LF is read-only,
    "recorded head missing", and Continue must still be offered and work: can_continue and record_break don't depend on
    whether the chain has a first line read, which is false until the LF is there. Check finds the break as the open
    does. The head record is written before the upgrade, whose 3 to 4 step then finds the journal read-only and keeps
    the case at format 3, the cut seal as it was."""
    case = format2(synthetic_case, note(5))
    cut = a_cut_seal(case, monkeypatch)
    heads.write(case.folder, 9, "f" * 64, build_id())
    case = upgraded(open_case(case.folder))
    assert case.settings.case_format == settings_of(case)["case_format"] == 3 and journal_path(case).read_bytes() == cut
    found, record = Journal(case).full_check()
    assert not found.chain.chained and found.tail == "missing_lf" and record["seq"] == 9
    checker = Journal(case)
    checker.full_check()
    assert "record_missing" in [p["kind"] for p in checker.problems] and checker.read_only
    app = opened(case)
    try:
        assert "record_missing" in [p["kind"] for p in app.journal.problems] and app.journal.read_only
        assert journal_path(case).read_bytes() == cut   # a break writes nothing
        state = _journal_state(app)
        assert state["broken"] and state["can_continue"]
        assert journal_row(app.journal, "2026-10-18T09:00:00Z")["can_continue"]
        entry = app.journal.record_break("looked at the cut seal")
    finally:
        app.con.close()
    assert entry["action"] == "chain_break" and journal_path(case).read_bytes().startswith(cut + b"\n")
    assert not Journal(open_case(case.folder)).read_only
    result = check(journal_path(case))
    assert not result.problems and len(result.chain.on_record) == 1


def test_the_seal_s_record_runs_inside_the_step_s_held_context(synthetic_case, monkeypatch):
    """The seal step holds the journal's context while case.upgrade's record writes the seal, which takes the context
    again in the same thread and returns at once. A lock per Journal that isn't re-entrant would make the record wait
    out LOCK_WAIT and fail."""
    monkeypatch.setattr(journal_module, "LOCK_WAIT", 3.0)
    case = format2(synthetic_case, note(5))
    started = time.monotonic()
    case = upgraded(case)
    assert time.monotonic() - started < 3.0
    assert case.settings.case_format == settings_of(case)["case_format"] == 4
    assert [e["to_format"] for e in entries_of(case) if e["action"] == "case_upgrade"] == [3, 4]


WRITERS = {"close": lambda folder, rule: ["close", folder], "rule add": lambda folder, rule: ["rule", folder, "add", rule],
           "rule change": lambda folder, rule: ["rule", folder, "change", rule],
           "rule remove": lambda folder, rule: ["rule", folder, "remove", "dc-logons"],
           "rule list": lambda folder, rule: ["rule", folder, "list"],
           "export": lambda folder, rule: ["export", folder], "findings": lambda folder, rule: ["findings", folder]}


@pytest.mark.parametrize("command", list(WRITERS))
def test_a_command_that_writes_upgrades_a_format_2_case_first(tmp_path, synthetic_case, command, monkeypatch):
    """On a format 2 case, close, rule add, change, remove, list with a changed built-in rule, export, and findings each
    upgrade first, the seal, a case_yaml for format 3, the 3 to 4 entry, and a case_yaml for format 4, then write with
    client cli and their build. No command writes case_open."""
    case = synthetic_case
    intake(case)
    has_rule = command in ("rule change", "rule remove")
    case = format2(case, *([{"seq": 5, "at": AT, "who": "cody", "action": "rule_add", "id": "dc-logons", "text": RULE}]
                           if has_rule else []))
    before = journal_path(case).read_bytes()
    monkeypatch.setitem(BUILTIN_RULES, "print-spooler-pipe", BUILTIN_RULES["print-spooler-pipe"] + "# later\n")
    rule = tmp_path / "rule.yaml"
    rule.write_text(CHANGED if command == "rule change" else RULE, encoding="utf-8")
    assert main(WRITERS[command](str(case.folder), str(rule))) in (0, 1)
    after = journal_path(case).read_bytes()
    assert settings_of(case)["case_format"] == 4 and after.startswith(before)
    written = [json.loads(line) for line in after[len(before):].split(b"\n")[:-1]]
    assert written[0]["action"] == "case_upgrade" and written[0]["sealed"]["bytes"] == len(before)
    assert [(e["action"], e.get("from_format"), e.get("to_format")) for e in written[:4]] == [
        ("case_upgrade", 2, 3), ("case_yaml", None, None), ("case_upgrade", 3, 4), ("case_yaml", None, None)]
    assert [e["settings"]["case_format"] for e in written if e["action"] == "case_yaml"] == [3, 4]
    assert all(e["client"] == "cli" and e["build"] == build_id() for e in written)
    assert "case_open" not in {e["action"] for e in written} and len(written) > 4
    assert check(journal_path(case)).consistent
    record = heads.read(case.folder)   # Head, "The record": each command-line write records the head
    assert (record["seq"], record["head"]) == (written[-1]["seq"], sha(after.split(b"\n")[-2]))


def test_a_command_that_writes_nothing_leaves_a_format_2_case_as_it_is(synthetic_case, capsys):
    """On a format 2 case, the commands runs, tools, verify, intake, and import --preview write nothing and leave the
    format as it is."""
    case = synthetic_case
    (case.evidence / "DC01" / "log.csv").write_text("time,src\n2024-02-05T10:00:00Z,10.0.0.1\n", encoding="utf-8")
    intake(case)
    case = format2(case)
    before = (journal_path(case).read_bytes(), (case.folder / "case.yaml").read_bytes())
    folder = str(case.folder)
    for argv in (["runs", folder], ["tools", folder], ["verify", folder], ["intake", folder, "--add"],
                 ["import", folder, "DC01/log.csv", "--preview"]):
        main(argv)
        assert (journal_path(case).read_bytes(), (case.folder / "case.yaml").read_bytes()) == before, argv


RULE_ARGUMENTS = {
    "a file that isn't a rule": lambda folder, files: ["rule", folder, "add", files["bad"]],
    "a built-in source's id": lambda folder, files: ["rule", folder, "add", files["source"]],
    "add of a rule that exists": lambda folder, files: ["rule", folder, "add", files["good"]],
    "change of a rule that doesn't": lambda folder, files: ["rule", folder, "change", files["other"]],
    "remove with no id": lambda folder, files: ["rule", folder, "remove"],
    "remove of an unknown rule": lambda folder, files: ["rule", folder, "remove", "no-such-rule"],
}


@pytest.mark.parametrize("name", list(RULE_ARGUMENTS))
def test_a_rule_command_refused_for_its_arguments_upgrades_nothing(tmp_path, synthetic_case, name, capsys):
    """Rule add, change, and remove check the rule before they upgrade the case, not only that the YAML file can be
    read, so a rule that isn't valid, a built-in source's id, an id that exists or doesn't, or a removal with no id
    leaves no upgraded case behind an error. Each is refused first, the journal and case.yaml as they were."""
    case = format2(synthetic_case, {"seq": 5, "at": AT, "who": "cody", "action": "rule_add", "id": "dc-logons", "text": RULE})
    files = {"bad": "id: [unclosed\n", "source": RULE.replace("dc-logons", "hayabusa"),
             "good": RULE, "other": RULE.replace("dc-logons", "no-such-rule")}
    for key, text in files.items():
        (tmp_path / f"{key}.yaml").write_text(text, encoding="utf-8")
    argv = RULE_ARGUMENTS[name](str(case.folder), {key: str(tmp_path / f"{key}.yaml") for key in files})
    before = (journal_path(case).read_bytes(), (case.folder / "case.yaml").read_bytes())
    assert main(argv) == 2, capsys.readouterr().err
    assert (journal_path(case).read_bytes(), (case.folder / "case.yaml").read_bytes()) == before
    assert settings_of(case)["case_format"] == 2


def format_2_eve_case(root: Path, monkeypatch):
    """test_rekey's found_eve_case brought to format 2 by format 2's step alone, as the build before format 3 left it."""
    f, _ = found_eve_case(root)
    monkeypatch.setattr(case_module, "CASE_FORMAT", 2)
    f.case = upgraded(f.case)
    monkeypatch.undo()
    assert settings_of(f.case)["case_format"] == 2 and not chain_links(f.case)
    return f


@pytest.mark.parametrize("command", [*LOADS, "copy-case", "start page Copy"])
def test_every_loader_reaches_the_seal_step(tmp_path, command, monkeypatch):
    """Every loader reaches the seal step: rebuild, run --all, import, load-output with a kind, copy-case, and the start
    page's Copy each leave a format 2 case, or its copy, at format 4 with the seal and the 3 to 4 entry. The case keeps
    its format 2 step's entry; the copy starts after it."""
    f = format_2_eve_case(tmp_path / "source", monkeypatch)
    if command in LOADS:
        assert main([command, str(f.case.folder), *LOADS[command]]) == 0
        target = f.case.folder
    elif command == "copy-case":
        target = tmp_path / "copy"
        assert main(["copy-case", str(f.case.folder), str(target), "--name", "Copy"]) == 0
    else:
        target = tmp_path / "copy"
        wait(start_copy({"source": str(f.case.folder), "case_folder": str(target), "name": "Copy"}, "cody"))
    case = open_case(target)
    upgrades = [(e["from_format"], e["to_format"]) for e in entries_of(case) if e["action"] == "case_upgrade"]
    assert upgrades == [*([(1, 2)] if command in LOADS else []), (2, 3), (3, 4)]
    assert settings_of(case)["case_format"] == 4 and check(journal_path(case)).consistent


def test_a_build_that_reads_format_2_refuses_a_format_3_case(synthetic_case, monkeypatch, capsys):
    """A build that reads formats up to 2 refuses a format 3 case by number, naming both, and writes nothing."""
    case = format3_case(synthetic_case)
    before = journal_path(case).read_bytes()
    monkeypatch.setattr(case_module, "CASE_FORMAT", 2)
    with pytest.raises(CaseError, match=r"is a case of format 3, and this build .* reads formats up to 2\."):
        open_case(case.folder)
    assert main(["rule", str(case.folder), "list"]) == 2
    assert "is a case of format 3" in capsys.readouterr().err
    assert journal_path(case).read_bytes() == before


def test_the_server_s_open_connects_before_it_writes(synthetic_case):
    """A case of this build's format, which needs no upgrade step, whose database another process holds: the server's
    open fails before it writes case_open or a built-in rule, which a new case's first open writes."""
    case = synthetic_case
    before = journal_path(case).read_bytes()
    holder = subprocess.Popen([sys.executable, "-c", HOLD, str(case.db_path)], stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, text=True)
    try:
        assert holder.stdout.readline().strip() == "held"
        with pytest.raises(Exception, match=r"(?i)lock|another process|being used"):
            Hub(case)
    finally:
        holder.communicate("", timeout=60)
    assert journal_path(case).read_bytes() == before


# ---------- Concurrency ----------

def test_a_reopen_while_a_thread_marks_through_the_first_app_numbers_each_entry_once(synthetic_case):
    """Hub.open of the open case, 50 times, while a thread marks events
    through the first App's journal and each new App marks through its own. Every seq appears once and the chain is
    consistent."""
    hub = Hub(synthetic_case)
    first = hub.app
    stop = threading.Event()
    errors = []

    def mark():
        i = 0
        while not stop.is_set():
            try:
                first.journal.append("mark", targets=[f"{i:032x}"], value="suspicious")
            except Exception as exc:   # noqa: BLE001
                errors.append(exc)
                return
            i += 1
            time.sleep(0.005)

    thread = threading.Thread(target=mark)
    thread.start()
    try:
        for n in range(50):
            app = hub.open(synthetic_case)
            app.journal.append("mark", targets=[f"{n:031x}f"], value="malicious")
    finally:
        stop.set()
        thread.join()
        hub.app.con.close()
    assert not errors, errors
    seqs = [e["seq"] for e in entries_of(synthetic_case)]
    assert seqs == list(range(1, len(seqs) + 1)) and check(journal_path(synthetic_case)).consistent


def test_the_server_s_next_entry_chains_after_close_s(synthetic_case):
    """close appends through its own Journal beside the server's, and the server's next entry takes the next number and
    names close's line."""
    case = synthetic_case
    intake(case)
    app = App(case, for_work=True)
    try:
        app.journal.append("mark", targets=[UID], value="suspicious")
        assert main(["close", str(case.folder)]) in (0, 1)
        close = lines_of(case)[-1]
        entry = app.journal.append("mark", targets=[OTHER], value="malicious")
    finally:
        app.con.close()
    assert json.loads(close)["action"] == "case_setting"
    assert entry["seq"] == json.loads(close)["seq"] + 1 and entry["prev"] == sha(close)
    assert app.journal.state.settings["closed"]["hash_check"] and check(journal_path(case)).consistent


# ---------- Head ----------

def test_new_case_and_copy_case_record_the_head(tmp_path, synthetic_case):
    """On the command line, new-case and copy-case each record the head of the journal they write, outside the case."""
    (tmp_path / "ev" / "PC1").mkdir(parents=True)
    assert main(["new-case", str(tmp_path / "new"), "--evidence", str(tmp_path / "ev"), "--name", "N"]) == 0
    assert main(["copy-case", str(synthetic_case.folder), str(tmp_path / "copy"), "--name", "C"]) == 0
    for folder in (tmp_path / "new", tmp_path / "copy"):
        case = open_case(folder)
        record = heads.read(case.folder)
        assert (record["seq"], record["head"]) == (entries_of(case)[-1]["seq"], sha(lines_of(case)[-1]))


def test_a_case_made_where_another_was_has_none_of_its_head(tmp_path, synthetic_case):
    """The head record is per folder, so a case made where another was starts from its own head: a new case's
    start_chain records it, and a copy of an older source, whose journal its upgrade seals, isn't refused for the
    earlier case's record (copy_case removes it, as create_case does)."""
    folder = synthetic_case.folder
    old = heads.read(folder)
    assert old is not None
    source = format2(create_case(tmp_path / "source", "Source", synthetic_case.evidence, "cody"), note(5))
    shutil.rmtree(folder)
    assert main(["copy-case", str(source.folder), str(folder), "--name", "Again"]) == 0
    copy = open_case(folder)
    assert heads.read(folder)["head"] == sha(lines_of(copy)[-1]) != old["head"]
    shutil.rmtree(folder)
    case = create_case(folder, "Again", synthetic_case.evidence, "cody")
    assert heads.read(folder)["head"] == sha(lines_of(case)[0])


# ---------- Damaged journals: the steps, the open, and the trail ----------

BAD_MARK = {"seq": 2, "at": AT, "who": "cody", "action": "mark", "targets": None, "value": "suspicious"}


@pytest.mark.parametrize("how", ["upgraded", "the server's open"])
@pytest.mark.parametrize("older", [1, 2])
def test_a_whole_unchained_line_the_reader_cant_apply_refuses_before_either_step_writes(synthetic_case, older, how):
    """The Journal skips such a line, so its read is no check: without one of its own, a format 1 case would get its
    columns, its remap, a journal line, and format 2 before the seal step refused. Both steps check the journal first,
    in a format 1 and a format 2 case, through the command line's upgrade and the server's open, and the refusal names
    the line and says nothing was changed."""
    as_format(synthetic_case.folder, older, unchained(note(1), BAD_MARK, note(3)))
    case = open_case(synthetic_case.folder)
    columns = as_an_older_build_left_it(case)
    before = files_of(case.folder)
    refused = {"upgraded": lambda: upgraded(open_case(case.folder)),
               "the server's open": lambda: App(open_case(case.folder), for_work=True)}[how]
    with pytest.raises(CaseError, match=r"line 2 is JSON that the journal's reader can't apply.*Nothing was changed"):
        refused()
    assert files_of(case.folder) == before and table_columns(case) == columns
    assert "account_key" not in columns and open_case(case.folder).settings.case_format == older


@pytest.mark.parametrize("name", list(forged_starts()))
def test_a_format_2_journal_ending_in_a_line_that_starts_no_chain_refuses_the_seal_step(synthetic_case, name):
    """has_chain takes any unended line that spells prev as the chain, so without a check of its own the upgrade would
    skip every check and write format 3 over a journal that opens read-only with no chain and no Continue. The step
    refuses first, with the case at format 2 and nothing written."""
    as_format(synthetic_case.folder, 2, forged_starts()[name])
    case = open_case(synthetic_case.folder)
    columns = as_an_older_build_left_it(case)
    before = files_of(case.folder)
    with pytest.raises(CaseError, match="Nothing was changed"):
        upgraded(case)
    assert files_of(case.folder) == before and table_columns(case) == columns
    assert open_case(case.folder).settings.case_format == 2


def test_a_journal_with_no_chain_offers_no_continue(synthetic_case):
    """The read-only sentence of a journal with no chained line doesn't end in "Continue with the break on record from
    the Case overview", which record_break refuses and the overview hides. It says what to do instead."""
    as_format(synthetic_case.folder, 3, forged_starts()["a note at byte 0"])
    app = opened(open_case(synthetic_case.folder))
    reason = app.journal.read_only
    assert reason.startswith(f"{WRITES}the journal has no chained line")
    assert "Continue with the break on record from" not in reason
    assert "once the journal has a chained line" in reason
    assert _journal_state(app)["can_continue"] is False


def test_a_journal_deleted_while_the_case_is_open_has_nothing_to_continue(synthetic_case):
    """can_continue asks Journal.started, which reads the file when the chain has not started and answers False when
    the file is gone, so a journal deleted under a running server doesn't make every overview and meta request raise
    FileNotFoundError."""
    as_format(synthetic_case.folder, 3, b"")
    app = opened(open_case(synthetic_case.folder))
    assert app.journal.read_only
    journal_path(synthetic_case).unlink()
    assert _journal_state(app)["can_continue"] is False and not app.journal.started()


def test_a_rule_command_on_a_sealed_case_whose_earlier_line_changed_is_refused_by_the_open(synthetic_case, tmp_path, capsys):
    """cmd_rule replays the journal before it opens the case, and replay refuses an unchained line _apply can't take.
    cmd_rule leaves that refusal to the open, so a changed line before the seal ends in the open's error message, not a
    bare traceback, as the server opens the case read-only and names the break."""
    case = sealed_case(synthetic_case)
    rows = journal_path(case).read_bytes().split(b"\n")
    rows[0] = rows[0].replace(b'"targets"', b'"targetz"')
    journal_path(case).write_bytes(b"\n".join(rows))
    rule_file = tmp_path / "rule.yaml"
    rule_file.write_text(RULE, encoding="utf-8")
    assert main(["rule", str(case.folder), "add", str(rule_file)]) == 2
    assert f"Error: {WRITES}" in capsys.readouterr().err


# Entries the state takes and the trail's readers can't: the trail page and its export must not raise on them, and an
# undo with no `undoes` must not make every undo plan raise
UNREADABLE_BY_THE_TRAIL = {
    "mark note null": ("mark", {"targets": [UID], "value": "suspicious"}, lambda e: e.update(note=None)),
    "finding severity null": ("finding", {"op": "add", "title": "T", "severity": "High"},
                              lambda e: e.update(severity=None)),
    "mark targets a one-key map": ("mark", {"targets": [UID], "value": "suspicious"},
                                   lambda e: e.update(targets={UID: 1})),
    "note_retract without note_seq": ("note_retract", {"target": UID, "note_seq": 1}, lambda e: e.pop("note_seq")),
    "undo without undoes": ("undo", UNDO, lambda e: e.pop("undoes")),
    "undo change without targets": ("undo", UNDO, lambda e: e["changes"].append(
        {"action": "finding", "op": "edit", "finding": 99})),
}


@pytest.mark.parametrize("name", list(UNREADABLE_BY_THE_TRAIL))
def test_the_trail_marks_an_entry_the_state_takes_and_the_trail_cannot_read(synthetic_case, name):
    """After Continue the trail page and its Markdown export must not raise on a payload _apply accepts but describe,
    touches, or undone_by can't read, or the case that opened could not be looked at. The entry is marked
    damaged, worded as one whose payload the trail can't read and that the journal applies as written, and not undoable."""
    case = synthetic_case
    seq, _ = with_a_changed_payload(case, name, UNREADABLE_BY_THE_TRAIL)
    app = App(case, for_work=True)
    try:
        app.journal.record_break("looked at the change")
        words = "stored payload the trail can't read"
        shown = {r["seq"]: r for r in api_audit(app, {})["rows"]}
        assert words in shown[seq]["text"] and not shown[seq]["undoable"] and shown[seq]["count"] == 0
        assert seq not in {r["seq"] for r in api_audit(app, {"event": [UID]})["rows"]}
        assert words in Path(api_audit_export(app, {})["path"]).read_text(encoding="utf-8")
        with pytest.raises(QueryError, match="can't be undone: its stored payload can't be read"):
            api_undo_plan(app, {"seq": [str(seq)]})
        try:   # the "N events" link of an entry whose targets can't be read answers, as an error, not a traceback
            api_audit_events(app, {"seq": [str(seq)]})
        except QueryError as exc:
            assert "can't be read" in str(exc)
    finally:
        app.con.close()


def changed_lines(case, changes: dict) -> None:
    """The journal with the line of each entry number in `changes` changed by its function, as a hand edit leaves it."""
    found = journal_path(case).read_bytes().split(b"\n")[:-1]
    for i, line in enumerate(found):
        entry = json.loads(line)
        if entry.get("seq") in changes:
            changes[entry["seq"]](entry)
            found[i] = json.dumps(entry, ensure_ascii=False).encode("utf-8")
    journal_path(case).write_bytes(b"".join(x + b"\n" for x in found))


def test_undo_counts_what_an_entry_the_trail_cannot_read_applied(synthetic_case):
    """An entry the trail can't read is not left out of undo planning as if the state had skipped it, since the state
    applied it. Otherwise undoing an earlier mark of the same event would set it back over the later mark, an undo the
    trail can't read would not count as undoing its entry, and a later entry whose changes can't be read would let an
    undo through. Undo plans from what the state holds, and refuses when it can't tell what changed since."""
    case = synthetic_case
    opened(case)
    journal = Journal(case)
    first = journal.append("mark", targets=[UID], value="suspicious")["seq"]
    later = journal.append("mark", targets=[UID], value="malicious")["seq"]
    other = journal.append("mark", targets=[OTHER], value="suspicious")["seq"]
    undo = journal.append("undo", undoes=other, correction="accident",
                          changes=[{"action": "mark", "targets": [OTHER], "value": "unreviewed"}])["seq"]
    changed_lines(case, {later: lambda e: e.update(note=None),   # describe can't read it; the state applies it
                         undo: lambda e: e["changes"].append({"action": "finding", "op": "edit", "finding": 99})})
    app = App(case, for_work=True)
    try:
        app.journal.record_break("looked at the change")
        assert app.journal.state.marks[UID].value == "malicious" and OTHER not in app.journal.state.marks
        assert api_undo_plan(app, {"seq": [str(first)]})["kept"] == 1   # the later mark changed the event since
        with pytest.raises(QueryError, match=f"#{other} was already undone by #{undo}"):
            api_undo_plan(app, {"seq": [str(other)]})
        tagged = app.journal.append("tag", targets=[UID], add=["tactic:TA0001"])["seq"]
        tag = app.journal.append("tag", targets=[UID], add=["tactic:TA0002"])["seq"]
    finally:
        app.con.close()
    changed_lines(case, {tag: lambda e: e.update(add="TA3")})   # touches can't read it; the state applies each letter
    app = App(case, for_work=True)
    try:
        app.journal.record_break("looked at the second change")
        assert set(app.journal.state.tags[UID]) == {"tactic:TA0001", "T", "A", "3"}
        with pytest.raises(QueryError, match=f"can't be undone: entry #{tag}, after it"):
            api_undo_plan(app, {"seq": [str(tagged)]})
    finally:
        app.con.close()
