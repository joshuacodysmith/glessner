"""The journal core: the chain's format and strict reading, the checks that find a changed journal, torn-line
recovery, the lock, and the head recorded outside the case. Every journal is synthetic."""

import errno
import json
import runpy
import subprocess
import sys
import textwrap
import threading
import time
from collections import Counter

import pytest
from chain_fixtures import (
    AT,
    BUILD,
    CHECKER,
    MARKS,
    OTHER,
    UID,
    add,
    as_format,
    chained,
    created,
    envelope,
    head,
    join,
    lines,
    note,
    run_checker,
    seal,
    sha,
    unchained,
)

import glessner.journal as jm
from glessner import heads
from glessner.case import create_case, open_case
from glessner.journal import (
    ENVELOPE,
    SYSTEM,
    ZERO,
    Journal,
    JournalError,
    check,
    line_bytes,
    mend_unchained,
    replay,
)
from glessner.rekey import upgraded
from glessner.version import build_id

NEW = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
ESCAPED_PREV = b'"\\u0070rev"'   # the key prev, spelled as JSON allows
WINDOWS =pytest.mark.skipif(sys.platform != "win32", reason="the lock is msvcrt's, on Windows, which the app targets")


@pytest.fixture
def chained_case(tmp_path):
    """A new case, whose journal create_case starts with case_created."""
    (tmp_path / "evidence" / "DC01").mkdir(parents=True)
    return create_case(tmp_path / "case", "Test", tmp_path / "evidence", "cody")


@pytest.fixture
def case(chained_case):
    """A case at format 2 with an empty journal and no head record, for a test that writes its own journal."""
    as_format(chained_case.folder, 2)
    return open_case(chained_case.folder)


def journal_of(case):
    return case.folder / "journal.jsonl"


def found(result) -> list[tuple[int | None, str]]:
    return [(p["line"], p["kind"]) for p in result.problems]


def side_files(case) -> list:
    return sorted(case.folder.glob("journal_torn_*.bin"))


def worked(case, client="cli") -> Journal:
    """A chained case with MARKS appended through the app's own journal, so the head record names the last."""
    j = Journal(case, client)
    for action, payload in MARKS:
        j.append(action, **payload)
    return j


def state_of(state):
    return ({u: m.value for u, m in state.marks.items()}, {u: [n["text"] for n in ns] for u, ns in state.notes.items()})


def agree(path, expect=None) -> bool:
    """The app's full check and the checker give the same result, and name the same head; the result."""
    result = check(path, expect)
    code, out = run_checker(path, *([expect] if expect else []))
    assert (code == 0) == result.consistent, out
    assert f"head {result.head} (entry #{result.seq})" in out, out
    return result.consistent


# Format

def test_exact_bytes():
    """A fixed entry with non-ASCII text, a tab, U+2028, a float, and a nested value gives these bytes."""
    entry = envelope(7, ZERO, "note", client="server", target=UID, text="Caf\u00e9\tline\u2028end", seconds=3600.0,
                     nested={"a": [1, -0.5, True, None]})
    assert line_bytes(entry) == (
        b'{"seq": 7, "prev": "' + ZERO.encode() + b'", "at": "2026-10-17T02:14:09.118204Z", "who": "cody", '
        b'"build": "0.2.0+1a2b3c4", "client": "server", "action": "note", "target": "' + UID.encode() + b'", '
        b'"text": "Caf\xc3\xa9\\tline\xe2\x80\xa8end", "seconds": 3600.0, "nested": {"a": [1, -0.5, true, null]}}\n')


def test_a_chained_append_writes_the_envelope_and_names_the_line_before(chained_case):
    path = journal_of(chained_case)
    first = lines(path.read_bytes())[0]
    assert json.loads(first)["action"] == "case_created" and json.loads(first)["prev"] == ZERO
    entry = Journal(chained_case, "server").append("note", target=UID, text="Caf\u00e9\u2028")
    data = path.read_bytes()
    assert data == first + b"\n" + line_bytes(entry)
    assert list(entry)[:7] == list(ENVELOPE) and entry["prev"] == sha(first) and entry["seq"] == 2
    assert (entry["client"], entry["build"], entry["who"]) == ("server", build_id(), "cody")
    assert agree(path)


@pytest.mark.parametrize("payload", [
    {"text": "\ud800"}, {"text": "x", "seconds": float("nan")}, {"text": "x", "seconds": float("inf")},
    {"text": "x", "seconds": float("-inf")}, {"text": "x", "at": "2020-01-01T00:00:00.000000Z"},
    {"text": "x", "prev": ZERO}, {"text": "x", "seq": 99}, {"text": "x", "client": "server"}, {"text": "x", "build": "1"},
])
def test_refusals_leave_the_file_as_it_was(chained_case, payload):
    """A lone surrogate, NaN, an infinity, and a payload key named like an envelope key are refused."""
    path = journal_of(chained_case)
    before = path.read_bytes()
    with pytest.raises(JournalError):
        Journal(chained_case).append("note", target=UID, **payload)
    assert path.read_bytes() == before


def test_case_open_has_no_payload_and_its_build_is_the_envelope_s(chained_case):
    path = journal_of(chained_case)
    j = Journal(chained_case, "server")
    with pytest.raises(JournalError, match="no payload"):
        j.append("case_open", build="0.9.0+abcdef0")
    entry = j.record_build("0.9.0+abcdef0")
    assert entry["build"] == "0.9.0+abcdef0" and set(entry) == set(ENVELOPE)
    assert j.record_build("0.9.0+abcdef0") is None and Journal(chained_case).build == "0.9.0+abcdef0"
    assert j.record_build("0.9.1+abcdef0")["build"] == "0.9.1+abcdef0"
    assert [json.loads(line)["action"] for line in lines(path.read_bytes())] == ["case_created", "case_open", "case_open"]


def _bad(data: bytes, raw: bytes) -> bytes:
    """`data` with `raw` as its next line and a valid line after it, which names `raw`'s bytes."""
    return add(data + raw + b"\n", "note", target=UID, text="after")


def _strict_cases():
    base = chained([MARKS[0]])
    nxt = envelope(3, head(base), "note", target=UID, text="a")
    good = line_bytes(nxt)[:-1]
    without = {k: line_bytes({kk: v for kk, v in nxt.items() if kk != k})[:-1] for k in ("at", "who", "build", "action",
                                                                                        "client")}
    cases = {
        "repeated key": good[:-1] + b', "text": "b"}',
        "seq 8.0": good.replace(b'"seq": 3', b'"seq": 3.0'),
        "seq true": good.replace(b'"seq": 3', b'"seq": true'),
        "NaN": good[:-1] + b', "seconds": NaN}',
        "Infinity": good[:-1] + b', "seconds": Infinity}',
        "-Infinity": good[:-1] + b', "seconds": -Infinity}',
        **{f"no {k}": v for k, v in without.items()},
    }
    out = {name: _bad(base, raw) for name, raw in cases.items()}
    first = envelope(1, ZERO, "case_created", who="glessner", **created())
    no_build = line_bytes({k: v for k, v in first.items() if k != "build"})
    out["first line without build, alone"] = no_build
    out["first line without build, with a valid second"] = add(no_build, "note", target=UID, text="x")
    out["first line with seq true, alone"] = line_bytes({**first, "seq": True})
    out["first line with seq 1.0, alone"] = line_bytes({**first, "seq": 1.0})
    before = unchained(note(1))
    out["a seal with seq x"] = before + line_bytes(envelope("x", ZERO, "case_upgrade", who="glessner", **seal(before)))
    return out


STRICT = _strict_cases()


@pytest.mark.parametrize("name", list(STRICT))
def test_strict_reading_is_a_break_in_the_app_and_the_checker(case, name):
    """A repeated key, a seq that isn't an integer, NaN and the infinities, and an incomplete envelope, on any
    chained line, the first included, are breaks; the app refuses to write, and the checker exits 1."""
    path = journal_of(case)
    path.write_bytes(STRICT[name])
    assert not agree(path)
    j = Journal(case)
    assert j.read_only
    before = path.read_bytes()
    with pytest.raises(JournalError, match="changed after it was written"):
        j.append("note", target=UID, text="refused")
    assert path.read_bytes() == before


# Tamper

def test_a_changed_line_is_a_break_and_the_append_is_refused(case):
    """One byte changed in a middle line's payload, in its prev, and in its spacing: a break at the line that no longer
    names it, or at the line itself for its prev."""
    base = chained(MARKS)
    third = lines(base)[2]
    at = third.index(b'"prev": "') + 9
    flipped = third[:at] + (b"1" if third[at:at + 1] == b"0" else b"0") + third[at + 1:]
    changed = {
        "payload": (base.replace(b"first look", b"first lOok"), 4),
        "prev": (base.replace(third, flipped), 3),
        "spacing": (base.replace(b'"target": "' + UID.encode() + b'", "text": "first look"',
                                 b'"target": "' + UID.encode() + b'","text": "first look"'), 4),
    }
    path = journal_of(case)
    for name, (data, line) in changed.items():
        assert data != base, name
        path.write_bytes(data)
        result = check(path)
        assert found(result)[0] == (line, "prev"), name
        assert not agree(path)
        with pytest.raises(JournalError, match=f"line {line}: prev doesn't match"):
            Journal(case).append("note", target=UID, text="refused")
        assert path.read_bytes() == data


def test_removed_reordered_and_inserted_lines(case):
    base = chained(MARKS)
    rows = lines(base)
    forged = line_bytes(envelope(4, sha(rows[2]), "mark", targets=[UID], value="authorized"))[:-1]
    cases = {
        "removed": (join(rows[:2] + rows[3:]), (3, "prev")),
        "swapped": (join(rows[:2] + [rows[3], rows[2]] + rows[4:]), (3, "prev")),
        "inserted": (join(rows[:3] + [forged] + rows[3:]), (5, "prev")),
        "blank": (join(rows[:3] + [b""] + rows[3:]), (4, "blank")),
    }
    path = journal_of(case)
    for name, (data, first) in cases.items():
        path.write_bytes(data)
        assert found(check(path))[0] == first, name
        assert not agree(path)


def test_the_chain_must_start_at_byte_0_or_at_a_seal(case):
    path = journal_of(case)
    path.write_bytes(b"")
    assert found(check(path)) == [(None, "chain_missing")] and not agree(path)
    off = unchained(note(1)) + line_bytes(envelope(2, ZERO, "case_created", who="glessner", **created()))
    path.write_bytes(off)
    assert found(check(path)) == [(2, "chain_missing")] and not agree(path)
    second = chained() + line_bytes(envelope(2, ZERO, "note", target=UID, text="x"))
    path.write_bytes(second)
    assert found(check(path)) == [(2, "prev")] and not agree(path)
    sealed = chained(MARKS, before=unchained(note(1), note(2)))
    path.write_bytes(sealed)
    assert agree(path) and check(path).chain.start == {"line": 3, "seq": 3, "action": "case_upgrade"}


def test_the_newest_lines_show_only_against_a_head_kept_outside(chained_case):
    """The last line edited, and the last two removed: the chain alone stays consistent; the running app's next append
    refuses; the checker fails the head from before; and the head record catches both at an open."""
    path = journal_of(chained_case)
    running = worked(chained_case)
    data = path.read_bytes()
    before = head(data)
    assert heads.read(chained_case.folder)["head"] == before
    edited = data.replace(b'"second"', b'"SECOND"')
    removed = join(lines(data)[:-2])
    for name, changed in (("edited", edited), ("removed", removed)):
        other = Journal(chained_case)   # read before the change, as a running server's is
        path.write_bytes(changed)
        assert check(path).consistent, name
        assert run_checker(path)[0] == 0
        code, out = run_checker(path, before)
        assert code == 1 and "the expected head is no entry" in out
        with pytest.raises(JournalError, match="newest line"):
            other.append("note", target=UID, text="refused")
        assert path.read_bytes() == changed
        opened = Journal(chained_case)
        opened.open_for_work()
        assert [p["kind"] for p in opened.breaks] == ["record_missing"], name
        assert path.read_bytes() == changed and not side_files(chained_case)
    assert running.state.last_seq == 5


def test_a_confirmed_entry_without_its_line_end_is_ended_and_recorded(chained_case):
    path = journal_of(chained_case)
    worked(chained_case)
    data = path.read_bytes()
    path.write_bytes(data[:-1])
    assert found(check(path)) == [(5, "missing_lf")] and not agree(path)
    j = Journal(chained_case)
    j.open_for_work()
    after = path.read_bytes()
    assert after.startswith(data) and not side_files(chained_case)
    recovered = json.loads(lines(after)[-1])
    assert (recovered["action"], recovered["completed"], recovered["entry"]) == (
        "journal_recovered", True, {"action": "note", "seq": 5})
    assert state_of(j.state) == state_of(replay(path)) == ({UID: "suspicious", OTHER: "malicious"},
                                                          {UID: ["first look"], OTHER: ["second"]})
    assert agree(path)


@pytest.mark.parametrize("ending", [b"\n", b""])
@pytest.mark.parametrize("where", ["over its end", "after it"])
def test_a_confirmed_entry_made_to_look_torn(chained_case, ending, where):
    """The last entry's tail NUL-filled, with and without its LF: with the head record, a break and nothing moved;
    without it, the app can't tell it from a crash, so it moves the bytes aside, "most likely" left by a crash. NULs
    after the whole entry leave it readable, so the record names what it held."""
    path = journal_of(chained_case)
    worked(chained_case)
    data = path.read_bytes()
    nulled = (data[:-12] + b"\0" * 11 if where == "over its end" else data[:-1] + b"\0" * 4) + ending
    path.write_bytes(nulled)
    assert "most likely" in check(path).problems[-1]["text"] and not agree(path)
    j = Journal(chained_case)
    j.open_for_work()
    assert [p["kind"] for p in j.breaks] == ["record_missing"]
    assert path.read_bytes() == nulled and not side_files(chained_case)
    heads.path_for(chained_case.folder).unlink()
    j = Journal(chained_case)
    j.open_for_work()
    assert not j.breaks
    [side] = side_files(chained_case)
    start = len(join(lines(data)[:-1]))
    assert side.read_bytes() == nulled[start:]
    assert path.read_bytes().startswith(nulled[:start])
    entry = json.loads(lines(path.read_bytes())[-1])
    assert (entry["saved_as"], entry["bytes"], entry["sha256"]) == (side.name, len(nulled) - start,
                                                                   sha(nulled[start:]))
    assert entry.get("held") == ({"action": "note", "seq": 5} if where == "after it" else None)
    assert agree(path) and OTHER not in j.state.notes


def test_a_line_ending_conversion_is_a_break_that_says_so(case):
    path = journal_of(case)
    path.write_bytes(chained(MARKS).replace(b"\n", b"\r\n"))
    result = check(path)
    assert result.problems[0]["kind"] == "line_endings" and "CR LF" in result.problems[0]["text"]
    code, out = run_checker(path)
    assert code == 1 and "CR LF" in out


def spelled(entry: dict) -> bytes:
    """A chained line whose prev key is spelled with an escape, which JSON reads as the same key."""
    return line_bytes(entry).replace(b'"prev"', ESCAPED_PREV, 1)


def _checker_cases():
    """The checker's cases and a format 2 region holding a rekey line, each with the exit it must give, among them a
    first line missing only its LF and a prev spelled with an escape."""
    marks = chained(MARKS)
    before = unchained(note(1), note(2))
    sealed = chained(MARKS, before=before)
    rows = lines(marks)
    rekey = unchained(note(1, UID), {"seq": 2, "at": AT, "who": SYSTEM, "action": "case_upgrade", "from_format": 1,
                                     "to_format": 2, "text": "Event IDs changed.", "rekey": {"pairs": {UID: NEW}}})
    first = envelope(1, ZERO, "case_created", who="glessner", **created())
    cut = chained(MARKS[:2])
    broken = join(rows[:2] + rows[3:])
    brk = add(broken, "chain_break", reason="investigated",
              breaks=[{"line": 3, "kind": "prev"}],
              sealed={"lines": len(lines(broken)), "bytes": len(broken), "sha256": sha(broken)})
    changed_after = brk.replace(b'"second"', b'"SECOND"')
    return {
        "case_created chain": (marks, None, 0),
        "seal chain": (sealed, None, 0),
        "format 2 region with a rekey line": (chained(MARKS, before=rekey), None, 0),
        "expected head found": (marks, head(cut), 0),
        "expected head cut off": (cut, head(marks), 1),
        "format 1 region deleted": (sealed[len(before):], None, 1),
        "format 1 region replaced": (before.replace(b"looked", b"LOOKED") + sealed[len(before):], None, 1),
        "last LF removed": (marks[:-1], None, 1),
        "NUL tail with LF": (marks + b'{"seq": 6, "pr\0\0\0\n', None, 1),
        "NUL tail without LF": (marks + b"\0\0\0\0", None, 1),
        "middle line edited": (marks.replace(b"first look", b"first lOok"), None, 1),
        "middle line deleted": (broken, None, 1),
        "blank chained line": (join(rows[:2] + [b""] + rows[2:]), None, 1),
        "seq 8.0": (STRICT["seq 8.0"], None, 1),
        "repeated key": (STRICT["repeated key"], None, 1),
        "empty file": (b"", None, 1),
        "format 1 lines only": (before, None, 1),
        "CRLF": (marks.replace(b"\n", b"\r\n"), None, 1),
        "line without prev appended": (marks + unchained(note(6)), None, 1),
        "last line without LF that doesn't chain": (marks + line_bytes(envelope(9, ZERO, "note", target=UID,
                                                                                text="x"))[:-1], None, 1),
        "chain_break whose seal matches": (brk, None, 1),
        "chain_break whose sealed lines changed": (changed_after, None, 1),
        "first line without build, alone": (STRICT["first line without build, alone"], None, 1),
        "first line without build, with a second": (STRICT["first line without build, with a valid second"], None, 1),
        "first line seq true": (STRICT["first line with seq true, alone"], None, 1),
        "first line seq 1.0": (STRICT["first line with seq 1.0, alone"], None, 1),
        "seal with seq x": (STRICT["a seal with seq x"], None, 1),
        "chained line holding NaN": (STRICT["NaN"], None, 1),
        "chained line without at": (STRICT["no at"], None, 1),
        "expected head before a chain_break": (brk, head(broken), 1),
        "first chained line alone": (line_bytes(first), None, 0),
        "prev spelled with an escape, alone": (spelled(first), None, 0),
        "prev spelled with an escape, with a line after": (add(spelled(first), "note", target=UID, text="x"), None, 0),
        "a seal over a line with prev spelled with an escape": (
            spelled(first) + line_bytes(envelope(2, ZERO, "case_upgrade", who="glessner", **seal(spelled(first)))), None, 1),
        "a seal lacking only its LF": (sealed[:-1], None, 1),
        "case_created lacking only its LF": (line_bytes(first)[:-1], None, 1),
        "case_created lacking only its LF, with prev spelled with an escape": (spelled(first)[:-1], None, 1),
        "a seal lacking its LF whose bytes changed": (before.replace(b"looked", b"LOOKED") + sealed[len(before):-1], None, 1),
        "case_created lacking its LF below another line": (before + line_bytes(first)[:-1], None, 1),
        "a seal carrying a rekey, lacking its LF": (before + line_bytes(envelope(
            3, ZERO, "case_upgrade", who="glessner", **seal(before), rekey={"pairs": {UID: NEW}}))[:-1], None, 1),
        "a rekey of format 2 after the chain, lacking its LF": (add(marks, "case_upgrade", who=SYSTEM, from_format=2,
                                                                    to_format=3, text="x", rekey={"pairs": {}})[:-1],
                                                                None, 1),
        "a manifest record": (add(marks, "manifest_recorded", sha256=sha(b"manifest"), bytes=8, lines=1, via="intake"),
                              None, 0),
    }


CHECKER_CASES = _checker_cases()


@pytest.mark.parametrize("name", list(CHECKER_CASES))
def test_the_checker_agrees_with_the_app(case, name):
    data, expect, code = CHECKER_CASES[name]
    path = journal_of(case)
    path.write_bytes(data)
    assert agree(path, expect) == (code == 0)


def test_the_full_check_lists_each_whole_manifest_record_with_its_line(case):
    """The full check lists the chained manifest_recorded entries whose payload is whole, with their lines, a last one
    missing only its LF among them, so verify needs no Journal object; one whose payload isn't whole is left out."""
    path = journal_of(case)
    record = {"sha256": sha(b"manifest"), "bytes": 8, "lines": 1, "via": "intake"}
    data = add(chained(MARKS), "manifest_recorded", **record)
    data = add(data, "manifest_recorded", **{**record, "via": "upload"})
    path.write_bytes(add(data, "manifest_recorded", **{**record, "via": "add"})[:-1])
    found = check(path)
    assert [(m["line"], m["seq"], m["via"], m["bytes"]) for m in found.manifests] == [(6, 6, "intake", 8), (8, 8, "add", 8)]
    assert found.tail == "missing_lf"


def _position(result, data: bytes, expect: str | None) -> bool:
    """The app's side of --file: a record counts only at or before the expected head."""
    where = next((line for line, _, h in result.files if h == sha(data)), None)
    return where is not None and result.expected is not None and where <= result.expected[0]


def test_the_checker_s_file_cases(case, tmp_path):
    """A file record counts only at or before a head kept outside the case."""
    path = journal_of(case)
    summary, changed = tmp_path / "summary.md", tmp_path / "changed.md"
    summary.write_bytes(b"# Findings summary\nline two\n")
    changed.write_bytes(b"# Findings summary\nline 2\n")
    printed = chained(MARKS)   # the head the summary prints is this journal's
    recorded = add(printed, "file_written", path="exports/summary.md", kind="findings_summary", format="md",
                   rows=2, bytes=summary.stat().st_size, sha256=sha(summary.read_bytes()), journal_head=head(printed))
    shown = head(recorded)   # the head the page shows after the entry
    closed = add(recorded, "case_setting", name="closed", value={"hash_check": "ok"})
    forged_a = add(closed, "file_written", path="exports/summary.md", kind="findings_summary", format="md", rows=2,
                   bytes=changed.stat().st_size, sha256=sha(changed.read_bytes()), journal_head=head(printed))
    forged_b = add(printed, "file_written", path="exports/summary.md", kind="findings_summary", format="md", rows=2,
                   bytes=changed.stat().st_size, sha256=sha(changed.read_bytes()), journal_head=head(printed))
    crlf = tmp_path / "crlf.md"
    crlf.write_bytes(summary.read_bytes().replace(b"\n", b"\r\n"))
    never = tmp_path / "never.md"
    never.write_bytes(b"never written by the case\n")
    cases = [
        (closed, summary, head(closed), 0),        # at the close's head
        (closed, summary, shown, 0),               # at the head just after its entry
        (closed, summary, head(printed), 1),       # against the head the summary prints, before its entry
        (closed, summary, None, 1),                # with no head
        (forged_a, changed, head(closed), 1),      # forgery A: a record after the head
        (forged_a, summary, head(closed), 0),      # the genuine file still checks
        (forged_b, changed, head(printed), 1),     # forgery B: cut back to the printed head, the record after it
        (forged_b, changed, shown, 1),             # against the genuine head: not found
        (closed, crlf, head(closed), 1),           # its line endings converted
        (closed, never, head(closed), 1),          # never recorded
    ]
    for data, file, expect, code in cases:
        path.write_bytes(data)
        got, out = run_checker(path, *([expect] if expect else []), "--file", str(file))
        assert got == code, (file.name, out)
        result = check(path, expect)
        assert (result.consistent and _position(result, file.read_bytes(), expect)) == (code == 0), file.name
    path.write_bytes(closed)
    assert "converted back, it matches entry #6" in run_checker(path, head(closed), "--file", str(crlf))[1]


# Torn

TORN = {"a partial entry": b'{"seq": 6, "prev": "ab', "NUL bytes": b"\0" * 40,
        "a last line with NULs ending in LF": b'{"seq": 6, "prev": "\0\0\0\0\0"}\n'}


@pytest.mark.parametrize("name", list(TORN))
def test_a_torn_last_line_is_moved_aside_and_recorded(chained_case, name):
    path = journal_of(chained_case)
    worked(chained_case)
    data = path.read_bytes()
    path.write_bytes(data + TORN[name])
    assert check(path).tail == "torn" and not agree(path)
    j = Journal(chained_case)
    j.open_for_work()
    [side] = side_files(chained_case)
    assert side.read_bytes() == TORN[name]
    after = path.read_bytes()
    assert after.startswith(data) and len(lines(after)) == len(lines(data)) + 1
    entry = json.loads(lines(after)[-1])
    assert (entry["action"], entry["who"], entry["saved_as"], entry["bytes"], entry["sha256"]) == (
        "journal_recovered", SYSTEM, side.name, len(TORN[name]), sha(TORN[name]))
    assert "held" not in entry and j.recovered == [entry]
    assert agree(path)


def test_a_crash_during_recovery_is_finished_at_the_next_open(chained_case):
    """Side file written and the journal not cut: the next open reuses it. The journal cut and no entry written: the
    next open names the file, found."""
    path = journal_of(chained_case)
    worked(chained_case)
    data = path.read_bytes()
    torn = b'{"seq": 6, "pr'
    path.write_bytes(data + torn)
    (chained_case.folder / "journal_torn_20261017T021409118204Z.bin").write_bytes(torn)   # saved, not yet cut
    Journal(chained_case).open_for_work()
    [side] = side_files(chained_case)
    entries = [json.loads(line) for line in lines(path.read_bytes())[len(lines(data)):]]
    assert [(e["action"], e["saved_as"], e.get("found")) for e in entries] == [("journal_recovered", side.name, None)]
    path.write_bytes(data)   # cut, and the entry lost; the record names the last entry, as the open had left it
    heads.write(chained_case.folder, 5, head(data), BUILD)
    Journal(chained_case).open_for_work()
    assert side_files(chained_case) == [side]
    entry = json.loads(lines(path.read_bytes())[-1])
    assert (entry["saved_as"], entry["found"], entry["bytes"]) == (side.name, True, len(torn))
    assert agree(path)


def test_a_found_side_file_is_recorded_once(chained_case):
    path = journal_of(chained_case)
    worked(chained_case)
    copied = chained_case.folder / "journal_torn_copied.bin"
    copied.write_bytes(b"someone's bytes")
    Journal(chained_case).open_for_work()
    entry = json.loads(lines(path.read_bytes())[-1])
    assert (entry["saved_as"], entry["found"], entry["sha256"]) == ("journal_torn_copied.bin", True,
                                                                     sha(b"someone's bytes"))
    size = path.stat().st_size
    Journal(chained_case).open_for_work()
    assert path.stat().st_size == size and copied.exists()


def test_lines_that_aren_t_torn_are_breaks_and_nothing_moves(chained_case):
    path = journal_of(chained_case)
    worked(chained_case)
    data = path.read_bytes()
    cases = {
        "an unreadable whole last line": (data + b"garbage\n", "unreadable"),
        "a partial line before more lines": (add(data + b'{"seq": 6, "pr\n', "note", target=UID, text="x"),
                                             "unreadable"),
        "a whole object that doesn't chain": (data + line_bytes(envelope(9, ZERO, "note", target=UID,
                                                                         text="x"))[:-1], "tail"),
    }
    for name, (changed, kind) in cases.items():
        path.write_bytes(changed)
        j = Journal(chained_case)
        j.open_for_work()
        assert j.breaks and j.breaks[0]["kind"] == kind, name
        assert path.read_bytes() == changed and not side_files(chained_case), name
        assert not agree(path)


@WINDOWS
def test_a_write_in_progress_is_waited_for_and_never_moved(chained_case):
    """Another process holds the lock with half a line written: the append waits, then chains after the finished line;
    the overview's counts and the full check ignore the partial line."""
    from glessner.overview import journal_facts

    path = journal_of(chained_case)
    worked(chained_case)
    data = path.read_bytes()
    line = line_bytes(envelope(6, head(data), "note", target=UID, text="from the other process"))
    writer = subprocess.Popen([sys.executable, "-c", textwrap.dedent(f"""
        import msvcrt, os, sys
        fd = os.open({str(chained_case.folder / "journal.lock")!r}, os.O_RDWR | os.O_CREAT | os.O_BINARY)
        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        with open({str(path)!r}, "ab", buffering=0) as f:
            f.write({line[:30]!r})
            print("half", flush=True)
            sys.stdin.readline()
            f.write({line[30:]!r})
        """)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    try:
        assert writer.stdout.readline().strip() == "half"
        result = check(path)
        assert result.tail == "writing" and result.consistent
        assert journal_facts(path)[0] == 5
        done = []
        appender = threading.Thread(target=lambda: done.append(Journal(chained_case).append("note", target=UID,
                                                                                          text="waited")))
        appender.start()
        time.sleep(0.5)
        assert appender.is_alive() and not done
        writer.stdin.write("\n")
        writer.stdin.flush()
        appender.join(15)
        assert done and done[0]["seq"] == 7 and done[0]["prev"] == sha(line[:-1])
    finally:
        writer.kill()
        writer.wait()
    assert journal_facts(path)[0] == 7 and agree(path) and not side_files(chained_case)


# Concurrency

def test_two_journals_of_one_case_in_one_process_take_turns(chained_case):
    """Two Journal objects of one case, 200 appends each from its own thread, number 400 entries once each, and the
    chain stays consistent. A lock per object would repeat numbers."""
    first, second = Journal(chained_case, "server"), Journal(chained_case, "server")
    errors = []

    def mark(j, uid):
        try:
            for _ in range(200):
                j.append("mark", targets=[uid], value="suspicious")
        except Exception as exc:   # noqa: BLE001 - reported below, from the main thread
            errors.append(exc)

    threads = [threading.Thread(target=mark, args=(j, u)) for j, u in ((first, UID), (second, OTHER))]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    seqs = [json.loads(line)["seq"] for line in lines(journal_of(chained_case).read_bytes())]
    assert sorted(seqs) == list(range(1, 402)) and seqs == sorted(seqs)
    assert agree(journal_of(chained_case))


def test_two_processes_number_their_entries_once_each(chained_case):
    """Two processes append 200 entries each at once; the OS lock keeps them in turn."""
    script = textwrap.dedent("""
        import sys
        from pathlib import Path
        from glessner.case import open_case
        from glessner.journal import Journal
        j = Journal(open_case(Path(sys.argv[1])))
        for i in range(200):
            j.append("note", target=sys.argv[2], text=str(i))
        """)
    procs = [subprocess.Popen([sys.executable, "-c", script, str(chained_case.folder), uid]) for uid in (UID, OTHER)]
    assert [p.wait(300) for p in procs] == [0, 0]
    seqs = [json.loads(line)["seq"] for line in lines(journal_of(chained_case).read_bytes())]
    assert seqs == list(range(1, 402))
    assert agree(journal_of(chained_case))


# Each told "hold", holds the lock through held() until the next line, then lets go and appends at once
HOLDER = textwrap.dedent("""
    import sys
    from pathlib import Path
    from glessner.case import open_case
    from glessner.journal import Journal
    j = Journal(open_case(Path(sys.argv[1])))
    print("ready", flush=True)
    while sys.stdin.readline().strip() == "hold":
        with j.held():
            print("held", flush=True)
            sys.stdin.readline()
        print(j.append("note", target=sys.argv[2], text="holder")["seq"], flush=True)
    """)
# Each told "append", appends, and says "waiting" at the append's first sleep, which follows its first failed try of
# the lock
WAITER = textwrap.dedent("""
    import sys, time
    from pathlib import Path
    from glessner.case import open_case
    from glessner.journal import Journal
    j = Journal(open_case(Path(sys.argv[1])))
    sleep, told = time.sleep, False

    def waiting(seconds):
        global told
        if not told:
            told = True
            print("waiting", flush=True)
        sleep(seconds)

    time.sleep = waiting
    print("ready", flush=True)
    while sys.stdin.readline().strip() == "append":
        told = False
        print(j.append("note", target=sys.argv[2], text="waiter")["seq"], flush=True)
    """)


def test_a_waiting_process_goes_before_the_holder_takes_the_lock_again(chained_case):
    """One process holds the lock through held() while another's append waits for it; the holder lets go and appends at
    once, and the waiting append goes first, every round. Without a fair hand-off the holder, back within a fraction of
    a millisecond, takes the lock again before the waiter's next try."""
    procs = holder, waiter = [subprocess.Popen([sys.executable, "-c", script, str(chained_case.folder), uid],
                                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
                              for script, uid in ((HOLDER, UID), (WAITER, OTHER))]

    def say(proc, line=""):
        proc.stdin.write(f"{line}\n")
        proc.stdin.flush()

    def heard(proc) -> str:
        return proc.stdout.readline().strip()

    try:
        assert heard(holder) == heard(waiter) == "ready"
        for _ in range(5):
            say(holder, "hold")
            assert heard(holder) == "held"
            say(waiter, "append")
            assert heard(waiter) == "waiting"
            say(holder)   # the holder lets go, then appends at once
            assert int(heard(waiter)) < int(heard(holder))
        for proc in procs:
            proc.stdin.close()
        assert [p.wait(60) for p in procs] == [0, 0]
    finally:
        for proc in procs:
            proc.kill()
            proc.wait()
    seqs = [json.loads(line)["seq"] for line in lines(journal_of(chained_case).read_bytes())]
    assert seqs == list(range(1, 12))
    assert agree(journal_of(chained_case))


# The bytes of journal.lock: a writer holds byte 0, and a writer waiting for it holds the gate
WRITER, GATE = 0, 1
HELD_BY = pytest.mark.parametrize("byte", [WRITER, GATE], ids=["writer", "gate"])


def _holder(case, *taken: int) -> subprocess.Popen:
    """A process that locks these bytes of journal.lock, then lets go of each byte named on a line of its stdin, and
    exits when its stdin closes."""
    script = textwrap.dedent(f"""
        import msvcrt, os, sys
        fd = os.open({str(case.folder / "journal.lock")!r}, os.O_RDWR | os.O_CREAT | os.O_BINARY)
        for byte in {taken!r}:
            os.lseek(fd, byte, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        print("held", flush=True)
        for line in sys.stdin:
            os.lseek(fd, int(line), os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            print("let go", flush=True)
        """)
    proc = subprocess.Popen([sys.executable, "-c", script], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    assert proc.stdout.readline().strip() == "held"
    return proc


@WINDOWS
@HELD_BY
def test_a_killed_holder_s_lock_is_taken_within_the_wait(chained_case, byte):
    """Windows lets go of a killed process's locks: a writer's byte 0, or the gate a waiting writer holds."""
    holder = _holder(chained_case, byte)
    started = time.monotonic()
    killer = threading.Timer(0.5, holder.kill)
    killer.start()
    try:
        entry = Journal(chained_case).append("note", target=UID, text="after the kill")
    finally:
        killer.cancel()
        holder.kill()
        holder.wait()
    assert entry["seq"] == 2 and time.monotonic() - started < jm.LOCK_WAIT


@WINDOWS
@HELD_BY
def test_a_lock_held_past_the_wait_refuses_and_writes_nothing(chained_case, monkeypatch, byte):
    """Another process holds byte 0, as a writer does, or the gate, as a waiting writer does, past the wait: the append
    refuses within it and writes nothing. It tries the gate every LOCK_RETRY seconds and, once it holds the gate, byte 0
    every LOCK_TURN_RETRY: the intervals it passes to _wait_for and the sleeps it takes both show it. The refusal
    leaves journal.lock closed, and once the holder is gone the next append goes through, so it kept no lock. Only
    byte 0 is a write in progress to the check."""
    assert jm.LOCK_WAIT == 10
    monkeypatch.setattr(jm, "LOCK_WAIT", 1.0)   # the wait, shortened for the test
    waits, wait_for = [], jm._wait_for

    def recorded(fd, at, deadline, retry):
        waits.append((at, retry))
        wait_for(fd, at, deadline, retry)

    monkeypatch.setattr(jm, "_wait_for", recorded)
    sleeps, real_sleep = [], time.sleep   # the real sleep, taken before the patch below replaces it

    def recorded_sleep(seconds):
        sleeps.append(seconds)
        real_sleep(seconds)   # a recorder that returned at once would turn the wait into a spin

    path = journal_of(chained_case)
    before = path.read_bytes()
    holder = _holder(chained_case, byte)
    killer = threading.Timer(10, holder.kill)   # ends an append that waits on past the wait
    killer.start()
    try:
        assert jm._writing(path) is (byte == WRITER)
        started = time.monotonic()
        with pytest.raises(JournalError, match="Another Glessner process is writing"), monkeypatch.context() as patch:
            patch.setattr(jm.time, "sleep", recorded_sleep)   # time.sleep for the whole process, so around the append only
            Journal(chained_case).append("note", target=UID, text="refused")
        assert 0.9 < time.monotonic() - started < 5
        assert path.read_bytes() == before
        retry = jm.LOCK_TURN_RETRY if byte == WRITER else jm.LOCK_RETRY
        if byte == WRITER:
            assert waits == [(GATE, jm.LOCK_RETRY), (WRITER, jm.LOCK_TURN_RETRY)]
        else:
            assert waits == [(GATE, jm.LOCK_RETRY)]
        # An empty list would pass a check of every sleep, and sleeps that took no time would fill the wait with them
        assert sleeps and all(seconds == retry for seconds in sleeps) and len(sleeps) <= 2 * jm.LOCK_WAIT / retry
        holder.stdin.close()   # the holder exits and closes its handle
        assert holder.wait(30) == 0
    finally:
        killer.cancel()
        holder.kill()
        holder.wait()
    (chained_case.folder / jm.LOCK_FILE).unlink()   # Windows refuses to delete a file that a handle holds open
    monkeypatch.undo()   # the whole wait again
    assert Journal(chained_case).append("note", target=UID, text="after the holder")["seq"] == 2


@WINDOWS
def test_the_wait_at_the_gate_and_at_byte_0_is_one_wait(chained_case, monkeypatch):
    """Another process holds byte 0 and the gate, and lets go of the gate partway through the wait: the append takes the
    gate, then refuses at byte 0 when the one wait for both runs out, not a wait later, and keeps no lock."""
    monkeypatch.setattr(jm, "LOCK_WAIT", 2.0)   # the wait, shortened for the test
    holder = _holder(chained_case, WRITER, GATE)
    journal = Journal(chained_case)
    opened = []

    def open_gate():
        opened.append(time.monotonic() - started)
        holder.stdin.write(f"{GATE}\n")
        holder.stdin.flush()

    timers = [threading.Timer(1.2, open_gate), threading.Timer(10, holder.kill)]   # the kill ends a wait past the wait
    started = time.monotonic()
    for timer in timers:
        timer.start()
    try:
        with pytest.raises(JournalError, match="Another Glessner process is writing"):
            journal.append("note", target=UID, text="refused")
        assert 1.9 < time.monotonic() - started < 3.0
        assert opened and opened[0] < 1.8   # the gate opened well inside the wait, so the refusal came at byte 0
        assert holder.stdout.readline().strip() == "let go"
    finally:
        for timer in timers:
            timer.cancel()
        holder.kill()
        holder.wait()
    monkeypatch.undo()   # the whole wait again
    assert journal.append("note", target=UID, text="after the holder")["seq"] == 2


def test_the_held_context_is_re_entrant_in_its_thread_only(chained_case):
    """The upgrade hook's record appends inside its step's held context; another thread waits for it."""
    j = Journal(chained_case)
    order = []
    with j.held():
        other = threading.Thread(target=lambda: order.append(Journal(chained_case).append("note", target=UID,
                                                                                          text="second")["seq"]))
        other.start()
        order.append(j.append("note", target=UID, text="first")["seq"])
        time.sleep(0.2)
        assert other.is_alive()
    other.join(15)
    assert order == [2, 3]


# Remap

def _rekey_line(data: bytes, raw_extra: bytes = b"") -> bytes:
    entry = envelope(0, head(data), "case_upgrade", who=SYSTEM, from_format=4, to_format=5, text="IDs changed.",
                     rekey={"pairs": {UID: NEW}})
    entry["seq"] = json.loads(lines(data)[-1])["seq"] + 1
    raw = line_bytes(entry)[:-1]
    return data + (raw[:-1] + raw_extra + b"}" if raw_extra else raw) + b"\n"


def test_translation_comes_after_strict_parsing(case):
    """A chained line before a rekey that repeats targets is a break and is applied nowhere; a chained rekey line with
    a repeated key is a break and translates nothing."""
    path = journal_of(case)
    base = chained()
    raw = line_bytes(envelope(2, head(base), "mark", targets=[UID], value="malicious"))[:-2] + (
        b', "targets": ["' + OTHER.encode() + b'"]}\n')
    path.write_bytes(_rekey_line(base + raw))
    state = replay(path)
    assert not state.marks and [r["seq"] for r in state.rekeys] == [3]
    assert [(b["line"], b["kind"]) for b in Journal(case).breaks] == [(2, "unreadable")]
    path.write_bytes(_rekey_line(chained([MARKS[0]]), b', "text": "again"'))
    state = replay(path)
    assert set(state.marks) == {UID} and not state.rekeys
    assert found(check(path))[0] == (3, "unreadable")


def test_the_last_action_reads_the_shared_way(case):
    """overview._last_action on a chained journal: the newest analyst entry read through the rekeys after it, past a
    chained line strict parsing refuses and a last line holding 0x00, and past the app's own entries."""
    from glessner.overview import _last_action

    path = journal_of(case)
    data = _rekey_line(chained([MARKS[0]]))
    data = add(data, "note", who=SYSTEM, target=UID, text="the app's")
    refused = line_bytes(envelope(5, head(data), "note", target=UID, text="a"))[:-2] + b', "text": "b"}\n'
    path.write_bytes(data + refused + b'{"seq": 6, "who": "cody", "action": "note"\0\0\n')
    last = _last_action(path)
    assert (last["action"], last["targets"], last["ids_changed_at"]) == ("mark", [NEW], [3])
    path.write_bytes(chained())
    assert _last_action(path) is None


# Head

def test_the_head_record_follows_each_append_and_a_failed_write_fails_none(chained_case, monkeypatch):
    path = journal_of(chained_case)
    assert heads.read(chained_case.folder)["head"] == head(path.read_bytes())
    j = worked(chained_case)
    record = heads.read(chained_case.folder)
    assert (record["seq"], record["head"], record["build"]) == (5, head(path.read_bytes()), build_id())

    def fails(*args, **kwargs):
        raise OSError("the settings folder is read-only")

    monkeypatch.setattr(heads, "write", fails)
    assert j.append("note", target=UID, text="still written")["seq"] == 6
    assert heads.read(chained_case.folder)["seq"] == 5


def test_a_stale_head_record_is_found_and_what_follows_it_is_counted(chained_case):
    """A record behind the journal, as a failed write or another computer leaves, is no break: the open finds it in the
    chain, counts the entries after it by action, and moves the record to the newest line."""
    path = journal_of(chained_case)
    worked(chained_case)
    data = path.read_bytes()
    later = add(add(add(data, "mark", targets=[UID], value="malicious"), "note", target=UID, text="x"),
                "file_written", path="exports/x.csv", kind="timeline", format="csv", rows=1, bytes=1,
                sha256=sha(b"x"))
    path.write_bytes(later)
    j = Journal(chained_case, "server")
    j.open_for_work()
    assert not j.breaks
    assert j.recorded["seq"] == 5 and Counter(j.recorded["after"]) == Counter(mark=1, note=1, file_written=1)
    last = json.loads(lines(path.read_bytes())[-1])
    assert last["action"] == "case_open" and heads.read(chained_case.folder)["seq"] == last["seq"]


def test_case_yaml_is_recorded_when_it_changed(chained_case):
    path = journal_of(chained_case)
    case_file = chained_case.folder / "case.yaml"
    Journal(chained_case).append("note", target=UID, text="nothing changed")
    assert [json.loads(line)["action"] for line in lines(path.read_bytes())] == ["case_created", "note"]
    case_file.write_text(case_file.read_text(encoding="utf-8").replace("analyst: cody", "analyst: tester"),
                         encoding="utf-8")
    entry = Journal(chained_case).append("note", target=UID, text="after")
    recorded = json.loads(lines(path.read_bytes())[-2])
    assert (recorded["action"], recorded["sha256"], recorded["settings"]["analyst"]) == (
        "case_yaml", sha(case_file.read_bytes()), "tester")
    assert entry["seq"] == recorded["seq"] + 1


# The unchained tail rule, which both upgrade steps call

@pytest.mark.parametrize("tail,entry", [
    (json.dumps(note(1.0)), {"action": "note", "seq": 1.0}),
    (json.dumps(note("1")), {"action": "note", "seq": "1"}),
    (json.dumps({"at": AT, "who": "cody", "action": "case_setting", "name": "x", "value": 1}),
     {"action": "case_setting", "seq": None}),
    ("   ", None),
])
def test_unchained_tails_format_2_s_reader_applies_get_their_line_end(case, tmp_path, tail, entry):
    """Format 2's reader applied such a tail as a whole line. The current reader stops at the last LF, so it applies
    the tail only once the mend gives it its line end, and then as format 2 read it."""
    path = journal_of(case)
    path.write_bytes(unchained(note(1, OTHER)) + tail.encode())
    without = state_of(replay(path))
    assert mend_unchained(path) == [{"completed": True, "entry": entry}]
    assert path.read_bytes() == unchained(note(1, OTHER)) + tail.encode() + b"\n" and not side_files(case)
    assert (state_of(replay(path)) == without) == (entry is None or entry["action"] != "note")


def test_unchained_tails_that_aren_t_whole_are_moved_and_bad_json_stops(case):
    path = journal_of(case)
    whole = unchained(note(1), note(2))
    for torn in (b'{"seq": 3, "at', b"\0\0\0", b'{"seq": 3}\0\0\n'):
        path.write_bytes(whole + torn)
        [payload] = mend_unchained(path)
        assert path.read_bytes() == whole
        assert (case.folder / payload["saved_as"]).read_bytes() == torn and payload["bytes"] == len(torn)
    bad = whole + json.dumps({"seq": "x", "at": AT, "who": "cody", "action": "note", "target": UID,
                              "text": "x"}).encode()
    path.write_bytes(bad)
    with pytest.raises(JournalError, match="line 3 is JSON that the journal's reader can't apply"):
        mend_unchained(path)
    assert path.read_bytes() == bad


def test_a_journal_with_no_chained_line_takes_only_the_upgrade_s_entries(case):
    """An unchained journal takes no general entry, only the upgrade's own, unchained and with no head record, until
    the seal starts the chain."""
    path = journal_of(case)
    with pytest.raises(JournalError, match="has no hash chain yet"):
        Journal(case).append("note", target=UID, text="format 2")
    assert path.read_bytes() == b""
    entry = Journal(case).append_unchained("case_upgrade", who=SYSTEM, from_format=1, to_format=2, text="t")
    assert set(entry) == {"seq", "at", "who", "action", "from_format", "to_format", "text"}
    assert heads.read(case.folder) is None


# Edge cases in the chain's writers, readers, and head record

@pytest.mark.parametrize("ending", [b"", b"\n"])
def test_a_forged_entry_after_the_recorded_head_is_counted_with_or_without_its_line_end(chained_case, ending):
    """A correctly chained entry appended while the app was closed, with its LF left off, looks like a
    crash's whole entry. The open ends it, but must count it among the entries after the recorded head, as it does the
    same entry with its LF; Integrity says so, and verify's count agrees."""
    from glessner.overview import journal_row

    path = journal_of(chained_case)
    worked(chained_case)
    data = path.read_bytes()
    path.write_bytes(add(data, "mark", targets=[UID], value="authorized")[:-1] + ending)
    assert check(path, head(data)).after == {"mark": 1}
    j = Journal(chained_case, "server")
    j.open_for_work()
    assert not j.breaks and j.recorded["after"] == {"mark": 1}
    row = journal_row(j, "2026-10-18T09:00:00Z")
    assert any("The 1 entry after it was written without updating that record: 1 mark" in t for t in row["text"])
    assert state_of(j.state)[0][UID] == "authorized"


def test_a_rekey_no_build_of_this_format_wrote_translates_nothing(case):
    """A line without prev appended after the chain is a break, and its rekey must not re-point the
    earlier entries' event IDs in the state the read-only page shows. The same for a chained rekey no build of this
    format writes (a format at or below this build's own, or a seal that carries one). A later format's rekey, from
    format 4 to 5, still translates."""
    base = chained([MARKS[0]])
    pairs = {"pairs": {UID: NEW}}
    before = unchained(note(1))
    cases = {
        "unchained, after the chain": (base + unchained({"seq": 3, "at": AT, "who": SYSTEM, "action": "case_upgrade",
                                                         "from_format": 1, "to_format": 2, "text": "x", "rekey": pairs}),
                                       "no_prev"),
        "chained, format 3 to 3": (add(base, "case_upgrade", who=SYSTEM, from_format=3, to_format=3, text="x",
                                       rekey=pairs), "rekey"),
        "chained, format 3 to 4": (add(base, "case_upgrade", who=SYSTEM, from_format=3, to_format=4, text="x",
                                       rekey=pairs), "rekey"),
        "chained, format 1 to 2": (add(base, "case_upgrade", who=SYSTEM, from_format=1, to_format=2, text="x",
                                       rekey=pairs), "rekey"),
        "a seal carrying a rekey": (before + line_bytes(
            envelope(2, ZERO, "case_upgrade", who="glessner", **seal(before), rekey=pairs)), "rekey"),
    }
    path = journal_of(case)
    for name, (data, kind) in cases.items():
        path.write_bytes(data)
        j = Journal(case)
        assert kind in [b["kind"] for b in j.breaks] and j.read_only, name
        for state in (j.state, replay(path)):
            assert (set(state.marks) | set(state.notes)) == {UID} and not state.rekeys, name
        assert not agree(path), name
    path.write_bytes(add(base, "case_upgrade", who=SYSTEM, from_format=4, to_format=5, text="x", rekey=pairs))
    assert agree(path) and set(replay(path).marks) == {NEW}


def test_the_rekey_pre_scan_takes_the_lines_the_read_takes_however_they_are_spelled(tmp_path):
    """_rekeys' pre-scan and _read must take the same lines as rekeys, or the read restarts
    forever (_Reread) and every open hangs. JSON can spell a key or a string with a \\u escape, which a filter on the
    words' bytes misses, and an unchained line with a repeated key and a nested "prev" is read leniently, as format 2
    read it, where the shared rule's strict parse refuses it."""
    rekey = {"seq": 2, "at": AT, "who": SYSTEM, "action": "case_upgrade", "from_format": 1, "to_format": 2, "text": "x",
             "rekey": {"pairs": {UID: NEW}}}
    escaped = unchained(rekey).replace(b'"case_upgrade"', b'"case_upgrad\\u0065"')
    repeated = unchained(rekey).replace(b'"text": "x"', b'"text": "x", "text": "y"').replace(b"}}}", b'}, "prev": 1}}')
    chained_escaped = add(chained([MARKS[0]]), "case_upgrade", who=SYSTEM, from_format=4, to_format=5, text="x",
                          rekey={"pairs": {UID: NEW}}).replace(b'"case_upgrade"', b'"case_upgrad\\u0065"')
    cases = {"escaped, before the chain": unchained(note(1)) + escaped + unchained(note(3)),
             "repeated key, before the chain": unchained(note(1)) + repeated + unchained(note(3)),
             "escaped, chained, from format 4 to 5": chained_escaped}
    for name, data in cases.items():
        path = tmp_path / f"{len(name)}.jsonl"
        path.write_bytes(data)
        done = {}
        reader = threading.Thread(target=lambda p=path, d=done: d.setdefault("state", replay(p)), daemon=True)
        reader.start()
        reader.join(20)
        assert not reader.is_alive(), f"{name}: the read restarts forever"
        state = done["state"]
        assert NEW in (set(state.marks) | set(state.notes)) and len(state.rekeys) == 1, name
    # The read stops at the last LF, so a rekey on a last line without one translates nothing until its LF is added
    path = tmp_path / "unended.jsonl"
    path.write_bytes(add(chained([MARKS[0]]), "case_upgrade", who=SYSTEM, from_format=4, to_format=5, text="x",
                         rekey={"pairs": {UID: NEW}})[:-1])
    state = replay(path)
    assert set(state.marks) == {UID} and not state.rekeys


def _returns(name: str, read, *args):
    """What `read(*args)` returns, from a thread that must end within ten seconds, so a read that restarts forever fails
    the test instead of hanging it."""
    done = {}
    reader = threading.Thread(target=lambda: done.setdefault("result", read(*args)), daemon=True)
    reader.start()
    reader.join(10)
    assert not reader.is_alive(), f"{name}: the read restarts forever"
    return done["result"]


@pytest.mark.parametrize("lacking,value", [("client", None), ("at", "")])
def test_a_rekey_line_with_a_wrong_prev_and_an_incomplete_envelope_is_a_break_to_every_reader(case, lacking, value):
    """A chained rekey of a later format after the chain's first entry, whose prev names no line and whose envelope
    has no client or an empty at, is an envelope break to the app's readers and the checker alike. It translates
    nothing, and every reader returns."""
    path = journal_of(case)
    rekey = envelope(3, "1" * 64, "case_upgrade", who=SYSTEM, from_format=4, to_format=5, text="x",
                     rekey={"pairs": {UID: NEW}}, **{lacking: value})
    data = chained([MARKS[0]]) + line_bytes(rekey)
    path.write_bytes(data)
    journal = _returns("Journal", Journal, case)
    assert (3, "envelope") in [(b["line"], b["kind"]) for b in journal.breaks] and journal.read_only
    assert set(journal.state.marks) == {UID} and not journal.state.rekeys
    result = _returns("check", check, path)
    assert (3, "envelope") in found(result) and not result.consistent
    assert [e["action"] for e in _returns("entries", jm.entries, path)] == ["case_created", "mark"]
    state = _returns("replay", replay, path)
    assert set(state.marks) == {UID} and not state.rekeys
    copied = _returns("copied_from", jm.copied_from, case)
    assert (copied["head"], copied["seq"]) == (head(data), 3)
    code, out = run_checker(path)
    assert code == 1 and f"line 3: no {lacking} in the envelope" in out, out


def test_a_format_2_rekey_line_strict_parsing_refuses_is_a_rekey_to_the_pre_scan_and_the_read(case):
    """Before the chain, a line that names prev but repeats a key is read as format 2 read it, whatever its envelope
    lacks, so the pre-scan takes it as a rekey just as the read does, and no reader restarts forever."""
    rekey = (b'{"seq": 2, "prev": "x", "prev": "y", "at": "", "who": "glessner", "action": "case_upgrade", '
             b'"from_format": 4, "to_format": 5, "text": "x", "rekey": {"pairs": {"' + UID.encode() + b'": "'
             + NEW.encode() + b'"}}}\n')
    path = journal_of(case)
    path.write_bytes(chained([MARKS[0]], before=unchained(note(1)) + rekey + unchained(note(3, OTHER))))
    assert [n for n, _ in jm._rekeys(path, 0, 0, False)] == [2]
    journal = _returns("Journal", Journal, case)
    assert not journal.breaks and set(journal.state.notes) == {NEW, OTHER} and len(journal.state.rekeys) == 1
    assert _returns("check", check, path).consistent
    assert len(_returns("entries", jm.entries, path)) == 5
    assert set(_returns("replay", replay, path).notes) == {NEW, OTHER}
    assert _returns("copied_from", jm.copied_from, case)["seq"] == 5


FORMAT_2_REKEY = {"seq": 2, "at": AT, "who": SYSTEM, "action": "case_upgrade", "from_format": 1, "to_format": 2,
                  "text": "x", "rekey": {"pairs": {UID: NEW}}}
WIDE = ["utf-16-le", "utf-16-be", "utf-16", "utf-32-le", "utf-32-be", "utf-32"]   # "utf-16" and "utf-32" write a BOM


@pytest.mark.parametrize("encoding", WIDE)
def test_a_format_2_rekey_line_in_utf_16_or_utf_32_is_a_rekey_to_the_pre_scan_and_the_read(case, encoding):
    """json reads a line of bytes in UTF-16 or UTF-32 as well as UTF-8, so a format 2 rekey line in either, under the
    seal, is a rekey to the read. The pre-scan lists it too, every reader translates through it, and the case opens with
    no break, as the checker finds."""
    rekey = json.dumps(FORMAT_2_REKEY).encode(encoding) + b"\n"
    path = journal_of(case)
    path.write_bytes(chained([MARKS[0]], before=unchained(note(1)) + rekey + unchained(note(3, OTHER))))
    journal = _returns("Journal", Journal, case)
    assert not journal.breaks and set(journal.state.notes) == {NEW, OTHER} and len(journal.state.rekeys) == 1
    assert agree(path)
    assert [e["target"] for e in _returns("entries", jm.entries, path) if e["action"] == "note"] == [NEW, OTHER]
    assert set(_returns("replay", replay, path).notes) == {NEW, OTHER}
    assert [n for n, _ in jm._rekeys(path, 0, 0, False)] == [2]


@pytest.mark.parametrize("encoding", WIDE)
def test_a_wide_rekey_on_the_last_line_is_neither_read_nor_listed(case, encoding):
    """The read stops before a last line holding 0x00, which a UTF-16 or UTF-32 line holds, so a rekey there translates
    nothing, and the pre-scan stops where the read does."""
    path = journal_of(case)
    path.write_bytes(unchained(note(1)) + json.dumps(FORMAT_2_REKEY).encode(encoding) + b"\n")
    assert jm._rekeys(path, 0, 0, False) == []
    assert [e.get("target") for e in jm.entries(path)] == [UID]
    state = replay(path)
    assert set(state.notes) == {UID} and not state.rekeys


def test_a_rekey_line_the_state_leaves_out_translates_nothing_and_the_rekey_after_it_still_reads(case):
    """A format 2 rekey line that _apply can't take, such as one whose seq is no number, is a line the state leaves out,
    so it re-points no event ID, and the rekey right after it is still the one the read expects next. The pre-scan
    leaves it out for every reader, so the state, the trail, and entries() put the notes on the same ID, also when a
    damaged note before it puts it in the state's skip partway through a pass."""
    upgrade = {"at": AT, "who": SYSTEM, "action": "case_upgrade", "from_format": 1, "to_format": 2, "text": "x"}
    damaged_rekey = {"seq": "x", **upgrade, "rekey": {"pairs": {UID: OTHER}}}
    damaged_note = {"seq": 2, "at": AT, "who": "cody", "action": "note", "target": UID}   # no text
    cases = {
        "alone": (unchained(note(1), damaged_rekey, {"seq": 3, **upgrade, "rekey": {"pairs": {UID: NEW}}}), {2}),
        # json reads Infinity, and int() raises OverflowError on it
        "an infinite seq": (unchained(note(1), {**damaged_rekey, "seq": float("inf")},
                                      {"seq": 3, **upgrade, "rekey": {"pairs": {UID: NEW}}}), {2}),
        "after a damaged note": (unchained(note(1), damaged_note, damaged_rekey,
                                           {"seq": 4, **upgrade, "rekey": {"pairs": {UID: NEW}}}), {2, 3}),
    }
    path = journal_of(case)
    for name, (before, skipped) in cases.items():
        path.write_bytes(chained([MARKS[0]], before=before))
        rekey_line = max(skipped) + 1
        journal = _returns("Journal", Journal, case)
        assert journal.skipped_lines == skipped and not journal.breaks, name
        assert set(journal.state.notes) == {NEW} and [r["seq"] for r in journal.state.rekeys] == [rekey_line], name
        trail, _ = journal.full_check(keep=True)
        assert {e["target"] for e in trail.entries if e["action"] == "note"} == {NEW}, name
        assert sum(bool(e.get(jm.DAMAGED)) for e in trail.entries) == len(skipped), name
        assert {e["target"] for e in jm.entries(path) if e["action"] == "note"} == {NEW}, name
        assert [n for n, _ in jm._rekeys(path, 0, 0, False)] == [rekey_line], name


def test_a_rekey_the_pre_scan_misses_restarts_a_read_once_then_is_a_break(case, monkeypatch):
    """A rekey the read's pre-scan didn't list, as when another writer appends it between the two, restarts the read
    from the first line once, and the restarted read applies it. One the pre-scan still misses after the restart is a
    break that translates nothing, so no reader restarts forever."""
    path = journal_of(case)
    data = add(chained([MARKS[0]]), "case_upgrade", who=SYSTEM, from_format=4, to_format=5, text="x",
               rekey={"pairs": {UID: NEW}})
    path.write_bytes(data)
    scan, scans = jm._rekeys, []

    def misses_it_the_first_time(read, *args):
        if read == path:   # a read of another journal still running in this process isn't counted
            scans.append(read)
            if len(scans) == 1:
                return []
        return scan(read, *args)

    monkeypatch.setattr(jm, "_rekeys", misses_it_the_first_time)
    assert set(_returns("replay", replay, path).marks) == {NEW} and len(scans) == 2
    monkeypatch.setattr(jm, "_rekeys", lambda *args: [])
    journal = _returns("Journal", Journal, case)
    assert (3, "rekey") in [(b["line"], b["kind"]) for b in journal.breaks] and journal.read_only
    assert set(journal.state.marks) == {UID} and not journal.state.rekeys
    result = _returns("check", check, path)
    assert (3, "rekey") in found(result) and not result.consistent
    assert [e["action"] for e in _returns("entries", jm.entries, path)] == ["case_created", "mark"]
    state = _returns("replay", replay, path)
    assert set(state.marks) == {UID} and not state.rekeys
    copied = _returns("copied_from", jm.copied_from, case)
    assert (copied["head"], copied["seq"]) == (head(data), 3)


def test_the_last_action_reads_through_only_the_rekeys_the_shared_reader_applies(tmp_path):
    """overview._last_action reads back from the end and translates the entry it finds
    through the rekeys after it. A rekey the shared reader drops (_rekey_ok: an unchained one after the chain started, or
    a chained one no build of this format writes) must not re-point it either; format 2's rekey before the seal, and a
    later format's chained one, still do."""
    from glessner.overview import _last_action

    pairs = {"pairs": {UID: NEW}}
    unchained_rekey = {"seq": 9, "at": AT, "who": SYSTEM, "action": "case_upgrade", "from_format": 1, "to_format": 2,
                       "text": "x", "rekey": pairs}
    base = chained([MARKS[1]])
    cases = {
        "unchained, after the chain": (base + unchained(unchained_rekey), UID),
        "chained, format 1 to 2": (add(base, "case_upgrade", who=SYSTEM, from_format=1, to_format=2, text="x",
                                       rekey=pairs), UID),
        "chained, format 3 to 4": (add(base, "case_upgrade", who=SYSTEM, from_format=3, to_format=4, text="x",
                                       rekey=pairs), UID),
        "chained, format 4 to 5": (add(base, "case_upgrade", who=SYSTEM, from_format=4, to_format=5, text="x",
                                       rekey=pairs), NEW),
        "format 2's, before the seal": (chained([], unchained(note(1), {**unchained_rekey, "seq": 2})), NEW),
    }
    for name, (data, target) in cases.items():
        path = tmp_path / f"{len(name)}.jsonl"
        path.write_bytes(data)
        assert _last_action(path)["target"] == target, name
        assert replay(path).notes.get(target), name   # the shared reader puts the note under the same ID


def test_the_last_action_reads_past_a_rekey_the_state_leaves_out(tmp_path):
    """A format 2 rekey line that _apply can't take, such as one whose seq is no number, re-points no event ID for the
    shared reader, so the last action read back past it names the ID that entries() gives."""
    from glessner.overview import _last_action

    damaged_rekey = {"at": AT, "who": SYSTEM, "action": "case_upgrade", "from_format": 1, "to_format": 2, "text": "x",
                     "rekey": {"pairs": {UID: OTHER}}}
    path = tmp_path / "journal.jsonl"
    for seq in ("x", float("inf")):   # json writes the second as Infinity, which int() can't take
        path.write_bytes(chained(before=unchained(note(1), {"seq": seq, **damaged_rekey})))
        given = [e for e in jm.entries(path) if e["who"] not in jm.APP_NAMES]
        assert given[-1]["target"] == UID and _last_action(path) == given[-1], seq


def test_the_last_action_is_an_entry_the_shared_reader_gives(tmp_path):
    """The last action is the newest entry by someone that entries() gives. The read stops at the last LF, and before a
    last line holding 0x00, which format 2's parse can read as UTF-16. After the chain starts, a line that names no prev
    is chained too, so it is given only with a seq, and as a rekey it re-points nothing, also when the entry before it
    names no prev either."""
    from glessner.overview import _last_action

    base = chained([MARKS[1]])   # the note "first look" on UID
    rekey = {"seq": 4, "at": AT, "who": SYSTEM, "action": "case_upgrade", "from_format": 1, "to_format": 2, "text": "x",
             "rekey": {"pairs": {UID: NEW}}}
    torn = line_bytes(envelope(3, head(base), "note", target=UID, text="still being written"))[:-1]
    cases = {
        "a last line missing only its LF": base + torn,
        "a last line holding 0x00": unchained(note(1)) + json.dumps(note(2, text="wide")).encode("utf-16-le") + b"\n",
        "a line that names no prev and has no seq": base + unchained(note("x", text="no number")),
        "a rekey that names no prev": base + unchained(note(3, text="no prev"), rekey),
    }
    for n, (name, data) in enumerate(cases.items()):
        path = tmp_path / f"{n}.jsonl"
        path.write_bytes(data)
        given = [e for e in jm.entries(path) if e["who"] not in jm.APP_NAMES]
        assert _last_action(path) == given[-1], name


def test_a_case_upgrade_goes_up():
    with pytest.raises(JournalError, match="goes up"):
        jm._validate("case_upgrade", {"from_format": 3, "to_format": 3, "text": "x"})
    jm._validate("case_upgrade", {"from_format": 3, "to_format": 4, "text": "x"})


def test_a_chain_break_or_a_rekey_after_the_recorded_head_gets_a_sentence_of_its_own(chained_case):
    """A chain_break or case_upgrade among the entries after the head this app recorded is not one count among
    others: the app records its head right after it writes either."""
    from glessner.overview import journal_row

    path = journal_of(chained_case)
    worked(chained_case)
    data = path.read_bytes()
    sealed = {"lines": len(lines(data)), "bytes": len(data), "sha256": sha(data)}
    cases = {"chain_break": add(data, "chain_break", reason="x", breaks=[], sealed=sealed),
             "case_upgrade": add(data, "case_upgrade", who=SYSTEM, from_format=4, to_format=5, text="x",
                                 rekey={"pairs": {UID: NEW}})}
    for action, changed in cases.items():
        path.write_bytes(changed)
        j = Journal(chained_case, "server")
        j.open_for_work()
        assert j.recorded["after"] == {action: 1}, action
        text = " ".join(journal_row(j, "2026-10-18T09:00:00Z")["text"])
        assert f"A {action} among them" in text and "check who added it" in text, action
        path.write_bytes(data)
        heads.write(chained_case.folder, 5, head(data), BUILD)


def test_a_later_append_checks_the_recorded_head_before_moving_a_torn_line_aside(chained_case):
    """A running app's next append checks the recorded head before it recovers a torn tail, at every append that would
    recover one, not only the object's first. Another process's NUL-filled entry is then a break and nothing is moved
    aside as a crash's, which would move the record past it."""
    path = journal_of(chained_case)
    running = worked(chained_case)
    Journal(chained_case).append("note", target=UID, text="from another process")   # the record names it
    data = path.read_bytes()
    nulled = data[:-12] + b"\0" * 11 + b"\n"
    path.write_bytes(nulled)
    with pytest.raises(JournalError, match="changed after it was written"):
        running.append("mark", targets=[UID], value="authorized")
    assert path.read_bytes() == nulled and not side_files(chained_case)
    assert [p["kind"] for p in running.breaks] == ["record_missing"] and heads.read(chained_case.folder)["seq"] == 6


def test_a_number_too_big_for_a_float_is_not_finite_in_the_app_and_the_checker(case):
    """1e999 parses as inf, so a chained line holding it is unreadable, as NaN and the infinities are, and not an
    entry."""
    base = chained([MARKS[0]])
    good = line_bytes(envelope(3, head(base), "note", target=UID, text="a"))[:-1]
    path = journal_of(case)
    for number in (b"1e999", b"-1e999", b"1E+400"):
        path.write_bytes(_bad(base, good[:-1] + b', "seconds": ' + number + b"}"))
        assert not agree(path), number
        assert Journal(case).read_only
    path.write_bytes(_bad(base, good[:-1] + b', "seconds": 1e300}'))
    assert agree(path)


def test_a_nul_line_before_unended_bytes_is_one_unreadable_line_to_the_app_and_the_checker(case):
    """A last LF-ended line holding NUL bytes, with more bytes after it and no LF, is a line of the chain that
    doesn't read, and the bytes after it are the torn tail. The checker and the app name the same head."""
    path = journal_of(case)
    path.write_bytes(chained(MARKS) + b'{"seq": 6, "pr\0\0\0\n' + b'{"seq": 7')
    result = check(path)
    code, out = run_checker(path)
    assert code == 1 and not result.consistent and result.tail == "torn"
    assert f"head {result.head} (entry #{result.seq})" in out
    assert (6, "unreadable") in found(result)


@pytest.mark.parametrize("ending", [b"\n", b""])
def test_a_line_nested_too_deep_for_json_is_unreadable_to_the_checker_as_to_the_app(case, ending):
    """A line of 200,000 open brackets is deeper than Python's JSON reader goes. The checker reports it, with or
    without its LF, as it reports any line it can't read, and names the head the app names."""
    path = journal_of(case)
    path.write_bytes(chained(MARKS) + b"[" * 200_000 + ending)
    assert not agree(path)
    code, out = run_checker(path)
    assert code == 1 and ("line 6: not one JSON object" if ending else "200,000 bytes after the last whole line") in out, out


def test_the_checker_names_a_journal_or_file_it_can_t_read_and_exits_2(case, tmp_path):
    """A missing journal or --file, or a folder given as either, is one line naming it and exit 2, which no journal
    gives: exit 1 says the journal or the file failed the check."""
    path = journal_of(case)
    path.write_bytes(chained(MARKS))
    missing = tmp_path / "missing.md"
    for args in ([missing], [tmp_path], [path, "--file", missing], [path, "--file", tmp_path]):
        code, out = run_checker(*map(str, args))
        assert code == 2 and len(out.splitlines()) == 1 and str(args[-1]) in out, out


class _ClosedPipe:
    """Standard output whose reader is gone, as when the checker's output is piped into head -1."""

    def write(self, text):
        raise BrokenPipeError(errno.EPIPE, "Broken pipe")

    def flush(self):
        pass


@pytest.mark.parametrize("with_file", [False, True])
def test_the_checker_raises_an_os_error_that_names_no_file_as_it_is(case, monkeypatch, with_file):
    """Exit 2 is for a journal or --file the checker can't read. An OSError that names no file, such as a broken pipe
    on its output, is raised as it is, with or without --file."""
    path = journal_of(case)
    path.write_bytes(chained(MARKS))
    monkeypatch.setattr(sys, "argv", [str(CHECKER), str(path), *(["--file", str(path)] if with_file else [])])
    monkeypatch.setattr(sys, "stdout", _ClosedPipe())
    with pytest.raises(BrokenPipeError):
        runpy.run_path(str(CHECKER), run_name="__main__")


def test_a_named_side_file_that_changed_or_went_missing_is_a_problem_in_the_app_and_the_checker(chained_case):
    """The chain covers a side file's hash in its journal_recovered entry, so replacing the file must
    show. It shows in verify and Check now, not at the open; the checker looks beside the journal."""
    path = journal_of(chained_case)
    worked(chained_case)
    path.write_bytes(path.read_bytes() + b'{"seq": 6, "pr')
    Journal(chained_case).open_for_work()
    [side] = side_files(chained_case)
    original = side.read_bytes()
    assert agree(path)
    side.write_bytes(original + b"x")
    result = check(path)
    assert [p["kind"] for p in result.problems] == ["side_file"] and not agree(path)
    assert side.name in result.problems[0]["text"] and "differs" in result.problems[0]["text"]
    side.unlink()
    assert "is missing" in check(path).problems[0]["text"] and not agree(path)
    side.write_bytes(original)
    assert agree(path)


def test_a_seal_s_side_file_is_checked_too(case):
    before = unchained(note(1))
    torn = b'{"seq": 2, "at'
    side = case.folder / "journal_torn_20261018T000000000000Z.bin"
    side.write_bytes(torn)
    recovered = [{"saved_as": side.name, "bytes": len(torn), "sha256": sha(torn)}]
    path = journal_of(case)
    path.write_bytes(before + line_bytes(envelope(2, ZERO, "case_upgrade", who="glessner", **seal(before),
                                                   recovered=recovered)))
    assert agree(path)
    side.write_bytes(b"other")
    assert not agree(path) and check(path).problems[0]["kind"] == "side_file"


def test_a_side_file_format_2_s_step_named_before_the_chain_is_checked_too(chained_case):
    """A format 1 case with a torn last line gets format 2's entry unchained, naming the side file in its
    `recovered`, and the seal covers its recorded hash. Both readers look at the unchained region for side files, so
    a file deleted or altered after the upgrade is a problem in verify, Check now, and the checker."""
    folder, path = chained_case.folder, journal_of(chained_case)
    as_format(folder, 1, unchained(note(1)) + b'{"seq": 2, "action": "note",')
    upgraded(open_case(folder))
    Journal(open_case(folder)).open_for_work()
    [side] = side_files(chained_case)
    entries = [json.loads(line) for line in lines(path.read_bytes())]
    named = [e for e in entries if "prev" not in e and e.get("recovered")]
    assert [(e["seq"], [r["saved_as"] for r in e["recovered"]]) for e in named] == [(2, [side.name])]
    assert not [e for e in entries if e["action"] == "journal_recovered"]   # nothing was added for it at the open
    expect = heads.read(folder)["head"]
    data, original = path.read_bytes(), side.read_bytes()
    assert agree(path, expect)
    side.write_bytes(original + b"x")
    result = check(path, expect)
    assert [p["kind"] for p in result.problems] == ["side_file"] and not agree(path, expect)
    assert side.name in result.problems[0]["text"] and "entry #2" in result.problems[0]["text"]
    side.unlink()
    assert "is missing" in check(path, expect).problems[0]["text"] and not agree(path, expect)
    assert Journal(open_case(folder)).read_only == ""   # a problem for verify and Check now, not a break at the open
    side.write_bytes(original)
    assert agree(path, expect) and path.read_bytes() == data


def test_the_last_action_skips_a_chained_line_with_an_incomplete_envelope(case):
    """Every other reader leaves out a chained line whose envelope is incomplete, so the overview's last action must
    not show it."""
    from glessner.overview import _last_action

    data = chained([MARKS[1]])
    entry = envelope(3, head(data), "note", target=OTHER, text="forged")
    del entry["build"]
    journal_of(case).write_bytes(data + line_bytes(entry))
    assert _last_action(journal_of(case))["text"] == "first look"


def test_the_overview_loads_on_a_broken_chain_whose_changed_line_is_the_close_entry(chained_case):
    """journal_facts reads a closed case_setting line without assuming it is a JSON object, so a whole line that holds
    both words and isn't one doesn't stop the page from loading on the read-only case it leaves."""
    from glessner.overview import journal_facts

    path = journal_of(chained_case)
    j = worked(chained_case)
    j.append("case_setting", name="closed", value={"hash_check": "ok"})
    data = path.read_bytes()
    for broken in (lines(data)[-1][:-1], b'["case_setting", "closed"]'):
        path.write_bytes(join(lines(data)[:-1] + [broken]))
        entries, close = journal_facts(path)
        assert entries == 6 and close is None
        assert Journal(chained_case).read_only


# A payload replay can't apply. The seven payloads of the full open, Continue, and the trail are test_format3's.

def test_a_changed_key_byte_in_a_payload_opens_read_only(case):
    """One byte of a payload's key changed makes _apply raise a KeyError, where a changed value only changes what is
    applied. The line is not applied, the lines after it are, and the break is the next line's prev."""
    path = journal_of(case)
    rows = lines(chained(MARKS))
    rows[1] = rows[1].replace(b'"targets"', b'"targetz"')
    path.write_bytes(join(rows))
    assert found(check(path)) == [(3, "prev")] and not agree(path)
    journal = Journal(case)
    assert journal.read_only and set(journal.state.marks) == {OTHER}
    assert {uid: len(on) for uid, on in journal.state.notes.items()} == {UID: 1, OTHER: 1}


def test_a_changed_last_line_replay_cannot_apply_opens_without_the_entry_and_the_recorded_head_shows_it(case):
    """Nothing follows the newest line, so the chain finds no break there. The case opens read-write with the entry
    absent; only a head kept outside the case shows the change."""
    path = journal_of(case)
    base = chained(MARKS[:2])
    rows = lines(base)
    rows[-1] = rows[-1].replace(b'"target"', b'"targit"')
    path.write_bytes(join(rows))
    assert check(path).consistent
    journal = Journal(case)
    assert not journal.read_only and set(journal.state.marks) == {UID} and not journal.state.notes
    heads.write(case.folder, 3, head(base), build_id())
    journal = Journal(case)
    journal.open_for_work()
    assert "record_missing" in [p["kind"] for p in journal.problems] and journal.read_only


def test_an_entry_that_fails_only_against_the_state_is_left_out_of_the_journal_s_state_and_the_undo_plan_s(case):
    """A finding edit whose techniques aren't a list applies to no state without its finding, so the dry run that
    marks damaged entries passes it, and _apply fails on it only when the finding exists. The journal and the undo plan
    build their states again without it."""
    from glessner import audit

    path = journal_of(case)
    path.write_bytes(chained([("finding", {"op": "add", "title": "T", "severity": "High"}),
                              ("finding", {"op": "edit", "finding": 2, "techniques": 5}),
                              ("mark", {"targets": [UID], "value": "suspicious"})]))
    result = check(path, keep=True)
    assert result.consistent and not [e for e in result.entries if e.get(jm.DAMAGED)]
    journal = Journal(case)
    assert not journal.read_only and set(journal.state.marks) == {UID}
    assert journal.state.findings[2]["techniques"] == [] and journal.state.findings[2]["edited"] is None
    plan = audit.plan_undo(result.entries, 4)
    assert plan["changes"] == [{"action": "mark", "targets": [UID], "value": "unreviewed", "note": ""}]


def test_a_whole_unchained_line_replay_cannot_apply_stops_replay_as_format_2_did_but_not_the_journal(case):
    """replay() skips only chained lines it can't apply, so the upgrade's check of the unchained lines still stops
    on one, as format 2's reader did; the journal, which opens a sealed case, leaves the line out. The seal covers it, so
    the chain is consistent, and the trail marks it."""
    bad = {"seq": 2, "at": AT, "who": "cody", "action": "mark", "targets": None, "value": "suspicious"}
    path = journal_of(case)
    path.write_bytes(chained(MARKS[:1], before=unchained(note(1), bad, note(3, OTHER))))
    with pytest.raises(JournalError, match=r"line 2 is JSON that the journal's reader can't apply.*Nothing was changed"):
        replay(path)
    journal = Journal(case)
    assert not journal.read_only and set(journal.state.marks) == {UID}
    assert {uid: len(on) for uid, on in journal.state.notes.items()} == {UID: 1, OTHER: 1}
    assert agree(path) and [e["seq"] for e in check(path, keep=True).entries if e.get(jm.DAMAGED)] == [2]


# Where the chain starts: one rule for the shared reader, has_chain, the rekey pre-scan, and the checker. The
# checker's rows for a first line missing only its LF are in CHECKER_CASES; the open and Continue are test_format3's.

def test_a_prev_spelled_with_an_escape_starts_the_chain_for_every_app_reader(case):
    """JSON reads "\\u0070rev" as the key prev, and the checker reads parsed keys, so every app reader takes the line
    as chained, not as format 1's or 2's: the shared reader, has_chain, the upgrade, which seals nothing over it and
    writes only the 3 to 4 entry after the open's case_yaml, and parse_line, which refuses it as strictly as a line
    holding `"prev"` when it repeats a key."""
    first = envelope(1, ZERO, "case_created", who="glessner", **created())
    data = add(spelled(first), "mark", targets=[UID], value="suspicious")
    path = journal_of(case)
    path.write_bytes(data)
    assert jm.has_chain(path) and check(path).chain.start == {"line": 1, "seq": 1, "action": "case_created"}
    path.write_bytes(spelled(first))   # alone, no line after it that names prev as the plain letters do
    assert jm.has_chain(path)
    path.write_bytes(data)
    assert agree(path) and set(replay(path).marks) == {UID} and set(Journal(case).state.marks) == {UID}
    repeated = spelled(first).replace(b'"who": "glessner"', b'"who": "glessner", "who": "x"')[:-1]
    assert jm.parse_line(repeated) is None and jm.parse_line(spelled(first)[:-1])["prev"] == ZERO
    # The upgrade of a format 2 case that holds such a line takes the chain as started and seals nothing
    as_format(case.folder, 2, data)
    upgraded(open_case(case.folder))
    after = path.read_bytes()
    assert after.startswith(data) and open_case(case.folder).settings.case_format == 4
    written = [json.loads(line) for line in after[len(data):].splitlines()]
    assert [(e["action"], e.get("from_format"), e.get("to_format")) for e in written] == [
        ("case_yaml", None, None), ("case_upgrade", 3, 4)]


def test_the_rekey_pre_scan_starts_the_chain_where_the_read_does_when_prev_is_spelled_with_an_escape(tmp_path):
    """_rekeys' pre-scan and the read both take the first line as the chain's start when it spells prev with an
    escape, so a format 2 rekey line after that chain is no rekey to either, and replay doesn't translate the mark's
    event ID with a rekey it never applied. Every chained line before the rekey spells prev with an escape, since one
    that holds `"prev"` as written starts the chain for the pre-scan."""
    first = spelled(envelope(1, ZERO, "case_created", who="glessner", **created()))
    rekey = {"seq": 3, "at": AT, "who": SYSTEM, "action": "case_upgrade", "from_format": 1, "to_format": 2, "text": "x",
             "rekey": {"pairs": {UID: NEW}}}
    mark = spelled(envelope(2, sha(lines(first)[-1]), "mark", targets=[UID], value="suspicious"))
    data = first + mark + unchained(rekey)
    path = tmp_path / "journal.jsonl"
    path.write_bytes(data)
    assert jm._rekeys(path, 0, 0, False) == []
    state = replay(path)
    assert set(state.marks) == {UID} and not state.rekeys


# More payloads replay can't apply: maps that aren't maps, many changed lines, a nested undo, a number that isn't
# one, and a skipped line the other readers must agree on.

@pytest.mark.parametrize("pairs", [[1], "abc", 5, True])
def test_a_rekey_whose_maps_are_no_maps_translates_nothing_and_opens(case, pairs):
    """A case_upgrade whose `pairs` or `unplaced` is a list, a string, or a number passes the chain (a 4 to 5 line
    after the head is no break). It translates nothing, the case opens, `verify --journal` doesn't crash, and every
    reader of the maps gets an empty one."""
    path = journal_of(case)
    path.write_bytes(add(chained(MARKS[:2]), "case_upgrade", who=SYSTEM, from_format=4, to_format=5, text="x",
                         rekey={"pairs": pairs, "unplaced": pairs}))
    assert agree(path)
    journal = Journal(case)
    assert not journal.read_only and set(journal.state.marks) == {UID} and set(replay(path).marks) == {UID}
    assert jm.renamed(journal.state, UID) is None and jm.unplaced(journal.state) == {}
    assert jm.unplaced_count(journal.state) == 0 and len(journal.state.rekeys) == 1


def test_an_unchained_rekey_with_no_pairs_map_under_a_seal_opens(case):
    """The same line in a format 1 or 2 journal, which translate reaches before the seal does."""
    rekey = {"seq": 2, "at": AT, "who": SYSTEM, "action": "case_upgrade", "from_format": 1, "to_format": 2, "text": "x",
             "rekey": {"pairs": [1]}}
    path = journal_of(case)
    path.write_bytes(chained(MARKS[:1], before=unchained(note(1), rekey, note(3, OTHER))))
    assert agree(path)
    journal = Journal(case)
    assert not journal.read_only and set(journal.state.marks) == {UID} and set(replay(path).marks) == {UID}


def test_a_chained_rekey_of_format_2_to_3_with_no_map_is_a_rekey_break_in_both_readers(case):
    """Reading the maps defensively keeps the line a break: tightening is_rekey instead would make it a plain entry in the
    app while the checker still called it a foreign rekey."""
    path = journal_of(case)
    path.write_bytes(add(chained(MARKS[:2]), "case_upgrade", who=SYSTEM, from_format=2, to_format=3, text="x",
                         rekey={"pairs": [1]}))
    assert not agree(path) and "rekey" in [kind for _, kind in found(check(path))]
    assert Journal(case).read_only


def test_many_changed_lines_open_after_one_rebuild(case, monkeypatch):
    """Each line _apply can't take must not cost a rebuild of its own: one that _catch_up made by calling itself would
    end in RecursionError at the open on about a thousand changed lines, and take 13 s on fifty in 20,000. After the
    first failure the rebuild tries each entry on an empty state first, so the lines it can't take are skipped in that
    pass."""
    rows = lines(chained(MARKS[:1]))
    for seq in range(3, 1103):
        rows.append(line_bytes(envelope(seq, sha(rows[-1]), "mark", targets=None, value="suspicious"))[:-1])
    rows.append(line_bytes(envelope(1103, sha(rows[-1]), "note", target=OTHER, text="after"))[:-1])
    path = journal_of(case)
    path.write_bytes(join(rows))
    resets = []
    reset = Journal._reset
    monkeypatch.setattr(Journal, "_reset", lambda self: (resets.append(1), reset(self))[1])
    journal = Journal(case)
    assert len(resets) <= 2 and len(journal.skipped_lines) == 1100
    assert not journal.read_only and set(journal.state.marks) == {UID}
    assert [n["text"] for n in journal.state.notes[OTHER]] == ["after"]
    assert len(check(path, keep=True).entries) == 1103 and set(replay(path).marks) == {UID}


def test_an_undo_nested_a_thousand_deep_is_one_more_entry_replay_cannot_apply(case):
    """The chain calls such a line consistent and the checker exits 0, so _apply must not recurse until
    RecursionError, which is no replay error and would keep the case from opening. The writer never nests an undo, so
    _apply refuses a change that is one."""
    base = chained([*MARKS[:1], ("undo", {"undoes": 2, "correction": "accident", "changes": []})])
    rows = lines(base)
    nest = (b'{"action": "undo", "changes": [' * 1200 + b'{"action": "mark", "targets": [], "value": "suspicious"}'
            + b"]}" * 1200)
    rows[-1] = rows[-1].replace(b'"changes": []', b'"changes": [' + nest + b"]")
    path = journal_of(case)
    path.write_bytes(join(rows))
    assert agree(path)
    journal = Journal(case)
    assert not journal.read_only and set(journal.state.marks) == {UID}
    assert [e["seq"] for e in check(path, keep=True).entries if e.get(jm.DAMAGED)] == [3]


def test_the_undo_plan_reads_a_damaged_line_whose_seq_is_no_number(case):
    """An unchained line with a seq that isn't a number is marked damaged, and state_before and plan_undo look at the
    mark before they compare its seq, so an undo of the case doesn't raise TypeError."""
    from glessner import audit

    before = unchained(note("x"), note(2, OTHER))
    path = journal_of(case)
    path.write_bytes(chained([("mark", {"targets": [UID], "value": "suspicious"})], before=before))
    result = check(path, keep=True)
    assert result.consistent and [e["seq"] for e in result.entries if e.get(jm.DAMAGED)] == ["x"]
    plan = audit.plan_undo(result.entries, 4)
    assert plan["changes"] == [{"action": "mark", "targets": [UID], "value": "unreviewed", "note": ""}]


def test_the_trail_marks_what_the_state_left_out_for_failing_against_it(case):
    """check(keep=True) tries each entry on an empty state, and a finding edit with techniques that aren't a list
    passes that and fails only against its finding, so the journal's state skips the line and the trail would show it
    as an entry that applied. The journal's full check marks the lines the journal skipped."""
    from glessner import audit

    path = journal_of(case)
    path.write_bytes(chained([("finding", {"op": "add", "title": "T", "severity": "High"}),
                              ("finding", {"op": "edit", "finding": 2, "techniques": 5}),
                              ("mark", {"targets": [UID], "value": "suspicious"})]))
    journal = Journal(case)
    result, _ = journal.full_check(keep=True)
    assert [e["seq"] for e in result.entries if e.get(jm.DAMAGED)] == [3]
    shown = {r["seq"]: r for r in audit.rows(result.entries, {})["rows"]}
    assert "can't be replayed" in shown[3]["text"] and not shown[3]["undoable"] and shown[4]["undoable"]
    with pytest.raises(audit.AuditError, match="can't be undone"):
        audit.plan_undo(result.entries, 3)


def test_integrity_counts_a_skipped_line_after_the_recorded_head(case):
    """_kept holds only the lines the state applied, so a changed last line after the recorded head must still count
    for Integrity as an entry written since the record."""
    base = chained(MARKS[:2])
    rows = lines(add(base, "mark", targets=[OTHER], value="malicious"))
    rows[-1] = rows[-1].replace(b'"targets"', b'"targetz"')
    path = journal_of(case)
    path.write_bytes(join(rows))
    heads.write(case.folder, 3, head(base), build_id())
    journal = Journal(case)
    journal.open_for_work()
    assert journal.skipped_lines == {4} and not journal.read_only
    assert journal.recorded["seq"] == 3 and journal.recorded["after"] == {"mark": 1}
