"""The journal's record of manifest.jsonl (manifest_recorded): intake, Add new evidence, and a copy write it, each only
after the append's own checks and right after the file is replaced, and verify, close, and the report compare the file
with the record that counts: matches, grew, differs, or none."""

import hashlib
import json
import re
from dataclasses import asdict, replace
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from chain_fixtures import add, format3_case
from rekey_cases import set_format
from test_custody import report_section
from test_format3 import entries_of, journal_path, opened, wait

from glessner import heads
from glessner import intake as intake_module
from glessner.audit import KINDS, describe, lookups, read_entries
from glessner.case import CaseError, open_case
from glessner.cli import main
from glessner.intake import ManifestCheck, ManifestEntry, add_new, intake, manifest_text
from glessner.journal import Journal, JournalError, check, unvouched_words
from glessner.overview import _manifest_row
from glessner.server import App, api_case_state, api_evidence_add, api_overview, api_report
from glessner.start import start_new_case


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def records(case) -> list[dict]:
    return [e for e in entries_of(case) if e["action"] == "manifest_recorded"]


def described(case, entry: dict) -> str:
    """The trail's words for one entry, with the lookups of the whole journal."""
    found = read_entries(journal_path(case))
    return describe(next(e for e in found if e["seq"] == entry["seq"]), {}, lookups(found))


def last_check(case) -> dict:
    return json.loads(case.verification_path.read_text(encoding="utf-8").splitlines()[-1])


def evidence_file(case, name: str, text: str = "evidence") -> None:
    (case.evidence / "DC01" / name).write_text(text, encoding="utf-8")


@pytest.fixture
def recorded_case(synthetic_case):
    """synthetic_case with two evidence files, taken in by the intake command, so the journal records the manifest."""
    evidence_file(synthetic_case, "a.txt", "first")
    evidence_file(synthetic_case, "b.txt", "second")
    assert main(["intake", str(synthetic_case.folder)]) == 0
    return synthetic_case


def counted_hashing(monkeypatch) -> list[str]:
    """The evidence files hashed from now on, by name."""
    real, hashed = intake_module.sha256_file, []

    def sha256_file(path):
        hashed.append(path.name)
        return real(path)

    monkeypatch.setattr(intake_module, "sha256_file", sha256_file)
    return hashed


def test_a_manifest_record_needs_its_hash_its_counts_and_how_it_was_written(synthetic_case):
    """A manifest_recorded entry gives manifest.jsonl's SHA-256, its bytes and its lines that aren't blank, each an
    integer from 0, and what wrote it: intake, Add new evidence, or a copy of the case."""
    journal = Journal(synthetic_case)
    good = {"sha256": sha(b"x"), "bytes": 1, "lines": 1, "via": "intake"}
    for bad in ({k: v for k, v in good.items() if k != "sha256"}, {**good, "bytes": -1}, {**good, "lines": 1.5},
                {**good, "lines": "1"}, {**good, "bytes": True}, {**good, "via": "upload"}):
        with pytest.raises(JournalError, match="manifest_recorded needs"):
            journal.append("manifest_recorded", **bad)
    entry = journal.append("manifest_recorded", **good)
    assert {k: entry[k] for k in good} == good and entry["who"] == "cody"
    assert journal.state.manifests == [{"seq": entry["seq"], "at": entry["at"], "who": "cody", **good}]
    assert KINDS["manifest_recorded"] == "Integrity"


def test_intake_and_add_new_evidence_record_the_manifest_once_and_a_refused_replace_records_nothing(
        recorded_case, monkeypatch):
    """The intake command records the manifest it wrote, by the analyst. Add new evidence, from the command line and the
    page, records the bytes it wrote, once. A replace Windows refuses raises before the record, so the manifest and the
    journal's records stay as they were."""
    case = recorded_case
    (first,) = records(case)
    data = case.manifest_path.read_bytes()
    assert {k: first[k] for k in ("who", "client", "sha256", "bytes", "lines", "via")} == {
        "who": "cody", "client": "cli", "sha256": sha(data), "bytes": len(data), "lines": 2, "via": "intake"}

    evidence_file(case, "c.txt")
    assert main(["intake", str(case.folder), "--add"]) == 0
    data = case.manifest_path.read_bytes()
    assert [(r["via"], r["sha256"], r["bytes"], r["lines"]) for r in records(case)[1:]] == [
        ("add", sha(data), len(data), 3)]

    evidence_file(case, "d.txt")
    app = App(case)
    try:
        assert api_evidence_add(app, {})["files"] == 1
    finally:
        app.con.close()
    data = case.manifest_path.read_bytes()
    assert [(r["via"], r["client"], r["sha256"], r["lines"]) for r in records(case)[2:]] == [
        ("add", "server", sha(data), 4)]

    evidence_file(case, "e.txt")

    def refused(path, data, shared=False):
        raise PermissionError(13, "The process cannot access the file")

    monkeypatch.setattr(intake_module, "write_atomically", refused)
    with pytest.raises(PermissionError):
        main(["intake", str(case.folder), "--add"])
    assert case.manifest_path.read_bytes() == data and len(records(case)) == 3


def test_a_new_case_from_the_start_page_records_its_intake(tmp_path):
    evidence = tmp_path / "evidence" / "DC01"
    evidence.mkdir(parents=True)
    (evidence / "a.txt").write_text("first", encoding="utf-8")
    job = wait(start_new_case({"name": "New", "evidence": str(evidence.parent), "case_folder": str(tmp_path / "case")},
                              "cody", lambda case: None))
    case = open_case(Path(job.case_folder))
    data = case.manifest_path.read_bytes()
    assert [(r["via"], r["client"], r["who"], r["sha256"], r["lines"]) for r in records(case)] == [
        ("intake", "server", "cody", sha(data), 1)]


def test_the_manifest_changing_while_add_new_evidence_hashes_is_refused_under_the_lock(recorded_case, monkeypatch,
                                                                                       capsys):
    """Another writer's change to manifest.jsonl while Add new evidence hashes is found under the journal's lock, before
    the replace: nothing is added over it, and nothing is recorded."""
    case = recorded_case
    evidence_file(case, "c.txt")
    other = case.manifest_path.read_bytes() + b'{"path": "DC01/other.txt"}\n'
    real = intake_module.sha256_file

    def meanwhile(path):
        case.manifest_path.write_bytes(other)
        return real(path)

    monkeypatch.setattr(intake_module, "sha256_file", meanwhile)
    assert main(["intake", str(case.folder), "--add"]) == 2
    assert "manifest.jsonl changed while Add new evidence was hashing" in capsys.readouterr().err
    assert case.manifest_path.read_bytes() == other and len(records(case)) == 1


def change_a_payload(case) -> None:
    """A middle line's text changed after it was written: the line after it no longer names it."""
    path = journal_path(case)
    path.write_bytes(path.read_bytes().replace(b'"text": "first look"', b'"text": "FIRST LOOK"'))


def remove_the_chain(case) -> None:
    journal_path(case).write_bytes(b"")


def remove_the_newest_entry(case) -> None:
    """The newest line removed, so the head recorded outside the case names no line."""
    path = journal_path(case)
    path.write_bytes(b"".join(path.read_bytes().splitlines(keepends=True)[:-1]))


BREAKS = {"a changed payload": change_a_payload, "a missing chain": remove_the_chain,
          "a removed newest entry": remove_the_newest_entry}


@pytest.mark.parametrize("route", ["intake", "start", "add", "page"])
@pytest.mark.parametrize("name", list(BREAKS))
def test_a_broken_chain_refuses_intake_and_add_new_evidence_before_any_file_is_hashed(synthetic_case, monkeypatch,
                                                                                      route, name):
    """On a broken chain the journal can't take the record, so intake and Add new evidence refuse, from the command line
    and the page, before any evidence file is hashed, and manifest.jsonl stays as it was, or absent. intake's own check
    refuses too, as the start page calls it, with a Journal that no open for work has checked."""
    case = synthetic_case
    evidence_file(case, "a.txt")
    if route not in ("intake", "start"):
        assert main(["intake", str(case.folder)]) == 0
        evidence_file(case, "b.txt")
    journal = Journal(case)
    journal.append("note", target="0" * 32, text="first look")
    journal.append("note", target="0" * 32, text="second look")
    before = case.manifest_path.read_bytes() if case.manifest_path.exists() else None
    BREAKS[name](case)
    hashed = counted_hashing(monkeypatch)
    if route == "page":
        app = App(case)
        try:
            with pytest.raises(JournalError, match="The journal was changed after it was written"):
                api_evidence_add(app, {})
        finally:
            app.con.close()
    elif route == "start":
        with pytest.raises(JournalError):
            intake(case, journal=Journal(case, "server"))
    else:
        assert main(["intake", str(case.folder), *(["--add"] if route == "add" else [])]) == 2
    assert hashed == []
    assert (case.manifest_path.read_bytes() if case.manifest_path.exists() else None) == before


def test_a_break_made_while_add_new_evidence_hashes_leaves_the_manifest_as_it_was(recorded_case, monkeypatch):
    """The append's checks run under the journal's lock before the replace, so a break made while Add new evidence
    hashes, such as the newest entry removed, refuses the add before manifest.jsonl changes."""
    case = recorded_case
    evidence_file(case, "c.txt")
    before = case.manifest_path.read_bytes()
    real = intake_module.sha256_file

    def meanwhile(path):
        remove_the_newest_entry(case)
        return real(path)

    monkeypatch.setattr(intake_module, "sha256_file", meanwhile)
    assert main(["intake", str(case.folder), "--add"]) == 2
    assert case.manifest_path.read_bytes() == before and records(case) == []


def test_a_case_kept_at_format_3_adds_evidence_without_a_record(synthetic_case):
    """A format 3 case whose journal is read-only stays at format 3, and its journal takes nothing: Add new evidence
    still adds the files, from the page and the command line, with no record."""
    case = synthetic_case
    evidence_file(case, "a.txt")
    intake(case)
    case = format3_case(case)
    Journal(case).append("note", target="0" * 32, text="first look")
    Journal(case).append("note", target="0" * 32, text="second look")
    change_a_payload(case)
    journal = journal_path(case).read_bytes()
    evidence_file(case, "b.txt")
    app = App(case, for_work=True)
    try:
        assert app.journal.read_only and app.case.settings.case_format == 3
        assert api_evidence_add(app, {})["files"] == 1
    finally:
        app.con.close()
    evidence_file(case, "c.txt")
    assert main(["intake", str(case.folder), "--add"]) == 0
    assert b"DC01/c.txt" in case.manifest_path.read_bytes()
    assert journal_path(case).read_bytes() == journal and records(case) == []


def test_add_new_evidence_after_a_stop_records_the_grown_manifest_with_nothing_new(recorded_case, capsys):
    """A stop between Add new evidence's replace of manifest.jsonl and its record leaves the file grown past the record,
    which verify fails. Add new evidence with nothing new then records the file as it stands, and verify passes. Once
    the file matches its record, Add new evidence with nothing new records nothing."""
    case = recorded_case
    evidence_file(case, "c.txt")
    add_new(case)   # the replace, with the stop before the record
    assert len(records(case)) == 1
    capsys.readouterr()
    assert main(["verify", str(case.folder)]) == 1
    assert "manifest.jsonl grew past its record in the journal" in capsys.readouterr().out
    assert main(["intake", str(case.folder), "--add"]) == 0
    data = case.manifest_path.read_bytes()
    assert [(r["via"], r["sha256"], r["bytes"]) for r in records(case)[1:]] == [("add", sha(data), len(data))]
    capsys.readouterr()
    assert main(["verify", str(case.folder)]) == 0
    assert "manifest.jsonl matches its record in the journal" in capsys.readouterr().out
    assert main(["intake", str(case.folder), "--add"]) == 0
    assert len(records(case)) == 2


@pytest.mark.parametrize("route", ["add", "page"])
def test_add_new_evidence_refuses_a_manifest_that_differs_from_its_record_before_any_file_is_hashed(
        recorded_case, monkeypatch, capsys, route):
    """Add new evidence adds nothing to a manifest.jsonl that differs from its record, since no record would
    vouch for the lines before the new ones. From the command line and the page it refuses before any evidence file is
    hashed, says to restore manifest.jsonl from a copy of the case, and records nothing."""
    case = recorded_case
    (record,) = records(case)
    differing(case)
    before = case.manifest_path.read_bytes()
    evidence_file(case, "c.txt")
    hashed = counted_hashing(monkeypatch)
    says = (f"manifest.jsonl differs from its record in the journal, entry #{record['seq']}, so Add new evidence adds "
            "nothing to it. Restore manifest.jsonl from a copy of the case")
    if route == "page":
        app = App(case)
        try:
            with pytest.raises(CaseError, match=re.escape(says)):
                api_evidence_add(app, {})
        finally:
            app.con.close()
    else:
        assert main(["intake", str(case.folder), "--add"]) == 2
        assert says in capsys.readouterr().err
    assert hashed == []
    assert case.manifest_path.read_bytes() == before and len(records(case)) == 1


def differing(case) -> None:
    """manifest.jsonl changed after its record, with every entry still read alike: a space added in each line."""
    path = case.manifest_path
    path.write_bytes(path.read_bytes().replace(b'"method": ', b'"method":  '))


def taken_in(case) -> None:
    assert main(["intake", str(case.folder)]) == 0


def grown(case) -> None:
    taken_in(case)
    evidence_file(case, "c.txt")
    add_new(case)


def changed(case) -> None:
    taken_in(case)
    differing(case)


# How a case comes to each answer, and the exit verify and close give it
STATES = {"matches": (taken_in, 0), "grew": (grown, 1), "differs": (changed, 1), "none": (intake, 0)}
SAYS = {"matches": "manifest.jsonl matches its record in the journal, entry #",
        "grew": "manifest.jsonl grew past its record in the journal, entry #",
        "differs": "manifest.jsonl differs from its record in the journal, entry #",
        "none": "No journal entry records manifest.jsonl's hash"}


@pytest.mark.parametrize("state", list(STATES))
def test_verify_close_and_the_report_give_each_answer(synthetic_case, capsys, state):
    """verify and close fail on a manifest that grew past or differs from its record, and say so; one that matches, or
    has no record, fails nothing. Each full check's line in verification.jsonl records the state and the record it
    compared, and a mismatch makes its result one with no problem file. The report says the same in Evidence and
    integrity, and the close's entry records it."""
    case = synthetic_case
    evidence_file(case, "a.txt", "first")
    evidence_file(case, "b.txt", "second")
    make, code = STATES[state]
    make(case)
    found = records(case)
    key = {"state": state, "seq": found[0]["seq"] if found else None}
    result = "mismatch" if code else "ok"
    capsys.readouterr()
    assert main(["verify", str(case.folder)]) == code
    assert SAYS[state] in capsys.readouterr().out
    assert (last_check(case)["manifest"], last_check(case)["result"], last_check(case)["problems"]) == (key, result, [])
    assert SAYS[state] in report_section(case)
    assert (last_check(case)["manifest"], last_check(case)["result"]) == (key, result)
    capsys.readouterr()
    assert main(["close", str(case.folder)]) == code
    assert SAYS[state] in capsys.readouterr().out
    close = read_entries(journal_path(case))[-1]
    assert close["value"]["manifest"] == key and close["value"]["hash_check"] == "ok"
    assert (last_check(case)["manifest"], last_check(case)["result"]) == (key, result)


def test_a_record_after_the_head_vouches_for_nothing(recorded_case, capsys):
    """A record appended after the head kept outside the case, as anyone who can write the case folder can append one,
    vouches for nothing: verify compares the newest record at or before that head, with --expect-head and without it,
    and names the later one."""
    case = recorded_case
    head = heads.read(case.folder)["head"]
    evidence_file(case, "c.txt")
    add_new(case)   # manifest.jsonl grows past its record
    data = case.manifest_path.read_bytes()
    path = journal_path(case)
    path.write_bytes(add(path.read_bytes(), "manifest_recorded", sha256=sha(data), bytes=len(data), lines=3, via="add"))
    later = entries_of(case)[-1]["seq"]
    capsys.readouterr()
    for expect, named in (([], "the head this computer recorded"), (["--expect-head", head], "the expected head")):
        assert main(["verify", str(case.folder), *expect]) == 1
        out = capsys.readouterr().out
        assert "manifest.jsonl grew past its record in the journal, entry #" in out, out
        assert f"Entry #{later} records manifest.jsonl after {named}, so it vouches for nothing." in out, out


def test_add_new_evidence_from_the_command_line_beside_the_server_reads_as_a_match_in_the_report(recorded_case):
    """The report reads the record after catching up with the journal, so a record the command line appended beside the
    server counts."""
    case = recorded_case
    app = App(case)
    try:
        evidence_file(case, "c.txt")
        assert main(["intake", str(case.folder), "--add"]) == 0
        report = (case.folder / api_report(app, {})["path"]).read_text(encoding="utf-8")
    finally:
        app.con.close()
    assert f"manifest.jsonl matches its record in the journal, entry #{records(case)[-1]['seq']}." in report
    assert last_check(case)["manifest"]["state"] == "matches"


def test_the_report_counts_no_record_appended_after_the_head_this_app_recorded(recorded_case):
    """A record appended by hand while the server has the case open follows the head the app recorded, so the report
    compares manifest.jsonl with the record before it and names the later one, which vouches for nothing."""
    case = recorded_case
    (first,) = records(case)
    app = App(case)
    try:
        evidence_file(case, "c.txt")
        add_new(case)   # manifest.jsonl grows past its record
        data = case.manifest_path.read_bytes()
        path = journal_path(case)
        path.write_bytes(add(path.read_bytes(), "manifest_recorded", sha256=sha(data), bytes=len(data), lines=3, via="add"))
        later = entries_of(case)[-1]["seq"]
        report = (case.folder / api_report(app, {})["path"]).read_text(encoding="utf-8")
    finally:
        app.con.close()
    assert f"manifest.jsonl grew past its record in the journal, entry #{first['seq']}" in report
    assert f"Entry #{later} records manifest.jsonl after the head this app recorded, so it vouches for nothing." in report
    assert last_check(case)["manifest"] == {"state": "grew", "seq": first["seq"]}


def test_verify_says_so_when_a_record_is_written_during_its_re_hash(recorded_case, monkeypatch, capsys):
    """verify reads the journal again after the evidence re-hash: a record written meanwhile, as Add new evidence writes
    one, means the manifest it compared may not be the one it re-hashed, so it fails and says to run it again."""
    import glessner.cli as cli

    case = recorded_case
    evidence_file(case, "c.txt")
    real = cli.check_files

    def meanwhile(*args, **kwargs):
        assert main(["intake", str(case.folder), "--add"]) == 0
        return real(*args, **kwargs)

    monkeypatch.setattr(cli, "check_files", meanwhile)
    capsys.readouterr()
    assert main(["verify", str(case.folder)]) == 1
    out = capsys.readouterr().out
    assert f"Entry #{records(case)[-1]['seq']} recorded manifest.jsonl while this check ran" in out, out


def test_the_header_and_integrity_say_a_full_check_found_only_the_manifest_changed(recorded_case):
    """A full check whose only problem is the manifest has the result mismatch and no problems: the case state carries
    the manifest's state, and Integrity's line warns of it."""
    case = recorded_case
    seq = records(case)[0]["seq"]
    differing(case)
    assert main(["verify", str(case.folder)]) == 1
    app = App(case)
    try:
        last = api_case_state(app, {})["checks"]["last_full"]
        line = api_overview(app, {})["integrity"]["manifest"]
    finally:
        app.con.close()
    assert (last["result"], last["problems"], last["manifest"]) == ("mismatch", 0, {"state": "differs", "seq": seq})
    assert (line["state"], line["warn"], line["text"]) == (
        "differs", True, f"differed from its record, entry #{seq}, at the last full re-hash")


def test_integrity_names_a_record_no_full_check_compared_yet(recorded_case):
    case = recorded_case
    app = App(case)
    try:
        line = api_overview(app, {})["integrity"]["manifest"]
    finally:
        app.con.close()
    seq = records(case)[0]["seq"]
    assert (line["state"], line["warn"], line["text"]) == (
        "unchecked", False, f"recorded in the journal, entry #{seq}; no full re-hash has compared it yet")


SOURCES = {"matches": (taken_in, 0), "differs": (changed, 1), "none": (intake, 0)}


@pytest.mark.parametrize("state", list(SOURCES))
def test_a_copy_gives_its_source_s_answer(synthetic_case, tmp_path, capsys, state):
    """A copy holds its source's manifest.jsonl byte for byte, and its journal a record carrying the values of the
    source's record that counts, written after case_created by the app, so verify gives the copy its source's answer. A
    source with no record gives its copy none."""
    source = synthetic_case
    evidence_file(source, "a.txt")
    make, code = SOURCES[state]
    make(source)
    assert main(["copy-case", str(source.folder), str(tmp_path / "copy"), "--name", "Copy"]) == 0
    copy = open_case(tmp_path / "copy")
    if state == "none":
        assert records(copy) == []
    else:
        (original,) = records(source)
        assert [e["action"] for e in entries_of(copy)] == ["case_created", "manifest_recorded"]
        assert [{k: r[k] for k in ("sha256", "bytes", "lines", "via", "who")} for r in records(copy)] == [
            {**{k: original[k] for k in ("sha256", "bytes", "lines")}, "via": "copy", "who": "glessner"}]
    for case in (source, copy):
        capsys.readouterr()
        assert main(["verify", str(case.folder)]) == code
        assert SAYS[state] in capsys.readouterr().out
        assert last_check(case)["manifest"]["state"] == state


def test_a_first_record_from_add_new_evidence_says_the_earlier_lines_were_not_recorded(synthetic_case):
    """An upgraded case has no record until Add new evidence adds a file. That first record covers lines no entry
    recorded, so the trail and Integrity say nothing shows those lines are as intake wrote them."""
    case = synthetic_case
    evidence_file(case, "a.txt")
    intake(case)
    case = format3_case(case)
    opened(case)   # the upgrade to format 4, which records no manifest
    case = open_case(case.folder)
    assert case.settings.case_format == 4 and records(case) == []
    assert main(["intake", str(case.folder), "--add"]) == 0   # nothing new, so still no record
    assert records(case) == []
    evidence_file(case, "b.txt")
    assert main(["intake", str(case.folder), "--add"]) == 0
    (first,) = records(case)
    assert described(case, first).endswith(
        ". No earlier entry records manifest.jsonl, so nothing shows that its lines from before this Add new evidence "
        "are as intake wrote them")
    assert main(["verify", str(case.folder)]) == 0
    app = App(case)
    try:
        text = api_overview(app, {})["integrity"]["manifest"]["text"]
    finally:
        app.con.close()
    assert text.endswith(". The first record came with Add new evidence, so nothing shows that the lines before it are "
                         "as intake wrote them")


def test_the_trail_words_each_record_and_integrity_warns_of_one_after_the_head(recorded_case):
    """The trail words a record by what wrote it, with its lines, bytes, and short SHA-256. Integrity names a record
    appended after the head recorded outside the case, which can vouch for a changed manifest."""
    case = recorded_case
    (first,) = records(case)
    data = case.manifest_path.read_bytes()
    words = f"2 lines, {len(data):,} bytes, SHA-256 {sha(data)[:8]}...{sha(data)[-4:]}"
    assert described(case, first) == f"Recorded manifest.jsonl at intake: {words}"
    path = journal_path(case)
    path.write_bytes(add(path.read_bytes(), "manifest_recorded", sha256=sha(data), bytes=len(data), lines=2, via="copy"))
    assert described(case, records(case)[-1]) == (
        f"Recorded manifest.jsonl with the source case's record, since the copy holds its bytes: {words}")
    evidence_file(case, "c.txt")
    assert main(["intake", str(case.folder), "--add"]) == 0
    assert described(case, records(case)[-1]).startswith("Recorded manifest.jsonl after Add new evidence: 3 lines, ")
    path.write_bytes(add(path.read_bytes(), "manifest_recorded", sha256=sha(data), bytes=len(data), lines=2, via="add"))
    app = App(case)
    try:
        text = " ".join(api_overview(app, {})["integrity"]["journal"]["text"])
    finally:
        app.con.close()
    assert "written without updating that record: 1 manifest record." in text
    assert "A manifest record among them can vouch for a changed manifest.jsonl." in text
    assert check(path).consistent


def entry_line(path: str, data: bytes, **changes) -> bytes:
    """A manifest line for `path` holding `data`, in the form Add new evidence writes, with the time it was added."""
    entry = ManifestEntry(path=path, size=len(data), sha256=sha(data), artifact=None, method="extension",
                          added_utc="2026-10-23T00:00:00Z")
    return (json.dumps({**asdict(entry), **changes}) + "\n").encode("utf-8")


def appended(case, *lines: bytes) -> None:
    path = case.manifest_path
    path.write_bytes(path.read_bytes() + b"".join(lines))


def relisted(case) -> None:
    """b.txt changed, and a line for it with its new hash appended in Add new evidence's form, as though it were new."""
    evidence_file(case, "b.txt", "changed")
    appended(case, entry_line("DC01/b.txt", b"changed"))


def new_file_twice(case) -> None:
    evidence_file(case, "c.txt")
    appended(case, entry_line("DC01/c.txt", b"evidence"), entry_line("DC01/c.txt", b"evidence"))


def no_time_added(case) -> None:
    evidence_file(case, "c.txt")
    appended(case, entry_line("DC01/c.txt", b"evidence", added_utc=""))


def a_blank_line(case) -> None:
    appended(case, b"\n")


def another_form(case) -> None:
    evidence_file(case, "c.txt")
    appended(case, entry_line("DC01/c.txt", b"evidence").replace(b'", "', b'","'))


def no_line_end(case) -> None:
    evidence_file(case, "c.txt")
    appended(case, entry_line("DC01/c.txt", b"evidence")[:-1])


# Lines after the recorded bytes that no stop between Add new evidence's replace and its record leaves
NOT_A_STOP = {"an evidence file listed again": relisted, "a new file listed twice": new_file_twice,
              "a line without the time it was added": no_time_added, "a blank line": a_blank_line,
              "an entry in another form": another_form, "a last line without its line end": no_line_end}


@pytest.mark.parametrize("name", list(NOT_A_STOP))
def test_lines_no_stop_leaves_after_the_record_make_the_manifest_differ(recorded_case, monkeypatch, capsys, name):
    """Only whole lines in Add new evidence's form, each with the time it was added and for a path no other line lists,
    read as grown past the record, which a stop leaves and the next Add new evidence records. Other lines after the
    recorded bytes make the manifest differ: verify and close fail, and Add new evidence refuses before hashing and
    records nothing, so a changed evidence file's new hash can't be recorded over its intake hash."""
    case = recorded_case
    (record,) = records(case)
    NOT_A_STOP[name](case)
    before = case.manifest_path.read_bytes()
    differs = f"manifest.jsonl differs from its record in the journal, entry #{record['seq']}"
    capsys.readouterr()
    assert main(["verify", str(case.folder)]) == 1
    assert differs in capsys.readouterr().out
    assert last_check(case)["manifest"] == {"state": "differs", "seq": record["seq"]}
    hashed = counted_hashing(monkeypatch)
    assert main(["intake", str(case.folder), "--add"]) == 2
    assert f"{differs}, so Add new evidence adds nothing to it." in capsys.readouterr().err
    assert hashed == [] and case.manifest_path.read_bytes() == before and len(records(case)) == 1
    assert main(["close", str(case.folder)]) == 1
    assert differs in capsys.readouterr().out


def test_an_evidence_file_listed_twice_is_a_problem_of_that_file(recorded_case, capsys):
    """A path the manifest lists more than once has no one intake hash, whichever line a reader takes, so a full check
    names it as a problem of that file rather than comparing it with either line."""
    case = recorded_case
    relisted(case)
    capsys.readouterr()
    assert main(["verify", str(case.folder)]) == 1
    assert "  DC01/b.txt: listed more than once in the manifest" in capsys.readouterr().out
    assert last_check(case)["problems"] == ["DC01/b.txt: listed more than once in the manifest"]


def test_a_deleted_manifest_the_journal_records_is_named_as_missing_and_intake_refuses_it(recorded_case, monkeypatch,
                                                                                        capsys):
    """Once the journal records manifest.jsonl, a missing one is a change, not a case still waiting for intake: intake
    refuses before hashing, from the command line and the start page's call, so it can't write a new baseline over
    changed evidence; Add new evidence and close refuse; verify fails and says to restore the file. Nothing is written,
    and the journal records no second intake."""
    case = recorded_case
    (record,) = records(case)
    case.manifest_path.unlink()
    evidence_file(case, "a.txt", "changed")
    says = (f"manifest.jsonl is missing, but the journal records it, entry #{record['seq']}. Restore it from a copy of the "
            "case.")
    hashed = counted_hashing(monkeypatch)
    capsys.readouterr()
    assert main(["intake", str(case.folder)]) == 2
    assert says in capsys.readouterr().err
    with pytest.raises(CaseError, match=re.escape(says)):
        intake(case, journal=Journal(case, "server"))
    assert main(["intake", str(case.folder), "--add"]) == 2
    assert says in capsys.readouterr().err
    app = App(case)
    try:
        with pytest.raises(CaseError, match=re.escape(says)):
            api_evidence_add(app, {})
    finally:
        app.con.close()
    assert main(["close", str(case.folder)]) == 2
    assert says in capsys.readouterr().err
    assert main(["verify", str(case.folder)]) == 1
    assert says in capsys.readouterr().out
    assert hashed == [] and not case.manifest_path.exists() and [r["seq"] for r in records(case)] == [record["seq"]]


def write_the_manifest(case) -> None:
    case.manifest_path.write_bytes(b"")


def record_a_manifest(case) -> None:
    Journal(case).append("manifest_recorded", sha256=sha(b""), bytes=0, lines=0, via="intake")


@pytest.mark.parametrize("meanwhile", [write_the_manifest, record_a_manifest])
def test_intake_refuses_under_the_lock_when_another_writes_the_manifest_or_its_record_while_it_hashes(
        synthetic_case, monkeypatch, capsys, meanwhile):
    """intake checks again under the journal's lock, before it writes, that manifest.jsonl is still absent and that the
    journal still records none: another intake that finished while this one hashed is not overwritten, and nothing is
    recorded for this one."""
    case = synthetic_case
    evidence_file(case, "a.txt")
    real, done = intake_module.sha256_file, []

    def hashing(path):
        if not done:
            meanwhile(case)
            done.append(path)
        return real(path)

    monkeypatch.setattr(intake_module, "sha256_file", hashing)
    capsys.readouterr()
    assert main(["intake", str(case.folder)]) == 2
    err = capsys.readouterr().err
    if meanwhile is write_the_manifest:
        assert "Intake already done for this case" in err and case.manifest_path.read_bytes() == b""
        assert records(case) == []
    else:
        assert "manifest.jsonl is missing, but the journal records it, entry #" in err
        assert not case.manifest_path.exists() and len(records(case)) == 1


def forged(case) -> dict:
    """manifest.jsonl changed, and a record of the changed file appended after the head kept outside the case, chained
    as the app writes one, as anyone who can write the case folder can append it. The record."""
    differing(case)
    data = case.manifest_path.read_bytes()
    path = journal_path(case)
    path.write_bytes(add(path.read_bytes(), "manifest_recorded", sha256=sha(data), bytes=len(data), lines=2, via="add"))
    return entries_of(case)[-1]


MOVED = ("This command moved that head to the newest entry, so later commands count that record; verify --expect-head "
         "with a head recorded before it, such as one a close printed, still names it.")


@pytest.mark.parametrize("route", ["close", "add", "page"])
def test_close_and_add_new_evidence_count_no_record_appended_after_the_head(recorded_case, monkeypatch, capsys, route):
    """close and Add new evidence compare manifest.jsonl with the record at or before the head recorded outside the case
    as their open found it, before the open moves it to the newest line, and the page with the record at or before the
    head the app recorded: a record appended after that head vouches for nothing, so a changed manifest that matches it
    fails the close, and Add new evidence refuses it. Each names the later record, and the command line's close and Add
    new evidence say that their open moved the head past it, so only verify --expect-head names it from then on."""
    case = recorded_case
    (first,) = records(case)
    app = App(case) if route == "page" else None
    try:
        later = forged(case)
        before = case.manifest_path.read_bytes()
        differs = f"manifest.jsonl differs from its record in the journal, entry #{first['seq']}"
        vouches = (f"Entry #{later['seq']} records manifest.jsonl after the head this app recorded, so it vouches for "
                   "nothing.")
        evidence_file(case, "c.txt")
        hashed = counted_hashing(monkeypatch)
        capsys.readouterr()
        if route == "close":
            assert main(["close", str(case.folder)]) == 1
            out = capsys.readouterr().out
            assert differs in out
            assert f"{vouches} {MOVED}" in out
            assert read_entries(journal_path(case))[-1]["value"]["manifest"] == {"state": "differs", "seq": first["seq"]}
            return
        if route == "page":
            with pytest.raises(CaseError, match=re.escape(differs)) as refused:
                api_evidence_add(app, {})
            assert str(refused.value).endswith(f"then add the evidence again. {vouches}")
        else:
            assert main(["intake", str(case.folder), "--add"]) == 2
            err = capsys.readouterr().err
            assert differs in err and f"then add the evidence again. {vouches} {MOVED}" in err
    finally:
        if app is not None:
            app.con.close()
    assert hashed == [] and case.manifest_path.read_bytes() == before
    assert [r["seq"] for r in records(case)] == [first["seq"], later["seq"]]


def test_the_page_refuses_a_break_made_while_the_case_is_open_before_any_file_is_hashed(recorded_case, monkeypatch):
    """Add new evidence from the page runs the append's checks, which catch up with the journal, before it hashes: a
    break made after the app opened the case, such as its newest entry removed, refuses the add with nothing hashed."""
    case = recorded_case
    Journal(case).append("note", target="0" * 32, text="first look")
    app = App(case)
    try:
        remove_the_newest_entry(case)
        evidence_file(case, "c.txt")
        hashed = counted_hashing(monkeypatch)
        before = case.manifest_path.read_bytes()
        with pytest.raises(JournalError, match="The journal was changed after it was written"):
            api_evidence_add(app, {})
    finally:
        app.con.close()
    assert hashed == [] and case.manifest_path.read_bytes() == before


def test_a_record_appended_while_the_page_hashes_is_compared_under_the_lock(recorded_case, monkeypatch):
    """Under the journal's lock, after its catch-up, the page's Add new evidence compares manifest.jsonl with the record
    that counts again: one another program appended while the files were hashed, which the file differs from, refuses
    the add, and manifest.jsonl stays as it was."""
    case = recorded_case
    evidence_file(case, "c.txt")
    before = case.manifest_path.read_bytes()
    real = intake_module.sha256_file

    def meanwhile(path):
        Journal(case).append("manifest_recorded", sha256=sha(b"other"), bytes=5, lines=1, via="add")
        return real(path)

    app = App(case)
    try:
        monkeypatch.setattr(intake_module, "sha256_file", meanwhile)
        with pytest.raises(CaseError, match=r"manifest\.jsonl differs from its record in the journal, entry #"):
            api_evidence_add(app, {})
    finally:
        app.con.close()
    assert case.manifest_path.read_bytes() == before and len(records(case)) == 2


def test_verify_with_no_head_recorded_counts_the_newest_record_and_says_nothing_shows_when_it_came(recorded_case,
                                                                                                    capsys):
    case = recorded_case
    (record,) = records(case)
    heads.forget(case.folder)
    capsys.readouterr()
    assert main(["verify", str(case.folder)]) == 0
    assert (f"manifest.jsonl matches its record in the journal, entry #{record['seq']}. No head recorded outside the case "
            "was given, so nothing shows the record wasn't added later.") in capsys.readouterr().out
    assert last_check(case)["manifest"] == {"state": "matches", "seq": record["seq"]}


def test_an_expected_head_that_is_no_line_counts_no_record(recorded_case, capsys):
    """With an expected head the journal doesn't hold, no record counts: verify says so and fails, its line in
    verification.jsonl records no record compared, and Integrity says no record counted rather than that none existed."""
    case = recorded_case
    (record,) = records(case)
    capsys.readouterr()
    assert main(["verify", str(case.folder), "--expect-head", "ab" * 32]) == 1
    assert ("No record of manifest.jsonl counts, since the expected head is no entry of the journal."
            in capsys.readouterr().out)
    assert last_check(case)["manifest"] == {"state": "none", "seq": None}
    app = App(case)
    try:
        line = api_overview(app, {})["integrity"]["manifest"]
    finally:
        app.con.close()
    assert (line["state"], line["warn"], line["text"]) == (
        "none", False, f"no record of its hash counted at the last full re-hash; entry #{record['seq']} records it")


def test_integrity_names_a_record_newer_than_the_one_the_last_full_re_hash_compared(recorded_case):
    """Integrity names the newest record when it is newer than the one the last full re-hash compared, and never names
    an older one as newer, as a state not yet caught up with the command line's Add new evidence would."""
    case = recorded_case
    (first,) = records(case)
    assert main(["verify", str(case.folder)]) == 0
    evidence_file(case, "c.txt")
    assert main(["intake", str(case.folder), "--add"]) == 0
    newer = records(case)[-1]["seq"]
    app = App(case)
    try:
        assert api_overview(app, {})["integrity"]["manifest"]["text"] == (
            f"matched its record, entry #{first['seq']}, at the last full re-hash; entry #{newer} is a newer record of it")
        evidence_file(case, "d.txt")
        assert main(["intake", str(case.folder), "--add"]) == 0
        assert main(["verify", str(case.folder)]) == 0
        newest = records(case)[-1]["seq"]
        assert api_overview(app, {})["integrity"]["manifest"]["text"] == (
            f"matched its record, entry #{newest}, at the last full re-hash")
    finally:
        app.con.close()


def broken_source(case) -> None:
    Journal(case).append("note", target="0" * 32, text="first look")
    Journal(case).append("note", target="0" * 32, text="second look")
    change_a_payload(case)


def break_on_record(case) -> None:
    broken_source(case)
    Journal(case).record_break("looked at the change")


def no_head_here(case) -> None:
    heads.forget(case.folder)


# Sources whose own check doesn't vouch for their record from the head kept outside them on this computer
UNVOUCHED = {"a break": broken_source, "a break on record": break_on_record, "no head recorded here": no_head_here}


BREAK_WORDS = "The source's journal had a break, so it could not vouch for this record"
NO_HEAD_WORDS = ("No head of the source's journal was recorded on this computer, so nothing showed that this record was "
                 "not added later")
ADD_WORDS = ("The source's first record came with Add new evidence, so nothing shows that the lines before it are as "
             "intake wrote them")
# Why each source's own check doesn't vouch for its record, as the copy's record names it
REASONS = {"a break": ["break"], "a break on record": ["break"], "no head recorded here": ["no_head"]}
WORDS = {"break": BREAK_WORDS, "no_head": NO_HEAD_WORDS, "add": ADD_WORDS}


def add_first_source(case):
    """A source whose journal's first record of manifest.jsonl came with Add new evidence, as every case upgraded from
    format 3 records: the case, reopened."""
    evidence_file(case, "a.txt")
    intake(case)
    case = format3_case(case)
    opened(case)
    case = open_case(case.folder)
    evidence_file(case, "b.txt")
    assert main(["intake", str(case.folder), "--add"]) == 0
    assert [r["via"] for r in records(case)] == ["add"]
    return case


def copied(source, tmp_path, name="copy"):
    assert main(["copy-case", str(source.folder), str(tmp_path / name), "--name", "Copy"]) == 0
    return open_case(tmp_path / name)


def integrity_line(case) -> dict:
    app = App(case)
    try:
        return api_overview(app, {})["integrity"]["manifest"]
    finally:
        app.con.close()


@pytest.mark.parametrize("name", list(UNVOUCHED))
def test_a_copy_of_a_source_that_cannot_vouch_for_its_record_carries_its_newest_record_and_says_why(
        synthetic_case, tmp_path, capsys, name):
    """A source whose chain is broken, whose break is on record, or whose head no record outside it names on this
    computer gives its copy the newest record of its journal, the only description of the manifest.jsonl the copy holds,
    with the reason its check couldn't vouch for it. The copy's verify gives the source's answer, and verify, the trail,
    and Integrity keep the warning."""
    source = synthetic_case
    evidence_file(source, "a.txt")
    assert main(["intake", str(source.folder)]) == 0
    UNVOUCHED[name](source)
    newest = records(source)[-1]
    copy = copied(source, tmp_path)
    [record] = records(copy)
    assert {k: record[k] for k in ("sha256", "bytes", "lines", "via", "who")} == {
        **{k: newest[k] for k in ("sha256", "bytes", "lines")}, "via": "copy", "who": "glessner"}
    assert record["unvouched"] == REASONS[name]
    words = WORDS[REASONS[name][0]]
    assert described(copy, record).endswith(f". {words}")
    line = integrity_line(copy)
    assert (line["state"], line["warn"]) == ("unchecked", True) and line["text"].endswith(f". {words}")
    capsys.readouterr()
    assert main(["verify", str(copy.folder)]) == 0
    out = capsys.readouterr().out
    assert f"manifest.jsonl matches its record in the journal, entry #{record['seq']}." in out and f"{words}." in out
    line = integrity_line(copy)
    assert (line["state"], line["warn"]) == ("matches", True) and line["text"].endswith(f". {words}")


def test_a_copy_of_a_source_whose_first_record_came_with_add_new_evidence_carries_the_record_and_says_so(
        synthetic_case, tmp_path, capsys):
    """The copy's record is the one at the source's head, and says the source's lines from before its first record were
    never recorded, as the source's own trail and Integrity say it. That is a note, not a warning: the copy matches."""
    source = add_first_source(synthetic_case)
    [original] = records(source)
    copy = copied(source, tmp_path)
    [record] = records(copy)
    assert {k: record[k] for k in ("sha256", "bytes", "lines", "via")} == {
        **{k: original[k] for k in ("sha256", "bytes", "lines")}, "via": "copy"}
    assert record["unvouched"] == ["add"]
    assert described(copy, record).endswith(f". {ADD_WORDS}")
    line = integrity_line(copy)
    assert (line["state"], line["warn"]) == ("unchecked", False) and line["text"].endswith(f". {ADD_WORDS}")
    capsys.readouterr()
    assert main(["verify", str(copy.folder)]) == 0
    out = capsys.readouterr().out
    assert f"manifest.jsonl matches its record in the journal, entry #{record['seq']}." in out and f"{ADD_WORDS}." in out
    assert integrity_line(copy)["state"] == "matches"


def test_a_copy_of_a_copy_keeps_the_reason_its_source_s_first_record_names(synthetic_case, tmp_path, capsys):
    """A copy's journal is chained and its head is recorded here, so it vouches for its record, and the copy of it
    carries the record with the reason the first copy's record names."""
    first = copied(add_first_source(synthetic_case), tmp_path, "first")
    second = copied(first, tmp_path, "second")
    [record] = records(second)
    assert (record["via"], record["unvouched"]) == ("copy", ["add"])
    capsys.readouterr()
    assert main(["verify", str(second.folder)]) == 0
    assert f"{ADD_WORDS}." in capsys.readouterr().out


def test_a_copy_of_a_broken_source_whose_first_record_came_with_add_names_both_reasons(synthetic_case, tmp_path):
    """The break first, then the source's Add new evidence, in the order the trail and Integrity word them."""
    source = add_first_source(synthetic_case)
    broken_source(source)
    copy = copied(source, tmp_path)
    [record] = records(copy)
    assert record["unvouched"] == ["break", "add"]
    assert described(copy, record).endswith(f". {BREAK_WORDS}. {ADD_WORDS}")
    assert integrity_line(copy)["text"].endswith(f". {BREAK_WORDS}. {ADD_WORDS}")


def test_a_copy_of_a_source_that_vouches_for_its_record_names_no_reason(recorded_case, tmp_path, capsys):
    """A source whose chain is whole, whose head is recorded here, and whose first record came from intake gives its copy
    the record at its head and no reason; verify and Integrity say nothing of the source."""
    copy = copied(recorded_case, tmp_path)
    [record] = records(copy)
    assert "unvouched" not in record
    capsys.readouterr()
    assert main(["verify", str(copy.folder)]) == 0
    assert "source's" not in capsys.readouterr().out
    assert "source's" not in integrity_line(copy)["text"] and "source's" not in described(copy, record)


def test_a_reason_a_record_names_is_a_list_of_known_reasons_on_a_copy_only(synthetic_case):
    journal = Journal(synthetic_case)
    good = {"sha256": sha(b"x"), "bytes": 1, "lines": 1, "via": "copy"}
    for bad in ({"via": "intake", "unvouched": ["break"]}, {"unvouched": []}, {"unvouched": "break"},
                {"unvouched": ["somewhere"]}, {"unvouched": ["break", "break"]}, {"unvouched": [1]}):
        with pytest.raises(JournalError, match="manifest_recorded needs"):
            journal.append("manifest_recorded", **{**good, **bad})
    entry = journal.append("manifest_recorded", **good, unvouched=["no_head", "add"])
    assert journal.state.manifests[-1]["unvouched"] == ["no_head", "add"] and entry["unvouched"] == ["no_head", "add"]
    assert "unvouched" not in journal.append("manifest_recorded", **good)


def test_a_copy_carries_the_record_at_its_source_s_head_not_one_appended_after_it(recorded_case, tmp_path, capsys):
    """The copy's record carries the values of the source's record at or before the head kept outside it, not those of
    a newer one appended after that head, so the copy's verify gives the source's answer."""
    source = recorded_case
    (first,) = records(source)
    evidence_file(source, "c.txt")
    add_new(source)   # manifest.jsonl grows past its record
    data = source.manifest_path.read_bytes()
    path = journal_path(source)
    path.write_bytes(add(path.read_bytes(), "manifest_recorded", sha256=sha(data), bytes=len(data), lines=3, via="add"))
    assert main(["copy-case", str(source.folder), str(tmp_path / "copy"), "--name", "Copy"]) == 0
    copy = open_case(tmp_path / "copy")
    assert [(r["sha256"], r["bytes"]) for r in records(copy)] == [(first["sha256"], first["bytes"])]
    for case in (source, copy):
        capsys.readouterr()
        assert main(["verify", str(case.folder)]) == 1
        assert "manifest.jsonl grew past its record in the journal, entry #" in capsys.readouterr().out


def verified_copy_and_source(source, tmp_path, capsys):
    """The copy of `source`, and the exit and output of verify on the source and then on the copy."""
    copy = copied(source, tmp_path)
    answers = []
    for case in (source, copy):
        capsys.readouterr()
        answers.append((main(["verify", str(case.folder)]), capsys.readouterr().out))
    return copy, answers


def test_a_copy_of_a_broken_source_carries_the_record_at_the_head_the_source_s_verify_counts(recorded_case, tmp_path,
                                                                                            capsys):
    """A break doesn't move the head recorded here: the source's verify counts the record at or before it, so the copy
    carries that one and not a newer record appended after the head, which vouches for nothing. Both then say the
    manifest grew past its record, and the copy says the source's journal had a break."""
    source = recorded_case
    (first,) = records(source)
    Journal(source).append("note", target="0" * 32, text="first look")
    Journal(source).append("note", target="0" * 32, text="second look")
    evidence_file(source, "c.txt")
    add_new(source)   # manifest.jsonl grows past its record
    data = source.manifest_path.read_bytes()
    path = journal_path(source)
    path.write_bytes(add(path.read_bytes(), "manifest_recorded", sha256=sha(data), bytes=len(data), lines=3, via="add"))
    change_a_payload(source)   # the break, with the head recorded here still a line of the journal
    copy, [(source_code, source_out), (copy_code, copy_out)] = verified_copy_and_source(source, tmp_path, capsys)
    [record] = records(copy)
    assert (record["sha256"], record["bytes"], record["unvouched"]) == (first["sha256"], first["bytes"], ["break"])
    assert source_code == copy_code == 1
    for out in (source_out, copy_out):
        assert f"manifest.jsonl grew past its record in the journal, entry #{first['seq']}" in out
    assert f"{BREAK_WORDS}." in copy_out and BREAK_WORDS not in source_out


def test_a_copy_of_a_source_with_no_head_here_carries_the_newest_record_the_source_s_verify_counts(recorded_case,
                                                                                                 tmp_path, capsys):
    """With no head recorded here the source's verify counts the newest record, so the copy carries the newest of
    several, not the first, and says no head was recorded."""
    source = recorded_case
    evidence_file(source, "c.txt")
    assert main(["intake", str(source.folder), "--add"]) == 0
    first, newest = records(source)
    heads.forget(source.folder)
    copy, [(source_code, source_out), (copy_code, copy_out)] = verified_copy_and_source(source, tmp_path, capsys)
    [record] = records(copy)
    assert (record["sha256"], record["bytes"], record["unvouched"]) == (newest["sha256"], newest["bytes"], ["no_head"])
    assert newest["sha256"] != first["sha256"]
    assert source_code == copy_code == 0
    assert f"manifest.jsonl matches its record in the journal, entry #{newest['seq']}." in source_out
    assert f"manifest.jsonl matches its record in the journal, entry #{record['seq']}." in copy_out
    assert f"{NO_HEAD_WORDS}." in copy_out


def test_a_copy_of_a_broken_source_with_no_head_here_names_both_reasons(recorded_case, tmp_path):
    source = recorded_case
    broken_source(source)
    heads.forget(source.folder)
    copy = copied(source, tmp_path)
    [record] = records(copy)
    assert record["unvouched"] == ["break", "no_head"]
    assert described(copy, record).endswith(f". {BREAK_WORDS}. {NO_HEAD_WORDS}")
    assert integrity_line(copy)["text"].endswith(f". {BREAK_WORDS}. {NO_HEAD_WORDS}")


def test_a_copy_of_a_source_whose_recorded_head_is_no_line_carries_the_newest_record_with_a_break(recorded_case,
                                                                                                 tmp_path):
    """The head recorded here names a line the journal no longer holds, so no record counts for the source. Its copy
    still carries the record, with the break, and not no record at all, which would leave the copy with no warning."""
    source = recorded_case
    (first,) = records(source)
    Journal(source).append("note", target="0" * 32, text="first look")
    remove_the_newest_entry(source)
    copy = copied(source, tmp_path)
    [record] = records(copy)
    assert (record["sha256"], record["unvouched"]) == (first["sha256"], ["break"])


# Each source whose copy's first record names reasons: how the source is made, and the reasons the copy's record names
SOURCES_WITH_REASONS = {**{name: (make, REASONS[name]) for name, make in UNVOUCHED.items()},
                        "a first record from Add new evidence": (None, ["add"])}


def copy_naming_reasons(synthetic_case, tmp_path, name, verified=False):
    """The copy of a source made as `name` says (SOURCES_WITH_REASONS), and its one record. With `verified`, the source
    was verified before its journal was changed, so the copy holds that full check."""
    make, reasons = SOURCES_WITH_REASONS[name]
    if make is None:
        source = add_first_source(synthetic_case)
        if verified:
            assert main(["verify", str(source.folder)]) == 0
    else:
        source = synthetic_case
        evidence_file(source, "a.txt")
        assert main(["intake", str(source.folder)]) == 0
        if verified:
            assert main(["verify", str(source.folder)]) == 0
        make(source)
    copy = copied(source, tmp_path)
    [record] = records(copy)
    assert record["unvouched"] == reasons
    return copy, record


@pytest.mark.parametrize("reasons", [("break",), ("no_head",), ("add",), ("break", "no_head", "add")])
@pytest.mark.parametrize("state", ["matches", "grew", "differs", "none"])
def test_manifest_text_adds_the_reasons_a_copy_s_record_names_after_what_it_says_of_the_file(state, reasons):
    """The sentence verify, close, and the report print for the file against its record is followed by the sentences of
    the reasons the copy's record names, in their order, and ManifestCheck keeps them in its key and warns of them when
    one is a break or a head not recorded here, never of Add new evidence's note. A check that names no reason says only
    what it says of the file."""
    seq = None if state == "none" else 5
    plain = ManifestCheck(state, seq, head="the head this app recorded")
    named = ManifestCheck(state, seq, head="the head this app recorded", unvouched=reasons)
    assert manifest_text(named) == f"{manifest_text(plain)} {unvouched_words({'unvouched': list(reasons)})}."
    assert plain.key == {"state": state, "seq": seq} and not plain.warns
    assert named.key == {"state": state, "seq": seq, "unvouched": list(reasons)}
    assert named.warns == bool({"break", "no_head"} & set(reasons))
    assert named.failed == plain.failed


@pytest.mark.parametrize("where", ["a missing manifest", "a head that is no line"])
def test_manifest_text_names_no_reason_where_no_record_is_in_question(where):
    """A manifest that is missing, or a head that is no line of the journal so that no record counts, is not a record
    the source couldn't vouch for: the sentence stands alone."""
    if where == "a missing manifest":
        alone = ManifestCheck("differs", 5, missing=True)
    else:
        alone = ManifestCheck("none", None, head="an unknown head", head_found=False)
    assert manifest_text(replace(alone, unvouched=("break",))) == manifest_text(alone)


@pytest.mark.parametrize("name", list(SOURCES_WITH_REASONS))
def test_verify_prints_a_copy_s_reasons_once_after_the_manifest_sentence(synthetic_case, tmp_path, capsys, name):
    """The reasons are part of the manifest sentence, so verify prints them once, in the sentence's paragraph, and its
    exit stays the evidence's: a copy that matches exits 0."""
    copy, record = copy_naming_reasons(synthetic_case, tmp_path, name)
    words = unvouched_words(record)
    capsys.readouterr()
    assert main(["verify", str(copy.folder)]) == 0
    out = capsys.readouterr().out
    assert f"manifest.jsonl matches its record in the journal, entry #{record['seq']}. {words}.\n" in out
    assert out.count(words) == 1
    assert last_check(copy)["manifest"] == {"state": "matches", "seq": record["seq"], "unvouched": record["unvouched"]}


@pytest.mark.parametrize("name", list(SOURCES_WITH_REASONS))
def test_close_prints_and_journals_a_copy_s_reasons(synthetic_case, tmp_path, capsys, name):
    """close prints the reasons after its manifest sentence, as verify does, and its entry records them beside the state
    and the record, so the trail's row for the close repeats them and the check's line in verification.jsonl holds them.
    The close's exit stays the evidence's: a copy that matches exits 0."""
    copy, record = copy_naming_reasons(synthetic_case, tmp_path, name)
    words = unvouched_words(record)
    capsys.readouterr()
    assert main(["close", str(copy.folder)]) == 0
    out = capsys.readouterr().out
    assert f"manifest.jsonl matches its record in the journal, entry #{record['seq']}. {words}.\n" in out
    assert out.count(words) == 1
    key = {"state": "matches", "seq": record["seq"], "unvouched": record["unvouched"]}
    close = read_entries(journal_path(copy))[-1]
    assert close["value"]["manifest"] == key and last_check(copy)["manifest"] == key
    assert described(copy, close).endswith(f" manifest.jsonl matched its record in the journal, entry #{record['seq']}. {words}.")


def test_close_on_a_copy_that_names_no_reason_records_the_state_and_the_record_alone(recorded_case, tmp_path, capsys):
    copy = copied(recorded_case, tmp_path)
    [record] = records(copy)
    capsys.readouterr()
    assert main(["close", str(copy.folder)]) == 0
    assert "source's" not in capsys.readouterr().out
    close = read_entries(journal_path(copy))[-1]
    assert close["value"]["manifest"] == {"state": "matches", "seq": record["seq"]}
    assert described(copy, close).endswith(f" manifest.jsonl matched its record in the journal, entry #{record['seq']}.")


@pytest.mark.parametrize("name", list(SOURCES_WITH_REASONS))
def test_the_report_names_a_copy_s_reasons_in_its_manifest_sentence(synthetic_case, tmp_path, name):
    """The report's evidence check, which the page writes and the findings command writes, says what verify says: the
    manifest sentence, then the reasons the copy's record names."""
    copy, record = copy_naming_reasons(synthetic_case, tmp_path, name)
    says = f"manifest.jsonl matches its record in the journal, entry #{record['seq']}. {unvouched_words(record)}."
    app = App(copy)
    try:
        report = (copy.folder / api_report(app, {})["path"]).read_text(encoding="utf-8")
    finally:
        app.con.close()
    assert says in report and says in report_section(copy)
    assert last_check(copy)["manifest"]["unvouched"] == record["unvouched"]


@pytest.mark.parametrize(("name", "warn"), [("a break", True), ("no head recorded here", True),
                                            ("a first record from Add new evidence", False)])
def test_the_case_state_carries_a_copy_s_reasons_from_the_journal_for_the_header(synthetic_case, tmp_path, name, warn):
    """The header reads the journal's first manifest record, as Integrity does, so a new copy's state names the reasons,
    whether one warns (a break or a head not recorded here, not Add new evidence's note), and their words before the
    copy's own first full re-hash, although the verification history it holds from its source names no reason. The
    copy's own re-hash changes none of it."""
    copy, record = copy_naming_reasons(synthetic_case, tmp_path, name, verified=True)
    expected = {"unvouched": record["unvouched"], "warn": warn, "text": unvouched_words(record)}
    inherited = {"state": "matches", "seq": last_check(copy)["manifest"]["seq"]}
    app = App(copy)
    try:
        state = api_case_state(app, {})
        assert (state["manifest_record"], state["checks"]["last_full"]["manifest"]) == (expected, inherited)
        assert main(["verify", str(copy.folder)]) == 0
        assert api_case_state(app, {})["manifest_record"] == expected
    finally:
        app.con.close()


def test_the_case_state_keeps_naming_a_copy_s_reasons_once_the_copy_records_more(synthetic_case, tmp_path):
    """The reasons are the journal's first manifest record's. Add new evidence in the copy writes a later record that
    names none, and the state still carries the first one's."""
    copy, record = copy_naming_reasons(synthetic_case, tmp_path, "a break")
    evidence_file(copy, "extra.txt")
    assert main(["intake", str(copy.folder), "--add"]) == 0
    assert len(records(copy)) == 2
    app = App(copy)
    try:
        assert api_case_state(app, {})["manifest_record"] == {
            "unvouched": record["unvouched"], "warn": True, "text": unvouched_words(record)}
    finally:
        app.con.close()


def test_the_case_state_names_no_reason_for_a_record_nothing_was_unvouched_about(recorded_case, tmp_path):
    """A source's own record and a copy of a source that vouches for its record name no reason."""
    none = {"unvouched": [], "warn": False, "text": ""}
    for case in (recorded_case, copied(recorded_case, tmp_path)):
        app = App(case)
        try:
            assert api_case_state(app, {})["manifest_record"] == none
        finally:
            app.con.close()


def dated(monkeypatch, days: int) -> None:
    """The checks this process writes from now on are dated `days` from the clock's day, so that the source's re-hash is
    dated before a copy's first record, which a clock that ticks in whole seconds can't promise."""
    class Shifted(datetime):
        @classmethod
        def now(cls, tz=None):
            return super().now(tz) + timedelta(days=days)

    monkeypatch.setattr(intake_module, "datetime", Shifted)


@pytest.mark.parametrize("layout", ["numbers that differ", "numbers that collide"])
def test_integrity_names_no_entry_of_the_source_s_journal_for_a_copy_s_inherited_re_hash(
        recorded_case, tmp_path, monkeypatch, layout):
    """A copy holds its source's verification history, whose full checks cite entries of the source's journal, and a
    check dated before the copy's first record is the source's. Integrity says the file matched its record at its
    source's re-hash without a number, also when the number is one of the copy's own entries: a copy's first record is
    entry 2, as is a source's first record. After the copy's own re-hash it names the copy's record."""
    source = recorded_case
    with monkeypatch.context() as patched:
        dated(patched, -1)
        if layout == "numbers that differ":
            Journal(source).append("note", target="0" * 32, text="first look")
            evidence_file(source, "c.txt")
            assert main(["intake", str(source.folder), "--add"]) == 0
            assert main(["verify", str(source.folder)]) == 0
            heads.forget(source.folder)
        else:
            assert main(["verify", str(source.folder)]) == 0
            evidence_file(source, "c.txt")
            assert main(["intake", str(source.folder), "--add"]) == 0
    copy = copied(source, tmp_path)
    [record] = records(copy)
    cited = last_check(copy)["manifest"]["seq"]
    assert (cited == record["seq"]) is (layout == "numbers that collide")
    line = integrity_line(copy)
    assert (line["state"], f"#{cited}" in line["text"]) == ("matches", False)
    assert line["text"].startswith("matched its record, at its source's last full re-hash")
    assert main(["verify", str(copy.folder)]) == 0
    line = integrity_line(copy)
    assert line["text"].startswith(f"matched its record, entry #{record['seq']}, at the last full re-hash")


@pytest.mark.parametrize(("via", "at", "seq", "says"), [
    ("copy", "2026-10-24T09:59:59Z", 2, "matched its record, at its source's last full re-hash"),
    ("copy", "2026-10-24T10:00:00Z", 2, "matched its record, entry #2, at the last full re-hash"),
    ("copy", "2026-10-24T10:00:00Z", 9, "matched its record, at the last full re-hash"),
    ("copy", "2026-10-25T10:00:00Z", 2, "matched its record, entry #2, at the last full re-hash"),
    ("intake", "2026-10-24T09:59:59Z", 2, "matched its record, entry #2, at the last full re-hash"),
    ("copy", "", 2, "matched its record, entry #2, at the last full re-hash"),
    ("copy", 20261024, 2, "matched its record, entry #2, at the last full re-hash"),
    ("copy", None, 9, "matched its record, at the last full re-hash"),
], ids=["a re-hash before the copy", "one in the copy's second", "one citing no record of the copy", "one after the copy",
        "a case that is no copy", "one with no time", "one with a time that is no string", "no time and no record of the copy"])
def test_integrity_tells_a_copy_s_own_re_hash_from_its_source_s_by_its_date_and_its_entry(via, at, seq, says):
    """A copy's first record is dated 10:00:00.5. A re-hash dated in an earlier second is its source's, whatever entry it
    cites. One in the same second or later is the copy's own, which names its entry only when that is one of the copy's
    records. A case that is not a copy cites the entry of any re-hash. A re-hash with no usable time, as a hand edit
    leaves, is not called the source's."""
    record = {"seq": 2, "via": via, "at": "2026-10-24T10:00:00.500000Z"}
    full = {"at": at, "reason": "manual full verification", "manifest": {"state": "matches", "seq": seq}}
    assert _manifest_row(full, [record], False)["text"] == says


@pytest.mark.parametrize("change", ["a rewritten line", "a deleted manifest"])
def test_a_case_yaml_set_back_below_format_4_still_compares_the_manifest_with_its_record(recorded_case, monkeypatch,
                                                                                         capsys, change):
    """case.yaml, which names the case format, sits outside the chain, so setting it back below format 4 doesn't turn the
    record off: once the journal holds a record of manifest.jsonl, every check compares the file with it. A changed
    evidence file whose manifest line was rewritten with its new hash fails verify and close, and Add new evidence
    refuses it; a deleted manifest is named as missing, and intake refuses to write a new baseline. Nothing is hashed for
    an add, and neither manifest.jsonl nor a record is written."""
    case = recorded_case
    (record,) = records(case)
    evidence_file(case, "b.txt", "SECOND")   # the same size as "second"
    if change == "a rewritten line":
        path = case.manifest_path
        path.write_bytes(path.read_bytes().replace(sha(b"second").encode(), sha(b"SECOND").encode()))
        says, closed = f"manifest.jsonl differs from its record in the journal, entry #{record['seq']}", 1
    else:
        case.manifest_path.unlink()
        says, closed = f"manifest.jsonl is missing, but the journal records it, entry #{record['seq']}.", 2
    set_format(case.folder, 3)
    before = case.manifest_path.read_bytes() if case.manifest_path.exists() else None
    capsys.readouterr()
    assert main(["verify", str(case.folder)]) == 1
    assert says in capsys.readouterr().out
    evidence_file(case, "c.txt")
    hashed = counted_hashing(monkeypatch)
    for command in ([["intake"]] if before is None else []) + [["intake", "--add"]]:
        assert main([command[0], str(case.folder), *command[1:]]) == 2
        assert says in capsys.readouterr().err
    app = App(open_case(case.folder))
    try:
        assert app.case.settings.case_format == 3
        with pytest.raises(CaseError, match=re.escape(says)):
            api_evidence_add(app, {})
    finally:
        app.con.close()
    assert hashed == []
    assert main(["close", str(case.folder)]) == closed
    assert says in (capsys.readouterr().out if closed == 1 else capsys.readouterr().err)
    assert (case.manifest_path.read_bytes() if case.manifest_path.exists() else None) == before
    assert [r["seq"] for r in records(case)] == [record["seq"]]


@pytest.mark.parametrize("writer", ["the server", "a hand edit"])
def test_close_counts_a_record_appended_after_its_open_only_with_the_head_moved_to_it(recorded_case, monkeypatch,
                                                                                    capsys, writer):
    """A record appended between close's open and its read of the records counts when the head this app records has
    moved to it, as a Glessner program on this computer moves it after its own record, such as the server's Add new
    evidence: the manifest matches it, and the close passes. One appended by hand leaves that head where the open put
    it, so it vouches for nothing, and the changed manifest it records fails the close."""
    case = recorded_case
    (first,) = records(case)
    evidence_file(case, "c.txt")
    real, done = Journal.full_check, []

    def full_check(self, *args, **kwargs):
        if not done:
            done.append(add_new(case, Journal(case, "server")) if writer == "the server" else forged(case))
        return real(self, *args, **kwargs)

    monkeypatch.setattr(Journal, "full_check", full_check)
    capsys.readouterr()
    code = main(["close", str(case.folder)])
    out = capsys.readouterr().out
    newest = records(case)[-1]
    if writer == "the server":
        assert code == 0 and done[0].files == 1 and (newest["via"], newest["client"]) == ("add", "server")
        assert f"manifest.jsonl matches its record in the journal, entry #{newest['seq']}." in out and "vouches" not in out
        key = {"state": "matches", "seq": newest["seq"]}
    else:
        assert code == 1
        assert f"manifest.jsonl differs from its record in the journal, entry #{first['seq']}" in out
        assert (f"Entry #{newest['seq']} records manifest.jsonl after the head this app recorded, so it vouches for "
                "nothing.") in out
        key = {"state": "differs", "seq": first["seq"]}
    assert read_entries(journal_path(case))[-1]["value"]["manifest"] == key


def test_a_deleted_manifest_the_journal_records_is_named_in_the_report_the_header_and_integrity(recorded_case):
    """A missing manifest.jsonl that the journal records is named as missing wherever the evidence is reported, not as a
    case still waiting for intake: the report's Evidence and integrity says to restore it, the case state carries the
    same words for the header, and Integrity's manifest line warns, whatever the last full re-hash found."""
    case = recorded_case
    (record,) = records(case)
    assert main(["verify", str(case.folder)]) == 0
    case.manifest_path.unlink()
    says = (f"manifest.jsonl is missing, but the journal records it, entry #{record['seq']}. Restore it from a copy of the "
            "case.")
    app = App(case)
    try:
        state = api_case_state(app, {})
        line = api_overview(app, {})["integrity"]["manifest"]
        report = (case.folder / api_report(app, {})["path"]).read_text(encoding="utf-8")
    finally:
        app.con.close()
    assert (state["intake"], state["manifest_missing"]) == (False, says)
    assert (line["state"], line["warn"], line["text"]) == (
        "missing", True, f"missing, but the journal records it, entry #{record['seq']}; restore it from a copy of the case")
    assert says in report and "No intake manifest exists" not in report
    assert says in report_section(case)   # the findings command's report


@pytest.mark.parametrize("reader", ["header", "report"])
def test_a_manifest_the_command_line_recorded_beside_the_server_is_named_as_missing_once_deleted(synthetic_case,
                                                                                                reader):
    """The case state and the report catch up with the journal when manifest.jsonl is missing, so an intake the command
    line recorded while the server had the case open names a later deleted manifest as missing, not as a case still
    waiting for intake."""
    case = synthetic_case
    evidence_file(case, "a.txt")
    app = App(case)
    try:
        assert main(["intake", str(case.folder)]) == 0
        (record,) = records(case)
        case.manifest_path.unlink()
        says = f"manifest.jsonl is missing, but the journal records it, entry #{record['seq']}."
        if reader == "header":
            assert says in api_case_state(app, {})["manifest_missing"]
        else:
            assert says in (case.folder / api_report(app, {})["path"]).read_text(encoding="utf-8")
    finally:
        app.con.close()


def test_a_case_without_intake_says_no_manifest_exists(synthetic_case):
    """A case whose journal records no manifest and that has none is still waiting for intake, and says so."""
    case = synthetic_case
    app = App(case)
    try:
        state = api_case_state(app, {})
        line = api_overview(app, {})["integrity"]["manifest"]
        report = (case.folder / api_report(app, {})["path"]).read_text(encoding="utf-8")
    finally:
        app.con.close()
    assert (state["intake"], state["manifest_missing"], line) == (False, "", None)
    assert "No intake manifest exists, so evidence hashes were not checked." in report
