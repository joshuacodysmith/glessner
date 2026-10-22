"""A check of no evidence file reads as nothing checked, never as a pass: verify exits 1, and close, the report, and the
audit trail say the intake manifest lists no file, where they say that all of the files match for a case with some."""

from glessner.audit import _closed_evidence, describe, read_entries
from glessner.cli import main
from glessner.export import _evidence_check
from glessner.intake import Check, intake

VERIFY_SAYS = "No evidence file to check: the intake manifest lists none."
CLOSE_SAYS = "Case closed. No evidence file was checked: the intake manifest lists none. Recorded in the journal."
REPORT_SAYS = "No evidence file was re-hashed when this report was written: the intake manifest lists none."
TRAIL_SAYS = "Closed the case. No evidence file was checked: the intake manifest lists none."


def with_one_file(case):
    (case.evidence / "DC01" / "Security.evtx").write_bytes(b"ElfFile\x00x")
    intake(case)


def test_verify_of_a_manifest_that_lists_no_file_says_so_and_exits_1(synthetic_case, capsys):
    """The journal check still runs and prints."""
    intake(synthetic_case)
    assert main(["verify", str(synthetic_case.folder)]) == 1
    out = capsys.readouterr().out
    assert out.startswith(VERIFY_SAYS + "\n")
    assert "All evidence files match" not in out
    assert "Consistent" in out


def test_verify_of_a_manifest_whose_only_file_intake_could_not_read_names_it_and_exits_0(synthetic_case, capsys, monkeypatch):
    """That file is unverified, which fails nothing since no later check can give it a hash, so the exit differs from an
    empty manifest's."""
    (synthetic_case.evidence / "DC01" / "Security.evtx").write_bytes(b"ElfFile\x00x")

    def locked(path):
        raise PermissionError(13, "The process cannot access the file")

    with monkeypatch.context() as m:
        m.setattr("glessner.intake.sha256_file", locked)
        intake(synthetic_case)
    assert main(["verify", str(synthetic_case.folder)]) == 0
    out = capsys.readouterr().out
    assert out.startswith("No evidence file has an intake hash to check. ")
    assert "DC01/Security.evtx" in out and "lists none" not in out


def test_verify_of_one_hashed_file_still_says_it_matches(synthetic_case, capsys):
    with_one_file(synthetic_case)
    assert main(["verify", str(synthetic_case.folder)]) == 0
    assert capsys.readouterr().out.startswith("All evidence files match the manifest.\n")


def test_close_of_a_manifest_that_lists_no_file_says_so_and_records_it_as_before(synthetic_case, capsys):
    """The journal entry's values are the same as for any close: no files counted, and a hash check that found no
    problem. Only the words differ."""
    intake(synthetic_case)
    assert main(["close", str(synthetic_case.folder)]) == 0
    out = capsys.readouterr().out
    assert out.startswith(CLOSE_SAYS + "\n")
    assert "All 0" not in out
    close = read_entries(synthetic_case.folder / "journal.jsonl")[-1]
    value = close["value"]
    assert (value["evidence_files"], value["hash_check"], value["problems"], value["unverified"]) == (0, "ok", [], 0)
    assert describe(close).startswith(TRAIL_SAYS + " The journal's ")


def test_close_of_one_hashed_file_still_says_it_matches(synthetic_case, capsys):
    with_one_file(synthetic_case)
    assert main(["close", str(synthetic_case.folder)]) == 0
    assert "Case closed. The 1 evidence file matches the intake manifest. Recorded in the journal." in capsys.readouterr().out
    close = read_entries(synthetic_case.folder / "journal.jsonl")[-1]
    assert describe(close).startswith("Closed the case. Its 1 evidence file matches the intake manifest.")


def test_the_report_of_a_manifest_that_lists_no_file_says_so(synthetic_case, capsys):
    intake(synthetic_case)
    assert main(["findings", str(synthetic_case.folder)]) == 0
    capsys.readouterr()
    (report,) = (synthetic_case.folder / "exports").glob("report_*.md")
    text = report.read_text(encoding="utf-8")
    assert REPORT_SAYS in text
    assert "Every evidence file" not in text and "all match" not in text


def test_the_evidence_check_sentences():
    assert _evidence_check(Check([], 0, [])) == REPORT_SAYS
    assert _evidence_check(Check([], 1, [])) == (
        "Every evidence file (1) was re-hashed when this report was written, and all match the intake manifest."
    )
    assert _evidence_check(Check([], 3, [])) == (
        "Every evidence file (3) was re-hashed when this report was written, and all match the intake manifest."
    )
    # A file intake couldn't read is named, and a report with only such files keeps its own sentence
    assert _evidence_check(Check([], 0, ["a.bin"])).startswith("No evidence file was re-hashed when this report was written.")
    assert "the intake manifest lists none" not in _evidence_check(Check([], 0, ["a.bin"]))


def test_the_audit_trail_sentences_for_a_close():
    assert _closed_evidence({"evidence_files": 0, "hash_check": "ok"}) == TRAIL_SAYS
    assert _closed_evidence({"evidence_files": 1, "hash_check": "ok"}) == (
        "Closed the case. Its 1 evidence file matches the intake manifest."
    )
    assert _closed_evidence({"evidence_files": 2, "hash_check": "ok"}) == (
        "Closed the case. All 2 evidence files match the intake manifest."
    )
    skipped = _closed_evidence({"evidence_files": 0, "hash_check": "ok", "unverified": 1})
    assert skipped.startswith("Closed the case. No evidence file has an intake hash to check.")
    assert "lists none" not in skipped
