"""What a case promises about its evidence: intake, runs on working copies, loads, imports, and exports leave it unchanged;
a report counts the files that no longer match the intake manifest and names the first ten; a copy carries the case's
custody record; and no load reads a file intake did not hash or one that changed. Each check of a file's hash is tried
with an edit that keeps the file's size, and most also with one that changes it."""

import json
import re

import pytest
from conftest import FAST_ALERTS, flip_a_byte
from custody_cases import (
    FAST_LOG,
    app_views,
    build,
    event_rows,
    load_found_outputs,
    make_evidence,
    snapshot,
    stand_in_sqlecmd,
    take_in,
)

from glessner import runner
from glessner.case import open_case
from glessner.cli import main
from glessner.imports import MappingError, preview, run_import
from glessner.intake import check_files, intake
from glessner.runner import load_found_output, plan_runs, read_runs, rebuild, run

EVTX_CSV = "DC01/Modules/EventLogs/20240514_EvtxECmd_Output.csv"
EVTX_CSV_EVENTS = 5   # the events in that file: two records, one of them twice, a dotted-domain logon, and a service event


def append_a_newline(path):
    """An edit that changes a file's size."""
    path.write_bytes(path.read_bytes() + b"\n")


def flip_near_the_end(path):
    """An edit that keeps a file's size: one byte, in the last line's text."""
    flip_a_byte(path, at=-3)


EDITS = pytest.mark.parametrize("edit", [append_a_newline, flip_near_the_end], ids=["size_changed", "size_kept"])


def test_the_evidence_is_never_written(tmp_path):
    """The evidence folder is the same after these ways the app reaches it: intake, a run of a tool that works on copies,
    the built-in reader's run, loads of found output, an import, adding a file that arrived later, opening the case for
    work, the exports and the indicators, the report, verify, close, a rebuild, and a copy of the case. Each file keeps its
    bytes, size, and modification time, and each folder its listing and modification time, which a temporary file made
    and deleted in it would change. A tool that reads the evidence in place is not run here."""
    evidence = make_evidence(tmp_path)
    before = snapshot(evidence)
    case = build(evidence, tmp_path / "case", stand_in_sqlecmd(tmp_path))
    assert snapshot(evidence) == before, "intake, a tool run, a load of found output, or the import wrote to the evidence"

    (evidence / "LATE").mkdir()
    (evidence / "LATE" / "late.txt").write_text("arrived after intake")
    before = snapshot(evidence)
    folder = str(case.folder)
    assert main(["intake", folder, "--add"]) == 0
    app_views(case)
    for command in (["findings", folder], ["verify", folder], ["close", folder]):
        assert main(command) == 0, command
    rebuild(case)
    assert main(["copy-case", folder, str(tmp_path / "copy"), "--name", "Copy"]) == 0
    assert snapshot(evidence) == before


def saved_record(case, run_id: str) -> dict:
    """A run's run.json as data, without load_seconds, which a copy's rebuild measures again for its own load."""
    record = json.loads((case.runs_folder / run_id / "run.json").read_text("utf-8"))
    del record["load_seconds"]
    return record


def test_a_copy_keeps_the_custody_record(tmp_path, capsys):
    """A copy of a case holds the source's manifest, verification history, run records, and events. A file added to the
    evidence after the source's intake stays unlisted in the copy. Verify gives the same answer on both, before and after
    a listed file changes. Making the copy writes nothing into the source."""
    evidence = make_evidence(tmp_path)
    (evidence / "NOTES.txt").write_text("listed at intake, read by no run")
    source = take_in(evidence, tmp_path / "source")
    (plan,) = plan_runs(source, stand_in_sqlecmd(tmp_path))
    assert run(source, plan).status == "ok"
    assert load_found_outputs(source, only=("evtxecmd_csv:DC01",)) == ["evtxecmd_csv:DC01"]
    (evidence / "late.txt").write_text("arrived after intake")
    before = snapshot(source.folder)

    assert main(["copy-case", str(source.folder), str(tmp_path / "copy"), "--name", "Copy"]) == 0
    assert snapshot(source.folder) == before
    copy = open_case(tmp_path / "copy")
    assert copy.manifest_path.read_bytes() == source.manifest_path.read_bytes()
    assert b"late.txt" not in copy.manifest_path.read_bytes()
    history = source.verification_path.read_bytes()
    assert history.count(b"\n") >= 3 and copy.verification_path.read_bytes().startswith(history)
    run_ids = sorted(record.run_id for record in read_runs(source))
    assert len(run_ids) == 2 and run_ids == sorted(record.run_id for record in read_runs(copy))
    for run_id in run_ids:
        assert saved_record(copy, run_id) == saved_record(source, run_id)
    assert event_rows(copy) == event_rows(source)

    capsys.readouterr()
    for case in (source, copy):
        assert main(["verify", str(case.folder)]) == 0
        output = capsys.readouterr().out
        assert "All evidence files match the manifest." in output and "Consistent: each of the " in output, output

    flip_a_byte(evidence / "NOTES.txt")
    checks = [check_files(case, reason="manual full verification") for case in (source, copy)]
    assert checks[0].problems == checks[1].problems == ["NOTES.txt: SHA-256 changed"]
    assert checks[0].checked == checks[1].checked
    capsys.readouterr()
    assert [main(["verify", str(case.folder)]) for case in (source, copy)] == [1, 1]
    assert capsys.readouterr().out.count("NOTES.txt: SHA-256 changed") == 2


def evidence_section(report: str) -> str:
    """The report's Evidence and integrity section."""
    return re.search(r"^## \d+\. Evidence and integrity\n(.*?)(?=^## |\Z)", report, re.DOTALL | re.MULTILINE).group(1)


def report_section(case) -> str:
    """Write a report with the findings command, and return its Evidence and integrity section."""
    reports = case.folder / "exports"
    before = set(reports.glob("report_*.md"))
    assert main(["findings", str(case.folder)]) == 0
    (report,) = set(reports.glob("report_*.md")) - before
    return evidence_section(report.read_text("utf-8"))


def test_the_report_names_the_files_that_changed_since_intake(synthetic_case):
    """Each report re-hashes every evidence file and says so. It names a file that changed in size, one that changed with
    its size kept, and a missing one, with the reasons verify gives, and says that all match once they are restored. The
    re-hash is recorded as a full check."""
    case = synthetic_case
    original = {"DC01/System.evtx": b"ElfFile\x00dc", "DESKTOP/NTUSER.DAT": b"regf" + b"\x02" * 10, "README.txt": b"readme"}
    for name, data in original.items():
        (case.evidence / name).write_bytes(data)
    intake(case)

    append_a_newline(case.evidence / "DC01/System.evtx")
    flip_a_byte(case.evidence / "DESKTOP/NTUSER.DAT")
    (case.evidence / "README.txt").unlink()
    section = report_section(case)
    assert "Every evidence file (3) was re-hashed when this report was written. 3 do not match the intake manifest: " in section
    problems = ["DC01/System.evtx: SHA-256 changed", "DESKTOP/NTUSER.DAT: SHA-256 changed", "README.txt: missing"]
    assert all(problem in section for problem in problems)

    for name, data in original.items():
        (case.evidence / name).write_bytes(data)
    assert ("Every evidence file (3) was re-hashed when this report was written, and all match the intake manifest."
            in report_section(case))
    checks = [json.loads(line) for line in case.verification_path.read_text("utf-8").splitlines()]
    assert [(c["reason"], c["result"], c["files_checked"], sorted(c["problems"])) for c in checks] == [
        ("full check when writing the report", "mismatch", 3, problems),
        ("full check when writing the report", "ok", 3, [])]


def test_the_report_counts_every_changed_file_and_names_the_first_ten(synthetic_case):
    """When more files changed than the report names, it states how many do not match and names the first ten in the
    manifest's order. The verification record keeps every one."""
    case = synthetic_case
    names = [f"DC01/f{n:02d}.txt" for n in range(12)]
    for name in names:
        (case.evidence / name).write_text(f"file {name}")
    intake(case)
    for name in names:
        flip_a_byte(case.evidence / name)

    section = report_section(case)
    problems = [f"{name}: SHA-256 changed" for name in names]
    assert (f"Every evidence file (12) was re-hashed when this report was written. 12 do not match the intake manifest: "
            f"{'; '.join(problems[:10])}." in section)
    assert not any(name in section for name in names[10:])
    (record,) = (json.loads(line) for line in case.verification_path.read_text("utf-8").splitlines())
    assert record["problems"] == problems


@pytest.fixture
def intaken_case(tmp_path):
    """A case on make_evidence's evidence, with nothing loaded."""
    return take_in(make_evidence(tmp_path), tmp_path / "case")


@EDITS
def test_an_import_refuses_a_file_intake_did_not_hash_and_one_that_changed(intaken_case, edit):
    """An import reads only a file the manifest lists, and only while it matches its intake hash. A file that arrived
    after intake is refused with the way to add it, and a listed file that changed fails its run with the check's reason.
    Neither loads an event."""
    case = intaken_case
    mapping = preview(case, FAST_LOG)["mapping"]
    mapping = {**mapping, "time": {**mapping["time"], "zone": "UTC"}}
    (case.evidence / "IDS" / "late.log").write_text(FAST_ALERTS, newline="\n")
    with pytest.raises(MappingError, match=r"IDS/late\.log isn't in the manifest yet; use Add new evidence first\."):
        run_import(case, "IDS/late.log", mapping, zones={})
    assert event_rows(case) == [] and list(case.runs_folder.iterdir()) == []

    edit(case.evidence / FAST_LOG)
    record = run_import(case, FAST_LOG, mapping, zones={})
    assert (record.status, record.evidence_check, record.loaded_rows) == ("failed", "mismatch", None)
    assert record.reason == "the file doesn't match its intake hash: IDS/fast.log: SHA-256 changed"
    assert event_rows(case) == []
    assert [(r.run_id, r.status) for r in read_runs(case)] == [(record.run_id, "failed")]


@EDITS
def test_found_output_is_refused_when_it_changed_and_fails_when_it_changes_while_read(intaken_case, monkeypatch, edit):
    """A load of a tool's output found in the evidence checks the files' hashes before it reads them and again after. A
    file that changed before the load is refused. One that changes while the load reads it fails the run, which records
    the file as changed."""
    case = intaken_case
    csv_file = case.evidence / EVTX_CSV
    original = csv_file.read_bytes()
    edit(csv_file)
    refused = load_found_output(case, "evtxecmd", "evtxecmd_csv", "DC01", [EVTX_CSV])
    assert (refused.status, refused.evidence_check, refused.loaded_rows) == ("failed", "mismatch", None)
    assert refused.reason == f"the output doesn't match its intake hash: {EVTX_CSV}: SHA-256 changed"
    assert event_rows(case) == []

    csv_file.write_bytes(original)
    real = runner.load_output

    def read_while_it_changes(case, record, folder, layout=None):
        real(case, record, folder, layout)
        edit(csv_file)

    monkeypatch.setattr(runner, "load_output", read_while_it_changes)
    changed = load_found_output(case, "evtxecmd", "evtxecmd_csv", "DC01", [EVTX_CSV])
    assert (changed.status, changed.evidence_check) == ("failed", "mismatch")
    assert changed.reason == "evidence changed while it was read"
    assert changed.evidence_problems == [f"{EVTX_CSV}: SHA-256 changed"]


@EDITS
def test_a_rebuild_leaves_out_found_output_that_changed_since_it_loaded(intaken_case, edit):
    """A rebuild loads a found-output run from the evidence again, after checking the files against their intake hashes. A
    file that changed since the load leaves its run out: no rows, and a note that gives the check's reason."""
    case = intaken_case
    loaded = load_found_output(case, "evtxecmd", "evtxecmd_csv", "DC01", [EVTX_CSV])
    assert (loaded.status, loaded.loaded_rows) == ("ok", EVTX_CSV_EVENTS)
    stored = event_rows(case)
    assert len(stored) == EVTX_CSV_EVENTS
    assert [r.loaded_rows for r in rebuild(case)] == [EVTX_CSV_EVENTS] and event_rows(case) == stored

    edit(case.evidence / EVTX_CSV)
    (record,) = rebuild(case)
    assert record.loaded_rows == 0
    assert " left it out: " in record.notes[-1] and f"{EVTX_CSV}: SHA-256 changed" in record.notes[-1]
    assert event_rows(case) == []
    (saved,) = read_runs(case)
    assert (saved.loaded_rows, saved.notes) == (0, record.notes)


def test_a_load_that_failed_because_the_file_changed_keeps_its_rows_until_a_rebuild(intaken_case, monkeypatch):
    """A found-output load whose file changes while it reads is recorded as failed, and the rows it committed stay in the
    events table, as an import's do. A rebuild loads only runs that succeeded, so it leaves them out, though the file is
    restored."""
    case = intaken_case
    csv_file = case.evidence / EVTX_CSV
    original = csv_file.read_bytes()
    real = runner.load_output

    def read_while_it_changes(case, record, folder, layout=None):
        real(case, record, folder, layout)
        flip_near_the_end(csv_file)

    monkeypatch.setattr(runner, "load_output", read_while_it_changes)
    changed = load_found_output(case, "evtxecmd", "evtxecmd_csv", "DC01", [EVTX_CSV])
    assert (changed.status, changed.loaded_rows) == ("failed", EVTX_CSV_EVENTS)
    assert len(event_rows(case)) == EVTX_CSV_EVENTS

    csv_file.write_bytes(original)
    assert rebuild(case) == []
    assert event_rows(case) == []
