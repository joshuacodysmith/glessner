"""A cloud placeholder, such as a OneDrive file whose content isn't on the disk, is never opened: reading it would download
it. A file whose recall attributes mark it as a placeholder can't be made in a test, so most of these tests name one by
patching the attribute checks, and make any read of its path fail. The last test sets the offline attribute, which an
ordinary file can carry, so that the real attribute read decides."""

import ctypes
import sys
from types import SimpleNamespace

import pytest
from test_runner import fake_spec, with_spec

from glessner import intake as intake_module
from glessner.case import create_case
from glessner.intake import (
    PLACEHOLDER,
    RECALL_ON_DATA_ACCESS,
    RECALL_ON_OPEN,
    add_new,
    check_files,
    current_entries,
    intake,
    is_placeholder,
    read_manifest,
    walk_evidence,
)
from glessner.runner import UNREADABLE, RunError, check_host_folder, check_result, plan_runs, run

CLOUD = "cloud.txt"
NOT_ON_DISK = "a cloud placeholder whose content isn't on this disk"


def listing_tool(tmp_path):
    """The fake host_dir tool, which lists the host's folder itself."""
    tool = fake_spec(tmp_path)
    return with_spec(tool, args=tool.spec.args[:-1] + ("ok",))


def refuse_reads(monkeypatch, name=CLOUD):
    """Make hashing or identifying the file called `name` fail the test."""
    def guard(real):
        def read(path, *args, **options):
            assert not str(path).endswith(name), f"{path} was read"
            return real(path, *args, **options)
        return read

    monkeypatch.setattr(intake_module, "sha256_file", guard(intake_module.sha256_file))
    monkeypatch.setattr(intake_module, "identify_file", guard(intake_module.identify_file))


def mark_placeholder(monkeypatch, name=CLOUD):
    """Make the folder listing report the file called `name` as a cloud placeholder."""
    monkeypatch.setattr(intake_module, "is_placeholder", lambda entry: entry.name == name)


def evidence_with_cloud_file(tmp_path):
    evidence = tmp_path / "evidence"
    logs = evidence / "HOST" / "Windows" / "System32" / "winevt" / "Logs"
    logs.mkdir(parents=True)
    (logs / "Security.evtx").write_bytes(b"ElfFile\x00host")
    (evidence / "HOST" / CLOUD).write_text("content that stays in the cloud")
    return evidence


def test_the_walk_lists_a_placeholder_and_still_yields_it(tmp_path, monkeypatch):
    evidence = evidence_with_cloud_file(tmp_path)
    mark_placeholder(monkeypatch)
    placeholders = []
    files = list(walk_evidence(evidence, placeholders=placeholders))
    assert placeholders == [f"HOST/{CLOUD}"] and f"HOST/{CLOUD}" in files
    assert list(walk_evidence(evidence)) == files   # a caller that doesn't ask sees no change


def test_intake_records_a_placeholder_as_unreadable_without_opening_it(tmp_path, monkeypatch):
    evidence = evidence_with_cloud_file(tmp_path)
    mark_placeholder(monkeypatch)
    refuse_reads(monkeypatch)
    case = create_case(tmp_path / "case", "Cloud", evidence, "cody")
    summary = intake(case)
    entry = next(e for e in read_manifest(case) if e.path == f"HOST/{CLOUD}")
    assert (entry.size, entry.sha256, entry.artifact, entry.method, entry.error) == (0, "", None, "unreadable", PLACEHOLDER)
    assert ": " not in PLACEHOLDER
    assert summary.errors == [f"HOST/{CLOUD}: {PLACEHOLDER}"]
    assert summary.by_artifact == {"evtx": 1}


def test_add_new_records_a_later_placeholder_without_opening_it_and_does_not_call_it_missing(tmp_path, monkeypatch):
    evidence = tmp_path / "evidence"
    (evidence / "HOST").mkdir(parents=True)
    (evidence / "HOST" / "a.txt").write_text("hashed at intake")
    case = create_case(tmp_path / "case", "Cloud", evidence, "cody")
    intake(case)
    (evidence / "HOST" / CLOUD).write_text("content that stays in the cloud")
    mark_placeholder(monkeypatch)
    refuse_reads(monkeypatch)
    summary = add_new(case)
    assert summary.missing == [] and summary.errors == [f"HOST/{CLOUD}: {PLACEHOLDER}"] and summary.by_artifact == {}
    entry = next(e for e in read_manifest(case) if e.path == f"HOST/{CLOUD}")
    assert (entry.sha256, entry.method, entry.error) == ("", "unreadable", PLACEHOLDER) and entry.added_utc
    again = add_new(case)
    assert again.missing == [] and again.errors == []   # listed now, and still seen by the walk


def test_a_check_reports_a_file_that_became_a_placeholder_and_never_reads_it(tmp_path, monkeypatch):
    evidence = tmp_path / "evidence"
    (evidence / "HOST").mkdir(parents=True)
    (evidence / "HOST" / CLOUD).write_text("hashed at intake")
    (evidence / "HOST" / "a.txt").write_text("stays on the disk")
    case = create_case(tmp_path / "case", "Cloud", evidence, "cody")
    intake(case)
    refuse_reads(monkeypatch)
    real = intake_module.file_attributes
    monkeypatch.setattr(intake_module, "file_attributes",
                        lambda path: RECALL_ON_DATA_ACCESS if path.name == CLOUD else real(path))
    check = check_files(case)
    assert check.problems == [f"HOST/{CLOUD}: unreadable ({NOT_ON_DISK})"]
    assert check_result(check.problems) == UNREADABLE


def test_a_tool_that_lists_the_host_folder_is_refused_while_it_holds_a_placeholder(tmp_path, monkeypatch):
    evidence = evidence_with_cloud_file(tmp_path)
    mark_placeholder(monkeypatch)
    case = create_case(tmp_path / "case", "Cloud", evidence, "cody")
    intake(case)
    (plan,) = plan_runs(case, listing_tool(tmp_path))
    with pytest.raises(RunError, match=rf"Fake wasn't run on HOST: .*1 cloud placeholder.*HOST/{CLOUD}"):
        check_host_folder(case, plan)
    with pytest.raises(RunError, match="cloud placeholder"):
        run(case, plan)
    assert not case.runs_folder.exists() or list(case.runs_folder.iterdir()) == []


def test_a_host_folder_without_a_placeholder_is_not_refused(tmp_path):
    evidence = evidence_with_cloud_file(tmp_path)
    case = create_case(tmp_path / "case", "Cloud", evidence, "cody")
    intake(case)
    (plan,) = plan_runs(case, listing_tool(tmp_path))
    check_host_folder(case, plan)


@pytest.mark.parametrize(("attributes", "expected"), [
    (RECALL_ON_DATA_ACCESS, True), (RECALL_ON_OPEN, True), (0x1000, True), (RECALL_ON_DATA_ACCESS | 0x20, True),
    (0x20, False), (0x80, False), (0, False)])
def test_the_attributes_that_mark_a_placeholder(attributes, expected):
    entry = SimpleNamespace(stat=lambda follow_symlinks=True: SimpleNamespace(st_file_attributes=attributes))
    assert is_placeholder(entry) is expected
    assert RECALL_ON_DATA_ACCESS == 0x400000 and RECALL_ON_OPEN == 0x40000


def test_an_entry_that_cannot_be_statted_is_not_a_placeholder():
    def refuse(follow_symlinks=True):
        raise OSError("gone")

    assert is_placeholder(SimpleNamespace(stat=refuse)) is False
    assert is_placeholder(SimpleNamespace(stat=lambda follow_symlinks=True: SimpleNamespace())) is False   # not Windows


def test_the_entries_never_read_again_a_file_that_became_a_placeholder_after_intake(tmp_path, monkeypatch):
    evidence = tmp_path / "evidence"
    (evidence / "HOST").mkdir(parents=True)
    (evidence / "HOST" / CLOUD).write_text("hashed at intake")
    (evidence / "HOST" / "a.txt").write_text("stays on the disk")
    case = create_case(tmp_path / "case", "Cloud", evidence, "cody")
    intake(case)
    read = []
    real_identify, real_attributes = intake_module.identify_file, intake_module.file_attributes

    def identify(path, *args, **options):
        read.append(path.name)
        return real_identify(path, *args, **options)

    monkeypatch.setattr(intake_module, "identify_file", identify)
    monkeypatch.setattr(intake_module, "file_attributes",
                        lambda path: RECALL_ON_OPEN if path.name == CLOUD else real_attributes(path))
    entries = {e.path: e for e in current_entries(case)}
    assert read == ["a.txt"]   # a text file is identified again by today's rules, unless reading it would download it
    assert entries[f"HOST/{CLOUD}"] == next(e for e in read_manifest(case) if e.path == f"HOST/{CLOUD}")   # as intake had it


@pytest.mark.skipif(sys.platform != "win32", reason="file attributes are Windows'")
def test_a_file_marked_offline_is_left_unread_by_the_real_attribute_check(tmp_path, monkeypatch):
    offline = 0x1000 | 0x20   # FILE_ATTRIBUTE_OFFLINE with FILE_ATTRIBUTE_ARCHIVE
    evidence = tmp_path / "evidence"
    (evidence / "HOST").mkdir(parents=True)
    old, later = evidence / "HOST" / CLOUD, evidence / "HOST" / "later.txt"
    old.write_text("hashed at intake")
    case = create_case(tmp_path / "case", "Cloud", evidence, "cody")
    intake(case)
    later.write_text("added after intake")
    try:
        assert ctypes.windll.kernel32.SetFileAttributesW(str(old), offline)
        assert ctypes.windll.kernel32.SetFileAttributesW(str(later), offline)
        refuse_reads(monkeypatch, "cloud.txt")
        refuse_reads(monkeypatch, "later.txt")
        assert check_files(case).problems == [f"HOST/{CLOUD}: unreadable ({NOT_ON_DISK})"]
        assert [e.path for e in current_entries(case)] == [f"HOST/{CLOUD}"]
        summary = add_new(case)
        assert summary.errors == [f"HOST/later.txt: {PLACEHOLDER}"]
        entry = next(e for e in read_manifest(case) if e.path == "HOST/later.txt")
        assert (entry.sha256, entry.method, entry.error) == ("", "unreadable", PLACEHOLDER)
    finally:
        for path in (old, later):
            ctypes.windll.kernel32.SetFileAttributesW(str(path), 0x20)
