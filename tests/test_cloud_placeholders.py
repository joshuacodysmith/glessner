"""A cloud placeholder, such as a OneDrive file whose content isn't on the disk, is never opened: reading it would download
it. A file whose recall attributes mark it as a placeholder can't be made in a test, so most of these tests name one by
patching the attribute checks, and make any read of its path fail. The last tests set the offline attribute, which an
ordinary file can carry, so that the real attribute read decides."""

import ctypes
import pathlib
import re
import sys
from types import SimpleNamespace

import pytest
from test_runner import fake_spec, with_spec

from glessner import imports as imports_module
from glessner import intake as intake_module
from glessner.case import create_case
from glessner.identify import EVTX_MAGIC, REGF_MAGIC
from glessner.imports import MappingError, guess_mapping, preview, run_import, sniff
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
from glessner.runner import UNREADABLE, RunError, _make_copies, check_host_folder, check_result, plan_runs, run

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


JSONL = ('{"@timestamp": "2024-02-05T10:21:48Z", "host": {"name": "WEB01"}, "message": "first"}\n'
         '{"@timestamp": "2024-02-05T10:21:49Z", "host": {"name": "WEB01"}, "message": "second"}\n')
SYSTEM_LOG = "HOST/Logs/System.evtx"


def logs_case(tmp_path):
    """HOST holds two event logs, a registry hive with a transaction log beside it, and a JSON lines log."""
    evidence = tmp_path / "evidence"
    (evidence / "HOST" / "Logs").mkdir(parents=True)
    for name in ("Security.evtx", "System.evtx"):
        (evidence / "HOST" / "Logs" / name).write_bytes(EVTX_MAGIC + name.encode())
    for name in ("NTUSER.DAT", "NTUSER.DAT.LOG1"):
        (evidence / "HOST" / name).write_bytes(REGF_MAGIC + bytes(100))
    (evidence / "HOST" / "app.jsonl").write_text(JSONL, newline="\n")
    case = create_case(tmp_path / "case", "Cloud", evidence, "cody")
    intake(case)
    return case


def became_placeholder(monkeypatch, *names):
    """Make the attribute read and the folder listing report each file called one of `names` as a cloud placeholder, as
    they do for a file that became one after intake."""
    real = intake_module.file_attributes
    monkeypatch.setattr(intake_module, "file_attributes",
                        lambda path: RECALL_ON_DATA_ACCESS if path.name in names else real(path))
    monkeypatch.setattr(intake_module, "is_placeholder", lambda entry: entry.name in names)


def refuse_import_reads(monkeypatch):
    """Make any read of an import's file fail the test."""
    def read(*args, **options):
        raise AssertionError(f"read {args}")

    for name in ("identify_file", "records", "count_lines"):
        monkeypatch.setattr(imports_module, name, read)


def refusal(reader, path, hashed=True):
    """The words that follow a refusal's first sentence: a cloud placeholder that `reader` would download, and, for one
    that intake hashed before it became one, that making it available again will do."""
    advice = ("Make it available on this disk and try again; intake's hash still covers it." if hashed
              else "Make the folder available on this disk and start a new case from it, or remove it.")
    return re.escape(f"1 cloud placeholder, whose content isn't on this disk, which {reader} would download by reading it: "
                     f"{path}. {advice}")


def nothing_run(case):
    return not case.runs_folder.exists() or list(case.runs_folder.iterdir()) == []


def each_file_tool(tmp_path):
    """The fake tool run once per file, given the file as {input_file}."""
    tool = fake_spec(tmp_path)
    return with_spec(tool, input="each_file", args=(tool.spec.args[0], "{input_file}", "{output_dir}", "ok"))


def input_list_tool(tmp_path):
    """The fake host_dir tool, given the list of its inputs rather than the folder, as the event XML reader is."""
    tool = fake_spec(tmp_path)
    return with_spec(tool, args=(tool.spec.args[0], "{input_list}", "{output_dir}", "ok"))


def copying_tool(tmp_path, copy_also=()):
    return with_spec(listing_tool(tmp_path), work_on_copies=True, copy_also=copy_also)


def test_the_import_preview_refuses_a_file_that_became_a_placeholder_after_intake(tmp_path, monkeypatch):
    case = logs_case(tmp_path)
    mapping = guess_mapping(sniff(case, "HOST/app.jsonl"))
    assert not preview(case, "HOST/app.jsonl", mapping, zones={})["problems"]   # as it reads while it is an ordinary file
    became_placeholder(monkeypatch, "app.jsonl")
    refuse_import_reads(monkeypatch)
    for given in (None, mapping):   # the mapping the page guesses, and the one it sends back
        with pytest.raises(MappingError, match=refusal("the import", "HOST/app.jsonl")):
            preview(case, "HOST/app.jsonl", given, zones={})


def test_the_import_says_when_intake_recorded_the_file_as_a_placeholder(tmp_path, monkeypatch):
    mark_placeholder(monkeypatch, "app.jsonl")
    case = logs_case(tmp_path)
    became_placeholder(monkeypatch, "app.jsonl")
    refuse_import_reads(monkeypatch)
    with pytest.raises(MappingError) as refused:
        sniff(case, "HOST/app.jsonl")
    assert str(refused.value) == (
        "The file wasn't read: intake recorded it as a cloud placeholder. "
        "1 cloud placeholder, whose content isn't on this disk, which the import would download by reading it: "
        "HOST/app.jsonl. Make the folder available on this disk and start a new case from it, or remove it.")


def test_the_import_says_when_intake_could_not_read_a_file_that_is_a_placeholder_now(tmp_path, monkeypatch):
    real_hash = intake_module.sha256_file

    def locked(path, *args, **options):
        if path.name == "app.jsonl":
            raise PermissionError(13, "The process cannot access the file")
        return real_hash(path, *args, **options)

    monkeypatch.setattr(intake_module, "sha256_file", locked)
    case = logs_case(tmp_path)
    error = next(e.error for e in read_manifest(case) if e.path == "HOST/app.jsonl")
    assert error.startswith("PermissionError")   # an entry with an error that isn't PLACEHOLDER
    became_placeholder(monkeypatch, "app.jsonl")
    refuse_import_reads(monkeypatch)
    with pytest.raises(MappingError) as refused:
        sniff(case, "HOST/app.jsonl")
    assert str(refused.value) == (
        "The file wasn't read: intake couldn't read it, and it is a cloud placeholder now. "
        "1 cloud placeholder, whose content isn't on this disk, which the import would download by reading it: "
        "HOST/app.jsonl. Make the folder available on this disk and start a new case from it, or remove it.")


def test_the_import_reads_a_files_attributes_before_it_resolves_or_opens_the_path(tmp_path, monkeypatch):
    """Resolving a path opens the file, or the link it is, so the check on a placeholder comes before it."""
    case = logs_case(tmp_path)
    became_placeholder(monkeypatch, "app.jsonl")
    touched = []

    def watch(real):
        def follow(self, *args, **options):
            touched.append(self.name)
            return real(self, *args, **options)
        return follow

    for name in ("resolve", "is_file"):
        monkeypatch.setattr(pathlib.Path, name, watch(getattr(pathlib.Path, name)))
    with pytest.raises(MappingError, match="cloud placeholder"):
        sniff(case, "HOST/app.jsonl")
    assert "app.jsonl" not in touched


def test_a_path_the_manifest_does_not_list_is_not_an_evidence_file(tmp_path):
    case = logs_case(tmp_path)
    for rel_path in ("../outside.txt", "HOST/missing.txt"):
        with pytest.raises(MappingError, match="Not an evidence file"):
            sniff(case, rel_path)


def test_the_import_refuses_a_file_that_became_a_placeholder_after_intake_and_makes_no_run(tmp_path, monkeypatch):
    case = logs_case(tmp_path)
    mapping = guess_mapping(sniff(case, "HOST/app.jsonl"))
    became_placeholder(monkeypatch, "app.jsonl")
    refuse_import_reads(monkeypatch)
    with pytest.raises(MappingError, match=refusal("the import", "HOST/app.jsonl")):
        run_import(case, "HOST/app.jsonl", mapping, zones={})
    assert nothing_run(case)


@pytest.mark.parametrize("make_tool", [listing_tool, each_file_tool, input_list_tool])
def test_a_run_is_refused_when_an_input_became_a_placeholder_after_intake(tmp_path, monkeypatch, make_tool):
    """The tool that lists the host's folder, the one run on each file, and the one given the list of its inputs: no
    tool starts, and no run folder is made."""
    case = logs_case(tmp_path)
    (plan,) = [p for p in plan_runs(case, make_tool(tmp_path)) if SYSTEM_LOG in p.inputs]
    became_placeholder(monkeypatch, "System.evtx")
    with pytest.raises(RunError, match=rf"Fake wasn't run on HOST: .*{refusal('the tool', SYSTEM_LOG)}"):
        run(case, plan)
    assert nothing_run(case)


def test_a_refusal_counts_the_placeholders_it_names(tmp_path, monkeypatch):
    case = logs_case(tmp_path)
    (plan,) = plan_runs(case, input_list_tool(tmp_path))
    became_placeholder(monkeypatch, "Security.evtx", "System.evtx")
    with pytest.raises(RunError) as refused:
        run(case, plan)
    assert str(refused.value) == (
        "Fake wasn't run on HOST: it reads files that intake hashed before they became cloud placeholders. "
        "2 cloud placeholders, whose content isn't on this disk, which the tool would download by reading them: "
        "HOST/Logs/Security.evtx; HOST/Logs/System.evtx. Make them available on this disk and try again; intake's hash "
        "still covers them.")


def test_a_tool_that_lists_the_host_folder_is_refused_for_a_file_that_became_a_placeholder_in_words_of_its_own(
        tmp_path, monkeypatch):
    """The folder holds files intake hashed, so the refusal doesn't say that the folder holds what intake didn't hash, and
    it names a file in the folder that is no input of the run, such as a hive's log."""
    case = logs_case(tmp_path)
    (plan,) = plan_runs(case, listing_tool(tmp_path))
    became_placeholder(monkeypatch, "System.evtx", "NTUSER.DAT.LOG1")
    with pytest.raises(RunError) as refused:
        run(case, plan)
    assert str(refused.value) == (
        "Fake wasn't run on HOST: it lists the host's folder itself, which holds files that intake hashed before they "
        "became cloud placeholders. 2 cloud placeholders, whose content isn't on this disk, which the tool would "
        "download by reading them: HOST/NTUSER.DAT.LOG1; HOST/Logs/System.evtx. Make them available on this disk and "
        "try again; intake's hash still covers them.")
    assert nothing_run(case)


def test_a_host_folder_with_both_kinds_of_placeholder_names_each_kind(tmp_path, monkeypatch):
    """One that intake recorded as a placeholder, and one that became one after intake hashed the file."""
    mark_placeholder(monkeypatch, "app.jsonl")
    case = logs_case(tmp_path)
    (plan,) = plan_runs(case, listing_tool(tmp_path))
    became_placeholder(monkeypatch, "app.jsonl", "System.evtx")
    with pytest.raises(RunError) as refused:
        run(case, plan)
    assert str(refused.value) == (
        "Fake wasn't run on HOST: it lists the host's folder itself, which holds what intake didn't hash. "
        "1 cloud placeholder, whose content isn't on this disk, which the tool would download by reading it: "
        "HOST/app.jsonl. Make the folder available on this disk and start a new case from it, or remove it. "
        "It also holds files that intake hashed before they became cloud placeholders. "
        "1 cloud placeholder, whose content isn't on this disk, which the tool would download by reading it: "
        "HOST/Logs/System.evtx. Make it available on this disk and try again; intake's hash still covers it.")


def test_a_file_run_on_its_own_is_unaffected_by_another_file_that_became_a_placeholder(tmp_path, monkeypatch):
    case = logs_case(tmp_path)
    plans = {p.input_file: p for p in plan_runs(case, each_file_tool(tmp_path))}
    became_placeholder(monkeypatch, "System.evtx")
    assert run(case, plans["HOST/Logs/Security.evtx"]).status == "ok"


@pytest.mark.parametrize(("name", "path"), [("System.evtx", SYSTEM_LOG), ("NTUSER.DAT.LOG1", "HOST/NTUSER.DAT.LOG1")])
def test_a_run_on_copies_is_refused_when_a_file_it_copies_became_a_placeholder(tmp_path, monkeypatch, name, path):
    """An input, and a file copied with the inputs (copy_also)."""
    case = logs_case(tmp_path)
    (plan,) = plan_runs(case, copying_tool(tmp_path, ("registry_log",)))
    became_placeholder(monkeypatch, name)
    with pytest.raises(RunError, match=rf"Fake wasn't run on HOST: .*{refusal('the tool', path)}"):
        run(case, plan)
    assert nothing_run(case)


def test_working_copies_are_not_made_of_a_file_that_became_a_placeholder(tmp_path, monkeypatch):
    case = logs_case(tmp_path)
    (plan,) = plan_runs(case, copying_tool(tmp_path))
    became_placeholder(monkeypatch, "System.evtx")
    copies = tmp_path / "copies"
    with pytest.raises(RunError, match=refusal("the tool", SYSTEM_LOG)):
        _make_copies(case, plan, copies)
    assert not copies.exists()   # nothing is copied before the check


@pytest.mark.parametrize("changes", [
    {"related": ({"artifact": "registry_log", "args": ["--log", "{related}"]},)},
    {"handles": ("registry:NTUSER",), "without_related": ({"artifact": "registry_log", "args": ["--nl"]},)}],
    ids=["a related file", "a log beside a hive"])
def test_a_run_is_refused_when_a_file_it_reads_with_its_input_became_a_placeholder(tmp_path, monkeypatch, changes):
    case = logs_case(tmp_path)
    (plan,) = plan_runs(case, with_spec(input_list_tool(tmp_path), **changes))
    became_placeholder(monkeypatch, "NTUSER.DAT.LOG1")
    with pytest.raises(RunError, match=rf"Fake wasn't run on HOST: .*{refusal('the tool', 'HOST/NTUSER.DAT.LOG1')}"):
        run(case, plan)
    assert nothing_run(case)


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


@pytest.mark.skipif(sys.platform != "win32", reason="file attributes are Windows'")
def test_a_file_marked_offline_after_intake_is_refused_by_the_preview_and_by_a_run(tmp_path, monkeypatch):
    offline = 0x1000 | 0x20   # FILE_ATTRIBUTE_OFFLINE with FILE_ATTRIBUTE_ARCHIVE
    case = logs_case(tmp_path)
    (plan,) = [p for p in plan_runs(case, each_file_tool(tmp_path)) if p.input_file == SYSTEM_LOG]
    marked = [case.evidence / "HOST" / "app.jsonl", case.evidence / "HOST" / "Logs" / "System.evtx"]
    try:
        for path in marked:
            assert ctypes.windll.kernel32.SetFileAttributesW(str(path), offline)
        refuse_import_reads(monkeypatch)
        with pytest.raises(MappingError, match="cloud placeholder"):
            preview(case, "HOST/app.jsonl", zones={})
        with pytest.raises(RunError, match="cloud placeholder"):
            run(case, plan)
        (host_plan,) = plan_runs(case, listing_tool(tmp_path))
        with pytest.raises(RunError, match="which holds files that intake hashed before they became cloud placeholders"):
            run(case, host_plan)
        assert nothing_run(case)
    finally:
        for path in marked:
            ctypes.windll.kernel32.SetFileAttributesW(str(path), 0x20)
