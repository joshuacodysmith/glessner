import contextlib
import hashlib
import json
import os
import stat
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from conftest import flip_a_byte, junction

from glessner import case as case_module
from glessner.case import CaseError, copy_case, create_case, open_case, write_atomically
from glessner.intake import CHUNK, add_new, entry_kind, intake, read_manifest, sha256_file, verify


@pytest.fixture
def evidence(tmp_path):
    root = tmp_path / "evidence"
    (root / "Windows" / "System32" / "winevt" / "Logs").mkdir(parents=True)
    (root / "Windows" / "System32" / "winevt" / "Logs" / "Security.evtx").write_bytes(b"ElfFile\x00" + b"\x01" * 100)
    (root / "Users" / "bob").mkdir(parents=True)
    (root / "Users" / "bob" / "NTUSER.DAT").write_bytes(b"regf" + b"\x02" * 100)
    (root / "hashes.json").write_text("{}")
    return root


def test_create_and_open_case(tmp_path, evidence):
    case = create_case(tmp_path / "case", "Test", evidence, "cody")
    assert (case.folder / "case.yaml").is_file()
    assert (case.folder / "journal.jsonl").is_file()
    assert (case.folder / "runs").is_dir()
    reopened = open_case(case.folder)
    assert reopened.settings.name == "Test"
    assert reopened.evidence == evidence.resolve()


def test_a_case_yaml_with_the_old_case_timezone_still_opens(tmp_path, evidence):
    """A new case.yaml has no case_timezone setting, and one that still holds it opens."""
    case = create_case(tmp_path / "case", "Test", evidence, "cody")
    settings = yaml.safe_load((case.folder / "case.yaml").read_text(encoding="utf-8"))
    assert "case_timezone" not in settings
    (case.folder / "case.yaml").write_text(yaml.safe_dump({**settings, "case_timezone": "UTC"}), encoding="utf-8")
    assert open_case(case.folder).settings.name == "Test"


def test_case_and_evidence_must_not_overlap(tmp_path, evidence):
    with pytest.raises(CaseError):
        create_case(evidence / "case", "Inside evidence", evidence, "cody")
    with pytest.raises(CaseError):
        create_case(tmp_path, "Contains evidence", evidence, "cody")


def test_a_tools_folder_holding_the_evidence_or_case_or_on_a_share_is_refused(tmp_path, evidence):
    """Detection runs what it finds in the tools folder, so one that holds the evidence would run a
    suspect's EvtxECmd.exe. A tools folder that holds, or sits in, the evidence or the case is refused, and so is a
    network folder. case.yaml names it, so opening a case and copying one check it too."""
    planted = evidence / "Users" / "bob" / "Downloads" / "EvtxECmd.exe"
    planted.parent.mkdir()
    planted.write_bytes(b"")   # a placeholder: nothing runs
    for tools, refusal in ((tmp_path, "tools folder and the evidence folder"),
                           (evidence / "Users", "tools folder and the evidence folder"),
                           (tmp_path / "case" / "tools", "tools folder and the case folder"),
                           (Path("\\\\server\\share\\tools"), "not a network path")):
        with pytest.raises(CaseError, match=refusal):
            create_case(tmp_path / "case", "Test", evidence, "cody", tools)
    assert not (tmp_path / "case").exists()
    (tmp_path / "tools").mkdir()
    case = create_case(tmp_path / "case", "Test", evidence, "cody", tmp_path / "tools")
    assert open_case(case.folder).settings.tools_folder == str((tmp_path / "tools").resolve())
    with pytest.raises(CaseError, match="tools folder and the case folder"):   # the copy would sit in the tools folder
        copy_case(case, tmp_path / "tools" / "copy", "Copy", "cody")
    # A case folder made elsewhere names its own tools folder: one holding the evidence stops the case opening.
    settings = yaml.safe_load((case.folder / "case.yaml").read_text(encoding="utf-8"))
    (case.folder / "case.yaml").write_text(yaml.safe_dump({**settings, "tools_folder": str(tmp_path)}), encoding="utf-8")
    with pytest.raises(CaseError, match=r"tools folder and the evidence folder .* Set tools_folder in .*case\.yaml"):
        open_case(case.folder)


@pytest.mark.skipif(os.name != "nt", reason="the \\\\?\\ spellings are Windows'")
def test_a_long_or_volume_spelling_gets_no_folder_past_the_overlap_checks(tmp_path, evidence):
    """resolve() keeps a \\\\?\\ prefix it's given, so a tools or evidence folder written as \\\\?\\D:\\... would never
    overlap one written plainly, and detection would choose a planted EvtxECmd.exe. A volume's own name,
    \\\\?\\Volume{...}\\, looks like a network path, so evidence written that way in case.yaml or on the start page
    would never be compared. Both are compared as the drive letter's path, and so are the case folder and the
    evidence."""
    def long(path):
        return Path("\\\\?\\" + str(path.resolve()))

    def volume(path):
        path = path.resolve()
        name = subprocess.run(["mountvol", path.drive, "/L"], capture_output=True, text=True, check=True).stdout
        return Path(name.strip() + str(path)[3:])

    planted = evidence / "Users" / "bob" / "Downloads" / "EvtxECmd.exe"
    planted.parent.mkdir()
    planted.write_bytes(b"")   # a placeholder: nothing runs
    inside = evidence / "Users"   # a tools folder that would run it
    for ev, tools in ((evidence, long(inside)), (long(evidence), inside)):
        with pytest.raises(CaseError, match="tools folder and the evidence folder"):
            create_case(tmp_path / "case", "Test", ev, "cody", tools)
    with pytest.raises(CaseError, match="case folder and the evidence folder"):
        create_case(evidence / "case", "Test", long(evidence), "cody")
    from glessner.start import check
    for ev, tools in ((evidence, long(inside)), (volume(evidence), inside)):
        assert "evidence folder must not" in check(str(ev), str(tmp_path / "new"), str(tools))["tools"]["message"]
    (tmp_path / "tools").mkdir()
    case = create_case(tmp_path / "case", "Test", evidence, "cody", volume(tmp_path / "tools"))   # local, not a share
    settings = yaml.safe_load((case.folder / "case.yaml").read_text(encoding="utf-8"))
    for changed in ({"tools_folder": str(long(inside))}, {"evidence_path": str(volume(evidence)),
                                                          "tools_folder": str(inside)}):
        (case.folder / "case.yaml").write_text(yaml.safe_dump({**settings, **changed}), encoding="utf-8")
        with pytest.raises(CaseError, match="tools folder and the evidence folder"):
            open_case(case.folder)


def test_intake_skips_junctions_and_reports_them(tmp_path, evidence, capsys):
    """os.walk follows directory junctions, so intake would hash files outside the evidence as the host's, and a
    junction pointing back up would repeat the folder until paths reached 260 characters. Junctions are skipped, and
    each one is listed with its target; Add new evidence does the same."""
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("the analyst's own file")
    junction(evidence / "Users" / "link", outside)                     # out of the evidence
    junction(evidence / "Users" / "bob" / "loop", evidence / "Users")   # back up: a loop
    junction(evidence / "again", evidence)                              # the evidence folder itself
    case = create_case(tmp_path / "case", "Test", evidence, "cody")
    summary = intake(case)
    assert summary.files == 3 and "secret.txt" not in case.manifest_path.read_text(encoding="utf-8")
    assert summary.links == [f"again -> {evidence}", f"Users/link -> {outside}",
                             f"Users/bob/loop -> {evidence / 'Users'}"]
    (evidence / "Users" / "new.txt").write_text("added later")
    added = add_new(case)
    assert (added.files, added.missing, added.links) == (1, [], summary.links)
    from glessner.cli import main
    assert main(["intake", str(case.folder), "--add"]) == 0
    assert capsys.readouterr().out.endswith(
        "Links skipped, not followed (3):\n" + "".join(f"  {link}\n" for link in summary.links))


def test_intake_skips_a_symbolic_link_to_a_file(tmp_path, evidence):
    """os.walk lists a symbolic link to a file among the files, and intake would hash its target. It is skipped and
    listed too."""
    outside = tmp_path / "secret.txt"
    outside.write_text("the analyst's own file")
    try:
        os.symlink(outside, evidence / "Users" / "secret.txt")
    except OSError:   # Windows needs Developer Mode or administrator rights for a symbolic link
        pytest.skip("this account can't make symbolic links")
    summary = intake(create_case(tmp_path / "case", "Test", evidence, "cody"))
    assert summary.files == 3 and summary.links == [f"Users/secret.txt -> {outside}"]


@pytest.mark.skipif(os.name != "nt", reason="file attributes are Windows'")
def test_a_folder_that_is_any_other_reparse_point_is_skipped_too():
    """Intake skips a folder that is any reparse point, not only a junction or a symbolic link. Another kind on a
    folder is mostly a cloud-sync placeholder, such as a OneDrive folder, which only a sync provider makes, so a stand-in
    for its directory entry is used. (A volume mounted in a folder is a junction, with the same reparse tag.)"""
    class Entry:
        def __init__(self, attributes):
            self.attributes = attributes

        def is_symlink(self):
            return False

        def is_junction(self):
            return False

        def is_dir(self, follow_symlinks=True):
            return True

        def stat(self, follow_symlinks=True):
            return SimpleNamespace(st_file_attributes=self.attributes)

    assert entry_kind(Entry(stat.FILE_ATTRIBUTE_DIRECTORY | stat.FILE_ATTRIBUTE_REPARSE_POINT)) == "link"
    assert entry_kind(Entry(stat.FILE_ATTRIBUTE_DIRECTORY)) == "folder"


def test_case_folder_must_be_empty(tmp_path, evidence):
    folder = tmp_path / "case"
    folder.mkdir()
    (folder / "leftover.txt").write_text("x")
    with pytest.raises(CaseError):
        create_case(folder, "Test", evidence, "cody")


def test_intake_writes_manifest_and_leaves_evidence_unchanged(tmp_path, evidence):
    before = {p: sha256_file(p) for p in evidence.rglob("*") if p.is_file()}
    case = create_case(tmp_path / "case", "Test", evidence, "cody")
    summary = intake(case)
    assert summary.files == 3
    assert summary.by_artifact == {"evtx": 1, "registry": 1, "unidentified": 1}
    assert summary.unidentified == ["hashes.json"]
    entries = {e.path: e for e in read_manifest(case)}
    security = "Windows/System32/winevt/Logs/Security.evtx"
    assert entries[security].sha256 == before[evidence / security]
    assert entries["Users/bob/NTUSER.DAT"].detail == "NTUSER"
    assert {p: sha256_file(p) for p in evidence.rglob("*") if p.is_file()} == before
    assert sorted(p.name for p in evidence.rglob("*") if p.is_file()) == ["NTUSER.DAT", "Security.evtx", "hashes.json"]


def test_second_intake_is_refused(tmp_path, evidence):
    case = create_case(tmp_path / "case", "Test", evidence, "cody")
    intake(case)
    with pytest.raises(CaseError):
        intake(case)


def test_verify_detects_changed_and_missing_files(tmp_path, evidence):
    case = create_case(tmp_path / "case", "Test", evidence, "cody")
    intake(case)
    assert verify(case, reason="clean") == []
    (evidence / "Users" / "bob" / "NTUSER.DAT").write_bytes(b"regf tampered")
    (evidence / "hashes.json").unlink()
    problems = verify(case, reason="after tampering")
    assert problems == ["hashes.json: missing", "Users/bob/NTUSER.DAT: SHA-256 changed"]
    records = [json.loads(line) for line in case.verification_path.read_text().splitlines()]
    assert [r["result"] for r in records] == ["ok", "mismatch"]


def test_a_check_after_a_last_line_without_a_line_break_starts_its_own_line(tmp_path, evidence):
    """A check's line in verification.jsonl would join a last line a hand edit left without its LF, and every read of
    the checks would fail; the upgrade checks run output, so it can hit this on its own. The check ends that line
    first, and keeps its bytes."""
    from glessner.intake import evidence_checks

    case = create_case(tmp_path / "case", "Test", evidence, "cody")
    intake(case)
    assert verify(case, reason="clean") == []
    bare = case.verification_path.read_bytes().rstrip(b"\n")
    case.verification_path.write_bytes(bare)
    (evidence / "hashes.json").unlink()
    assert verify(case, reason="manual full verification") == ["hashes.json: missing"]
    assert case.verification_path.read_bytes().startswith(bare + b"\n")
    checks = evidence_checks(case)
    assert checks["checks"] == 2 and checks["problems"] == ["hashes.json: missing"]


@contextlib.contextmanager
def held(path):
    """The file held open with share mode 0, as antivirus or another tool can hold it: no other open succeeds until it
    closes, though its directory entry still reads."""
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.CreateFileW.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD,
                                     wintypes.DWORD, wintypes.HANDLE)
    generic_read, open_existing = 0x80000000, 3
    handle = kernel32.CreateFileW(str(path), generic_read, 0, None, open_existing, 0, None)
    if handle == wintypes.HANDLE(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        yield
    finally:
        kernel32.CloseHandle(handle)


@pytest.mark.skipif(os.name != "nt", reason="share modes are Windows'")
def test_a_check_records_a_file_it_can_t_read_as_unreadable(tmp_path, evidence):
    """A file another process holds open can't be re-hashed. The check names it as unreadable and records its line, so
    the run that asked for it can finish its record."""
    from glessner.intake import check_files

    case = create_case(tmp_path / "case", "Test", evidence, "cody")
    intake(case)
    with held(evidence / "hashes.json"):
        check = check_files(case, reason="manual full verification")
    [problem] = check.problems
    assert problem.startswith("hashes.json: unreadable (") and check.checked == 3
    record = json.loads(case.verification_path.read_text(encoding="utf-8").splitlines()[-1])
    assert (record["result"], record["problems"]) == ("mismatch", [problem])
    assert verify(case, reason="manual full verification") == []


def test_lines_of_the_check_log_that_can_t_be_read_are_counted(tmp_path, evidence):
    """A crash during a check's append can leave a run of 0x00 at the end of verification.jsonl, and the next check's
    line end makes it a whole line. Such a line, or one a hand edit left that isn't a JSON object, is counted, and the
    checks around it still read."""
    from glessner.intake import evidence_checks

    case = create_case(tmp_path / "case", "Test", evidence, "cody")
    intake(case)
    assert verify(case, reason="manual full verification") == []
    with case.verification_path.open("ab") as f:
        f.write(b"\0" * 64)
    assert evidence_checks(case)["checks"] == 1   # the unended tail may be a check still writing
    (evidence / "hashes.json").unlink()
    assert verify(case, reason="after a run") == ["hashes.json: missing"]
    checks = evidence_checks(case)
    assert (checks["checks"], checks["unreadable_lines"], checks["problems"]) == (2, 1, ["hashes.json: missing"])
    with case.verification_path.open("ab") as f:
        f.write(b"[1, 2]\n{not json\n\xff\xfe\n" + b"[" * 100_000 + b"]" * 100_000 + b"\n")
    checks = evidence_checks(case)
    assert (checks["checks"], checks["unreadable_lines"], checks["newest"]["reason"]) == (2, 5, "after a run")


def test_a_full_re_hash_that_matches_clears_the_unreadable_lines_before_it(tmp_path, evidence):
    """A full re-hash that matches checked every file since any line before it that can't be read, so such a line no
    longer counts, as a problem recorded before it doesn't. One that found a problem clears nothing, and a line that
    can't be read after the full re-hash counts."""
    from glessner.intake import evidence_checks

    def unreadable_line():
        with case.verification_path.open("ab") as f:
            f.write(b"\0" * 64)
        assert verify(case, ["hashes.json"], reason="after a run") == []

    case = create_case(tmp_path / "case", "Test", evidence, "cody")
    intake(case)
    unreadable_line()
    assert evidence_checks(case)["unreadable_lines"] == 1
    (evidence / "hashes.json").write_text("changed")
    assert verify(case, reason="manual full verification") == ["hashes.json: SHA-256 changed"]
    assert evidence_checks(case)["unreadable_lines"] == 1
    (evidence / "hashes.json").write_text("{}")
    assert verify(case, reason="manual full verification") == []
    assert evidence_checks(case)["unreadable_lines"] == 0
    unreadable_line()
    assert evidence_checks(case)["unreadable_lines"] == 1


def test_verify_subset_of_paths(tmp_path, evidence):
    case = create_case(tmp_path / "case", "Test", evidence, "cody")
    intake(case)
    (evidence / "hashes.json").write_text("changed")
    assert verify(case, ["Users/bob/NTUSER.DAT"], reason="run inputs") == []
    assert verify(case, ["not/in/manifest"]) == ["not/in/manifest: not in the manifest"]


def test_add_new_evidence_appends_only_new_files(tmp_path, evidence):
    """Files copied in later are hashed and added; the first intake's lines stay as they were."""
    case = create_case(tmp_path / "case", "Test", evidence, "cody")
    intake(case)
    before = case.manifest_path.read_bytes()
    (evidence / "FIREWALL").mkdir()
    (evidence / "FIREWALL" / "traffic.csv").write_text("receive_time,src,dst\n2024/02/05 10:21:48,203.0.113.9,10.0.0.12\n")
    (evidence / "hashes.json").unlink()
    summary = add_new(case)
    assert (summary.files, summary.by_artifact, summary.missing) == (1, {"csv": 1}, ["hashes.json"])
    after = case.manifest_path.read_bytes()
    assert after.startswith(before) and b"added_utc" not in before
    added = read_manifest(case)[-1]
    assert (added.path, added.artifact, added.method) == ("FIREWALL/traffic.csv", "csv", "content")
    assert added.added_utc and added.sha256 == sha256_file(evidence / "FIREWALL" / "traffic.csv")
    assert add_new(case).files == 0 and case.manifest_path.read_bytes() == after


def test_intake_add_leaves_a_changed_listed_file_s_line_alone_and_verify_flags_it(tmp_path, evidence, capsys):
    """Adding new evidence never replaces the intake baseline: a listed file that changed keeps its original hash, whether
    its size changed or stayed, so verify still names it, and the manifest gains one line, for the new file."""
    from glessner.cli import main

    case = create_case(tmp_path / "case", "Test", evidence, "cody")
    intake(case)
    before = case.manifest_path.read_bytes()
    flip_a_byte(evidence / "Users" / "bob" / "NTUSER.DAT")
    security = evidence / "Windows" / "System32" / "winevt" / "Logs" / "Security.evtx"
    security.write_bytes(security.read_bytes() + b"\x00")
    (evidence / "FIREWALL").mkdir()
    (evidence / "FIREWALL" / "traffic.csv").write_text("receive_time,src,dst\n2024/02/05 10:21:48,203.0.113.9,10.0.0.12\n")
    assert main(["intake", str(case.folder), "--add"]) == 0
    assert "1 new file" in capsys.readouterr().out
    after = case.manifest_path.read_bytes()
    assert after.startswith(before)
    (added,) = (json.loads(line) for line in after[len(before):].decode("utf-8").splitlines())
    traffic = evidence / "FIREWALL" / "traffic.csv"
    assert added["path"] == "FIREWALL/traffic.csv" and added["sha256"] == hashlib.sha256(traffic.read_bytes()).hexdigest()
    assert main(["verify", str(case.folder)]) == 1
    output = capsys.readouterr().out
    assert ("2 problems:\n  Users/bob/NTUSER.DAT: SHA-256 changed\n"
            "  Windows/System32/winevt/Logs/Security.evtx: SHA-256 changed\n") in output
    assert "traffic.csv" not in output


def test_a_file_longer_than_one_read_is_hashed_whole(tmp_path, evidence, capsys):
    """Intake and verify hash all of a file, not only its first read (CHUNK bytes). The manifest holds the SHA-256 of the
    whole file, as hashlib gives it, and verify names a file with a byte changed after the first read, which keeps its
    size."""
    from glessner.cli import main

    big = evidence / "Windows" / "System32" / "config" / "SYSTEM"
    big.parent.mkdir(parents=True)
    data = b"regf" + bytes(range(256)) * (CHUNK // 256 + 16)
    big.write_bytes(data)
    assert len(data) > CHUNK + 4096
    case = create_case(tmp_path / "case", "Test", evidence, "cody")
    intake(case)
    (entry,) = (e for e in read_manifest(case) if e.path == "Windows/System32/config/SYSTEM")
    assert (entry.size, entry.sha256) == (len(data), hashlib.sha256(data).hexdigest())
    assert verify(case) == []

    flip_a_byte(big, at=CHUNK + 100)
    assert verify(case) == ["Windows/System32/config/SYSTEM: SHA-256 changed"]
    assert main(["verify", str(case.folder)]) == 1
    assert "1 problem:\n  Windows/System32/config/SYSTEM: SHA-256 changed\n" in capsys.readouterr().out


def test_add_new_names_a_listed_file_that_a_folder_of_its_name_replaced(tmp_path, evidence):
    """A file the manifest lists is gone once a folder of the same name takes its place; the folder's files are new."""
    case = create_case(tmp_path / "case", "Test", evidence, "cody")
    intake(case)
    (evidence / "hashes.json").unlink()
    (evidence / "hashes.json").mkdir()
    (evidence / "hashes.json" / "inner.txt").write_text("inner")
    summary = add_new(case)
    assert (summary.files, summary.missing) == (1, ["hashes.json"])
    assert verify(case, reason="manual full verification") == ["hashes.json: missing"]


def test_add_new_needs_an_intake_first(tmp_path, evidence):
    case = create_case(tmp_path / "case", "Test", evidence, "cody")
    with pytest.raises(CaseError):
        add_new(case)


def test_copy_case_starts_a_clean_round_on_the_same_runs(tmp_path, evidence):
    """A copy starts clean: the same evidence, intake, and runs; no marks, tags, or notes. A copy of a format 1 case is
    upgraded before its rebuild: format 2's step, the seal, case_created naming the source's journal, and then the 3 to
    4 entry."""
    from chain_fixtures import append_unchained, as_format

    from glessner.cli import main
    from glessner.events import connect
    from glessner.imports import run_import

    (evidence / "FW").mkdir()
    (evidence / "FW" / "log.csv").write_text("time,src\n2024-02-05T10:00:00Z,10.0.0.1\n2024-02-05T10:00:01Z,10.0.0.2\n")
    source = create_case(tmp_path / "case", "Worked", evidence, "cody")
    as_format(source.folder, 1)
    source = open_case(source.folder)   # a case made before the step
    intake(source)
    run_import(source, "FW/log.csv", {"format": "csv", "time": {"columns": ["time"], "format": "ymd"},
                                     "fields": {"source_ip": "src"}}, zones={})
    con = connect(source.db_path, read_only=True)
    uid = con.execute("SELECT event_uid FROM events LIMIT 1").fetchone()[0]
    con.close()
    append_unchained(source.folder, "mark", targets=[uid], value="malicious", note="")
    before = (source.folder / "journal.jsonl").read_bytes()
    assert main(["copy-case", str(source.folder), str(tmp_path / "blind"), "--name", "Blind round", "--analyst", "tester"]) == 0
    copy = open_case(tmp_path / "blind")
    assert (copy.settings.name, copy.settings.analyst, copy.evidence) == ("Blind round", "tester", source.evidence)
    assert copy.settings.copied_from.startswith(str(source.folder))
    rekey, seal, created, step = [json.loads(line) for line in (copy.folder / "journal.jsonl").read_bytes().splitlines()]
    assert [(e["action"], e.get("to_format")) for e in (rekey, seal, created, step)] == [
        ("case_upgrade", 2), ("case_upgrade", 3), ("case_created", None), ("case_upgrade", 4)]
    assert seal["sealed"]["lines"] == 1 and copy.settings.case_format == 4 and step["from_format"] == 3
    assert created["copied_from"]["bytes"] == len(before) and created["copied_from"]["folder"] == str(source.folder)
    assert open_case(source.folder).settings.case_format == 1
    assert (copy.folder / "manifest.jsonl").read_bytes() == (source.folder / "manifest.jsonl").read_bytes()
    con = connect(copy.db_path, read_only=True)
    assert con.execute("SELECT count(*) FROM events").fetchone()[0] == 2
    con.close()
    assert (source.folder / "journal.jsonl").read_bytes() == before
    with pytest.raises(CaseError):
        copy_case(source, tmp_path / "blind", "Again", "cody")   # not empty
    with pytest.raises(CaseError):
        copy_case(source, source.folder / "inside", "Inside", "cody")


def test_a_file_is_written_whole_or_not_at_all(tmp_path, monkeypatch):
    """write_atomically writes a temporary file beside the target, flushes it to disk, then replaces the
    target, so a stop at any point leaves the old file or the new one, never a cut-short one."""
    target = tmp_path / "settings.yaml"
    target.write_text("old", encoding="utf-8")
    calls = []
    monkeypatch.setattr(os, "fsync", lambda fd: calls.append("fsync"))
    real_replace = os.replace
    monkeypatch.setattr(os, "replace", lambda src, dst: (calls.append("replace"), real_replace(src, dst)))
    write_atomically(target, "new")
    assert target.read_text(encoding="utf-8") == "new" and calls == ["fsync", "replace"]
    assert [p.name for p in tmp_path.iterdir()] == ["settings.yaml"]

    # Windows refuses the replace while another process has the target open, as an open_case read does for a moment: it
    # is tried again for about 1 s, and then the old file stays
    refusals = []

    def refused(times):
        def replace(src, dst):
            if len(refusals) < times:
                refusals.append(dst)
                raise PermissionError(13, "in use by another process")
            return real_replace(src, dst)
        return replace

    monkeypatch.setattr(case_module, "REPLACE_WAIT", 0)
    monkeypatch.setattr(os, "replace", refused(2))
    write_atomically(target, "newer")
    assert target.read_text(encoding="utf-8") == "newer" and len(refusals) == 2
    refusals.clear()
    monkeypatch.setattr(os, "replace", refused(1000))
    with pytest.raises(PermissionError):
        write_atomically(target, "newest")
    assert len(refusals) == case_module.REPLACE_TRIES
    assert target.read_text(encoding="utf-8") == "newer" and [p.name for p in tmp_path.iterdir()] == ["settings.yaml"]


SETTINGS = b"name: Test\nanalyst: cody\ncreated_utc: '2026-10-17T00:00:00Z'\n"


@pytest.mark.parametrize("content", [b"", b"\0" * 64, b"name: [unclosed", b"- a\n- b\n", b"just text\n", b"\xff\xfe\x00bad",
                                     b"name: Test\n", b"1: x\n" + SETTINGS + b"evidence_path: E\n",
                                     SETTINGS + b"evidence_path: 5\n",
                                     SETTINGS + b"evidence_path: E\ntools_folder: [a]\n"])
def test_a_case_yaml_that_can_t_be_read_is_a_case_error_naming_the_file(tmp_path, evidence, content, capsys):
    """An empty, NUL-filled, unparseable, non-mapping, or incomplete case.yaml, such as a write cut short leaves,
    or one where a hand edit left a number as a setting's name or a number or list as its text, gives the analyst a
    sentence naming the file, from the command line and from the start page, never a traceback."""
    from glessner.cli import main
    from glessner.server import start_open

    case = create_case(tmp_path / "case", "Test", evidence, "cody")
    (case.folder / "case.yaml").write_bytes(content)
    with pytest.raises(CaseError, match=r"case.yaml"):
        open_case(case.folder)
    assert main(["runs", str(case.folder)]) == 2
    assert str(case.folder / "case.yaml") in capsys.readouterr().err
    with pytest.raises(CaseError, match=r"case.yaml"):
        start_open(None, {"folder": str(case.folder)})
