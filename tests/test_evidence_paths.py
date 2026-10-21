"""Evidence names a plain Win32 path reaches wrongly or not at all: a folder past 260 characters, a name that ends in
a dot or a space, and a file named NUL. Intake, verify, the start page's check, and the import read each one as the
file it names, and a folder that can't be opened is recorded."""

import hashlib
import os
from pathlib import Path

import pytest

from glessner import intake as intake_module
from glessner.case import create_case
from glessner.imports import sniff
from glessner.intake import add_new, check_files, intake, read_manifest, unverified_text, verify
from glessner.long_paths import long_path
from glessner.start import check

pytestmark = pytest.mark.skipif(os.name != "nt", reason="the Win32 path rules are Windows'")


def put(root: Path, rel: str, data: bytes) -> None:
    """Write a file under root through the extended-length form, which makes names a plain path can't: long ones, ones
    that end in a dot or a space, and NUL. Only the root is resolved, since resolve() drops a trailing dot."""
    path = Path("\\\\?\\" + str(root.resolve()), rel)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def shut(monkeypatch, *names: str) -> None:
    """Make every folder whose path ends in one of `names` refuse to be listed, as one whose ACL denies it."""
    real = os.scandir

    def scandir(path="."):
        if os.fspath(path).endswith(names):
            raise PermissionError(13, "Access is denied")
        return real(path)

    monkeypatch.setattr(os, "scandir", scandir)


def test_a_long_path_keeps_each_name_and_stays_under_its_root(tmp_path):
    """long_path resolves only the root, so a trailing dot or space stays, and joins the relative path as text, so no
    part of it can name a place outside the root."""
    root = Path("\\\\?\\" + str(tmp_path.resolve()))
    assert long_path(tmp_path) == root
    assert str(long_path(tmp_path, "HOST/note.txt.")) == f"{root}\\HOST\\note.txt."
    assert str(long_path(root, "HOST/dir /NUL")) == f"{root}\\HOST\\dir \\NUL"
    for rel in ("C:/Windows/win.ini", "/x", "//server/share/x"):
        assert long_path(root, rel).is_relative_to(root), rel
    share = Path("\\\\?\\UNC\\server\\share\\evidence")   # taken as it is, so no network lookup
    assert str(long_path(share, "a/b.")) == f"{share}\\a\\b."
    # A volume with no drive letter, which resolve() leaves in the device form; no volume has this GUID
    volume = "Volume{00000000-0000-0000-0000-000000000000}"
    assert str(long_path(Path(f"\\\\.\\{volume}\\"), "a/b.")) == f"\\\\?\\{volume}\\a\\b."
    put(tmp_path, "dir/x.txt", b"x")
    assert not long_path(root, "dir/../dir/x.txt").is_file() and long_path(root, "dir/x.txt").is_file()


def test_a_folder_past_260_characters_is_hashed_and_checked(tmp_path):
    """With long paths off, as Windows ships, a plain path to a folder past 260 characters can't be opened."""
    ev = tmp_path / "evidence"
    deep = "HOST/Users/x/AppData/Local/Packages/" + "/".join(["p" * 40] * 5) + "/LocalState/deep.txt"
    assert len(str(ev.resolve())) + len(deep) > 300
    put(ev, deep, b"deep data")
    put(ev, "HOST/top.txt", b"top")
    case = create_case(tmp_path / "case", "Long", ev, "cody")
    summary = intake(case)
    entries = {e.path: e for e in read_manifest(case)}
    assert summary.errors == [] and summary.files == 2
    assert entries[deep].sha256 == sha256(b"deep data") and entries[deep].size == 9
    assert verify(case, reason="manual full verification") == []
    put(ev, deep, b"changed")
    assert verify(case, reason="manual full verification") == [f"{deep}: SHA-256 changed"]


def test_names_that_end_in_a_dot_or_a_space_are_read_as_named(tmp_path):
    """A plain path drops a trailing dot or space, so note.txt. would open note.txt beside it, and dir. would list
    dir's files."""
    ev = tmp_path / "evidence"
    files = {"HOST/note.txt": b"plain", "HOST/note.txt.": b"with a dot", "HOST/note.txt ": b"with a space",
             "HOST/dir/x.txt": b"plain folder", "HOST/dir./x.txt": b"dot folder", "HOST/alone./y.txt": b"no sibling"}
    for rel, data in files.items():
        put(ev, rel, data)
    case = create_case(tmp_path / "case", "Dots", ev, "cody")
    summary = intake(case)
    assert summary.errors == []
    assert {e.path: e.sha256 for e in read_manifest(case)} == {rel: sha256(data) for rel, data in files.items()}
    assert verify(case, reason="manual full verification") == []
    put(ev, "HOST/note.txt.", b"rewritten")
    put(ev, "HOST/dir./x.txt", b"rewritten")
    assert verify(case, reason="manual full verification") == ["HOST/note.txt.: SHA-256 changed",
                                                                "HOST/dir./x.txt: SHA-256 changed"]


def test_a_file_named_nul_is_hashed_and_not_the_device(tmp_path):
    """A plain path to a file named NUL, in any folder, opens the null device, which reads as empty."""
    ev = tmp_path / "evidence"
    data = bytes(range(64))
    put(ev, "HOST/Users/x/AppData/Local/Temp/NUL", data)
    case = create_case(tmp_path / "case", "Nul", ev, "cody")
    intake(case)
    [entry] = read_manifest(case)
    assert (entry.path, entry.size, entry.sha256, entry.error) == ("HOST/Users/x/AppData/Local/Temp/NUL", 64,
                                                                    sha256(data), "")
    assert verify(case, reason="manual full verification") == []


def test_a_folder_that_can_t_be_opened_is_an_error_in_the_summary_and_the_manifest(tmp_path, monkeypatch):
    """A folder intake can't list leaves its files out of the manifest, so it is recorded as an entry with its error
    and no hash, as a file intake can't read is. Add new evidence takes the folder's files once it opens."""
    ev = tmp_path / "evidence"
    put(ev, "HOST/open.txt", b"open")
    put(ev, "HOST/shut/inner.txt", b"inner")
    real = os.scandir

    def scandir(path="."):
        if os.fspath(path).endswith("shut"):
            raise PermissionError(13, "Access is denied")
        return real(path)

    case = create_case(tmp_path / "case", "Shut", ev, "cody")
    monkeypatch.setattr(os, "scandir", scandir)
    summary = intake(case)
    assert summary.errors == ["HOST/shut: folder can't be opened, so its files aren't in the manifest: "
                              "PermissionError: [Errno 13] Access is denied"]
    entries = {e.path: e for e in read_manifest(case)}
    assert set(entries) == {"HOST/open.txt", "HOST/shut"}
    assert (entries["HOST/shut"].sha256, entries["HOST/shut"].method) == ("", "unreadable")
    check = check_files(case, reason="manual full verification")
    assert (check.problems, check.checked, check.unverified) == ([], 1, ["HOST/shut/"])
    again = add_new(case)
    assert (again.files, again.missing) == (0, [])
    monkeypatch.setattr(os, "scandir", real)
    opened = add_new(case)
    assert (opened.files, opened.missing) == (1, [])
    assert {e.path: e.sha256 for e in read_manifest(case)}["HOST/shut/inner.txt"] == sha256(b"inner")
    # Its files are in the manifest now, hashed when they were added, but none has a hash from intake
    check = check_files(case, reason="manual full verification")
    assert (check.problems, check.checked, check.unverified) == ([], 2, ["HOST/shut/"])
    assert unverified_text(check.unverified) == ("1 folder could not be listed at intake, so no check can show that "
                                                 "the files it held then are unchanged since intake: HOST/shut.")


def test_a_listed_folder_that_can_t_be_opened_later_keeps_its_files(tmp_path, monkeypatch):
    """When a folder whose files the manifest lists can't be opened, Add new evidence writes no entry for it, which
    would leave its files unverified for good, and calls none of them gone: the summary names the folder and how many
    of its files it couldn't look for. The evidence folder itself is no different."""
    ev = tmp_path / "evidence"
    put(ev, "HOST/open.txt", b"open")
    put(ev, "HOST/shut/inner.txt", b"inner")
    case = create_case(tmp_path / "case", "Shut later", ev, "cody")
    intake(case)
    before = case.manifest_path.read_bytes()
    denied = "PermissionError: [Errno 13] Access is denied"
    with monkeypatch.context() as m:
        shut(m, "shut")
        summary = add_new(case)
    assert (summary.files, summary.missing) == (0, [])
    assert summary.errors == [f"HOST/shut: folder can't be opened, so its 1 file in the manifest can't be looked for: "
                              f"{denied}"]
    with monkeypatch.context() as m:
        shut(m, "evidence")
        summary = add_new(case)
    assert (summary.files, summary.missing) == (0, [])
    assert summary.errors == [f".: folder can't be opened, so its 2 files in the manifest can't be looked for: {denied}"]
    assert case.manifest_path.read_bytes() == before
    check = check_files(case, reason="manual full verification")
    assert (check.problems, check.checked, check.unverified) == ([], 2, [])


def test_a_folder_intake_couldn_t_list_is_named_as_a_folder_and_counted_as_no_file(tmp_path, monkeypatch):
    """How many files a folder intake couldn't list holds is unknown, so the intake summary counts none for it, and a
    full check's outputs name it as a folder whose files intake didn't hash, apart from the files intake couldn't
    read."""
    ev = tmp_path / "evidence"
    for rel in ("HOST/open.txt", "HOST/locked.bin", "HOST/deep/a.txt", "HOST/deep/b.txt", "HOST/also/c.txt"):
        put(ev, rel, rel.encode())
    real = intake_module.sha256_file

    def sha256_file(path):   # as when another program holds the file open with no sharing
        if path.name == "locked.bin":
            raise PermissionError(13, "The process cannot access the file")
        return real(path)

    case = create_case(tmp_path / "case", "Deep", ev, "cody")
    with monkeypatch.context() as m:
        shut(m, "deep", "also")
        m.setattr(intake_module, "sha256_file", sha256_file)
        summary = intake(case)
    assert summary.files == 2
    check = check_files(case, reason="manual full verification")
    assert (check.checked, check.unverified) == (1, ["HOST/locked.bin", "HOST/also/", "HOST/deep/"])
    assert unverified_text(check.unverified) == (
        "1 evidence file could not be read at intake, so it has no hash to check and is unverified: HOST/locked.bin. "
        "2 folders could not be listed at intake, so no check can show that the files they held then are unchanged "
        "since intake: HOST/also; HOST/deep.")
    assert unverified_text(["./"]) == ("1 folder could not be listed at intake, so no check can show that the files it "
                                       "held then are unchanged since intake: the evidence folder.")


def test_the_start_page_counts_each_file_s_own_bytes(tmp_path):
    """The evidence check adds up each file's size by its extended-length path, so a file in a folder past 260
    characters counts its bytes, and note.txt. counts its own rather than note.txt's."""
    ev = tmp_path / "evidence"
    deep = "HOST/" + "/".join(["p" * 40] * 7) + "/deep.txt"
    assert len(str(ev.resolve())) + len(deep) > 300
    files = {deep: b"d" * 100, "HOST/note.txt": b"n" * 10, "HOST/note.txt.": b"t" * 200}
    for rel, data in files.items():
        put(ev, rel, data)
    out = check(str(ev))["evidence"]
    assert (out["files"], out["bytes"]) == (3, 310)


def test_the_import_reads_the_file_its_name_gives(tmp_path):
    """The import opens a text log by its manifest path, in a folder past 260 characters, with a trailing dot beside a
    plain sibling, or named NUL, and reads that file."""
    ev = tmp_path / "evidence"
    deep = "SIEM/" + "/".join(["q" * 40] * 6) + "/deep.csv"
    logs = {"SIEM/logons.csv": "time,plain\n", "SIEM/logons.csv.": "time,dotted\n", "SIEM/NUL": "time,nul\n",
            deep: "time,deep\n"}
    for rel, text in logs.items():
        put(ev, rel, (text + "2024-02-05 10:00:00Z,1\n").encode())
    case = create_case(tmp_path / "case", "Import", ev, "cody")
    intake(case)
    assert {rel: sniff(case, rel, {"format": "csv"}).columns for rel in logs} == {
        rel: text.strip().split(",") for rel, text in logs.items()}
