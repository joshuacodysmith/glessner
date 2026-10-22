"""A journal head record that can't be removed refuses a new case (create_case, copy_case) and leaves the disk as it found
it: the folders the call made above the case folder, which it makes before the record goes so that a path that can't be
reached keeps the record, are removed again. A folder that was there before, empty or not, and a folder that something
has put a file in since, stay."""

import errno

import pytest

from glessner import heads
from glessner.case import CaseError, copy_case, create_case

OLD_HEAD = "a" * 64

# What removing the record can fail with: Windows reports denied access, a file another process holds, and a
# write-protected volume as PermissionError, and other failures, such as a device I/O error or a dropped network
# connection, as an OSError of no subclass.
CANT_REMOVE = [pytest.param(PermissionError("access is denied"), id="PermissionError"),
               pytest.param(OSError(errno.EIO, "I/O error"), id="OSError")]


@pytest.fixture
def evidence(tmp_path):
    (tmp_path / "evidence" / "DC01").mkdir(parents=True)
    return tmp_path / "evidence"


@pytest.fixture
def source(tmp_path, evidence):
    """The case a copy is made from."""
    return create_case(tmp_path / "source", "Source", evidence, "cody")


def make_case(how, source, folder, evidence):
    """A new case in `folder`, made from scratch or as a copy of `source`."""
    if how == "create_case":
        return create_case(folder, "Again", evidence, "cody")
    return copy_case(source, folder, "Again", "cody")


def leave_record(folder):
    """The record that a case once in `folder` left, naming a line no new journal holds."""
    heads.write(folder, 9, OLD_HEAD, "old build")
    assert heads.read(folder)["head"] == OLD_HEAD


def listing(root):
    """Every folder and file under `root`, as paths relative to it."""
    return sorted(each.relative_to(root) for each in root.rglob("*"))


def refuses(error, before=None):
    """A stand-in for heads.forget that runs `before` and then fails with `error`."""
    def forget(folder):
        if before:
            before(folder)
        raise error
    return forget


@pytest.mark.parametrize("error", CANT_REMOVE)
@pytest.mark.parametrize("how", ["create_case", "copy_case"])
def test_a_refusal_removes_the_folders_it_made_above_the_case(tmp_path, evidence, source, monkeypatch, how, error):
    folder = (tmp_path / "new" / "deep" / "case").resolve()
    leave_record(folder)
    found = listing(tmp_path)
    monkeypatch.setattr(heads, "forget", refuses(error))
    with pytest.raises(CaseError, match="Can't remove the journal head record"):
        make_case(how, source, folder, evidence)
    assert listing(tmp_path) == found
    assert heads.read(folder)["head"] == OLD_HEAD


@pytest.mark.parametrize("how", ["create_case", "copy_case"])
def test_a_record_that_is_a_folder_leaves_no_folder_above_the_case(tmp_path, evidence, source, how):
    folder = (tmp_path / "new" / "deep" / "case").resolve()
    heads.path_for(folder).mkdir(parents=True)
    found = listing(tmp_path)
    with pytest.raises(CaseError, match="Can't remove the journal head record"):
        make_case(how, source, folder, evidence)
    assert listing(tmp_path) == found


@pytest.mark.parametrize("how", ["create_case", "copy_case"])
def test_a_refusal_keeps_the_folders_that_were_there(tmp_path, evidence, source, monkeypatch, how):
    (tmp_path / "kept").mkdir()
    (tmp_path / "kept" / "notes.txt").write_text("mine", encoding="utf-8")
    folder = (tmp_path / "kept" / "new" / "case").resolve()
    leave_record(folder)
    monkeypatch.setattr(heads, "forget", refuses(PermissionError("access is denied")))
    with pytest.raises(CaseError):
        make_case(how, source, folder, evidence)
    assert (tmp_path / "kept" / "notes.txt").read_text(encoding="utf-8") == "mine"
    assert not (tmp_path / "kept" / "new").exists()


@pytest.mark.parametrize("below", [("case",), ("new", "case")], ids=["parent", "ancestor"])
@pytest.mark.parametrize("how", ["create_case", "copy_case"])
def test_a_refusal_keeps_an_empty_folder_that_was_there(tmp_path, evidence, source, monkeypatch, how, below):
    """The folders the call made are removed only because it made them: an empty one the analyst made first stays."""
    (tmp_path / "kept").mkdir()
    folder = tmp_path.joinpath("kept", *below).resolve()
    leave_record(folder)
    monkeypatch.setattr(heads, "forget", refuses(PermissionError("access is denied")))
    with pytest.raises(CaseError, match="Can't remove the journal head record"):
        make_case(how, source, folder, evidence)
    assert (tmp_path / "kept").is_dir()
    assert not (tmp_path / "kept" / below[0]).exists()


@pytest.mark.parametrize("how", ["create_case", "copy_case"])
def test_a_refusal_keeps_an_empty_case_folder_that_was_there(tmp_path, evidence, source, monkeypatch, how):
    """An empty case folder is accepted for a new case, and a refusal leaves it as the analyst made it."""
    folder = (tmp_path / "case").resolve()
    folder.mkdir()
    leave_record(folder)
    monkeypatch.setattr(heads, "forget", refuses(PermissionError("access is denied")))
    with pytest.raises(CaseError, match="Can't remove the journal head record"):
        make_case(how, source, folder, evidence)
    assert folder.is_dir()
    assert not any(folder.iterdir())


@pytest.mark.parametrize("how", ["create_case", "copy_case"])
def test_a_folder_that_something_filled_meanwhile_is_left_alone(tmp_path, evidence, source, monkeypatch, how):
    """Only empty folders are removed, so a refusal never deletes a file, and it still raises its own error."""
    folder = (tmp_path / "new" / "deep" / "case").resolve()
    leave_record(folder)

    def fill(case_folder):
        (case_folder.parent / "stray.txt").write_text("not the case's", encoding="utf-8")

    monkeypatch.setattr(heads, "forget", refuses(PermissionError("access is denied"), before=fill))
    with pytest.raises(CaseError, match="Can't remove the journal head record"):
        make_case(how, source, folder, evidence)
    assert (tmp_path / "new" / "deep" / "stray.txt").read_text(encoding="utf-8") == "not the case's"
    assert not folder.exists()


@pytest.mark.parametrize("how", ["create_case", "copy_case"])
def test_a_case_in_folders_that_are_not_there_yet_makes_them(tmp_path, evidence, source, how):
    folder = (tmp_path / "new" / "deep" / "case").resolve()
    leave_record(folder)
    make_case(how, source, folder, evidence)
    assert (folder / "case.yaml").is_file()
    assert heads.read(folder)["head"] != OLD_HEAD
