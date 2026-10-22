"""The head record kept outside a case folder, for a case made where another case was: create_case and copy_case remove
the record an earlier case in the same folder path left, so the new case's journal is compared with no head but its own,
also when the new case's own record can't be written. A path that can't be reached keeps the record of the case there."""

import errno

import pytest
from chain_fixtures import as_format

from glessner import heads
from glessner.case import CaseError, copy_case, create_case, open_case
from glessner.journal import Journal

OLD_HEAD = "a" * 64


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


def refuses(error):
    """A stand-in for heads.forget that fails with `error`."""
    def forget(*args, **kwargs):
        raise error
    return forget


# What removing the record can fail with: Windows reports denied access, a file another process holds, and a
# write-protected volume as PermissionError, and other failures, such as a device I/O error, as an OSError of no subclass.
CANT_REMOVE = [pytest.param(PermissionError("access is denied"), "access is denied", id="PermissionError"),
               pytest.param(OSError(errno.EIO, "I/O error"), "I/O error", id="OSError")]


def fails_to_write(*args, **kwargs):
    raise OSError("the settings folder is read-only")


@pytest.mark.parametrize("how", ["create_case", "copy_case"])
def test_a_new_case_isnt_read_only_when_its_own_record_cant_be_written(tmp_path, evidence, source, monkeypatch, how):
    folder = (tmp_path / "again").resolve()
    leave_record(folder)
    with monkeypatch.context() as patch:
        patch.setattr(heads, "write", fails_to_write)
        case = make_case(how, source, folder, evidence)
    assert not heads.path_for(folder).exists()
    journal = Journal(case)
    journal.open_for_work()
    assert journal.read_only == "" and not journal.breaks
    assert heads.read(folder)["seq"] == 1


@pytest.mark.parametrize("older", [False, True])
def test_a_copy_of_any_format_forgets_the_record_an_earlier_case_left(tmp_path, evidence, source, older):
    """A copy of an older source has an empty journal until its upgrade seals it, so it writes no record of its own."""
    if older:
        as_format(source.folder, 2)
        source = open_case(source.folder)
    folder = (tmp_path / "again").resolve()
    leave_record(folder)
    copy_case(source, folder, "Again", "cody")
    record = heads.read(folder)
    if older:
        assert record is None
    else:
        assert record["head"] != OLD_HEAD


@pytest.mark.parametrize(("error", "text"), CANT_REMOVE)
@pytest.mark.parametrize("how", ["create_case", "copy_case"])
def test_a_record_that_cant_be_removed_refuses_the_case_before_its_folder(tmp_path, evidence, source, monkeypatch, how,
                                                                          error, text):
    folder = (tmp_path / "again").resolve()
    leave_record(folder)
    monkeypatch.setattr(heads, "forget", refuses(error))
    with pytest.raises(CaseError) as refused:
        make_case(how, source, folder, evidence)
    assert str(heads.path_for(folder)) in str(refused.value) and text in str(refused.value)
    assert not folder.exists()


@pytest.mark.parametrize("how", ["create_case", "copy_case"])
def test_a_path_that_cant_be_reached_keeps_the_record_of_the_case_there(tmp_path, evidence, source, how):
    """An absent drive or share looks like a missing folder. Making a case there fails, and the record of the case that
    is there, once the volume is back, stays."""
    (tmp_path / "away").write_text("not a folder", encoding="utf-8")
    folder = (tmp_path / "away" / "again").resolve()
    leave_record(folder)
    with pytest.raises(OSError):   # the OS's own error, as for any folder that can't be made
        make_case(how, source, folder, evidence)
    assert heads.read(folder)["head"] == OLD_HEAD


@pytest.mark.parametrize("how", ["create_case", "copy_case"])
def test_a_record_is_forgotten_when_the_folders_above_the_case_are_gone_too(tmp_path, evidence, source, how):
    """Deleting a case's parent folder with it leaves its record stale all the same."""
    folder = (tmp_path / "gone" / "again").resolve()
    leave_record(folder)
    make_case(how, source, folder, evidence)
    assert heads.read(folder)["head"] != OLD_HEAD


@pytest.mark.parametrize("how", ["create_case", "copy_case"])
def test_a_record_that_is_a_folder_refuses_the_case_naming_it(tmp_path, evidence, source, how):
    folder = (tmp_path / "again").resolve()
    heads.path_for(folder).mkdir(parents=True)
    with pytest.raises(CaseError, match="Can't remove the journal head record") as refused:
        make_case(how, source, folder, evidence)
    assert str(heads.path_for(folder)) in str(refused.value)
    assert not folder.exists()


@pytest.mark.parametrize("how", ["create_case", "copy_case"])
def test_a_folder_that_holds_a_case_keeps_its_record(tmp_path, evidence, source, how):
    """The refusal of a folder that isn't empty comes first: the record belongs to the case there."""
    folder = (tmp_path / "again").resolve()
    make_case(how, source, folder, evidence)
    record = heads.read(folder)
    assert record is not None
    with pytest.raises(CaseError, match="not empty"):
        make_case(how, source, folder, evidence)
    assert heads.read(folder) == record
