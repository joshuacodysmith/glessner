r"""Browse on the start page opens folders on this computer only. With no path it lists the local drives and leaves a
mapped network drive alone. A network folder, whether typed as a UNC path, as a device or NT-prefix path to a share, as a
path on a mapped drive, or reached through a home folder on a share, is refused before any call can reach the share. So is
a path that passes through a symbolic link or a junction, since Windows follows a link on a local drive to a share and a
junction can lead to such a link; a folder's listing leaves out both. A device or
NT-prefix path to this computer, such as \\?\C:\Windows or \\.\PhysicalDrive0, is refused too, in words of its own."""

import contextlib
import os
import pathlib
import stat
import sys
from types import SimpleNamespace

import pytest
from conftest import junction

from glessner import start
from glessner.start import browse

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Browse's drive and network handling is Windows-only")

FIXED, REMOTE = 3, 4  # GetDriveTypeW's DRIVE_FIXED and DRIVE_REMOTE
NETWORK_MESSAGE = "Browse doesn't open network folders. Type the folder's path instead."
DEVICE_MESSAGE = "Browse doesn't open device paths. Type the folder's path instead."
LINK_MESSAGE = "Browse doesn't open folders through a link. Type the folder's path instead."
NETWORK_REFUSED = {"folders": [], "parent": None, "message": NETWORK_MESSAGE}
DEVICE_REFUSED = {"folders": [], "parent": None, "message": DEVICE_MESSAGE}
LINK_REFUSED = {"folders": [], "parent": None, "message": LINK_MESSAGE}
GUID = "{12345678-1234-1234-1234-123456789abc}"   # a volume's name in a volume GUID path


@contextlib.contextmanager
def filesystem_calls(monkeypatch, links=()):
    """Record each Path.is_dir, os.path.isdir, os.lstat, and os.scandir call made inside the block. The recorded calls
    never reach the real filesystem: is_dir and isdir answer False, lstat answers the attributes of a reparse point for
    a path named in `links` and those of an ordinary folder for any other, and scandir lists nothing."""
    touched = []

    def lstat(path):
        touched.append(("lstat", str(path)))
        return SimpleNamespace(st_file_attributes=stat.FILE_ATTRIBUTE_REPARSE_POINT if str(path) in links else 0)

    with monkeypatch.context() as patch:
        patch.setattr(pathlib.Path, "is_dir", lambda self, **kwargs: touched.append(("is_dir", str(self))) or False)
        patch.setattr(os.path, "isdir", lambda path: touched.append(("isdir", str(path))) or False)
        patch.setattr(os, "lstat", lstat)
        patch.setattr(os, "scandir", lambda path=".": touched.append(("scandir", str(path))) or iter(()))
        yield touched


def drive_z_is_remote(monkeypatch):
    """C: is a fixed drive and Z: a mapped network drive. Any other drive raises KeyError when it is asked about."""
    types = {"C:\\": FIXED, "Z:\\": REMOTE}
    monkeypatch.setattr(start, "_drive_letters", lambda: ["C", "Z"])
    monkeypatch.setattr(start, "_drive_type", lambda root: types[root])


@pytest.fixture
def linked_folder(tmp_path):
    """A folder that holds `real`, which holds `inner`, and `link`, a symbolic link to `real`."""
    (tmp_path / "real" / "inner").mkdir(parents=True)
    try:
        (tmp_path / "link").symlink_to(tmp_path / "real", target_is_directory=True)
    except OSError:
        pytest.skip("this account can't create symbolic links")
    return tmp_path


def test_with_no_path_browse_lists_local_drives_and_never_probes_a_network_drive(monkeypatch):
    drive_z_is_remote(monkeypatch)
    probed = []
    monkeypatch.setattr(os.path, "isdir", lambda path: probed.append(path) or True)
    assert browse("") == {"path": "", "parent": None, "folders": ["C:\\"], "message": ""}
    assert probed == ["C:\\"]


def test_drives_with_no_root_folder_are_left_out(monkeypatch):
    types = {"C:\\": FIXED, "D:\\": start.DRIVE_NO_ROOT_DIR, "E:\\": FIXED}
    monkeypatch.setattr(start, "_drive_letters", lambda: ["C", "D", "E"])
    monkeypatch.setattr(start, "_drive_type", lambda root: types[root])
    monkeypatch.setattr(os.path, "isdir", lambda path: path != "E:\\")  # E: is a local drive with no medium
    assert browse("")["folders"] == ["C:\\"]


@pytest.mark.parametrize(
    "typed",
    [
        r"\\server\share",
        r"\\server\share\folder",
        "//server/share",
        r"\/server\share",
        r"\\?\UNC\server\share",
        r"\\.\UNC\server\share",
        r"\\.\unc\server\share",
        r"\??\UNC\server\share",
        "/??/UNC/server/share",
        r"\\?\GLOBALROOT\Device\Mup\server\share",
        r"\\.\GLOBALROOT\Device\Mup\server\share",
        r"\??\GLOBALROOT\Device\Mup\server\share",
        r"\\?\globalroot\device\mup\server\share",
        r"\\?\Global\UNC\server\share",
        r"\\.\Global\UNC\server\share",
        r"\??\Global\GLOBALROOT\Device\Mup\server\share",
        r"\\.\global\unc\server\share",
        r"\\?\Global\Global\UNC\server\share",
        r"\\.\Global\GlobalRoot\Device\Mup\server\share",
    ],
)
def test_a_unc_or_device_path_to_a_share_is_refused_without_opening_it(monkeypatch, typed):
    drive_z_is_remote(monkeypatch)
    with filesystem_calls(monkeypatch) as touched:
        out = browse(typed)
    assert out == {"path": str(pathlib.Path(typed)), **NETWORK_REFUSED}
    assert touched == []


@pytest.mark.parametrize(
    "typed",
    [
        r"\\?\C:\Windows",
        r"\??\C:\Windows",
        r"\\.\C:\Windows",
        r"\\?\c:\Windows",
        "//?/C:/Windows",
        "/??/C:/Windows",
        "//./PhysicalDrive0",
        "//?/Volume" + GUID + "/",
        r"\\?\C:",
        r"\\.\PhysicalDrive0",
        r"\\?\PhysicalDrive0",
        r"\??\PhysicalDrive0",
        "//?/PhysicalDrive0",
        r"\\?\pipe\name",
        r"\\.\Volume" + GUID,
        r"\\?\Volume" + GUID + "\\Windows",
        r"\??\Volume" + GUID,
        r"\\?\VOLUME" + GUID,
        r"\\.\Global\C:\Windows",
        r"\\?\Global\C:\Windows",
        r"\??\Global\C:\Windows",
        r"\\.\Global\PhysicalDrive0",
        r"\\?\GLOBAL\PhysicalDrive0",
        r"\\?\Global\Global\C:\Windows",
        r"\\.\Global",
    ],
)
def test_a_device_path_to_this_computer_is_refused_in_words_of_its_own(monkeypatch, typed):
    drive_z_is_remote(monkeypatch)
    with filesystem_calls(monkeypatch) as touched:
        out = browse(typed)
    assert out == {"path": str(pathlib.Path(typed)), **DEVICE_REFUSED}
    assert touched == []


@pytest.mark.parametrize(
    "typed",
    [
        r"Z:\cases",
        "z:/cases",
        "Z:\\",
        "Z:cases",
        r"\??\Z:\cases",
        r"\\?\Z:\cases",
        r"\\.\Z:\cases",
        r"\\?\z:\cases",
        r"\\?\Global\Z:\cases",
        r"\\.\Global\Global\Z:\cases",
    ],
)
def test_a_path_on_a_mapped_drive_is_refused_without_opening_it(monkeypatch, typed):
    drive_z_is_remote(monkeypatch)
    with filesystem_calls(monkeypatch) as touched:
        out = browse(typed)
    assert out == {"path": str(pathlib.Path(typed)), **NETWORK_REFUSED}
    assert touched == []


@pytest.mark.parametrize("cwd", ["Z:\\work", r"\\server\share\work"])
@pytest.mark.parametrize("typed", ["cases", r"\cases"])
def test_a_path_relative_to_a_working_directory_on_a_share_is_refused(monkeypatch, cwd, typed):
    drive_z_is_remote(monkeypatch)
    with filesystem_calls(monkeypatch) as touched, monkeypatch.context() as patch:
        patch.setattr(os, "getcwd", lambda: cwd)
        out = browse(typed)
    assert out == {"path": typed, **NETWORK_REFUSED}
    assert touched == []


@pytest.mark.parametrize("text", ["//server/share", r"\/server\share", "//?/UNC/server/share", "/??/UNC/server/share"])
def test_forward_slashes_are_read_as_backslashes(text):
    assert start._network_path(text)


def test_a_device_path_to_this_computer_is_no_network_path_and_one_to_a_share_is(monkeypatch):
    drive_z_is_remote(monkeypatch)
    for local in (r"\\?\C:\Windows", r"\??\C:\Windows", r"\\.\PhysicalDrive0", r"\\?\PhysicalDrive0",
                  r"\\?\Volume" + GUID, r"\\.\Global\C:\Windows", r"\\?\Global\PhysicalDrive0"):
        assert start._device_path(local) and not start._network_path(local), local
    for remote in (r"\\?\Z:\cases", r"\\?\UNC\server\share", r"\??\GLOBALROOT\Device\Mup\server\share",
                   r"\\.\Global\UNC\server\share", r"\\?\Global\Z:\cases"):
        assert start._network_path(remote) and not start._device_path(remote), remote


def test_a_home_folder_on_a_share_is_refused_after_the_tilde_expands(monkeypatch):
    monkeypatch.setenv("USERPROFILE", r"\\server\home\cody")
    with filesystem_calls(monkeypatch) as touched:
        out = browse("~")
    assert out == {"path": r"\\server\home\cody", **NETWORK_REFUSED}
    assert touched == []


@pytest.mark.parametrize("typed", [r"C:\links\share", r"C:\links\share\folder"])
def test_the_walk_down_a_path_stops_at_the_first_link(monkeypatch, typed):
    drive_z_is_remote(monkeypatch)
    with filesystem_calls(monkeypatch, links=(r"C:\links\share",)) as touched:
        out = browse(typed)
    assert out == {"path": typed, **LINK_REFUSED}
    assert touched == [("lstat", "C:\\"), ("lstat", "C:\\links"), ("lstat", "C:\\links\\share")]


def test_a_real_link_is_refused_and_the_folder_it_points_to_is_listed(linked_folder, monkeypatch):
    assert browse(str(linked_folder / "real"))["folders"] == ["inner"]
    for typed in (linked_folder / "link", linked_folder / "link" / "inner"):
        assert browse(str(typed)) == {"path": str(typed), **LINK_REFUSED}
    monkeypatch.chdir(linked_folder)
    assert browse("link") == {"path": "link", **LINK_REFUSED}
    monkeypatch.chdir(linked_folder / "link" / "inner")
    assert browse("below") == {"path": "below", **LINK_REFUSED}


@pytest.fixture
def junction_to_a_link(linked_folder):
    """linked_folder with `junction`, a junction to `link`: a chain of two reparse points that leads to `real`."""
    junction(linked_folder / "junction", linked_folder / "link")
    return linked_folder


def test_a_junction_to_a_link_is_refused_and_the_folder_it_leads_to_is_not_listed(junction_to_a_link, monkeypatch):
    root = junction_to_a_link
    assert os.listdir(root / "junction") == ["inner"]   # the chain reaches the folder the link points to
    for typed in (root / "junction", root / "junction" / "inner"):
        assert browse(str(typed)) == {"path": str(typed), **LINK_REFUSED}
    monkeypatch.chdir(root)
    assert browse("junction") == {"path": "junction", **LINK_REFUSED}
    monkeypatch.chdir(root / "junction" / "inner")
    assert browse("below") == {"path": "below", **LINK_REFUSED}


def test_a_folder_that_holds_a_junction_and_a_link_lists_neither(junction_to_a_link):
    assert browse(str(junction_to_a_link))["folders"] == ["real"]


def test_a_junction_is_refused_and_is_not_listed_as_a_folder(tmp_path):
    (tmp_path / "real" / "inner").mkdir(parents=True)
    junction(tmp_path / "junction", tmp_path / "real")
    assert browse(str(tmp_path))["folders"] == ["real"]
    for typed in (tmp_path / "junction", tmp_path / "junction" / "inner"):
        assert browse(str(typed)) == {"path": str(typed), **LINK_REFUSED}
    assert browse(str(tmp_path / "real"))["folders"] == ["inner"]


def folder_entry(name, attributes, **kinds):
    """A directory listing's entry for a folder: not a symbolic link or a junction unless `kinds` says so, with the
    attributes the listing read for it."""
    return SimpleNamespace(
        name=name, is_symlink=lambda: kinds.get("symlink", False), is_junction=lambda: kinds.get("junction", False),
        is_dir=lambda follow_symlinks=True: not kinds.get("symlink", False),
        stat=lambda follow_symlinks=True: SimpleNamespace(st_file_attributes=attributes))


def test_a_folder_that_is_a_cloud_sync_reparse_point_is_listed(tmp_path, monkeypatch):
    """A cloud-sync folder carries the reparse attribute in a directory listing, but it stays on its own volume, and
    lstat follows it, so Browse lists it as it lists any folder, and opens it."""
    directory, reparse = stat.FILE_ATTRIBUTE_DIRECTORY, stat.FILE_ATTRIBUTE_REPARSE_POINT
    entries = [folder_entry("OneDrive", directory | reparse), folder_entry("Cases", directory),
               folder_entry("junction", directory | reparse, junction=True),
               folder_entry("link", directory | reparse, symlink=True)]
    monkeypatch.setattr(os, "scandir", lambda path: iter(entries))
    assert browse(str(tmp_path))["folders"] == ["Cases", "OneDrive"]


def test_a_local_folder_is_listed(tmp_path):
    (tmp_path / "evidence").mkdir()
    (tmp_path / "Cases").mkdir()
    (tmp_path / "notes.txt").write_text("not a folder")
    assert browse(str(tmp_path)) == {
        "path": str(tmp_path),
        "parent": str(tmp_path.parent),
        "folders": ["Cases", "evidence"],
        "message": "",
    }


def test_a_missing_local_folder_is_not_reported_as_a_network_folder(tmp_path):
    out = browse(str(tmp_path / "nope"))
    assert out["message"] == "Folder not found." and out["folders"] == []


def test_the_drive_helpers_report_this_computers_drives(tmp_path):
    root = tmp_path.drive.upper() + "\\"
    assert root[0] in start._drive_letters()
    assert start._drive_type(root) not in (start.DRIVE_NO_ROOT_DIR, start.DRIVE_REMOTE)
    assert root in start.local_drives()
    assert not start._network_path(str(tmp_path))
    assert start._network_path(r"\\server\share")
