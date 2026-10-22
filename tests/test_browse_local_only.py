"""Browse on the start page opens folders on this computer only. With no path it lists the local drives and leaves a
mapped network drive alone. A network folder, whether typed as a UNC path, as a device or NT-prefix path, as a path on a
mapped drive, or reached through a home folder on a share, is refused before any call can reach the share. So is a path
that passes through a symbolic link, since Windows follows a link on a local drive to a share."""

import contextlib
import os
import pathlib
import sys

import pytest

from glessner import start
from glessner.start import browse

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Browse's drive and network handling is Windows-only")

FIXED, REMOTE = 3, 4  # GetDriveTypeW's DRIVE_FIXED and DRIVE_REMOTE
NETWORK_MESSAGE = "Browse doesn't open network folders. Type the folder's path instead."
LINK_MESSAGE = "Browse doesn't open folders through a link. Type the folder's path instead."
NETWORK_REFUSED = {"folders": [], "parent": None, "message": NETWORK_MESSAGE}
LINK_REFUSED = {"folders": [], "parent": None, "message": LINK_MESSAGE}


@contextlib.contextmanager
def filesystem_calls(monkeypatch, links=()):
    """Record each Path.is_dir, os.path.isdir, os.path.islink, and os.scandir call made inside the block. The recorded
    calls never reach the real filesystem: is_dir and isdir answer False, islink answers True for a path named in
    `links` and False for any other, and scandir lists nothing."""
    touched = []
    with monkeypatch.context() as patch:
        patch.setattr(pathlib.Path, "is_dir", lambda self, **kwargs: touched.append(("is_dir", str(self))) or False)
        patch.setattr(os.path, "isdir", lambda path: touched.append(("isdir", str(path))) or False)
        patch.setattr(os.path, "islink", lambda path: touched.append(("islink", str(path))) or str(path) in links)
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
        r"\\?\C:\Windows",
        r"\??\UNC\server\share",
        "/??/UNC/server/share",
        r"\??\GLOBALROOT\Device\Mup\server\share",
        r"\??\C:\Windows",
    ],
)
def test_a_unc_or_device_path_is_refused_without_opening_it(monkeypatch, typed):
    with filesystem_calls(monkeypatch) as touched:
        out = browse(typed)
    assert out == {"path": str(pathlib.Path(typed)), **NETWORK_REFUSED}
    assert touched == []


@pytest.mark.parametrize("typed", [r"Z:\cases", "z:/cases", "Z:\\", "Z:cases", r"\??\Z:\cases"])
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
    assert touched == [("islink", "C:\\"), ("islink", "C:\\links"), ("islink", "C:\\links\\share")]


def test_a_real_link_is_refused_and_the_folder_it_points_to_is_listed(linked_folder, monkeypatch):
    assert browse(str(linked_folder / "real"))["folders"] == ["inner"]
    for typed in (linked_folder / "link", linked_folder / "link" / "inner"):
        assert browse(str(typed)) == {"path": str(typed), **LINK_REFUSED}
    monkeypatch.chdir(linked_folder)
    assert browse("link") == {"path": "link", **LINK_REFUSED}
    monkeypatch.chdir(linked_folder / "link" / "inner")
    assert browse("below") == {"path": "below", **LINK_REFUSED}


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
