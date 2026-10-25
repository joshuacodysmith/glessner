"""The files in a tool's own folder that a run names, which it records by SHA-256 (tools.tool_files), and the name of the
rule or map set it runs with (tools.rules_label), read from the tool's folder without running anything."""

import dataclasses
import hashlib
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from conftest import junction
from test_evidence_paths import shut

from glessner import tools
from glessner.tools import DetectedTool, detect, folder_sha256, load_registry, rules_label, tool_files

COMMIT = "fffbdd179c8c8c7554368c443f9ba2917877f108"
OTHER_COMMIT = "0123456789abcdef0123456789abcdef01234567"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write(folder: Path, files: dict[str, bytes]) -> None:
    for rel, data in files.items():
        path = folder / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)


def listing(files: dict[str, bytes], order: list[str]) -> str:
    """The SHA-256 of what sha256sum prints for `files` in `order`: a "<sha256>  <path>" line for each."""
    return sha("".join(f"{sha(files[path])}  {path}\n" for path in order).encode("utf-8"))


def spec(tool_id: str, **changes) -> tools.ToolSpec:
    return dataclasses.replace(load_registry()[tool_id], **changes)


def test_a_folder_s_hash_is_that_of_its_sha256sum_listing_in_code_point_order(tmp_path):
    """Sorted by code point, capitals come before small letters, "." before "/", and é after z: neither the order Windows
    lists a folder in nor a walk that lists a folder's files before its subfolders gives it."""
    files = {"b.txt": b"bee\n", "C.txt": b"sea\n", "a.txt": b"ay\n", "a/x.map": b"ex\n", "é.txt": b"e\n"}
    write(tmp_path / "Maps", files)
    assert folder_sha256(tmp_path / "Maps") == listing(files, ["C.txt", "a.txt", "a/x.map", "b.txt", "é.txt"])


def test_a_folder_s_hash_leaves_out_its_git_folder(tmp_path):
    rules = {"a.yml": b"title: a\n", "sub/b.yml": b"title: b\n"}
    write(tmp_path / "rules", {**rules, ".git/HEAD": b"ref: refs/heads/main\n",
                               ".git/refs/heads/main": COMMIT.encode() + b"\n"})
    assert folder_sha256(tmp_path / "rules") == listing(rules, ["a.yml", "sub/b.yml"])


def test_a_folder_s_hash_skips_a_link_in_it(tmp_path):
    rules = {"a.yml": b"title: a\n"}
    write(tmp_path / "rules", rules)
    write(tmp_path / "outside", {"c.yml": b"title: c\n"})
    junction(tmp_path / "rules" / "linked", tmp_path / "outside")
    assert folder_sha256(tmp_path / "rules") == listing(rules, ["a.yml"])


def test_a_tool_s_files_are_its_executable_its_dll_what_its_arguments_name_and_its_registry_s(tmp_path):
    """The executable and the .dll of the same name beside it, each argument that names a path in the tool's folder, or
    whose part after = does, and the registry's tool_files, in path order. A folder is recorded by its hash with a /
    after its name. The tool's folder itself, a path outside it, and one that doesn't exist are left out."""
    folder = tmp_path / "tools" / "EvtxECmd"
    maps = {"a.map": b"a\n", "b.map": b"b\n"}
    plugins = {"one.dll": b"plugin\n"}
    files = {"EvtxECmd.exe": b"MZ exe", "EvtxECmd.dll": b"MZ dll", "conf/run.yaml": b"x: 1\n",
             "conf/extra.config": b"y\n", "unused.txt": b"not read\n",
             **{f"Maps/{name}": data for name, data in maps.items()},
             **{f"Plugins/{name}": data for name, data in plugins.items()}}
    write(folder, files)
    (tmp_path / "elsewhere.txt").write_bytes(b"outside the tool's folder\n")
    tool = DetectedTool(spec("evtxecmd", tool_files=("Maps", "Gone")), folder / "EvtxECmd.exe", "1")
    argv = [str(folder / "EvtxECmd.exe"), "-c", str(folder / "conf" / "run.yaml"),
            "--set", f"extra-file={folder}\\conf\\extra.config", "--plugins", str(folder / "Plugins"),
            "-d", str(tmp_path / "elsewhere.txt"), "--missing", str(folder / "absent.txt"), "-q", "plain",
            "--cwd", str(folder)]
    files = tool_files(tool, argv)
    assert files == {
        "EvtxECmd.dll": sha(b"MZ dll"), "EvtxECmd.exe": sha(b"MZ exe"), "Maps/": listing(maps, ["a.map", "b.map"]),
        "Plugins/": listing(plugins, ["one.dll"]), "conf/extra.config": sha(b"y\n"), "conf/run.yaml": sha(b"x: 1\n")}
    assert list(files) == sorted(files)
    (folder / "EvtxECmd.dll").unlink()
    assert "EvtxECmd.dll" not in tool_files(tool, argv)


def test_a_builtin_tool_records_no_file():
    found = detect([load_registry()["event_xml"]], None)["event_xml"]
    assert tool_files(found, [sys.executable, "-m", "glessner"]) == {}


def test_a_tool_file_that_cannot_be_read_raises(tmp_path, monkeypatch):
    folder = tmp_path / "tools" / "EvtxECmd"
    write(folder, {"EvtxECmd.exe": b"MZ", "Maps/a.map": b"a\n"})
    tool = DetectedTool(spec("evtxecmd"), folder / "EvtxECmd.exe", "1")
    real = tools.file_sha256

    def refuse(name):
        def hash_file(path):
            if path.name == name:
                raise PermissionError(13, "Permission denied")
            return real(path)
        return hash_file

    for name in ("EvtxECmd.exe", "a.map"):   # a file the tool's folder holds, and one in a folder it reads
        with monkeypatch.context() as patch:
            patch.setattr(tools, "file_sha256", refuse(name))
            with pytest.raises(PermissionError):
                tool_files(tool, [str(folder / "EvtxECmd.exe")])


@pytest.mark.skipif(sys.platform != "win32", reason="the lock is msvcrt's, on Windows, which the app targets")
def test_a_tool_file_that_opens_but_cannot_be_read_raises_naming_it(tmp_path):
    """A read refused after the file opens, as a lock or antivirus refuses one, raises an error that names no file, so
    the error raised names it."""
    import msvcrt

    tool = hayabusa(tmp_path)
    locked = tool.executable.parent / "rules" / "sigma" / "b.yml"
    size = locked.stat().st_size
    with locked.open("r+b") as f:
        msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, size)
        try:
            with pytest.raises(PermissionError, match=r"sigma\\\\b\.yml"):
                tool_files(tool, [str(tool.executable)])
        finally:
            msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, size)


def test_a_folder_below_one_the_tool_reads_that_cannot_be_listed_raises_naming_it(tmp_path, monkeypatch):
    """Skipped, the folder's files would drop out of the hash unnoticed. A .git folder that can't be listed is left out,
    as .git is."""
    tool = hayabusa(tmp_path)
    rules = tool.executable.parent / "rules"
    write(rules, {".git/HEAD": b"ref: refs/heads/main\n"})
    with monkeypatch.context() as patch:
        shut(patch, ".git")
        assert folder_sha256(rules) == listing({"hayabusa/a.yml": b"title: a\n", "sigma/b.yml": b"title: b\n"},
                                               ["hayabusa/a.yml", "sigma/b.yml"])
    shut(monkeypatch, "sigma")
    with pytest.raises(OSError, match=r"rules\\sigma can't be listed: PermissionError"):
        folder_sha256(rules)
    with pytest.raises(OSError, match=r"rules\\sigma can't be listed"):
        tool_files(tool, [str(tool.executable)])


def test_a_link_in_a_folder_the_tool_reads_is_left_out_of_its_hash_and_named(tmp_path):
    """The tool may read through the link, so the run names it. One in .git, which the hash leaves out, isn't named."""
    tool = hayabusa(tmp_path)
    rules = tool.executable.parent / "rules"
    write(tmp_path / "shared", {"c.yml": b"title: c\n"})
    hashed = folder_sha256(rules)
    junction(rules / "shared", tmp_path / "shared")
    write(rules, {".git/HEAD": b"ref: refs/heads/main\n"})
    junction(rules / ".git" / "linked", tmp_path / "shared")
    links = []
    assert tool_files(tool, [str(tool.executable)], links)["rules/"] == hashed
    assert links == [f"rules/shared -> {tmp_path / 'shared'}"]
    inside = []
    assert folder_sha256(rules, inside) == hashed and inside == [f"shared -> {tmp_path / 'shared'}"]


def hayabusa(tmp_path) -> DetectedTool:
    """Hayabusa unpacked in a tools folder, with a rules folder and its config folder."""
    folder = tmp_path / "tools" / "hayabusa-4.1.0"
    write(folder, {"hayabusa-4.1.0-win-x64.exe": b"MZ", "config/level_tuning.txt": b"id,level\n",
                   "rules/hayabusa/a.yml": b"title: a\n", "rules/sigma/b.yml": b"title: b\n"})
    return DetectedTool(load_registry()["hayabusa"], folder / "hayabusa-4.1.0-win-x64.exe", "4.1.0")


def test_a_rules_checkout_is_named_by_its_commit_read_from_its_git_files(tmp_path, monkeypatch):
    """HEAD names a branch, whose commit is in its own file or in packed-refs, or HEAD holds the commit itself. Nothing is
    run: a checkout's git config can run commands. A HEAD that holds no commit, or names a branch git refuses, gives the
    rules folder's hash instead, though the file the name would lead to holds a commit. git refuses a part that is .. or
    starts with a dot, a backslash, a colon, which on Windows reads a file's stream, and an empty part; for each rule,
    one name here breaks that rule alone. The commit is followed by the first 8 digits of the folder's hash."""
    tool = hayabusa(tmp_path)
    git = tool.executable.parent / "rules" / ".git"
    write(git, {"HEAD": b"ref: refs/heads/main\n", "refs/heads/main": COMMIT.encode() + b"\n"})
    files = folder_sha256(git.parent)[:8]

    def refuse(*args, **kwargs):
        raise AssertionError(f"ran {args}")

    monkeypatch.setattr(subprocess, "run", refuse)
    monkeypatch.setattr(subprocess, "Popen", refuse)
    assert rules_label(tool.spec, tool.executable) == f"Hayabusa rules fffbdd1, files {files}"
    (git / "refs" / "heads" / "main").unlink()
    (git / "packed-refs").write_text(f"# pack-refs with: peeled fully-peeled sorted \n{OTHER_COMMIT} refs/heads/dev\n"
                                     f"{COMMIT} refs/heads/main\n", encoding="utf-8")
    assert rules_label(tool.spec, tool.executable) == f"Hayabusa rules fffbdd1, files {files}"
    (git / "HEAD").write_text(OTHER_COMMIT + "\n", encoding="utf-8")   # a detached HEAD
    assert rules_label(tool.spec, tool.executable) == f"Hayabusa rules 0123456, files {files}"
    (tool.executable.parent / "outside").write_text(COMMIT + "\n", encoding="utf-8")
    for name in ("main", "main:x"):   # on NTFS, main:x is the stream x of the file main
        (git / "refs" / "heads" / name).write_text(COMMIT + "\n", encoding="utf-8")
    hashed = f"Hayabusa rules {folder_sha256(git.parent)[:8]}"
    for head in ("not a commit", "ref: ../../outside", "ref: refs/../../../outside", "ref: refs/..\\..\\..\\outside",
                 "ref: refs/heads\\..\\..\\..\\..\\outside", "ref: refs/heads/./main", "ref: refs/heads/main:x",
                 "ref: refs//heads/main"):
        (git / "HEAD").write_text(head + "\n", encoding="utf-8")
        assert rules_label(tool.spec, tool.executable) == hashed, head


def test_a_rules_folder_without_git_such_as_a_release_zip_s_is_named_by_its_hash(tmp_path):
    """The release zip unpacks a rules folder with no .git. Its label is the first 8 hex digits of the folder's hash, as
    the run's tool_files records it; given a run's own hashes, it takes the rules folder's from them."""
    tool = hayabusa(tmp_path)
    rules = tool.executable.parent / "rules"
    assert rules_label(tool.spec, tool.executable) == f"Hayabusa rules {folder_sha256(rules)[:8]}"
    assert rules_label(tool.spec, tool.executable, {"rules/": "ab" * 32}) == "Hayabusa rules abababab"
    write(rules, {".git/HEAD": b"ref: refs/heads/main\n"})   # a checkout whose branch names no commit
    assert rules_label(tool.spec, tool.executable) == f"Hayabusa rules {folder_sha256(rules)[:8]}"
    shutil.rmtree(rules)
    assert rules_label(tool.spec, tool.executable) == ""


def checkout(tmp_path) -> DetectedTool:
    """Hayabusa with its rules folder a git checkout at COMMIT, and the rules/config files analysts edit."""
    tool = hayabusa(tmp_path)
    rules = tool.executable.parent / "rules"
    write(rules, {"config/exclude_rules.txt": b"# excluded rules\n", ".git/HEAD": b"ref: refs/heads/main\n",
                  ".git/refs/heads/main": COMMIT.encode() + b"\n", ".git/index": b"index as of the commit"})
    return tool


def test_a_rules_checkout_names_the_hash_of_its_files_beside_its_commit(tmp_path):
    """The label's second part is the first 8 digits of the rules folder's hash, which a run's tool_files records; given
    the run's hashes, the label takes the folder's from them."""
    tool = checkout(tmp_path)
    rules = tool.executable.parent / "rules"
    label = rules_label(tool.spec, tool.executable)
    assert label == f"Hayabusa rules fffbdd1, files {folder_sha256(rules)[:8]}"
    assert rules_label(tool.spec, tool.executable, {"rules/": "ab" * 32}) == "Hayabusa rules fffbdd1, files abababab"
    assert rules_label(tool.spec, tool.executable, tool_files(tool, [str(tool.executable)])) == label


def test_editing_a_file_in_a_rules_checkout_changes_its_label(tmp_path):
    """The checkout keeps its commit, so the label's commit stays, and its files part follows the files: an edit to a
    rule or a config file, a file added, and one removed each change it, and putting the file back restores it."""
    tool = checkout(tmp_path)
    rules = tool.executable.parent / "rules"
    exclude, added, removed = rules / "config" / "exclude_rules.txt", rules / "hayabusa" / "new.yml", rules / "hayabusa" / "a.yml"
    label = lambda: rules_label(tool.spec, tool.executable)
    original = label()
    seen = {original}
    for change in (lambda: exclude.write_bytes(b"# excluded rules\n# one more\n"),
                   lambda: added.write_bytes(b"title: new\n"),
                   removed.unlink):
        change()
        now = label()
        assert now.startswith("Hayabusa rules fffbdd1, files ") and now not in seen
        seen.add(now)
    exclude.write_bytes(b"# excluded rules\n")
    added.unlink()
    removed.write_bytes(b"title: a\n")
    assert label() == original


def test_a_rules_checkout_s_label_ignores_git_s_own_files_and_what_git_status_would_show(tmp_path):
    """A release install of the rules is a checkout with files git status shows deleted, such as its README.md and
    .github folder, and an index that lists them. The label reads the commit and the files that are there, so it names
    the same files before and after anything changes in .git."""
    tool = checkout(tmp_path)
    rules = tool.executable.parent / "rules"
    original = rules_label(tool.spec, tool.executable)
    write(rules, {".git/index": b"an index that lists README.md, CHANGELOG.md, and .github/workflows/ci.yml",
                  ".git/config": b"[core]\n", ".git/logs/HEAD": b"a reflog line\n"})
    assert rules_label(tool.spec, tool.executable) == original


def test_the_eric_zimmerman_tools_are_named_by_their_maps_count_and_their_batch_file_s_version(tmp_path):
    evtx, sqle, recmd = (tmp_path / name for name in ("EvtxECmd", "SQLECmd", "RECmd"))
    write(evtx, {"EvtxECmd.exe": b"MZ", "Maps/a.map": b"a", "Maps/b.map": b"b", "Maps/c.MAP": b"c",
                 "Maps/readme.txt": b"not a map", "Maps/old/d.map": b"in a folder below",
                 "Maps/folder.map/e.txt": b"a folder whose name fits"})
    write(sqle, {"SQLECmd.exe": b"MZ", "Maps/a.smap": b"a", "Maps/b.smap": b"b", "Maps/c.map": b"not SQLECmd's"})
    write(recmd, {"RECmd.exe": b"MZ", "BatchExamples/DFIRBatch.reb":
                  b"Description: DFIR RECmd Batch File\nAuthor: someone\nVersion: 2.22\nId: 77ae78db\nKeys:\n"})
    assert rules_label(spec("evtxecmd"), evtx / "EvtxECmd.exe") == "Maps, 3 maps"
    assert rules_label(spec("sqlecmd"), sqle / "SQLECmd.exe") == "Maps, 2 maps"
    assert rules_label(spec("recmd"), recmd / "RECmd.exe") == "DFIRBatch.reb 2.22"
    (recmd / "BatchExamples" / "DFIRBatch.reb").write_bytes(b"Description: no version\nKeys:\n")
    assert rules_label(spec("recmd"), recmd / "RECmd.exe") == ""
    assert rules_label(spec("evtxecmd"), tmp_path / "Elsewhere" / "EvtxECmd.exe") == ""   # no Maps folder
    assert rules_label(spec("recmd"), tmp_path / "Elsewhere" / "RECmd.exe") == ""


def test_suricata_is_named_by_its_rule_set_s_version_file(tmp_path):
    folder = tmp_path / "Suricata"
    write(folder, {"suricata.exe": b"MZ", "rules/suricata.rules": b"alert ip any any -> any any (sid:1;)\n",
                   "rules/et-open-version.txt": b"ET Open 11310\n"})
    assert rules_label(spec("suricata"), folder / "suricata.exe") == "ET Open 11310"
    (folder / "rules" / "suricata.rules").unlink()
    assert rules_label(spec("suricata"), folder / "suricata.exe") == ""


def test_detection_names_each_tool_s_set(tmp_path):
    tool = hayabusa(tmp_path)
    write(tool.executable.parent / "rules" / ".git", {"HEAD": b"ref: refs/heads/main\n",
                                                      "refs/heads/main": COMMIT.encode() + b"\n"})
    files = folder_sha256(tool.executable.parent / "rules")[:8]
    assert detect([tool.spec], tmp_path / "tools")["hayabusa"].rules == f"Hayabusa rules fffbdd1, files {files}"
