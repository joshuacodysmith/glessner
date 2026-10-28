"""The tools manifest: the file at the top of the tools folder that pins each tool's files, its reader, the check of a run's
files against a pin, and pinning under the manifest's lock."""

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import threading
from pathlib import Path

import pytest
from conftest import junction

from glessner import case as case_module
from glessner import tools, tools_manifest
from glessner.tools import DetectedTool, load_registry
from glessner.tools_manifest import ManifestError, Pin, check_tool, manifest_file, pin_tools, read_manifest, take_pin
from glessner.version import build_id

UTC = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write(folder: Path, files: dict[str, bytes]) -> None:
    for rel, data in files.items():
        path = folder / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)


MAPS = {"a.map": b"a\n", "b.map": b"b\n"}


def evtx(root: Path, maps: dict[str, bytes] | None = None) -> DetectedTool:
    """EvtxECmd in a tools folder: its executable, the .dll beside it, and a Maps folder."""
    folder = root / "tools" / "EZTools" / "EvtxECmd"
    write(folder, {"EvtxECmd.exe": b"MZ exe", "EvtxECmd.dll": b"MZ dll",
                   **{f"Maps/{name}": data for name, data in (MAPS if maps is None else maps).items()}})
    return DetectedTool(load_registry()["evtxecmd"], folder / "EvtxECmd.exe", "1.5.2.0")


def hayabusa(root: Path) -> DetectedTool:
    folder = root / "tools" / "hayabusa-3.6.0"
    write(folder, {"hayabusa-3.6.0-win-x64.exe": b"MZ", "config/level_tuning.txt": b"id,level\n",
                   "rules/hayabusa/a.yml": b"title: a\n", "rules/sigma/b.yml": b"title: b\n"})
    return DetectedTool(load_registry()["hayabusa"], folder / "hayabusa-3.6.0-win-x64.exe", "3.6.0")


def mft(root: Path) -> dict[str, DetectedTool]:
    """MFTECmd under both of its registry IDs, which run one executable."""
    folder = root / "tools" / "EZTools" / "MFTECmd"
    write(folder, {"MFTECmd.exe": b"MZ mft", "MFTECmd.dll": b"MZ mft dll"})
    return {i: DetectedTool(load_registry()[i], folder / "MFTECmd.exe", "1.2.2.1") for i in ("mftecmd", "mftecmd_j")}


def runnable(root: Path) -> DetectedTool:
    """A tool of the registry ID "fake" in the tools folder that runs: a batch file that writes the output a run expects,
    with a Maps folder, which its registry entry lists."""
    folder = root / "tools" / "Fake"
    write(folder, {"Fake.bat": b'@echo off\r\necho ok> "%~2\\out.txt"\r\n', "Maps/a.map": b"a\n", "Maps/b.map": b"b\n"})
    spec = tools.ToolSpec(id="fake", name="Fake", publisher="", license="", download_url="https://example.invalid",
                          executables=("Fake.bat",), version_args=(), version_regex="", handles=("evtx",),
                          input="host_dir", args=("{host_dir}", "{output_dir}"), timeout_minutes=1, outputs=("out.txt",),
                          parser=None, tool_files=("Maps",))
    return DetectedTool(spec, folder / "Fake.bat", "1.0")


def new_case(root: Path, tools_folder: Path | None = None, events: Path | None = None):
    """A case with two hosts, whose DC01 holds an event log taken in, with `tools_folder` as its tools folder and, when
    given, a copy of the events database `events`."""
    from glessner.case import create_case
    from glessner.intake import intake

    logs = root / "evidence" / "DC01" / "Windows" / "System32" / "winevt" / "Logs"
    logs.mkdir(parents=True)
    (root / "evidence" / "DESKTOP").mkdir()
    (logs / "Security.evtx").write_bytes(b"ElfFile\x00" + b"\x01" * 64)
    case = create_case(root / "case", "Pins", root / "evidence", "cody", tools_folder)
    if events is not None:
        shutil.copyfile(events, case.db_path)
    intake(case)
    return case


def tools_folder(root: Path) -> Path:
    return root / "tools"


def pinned(root: Path, *found: DetectedTool) -> Path:
    return pin_tools(tools_folder(root), {t.spec.id: take_pin(t) for t in found})


def entries(root: Path) -> dict:
    return json.loads(manifest_file(tools_folder(root)).read_text(encoding="utf-8"))["tools"]


def checked(root: Path, tool: DetectedTool, folder: Path | None = None) -> dict:
    """The tool_check a run of the tool records now: its files as pin_files reads them, against the manifest."""
    links: list[str] = []
    listing = tools.pin_files(tool, links)
    return check_tool(tools_folder(root) if folder is None else folder, tool, listing, links)


def test_a_pin_writes_one_entry_per_tool_with_each_recorded_field(tmp_path):
    first, second = evtx(tmp_path), hayabusa(tmp_path)
    path = pinned(tmp_path, first, second)
    assert path == tools_folder(tmp_path) / "tools_manifest.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    assert list(data) == ["format", "tools"] and data["format"] == 1 and sorted(data["tools"]) == ["evtxecmd", "hayabusa"]
    entry = data["tools"]["evtxecmd"]
    assert sorted(entry) == ["executable", "files", "folders", "links", "pinned_by", "pinned_utc", "rules", "version"]
    assert entry["executable"] == "EZTools/EvtxECmd/EvtxECmd.exe"
    assert entry["files"] == {"EvtxECmd.dll": sha(b"MZ dll"), "EvtxECmd.exe": sha(b"MZ exe"),
                              "Maps/": tools.listing_sha256({n: sha(d) for n, d in MAPS.items()})}
    assert entry["folders"] == {"Maps/": {n: sha(d) for n, d in MAPS.items()}}
    assert entry["links"] == [] and entry["pinned_by"] == build_id() and entry["version"] == "1.5.2.0"
    assert entry["rules"] == "Maps, 2 maps" and UTC.fullmatch(entry["pinned_utc"])
    text = path.read_text(encoding="utf-8")
    assert text == json.dumps(data, indent=2, sort_keys=True) + "\n"   # sorted keys, so two versions compare line by line


def test_pinning_one_tool_leaves_the_other_entries_as_they_were(tmp_path):
    pinned(tmp_path, evtx(tmp_path))
    before = entries(tmp_path)["evtxecmd"]
    pinned(tmp_path, hayabusa(tmp_path))
    now = entries(tmp_path)
    assert sorted(now) == ["evtxecmd", "hayabusa"] and now["evtxecmd"] == before
    (tools_folder(tmp_path) / "EZTools" / "EvtxECmd" / "Maps" / "c.map").write_bytes(b"c\n")
    pinned(tmp_path, evtx(tmp_path))   # pinned again: its entry changes, the other's does not
    again = entries(tmp_path)
    assert again["hayabusa"] == now["hayabusa"] and "c.map" in again["evtxecmd"]["folders"]["Maps/"]


def test_the_ids_that_share_an_executable_are_pinned_together(tmp_path):
    shared, other = mft(tmp_path), evtx(tmp_path)
    found = {**shared, "evtxecmd": other}
    assert tools_manifest.pin_group(found, ["mftecmd_j"]) == ["mftecmd", "mftecmd_j"]
    assert tools_manifest.pin_group(found, ["mftecmd"]) == ["mftecmd", "mftecmd_j"]
    assert tools_manifest.pin_group(found, ["evtxecmd", "mftecmd"]) == ["evtxecmd", "mftecmd", "mftecmd_j"]
    registry = load_registry()
    assert tools_manifest.pinnable(tools_folder(tmp_path), registry, found, ["mftecmd"]) == ["mftecmd", "mftecmd_j"]


def test_a_bare_pin_takes_the_tools_with_no_pin_and_leaves_one_whose_files_differ(tmp_path):
    """A tool that has a pin, whether its files match it or differ, isn't taken again: that takes a name."""
    found = {"evtxecmd": evtx(tmp_path), "hayabusa": hayabusa(tmp_path), **mft(tmp_path)}
    folder = tools_folder(tmp_path)
    assert tools_manifest.unpinned(folder, found) == ["evtxecmd", "hayabusa", "mftecmd", "mftecmd_j"]
    pinned(tmp_path, found["evtxecmd"], found["hayabusa"])
    (folder / "hayabusa-3.6.0" / "rules" / "sigma" / "b.yml").write_bytes(b"title: changed\n")
    assert checked(tmp_path, found["hayabusa"])["result"] == "differs"
    assert tools_manifest.unpinned(folder, found) == ["mftecmd", "mftecmd_j"]


def test_a_bare_pin_leaves_out_a_tool_outside_the_tools_folder_and_a_builtin_one(tmp_path):
    found = {"evtxecmd": evtx(tmp_path),
             "pecmd": DetectedTool(load_registry()["pecmd"], tmp_path / "elsewhere" / "PECmd.exe", "1"),
             "event_xml": tools.detect([load_registry()["event_xml"]], None)["event_xml"]}
    assert tools_manifest.unpinned(tools_folder(tmp_path), found) == ["evtxecmd"]


def test_a_pin_refuses_what_cannot_be_pinned_and_names_why(tmp_path):
    registry, found = load_registry(), {"evtxecmd": evtx(tmp_path)}
    found["pecmd"] = DetectedTool(registry["pecmd"], tmp_path / "elsewhere" / "PECmd.exe", "1")
    found["event_xml"] = tools.detect([registry["event_xml"]], None)["event_xml"]
    folder = tools_folder(tmp_path)

    def refused(names, where=folder):
        with pytest.raises(ValueError) as error:
            tools_manifest.pinnable(where, registry, found, names)
        return str(error.value)

    assert "No tool 'nope' in the registry" in refused(["nope"])
    assert "Windows event XML is built in" in refused(["event_xml"])
    assert "Hayabusa isn't installed" in refused(["hayabusa"])
    outside = refused(["pecmd"])
    assert "PECmd runs from" in outside and "outside the tools folder" in outside and "Move it into the tools folder" in outside
    assert "needs a tools folder" in refused(["evtxecmd"], None)
    assert tools_manifest.pinnable(folder, registry, found, ["evtxecmd"]) == ["evtxecmd"]
    with pytest.raises(ValueError, match="outside the tools folder"):   # the writer refuses it too
        pin_tools(folder, {"pecmd": Pin(found["pecmd"], tools.ToolListing({}, {}), ())})


def test_a_pin_refuses_an_unreadable_manifest_rather_than_replacing_it(tmp_path):
    tool = evtx(tmp_path)
    path = manifest_file(tools_folder(tmp_path))
    path.write_text("not json {", encoding="utf-8")
    before = path.read_bytes()
    with pytest.raises(ValueError) as refused:
        pin_tools(tools_folder(tmp_path), {"evtxecmd": take_pin(tool)})
    text = str(refused.value)
    assert text.startswith(f"The tools manifest at {path} can't be read: ") and text.endswith(
        "Restore it, or delete it and pin again.")
    with pytest.raises(ValueError, match="can't be read"):
        tools_manifest.unpinned(tools_folder(tmp_path), {"evtxecmd": tool})
    assert path.read_bytes() == before


def test_a_replace_that_fails_leaves_the_old_manifest_as_it_was(tmp_path, monkeypatch):
    pinned(tmp_path, evtx(tmp_path))
    path = manifest_file(tools_folder(tmp_path))
    before = path.read_bytes()

    def refuse(source, target):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(case_module, "REPLACE_WAIT", 0)
    monkeypatch.setattr(os, "replace", refuse)
    with pytest.raises(ValueError, match=r"can't be written: Permission denied"):
        pinned(tmp_path, hayabusa(tmp_path))
    assert path.read_bytes() == before
    assert sorted(p.name for p in tools_folder(tmp_path).glob("tools_manifest*")) == ["tools_manifest.json",
                                                                                      "tools_manifest.lock"]


def test_two_pins_at_once_keep_both_entries_and_a_manifest_that_reads(tmp_path, monkeypatch):
    """The first pin is paused between reading the manifest and writing it, as another window's would be by a slow disk,
    while the second runs. The second waits for the lock, and each entry is kept."""
    first, second = evtx(tmp_path), hayabusa(tmp_path)
    reading, resume, real = threading.Event(), threading.Event(), tools_manifest.read_manifest
    paused = []

    def read_then_wait(path):
        found = real(path)
        if not paused:
            paused.append(path)
            reading.set()
            assert resume.wait(20)
        return found

    monkeypatch.setattr(tools_manifest, "read_manifest", read_then_wait)
    errors = []

    def run(tool):
        try:
            pinned(tmp_path, tool)
        except Exception as exc:   # noqa: BLE001  (reported by the test thread)
            errors.append(exc)

    one = threading.Thread(target=run, args=(first,))
    one.start()
    assert reading.wait(20)
    two = threading.Thread(target=run, args=(second,))
    two.start()
    two.join(0.5)   # without the lock it finishes in this time, and the first's write then drops its entry
    resume.set()
    one.join(20)
    two.join(20)
    assert errors == []
    assert sorted(entries(tmp_path)) == ["evtxecmd", "hayabusa"]
    assert read_manifest(manifest_file(tools_folder(tmp_path))).tools.keys() == {"evtxecmd", "hayabusa"}


def test_a_pin_that_cannot_get_the_lock_in_time_says_another_window_is_pinning(tmp_path, monkeypatch):
    tool = evtx(tmp_path)
    monkeypatch.setattr(tools_manifest, "LOCK_WAIT", 0.3)
    taken = threading.Event()
    release = threading.Event()

    def hold():
        with tools_manifest.held(tools_folder(tmp_path)):
            taken.set()
            release.wait(20)

    holder = threading.Thread(target=hold)
    holder.start()
    assert taken.wait(20)
    try:
        with pytest.raises(ValueError, match=r"^Another Glessner window is pinning tools in this folder\. Try again\.$"):
            pinned(tmp_path, tool)
    finally:
        release.set()
        holder.join(20)
    assert not manifest_file(tools_folder(tmp_path)).exists()
    pinned(tmp_path, tool)   # the lock is free again


HOLDER = """
import sys
from pathlib import Path
from glessner import tools_manifest
with tools_manifest.held(Path(sys.argv[1])):
    print("held", flush=True)
    sys.stdin.readline()
"""


def test_a_pin_waits_for_the_lock_another_process_holds_and_refuses_when_it_is_not_let_go(tmp_path, monkeypatch):
    """The command line and a server, or two servers, pin one tools folder from different processes, which the module's
    lock for threads can't order: the lock on tools_manifest.lock does."""
    tool = evtx(tmp_path)
    monkeypatch.setattr(tools_manifest, "LOCK_WAIT", 0.5)
    holder = subprocess.Popen([sys.executable, "-c", HOLDER, str(tools_folder(tmp_path))], stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, text=True)
    try:
        assert holder.stdout.readline().strip() == "held"
        with pytest.raises(ValueError, match=re.escape(tools_manifest.BUSY)):
            pinned(tmp_path, tool)
        assert not manifest_file(tools_folder(tmp_path)).exists()
    finally:
        holder.stdin.close()   # the holder's readline ends, and it lets go
        holder.wait(30)
    pinned(tmp_path, tool)   # the lock is free again
    assert sorted(entries(tmp_path)) == ["evtxecmd"]


def test_a_pin_into_a_folder_that_cannot_be_written_says_so_naming_the_manifest(tmp_path):
    tool = evtx(tmp_path)
    (tools_folder(tmp_path) / tools_manifest.LOCK_FILE).mkdir()   # a lock file that can't be opened for writing
    path = manifest_file(tools_folder(tmp_path))
    with pytest.raises(ValueError) as refused:
        pinned(tmp_path, tool)
    assert str(refused.value).startswith(f"The tools manifest at {path} can't be written: ")
    assert "a tools folder this account can write to" in str(refused.value)
    assert not path.exists()


@pytest.mark.parametrize("change", ["drop", "clear"])
def test_a_hash_taken_while_the_cache_was_dropped_or_cleared_is_not_kept(tmp_path, monkeypatch, change):
    """A job that ends, or a scan that begins, while a tool's files are hashed outside the cache's lock: the hash is
    returned to its caller, and a later page doesn't read it as current."""
    tool = evtx(tmp_path)
    cache = tools_manifest.PinCache()
    real = tools_manifest._take

    def take_then_change(found):
        taken = real(found)
        if change == "drop":
            cache.drop(["evtxecmd"])
        else:
            cache.clear()
        return taken

    monkeypatch.setattr(tools_manifest, "_take", take_then_change)
    assert cache.get(tool).error == "" and len(cache) == 0
    monkeypatch.setattr(tools_manifest, "_take", real)
    cache.get(tool)
    assert len(cache) == 1   # a hash taken with no change in between is kept


ENTRY = {"executable": "EvtxECmd.exe", "files": {"EvtxECmd.exe": "ab" * 32}, "folders": {}, "links": [],
         "pinned_by": "0.3.0+c022c45", "pinned_utc": "2026-10-27T16:40:00Z", "rules": "", "version": "1.5.2.0"}


def manifest_text(**changes) -> str:
    return json.dumps({"format": 1, "tools": {"evtxecmd": ENTRY}, **changes})


def refused_text(tmp_path, text: str) -> ManifestError:
    path = manifest_file(tools_folder(tmp_path))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(text.encode("utf-8"))
    with pytest.raises(ManifestError) as refused:
        read_manifest(path)
    assert refused.value.sha256 == sha(text.encode("utf-8"))   # the bytes were read, so their hash is known
    return refused.value


def test_the_reader_refuses_text_that_is_not_json_naming_it(tmp_path):
    assert "isn't JSON" in str(refused_text(tmp_path, "tools: {"))
    assert "isn't JSON" in str(refused_text(tmp_path, ""))
    assert "isn't a JSON object" in str(refused_text(tmp_path, "[1, 2]"))


def test_the_reader_and_the_check_refuse_text_nested_too_deeply_to_parse_without_raising(tmp_path):
    """json.loads raises RecursionError, which isn't a ValueError, for arrays nested past the interpreter's limit."""
    text = "[" * 200_000 + "]" * 200_000
    assert "nested too deeply" in str(refused_text(tmp_path, text))
    tool = evtx(tmp_path)
    check = checked(tmp_path, tool)
    assert check["result"] == "unreadable" and check["manifest_sha256"] == sha(text.encode("utf-8"))
    assert "nested too deeply" in check["reason"]


def test_the_reader_refuses_a_format_it_does_not_know_naming_it(tmp_path):
    assert "format is 2, which this build doesn't read" in str(refused_text(tmp_path, manifest_text(format=2)))
    assert "format is '1'" in str(refused_text(tmp_path, manifest_text(format="1")))
    assert "format is True, which this build doesn't read" in str(refused_text(tmp_path, manifest_text(format=True)))
    assert "format is 1.0, which this build doesn't read" in str(refused_text(tmp_path, manifest_text(format=1.0)))
    text = json.dumps({"tools": {}})
    assert "has no format" in str(refused_text(tmp_path, text))


def test_the_reader_refuses_a_key_it_does_not_know_naming_it(tmp_path):
    assert "a key it doesn't know: 'extra'" in str(refused_text(tmp_path, manifest_text(extra=1)))
    entry = {**ENTRY, "signer": "ZimTech LLC"}
    text = json.dumps({"format": 1, "tools": {"evtxecmd": entry}})
    assert "evtxecmd has a key it doesn't know: 'signer'" in str(refused_text(tmp_path, text))
    lacking = {k: v for k, v in ENTRY.items() if k != "files"}
    text = json.dumps({"format": 1, "tools": {"evtxecmd": lacking}})
    assert "evtxecmd has no 'files'" in str(refused_text(tmp_path, text))


@pytest.mark.parametrize("value", ["AB" * 32, "ab" * 31 + "a", "ab" * 33, "xy" * 32, "", None, 7, ("ab" * 32) + "\n"])
def test_the_reader_refuses_a_hash_that_is_not_64_lowercase_hex_digits_naming_it(tmp_path, value):
    for where in ("files", "folders"):
        entry = {**ENTRY, "files": {"Maps/": "ab" * 32, "EvtxECmd.exe": "ab" * 32}, "folders": {"Maps/": {"a.map": "ab" * 32}}}
        if where == "files":
            entry["files"] = {**entry["files"], "EvtxECmd.exe": value}
            name = "EvtxECmd.exe"
        else:
            entry["folders"] = {"Maps/": {"a.map": value}}
            name = "a.map"
        text = json.dumps({"format": 1, "tools": {"evtxecmd": entry}})
        message = str(refused_text(tmp_path, text))
        assert f"hash for {name!r} in evtxecmd isn't 64 lowercase hex digits" in message


def test_the_reader_refuses_an_entry_of_the_wrong_shape_naming_it(tmp_path):
    for field, value in (("files", ["a"]), ("folders", {"Maps/": ["a"]}), ("links", "none"), ("version", 3),
                         ("pinned_utc", None), ("links", [3])):
        text = json.dumps({"format": 1, "tools": {"evtxecmd": {**ENTRY, field: value}}})
        assert f"evtxecmd's {field}" in str(refused_text(tmp_path, text)), field
    assert "'tools'" in str(refused_text(tmp_path, json.dumps({"format": 1, "tools": []})))


def test_the_reader_reads_what_a_pin_wrote_and_none_when_there_is_no_file(tmp_path):
    assert read_manifest(manifest_file(tools_folder(tmp_path))) is None
    path = pinned(tmp_path, evtx(tmp_path))
    read = read_manifest(path)
    assert read.path == path and read.sha256 == sha(path.read_bytes())
    assert read.tools == json.loads(path.read_text(encoding="utf-8"))["tools"]


def test_the_check_says_matches_for_files_equal_to_the_pin(tmp_path):
    tool = evtx(tmp_path)
    path = pinned(tmp_path, tool)
    check = checked(tmp_path, tool)
    entry = entries(tmp_path)["evtxecmd"]
    assert check == {"result": "matches", "manifest_sha256": sha(path.read_bytes()), "pinned_utc": entry["pinned_utc"],
                     "pinned_version": "1.5.2.0", "pinned_by": build_id()}


def test_the_check_names_a_changed_executable_an_added_dll_and_a_removed_file(tmp_path):
    tool = evtx(tmp_path)
    pinned(tmp_path, tool)
    folder = tool.executable.parent
    old = sha(b"MZ exe")
    tool.executable.write_bytes(b"MZ exe, replaced")
    (folder / "Added.dll").write_bytes(b"MZ new")
    (folder / "EvtxECmd.dll").unlink()
    check = checked(tmp_path, tool)
    assert check["result"] == "differs" and "more" not in check
    assert check["files"] == [
        {"path": "Added.dll", "state": "added", "now": sha(b"MZ new")},
        {"path": "EvtxECmd.dll", "state": "missing", "pinned": sha(b"MZ dll")},
        {"path": "EvtxECmd.exe", "state": "changed", "pinned": old, "now": sha(b"MZ exe, replaced")}]
    assert {"pinned_utc", "pinned_version", "pinned_by", "manifest_sha256"} <= set(check)


def test_the_check_names_each_changed_removed_and_added_map_inside_a_folder(tmp_path):
    """A differing folder is compared through its listing, so the files inside it are named, not the folder."""
    tool = evtx(tmp_path)
    pinned(tmp_path, tool)
    maps = tool.executable.parent / "Maps"
    (maps / "a.map").write_bytes(b"a, edited\n")
    (maps / "b.map").unlink()
    (maps / "c.map").write_bytes(b"c\n")
    check = checked(tmp_path, tool)
    assert check["result"] == "differs"
    assert check["files"] == [
        {"path": "Maps/a.map", "state": "changed", "pinned": sha(b"a\n"), "now": sha(b"a, edited\n")},
        {"path": "Maps/b.map", "state": "missing", "pinned": sha(b"b\n")},
        {"path": "Maps/c.map", "state": "added", "now": sha(b"c\n")}]


def test_the_check_names_a_pinned_folder_that_is_gone_and_one_the_pin_lacks(tmp_path):
    tool = evtx(tmp_path)
    pinned(tmp_path, tool)
    maps = tool.executable.parent / "Maps"
    for item in maps.iterdir():
        item.unlink()
    maps.rmdir()
    check = checked(tmp_path, tool)
    assert check["files"] == [{"path": "Maps/", "state": "missing", "pinned": tools.listing_sha256(
        {n: sha(d) for n, d in MAPS.items()})}]
    # a tool pinned without Maps that now has one
    lean = evtx(tmp_path / "second", {})
    pinned(tmp_path / "second", lean)
    write(lean.executable.parent / "Maps", {"x.map": b"x\n"})
    found = checked(tmp_path / "second", lean)
    assert found["files"] == [{"path": "Maps/", "state": "added", "now": tools.listing_sha256({"x.map": sha(b"x\n")})}]


def test_the_check_names_an_added_link_and_a_retargeted_one(tmp_path):
    tool = evtx(tmp_path)
    pinned(tmp_path, tool)
    maps = tool.executable.parent / "Maps"
    write(tmp_path / "one", {"x.map": b"x\n"})
    write(tmp_path / "two", {"y.map": b"y\n"})
    junction(maps / "linked", tmp_path / "one")
    added = checked(tmp_path, tool)
    assert added["result"] == "differs"
    assert added["files"] == [{"path": "Maps/linked", "state": "added", "now": str(tmp_path / "one"), "link": True}]
    pinned(tmp_path, tool)   # pinned with the link
    assert checked(tmp_path, tool)["result"] == "matches"
    assert entries(tmp_path)["evtxecmd"]["links"] == [f"Maps/linked -> {tmp_path / 'one'}"]
    os.rmdir(maps / "linked")
    junction(maps / "linked", tmp_path / "two")
    moved = checked(tmp_path, tool)
    assert moved["files"] == [{"path": "Maps/linked", "state": "changed", "pinned": str(tmp_path / "one"),
                               "now": str(tmp_path / "two"), "link": True}]
    os.rmdir(maps / "linked")
    assert checked(tmp_path, tool)["files"] == [{"path": "Maps/linked", "state": "missing", "pinned": str(tmp_path / "one"),
                                                 "link": True}]


def test_the_check_names_at_most_20_paths_and_counts_the_rest(tmp_path):
    tool = evtx(tmp_path, {f"m{n:02d}.map": b"m\n" for n in range(25)})
    pinned(tmp_path, tool)
    for n in range(25):
        (tool.executable.parent / "Maps" / f"m{n:02d}.map").write_bytes(b"edited\n")
    check = checked(tmp_path, tool)
    assert check["result"] == "differs" and check["more"] == 5
    assert [f["path"] for f in check["files"]] == [f"Maps/m{n:02d}.map" for n in range(20)]


def test_the_check_says_not_pinned_for_a_tool_the_manifest_lacks_and_why_for_one_outside_the_folder(tmp_path):
    tool, other = evtx(tmp_path), hayabusa(tmp_path)
    path = pinned(tmp_path, other)
    digest = sha(path.read_bytes())
    assert checked(tmp_path, tool) == {"result": "not pinned", "manifest_sha256": digest}
    outside = DetectedTool(tool.spec, tmp_path / "elsewhere" / "EvtxECmd.exe", "1")
    write(tmp_path / "elsewhere", {"EvtxECmd.exe": b"MZ"})
    assert checked(tmp_path, outside) == {"result": "not pinned", "manifest_sha256": digest,
                                          "reason": "the tool runs from outside the tools folder"}


def test_the_check_pins_by_tool_id_wherever_the_executable_is(tmp_path):
    """A tool run from outside the folder that the manifest does have an entry for is compared with it: the files are
    named relative to the executable's own folder."""
    tool = evtx(tmp_path)
    pinned(tmp_path, tool)
    copy = tmp_path / "elsewhere"
    write(copy, {"EvtxECmd.exe": b"MZ exe", "EvtxECmd.dll": b"MZ dll", **{f"Maps/{n}": d for n, d in MAPS.items()}})
    outside = DetectedTool(tool.spec, copy / "EvtxECmd.exe", "1.5.2.0")
    assert checked(tmp_path, outside)["result"] == "matches"


def test_the_check_says_no_manifest_for_no_file_and_for_no_tools_folder(tmp_path):
    tool = evtx(tmp_path)
    assert checked(tmp_path, tool) == {"result": "no manifest", "reason": "the tools folder has no tools_manifest.json"}
    links: list[str] = []
    none = check_tool(None, tool, tools.pin_files(tool, links), links)
    assert none == {"result": "no manifest", "reason": "no tools folder is set"}


def test_the_check_says_unreadable_with_the_manifest_s_hash_when_it_was_read_and_without_when_it_was_not(tmp_path):
    tool = evtx(tmp_path)
    path = manifest_file(tools_folder(tmp_path))
    path.write_text("not json {", encoding="utf-8")
    refused = checked(tmp_path, tool)
    assert refused["result"] == "unreadable" and refused["manifest_sha256"] == sha(path.read_bytes())
    assert "isn't JSON" in refused["reason"]
    path.unlink()
    path.mkdir()   # a folder in the manifest's place can't be opened as a file
    unopened = checked(tmp_path, tool)
    assert unopened["result"] == "unreadable" and "manifest_sha256" not in unopened
    assert unopened["reason"].startswith(f"{path} can't be opened: ")


def test_the_check_never_raises(tmp_path, monkeypatch):
    tool = evtx(tmp_path)
    pinned(tmp_path, tool)

    def fail(path):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(tools_manifest, "read_manifest", fail)
    assert checked(tmp_path, tool)["result"] == "unreadable"


def test_a_summary_of_the_differences_counts_each_state_by_folder(tmp_path):
    tool = evtx(tmp_path)
    pinned(tmp_path, tool)
    maps = tool.executable.parent / "Maps"
    (maps / "a.map").write_bytes(b"edited\n")
    (maps / "b.map").unlink()
    (maps / "c.map").write_bytes(b"c\n")
    tool.executable.write_bytes(b"MZ changed")
    check = checked(tmp_path, tool)
    assert tools_manifest.summary(check["files"]) == "EvtxECmd.exe changed; 1 changed, 1 missing, and 1 added in Maps/"
    assert tools_manifest.summary(check["files"][1:3]) == "1 changed and 1 missing in Maps/"
    assert tools_manifest.summary(check["files"][1:2], 2) == "1 changed in Maps/; 2 more not listed"


GOOD_FILES = [{"path": "Maps/a.map", "state": "changed", "pinned": "ab" * 32, "now": "cd" * 32}]


@pytest.mark.parametrize(("check", "text"), [
    (None, "tool check not recorded"),
    ({"result": "matches"}, "tool check matches"),
    ({}, "tool check unknown"),
    ({"result": "quarantined"}, "tool check quarantined"),   # a word this build doesn't know is shown as written
    ({"result": "differs"}, "tool check differs"),
    ({"result": "differs", "files": []}, "tool check differs"),
    ({"result": "differs", "files": GOOD_FILES}, "tool check differs, 1 changed in Maps/"),
    ({"result": "differs", "files": GOOD_FILES, "more": 2}, "tool check differs, 1 changed in Maps/; 2 more not listed"),
])
def test_the_check_text_gives_the_result_and_for_differs_the_paths(check, text):
    assert tools_manifest.check_text(check) == text


@pytest.mark.parametrize(("files", "more"), [
    ([1], 0),
    ("abc", 0),
    ({"path": "Maps/a.map", "state": "changed"}, 0),
    ([{"path": "Maps/a.map"}], 0),
    ([{"state": "changed"}], 0),
    ([{"path": 3, "state": "changed"}], 0),
    ([{"path": "Maps/a.map", "state": ["changed"]}], 0),
    ([{"path": "Maps/a.map", "state": "quarantined"}], 0),
    ([*GOOD_FILES, "Maps/b.map"], 0),
    (GOOD_FILES, "x"),
    (GOOD_FILES, None),
    (GOOD_FILES, [1]),
])
def test_the_check_text_shows_the_result_alone_for_files_not_shaped_as_a_check_is_written(files, more):
    """A run.json that another build wrote, or someone edited, can hold a differs check whose files or more aren't what
    check_tool makes. The Tools page shows the result and draws the rest."""
    assert tools_manifest.check_text({"result": "differs", "files": files, "more": more}) == "tool check differs"
