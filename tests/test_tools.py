import dataclasses
import os
import re
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from glessner import tools
from glessner.runner import RunError
from glessner.tools import REGISTRY_DIR, DetectedTool, detect, find_dotnet, load_registry, recommend, tool_env


def test_registry_loads_all_tools():
    specs = load_registry()
    assert set(specs) == {"evtxecmd", "hayabusa", "mftecmd", "recmd", "pecmd", "lecmd",
                          "sbecmd", "amcacheparser", "jlecmd", "srumecmd", "rbcmd", "event_xml",
                          "suricata", "mftecmd_j", "sqlecmd", "wxtcmd"}
    assert "-l" not in specs["sbecmd"].args   # never the live registry
    assert specs["amcacheparser"].handles == ("registry:AMCACHE",) and specs["rbcmd"].input == "host_dir"
    assert specs["rbcmd"].dotnet == 10 and "administrator" in specs["rbcmd"].empty_result
    assert {s.id: s.dotnet for s in specs.values() if s.dotnet} == {"amcacheparser": 10, "rbcmd": 10, "sqlecmd": 10, "wxtcmd": 10}
    assert specs["mftecmd"].input == "each_file"
    assert specs["recmd"].handles == ("registry", "registry_log")
    assert "-b" in specs["hayabusa"].args and "verbose" in specs["hayabusa"].args
    assert [s.id for s in specs.values() if s.builtin] == ["event_xml"]
    for spec in specs.values():
        assert spec.download_url.startswith("https://") or spec.builtin
        assert spec.outputs


def test_detect_in_tools_folder_and_tolerate_failed_version_check(tmp_path):
    (tmp_path / "EZ" / "EvtxECmd").mkdir(parents=True)
    (tmp_path / "EZ" / "EvtxECmd" / "EvtxECmd.exe").write_bytes(b"not a real program")
    (tmp_path / "hayabusa-9.9.9").mkdir()
    (tmp_path / "hayabusa-9.9.9" / "hayabusa-9.9.9-win-x64.exe").write_bytes(b"not a real program")
    specs = load_registry()
    found = detect([specs["evtxecmd"], specs["hayabusa"], specs["lecmd"]], tmp_path)
    assert set(found) == {"evtxecmd", "hayabusa"}
    assert found["hayabusa"].executable.name == "hayabusa-9.9.9-win-x64.exe"
    assert found["evtxecmd"].version == "unknown"


def fake_runtime(folder, version):
    (folder / "shared" / "Microsoft.NETCore.App" / version).mkdir(parents=True)
    (folder / "dotnet.exe").write_bytes(b"x")


def test_private_dotnet_runtime_is_found_in_the_tools_folder(tmp_path):
    fake_runtime(tmp_path / "dotnet-8", "8.0.11")
    assert find_dotnet(tmp_path, 10) is None
    fake_runtime(tmp_path / "dotnet-10", "10.0.13")
    assert find_dotnet(tmp_path, 10) == tmp_path / "dotnet-10" and find_dotnet(tmp_path, 8) == tmp_path / "dotnet-8"
    assert find_dotnet(tmp_path / "absent", 10) is None

    (tmp_path / "EZ" / "RBCmd").mkdir(parents=True)
    (tmp_path / "EZ" / "RBCmd" / "RBCmd.exe").write_bytes(b"not a real program")
    specs = load_registry()
    found = detect([specs["rbcmd"]], tmp_path)
    assert found["rbcmd"].dotnet_root == str(tmp_path / "dotnet-10")
    env = tool_env(found["rbcmd"])
    assert env["DOTNET_ROOT"] == env["DOTNET_ROOT_X64"] == str(tmp_path / "dotnet-10") and env["PATH"] == os.environ["PATH"]
    assert tool_env(DetectedTool(specs["evtxecmd"], tmp_path / "EvtxECmd.exe", "1")) is None   # inherits as before


EZ_DOWNLOADS = "https://download.ericzimmermanstools.com"
DOTNET_10_BUILDS = {"amcacheparser", "rbcmd", "sqlecmd", "wxtcmd"}


def ez_specs():
    return {s.id: s for s in load_registry().values() if s.publisher == "Eric Zimmerman"}


def test_each_ez_tool_downloads_from_the_folder_of_its_build():
    """Eric Zimmerman's site keeps the .NET 10 builds under /net/ and the .NET Framework 4 builds at its root. $J is read
    by MFTECmd's own zip."""
    specs = ez_specs()
    assert set(specs) == DOTNET_10_BUILDS | {"evtxecmd", "jlecmd", "lecmd", "mftecmd", "mftecmd_j", "pecmd", "recmd", "sbecmd",
                                             "srumecmd"}
    for tool_id, spec in specs.items():
        zip_name = Path(spec.executables[0]).stem + ".zip"
        folder = "/net" if tool_id in DOTNET_10_BUILDS else ""
        assert spec.download_url == f"{EZ_DOWNLOADS}{folder}/{zip_name}", tool_id
        assert bool(spec.dotnet) == (tool_id in DOTNET_10_BUILDS), tool_id


def test_the_four_dotnet_10_builds_run_on_a_dotnet_10_runtime_and_the_others_on_none(tmp_path):
    """A .NET 9 runtime doesn't serve them."""
    for spec in ez_specs().values():
        folder = tmp_path / "EZTools" / Path(spec.executables[0]).stem
        folder.mkdir(parents=True, exist_ok=True)
        (folder / spec.executables[0]).write_bytes(b"not a real program")
    fake_runtime(tmp_path / "dotnet-9", "9.0.21")
    without = detect(ez_specs().values(), tmp_path)
    assert {i: t.dotnet_root for i, t in without.items()} == dict.fromkeys(ez_specs(), "")
    fake_runtime(tmp_path / "dotnet-10", "10.0.13")
    with_runtime = detect(ez_specs().values(), tmp_path)
    expected = {i: str(tmp_path / "dotnet-10") if i in DOTNET_10_BUILDS else "" for i in ez_specs()}
    assert {i: t.dotnet_root for i, t in with_runtime.items()} == expected
    assert {i for i, t in with_runtime.items() if tool_env(t) is None} == set(ez_specs()) - DOTNET_10_BUILDS


def install_ez_tools(tools_folder):
    """A stand-in executable for each of Eric Zimmerman's tools, which prints nothing when it starts."""
    for spec in ez_specs().values():
        folder = tools_folder / "EZTools" / Path(spec.executables[0]).stem
        folder.mkdir(parents=True, exist_ok=True)
        (folder / spec.executables[0]).write_bytes(b"not a real program")


NEEDS_DOTNET_10 = "Needs a .NET 10 runtime: unpack Microsoft's .NET 10 runtime zip into a folder in the tools folder"
HOST_STOP_CODE = 0x80008096   # the .NET host's exit code for a framework it can't find, as Windows reports it
HOST_STOP_TEXT = ("You must install or update .NET to run this application.\n\nApp: C:\\Tools\\EZTools\\RBCmd\\RBCmd.exe\n"
                  "Architecture: x64\nFramework: 'Microsoft.NETCore.App', version '10.0.0' (x64)\n")


def version_checks_end(monkeypatch, code=0, stdout="", stderr="", error=None):
    """Make every version check of a tool end as given instead of starting the tool: with the process's exit code and
    output, or by raising `error`, such as a timeout."""
    def run(argv, **kwargs):
        if error:
            raise error
        return subprocess.CompletedProcess(argv, code, stdout, stderr)
    monkeypatch.setattr(tools, "subprocess", SimpleNamespace(run=run, TimeoutExpired=subprocess.TimeoutExpired))


def test_a_dotnet_10_build_that_cannot_start_for_want_of_its_runtime_is_marked_unable_to_run(tmp_path, monkeypatch):
    """A tools folder that holds only a .NET 9 runtime starts none of the four .NET 10 builds: the .NET host stops each
    with its own message. Each is marked with the runtime it needs, which is the reason a run is refused with and the
    reason the Tools page shows for a tool the case has evidence for. The .NET Framework builds are not marked, and a
    .NET 10 runtime in the folder clears the mark."""
    install_ez_tools(tmp_path)
    fake_runtime(tmp_path / "dotnet-9", "9.0.21")
    version_checks_end(monkeypatch, code=HOST_STOP_CODE, stderr=HOST_STOP_TEXT)
    found = detect(ez_specs().values(), tmp_path)
    assert {i: t.missing for i, t in found.items()} == {i: NEEDS_DOTNET_10 if i in DOTNET_10_BUILDS else "" for i in ez_specs()}
    fake_runtime(tmp_path / "dotnet-10", "10.0.13")
    assert {t.missing for t in detect(ez_specs().values(), tmp_path).values()} == {""}


@pytest.mark.parametrize("code,text", [
    (HOST_STOP_CODE, ""),                         # the exit code alone
    (HOST_STOP_CODE - 2**32, ""),                 # the same code read as a signed number
    (0x80008083, ""),                             # the host's library missing, as with no .NET installed at all
    (1, HOST_STOP_TEXT),                          # the message alone
    (1, "You must install .NET to run this application.\n"),
])
def test_the_dotnet_hosts_own_stop_marks_a_build_that_has_no_private_runtime(tmp_path, monkeypatch, code, text):
    install_ez_tools(tmp_path)
    version_checks_end(monkeypatch, code=code, stderr=text)
    found = detect(ez_specs().values(), tmp_path)
    assert {found[i].missing for i in DOTNET_10_BUILDS} == {NEEDS_DOTNET_10}


@pytest.mark.parametrize("ending", [
    {"error": subprocess.TimeoutExpired(["RBCmd.exe"], 20)},     # slow under load, or held by antivirus
    {"error": PermissionError("blocked by antivirus")},
    {"code": 1, "stderr": "Unhandled exception. System.IO.IOException: The disk is full."},
    {"code": 0x80008100},                                        # past the host's own codes
    {"code": 0x80007FFF},
    {"code": 0},                                                 # exits quietly with no version
])
def test_a_version_check_the_dotnet_host_did_not_stop_leaves_a_build_unmarked(tmp_path, monkeypatch, ending):
    """A build with no private runtime reads unknown for many reasons, such as a timeout. The mark names a missing runtime
    only when the .NET host itself said so, since a run is refused on the mark."""
    install_ez_tools(tmp_path)
    version_checks_end(monkeypatch, **ending)
    found = detect(ez_specs().values(), tmp_path)
    assert {t.version for t in found.values()} == {"unknown"}
    assert {t.missing for t in found.values()} == {""}


def test_a_dotnet_build_that_prints_its_version_without_a_private_runtime_is_not_marked(tmp_path, monkeypatch):
    """A machine-wide .NET 10 runtime serves a .NET 10 build, and a build for the .NET Framework needs none, so a version
    printed is proof the tool starts."""
    install_ez_tools(tmp_path)
    version_checks_end(monkeypatch, stdout="2026.10.1+5677ea8a6e38\r\n")
    found = detect(ez_specs().values(), tmp_path)
    assert {t.missing for t in found.values()} == {""} and {t.version for t in found.values()} == {"2026.10.1"}
    assert {i: t.dotnet_root for i, t in found.items() if i in DOTNET_10_BUILDS} == dict.fromkeys(DOTNET_10_BUILDS, "")


def test_the_mark_names_the_major_version_the_tool_needs(tmp_path, monkeypatch):
    (tmp_path / "RBCmd").mkdir()
    (tmp_path / "RBCmd" / "RBCmd.exe").write_bytes(b"not a real program")
    needs_11 = dataclasses.replace(load_registry()["rbcmd"], dotnet=11)
    fake_runtime(tmp_path / "dotnet-10", "10.0.13")
    version_checks_end(monkeypatch, code=HOST_STOP_CODE, stderr=HOST_STOP_TEXT)
    assert detect([needs_11], tmp_path)["rbcmd"].missing == (
        "Needs a .NET 11 runtime: unpack Microsoft's .NET 11 runtime zip into a folder in the tools folder")


def test_the_tools_command_names_the_runtime_a_tool_lacks(tmp_path, monkeypatch, capsys):
    from glessner.case import create_case
    from glessner.cli import main

    (tmp_path / "evidence").mkdir()
    install_ez_tools(tmp_path / "tools")
    fake_runtime(tmp_path / "tools" / "dotnet-9", "9.0.21")
    version_checks_end(monkeypatch, code=HOST_STOP_CODE, stderr=HOST_STOP_TEXT)
    case = create_case(tmp_path / "case", "Test", tmp_path / "evidence", "cody", tmp_path / "tools")
    assert main(["tools", str(case.folder)]) == 0
    lines = {line.split()[0]: line for line in capsys.readouterr().out.splitlines() if line.startswith("  ")}
    assert f"Can't run here: {NEEDS_DOTNET_10}" in lines["RBCmd"]
    assert "Can't run here" not in lines["EvtxECmd"]


def runtime_less_case(tmp_path, monkeypatch, recycle_bin=True, with_output=False):
    """A case whose tools folder holds RBCmd with only a .NET 9 runtime, so the .NET host stops it. With `recycle_bin`,
    DC01 holds a Recycle Bin $I file, which RBCmd reads. With `with_output`, WS01 holds a SBECmd CSV, which loads
    without a tool."""
    from test_tool_outputs import SBE_COLUMNS, write_rows

    from glessner.case import create_case
    from glessner.intake import intake

    evidence = tmp_path / "evidence"
    evidence.mkdir()
    if recycle_bin:
        bin_folder = evidence / "DC01" / "$Recycle.Bin" / "S-1-5-21-22-500"
        bin_folder.mkdir(parents=True)
        (bin_folder / "$IU2L112.txt").write_bytes(b"\x01" + b"\x00" * 7 + b"\x1c" + b"\x00" * 100)
    if with_output:
        write_rows(evidence / "WS01" / "Modules" / "FileFolderAccess" / "alice_UsrClass.csv", SBE_COLUMNS, [
            {"BagPath": "BagMRU\\0", "Slot": "1", "AbsolutePath": "Desktop\\This PC\\C:\\Tools", "ShellType": "Directory",
             "FirstInteracted": "2024-05-14 12:06:00"}])
    tools_folder = tmp_path / "tools"
    (tools_folder / "RBCmd").mkdir(parents=True)
    (tools_folder / "RBCmd" / "RBCmd.exe").write_bytes(b"not a real program")
    fake_runtime(tools_folder / "dotnet-9", "9.0.21")
    version_checks_end(monkeypatch, code=HOST_STOP_CODE, stderr=HOST_STOP_TEXT)
    case = create_case(tmp_path / "case", "Test", evidence, "cody", tools_folder)
    intake(case)
    return case


LEFT_OUT_RBCMD = f"Left out: RBCmd can't run here: {NEEDS_DOTNET_10}."


def test_run_all_names_the_tool_it_leaves_out_for_want_of_its_runtime_and_exits_1(tmp_path, monkeypatch, capsys):
    """RBCmd, which the .NET host stops, is left out of the run: the command names it and exits 1, rather than saying
    every tool has run."""
    from glessner.cli import main

    case = runtime_less_case(tmp_path, monkeypatch)
    assert main(["run", str(case.folder), "--all"]) == 1
    out = capsys.readouterr().out
    assert out.splitlines() == [LEFT_OUT_RBCMD]


def test_run_all_loads_what_is_ready_before_it_exits_1_for_the_tool_it_left_out(tmp_path, monkeypatch, capsys):
    from glessner.cli import main

    case = runtime_less_case(tmp_path, monkeypatch, with_output=True)
    assert main(["run", str(case.folder), "--all"]) == 1
    out = capsys.readouterr().out
    assert LEFT_OUT_RBCMD in out.splitlines()
    assert "SBECmd CSV on WS01 (1 file) ...\n  ok: 1 row in " in out


def test_run_all_names_no_tool_that_has_no_evidence_here(tmp_path, monkeypatch, capsys):
    from glessner.cli import main

    case = runtime_less_case(tmp_path, monkeypatch, recycle_bin=False, with_output=True)
    assert main(["run", str(case.folder), "--all"]) == 0
    out = capsys.readouterr().out
    assert "Left out" not in out and "SBECmd CSV on WS01 (1 file) ...\n  ok: 1 row in " in out


def test_the_everything_ready_job_names_the_tool_it_leaves_out_when_nothing_else_is_ready(tmp_path, monkeypatch):
    from glessner.toolbox import start_all_job

    case = runtime_less_case(tmp_path, monkeypatch)
    specs = load_registry()
    with pytest.raises(RunError) as error:
        start_all_job(case, specs, detect(specs.values(), Path(case.settings.tools_folder)), lambda job: None)
    assert str(error.value) == f"Nothing is ready: RBCmd can't run here: {NEEDS_DOTNET_10}."


@pytest.mark.parametrize("printed,version", [
    ("2026.5.0+bfc7f47\r\n", "2026.5.0"),
    ("2026.10.2+f750a40f11b72c922428eff80e866c800631544d\r\n", "2026.10.2"),
    ("2026.10.6\r\n", "2026.10.6"),
])
def test_every_ez_tool_reads_the_version_of_a_2026_5_and_a_2026_10_build(printed, version):
    for tool_id, spec in ez_specs().items():
        assert re.search(spec.version_regex, printed, re.MULTILINE).group(1) == version, tool_id


def test_recommend_only_missing_tools_for_present_artifacts(tmp_path):
    specs = load_registry()
    (tmp_path / "EvtxECmd.exe").write_bytes(b"x")
    found = detect(specs.values(), tmp_path)
    recs = {r.spec.id: r.artifacts for r in recommend(specs.values(), found, {"evtx", "lnk"})}
    assert recs == {"hayabusa": ("evtx",), "lecmd": ("lnk",)}


def test_builtin_tool_is_found_without_a_tools_folder():
    import sys

    from glessner.version import build_id

    found = detect([load_registry()["event_xml"]], None)["event_xml"]
    assert (str(found.executable), found.version) == (sys.executable, build_id())   # the app's build


def test_the_registry_names_the_tool_files_no_argument_names_and_how_each_set_is_named():
    """Suricata needs neither: its arguments name its configuration and rule files, and its rules block names its set."""
    specs = load_registry()
    assert {s.id: s.tool_files for s in specs.values() if s.tool_files} == {
        "hayabusa": ("rules", "config"), "evtxecmd": ("Maps",), "sqlecmd": ("Maps", "runtimes"),
        "recmd": ("Plugins",)}
    assert {s.id: s.rules_label["kind"] for s in specs.values() if s.rules_label} == {
        "hayabusa": "git", "evtxecmd": "count", "sqlecmd": "count", "recmd": "version_line"}
    assert specs["suricata"].rules and specs["suricata"].rules_label is None


@pytest.mark.parametrize("label", [
    {"kind": "svn", "path": "Maps", "text": "Maps {value}"},   # a kind the registry doesn't know
    {"kind": "count", "text": "Maps {value}"},                  # no path
    {"kind": "count", "path": "Maps", "text": "Maps"},          # no {value} in its text
    "count",
])
def test_a_rules_label_without_a_known_kind_a_path_and_a_value_is_refused(tmp_path, label):
    entry = yaml.safe_load((REGISTRY_DIR / "evtxecmd.yaml").read_text(encoding="utf-8"))
    entry["rules_label"] = label
    (tmp_path / "evtxecmd.yaml").write_text(yaml.safe_dump(entry), encoding="utf-8")
    with pytest.raises(ValueError, match=r"evtxecmd\.yaml: rules_label needs a kind, one of \['git', 'count'"):
        load_registry(tmp_path)


def test_no_registry_entry_requires_a_console_log_or_switches_it_off():
    """Builds from 2026.10 write <stamp>_<tool>_<version>_ConsoleLog.txt in the output folder, and builds before it write
    none and refuse --co. So no entry passes --co or requires the file by itself, and the file is none of a tool's own
    files. Only SBECmd names it, as the alternative to the messages file that older builds write, since its parser takes
    each CSV's hive from one of the two."""
    specs = load_registry()
    for spec in specs.values():
        assert "--co" not in spec.args and all("--co" not in option.args for option in spec.options), spec.id
        assert not any("ConsoleLog" in output for output in spec.outputs if isinstance(output, str)), spec.id
        assert not any("ConsoleLog" in name for name in spec.tool_files), spec.id
    assert [s.id for s in specs.values() if any(isinstance(o, tuple) for o in s.outputs)] == ["sbecmd"]
    assert specs["sbecmd"].outputs == (("!SBECmd_Messages.txt", "*_SBECmd_*_ConsoleLog.txt"),)


@pytest.mark.parametrize("outputs", [[[]], [[1]], [["a.csv", ""]], "a.csv", [{"a": 1}], [None]])
def test_an_outputs_entry_that_is_not_a_pattern_or_a_group_of_them_is_refused(tmp_path, outputs):
    entry = yaml.safe_load((REGISTRY_DIR / "sbecmd.yaml").read_text(encoding="utf-8"))
    entry["outputs"] = outputs
    (tmp_path / "sbecmd.yaml").write_text(yaml.safe_dump(entry), encoding="utf-8")
    with pytest.raises(ValueError, match=r"sbecmd\.yaml: outputs"):
        load_registry(tmp_path)


def pin_states(case, found, cache=None):
    """The Tools page's pin state for each tool in `found`, by registry ID, from the overview built with the cache."""
    from glessner.toolbox import overview
    from glessner.tools_manifest import PinCache

    view = overview(case, load_registry(), found, PinCache() if cache is None else cache)
    return {t["id"]: t["pin"] for t in view["tools"] if t["id"] in found}, view


def test_the_tools_page_gives_each_found_tool_a_pin_state_and_says_when_the_states_were_taken(tmp_path, monkeypatch):
    """Not pinned, then Matches pin once pinned; Differs from pin after a map changes and the tool's cached files are
    dropped; Can't check for the one tool whose file can't be read now, while the others are drawn; and Outside the tools
    folder for a tool found on PATH. A builtin tool and one not found have none."""
    import re

    from test_tools_manifest import evtx, hayabusa, mft, new_case

    from glessner import tools
    from glessner.tools_manifest import PinCache, manifest_file, pin_tools, take_pin

    specs = load_registry()
    found = {"evtxecmd": evtx(tmp_path), "hayabusa": hayabusa(tmp_path), **mft(tmp_path),
             "pecmd": DetectedTool(specs["pecmd"], tmp_path / "elsewhere" / "PECmd.exe", "1"),
             "event_xml": detect([specs["event_xml"]], None)["event_xml"]}
    case = new_case(tmp_path, tmp_path / "tools")
    cache = PinCache()
    pins, view = pin_states(case, found, cache)
    assert {i: p["state"] for i, p in pins.items() if p} == {
        "evtxecmd": "not_pinned", "hayabusa": "not_pinned", "mftecmd": "not_pinned", "mftecmd_j": "not_pinned",
        "pecmd": "outside"}
    assert pins["event_xml"] is None and all(t["pin"] is None for t in view["tools"] if t["id"] not in found)
    assert (pins["evtxecmd"]["label"], pins["evtxecmd"]["tone"]) == ("Not pinned", "muted")
    assert (pins["pecmd"]["label"], pins["pecmd"]["tone"]) == ("Outside the tools folder", "muted")
    manifest = view["manifest"]
    path = manifest_file(tmp_path / "tools")
    assert (manifest["path"], manifest["state"]) == (str(path), "absent")
    assert manifest["counts"] == {"matches": 0, "differs": 0, "not_pinned": 4, "cant_check": 0, "total": 4}
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", manifest["checked"])
    assert manifest["text"] == "0 of 4 tools match their pins, 4 are not pinned"
    # what a pin from the page sends back: the hashes and links the page showed, and the executable they were read for
    listing = tools.pin_files(found["evtxecmd"])
    assert (pins["evtxecmd"]["files"], pins["evtxecmd"]["links"]) == (listing.hashes, [])
    assert pins["evtxecmd"]["executable"] == str(found["evtxecmd"].executable)

    pin_tools(tmp_path / "tools", {i: take_pin(found[i]) for i in ("evtxecmd", "hayabusa")})
    pins, view = pin_states(case, found, cache)   # a pin made elsewhere shows with no scan
    assert {i: p["label"] for i, p in pins.items() if p and p["state"] != "outside"} == {
        "evtxecmd": "Matches pin", "hayabusa": "Matches pin", "mftecmd": "Not pinned", "mftecmd_j": "Not pinned"}
    assert pins["evtxecmd"]["tone"] == "ok" and view["manifest"]["counts"] == {
        "matches": 2, "differs": 0, "not_pinned": 2, "cant_check": 0, "total": 4}
    assert view["manifest"]["text"] == "2 of 4 tools match their pins, 2 are not pinned"

    (found["evtxecmd"].executable.parent / "Maps" / "a.map").write_bytes(b"a, edited\n")
    assert pin_states(case, found, cache)[0]["evtxecmd"]["state"] == "matches"   # as cached, until dropped
    cache.drop(["evtxecmd"])
    pins, view = pin_states(case, found, cache)
    assert (pins["evtxecmd"]["state"], pins["evtxecmd"]["label"], pins["evtxecmd"]["tone"]) == (
        "differs", "Differs from pin", "warn")
    assert pins["evtxecmd"]["changes"] == "1 changed in Maps/"
    assert "antivirus" in pins["evtxecmd"]["hint"] and "pin it again" in pins["evtxecmd"]["hint"]
    assert view["manifest"]["text"] == "1 of 4 tools match their pins, 1 differs, 2 are not pinned"

    real = tools.file_sha256

    def refuse(file):
        if file.name == "b.yml":
            raise PermissionError(13, "Permission denied", str(file))
        return real(file)

    monkeypatch.setattr(tools, "file_sha256", refuse)
    cache.clear()
    pins, view = pin_states(case, found, cache)
    assert (pins["hayabusa"]["state"], pins["hayabusa"]["label"]) == ("cant_check", "Can't check")
    assert "Permission denied" in pins["hayabusa"]["reason"] and "b.yml" in pins["hayabusa"]["reason"]
    assert pins["hayabusa"]["files"] == {} and pins["evtxecmd"]["state"] == "differs"   # the rest drew
    assert pins["mftecmd"]["state"] == "not_pinned"
    assert view["manifest"]["text"] == "0 of 4 tools match their pins, 1 differs, 2 are not pinned, 1 can't be checked"


def test_the_tools_page_says_so_with_no_tools_folder_and_with_a_manifest_that_cannot_be_read(tmp_path):
    from test_tools_manifest import evtx, hayabusa, new_case

    from glessner.tools_manifest import manifest_file

    specs = load_registry()
    found = {"evtxecmd": evtx(tmp_path), "hayabusa": hayabusa(tmp_path),
             "pecmd": DetectedTool(specs["pecmd"], tmp_path / "elsewhere" / "PECmd.exe", "1")}
    bare = new_case(tmp_path / "bare")
    pins, view = pin_states(bare, found)
    assert {i: (p["state"], p["label"], p["tone"]) for i, p in pins.items()} == dict.fromkeys(
        found, ("no_folder", "No tools folder", "muted"))
    assert "needs a tools folder" in pins["evtxecmd"]["hint"]
    assert (view["manifest"]["state"], view["manifest"]["path"]) == ("no_folder", "")

    case = new_case(tmp_path / "set", tmp_path / "tools")
    path = manifest_file(tmp_path / "tools")
    path.write_text("not json {", encoding="utf-8")
    pins, view = pin_states(case, found)
    assert {i: (p["state"], p["label"], p["tone"]) for i, p in pins.items() if i != "pecmd"} == {
        "evtxecmd": ("unreadable", "Pins unreadable", "warn"), "hayabusa": ("unreadable", "Pins unreadable", "warn")}
    assert str(path) in pins["evtxecmd"]["hint"] and "isn't JSON" in pins["evtxecmd"]["hint"]
    assert view["manifest"]["state"] == "unreadable" and "isn't JSON" in view["manifest"]["reason"]
    assert view["manifest"]["sha256"] != ""


def test_the_tools_page_gives_a_tool_s_latest_run_with_its_tool_check_and_a_job_step_carries_it(tmp_path):
    """The latest run's check, as recorded, for the page's fold and its Ran line: a record from before the check was
    made has none. A step of a job carries its tool's ID and the check's result, and a group of found output has no tool
    to carry."""
    from test_runner import fake_spec
    from test_tools_manifest import new_case

    from glessner.runner import RunPlan, RunRecord, finish_run, start_run
    from glessner.toolbox import _step_result, overview

    case = new_case(tmp_path, tmp_path / "tools")
    specs = {"fake": fake_spec(tmp_path).spec}
    found = {"fake": fake_spec(tmp_path)}
    (fake,) = overview(case, specs, found)["tools"]
    assert fake["last_run"] is None and fake["pin"] is None   # no cache: no pin state
    check = {"result": "differs", "manifest_sha256": "ab" * 32,
             "files": [{"path": "Maps/a.map", "state": "missing", "pinned": "cd" * 32}]}
    for tool_check in (None, check):   # the second is the later run
        record, folder = start_run(case, "fake", "DC01", tool_version="1.0", host="DC01", inputs=["DC01/x"], status="ok",
                                   loaded_rows=1, tool_check=tool_check)
        finish_run(folder, record)
    (fake,) = overview(case, specs, found)["tools"]
    assert fake["last_run"]["latest"] == {"run_id": record.run_id, "host": "DC01", "at": record.finished_utc, "check": check,
                                          "text": "tool check differs, 1 missing in Maps/"}
    plan = RunPlan(found["fake"], "DC01", ("DC01/x",))
    result = _step_result("Fake on DC01", plan, [record])
    assert (result["tool_id"], result["tool_check"]) == ("fake", "differs")
    without = RunRecord(run_id="r", tool="fake", tool_version="1", executable="", host="DC01", argv=[], cwd="", inputs=[],
                        started_utc="", status="ok")
    assert _step_result("Fake on DC01", plan, [without])["tool_check"] == ""
    group = {"tool": "hayabusa", "host": "DC01", "label": "Hayabusa CSV"}
    assert not _step_result("Hayabusa CSV on DC01", group, [record]).get("tool_id")
    assert not _step_result("Hayabusa CSV on DC01", group, [record]).get("tool_check")


@pytest.mark.parametrize("files", [[1], "abc", [{"path": "Maps/a.map"}], [{"path": 3, "state": "missing"}]])
def test_the_tools_page_draws_a_latest_run_whose_tool_check_is_not_shaped_as_this_build_writes_it(tmp_path, files):
    """A run.json that another build wrote, or someone edited, can hold a differs check with files that aren't a list of
    paths and states. The page gives that run's check as recorded and its result in words, and still draws."""
    from test_runner import fake_spec
    from test_tools_manifest import new_case

    from glessner.runner import finish_run, start_run
    from glessner.toolbox import overview

    case = new_case(tmp_path, tmp_path / "tools")
    found = {"fake": fake_spec(tmp_path)}
    check = {"result": "differs", "files": files}
    record, folder = start_run(case, "fake", "DC01", tool_version="1.0", host="DC01", inputs=["DC01/x"], status="ok",
                               loaded_rows=1, tool_check=check)
    finish_run(folder, record)
    (fake,) = overview(case, {"fake": found["fake"].spec}, found)["tools"]
    assert fake["last_run"]["latest"]["check"] == check
    assert fake["last_run"]["latest"]["text"] == "tool check differs"


@pytest.fixture
def no_path(monkeypatch):
    """Detection finds tools in the tools folder alone: none on this computer's PATH."""
    monkeypatch.setattr("glessner.tools._on_path", lambda spec: None)


def pinned_case(tmp_path):
    """A case whose tools folder holds EvtxECmd, Hayabusa, and MFTECmd, whose executables are files that don't run, so
    detection reads their versions as unknown."""
    from test_tools_manifest import evtx, hayabusa, mft, new_case

    evtx(tmp_path)
    hayabusa(tmp_path)
    mft(tmp_path)
    return new_case(tmp_path, tmp_path / "tools")


def answers(monkeypatch, *replies):
    """Make input() give each reply in turn, and keep what each was asked. A reply that is an exception is raised."""
    asked = []
    queue = list(replies)

    def reply(prompt=""):
        asked.append(prompt)
        answer = queue.pop(0)
        if isinstance(answer, BaseException):
            raise answer
        return answer

    monkeypatch.setattr("builtins.input", reply)
    return asked


def run_tools(case, *args, capsys):
    from glessner.cli import main

    code = main(["tools", str(case.folder), *args])
    out = capsys.readouterr()
    return code, out.out, out.err


def test_the_tools_command_prints_each_tool_s_pin_state_and_a_manifest_line(tmp_path, capsys, no_path):
    from glessner.tools_manifest import manifest_file

    case = pinned_case(tmp_path)
    code, out, _ = run_tools(case, capsys=capsys)
    lines = {line.split()[0]: line.rstrip() for line in out.splitlines() if line.startswith("  ")}
    assert code == 0 and lines["EvtxECmd"].endswith("Not pinned") and lines["Hayabusa"].endswith("Not pinned")
    assert lines["RECmd"].endswith("not found") and "Outside" not in out
    path = manifest_file(tmp_path / "tools")
    assert f"Tools manifest {path}: 0 of 4 tools match their pins, 4 are not pinned." in out.splitlines()
    from test_tools_manifest import new_case

    _, out, _ = run_tools(new_case(tmp_path / "bare"), capsys=capsys)
    assert "Tools manifest" not in out and "(not set; PATH only)" in out and "Not pinned" not in out


def test_pin_asks_first_naming_the_manifest_and_the_tools_and_pins_on_a_yes(tmp_path, capsys, monkeypatch, no_path):
    from glessner.tools_manifest import manifest_file, read_manifest

    case = pinned_case(tmp_path)
    path = manifest_file(tmp_path / "tools")
    asked = answers(monkeypatch, "y")
    code, out, _ = run_tools(case, "--pin", "evtxecmd", "hayabusa", capsys=capsys)
    assert code == 0 and len(asked) == 1 and asked[0].endswith("[y/N] ")
    assert f"Pin EvtxECmd and Hayabusa as they are now, in {path}? Every case that uses this tools folder compares with " \
           "its pins." in out
    assert "A pin records what is in the folder; it doesn't check where the files came from." in out
    assert f"Pinned EvtxECmd and Hayabusa in {path}." in out
    assert read_manifest(path).tools.keys() == {"evtxecmd", "hayabusa"}
    _, out, _ = run_tools(case, capsys=capsys)
    assert f"{path}: 2 of 4 tools match their pins, 2 are not pinned." in out


def test_pin_writes_nothing_on_a_no_an_empty_answer_or_input_that_ends(tmp_path, capsys, monkeypatch, no_path):
    from glessner.tools_manifest import manifest_file

    case = pinned_case(tmp_path)
    path = manifest_file(tmp_path / "tools")
    for reply in ("n", "", "yes please no", EOFError()):
        answers(monkeypatch, reply)
        code, out, _ = run_tools(case, "--pin", "evtxecmd", capsys=capsys)
        assert code == 1 and "Nothing pinned." in out and not path.exists(), reply
    answers(monkeypatch, "Y")
    assert run_tools(case, "--pin", "evtxecmd", capsys=capsys)[0] == 0 and path.exists()


def test_a_bare_pin_takes_the_tools_with_no_pin_and_says_which_it_left_for_a_name(tmp_path, capsys, monkeypatch, no_path):
    from glessner.tools_manifest import manifest_file, read_manifest

    case = pinned_case(tmp_path)
    path = manifest_file(tmp_path / "tools")
    answers(monkeypatch, "y")
    code, out, _ = run_tools(case, "--pin", capsys=capsys)
    assert code == 0 and f"Pinned EvtxECmd, Hayabusa, MFTECmd, and MFTECmd ($J) in {path}." in out
    pinned = read_manifest(path).tools
    assert pinned.keys() == {"evtxecmd", "hayabusa", "mftecmd", "mftecmd_j"}
    (tmp_path / "tools" / "hayabusa-3.6.0" / "rules" / "sigma" / "b.yml").write_bytes(b"title: changed\n")
    answers(monkeypatch)   # nothing is asked
    code, out, _ = run_tools(case, "--pin", capsys=capsys)
    assert code == 0 and "Nothing to pin: every tool found in the tools folder has a pin." in out
    assert "Hayabusa differs from its pin; name it to pin it again." in out
    assert read_manifest(path).tools == pinned


def test_a_named_pin_takes_a_tool_whose_files_differ_and_says_what_changed(tmp_path, capsys, monkeypatch, no_path):
    from glessner.tools_manifest import manifest_file, read_manifest

    case = pinned_case(tmp_path)
    path = manifest_file(tmp_path / "tools")
    answers(monkeypatch, "y")
    run_tools(case, "--pin", "hayabusa", capsys=capsys)
    before = read_manifest(path).tools["hayabusa"]
    (tmp_path / "tools" / "hayabusa-3.6.0" / "rules" / "sigma" / "b.yml").write_bytes(b"title: changed\n")
    asked = answers(monkeypatch, "y")
    code, out, _ = run_tools(case, "--pin", "hayabusa", capsys=capsys)
    assert code == 0 and len(asked) == 1
    assert re.search(r"Hayabusa, since its pin of \d{4}-\d\d-\d\d: 1 changed in rules/\.", out)
    assert read_manifest(path).tools["hayabusa"]["files"]["rules/"] != before["files"]["rules/"]


def test_pin_names_a_tool_that_shares_an_executable_with_the_one_asked_for(tmp_path, capsys, monkeypatch, no_path):
    from glessner.tools_manifest import manifest_file, read_manifest

    case = pinned_case(tmp_path)
    answers(monkeypatch, "y")
    code, out, _ = run_tools(case, "--pin", "mftecmd_j", capsys=capsys)
    assert code == 0 and "Pin MFTECmd and MFTECmd ($J) as they are now" in out
    assert read_manifest(manifest_file(tmp_path / "tools")).tools.keys() == {"mftecmd", "mftecmd_j"}


def test_pin_is_refused_for_what_cannot_be_pinned_and_for_a_manifest_that_cannot_be_read(tmp_path, capsys, monkeypatch, no_path):
    from glessner.tools_manifest import manifest_file

    case = pinned_case(tmp_path)
    answers(monkeypatch)   # none of these asks
    for name, text in (("nope", "No tool 'nope' in the registry"), ("recmd", "RECmd isn't installed"),
                       ("event_xml", "Windows event XML is built in")):
        code, out, err = run_tools(case, "--pin", name, capsys=capsys)
        assert code == 2 and text in err and "Pinned" not in out, name
    from test_tools_manifest import new_case

    code, _, err = run_tools(new_case(tmp_path / "bare"), "--pin", "evtxecmd", capsys=capsys)
    assert code == 2 and "needs a tools folder" in err
    path = manifest_file(tmp_path / "tools")
    path.write_text("not json {", encoding="utf-8")
    for args in (("--pin",), ("--pin", "evtxecmd")):
        code, _, err = run_tools(case, *args, capsys=capsys)
        assert code == 2 and f"The tools manifest at {path} can't be read" in err and "delete it and pin again" in err
    assert path.read_text(encoding="utf-8") == "not json {"


def test_pin_says_a_tools_folder_it_cannot_write_is_the_problem_and_exits_2(tmp_path, capsys, monkeypatch, no_path):
    from glessner.tools_manifest import LOCK_FILE, manifest_file

    case = pinned_case(tmp_path)
    (tmp_path / "tools" / LOCK_FILE).mkdir()   # a lock file that can't be opened for writing
    answers(monkeypatch, "y")
    code, out, err = run_tools(case, "--pin", "evtxecmd", capsys=capsys)
    path = manifest_file(tmp_path / "tools")
    assert code == 2 and f"Error: The tools manifest at {path} can't be written: " in err and "Pinned" not in out
    assert not path.exists()


def test_run_warns_before_a_step_s_result_when_its_tool_s_files_differ_from_the_pin(tmp_path, capsys):
    from test_tools_manifest import new_case, pinned, runnable

    from glessner.cli import _run_and_load
    from glessner.runner import plan_runs

    tool = runnable(tmp_path)
    case = new_case(tmp_path, tmp_path / "tools")
    pinned(tmp_path, tool)
    plans = plan_runs(case, tool)
    assert _run_and_load(case, plans, []) == 0
    out = capsys.readouterr().out
    assert "differ from the pin" not in out and "  ok: " in out
    (tool.executable.parent / "Maps" / "a.map").write_bytes(b"a, edited\n")
    assert _run_and_load(case, plans, []) == 0
    lines = capsys.readouterr().out.splitlines()
    warning = next(i for i, line in enumerate(lines) if "differ from the pin" in line)
    assert re.fullmatch(r"Fake on DC01: its files differ from the pin of \d{4}-\d\d-\d\d: 1 changed in Maps/\.",
                        lines[warning])
    assert lines[warning + 1].startswith("  ok: ") and lines[warning - 1].startswith("Fake 1.0 on DC01")
    (tool.executable.parent / "Maps" / "b.map").unlink()
    _run_and_load(case, plans, [])
    out = capsys.readouterr().out
    assert "1 changed and 1 missing in Maps/. A missing file may have been removed by antivirus." in out


def test_runs_lists_each_run_s_tool_check_result_and_a_dash_for_a_run_without_one(tmp_path, capsys):
    from test_tools_manifest import new_case, pinned, runnable

    from glessner.cli import _run_and_load, main
    from glessner.runner import plan_runs, start_run

    tool = runnable(tmp_path)
    case = new_case(tmp_path, tmp_path / "tools")
    start_run(case, "fake", "OLD", tool_version="1.0", host="OLD", inputs=[], status="ok")   # made without a check
    _run_and_load(case, plan_runs(case, tool), [])   # no manifest yet
    pinned(tmp_path, tool)
    _run_and_load(case, plan_runs(case, tool), [])
    (tool.executable.parent / "Maps" / "a.map").write_bytes(b"edited\n")
    _run_and_load(case, plan_runs(case, tool), [])
    capsys.readouterr()
    assert main(["runs", str(case.folder)]) == 0
    lines = capsys.readouterr().out.splitlines()
    words = [re.search(r"\d+\.\ds  (matches|differs|not pinned|no manifest|unreadable|-)\s{2,}", line).group(1)
             for line in lines]
    assert sorted(words) == ["-", "differs", "matches", "no manifest"]


def test_runs_lists_a_run_whose_tool_check_result_is_not_text_as_written(tmp_path, capsys):
    """A later build's record can hold any JSON as the result, which read_runs accepts, so the listing doesn't stop."""
    from test_tools_manifest import new_case

    from glessner.cli import main
    from glessner.runner import start_run

    case = new_case(tmp_path)
    for name, result in (("NULL", None), ("LIST", ["x"]), ("DICT", {"a": 1})):
        start_run(case, "fake", name, tool_version="1.0", host=name, inputs=[], status="ok", tool_check={"result": result})
    assert main(["runs", str(case.folder)]) == 0
    out = capsys.readouterr().out
    for name, shown in (("NULL", "None"), ("LIST", "['x']"), ("DICT", "{'a': 1}")):
        (line,) = [line for line in out.splitlines() if f"_fake_{name}" in line]
        assert f"s  {shown}" in line, line
