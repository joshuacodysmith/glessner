import os

from glessner.tools import DetectedTool, detect, find_dotnet, load_registry, recommend, tool_env


def test_registry_loads_all_tools():
    specs = load_registry()
    assert set(specs) == {"evtxecmd", "hayabusa", "mftecmd", "recmd", "pecmd", "lecmd",
                          "sbecmd", "amcacheparser", "jlecmd", "srumecmd", "rbcmd", "event_xml",
                          "suricata", "mftecmd_j", "sqlecmd", "wxtcmd"}
    assert "-l" not in specs["sbecmd"].args   # never the live registry
    assert specs["amcacheparser"].handles == ("registry:AMCACHE",) and specs["rbcmd"].input == "host_dir"
    assert specs["rbcmd"].dotnet == 9 and "administrator" in specs["rbcmd"].empty_result
    assert {s.id for s in specs.values() if s.dotnet} == {"rbcmd", "sqlecmd", "wxtcmd"}
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
    assert find_dotnet(tmp_path, 9) is None
    fake_runtime(tmp_path / "dotnet-9", "9.0.21")
    assert find_dotnet(tmp_path, 9) == tmp_path / "dotnet-9" and find_dotnet(tmp_path, 8) == tmp_path / "dotnet-8"
    assert find_dotnet(tmp_path / "absent", 9) is None

    (tmp_path / "EZ" / "RBCmd").mkdir(parents=True)
    (tmp_path / "EZ" / "RBCmd" / "RBCmd.exe").write_bytes(b"not a real program")
    specs = load_registry()
    found = detect([specs["rbcmd"]], tmp_path)
    assert found["rbcmd"].dotnet_root == str(tmp_path / "dotnet-9")
    env = tool_env(found["rbcmd"])
    assert env["DOTNET_ROOT"] == env["DOTNET_ROOT_X64"] == str(tmp_path / "dotnet-9") and env["PATH"] == os.environ["PATH"]
    assert tool_env(DetectedTool(specs["evtxecmd"], tmp_path / "EvtxECmd.exe", "1")) is None   # inherits as before


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
