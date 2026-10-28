"""Runner behavior, using a small Python script as a stand-in forensic tool."""

import hashlib
import json
import sys
from dataclasses import replace
from pathlib import Path

import pytest
from chain_fixtures import format3_case
from conftest import junction

from glessner.case import create_case
from glessner.intake import add_new, intake
from glessner.long_paths import long_path
from glessner.runner import RunError, plan_runs, read_runs, run
from glessner.tools import DetectedTool, ToolOption, ToolSpec, detect, folder_sha256

FAKE_TOOL = """
import json, os, pathlib, sys, time
host_dir, out_dir, mode = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]), sys.argv[3]
names = sorted(p.name for p in host_dir.rglob('*.evtx'))
if mode == 'sleep':
    time.sleep(30)
if mode == 'tamper':
    next(host_dir.rglob('*.evtx')).write_bytes(b'ElfFile\\x00changed')
if mode == 'unreadable-output':
    (out_dir / 'out.txt').mkdir()   # matches the output name but cannot be opened as a file
elif mode == 'env':
    (out_dir / 'out.txt').write_text(os.environ.get('DOTNET_ROOT', '') + '|' + os.environ.get('DOTNET_ROOT_X64', ''))
elif mode == 'argv':
    (out_dir / 'out.txt').write_text(json.dumps(sys.argv))
elif mode == 'messages':   # a build that writes only a messages file
    (out_dir / 'messages.txt').write_text('messages')
elif mode == 'console-log':   # a build that writes only a console log
    (out_dir / '20261025181337_Fake_2026.10.1_ConsoleLog.txt').write_text('messages')
elif mode == 'ok-console-log':
    (out_dir / 'out.txt').write_text('\\n'.join(names))
    (out_dir / '20261025181337_Fake_2026.10.1_ConsoleLog.txt').write_text('console messages')
elif mode not in ('no-output', 'fail-no-output'):
    (out_dir / 'out.txt').write_text('\\n'.join(names))
print('read', len(names), 'files')
sys.exit(3 if mode.startswith('fail') else 0)
"""


def fake_spec(tmp_path: Path, timeout_minutes: float = 1.0) -> DetectedTool:
    script = tmp_path / "fake_tool.py"
    script.write_text(FAKE_TOOL)
    spec = ToolSpec(id="fake", name="Fake", publisher="", license="", download_url="https://example.invalid",
                    executables=("python.exe",), version_args=(), version_regex="", handles=("evtx",),
                    input="host_dir", args=(str(script), "{host_dir}", "{output_dir}", "{value}"),
                    timeout_minutes=timeout_minutes, outputs=("out.txt",), parser=None,
                    options=(ToolOption("mode", "Mode", ()),))
    return DetectedTool(spec, Path(sys.executable), "1.0")


@pytest.fixture
def case(tmp_path):
    evidence = tmp_path / "evidence"
    for host in ("DC01", "DESKTOP"):
        logs = evidence / host / "Windows" / "System32" / "winevt" / "Logs"
        logs.mkdir(parents=True)
        (logs / "Security.evtx").write_bytes(b"ElfFile\x00" + host.encode())
    (evidence / "README.txt").write_text("root file, no host")
    c = create_case(tmp_path / "case", "Test", evidence, "cody")
    intake(c)
    return c


def run_mode(case, tool, mode, host="DC01"):
    (plan,) = plan_runs(case, tool, [host])
    # The fake tool reads its mode from the last argument, which comes from the {value} placeholder.
    patched = replace(tool, spec=replace(tool.spec, args=tool.spec.args[:-1] + (mode,)))
    return run(case, plan.__class__(patched, plan.host, plan.inputs))


def test_plans_one_run_per_host_and_skips_root_files(case, tmp_path):
    plans = plan_runs(case, fake_spec(tmp_path))
    assert [(p.host, p.inputs) for p in plans] == [
        ("DC01", ("DC01/Windows/System32/winevt/Logs/Security.evtx",)),
        ("DESKTOP", ("DESKTOP/Windows/System32/winevt/Logs/Security.evtx",)),
    ]


def test_successful_run_is_recorded(case, tmp_path):
    record = run_mode(case, fake_spec(tmp_path), "ok")
    assert (record.status, record.exit_code, record.evidence_check) == ("ok", 0, "ok")
    folder = case.runs_folder / record.run_id
    saved = json.loads((folder / "run.json").read_text())
    assert saved["argv"][0] == sys.executable and saved["argv"][-1] == "ok"
    assert saved["outputs"][0]["path"] == "out.txt" and len(saved["outputs"][0]["sha256"]) == 64
    assert "read 1 files" in (folder / "stdout.txt").read_text()
    assert (folder / "output" / "out.txt").read_text() == "Security.evtx"
    assert [r.run_id for r in read_runs(case)] == [record.run_id]


def test_missing_output_fails_with_antivirus_hint(case, tmp_path):
    record = run_mode(case, fake_spec(tmp_path), "no-output")
    assert record.status == "failed" and record.missing_outputs == ["out.txt"]
    assert "Antivirus may have quarantined it" in record.reason


def test_unreadable_output_fails_instead_of_crashing(case, tmp_path):
    record = run_mode(case, fake_spec(tmp_path), "unreadable-output")
    assert record.status == "failed" and record.missing_outputs[0].startswith("out.txt (unreadable")
    assert "Antivirus may have quarantined it" in record.reason
    assert json.loads((case.runs_folder / record.run_id / "run.json").read_text())["status"] == "failed"


def with_spec(tool, **changes):
    return DetectedTool(ToolSpec(**{**tool.spec.__dict__, **changes}), tool.executable, tool.version, tool.dotnet_root)


def test_empty_result_explains_absent_output_only(case, tmp_path):
    # RBCmd exits 0 and writes no CSV when it finds no Recycle Bin files, so the registry names the likely cause.
    tool = with_spec(fake_spec(tmp_path), empty_result="Found none of the host's files.")
    assert (run_mode(case, tool, "no-output").reason) == "Found none of the host's files."
    assert "Antivirus may have quarantined it" in run_mode(case, tool, "unreadable-output").reason
    assert run_mode(case, tool, "fail-no-output").reason == "exit code 3"
    assert run_mode(case, tool, "ok").status == "ok"


CONSOLE_LOG = "20261025181337_Fake_2026.10.1_ConsoleLog.txt"


def test_a_console_log_is_hashed_with_the_output_and_is_none_of_the_tool_s_files(case, tmp_path):
    """Builds from 2026.10 write <stamp>_<tool>_<version>_ConsoleLog.txt in the output folder. No registry entry requires
    it, so a run of an older build, which writes none, passes too. A run records the file with the rest of its output,
    and it is none of the files the run records for the tool."""
    tool = fake_spec(tmp_path)
    older, newer = run_mode(case, tool, "ok"), run_mode(case, tool, "ok-console-log")
    assert [(r.status, r.reason, r.missing_outputs) for r in (older, newer)] == [("ok", "", [])] * 2
    assert [o["path"] for o in older.outputs] == ["out.txt"]
    assert [o["path"] for o in newer.outputs] == [CONSOLE_LOG, "out.txt"]
    log = case.runs_folder / newer.run_id / "output" / CONSOLE_LOG
    assert newer.outputs[0]["sha256"] == hashlib.sha256(log.read_bytes()).hexdigest()
    assert not any("ConsoleLog" in name for name in saved_record(case, newer)["tool_files"])


def with_logs(tool):
    """The fake tool needing one of two logs, as SBECmd's entry does, in place of its single output."""
    return with_spec(tool, outputs=(("messages.txt", "*_ConsoleLog.txt"),))


@pytest.mark.parametrize("mode", ["messages", "console-log"])
def test_a_run_that_writes_one_of_a_group_of_outputs_passes(case, tmp_path, mode):
    record = run_mode(case, with_logs(fake_spec(tmp_path)), mode)
    assert (record.status, record.reason, record.missing_outputs) == ("ok", "", [])


def test_a_run_that_writes_none_of_a_group_of_outputs_fails_naming_the_group(case, tmp_path):
    record = run_mode(case, with_logs(fake_spec(tmp_path)), "no-output")
    assert record.status == "failed" and record.missing_outputs == ["messages.txt or *_ConsoleLog.txt"]
    assert "expected output missing or unreadable: messages.txt or *_ConsoleLog.txt." in record.reason
    assert "Antivirus may have quarantined it" in record.reason


def test_a_run_that_writes_a_group_s_file_it_cannot_read_fails_instead_of_passing_on_the_group(case, tmp_path):
    """A file of the group that the run hashes and can't read is a missing output of its own, as for any output."""
    tool = with_spec(fake_spec(tmp_path), outputs=(("out.txt", "other.txt"),))
    record = run_mode(case, tool, "unreadable-output")
    assert record.status == "failed" and record.missing_outputs[0].startswith("out.txt (unreadable")


def test_private_dotnet_runtime_reaches_the_tool_and_the_record(case, tmp_path):
    runtime = str(tmp_path / "tools" / "dotnet-9")
    tool = fake_spec(tmp_path)
    record = run_mode(case, DetectedTool(tool.spec, tool.executable, tool.version, runtime), "env")
    assert record.status == "ok" and record.dotnet_root == runtime
    assert (case.runs_folder / record.run_id / "output" / "out.txt").read_text() == f"{runtime}|{runtime}"
    assert json.loads((case.runs_folder / record.run_id / "run.json").read_text())["dotnet_root"] == runtime


def test_a_run_of_a_tool_that_lacks_its_dotnet_runtime_is_refused_naming_the_runtime(case, tmp_path, monkeypatch):
    """With only a .NET 9 runtime in the tools folder, a tool that needs .NET 10 is stopped by the .NET host, which says
    so when its version is checked, and a run is refused with the runtime named rather than started to fail with the host's
    exit code."""
    from test_tools import HOST_STOP_CODE, HOST_STOP_TEXT, fake_runtime, version_checks_end

    version_checks_end(monkeypatch, code=HOST_STOP_CODE, stderr=HOST_STOP_TEXT)
    spec = replace(fake_spec(tmp_path).spec, executables=("Fake.exe",), version_args=("--version",),
                   version_regex=r"^(\d+\.\d+\.\d+)", dotnet=10)
    tools_folder = tmp_path / "tools"
    (tools_folder / "Fake").mkdir(parents=True)
    (tools_folder / "Fake" / "Fake.exe").write_bytes(b"not a real program")
    fake_runtime(tools_folder / "dotnet-9", "9.0.21")
    found = detect([spec], tools_folder)["fake"]
    (plan,) = plan_runs(case, found, ["DC01"])
    with pytest.raises(RunError, match=r"Fake can't run here: Needs a \.NET 10 runtime: unpack Microsoft's \.NET 10 runtime zip"):
        run(case, plan)
    assert read_runs(case) == []
    fake_runtime(tools_folder / "dotnet-10", "10.0.13")
    assert detect([spec], tools_folder)["fake"].missing == ""


def test_nonzero_exit_fails(case, tmp_path):
    record = run_mode(case, fake_spec(tmp_path), "fail")
    assert (record.status, record.reason) == ("failed", "exit code 3")


def test_timeout_fails(case, tmp_path):
    record = run_mode(case, fake_spec(tmp_path, timeout_minutes=0.02), "sleep")
    assert record.status == "failed" and record.timed_out and record.reason == "timed out"


def test_evidence_change_is_caught(case, tmp_path):
    record = run_mode(case, fake_spec(tmp_path), "tamper")
    assert record.status == "failed" and record.evidence_check == "mismatch"
    assert record.evidence_problems == ["DC01/Windows/System32/winevt/Logs/Security.evtx: SHA-256 changed"]


def test_refused_runs_leave_no_run_folder(case, tmp_path):
    tool = fake_spec(tmp_path)
    (plan,) = plan_runs(case, tool, ["DC01"])
    with pytest.raises(RunError, match="placeholder"):
        run(case, plan)   # {value} in the base arguments is only filled by an option
    spec = tool.spec
    no_value = DetectedTool(ToolSpec(**{**spec.__dict__, "args": spec.args[:-1] + ("ok",)}), tool.executable, "1.0")
    with pytest.raises(RunError, match="has no option"):
        run(case, plan.__class__(no_value, plan.host, plan.inputs), {"nope": "1"})
    assert list(case.runs_folder.iterdir()) == []


def test_working_copies_keep_the_evidence_unchanged(case, tmp_path):
    """A tool that writes beside what it reads, as SrumECmd does, runs on copies in its run folder."""
    tool = fake_spec(tmp_path)
    copies = DetectedTool(ToolSpec(**{**tool.spec.__dict__, "work_on_copies": True}), tool.executable, tool.version)
    record = run_mode(case, copies, "tamper")
    log = "DC01/Windows/System32/winevt/Logs/Security.evtx"
    assert (record.status, record.evidence_check) == ("ok", "ok")
    assert record.working_copies == [log] and record.working_copy_changes == [log]
    assert (case.evidence / log).read_bytes() == b"ElfFile\x00DC01"
    assert str(case.runs_folder / record.run_id / "input" / "DC01") in record.argv
    # The folders the output names files in, for a copied or moved case
    assert (record.input_root, record.evidence_root) == (str(case.runs_folder / record.run_id / "input"), str(case.evidence))


def test_the_recorded_command_line_is_the_one_the_tool_received(case, tmp_path):
    """run.json's argv is the list the tool was started with, after the working copies' paths replaced the evidence's:
    the executable first, then what the tool read from its own command line. The case folder's name holds a space, as a
    folder an analyst names can, so a command line joined into one string would split the paths."""
    spaced = create_case(tmp_path / "case folder", "Spaced", case.evidence, "cody")
    intake(spaced)
    record = run_mode(spaced, with_spec(fake_spec(tmp_path), work_on_copies=True), "argv")
    folder = spaced.runs_folder / record.run_id
    saved = json.loads((folder / "run.json").read_text())
    received = json.loads((folder / "output" / "out.txt").read_text())
    assert record.status == "ok"
    assert saved["argv"][0] == sys.executable and saved["argv"][1:] == received
    assert received[1:] == [str(folder / "input" / "DC01"), str(folder / "output"), "argv"]
    assert " " in received[1] and " " in received[2]


def test_working_copies_are_copied_from_the_files_the_manifest_names(tmp_path):
    """A working copy is read from the evidence, and written, by its manifest name in extended-length form. A plain
    path drops a trailing dot from a name, so Security.evtx. would be copied from Security.evtx beside it and fail its
    hash check."""
    logs = tmp_path / "dots" / "DC01" / "Logs"
    logs.mkdir(parents=True)
    (logs / "Security.evtx").write_bytes(b"ElfFile\x00plain")
    long_path(logs, "Security.evtx.").write_bytes(b"ElfFile\x00dotted")
    c = create_case(tmp_path / "dots_case", "Dots", tmp_path / "dots", "cody")
    intake(c)
    record = run_mode(c, with_spec(fake_spec(tmp_path), work_on_copies=True), "ok")
    assert (record.status, record.reason) == ("ok", "")
    assert record.working_copies == ["DC01/Logs/Security.evtx", "DC01/Logs/Security.evtx."]
    assert record.working_copy_changes == []
    copies = c.runs_folder / record.run_id / "input"
    assert long_path(copies, "DC01/Logs/Security.evtx.").read_bytes() == b"ElfFile\x00dotted"
    assert long_path(copies, "DC01/Logs/Security.evtx").read_bytes() == b"ElfFile\x00plain"


LOGS = "Windows/System32/winevt/Logs"


def test_a_tool_that_lists_the_host_folder_is_refused_a_file_intake_did_not_hash(case, tmp_path):
    """EvtxECmd and the other tools given {host_dir} list the host's folder themselves, so a file copied there after
    intake would load with no intake hash, and the run's evidence check, which covers the manifest's files, wouldn't
    see it. The run is refused before its folder is made, naming the file and Add new evidence, and runs once the
    file is added. A tool that works on copies reads only the copies of the files its run names, so it runs."""
    (case.evidence / "DC01" / LOGS / "System.evtx").write_bytes(b"ElfFile\x00later")
    tool = fake_spec(tmp_path)
    with pytest.raises(RunError) as refused:
        run_mode(case, tool, "ok")
    text = str(refused.value)
    assert text.startswith("Fake wasn't run on DC01: it lists the host's folder itself")
    assert f"1 file the intake manifest doesn't list: DC01/{LOGS}/System.evtx." in text and "intake --add" in text
    assert list(case.runs_folder.iterdir()) == []
    assert run_mode(case, tool, "ok", host="DESKTOP").status == "ok"   # another host's folder holds nothing new
    assert run_mode(case, with_spec(tool, work_on_copies=True), "ok").status == "ok"
    add_new(case)
    record = run_mode(case, tool, "ok")
    assert record.status == "ok" and record.inputs == [f"DC01/{LOGS}/Security.evtx", f"DC01/{LOGS}/System.evtx"]


def test_a_tool_that_lists_the_host_folder_is_refused_a_link_in_it(case, tmp_path):
    """A junction or symbolic link in a host's folder, which intake skips, would take a tool that lists the folder to
    files outside the evidence, which it would load as the host's. The run is refused, naming the link and its
    target. Files under a folder whose name ends in a dot are listed by that name, as intake lists them."""
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "Other.evtx").write_bytes(b"ElfFile\x00outside")
    junction(case.evidence / "DESKTOP" / "Linked", outside)
    tool = fake_spec(tmp_path)
    with pytest.raises(RunError) as refused:
        run_mode(case, tool, "ok", host="DESKTOP")
    text = str(refused.value)
    assert f"1 link, which the tool may follow out of the evidence: DESKTOP/Linked -> {outside}." in text
    assert "file the intake manifest doesn't list" not in text
    assert list(case.runs_folder.iterdir()) == []
    long_path(case.evidence, "DC01/Old.").mkdir()
    long_path(case.evidence, "DC01/Old./Old.evtx").write_bytes(b"ElfFile\x00old")
    with pytest.raises(RunError, match=r"1 file the intake manifest doesn't list: DC01/Old\./Old\.evtx\."):
        run_mode(case, tool, "ok")


def test_a_refused_host_is_reported_and_the_job_runs_the_others(case, tmp_path, capsys):
    """The Tools page's job and the command line's run --all and run --tool go through toolbox.run_and_load. A host whose
    run is refused is reported as failed with the reason, and the other hosts run. The command line names a run record
    only for the run that has one."""
    import time

    from glessner import toolbox
    from glessner.cli import _run_and_load

    (case.evidence / "DC01" / "later.evtx").write_bytes(b"ElfFile\x00later")
    tool = with_spec(fake_spec(tmp_path), args=fake_spec(tmp_path).spec.args[:-1] + ("ok",))
    job = toolbox.start_job(case, tool, None, lambda job: None)
    while not job.finished:
        time.sleep(0.05)
    assert job.error == ""
    assert [(r["host"], r["status"], r["evidence"]) for r in job.results] == [("DC01", "failed", "not checked"),
                                                                              ("DESKTOP", "ok", "ok")]
    assert "DC01/later.evtx" in job.results[0]["reason"] and job.results[0]["loaded"] is False
    assert [r.host for r in read_runs(case)] == ["DESKTOP"]
    capsys.readouterr()
    assert _run_and_load(case, plan_runs(case, tool), []) == 1
    out = capsys.readouterr().out
    assert "  failed: 0.0s, evidence not checked (Fake wasn't run on DC01: " in out and "DC01/later.evtx" in out
    assert out.count("evidence ok") == 1
    assert [r.host for r in read_runs(case)] == ["DESKTOP", "DESKTOP"]
    (record_line,) = [line for line in out.splitlines() if "run record:" in line]
    assert record_line == f"  run record: {case.runs_folder / read_runs(case)[-1].run_id / 'run.json'}"


def test_older_manifests_and_hive_types_plan_the_right_files(tmp_path):
    """A case taken in before the jump list signature still plans JLECmd, and registry:AMCACHE picks one hive."""
    from glessner.intake import current_entries

    evidence = tmp_path / "evidence"
    recent = evidence / "WS01" / "Users" / "bob" / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Recent"
    (recent / "AutomaticDestinations").mkdir(parents=True)
    (recent / "AutomaticDestinations" / "1bc392b8e104a00e.automaticDestinations-ms").write_bytes(
        bytes.fromhex("d0cf11e0a1b11ae1") + b"\x00" * 100)
    config = evidence / "WS01" / "Windows" / "System32" / "config"
    config.mkdir(parents=True)
    (config / "SYSTEM").write_bytes(b"regf" + b"\x00" * 100)
    programs = evidence / "WS01" / "Windows" / "AppCompat" / "Programs"
    programs.mkdir(parents=True)
    (programs / "Amcache.hve").write_bytes(b"regf" + b"\x00" * 100)
    c = create_case(tmp_path / "case", "Old", evidence, "cody")
    intake(c)
    # Make the manifest look like one written before the signature existed.
    lines = [json.loads(line) for line in c.manifest_path.read_text().splitlines()]
    for e in lines:
        if e["path"].endswith("automaticDestinations-ms"):
            e.update(artifact=None, method="unidentified", detail="")
    c.manifest_path.write_text("".join(json.dumps(e) + "\n" for e in lines))
    assert [e.artifact for e in current_entries(c) if e.path.endswith("-ms")] == ["jumplist"]
    on_disk = [json.loads(line) for line in c.manifest_path.read_text().splitlines()]
    assert [e["artifact"] for e in on_disk if e["path"].endswith("-ms")] == [None]   # the manifest itself is unchanged

    def tool(handles):
        spec = fake_spec(tmp_path).spec
        return DetectedTool(ToolSpec(**{**spec.__dict__, "handles": handles}), Path(sys.executable), "1.0")
    (jl,) = plan_runs(c, tool(("jumplist",)))
    assert jl.inputs == ("WS01/Users/bob/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/"
                         "1bc392b8e104a00e.automaticDestinations-ms",)
    (am,) = plan_runs(c, tool(("registry:AMCACHE",)))
    assert am.inputs == ("WS01/Windows/AppCompat/Programs/Amcache.hve",)


def test_a_run_whose_load_fails_is_recorded_and_its_job_refreshes_the_case(case, tmp_path, monkeypatch):
    """A load that raises anything but OSError doesn't escape run() before run.json is written again, so the run
    doesn't stay "running", and the job runs `after`, which brings the derived tables up to date."""
    import time

    from glessner import runner, toolbox

    tool = fake_spec(tmp_path)
    loads = DetectedTool(ToolSpec(**{**tool.spec.__dict__, "parser": "evtxecmd_csv"}), tool.executable, tool.version)

    def broken(*args, **kwargs):
        raise RuntimeError("no parser state")
    monkeypatch.setattr(runner, "load_output", broken)
    record = run_mode(case, loads, "ok")
    assert (record.status, record.reason) == ("failed", "could not load the output: RuntimeError: no parser state")
    assert json.loads((case.runs_folder / record.run_id / "run.json").read_text())["status"] == "failed"

    real_run, hosts, refreshed = toolbox.run, [], []

    def second_fails(c, plan, options=None):
        hosts.append(plan.host)
        return broken() if len(hosts) > 1 else real_run(c, plan, options)
    monkeypatch.setattr(toolbox, "run", second_fails)
    ok = DetectedTool(ToolSpec(**{**tool.spec.__dict__, "args": tool.spec.args[:-1] + ("ok",)}), tool.executable, tool.version)
    job = toolbox.start_job(case, ok, None, lambda job: refreshed.append([r["status"] for r in job.results]))
    while not job.finished:
        time.sleep(0.05)
    assert hosts == ["DC01", "DESKTOP"] and job.error == "RuntimeError: no parser state" and refreshed == [["ok"]]


PREFETCH = "DC01/Windows/Prefetch/CMD.EXE-0BD30981.pf"


def write_pecmd(path, case, exe, when, prefetch=PREFETCH):
    """PECmd's CSV of one prefetch file run once, as PECmd writes it."""
    import csv

    row = {"SourceFilename": str(case.evidence / prefetch), "ExecutableName": exe, "RunCount": "1", "LastRun": when,
           **{f"PreviousRun{i}": "" for i in range(7)}, "FilesLoaded": f"\\VOLUME{{1}}\\{exe}",
           "Volume0Name": "\\VOLUME{1}", "ParsingError": "False"}
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(row))
        writer.writeheader()
        writer.writerow(row)


def pecmd_run(case, host="DC01", exe="FIRST.EXE"):
    """An ok PECmd run on a host, its output written as PECmd would and recorded as runner.run records it, and
    loaded."""
    from glessner.runner import RunRecord, _check_outputs, _write_record, load_output
    from glessner.tools import load_registry

    prefetch = PREFETCH.replace("DC01", host, 1)
    folder = case.runs_folder / f"20240101T000000Z_pecmd_{host}"
    (folder / "output").mkdir(parents=True)
    write_pecmd(folder / "output" / "pecmd.csv", case, exe, "2024-01-01 00:00:00.0000000", prefetch)
    (folder / "output" / "pecmd_Timeline.csv").write_text("RunTime,ExecutableName\n", encoding="utf-8")
    record = RunRecord(run_id=folder.name, tool="pecmd", tool_version="1", executable="", host=host, argv=[], cwd="",
                       inputs=[prefetch], started_utc="", status="ok", parser="pecmd_csv",
                       evidence_root=str(case.evidence))
    _check_outputs(load_registry()["pecmd"], folder / "output", record)
    assert record.outputs_all and not record.missing_outputs
    load_output(case, record, folder)
    _write_record(folder, record)
    return record, folder / "output"


def messages(case):
    from glessner.events import connect

    con = connect(case.db_path, read_only=True)
    try:
        return [m for (m,) in con.execute("SELECT message FROM events ORDER BY message").fetchall()]
    finally:
        con.close()


def test_rebuild_leaves_out_a_run_whose_output_changed_since_it_ran(case):
    """run.json records the SHA-256 of the run's output, and rebuild reads it. Without that, a pecmd.csv changed after
    the run would reload silently, as another executable under the same event ID, which would keep its Malicious mark;
    a deleted one would raise FileNotFoundError after the database was gone. A changed, missing, or added output file
    leaves the run out with a note naming it, the command line prints, and the Tools page and the overview's Gaps show
    as the run's reason. The mark is then counted as referring to an event that no longer exists."""
    from glessner.events import connect
    from glessner.journal import Journal
    from glessner.runner import rebuild
    from glessner.server import App
    from glessner.toolbox import run_gaps
    from glessner.tools import load_registry

    record, output = pecmd_run(case)
    first = messages(case)
    assert first == ["Executed FIRST.EXE (\\VOLUME{1}\\FIRST.EXE), run count 1"]
    con = connect(case.db_path, read_only=True)
    (uid,) = con.execute("SELECT event_uid FROM events").fetchone()
    con.close()
    Journal(case).append("mark", targets=[uid], value="malicious")
    original = (output / "pecmd.csv").read_bytes()
    notes = []

    def rebuilt():
        notes.clear()
        rebuild(case, report=lambda r, text: notes.append((r.run_id, text)))
        return messages(case)

    assert rebuilt() == first and notes == []   # as recorded: no note
    write_pecmd(output / "pecmd.csv", case, "DIFFERENT.EXE", "2024-02-01 00:00:00.0000000")
    assert rebuilt() == []
    assert [(run, text.split(" left it out: ")[1]) for run, text in notes] == [(record.run_id, "pecmd.csv: SHA-256 changed")]
    (saved,) = read_runs(case)
    assert (saved.status, saved.loaded_rows, saved.notes[-1]) == ("ok", 0, notes[0][1])
    (gap,) = run_gaps([saved], load_registry())
    assert gap["reason"] == notes[0][1]
    app = App(case)
    try:
        assert app.orphans == 1
    finally:
        app.con.close()
    (output / "pecmd.csv").unlink()
    assert rebuilt() == [] and notes[0][1].endswith(" left it out: pecmd.csv: missing")
    (output / "pecmd.csv").write_bytes(original)
    assert rebuilt() == first and notes == []
    (output / "extra.csv").write_text("SourceFilename,ExecutableName\n", encoding="utf-8")
    assert rebuilt() == [] and notes[0][1].endswith(" left it out: extra.csv: not there when the tool ran")


def test_a_run_made_before_every_output_was_hashed_loads_with_a_note(case, capsys):
    """Runs made before every output was hashed recorded only the files the registry's patterns name, so for
    AmcacheParser, SrumECmd, and SBECmd most of what their parsers read has no hash. For those runs, a rebuild checks
    the files they did record, loads the rest, and says which files it couldn't check."""
    import json

    from glessner.cli import main

    record, output = pecmd_run(case)
    saved = json.loads((output.parent / "run.json").read_text(encoding="utf-8"))
    saved["outputs"] = [o for o in saved["outputs"] if o["path"] == "pecmd.csv"]
    del saved["outputs_all"]   # as an older run.json is written
    (output.parent / "run.json").write_text(json.dumps(saved), encoding="utf-8")
    assert main(["rebuild", str(case.folder)]) == 0
    out = capsys.readouterr().out
    assert f"{record.run_id}: Rebuild at " in out and (
        "1 output file was loaded unchecked (pecmd_Timeline.csv): the run recorded no hash for them.") in out
    assert messages(case) == ["Executed FIRST.EXE (\\VOLUME{1}\\FIRST.EXE), run count 1"]
    assert main(["rebuild", str(case.folder)]) == 0   # the note replaces the last rebuild's, rather than adding one
    assert sum("loaded unchecked" in n for n in read_runs(case)[0].notes) == 1
    # Written again, the older run.json keeps its shape, which an older build's read_runs reads; a key it doesn't know
    # fails its Case overview and Tools page with a TypeError
    assert "outputs_all" not in json.loads((output.parent / "run.json").read_text(encoding="utf-8"))
    capsys.readouterr()
    write_pecmd(output / "pecmd.csv", case, "DIFFERENT.EXE", "2024-02-01 00:00:00.0000000")   # a recorded file
    # A run left out isn't counted as rebuilt, and the command exits 1, as verify does for a changed file
    assert main(["rebuild", str(case.folder)]) == 1
    out = capsys.readouterr().out
    assert "left it out: pecmd.csv: SHA-256 changed" in out and messages(case) == []
    assert out.splitlines()[-1] == ("Rebuilt events.duckdb from the latest successful run of each tool and host, "
                                    "leaving out 1 of 1 run as noted above: 0 rows.")


def test_a_copy_names_the_runs_its_rebuild_left_out(case, tmp_path, capsys):
    """A run whose output changed since it ran is left out of a copy's events. copy-case counts it apart from the runs
    it rebuilt and exits 1, and the start page's job names it, not only that the copy is ready."""
    import time

    from glessner.cli import main
    from glessner.start import start_copy

    record, output = pecmd_run(case)
    assert json.loads((output.parent / "run.json").read_text(encoding="utf-8"))["outputs_all"] is True
    write_pecmd(output / "pecmd.csv", case, "DIFFERENT.EXE", "2024-02-01 00:00:00.0000000")
    assert main(["copy-case", str(case.folder), str(tmp_path / "copy"), "--name", "Copy"]) == 1
    out = capsys.readouterr().out.splitlines()
    assert out[1].startswith(f"{record.run_id}: Rebuild at ") and out[1].endswith(" left it out: pecmd.csv: SHA-256 changed")
    assert out[2] == f"Rebuilt the events from 1 run, leaving out 1 as noted above: 0 rows. Evidence: {case.evidence}"
    job = start_copy({"source": str(case.folder), "case_folder": str(tmp_path / "copy2"), "name": "Copy 2"}, "cody")
    for _ in range(200):
        if job.finished:
            break
        time.sleep(0.05)
    assert not job.error and job.result["runs"] == 1
    (note,) = job.result["left_out"]
    assert note.startswith(f"{record.run_id}: Rebuild at ") and note.endswith(" left it out: pecmd.csv: SHA-256 changed")


def events_files(folder):
    return sorted(p.name for p in folder.iterdir() if p.name.startswith("events"))


def fail_second_load(monkeypatch, error):
    """Make the second load of a rebuild raise `error`, after the first has loaded."""
    from glessner import runner

    real, calls = runner.load_output, []

    def flaky(*args, **kwargs):
        calls.append(1)
        if len(calls) == 2:
            raise error
        return real(*args, **kwargs)
    monkeypatch.setattr(runner, "load_output", flaky)


def test_a_rebuild_that_fails_partway_leaves_the_database_and_the_runs_as_they_were(case, monkeypatch):
    """A rebuild loads a new database beside events.duckdb and puts it in place only once every run has loaded. A load
    that raises, or Ctrl-C, partway leaves the case's events and each run.json as they were, rather than a database
    holding only the runs before it, which would open as if it were whole, and the error is raised. A new database
    a rebuild left behind when its process was killed is replaced by the next."""
    from glessner.runner import rebuild

    runs = [pecmd_run(case, "DC01", "FIRST.EXE")[0], pecmd_run(case, "DESKTOP", "SECOND.EXE")[0]]
    rebuild(case)
    both = messages(case)
    assert len(both) == 2 and events_files(case.folder) == ["events.duckdb"]
    saved = [(case.runs_folder / r.run_id / "run.json").read_bytes() for r in runs]
    for error in (ValueError("a row the parser can't read"), KeyboardInterrupt()):
        with monkeypatch.context() as patch:
            fail_second_load(patch, error)
            with pytest.raises(type(error)):
                rebuild(case)
        assert messages(case) == both and events_files(case.folder) == ["events.duckdb"]
        assert [(case.runs_folder / r.run_id / "run.json").read_bytes() for r in runs] == saved
    (case.folder / "events.duckdb.rebuild").write_bytes(b"left by a rebuild that was killed")
    assert [r.run_id for r in rebuild(case)] == [r.run_id for r in runs]
    assert messages(case) == both and events_files(case.folder) == ["events.duckdb"]


def test_a_copy_whose_rebuild_fails_has_no_events_database(case, tmp_path, monkeypatch, capsys):
    """A copy has no events database until its rebuild puts one in place, so a load that fails partway leaves it with
    none, rather than one holding only the runs before it. copy-case and the start page's job report the error. The
    copied runs' records, which count the source's rows, say first that no database holds them, so an open of the copy,
    which makes an empty database, lists each run as a gap with that reason, and the Tools page counts no rows. The
    next rebuild that finishes loads them and drops the note."""
    import time

    from glessner.case import open_case
    from glessner.cli import main
    from glessner.runner import LEFT_OUT, UNFINISHED_NOTE, rebuild
    from glessner.start import start_copy
    from glessner.toolbox import overview, run_gaps
    from glessner.tools import load_registry

    pecmd_run(case, "DC01", "FIRST.EXE")
    pecmd_run(case, "DESKTOP", "SECOND.EXE")
    specs = load_registry()

    def unloaded(folder):
        copy = open_case(folder)
        runs = read_runs(copy)
        assert [(r.status, r.loaded_rows) for r in runs] == [("ok", 0), ("ok", 0)]
        assert all(LEFT_OUT in r.notes[-1] and r.notes[-1].endswith(UNFINISHED_NOTE) for r in runs)
        assert [g["reason"] for g in run_gaps(runs, specs)] == [r.notes[-1] for r in runs]
        (pecmd,) = [t for t in overview(copy, specs, {})["tools"] if t["id"] == "pecmd"]
        assert pecmd["last_run"]["rows"] == 0
        return copy

    with monkeypatch.context() as patch:
        fail_second_load(patch, ValueError("a row the parser can't read"))
        assert main(["copy-case", str(case.folder), str(tmp_path / "copy"), "--name", "Copy"]) == 2
    assert "a row the parser can't read" in capsys.readouterr().err
    assert (tmp_path / "copy" / "case.yaml").is_file() and events_files(tmp_path / "copy") == []
    copy = unloaded(tmp_path / "copy")
    rebuild(copy)
    assert [(r.loaded_rows, r.notes) for r in read_runs(copy)] == [(1, []), (1, [])]
    with monkeypatch.context() as patch:
        fail_second_load(patch, ValueError("a row the parser can't read"))
        job = start_copy({"source": str(case.folder), "case_folder": str(tmp_path / "copy2"), "name": "Copy 2"}, "cody")
        for _ in range(200):
            if job.finished:
                break
            time.sleep(0.05)
    assert job.finished and job.error == "a row the parser can't read"
    assert events_files(tmp_path / "copy2") == []
    unloaded(tmp_path / "copy2")


def test_a_run_hashes_every_file_its_tool_writes(tmp_path):
    """_check_outputs hashes every file the tool writes, not only the files the registry's outputs patterns name: for
    AmcacheParser, ProgramEntries alone of the four CSVs its parser reads."""
    from glessner.runner import RunRecord, _check_outputs
    from glessner.tools import load_registry

    tables = ("AssociatedFileEntries", "ProgramEntries", "ShortCuts", "UnassociatedFileEntries")
    (tmp_path / "out" / "sub").mkdir(parents=True)
    for table in tables:
        (tmp_path / "out" / f"20240101_Amcache_{table}.csv").write_text(f"{table}\n", encoding="utf-8")
    (tmp_path / "out" / "sub" / "log.txt").write_text("written by the tool\n", encoding="utf-8")
    record = RunRecord(run_id="a", tool="amcacheparser", tool_version="1", executable="", host="WS01", argv=[], cwd="",
                       inputs=[], started_utc="")
    _check_outputs(load_registry()["amcacheparser"], tmp_path / "out", record)
    assert [o["path"] for o in record.outputs] == [*(f"20240101_Amcache_{t}.csv" for t in tables), "sub/log.txt"]
    assert record.outputs_all and not record.missing_outputs and all(len(o["sha256"]) == 64 for o in record.outputs)


def test_a_run_json_key_this_build_doesn_t_read_is_refused_by_name(case, tmp_path):
    """A run.json written by a newer build has a key RunRecord doesn't declare. read_runs refuses it by name, as
    open_case does a setting, rather than in a TypeError that would fail the Case overview, the Tools page, and `runs`."""
    from glessner.case import CaseError
    from glessner.cli import main

    record = run_mode(case, fake_spec(tmp_path), "ok")
    path = case.runs_folder / record.run_id / "run.json"
    saved = json.loads(path.read_text(encoding="utf-8"))
    assert [r.run_id for r in read_runs(case)] == [record.run_id]   # its own keys read as before
    saved.update(zeta_key=1, alpha_key="x")
    path.write_text(json.dumps(saved), encoding="utf-8")
    with pytest.raises(CaseError) as raised:
        read_runs(case)
    assert "doesn't read: alpha_key, zeta_key" in str(raised.value) and str(path) in str(raised.value)
    assert main(["runs", str(case.folder)]) == 2   # the command line says so rather than failing with a traceback


HOLD = "import sys, duckdb; con = duckdb.connect(sys.argv[1]); print('held', flush=True); sys.stdin.read()"


def test_a_rebuild_refuses_while_another_program_holds_the_database(case, capsys):
    """DuckDB lets another process delete a file it holds, so `glessner rebuild` in a terminal would delete the
    database that glessner serving the case has open. It opens the database read-write first and stops, deleting
    nothing."""
    import subprocess

    from glessner.case import CaseError
    from glessner.cli import main
    from glessner.events import connect
    from glessner.runner import rebuild

    connect(case.db_path).close()
    size = case.db_path.stat().st_size
    holder = subprocess.Popen([sys.executable, "-c", HOLD, str(case.db_path)], stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, text=True)
    try:
        assert holder.stdout.readline().strip() == "held"
        with pytest.raises(CaseError, match="another program has its events database open, such as glessner serving the case"):
            rebuild(case)
        assert main(["rebuild", str(case.folder)]) == 2
        assert "Close it, then try again" in capsys.readouterr().err
        assert case.db_path.exists() and case.db_path.stat().st_size == size
    finally:
        holder.communicate("", timeout=60)
    rebuild(case)   # nothing holds it now
    assert case.db_path.exists()


def eve_lines(ports) -> str:
    """Suricata EVE DNS records, one for each source port."""
    return "".join(json.dumps({"timestamp": "2024-01-01T00:00:00.000000+0000", "event_type": "dns",
                               "src_ip": "192.0.2.1", "src_port": port, "dest_ip": "198.51.100.2", "dest_port": 53,
                               "proto": "UDP", "dns": {"queries": [{"rrname": f"host{port}.example.test"}]}}) + "\n"
                   for port in ports)


def test_found_output_is_read_by_the_names_intake_hashed(tmp_path):
    """A load of output found in the evidence opens each file by its extended-length path, as intake hashed it. A file
    in a folder whose name ends in a dot gives its own rows, not those of the sibling its plain path opens, and a file
    past 260 characters loads. An event's source is the file's path in the evidence folder, and a CSV that names a file
    under the evidence folder still gives that file's evidence path. A rebuild reads the same files."""
    from test_tool_outputs import EVTX_COLUMNS, evtx_rows, write_rows

    from glessner.events import connect
    from glessner.runner import load_found_output, rebuild

    ev = tmp_path / "evidence"
    deep = "SENSOR/" + "/".join(c * 80 for c in "abc") + "/eve.json"
    ports = {"SENSOR/dir/eve.json": [1000], "SENSOR/dir./eve.json": [2000, 2001, 2002], deep: [3000, 3001]}
    for rel, numbers in ports.items():
        path = long_path(ev, rel)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(eve_lines(numbers), encoding="utf-8")
    assert len(str(long_path(ev, deep))) > 260
    evtx_csv = "SENSOR/Modules/x_EvtxECmd_Output.csv"
    write_rows(ev / evtx_csv, EVTX_COLUMNS,
               [{**row, "SourceFile": str(ev / "SENSOR" / "Logs" / "Security.evtx")} for row in evtx_rows("SENSOR")])
    case = create_case(tmp_path / "case", "Found", ev, "cody")
    intake(case)
    for rel, numbers in ports.items():
        record = load_found_output(case, "suricata", "suricata_eve", "SENSOR", [rel])
        assert (record.status, record.reason, record.loaded_rows, record.evidence_check) == ("ok", "", len(numbers), "ok")
    assert load_found_output(case, "evtxecmd", "evtxecmd_csv", "SENSOR", [evtx_csv]).loaded_rows == 2

    def sources():
        con = connect(case.db_path, read_only=True)
        try:
            return dict(con.execute("SELECT source_file, list(source_port ORDER BY source_port) FROM events "
                                    "GROUP BY 1").fetchall())
        finally:
            con.close()
    expected = {**{rel: [str(n) for n in numbers] for rel, numbers in ports.items()},
                "SENSOR/Logs/Security.evtx": ["", ""]}
    assert sources() == expected
    rebuild(case)
    assert sources() == expected


def test_found_output_gives_evidence_paths_under_an_evidence_folder_typed_in_extended_length_form(tmp_path):
    """The case keeps an evidence folder typed as \\\\?\\D:\\..., and a found file's events, and the files a CSV in it
    names by their plain paths, still get their paths in the evidence folder, as under the folder's plain form."""
    from test_tool_outputs import EVTX_COLUMNS, evtx_rows, write_rows

    from glessner.events import connect
    from glessner.runner import load_found_output

    plain = tmp_path / "evidence"
    (plain / "SENSOR").mkdir(parents=True)
    (plain / "SENSOR" / "eve.json").write_text(eve_lines([1000, 1001]), encoding="utf-8")
    evtx_csv = "SENSOR/Modules/x_EvtxECmd_Output.csv"
    log = plain.resolve() / "SENSOR" / "Logs" / "Security.evtx"
    write_rows(plain / evtx_csv, EVTX_COLUMNS, [{**row, "SourceFile": str(log)} for row in evtx_rows("SENSOR")])
    typed = long_path(plain)
    case = create_case(tmp_path / "case", "Typed", typed, "cody")
    assert case.evidence == typed
    intake(case)
    assert load_found_output(case, "suricata", "suricata_eve", "SENSOR", ["SENSOR/eve.json"]).loaded_rows == 2
    assert load_found_output(case, "evtxecmd", "evtxecmd_csv", "SENSOR", [evtx_csv]).loaded_rows == 2
    con = connect(case.db_path, read_only=True)
    try:
        sources = dict(con.execute("SELECT source_file, count(*) FROM events GROUP BY 1").fetchall())
    finally:
        con.close()
    assert sources == {"SENSOR/eve.json": 2, "SENSOR/Logs/Security.evtx": 2}


def refuse_reads(monkeypatch, name):
    """Make every evidence check refuse the files named `name`, as Windows refuses one that another program, such as
    antivirus, holds open with no sharing."""
    from glessner import intake as intake_module

    real = intake_module.sha256_file

    def sha256_file(path):
        if path.name == name:
            raise PermissionError(13, "Permission denied")
        return real(path)
    monkeypatch.setattr(intake_module, "sha256_file", sha256_file)


def finish(job):
    import time

    while not job.finished:
        time.sleep(0.05)
    return job


def test_a_file_the_check_after_a_run_cannot_re_read_is_not_called_changed(case, tmp_path, monkeypatch):
    """A check that can't read a file compares no hash, so the run fails saying the file could not be re-read, not that
    the evidence changed, and the job goes on to the next host. A changed file still stops the job, also when another
    file could not be re-read."""
    from glessner import runner, toolbox

    log = "DC01/Windows/System32/winevt/Logs/Security.evtx"
    tool = with_spec(fake_spec(tmp_path), args=fake_spec(tmp_path).spec.args[:-1] + ("ok",))
    with monkeypatch.context() as m:
        refuse_reads(m, "Security.evtx")
        record = run_mode(case, tool, "ok")
        assert (record.status, record.evidence_check) == ("failed", "unreadable")
        assert record.evidence_problems == [f"{log}: unreadable (Permission denied)"]
        assert record.reason == (f"the evidence check after the run could not re-read 1 file, so it compared no hash "
                                 f"with intake's: {log}: unreadable (Permission denied). Another program, such as "
                                 "antivirus, may have held it open; run the tool again.")
        job = finish(toolbox.start_job(case, tool, None, lambda job: None))
        assert job.error == ""
        assert [(r["host"], r["status"], r["evidence"]) for r in job.results] == [("DC01", "failed", "unreadable"),
                                                                                  ("DESKTOP", "failed", "unreadable")]
    tamper = with_spec(tool, args=tool.spec.args[:-1] + ("tamper",))
    job = finish(toolbox.start_job(case, tamper, None, lambda job: None))
    assert job.error == toolbox.STOP_RUN and [r["evidence"] for r in job.results] == ["mismatch"]
    unread, changed = f"{log}: unreadable (Permission denied)", "DC01/later.evtx: SHA-256 changed"
    assert [runner.check_result(p) for p in ([], [unread], [unread, changed], ["DC01/x: missing"])] == [
        "ok", "unreadable", "mismatch", "mismatch"]


def test_found_output_a_check_cannot_re_read_is_not_called_changed(tmp_path, monkeypatch):
    """A load of found output whose check before or after the load can't read its file fails, saying so rather than
    that the output doesn't match or changed, and the job goes on to the next host."""
    from test_tool_outputs import EVTX_COLUMNS, evtx_rows, write_rows

    from glessner import runner, toolbox
    from glessner.runner import load_found_output
    from glessner.tools import load_registry

    ev = tmp_path / "evidence"
    for host in ("WS01", "WS02"):
        write_rows(ev / host / "Modules" / f"{host}_EvtxECmd_Output.csv", EVTX_COLUMNS, evtx_rows(host))
    case = create_case(tmp_path / "case", "Found", ev, "cody")
    intake(case)
    csv_path = "WS01/Modules/WS01_EvtxECmd_Output.csv"
    with monkeypatch.context() as m:
        refuse_reads(m, "WS01_EvtxECmd_Output.csv")
        record = load_found_output(case, "evtxecmd", "evtxecmd_csv", "WS01", [csv_path])
    assert (record.status, record.evidence_check, record.loaded_rows) == ("failed", "unreadable", None)
    assert record.reason.startswith("the check before loading could not re-read 1 file, so it compared no hash with "
                                    f"intake's: {csv_path}: unreadable (Permission denied). Another program")
    with monkeypatch.context() as m:
        real_load = runner.load_output

        def load_then_hold(*args, **kwargs):
            real_load(*args, **kwargs)
            refuse_reads(m, "WS01_EvtxECmd_Output.csv")
        m.setattr(runner, "load_output", load_then_hold)
        record = load_found_output(case, "evtxecmd", "evtxecmd_csv", "WS01", [csv_path])
    assert (record.status, record.evidence_check, record.loaded_rows) == ("failed", "unreadable", 2)
    assert record.reason.startswith("the check after loading could not re-read 1 file, so it compared no hash")
    with monkeypatch.context() as m:
        refuse_reads(m, "WS01_EvtxECmd_Output.csv")
        refuse_reads(m, "WS02_EvtxECmd_Output.csv")
        job = finish(toolbox.start_load_job(case, load_registry(), {}, "evtxecmd_csv", None, False, lambda job: None))
    assert job.error == ""
    assert [(r["host"], r["status"], r["evidence"]) for r in job.results] == [("WS01", "failed", "unreadable"),
                                                                              ("WS02", "failed", "unreadable")]


FORMAT_4_KEYS = {"tool_files", "rows_skipped", "tool_check"}


def saved_record(case, record) -> dict:
    return json.loads((case.runs_folder / record.run_id / "run.json").read_text(encoding="utf-8"))


def git_rules(folder: Path, commit: str) -> dict:
    """A rules checkout at `commit`, and a registry rules_label that names it, as Hayabusa's names its rules folder."""
    (folder / ".git").mkdir(parents=True, exist_ok=True)
    (folder / ".git" / "HEAD").write_text(f"{commit}\n", encoding="utf-8")
    return {"kind": "git", "path": str(folder), "text": "Fake rules {value}"}


def test_a_run_records_the_sha_256_of_its_tool_s_files(case, tmp_path):
    """The fake tool is the Python executable, given a script outside its folder, so it records the executable and the
    libraries beside it, if it has any. A case with no tools folder checks it against no manifest."""
    exe = Path(sys.executable)
    record = run_mode(case, fake_spec(tmp_path), "ok")
    saved = saved_record(case, record)
    assert record.status == "ok" and saved["tool_files"][exe.name] == hashlib.sha256(exe.read_bytes()).hexdigest()
    assert all(name.lower().endswith(".dll") for name in saved["tool_files"] if name != exe.name)
    assert saved["rules"] == "" and "rows_skipped" not in saved   # no set, no parser
    assert saved["tool_check"] == {"result": "no manifest", "reason": "no tools folder is set"}


def test_a_builtin_tool_s_run_records_an_empty_set_of_tool_files(case, tmp_path):
    """The app's own Python runs a builtin tool, so it has no files of its own; an empty set, not none, says the run
    was made at format 4."""
    record = run_mode(case, with_spec(fake_spec(tmp_path), builtin=True), "ok")
    assert record.status == "ok" and saved_record(case, record)["tool_files"] == {}


def test_a_run_notes_each_link_its_tool_files_leave_out(case, tmp_path, monkeypatch):
    """A folder's hash skips the links in it, as intake skips them, but the tool may read through one."""
    from glessner import runner
    from glessner.tools import ToolListing

    def hashed(tool, argv, links):
        links += ["rules/shared -> D:\\Rules", "Maps/more -> D:\\Maps"]
        return ToolListing({}, {})

    monkeypatch.setattr(runner, "tool_listing", hashed)
    record = run_mode(case, fake_spec(tmp_path), "ok")
    note = ("The SHA-256s recorded for Fake's files don't cover what 2 links in its folder point to, which Fake may "
            "read: rules/shared -> D:\\Rules; Maps/more -> D:\\Maps.")
    assert record.status == "ok" and note in saved_record(case, record)["notes"]
    monkeypatch.setattr(runner, "tool_listing", lambda tool, argv, links: ToolListing({}, {}))
    assert not any("SHA-256s" in n for n in run_mode(case, fake_spec(tmp_path), "ok").notes)


def test_a_run_records_its_rule_set_as_it_is_when_the_tool_starts(case, tmp_path):
    """Detection, which the server keeps, names the set too, but the rules may be updated after it."""
    from glessner.tools import rules_label

    tool = with_spec(fake_spec(tmp_path), rules_label=git_rules(tmp_path / "rules", "1" * 40))
    detected = replace(tool, rules=rules_label(tool.spec, tool.executable))
    files = folder_sha256(tmp_path / "rules")[:8]
    assert detected.rules == f"Fake rules 1111111, files {files}"
    git_rules(tmp_path / "rules", "2" * 40)   # an update of the rules after detection
    record = run_mode(case, detected, "ok")
    updated = f"Fake rules 2222222, files {files}"
    assert (record.status, record.rules, saved_record(case, record)["rules"]) == ("ok", updated, updated)


def test_a_run_whose_tool_file_cannot_be_read_is_refused_naming_it_before_anything_is_made(case, tmp_path, monkeypatch):
    """The read is refused once the file is open, as a lock or antivirus refuses one, with an error that names no
    file."""
    def refuse(f, digest):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(hashlib, "file_digest", refuse)
    with pytest.raises(RunError) as refused:
        run_mode(case, fake_spec(tmp_path), "ok")
    assert str(refused.value).startswith("Fake wasn't run on DC01: ") and "Permission denied" in str(refused.value)
    assert f"{Path(sys.executable).name}'" in str(refused.value)
    assert list(case.runs_folder.iterdir()) == []


def test_a_run_in_a_case_below_format_4_records_none_of_format_4_s_keys(case, tmp_path):
    """A case still at format 3, as one whose journal is read-only stays, is read by the builds of that format, which
    refuse a run.json key they don't know. A run there records its rule set as those builds do, which for a tool named
    by its rules_label, such as Hayabusa, is none, and records no tool files. The same run in a format 4 case records
    both."""
    tool = with_spec(fake_spec(tmp_path), rules_label=git_rules(tmp_path / "rules", "1" * 40))
    named = f"Fake rules 1111111, files {folder_sha256(tmp_path / 'rules')[:8]}"
    detected = replace(tool, rules=named)   # as detection names it
    at_4 = run_mode(case, detected, "ok")
    assert at_4.rules == named and "tool_files" in saved_record(case, at_4)
    below = format3_case(case)
    record = run_mode(below, detected, "ok")
    assert (record.status, record.rules, record.tool_files) == ("ok", "", None)
    assert not FORMAT_4_KEYS & set(saved_record(below, record))


def at_tools_folder(case, folder):
    """`case` with its tools folder set to `folder`."""
    return replace(case, settings=replace(case.settings, tools_folder=str(folder)))


def stand_in(tmp_path) -> DetectedTool:
    """The registry ID "fake" unpacked in a tools folder under tmp_path, with a Maps folder. The fake tool that runs is the
    Python executable, whose folder can't be written to, so the runs below stub the listing of its files with this one's."""
    folder = tmp_path / "tools" / "Fake"
    for rel, data in {"Fake.exe": b"MZ", "Fake.dll": b"MZ dll", "Maps/a.map": b"a\n", "Maps/b.map": b"b\n"}.items():
        (folder / rel).parent.mkdir(parents=True, exist_ok=True)
        (folder / rel).write_bytes(data)
    return DetectedTool(replace(fake_spec(tmp_path).spec, tool_files=("Maps",)), folder / "Fake.exe", "1.0")


def pinned_stand_in(tmp_path, monkeypatch) -> tuple[DetectedTool, Path]:
    """The stand-in pinned in the manifest of tmp_path's tools folder, and runs listing its files, as a run's own listing."""
    from glessner import runner, tools
    from glessner.tools_manifest import pin_tools, take_pin

    found = stand_in(tmp_path)
    path = pin_tools(tmp_path / "tools", {"fake": take_pin(found)})
    listed = runner.tool_listing

    def listing(tool, argv, links):
        return tools.pin_files(found, links) if tool.spec.id == "fake" and not tool.spec.builtin else listed(tool, argv, links)

    monkeypatch.setattr(runner, "tool_listing", listing)
    return found, path


def test_a_run_records_that_its_tool_s_files_match_the_pin(case, tmp_path, monkeypatch):
    """The check is made before the run's first write, from the manifest read once, so a run that is stopped keeps it and
    the record names the manifest by the hash of its bytes."""
    from glessner import runner

    _, path = pinned_stand_in(tmp_path, monkeypatch)
    at = at_tools_folder(case, tmp_path / "tools")
    record = run_mode(at, fake_spec(tmp_path), "ok")
    entry = json.loads(path.read_text(encoding="utf-8"))["tools"]["fake"]
    expected = {"result": "matches", "manifest_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "pinned_utc": entry["pinned_utc"], "pinned_version": "1.0", "pinned_by": entry["pinned_by"]}
    assert record.status == "ok" and record.tool_check == expected == saved_record(at, record)["tool_check"]
    assert read_runs(at)[0].tool_check == expected

    class Stop(BaseException):
        pass

    def stop(*args, **kwargs):
        raise Stop

    monkeypatch.setattr(runner.subprocess, "run", stop)
    with pytest.raises(Stop):
        run_mode(at, fake_spec(tmp_path), "ok")
    (interrupted,) = [r for r in read_runs(at) if r.status == "running"]
    assert interrupted.tool_check == expected


def test_a_run_whose_tool_files_differ_from_the_pin_goes_ahead_and_records_which(case, tmp_path, monkeypatch):
    found, _ = pinned_stand_in(tmp_path, monkeypatch)
    (found.executable.parent / "Maps" / "a.map").write_bytes(b"a, edited\n")
    at = at_tools_folder(case, tmp_path / "tools")
    record = run_mode(at, fake_spec(tmp_path), "ok")
    assert (record.status, record.evidence_check) == ("ok", "ok")
    assert (case.runs_folder / record.run_id / "output" / "out.txt").read_text() == "Security.evtx"
    check = saved_record(at, record)["tool_check"]
    assert check["result"] == "differs" and "more" not in check
    assert check["files"] == [{"path": "Maps/a.map", "state": "changed", "pinned": hashlib.sha256(b"a\n").hexdigest(),
                               "now": hashlib.sha256(b"a, edited\n").hexdigest()}]
    assert saved_record(at, record)["tool_files"]["Maps/"] != json.loads(
        (tmp_path / "tools" / "tools_manifest.json").read_text(encoding="utf-8"))["tools"]["fake"]["files"]["Maps/"]


def test_a_run_whose_manifest_cannot_be_read_goes_ahead_and_records_unreadable(case, tmp_path, monkeypatch):
    _, path = pinned_stand_in(tmp_path, monkeypatch)
    path.write_text("not json {", encoding="utf-8")
    at = at_tools_folder(case, tmp_path / "tools")
    record = run_mode(at, fake_spec(tmp_path), "ok")
    assert record.status == "ok" and record.tool_check["result"] == "unreadable"
    assert record.tool_check["manifest_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert "isn't JSON" in record.tool_check["reason"]


def test_a_run_in_a_case_with_no_tools_folder_or_no_manifest_records_no_manifest(case, tmp_path):
    record = run_mode(case, fake_spec(tmp_path), "ok")
    assert record.tool_check == {"result": "no manifest", "reason": "no tools folder is set"}
    (tmp_path / "tools").mkdir()
    record = run_mode(at_tools_folder(case, tmp_path / "tools"), fake_spec(tmp_path), "ok")
    assert record.tool_check == {"result": "no manifest", "reason": "the tools folder has no tools_manifest.json"}
    assert saved_record(case, record)["tool_check"] == record.tool_check


def test_a_run_records_no_tool_check_below_format_4_for_a_builtin_tool_or_for_a_load_of_found_output(case, tmp_path,
                                                                                                     monkeypatch):
    """The key joins run.json only for a tool a case at format 4 ran from files that can be hashed: a case kept at format
    3 with a manifest in its tools folder, a builtin tool, an import's or found output's load, all leave it out."""
    from conftest import FAST_ALERTS

    from glessner.imports import preview, run_import
    from glessner.runner import load_found_output

    _, path = pinned_stand_in(tmp_path, monkeypatch)
    at = at_tools_folder(case, tmp_path / "tools")
    builtin = run_mode(at, with_spec(fake_spec(tmp_path), builtin=True), "ok")
    assert builtin.tool_files == {} and builtin.tool_check is None and "tool_check" not in saved_record(at, builtin)
    (case.evidence / "SENSOR").mkdir()
    (case.evidence / "SENSOR" / "eve.json").write_text(eve_lines([1000]), encoding="utf-8")
    (case.evidence / "IDS").mkdir()
    (case.evidence / "IDS" / "fast.log").write_text(FAST_ALERTS, newline="\n")
    add_new(at)
    found = load_found_output(at, "suricata", "suricata_eve", "SENSOR", ["SENSOR/eve.json"])
    assert found.status == "ok" and found.tool_check is None and "tool_check" not in saved_record(at, found)
    mapping = preview(at, "IDS/fast.log")["mapping"]
    imported = run_import(at, "IDS/fast.log", {**mapping, "time": {**mapping["time"], "zone": "UTC"}}, zones={})
    assert imported.status == "ok" and imported.tool_check is None and "tool_check" not in saved_record(at, imported)
    below = at_tools_folder(format3_case(case), tmp_path / "tools")
    record = run_mode(below, fake_spec(tmp_path), "ok")
    assert path.is_file() and record.tool_check is None and "tool_check" not in saved_record(below, record)


def test_a_rebuild_a_reload_and_the_mark_of_an_interrupted_run_keep_the_tool_check_as_it_was(case):
    """A rebuild and a reload write each run's record again and a mark of an interrupted run rewrites it. The tool_check a
    run recorded stays equal, and a record without one has none afterward, since the tools folder at that time isn't
    what the run used."""
    from glessner.journal import host_layout
    from glessner.runner import _write_record, rebuild, reload_run
    from glessner.toolbox import close_interrupted

    check = {"result": "differs", "manifest_sha256": "ab" * 32, "files": [{"path": "Maps/a.map", "state": "missing",
                                                                           "pinned": "cd" * 32}]}
    with_check, folder = pecmd_run(case, "DC01")
    without, _ = pecmd_run(case, "DESKTOP")
    with_check.tool_check = check
    _write_record(folder.parent, with_check)
    saved = lambda record: json.loads((case.runs_folder / record.run_id / "run.json").read_text(encoding="utf-8"))
    rebuild(case)
    assert saved(with_check)["tool_check"] == check and "tool_check" not in saved(without)
    record = next(r for r in read_runs(case) if r.run_id == with_check.run_id)
    reload_run(case, record, host_layout(case))
    assert saved(with_check)["tool_check"] == check and "tool_check" not in saved(without)
    running = saved(with_check) | {"status": "running"}
    (case.runs_folder / with_check.run_id / "run.json").write_text(json.dumps(running), encoding="utf-8")
    assert [r.run_id for r in close_interrupted(case)] == [with_check.run_id]
    assert saved(with_check)["tool_check"] == check and saved(with_check)["status"] == "failed"


def test_a_run_record_whose_tool_check_has_a_result_word_this_build_does_not_know_is_read(case, tmp_path):
    from glessner.toolbox import overview
    from glessner.tools import load_registry

    _, folder = pecmd_run(case, "DC01")
    path = folder.parent / "run.json"
    check = {"result": "sparkles", "a_later_key": [1, 2]}
    path.write_text(json.dumps({**json.loads(path.read_text(encoding="utf-8")), "tool_check": check}), encoding="utf-8")
    (read,) = read_runs(case)
    assert read.tool_check == check
    (pecmd,) = [t for t in overview(case, load_registry(), {})["tools"] if t["id"] == "pecmd"]
    assert pecmd["last_run"]["latest"]["check"] == check   # shown as written
