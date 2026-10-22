"""Which of a host's files a tool reads: the name patterns a tool selects by, and the transaction logs a hive has."""

import json
from dataclasses import replace
from pathlib import Path

import pytest
from test_runner import fake_spec, with_spec

from glessner.case import create_case
from glessner.identify import LNK_CLSID, LNK_HEADER_SIZE, REGF_MAGIC
from glessner.intake import add_new, current_entries, intake
from glessner.runner import RunError, build_argv, inputs_without, plan_runs, run
from glessner.tools import DetectedTool, load_registry

LNK = LNK_HEADER_SIZE + LNK_CLSID + bytes(60)


def lnk_case(tmp_path):
    """HOST holds two LNK files by signature, one named a.lnk and one renamed; ONLY holds renamed ones alone."""
    evidence = tmp_path / "evidence"
    for host, names in (("HOST", ("a.lnk", "renamed.dat")), ("ONLY", ("c.dat", "d.tmp", "e.bin"))):
        (evidence / host).mkdir(parents=True)
        for name in names:
            (evidence / host / name).write_bytes(LNK)
    case = create_case(tmp_path / "case", "Selects", evidence, "cody")
    intake(case)
    return case


def selecting_tool(tmp_path):
    """The fake host_dir tool, reading LNK files by name patterns as LECmd does."""
    tool = with_spec(fake_spec(tmp_path), handles=("lnk",), selects=("*.lnk",))
    return with_spec(tool, args=tool.spec.args[:-1] + ("ok",))


def test_the_registry_names_the_patterns_lecmd_and_pecmd_read():
    specs = load_registry()
    assert (specs["lecmd"].selects, specs["pecmd"].selects) == (("*.lnk",), ("*.pf",))
    assert all(not spec.selects for key, spec in specs.items() if key not in ("lecmd", "pecmd"))


def test_a_plan_names_the_identified_files_the_tool_would_not_read(tmp_path):
    case = lnk_case(tmp_path)
    tool = DetectedTool(load_registry()["lecmd"], Path("LECmd.exe"), "1.5")
    plans = {plan.host: plan for plan in plan_runs(case, tool)}
    assert plans["HOST"].inputs == ("HOST/a.lnk", "HOST/renamed.dat")   # every identified file stays an input
    assert plans["HOST"].left_out == ("HOST/renamed.dat",)
    assert plans["ONLY"].left_out == plans["ONLY"].inputs == ("ONLY/c.dat", "ONLY/d.tmp", "ONLY/e.bin")


def test_a_plan_matches_names_without_regard_to_case(tmp_path):
    evidence = tmp_path / "evidence"
    (evidence / "HOST").mkdir(parents=True)
    (evidence / "HOST" / "Upper.LNK").write_bytes(LNK)
    case = create_case(tmp_path / "case", "Selects", evidence, "cody")
    intake(case)
    (plan,) = plan_runs(case, DetectedTool(load_registry()["lecmd"], Path("LECmd.exe"), "1.5"))
    assert plan.inputs == ("HOST/Upper.LNK",) and plan.left_out == ()


def test_a_tool_without_patterns_leaves_nothing_out(tmp_path):
    case = lnk_case(tmp_path)
    tool = with_spec(selecting_tool(tmp_path), selects=())
    assert {plan.host: plan.left_out for plan in plan_runs(case, tool)} == {"HOST": (), "ONLY": ()}


def test_a_run_notes_the_files_it_left_out_and_keeps_every_input(tmp_path):
    case = lnk_case(tmp_path)
    (plan,) = plan_runs(case, selecting_tool(tmp_path), ["HOST"])
    record = run(case, plan)
    assert record.status == "ok" and record.inputs == ["HOST/a.lnk", "HOST/renamed.dat"]
    (note,) = record.notes
    assert note == ("1 file that intake identified for Fake was not read: it reads only files named *.lnk in a folder, "
                    "and this one is named otherwise: HOST/renamed.dat.")


def test_a_run_whose_every_input_is_left_out_is_refused_before_anything_is_made(tmp_path):
    case = lnk_case(tmp_path)
    (plan,) = plan_runs(case, selecting_tool(tmp_path), ["ONLY"])
    with pytest.raises(RunError, match=r"Fake wasn't run on ONLY: it reads only files named \*\.lnk, and the 3 files intake "
                                       r"identified for it are named otherwise: ONLY/c\.dat; ONLY/d\.tmp; ONLY/e\.bin\."):
        run(case, plan)
    assert not case.runs_folder.exists() or list(case.runs_folder.iterdir()) == []


HIVE = REGF_MAGIC + bytes(100)


def hive_case(tmp_path):
    """HOST holds a user's NTUSER.DAT with both of its transaction logs beside it."""
    evidence = tmp_path / "evidence"
    folder = evidence / "HOST" / "Users" / "u"
    folder.mkdir(parents=True)
    for name in ("NTUSER.DAT", "NTUSER.DAT.LOG1", "NTUSER.DAT.LOG2"):
        (folder / name).write_bytes(HIVE)
    case = create_case(tmp_path / "case", "Hives", evidence, "cody")
    intake(case)
    return case


def add_hive_without_logs(case):
    folder = case.evidence / "HOST" / "Users" / "v"
    folder.mkdir(parents=True)
    (folder / "UsrClass.dat").write_bytes(HIVE)
    add_new(case)


def sbecmd(case, tmp_path):
    (plan,) = plan_runs(case, DetectedTool(load_registry()["sbecmd"], Path("SBECmd.exe"), "1.0"))
    return plan, build_argv(case, plan, tmp_path / "out", {})


def test_sbecmd_reads_transaction_logs_collected_beside_every_hive(tmp_path):
    case = hive_case(tmp_path)
    plan, argv = sbecmd(case, tmp_path)
    assert plan.inputs == ("HOST/Users/u/NTUSER.DAT",)
    assert "--nl" not in argv and "--nl" not in load_registry()["sbecmd"].args


def test_sbecmd_skips_the_logs_when_a_planned_hive_has_none_beside_it(tmp_path):
    case = hive_case(tmp_path)
    add_hive_without_logs(case)
    plan, argv = sbecmd(case, tmp_path)
    assert plan.inputs == ("HOST/Users/u/NTUSER.DAT", "HOST/Users/v/UsrClass.dat")
    assert argv[-1] == "--nl"


def test_a_log_named_for_another_hive_is_not_beside_the_hive(tmp_path):
    case = hive_case(tmp_path)
    folder = case.evidence / "HOST" / "Users" / "v"
    folder.mkdir(parents=True)
    (folder / "UsrClass.dat").write_bytes(HIVE)
    (folder / "NTUSER.DAT.LOG1").write_bytes(HIVE)   # named for a hive that isn't here
    add_new(case)
    assert "--nl" in sbecmd(case, tmp_path)[1]


def test_a_log_in_another_folder_is_not_beside_a_hive_of_the_same_name(tmp_path):
    case = hive_case(tmp_path)   # HOST/Users/u/NTUSER.DAT, with its logs
    folder = case.evidence / "HOST" / "Users" / "v"
    folder.mkdir(parents=True)
    (folder / "NTUSER.DAT").write_bytes(HIVE)   # another user's hive, with no logs beside it
    add_new(case)
    plan, argv = sbecmd(case, tmp_path)
    assert plan.inputs == ("HOST/Users/u/NTUSER.DAT", "HOST/Users/v/NTUSER.DAT")
    assert argv[-1] == "--nl"
    assert inputs_without(case, plan, "registry_log") == ["HOST/Users/v/NTUSER.DAT"]


def test_a_log_whose_entry_carries_an_error_is_not_beside_the_hive(tmp_path, monkeypatch):
    case = hive_case(tmp_path)
    entries = [replace(e, error="unreadable") if e.artifact == "registry_log" else e for e in current_entries(case)]
    monkeypatch.setattr("glessner.runner.current_entries", lambda _: entries)
    assert "--nl" in sbecmd(case, tmp_path)[1]


APPEND_TO_A_FILE = """
import pathlib, sys
host_dir, out_dir, name = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]), sys.argv[3]
target = next(p for p in host_dir.rglob('*') if p.name.lower() == name)
target.write_bytes(target.read_bytes() + b'changed')
(out_dir / 'out.txt').write_text('x')
"""


def logging_tool(tmp_path, changes=None):
    """The fake host_dir tool on the user hives, which takes --nl when a hive has no log beside it, as SBECmd does. With
    `changes`, the lower-case name of a file, the tool appends to that file instead of reading."""
    tool = with_spec(fake_spec(tmp_path), handles=("registry:NTUSER", "registry:USRCLASS"),
                     without_related=({"artifact": "registry_log", "args": ["--nl"]},))
    if changes is None:
        return with_spec(tool, args=tool.spec.args[:-1] + ("ok",))
    script = tmp_path / "append_to_a_file.py"
    script.write_text(APPEND_TO_A_FILE)
    return with_spec(tool, args=(str(script), "{host_dir}", "{output_dir}", changes), options=())


def last_check(case):
    """The latest line of the case's verification record."""
    return json.loads(case.verification_path.read_text(encoding="utf-8").splitlines()[-1])


def test_a_run_with_the_argument_notes_the_hives_that_have_no_log(tmp_path):
    case = hive_case(tmp_path)
    add_hive_without_logs(case)
    (plan,) = plan_runs(case, logging_tool(tmp_path))
    record = run(case, plan)
    assert record.status == "ok" and record.argv[-1] == "--nl"
    assert record.notes == ["Ran with --nl, so Fake skipped the transaction logs of every hive on this host: "
                            "HOST/Users/v/UsrClass.dat has none beside it."]


def test_a_run_without_the_argument_has_no_such_note(tmp_path):
    case = hive_case(tmp_path)
    (plan,) = plan_runs(case, logging_tool(tmp_path))
    record = run(case, plan)
    assert record.status == "ok" and "--nl" not in record.argv and record.notes == []


def test_a_log_the_tool_reads_is_covered_by_the_evidence_check_though_it_is_not_an_input(tmp_path):
    case = hive_case(tmp_path)
    (plan,) = plan_runs(case, logging_tool(tmp_path, "ntuser.dat.log1"))
    record = run(case, plan)
    assert "--nl" not in record.argv and record.inputs == ["HOST/Users/u/NTUSER.DAT"]
    assert (record.status, record.evidence_check) == ("failed", "mismatch")
    assert record.evidence_problems == ["HOST/Users/u/NTUSER.DAT.LOG1: SHA-256 changed"]


def test_a_changed_hive_still_fails_the_evidence_check(tmp_path):
    case = hive_case(tmp_path)
    (plan,) = plan_runs(case, logging_tool(tmp_path, "ntuser.dat"))
    record = run(case, plan)
    assert record.evidence_problems == ["HOST/Users/u/NTUSER.DAT: SHA-256 changed"]


def test_the_check_after_a_run_covers_the_logs_only_when_the_tool_reads_them(tmp_path):
    case = hive_case(tmp_path)
    run(case, plan_runs(case, logging_tool(tmp_path))[0])
    assert last_check(case)["files_checked"] == 3   # the hive and its two logs
    add_hive_without_logs(case)
    run(case, plan_runs(case, logging_tool(tmp_path))[0])
    assert last_check(case)["files_checked"] == 2   # --nl: the two hives alone
