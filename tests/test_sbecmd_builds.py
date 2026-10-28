"""SBECmd's registry entry run with a stand-in for each kind of build. Builds before 2026.10 write !SBECmd_Messages.txt,
and later ones write <stamp>_SBECmd_<version>_ConsoleLog.txt in its place. A run passes and loads its events with either,
and fails when the build wrote neither, since its parser could not name the hive of any CSV."""

import csv
import sys
from dataclasses import replace
from pathlib import Path

import pytest
from sbecmd_log_fixtures import CONSOLE_LOG_NAME, MESSAGES_NAME, console_log_text, messages_text
from test_tool_outputs import SBE_COLUMNS

from glessner.case import create_case
from glessner.identify import REGF_MAGIC
from glessner.intake import intake
from glessner.runner import plan_runs, run
from glessner.tools import DetectedTool, load_registry

STAND_IN = """
import pathlib, shutil, sys
prepared, out_dir, log = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]), sys.argv[3]
shutil.copy(prepared / 'alice_UsrClass.csv', out_dir)
if log:
    shutil.copy(prepared / log, out_dir)
"""
HIVE_FOLDER = ("HOST", "Users", "alice", "AppData", "Local", "Microsoft", "Windows")
BAG = {"BagPath": "BagMRU\\0", "Slot": "1", "AbsolutePath": "Desktop\\This PC\\C:\\Tools", "ShellType": "Directory",
       "FirstInteracted": "2024-05-14 12:06:00"}


@pytest.fixture
def hive_case(tmp_path):
    folder = tmp_path / "evidence" / Path(*HIVE_FOLDER)
    folder.mkdir(parents=True)
    for name in ("UsrClass.dat", "UsrClass.dat.LOG1", "UsrClass.dat.LOG2"):
        (folder / name).write_bytes(REGF_MAGIC + bytes(100))
    case = create_case(tmp_path / "case", "Builds", tmp_path / "evidence", "cody")
    intake(case)
    return case


def stand_in(tmp_path, case, log_name) -> DetectedTool:
    """The registry's SBECmd, started as a script that copies a CSV for the hive, and the named log, if any, into its
    output folder."""
    prepared = tmp_path / "prepared"
    prepared.mkdir()
    hive = str(case.evidence / Path(*HIVE_FOLDER) / "UsrClass.dat")
    exported = r"C:\out\alice_UsrClass.csv"
    (prepared / MESSAGES_NAME).write_text(messages_text(hive, exported), encoding="utf-8", newline="")
    (prepared / CONSOLE_LOG_NAME).write_text(console_log_text(hive, exported), encoding="utf-8", newline="")
    with (prepared / "alice_UsrClass.csv").open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=SBE_COLUMNS)
        writer.writeheader()
        writer.writerow(BAG)
    script = tmp_path / "stand_in.py"
    script.write_text(STAND_IN, encoding="utf-8")
    spec = replace(load_registry()["sbecmd"], args=(str(script), str(prepared), "{output_dir}", log_name))
    return DetectedTool(spec, Path(sys.executable), "stand-in")


@pytest.mark.parametrize("log_name", [MESSAGES_NAME, CONSOLE_LOG_NAME])
def test_a_run_loads_its_shellbags_with_either_build_s_record_of_the_run(tmp_path, hive_case, log_name):
    tool = stand_in(tmp_path, hive_case, log_name)
    (plan,) = plan_runs(hive_case, tool)
    record = run(hive_case, plan)
    assert (record.status, record.reason, record.loaded_rows) == ("ok", "", 1)
    assert sorted(o["path"] for o in record.outputs) == sorted(["alice_UsrClass.csv", log_name])


def test_a_run_that_leaves_neither_record_of_the_run_fails(tmp_path, hive_case):
    tool = stand_in(tmp_path, hive_case, "")
    (plan,) = plan_runs(hive_case, tool)
    record = run(hive_case, plan)
    assert record.status == "failed" and record.loaded_rows is None
    assert "expected output missing or unreadable: !SBECmd_Messages.txt or *_SBECmd_*_ConsoleLog.txt." in record.reason
