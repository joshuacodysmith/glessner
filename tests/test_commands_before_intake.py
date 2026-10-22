"""A command that reads the intake manifest refuses a case that has no intake yet: it prints why and exits 2, as
intake --add and close do, rather than ending in a traceback. Commands that need no manifest still work."""

import sys
from pathlib import Path

import pytest

from glessner import cli
from glessner.case import create_case
from glessner.cli import main
from glessner.tools import DetectedTool

NO_INTAKE = "No intake manifest yet; run intake first."

READS_THE_MANIFEST = {
    "load-output, listing": ["load-output"],
    "load-output, loading": ["load-output", "evtxecmd_csv"],
    "run --all": ["run", "--all"],
    "run --tool": ["run", "--tool", "evtxecmd"],
    "import --list": ["import", "--list"],
    "import a file": ["import", "DC01/fw.log"],
    "import a pattern": ["import", "DC01/*.log", "--preview"],
    "verify": ["verify"],
}


@pytest.fixture
def case(tmp_path, monkeypatch):
    """A case on an evidence folder holding one file, with no intake. Every registry tool counts as installed, so
    run --tool reaches its plan."""
    (tmp_path / "evidence" / "DC01").mkdir(parents=True)
    (tmp_path / "evidence" / "DC01" / "fw.log").write_text("time,src\n2020-09-19T03:21:48Z,10.0.0.1\n", encoding="utf-8")
    monkeypatch.setattr(cli, "detect", lambda specs, folder: {s.id: DetectedTool(s, Path(sys.executable), "1.0") for s in specs})
    return create_case(tmp_path / "case", "No intake", tmp_path / "evidence", "cody")


@pytest.mark.parametrize("command", READS_THE_MANIFEST)
def test_a_command_that_reads_the_manifest_refuses_a_case_with_no_intake(case, capsys, command):
    name, *args = READS_THE_MANIFEST[command]
    journal = (case.folder / "journal.jsonl").read_bytes()
    assert main([name, str(case.folder), *args]) == 2
    captured = capsys.readouterr()
    assert captured.err == f"Error: {NO_INTAKE}\n"
    assert captured.out == ""
    assert not case.manifest_path.exists()
    assert not case.verification_path.exists()
    assert list(case.runs_folder.glob("*")) == []
    assert (case.folder / "journal.jsonl").read_bytes() == journal


def test_verify_of_the_journal_alone_needs_no_intake(case, capsys):
    assert main(["verify", str(case.folder), "--journal"]) == 0
    assert capsys.readouterr().out.startswith("Consistent")
    assert not case.verification_path.exists()


def test_the_commands_that_work_without_intake_still_do(case, capsys):
    folder = str(case.folder)
    assert main(["tools", folder]) == 0
    assert main(["runs", folder]) == 0
    assert main(["close", folder]) == 2
    assert capsys.readouterr().err == "Error: No intake manifest; run intake before closing the case.\n"
    assert main(["intake", folder, "--add"]) == 2
    assert capsys.readouterr().err == f"Error: {NO_INTAKE}\n"
    assert main(["intake", folder]) == 0
    assert main(["load-output", folder]) == 0
    assert "No tool output found in the evidence." in capsys.readouterr().out
