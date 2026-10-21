"""Commands that refuse print why and exit 2 before they change the case: a case whose events database another program
holds, as `glessner serve` does, a rule file the command can't read, and a mapping name import can't save."""

import subprocess
import sys
from contextlib import contextmanager

import pytest
from test_server import fake_tool_case
from test_tool_outputs import EVTX_COLUMNS, evtx_rows, write_rows

from glessner import cli
from glessner.cli import main
from glessner.runner import read_runs
from glessner.tools import load_registry

HOLD = "import sys, duckdb; con = duckdb.connect(sys.argv[1]); print('held', flush=True); sys.stdin.read()"
HELD = "another program has its events database open"


@contextmanager
def held(case):
    """The case's events database held open by another process, as glessner serving the case holds it."""
    holder = subprocess.Popen([sys.executable, "-c", HOLD, str(case.db_path)], stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, text=True)
    try:
        assert holder.stdout.readline().strip() == "held"
        yield
    finally:
        holder.communicate("", timeout=60)


LOADS = {"run --tool": ["run", "--tool", "fake"], "run --all": ["run", "--all"],
         "load-output": ["load-output", "evtxecmd_csv"]}


@pytest.mark.parametrize("command", LOADS)
def test_a_run_or_load_refuses_before_its_first_step_while_another_program_holds_the_case(
        synthetic_case, tmp_path, monkeypatch, capsys, command):
    """run and load-output check the events database before the first tool starts or the first output loads, so a
    server holding it costs no tool run and leaves no failed run behind. The refusal says to stop the server."""
    case = synthetic_case
    write_rows(case.evidence / "DESKTOP" / "Modules" / "EventLogs" / "x_EvtxECmd_Output.csv", EVTX_COLUMNS,
               evtx_rows("DESKTOP"))
    specs, detected = fake_tool_case(case, tmp_path)   # DC01's event log, for the stand-in tool
    monkeypatch.setattr(cli, "load_registry", lambda: {**load_registry(), **specs})
    monkeypatch.setattr(cli, "detect", lambda specs, folder: detected)
    name, *args = LOADS[command]
    with held(case):
        assert main([name, str(case.folder), *args]) == 2
    err = capsys.readouterr().err
    assert HELD in err and "Stop the server" in err
    assert read_runs(case) == []


@pytest.mark.parametrize("argv", [["export"], ["findings"], ["rule", "list"], ["serve", "--no-browser", "--port", "0"]])
def test_a_command_that_opens_the_case_refuses_while_another_program_holds_it(synthetic_case, capsys, argv):
    """export, findings, rule, and serve open the case as the server does. With its events database held they print
    why and exit 2, with the journal as it was."""
    case = synthetic_case
    journal = (case.folder / "journal.jsonl").read_bytes()
    with held(case):
        assert main([argv[0], str(case.folder), *argv[1:]]) == 2
    assert HELD in capsys.readouterr().err
    assert (case.folder / "journal.jsonl").read_bytes() == journal


def test_import_refuses_a_save_as_name_before_it_imports_anything(synthetic_case, capsys):
    """--save-as is checked before the first file is imported, with save_mapping's own message, so a name it would
    refuse leaves no run, no events, and no saved mapping behind the error."""
    from glessner.events import connect
    from glessner.imports import MappingError, save_mapping
    from glessner.intake import intake

    case = synthetic_case
    (case.evidence / "DC01" / "fw.csv").write_text("time,src\n2020-09-19T03:21:48Z,194.61.24.102\n", encoding="utf-8")
    intake(case)
    with pytest.raises(MappingError) as refused:
        save_mapping(case, "Palo Alto traffic", {})
    assert main(["import", str(case.folder), "DC01/fw.csv", "--save-as", "Palo Alto traffic"]) == 2
    assert capsys.readouterr().err == f"Error: {refused.value}\n"
    assert read_runs(case) == []
    con = connect(case.db_path, read_only=True)
    try:
        assert con.execute("SELECT count(*) FROM events WHERE source_file = 'DC01/fw.csv'").fetchone()[0] == 0
    finally:
        con.close()
    assert not (case.folder / "mappings").exists()


@pytest.mark.parametrize("op", ["add", "change"])
def test_rule_add_or_change_names_a_rule_file_it_cannot_read(synthetic_case, tmp_path, capsys, op):
    """A missing YAML file, or a folder, is refused with its path before the case is opened."""
    journal = (synthetic_case.folder / "journal.jsonl").read_bytes()
    for target in (tmp_path / "typo.yaml", tmp_path):
        assert main(["rule", str(synthetic_case.folder), op, str(target)]) == 2
        assert str(target) in capsys.readouterr().err
    assert (synthetic_case.folder / "journal.jsonl").read_bytes() == journal
