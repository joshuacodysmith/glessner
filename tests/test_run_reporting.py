"""How runs are reported: a group load refused before it read anything shows as not checked, one that failed while it
read shows as not read, a run.json that lacks a key is refused by name, and the import command marks the runs an
earlier command left running."""

import json
import time

import pytest
from test_cli_refusals import held
from test_found_output_checks import CSV, MESSAGES, found_case, write_messages
from test_interrupted_runs import started, statuses

from glessner import imports, runner, toolbox
from glessner.case import CaseError
from glessner.cli import main
from glessner.intake import intake
from glessner.runner import NOT_CHECKED, NOT_READ, UNREADABLE, RunRecord, read_runs
from glessner.tools import load_registry

GROUP = {"key": "sbecmd_csv", "host": "HOST", "preset": "", "tool": "sbecmd", "parser": "sbecmd_csv"}


def load_record(check: str) -> RunRecord:
    """The record of a load of found output that ended with `check` as its evidence check."""
    return RunRecord(run_id="", tool="sbecmd", tool_version="found output", executable="", host="HOST", argv=[], cwd="",
                     inputs=[CSV], started_utc="", status="failed" if check != "ok" else "ok", evidence_check=check)


def load_result(case) -> dict:
    """The one step result of the Tools page's job that loads the case's SBECmd found output."""
    job = toolbox.start_load_job(case, load_registry(), {}, "sbecmd_csv", None, False, lambda job: None)
    deadline = time.monotonic() + 60
    while not job.finished and time.monotonic() < deadline:
        time.sleep(0.05)
    assert job.finished and job.error == ""
    (result,) = job.results
    return result


def test_a_load_refused_for_a_messages_file_the_manifest_does_not_list_is_reported_as_not_checked(tmp_path):
    case = found_case(tmp_path)
    write_messages(case.evidence)   # beside the CSV, after intake
    result = load_result(case)
    assert (result["status"], result["rows"], result["loaded"]) == ("failed", 0, False)
    assert MESSAGES in result["reason"] and "Add new evidence" in result["reason"]
    assert result["evidence"] == NOT_CHECKED


def test_a_load_that_fails_while_it_reads_is_reported_as_not_read(tmp_path, monkeypatch):
    case = found_case(tmp_path)

    def refuse(*args, **kwargs):
        raise RuntimeError("the database refused it")

    monkeypatch.setattr(runner, "load", refuse)
    result = load_result(case)
    assert (result["status"], result["loaded"]) == ("failed", False)
    assert "could not load: RuntimeError: the database refused it" in result["reason"]
    assert result["evidence"] == "not read"


@pytest.mark.parametrize(
    ("checks", "reported"),
    [
        (["ok", NOT_CHECKED], NOT_CHECKED),
        ([NOT_CHECKED, "ok"], NOT_CHECKED),
        ([NOT_CHECKED, UNREADABLE], UNREADABLE),
        ([NOT_CHECKED, "mismatch"], "mismatch"),
        ([UNREADABLE, "mismatch", NOT_CHECKED], "mismatch"),
        (["ok", "ok"], "ok"),
        ([""], NOT_READ),
        (["ok", ""], NOT_READ),
        (["", "ok"], NOT_READ),
        (["", NOT_CHECKED], NOT_CHECKED),
        ([UNREADABLE, ""], UNREADABLE),
        (["", "mismatch", "ok"], "mismatch"),
    ],
)
def test_a_group_step_reports_the_most_serious_evidence_check_of_its_runs(checks, reported):
    result = toolbox._step_result("HOST", GROUP, [load_record(check) for check in checks])
    assert result["evidence"] == reported


@pytest.fixture
def case_with_a_record_missing_a_key(synthetic_case):
    """The synthetic case, and a run whose run.json lacks tool_version."""
    record, path = started(synthetic_case, "HOST1")
    data = json.loads(path.read_text(encoding="utf-8"))
    del data["tool_version"]
    path.write_text(json.dumps(data), encoding="utf-8")
    return synthetic_case, record.run_id


def test_a_run_record_that_lacks_a_key_is_refused_naming_the_run_and_the_key(case_with_a_record_missing_a_key):
    case, run_id = case_with_a_record_missing_a_key
    with pytest.raises(CaseError) as refused:
        read_runs(case)
    assert run_id in str(refused.value) and "tool_version" in str(refused.value)


def test_a_run_record_that_lacks_several_keys_names_each(synthetic_case):
    _, path = started(synthetic_case, "HOST1")
    path.write_text(json.dumps({"run_id": path.parent.name, "status": "running"}), encoding="utf-8")
    with pytest.raises(CaseError) as refused:
        read_runs(synthetic_case)
    message = str(refused.value)
    assert path.parent.name in message
    assert "argv, cwd, executable, host, inputs, started_utc, tool, tool_version" in message


@pytest.mark.parametrize("text", ["[]", '["tool"]', "null", "5", '"tool"'])
def test_a_run_record_that_is_not_an_object_is_refused_naming_the_run(synthetic_case, text):
    _, path = started(synthetic_case, "HOST1")
    path.write_text(text, encoding="utf-8")
    with pytest.raises(CaseError, match="isn't a JSON object") as refused:
        read_runs(synthetic_case)
    assert path.parent.name in str(refused.value)


def test_the_runs_command_says_which_run_record_lacks_which_key(case_with_a_record_missing_a_key, capsys):
    case, run_id = case_with_a_record_missing_a_key
    assert main(["runs", str(case.folder)]) == 2
    error = capsys.readouterr().err
    assert error.startswith("Error: ") and run_id in error and "tool_version" in error


def test_closing_interrupted_runs_goes_past_a_record_that_lacks_a_key_without_raising(case_with_a_record_missing_a_key):
    case, _ = case_with_a_record_missing_a_key
    assert toolbox.close_interrupted(case) == []


def test_closing_interrupted_runs_goes_past_a_record_whose_run_id_is_not_text_without_raising(synthetic_case):
    _, path = started(synthetic_case, "HOST1")
    data = json.loads(path.read_text(encoding="utf-8"))
    path.write_text(json.dumps({**data, "run_id": 1}), encoding="utf-8")
    assert toolbox.close_interrupted(synthetic_case) == []


@pytest.fixture
def import_case(synthetic_case):
    """The synthetic case with two CSVs in DC01's folder that the import command loads, hashed at intake, and a run left
    running on HOST1 by a command that stopped."""
    for name in ("notes", "more"):
        csv_file = synthetic_case.evidence / "DC01" / f"{name}.csv"
        csv_file.write_text(f"time,what\n2024-02-05 10:00:00Z,{name}\n", encoding="utf-8")
    intake(synthetic_case)
    started(synthetic_case, "HOST1")
    return synthetic_case


@pytest.fixture
def watched(monkeypatch):
    """What the import command does around its loads: `closes` counts its calls to close_interrupted, and `at_load`
    lists the status of the run left running on HOST1 as each load begins."""
    seen = {"closes": 0, "at_load": []}
    close, load = toolbox.close_interrupted, imports.run_import

    def counted_close(case):
        seen["closes"] += 1
        return close(case)

    def watched_load(case, *args, **kwargs):
        seen["at_load"].append(statuses(case)["HOST1"])
        return load(case, *args, **kwargs)

    monkeypatch.setattr(toolbox, "close_interrupted", counted_close)
    monkeypatch.setattr(imports, "run_import", watched_load)
    return seen


def test_the_import_command_marks_a_run_left_running_as_failed_before_it_loads(import_case, watched, capsys):
    assert main(["import", str(import_case.folder), "DC01/notes.csv"]) == 0
    out = capsys.readouterr().out
    assert "ok: 1 event" in out
    assert watched["at_load"] == ["failed"]
    assert statuses(import_case)["HOST1"] == "failed"
    (interrupted,) = (r for r in read_runs(import_case) if r.host == "HOST1")
    assert interrupted.reason == toolbox.INTERRUPTED and interrupted.finished_utc
    assert "Marked 1 earlier run still recorded as running as failed" in out and interrupted.run_id in out
    assert out.index("Marked ") < out.index("ok: 1 event")


def test_the_import_command_marks_the_runs_once_for_several_files(import_case, watched, capsys):
    assert main(["import", str(import_case.folder), "DC01/*.csv"]) == 0
    out = capsys.readouterr().out
    assert out.count("ok: 1 event") == 2 and out.count("Marked ") == 1
    assert watched["closes"] == 1
    assert watched["at_load"] == ["failed", "failed"]


def test_the_import_command_leaves_a_running_run_alone_when_it_loads_nothing(import_case, capsys):
    folder = str(import_case.folder)
    assert main(["import", folder, "--list"]) == 0
    assert main(["import", folder, "DC01/notes.csv", "--preview"]) == 0
    assert main(["import", folder, "nothing/*.csv"]) == 2
    assert "Marked" not in capsys.readouterr().out
    assert statuses(import_case)["HOST1"] == "running"


def test_the_import_command_marks_no_run_while_another_program_holds_the_events_database(import_case, capsys):
    with held(import_case):
        assert main(["import", str(import_case.folder), "DC01/notes.csv"]) == 2
    assert "another program has its events database open" in capsys.readouterr().err
    assert statuses(import_case)["HOST1"] == "running"
