"""A run left marked running, as Ctrl+C, a closed window, or a crash leaves it, is marked failed when the case is next
opened for work, so the Gaps list it instead of leaving it out as a run a job may still be running."""

import dataclasses
import json
from pathlib import Path

import pytest
from chain_fixtures import format3_case
from test_cli_refusals import held

from glessner import cli, toolbox
from glessner.case import CaseError
from glessner.runner import finish_run, read_runs, start_run
from glessner.server import App
from glessner.tools import load_registry


def started(case, host, status="running"):
    """A run of the evtxecmd tool on `host`, recorded as the tool starts, then as `status` when that is not running."""
    record, folder = start_run(
        case, "evtxecmd", host, tool_version="2.0", host=host, inputs=[f"{host}/Security.evtx"], parser="evtxecmd_csv"
    )
    if status != "running":
        record.status, record.loaded_rows = status, 5
        finish_run(folder, record)
    return record, folder / "run.json"


def statuses(case):
    return {r.host: r.status for r in read_runs(case)}


@pytest.fixture
def case(synthetic_case):
    """The synthetic case with one run left running on HOST1 and one finished run on HOST2."""
    started(synthetic_case, "HOST1")
    started(synthetic_case, "HOST2", "ok")
    return synthetic_case


def gap_hosts(case):
    return [g["host"] for g in toolbox.run_gaps(read_runs(case), load_registry())]


def test_the_open_for_work_marks_a_run_left_running_as_failed(case):
    finished = next(r for r in read_runs(case) if r.host == "HOST2")
    ok_bytes = (case.runs_folder / finished.run_id / "run.json").read_bytes()
    assert gap_hosts(case) == []  # a run marked running is left out of the Gaps
    app = App(case, for_work=True)
    app.con.close()
    assert statuses(case) == {"HOST1": "failed", "HOST2": "ok"}
    (interrupted,) = (r for r in read_runs(case) if r.host == "HOST1")
    assert interrupted.reason == toolbox.INTERRUPTED and interrupted.finished_utc
    assert (case.runs_folder / finished.run_id / "run.json").read_bytes() == ok_bytes
    (gap,) = toolbox.run_gaps(read_runs(case), load_registry())
    assert (gap["run_id"], gap["host"], gap["status"], gap["reason"]) == (
        interrupted.run_id,
        "HOST1",
        "failed",
        toolbox.INTERRUPTED,
    )


def test_an_open_that_is_not_for_work_leaves_a_running_run_alone(case):
    app = App(case)
    app.con.close()
    assert statuses(case) == {"HOST1": "running", "HOST2": "ok"}


def test_the_open_for_work_stops_at_a_held_events_database_before_it_marks_a_run(case):
    with held(case), pytest.raises(CaseError, match="another program has its events database open"):
        App(case, for_work=True)
    assert statuses(case) == {"HOST1": "running", "HOST2": "ok"}


def test_a_command_line_run_or_load_marks_a_run_left_running_as_failed(case, capsys):
    assert cli._run_and_load(case, [], []) == 0
    assert statuses(case) == {"HOST1": "failed", "HOST2": "ok"}
    (interrupted,) = (r for r in read_runs(case) if r.host == "HOST1")
    assert interrupted.reason == toolbox.INTERRUPTED
    assert interrupted.run_id in capsys.readouterr().out
    assert gap_hosts(case) == ["HOST1"]


def test_a_command_line_run_or_load_stops_at_a_held_events_database_before_it_marks_a_run(case):
    with held(case), pytest.raises(CaseError, match="another program has its events database open"):
        cli._run_and_load(case, [], [])
    assert statuses(case) == {"HOST1": "running", "HOST2": "ok"}


def test_close_interrupted_returns_the_runs_it_marked_and_marks_each_once(case):
    closed = toolbox.close_interrupted(case)
    assert [(r.host, r.status, r.reason) for r in closed] == [("HOST1", "failed", toolbox.INTERRUPTED)]
    assert toolbox.close_interrupted(case) == []


def test_close_interrupted_marks_every_run_left_running(synthetic_case):
    for host in ("HOST1", "HOST2", "HOST3"):
        started(synthetic_case, host)
    assert sorted(r.host for r in toolbox.close_interrupted(synthetic_case)) == ["HOST1", "HOST2", "HOST3"]
    assert set(statuses(synthetic_case).values()) == {"failed"}


UNREADABLE_RECORDS = {
    "a key this build does not read": json.dumps({"future_key": 1}),
    "text that is not JSON": "{not json",
    "an object with no key": "{}",
    "an object missing most keys": json.dumps({"run_id": 1}),
    "a list": "[]",
    "null": "null",
}


@pytest.fixture(params=UNREADABLE_RECORDS.values(), ids=UNREADABLE_RECORDS)
def case_with_an_unreadable_record(case, request):
    """The case, and a third run whose run.json holds `request.param`, which read_runs refuses."""
    _, path = started(case, "HOST3")
    path.write_text(request.param, encoding="utf-8")
    return case


def test_close_interrupted_returns_without_raising_on_a_run_record_it_cannot_read(case_with_an_unreadable_record):
    assert toolbox.close_interrupted(case_with_an_unreadable_record) == []


def test_the_open_for_work_and_a_command_line_run_go_on_past_a_run_record_that_cannot_be_read(
    case_with_an_unreadable_record, capsys
):
    app = App(case_with_an_unreadable_record, for_work=True)
    app.con.close()
    assert cli._run_and_load(case_with_an_unreadable_record, [], []) == 0
    assert "Marked" not in capsys.readouterr().out


def test_close_interrupted_leaves_a_run_that_finishes_after_the_records_are_read(case, monkeypatch):
    """The run's own process writes its final record between this one's read of the records and its write of the mark."""
    real = toolbox.read_runs

    def read_then_finish(case_read):
        records = real(case_read)
        running = next(r for r in records if r.status == "running")
        finish_run(case_read.runs_folder / running.run_id, dataclasses.replace(running, status="ok", loaded_rows=5))
        return records

    monkeypatch.setattr(toolbox, "read_runs", read_then_finish)
    assert toolbox.close_interrupted(case) == []
    (record,) = (r for r in read_runs(case) if r.host == "HOST1")
    assert (record.status, record.loaded_rows, record.reason) == ("ok", 5, "")


def test_close_interrupted_returns_what_it_marked_when_a_record_cannot_be_written(case, monkeypatch):
    started(case, "HOST3")
    real = toolbox.finish_run
    writes = []

    def finish(folder: Path, record):
        if writes:
            raise PermissionError(13, "The process cannot access the file")
        writes.append(record.host)
        real(folder, record)

    monkeypatch.setattr(toolbox, "finish_run", finish)
    closed = toolbox.close_interrupted(case)
    assert [r.host for r in closed] == writes == ["HOST1"]
    assert statuses(case) == {"HOST1": "failed", "HOST2": "ok", "HOST3": "running"}


def test_close_interrupted_keeps_a_tool_check_and_writes_no_format_4_key_below_format_4(synthetic_case):
    """The mark rewrites the record: in a format 4 case its tool_check, which this build doesn't fill, stays as it was,
    and in a case below format 4 the record keeps the shape the builds of its format read."""
    check = {"manifest": "tools.json", "files": {"EvtxECmd.exe": "matches"}, "found": [1, None, "x"]}
    _, path = started(synthetic_case, "HOST1")
    path.write_text(json.dumps({**json.loads(path.read_text(encoding="utf-8")), "tool_check": check}), encoding="utf-8")
    assert [r.host for r in toolbox.close_interrupted(synthetic_case)] == ["HOST1"]
    assert json.loads(path.read_text(encoding="utf-8"))["tool_check"] == check
    below = format3_case(synthetic_case)
    _, path = started(below, "HOST2")
    assert [r.host for r in toolbox.close_interrupted(below)] == ["HOST2"]
    saved = json.loads(path.read_text(encoding="utf-8"))
    assert saved["status"] == "failed" and not {"tool_files", "rows_skipped", "tool_check"} & set(saved)
