"""A rebuild that fails, in a case whose events database is missing or holds no events, leaves each run's record saying
that no database holds its rows."""

import pytest

from glessner import runner
from glessner.case import create_case
from glessner.events import Event, connect, load
from glessner.intake import intake
from glessner.runner import LEFT_OUT, UNFINISHED_NOTE, read_runs


def case_with_one_run(tmp_path):
    (tmp_path / "evidence" / "HOST").mkdir(parents=True)
    (tmp_path / "evidence" / "HOST" / "a.txt").write_text("evidence")
    case = create_case(tmp_path / "case", "Rebuild", tmp_path / "evidence", "cody")
    intake(case)
    record, folder = runner.start_run(case, "evtxecmd", "HOST", tool_version="1.0", host="HOST", parser="evtxecmd_csv",
                                      inputs=["HOST/a.txt"])
    record.status, record.loaded_rows = "ok", 5
    runner.finish_run(folder, record)
    return case


def fail_to_load(monkeypatch):
    def refuse(*args, **options):
        raise RuntimeError("the load stopped")

    monkeypatch.setattr(runner, "_reload", refuse)


def test_a_failed_rebuild_with_an_empty_database_leaves_the_run_with_no_rows_and_a_note(tmp_path, monkeypatch):
    case = case_with_one_run(tmp_path)
    connect(case.db_path).close()   # a copy of an older case gets an empty database from its upgrade
    fail_to_load(monkeypatch)
    with pytest.raises(RuntimeError, match="the load stopped"):
        runner.rebuild(case)
    (saved,) = read_runs(case)
    assert saved.loaded_rows == 0
    assert saved.notes[-1].endswith(UNFINISHED_NOTE) and LEFT_OUT in saved.notes[-1]


def test_a_failed_rebuild_with_no_database_leaves_the_run_with_no_rows_and_a_note(tmp_path, monkeypatch):
    case = case_with_one_run(tmp_path)
    assert not case.db_path.exists()
    fail_to_load(monkeypatch)
    with pytest.raises(RuntimeError, match="the load stopped"):
        runner.rebuild(case)
    (saved,) = read_runs(case)
    assert saved.loaded_rows == 0 and saved.notes[-1].endswith(UNFINISHED_NOTE)


def test_a_failed_rebuild_of_a_database_with_events_leaves_the_record_as_it_was(tmp_path, monkeypatch):
    case = case_with_one_run(tmp_path)
    (record,) = read_runs(case)
    event = Event(ts_us=1600485708000000, ts_desc="Event Recorded", artifact="evtx", source_file="HOST/a.txt",
                  source_record="1", message="4624 logon")
    load(case.db_path, [event], host="HOST", tool="evtxecmd", tool_version="1", run_id=record.run_id,
         replaces_sources=["HOST/a.txt"], staging_dir=tmp_path)
    fail_to_load(monkeypatch)
    with pytest.raises(RuntimeError, match="the load stopped"):
        runner.rebuild(case)
    (saved,) = read_runs(case)
    assert saved.loaded_rows == 5 and saved.notes == []
    con = connect(case.db_path, read_only=True)
    try:
        assert con.execute("SELECT count(*) FROM events").fetchone() == (1,)
    finally:
        con.close()
