"""The Tools page's job for a load of output found in the evidence reports each group's result: a load that left out every
row, because a tool run's events stand for the files the rows name, says so with the load's own note."""

import time

from test_found_output_sources import LEFT_OUT_NOTE, SAME, SYSTEM_LOG, evtxecmd_run
from test_tool_outputs import EVTX_COLUMNS, evtx_rows, write_rows

from glessner.case import create_case
from glessner.intake import intake
from glessner.runner import READ_ITSELF_NOTE, RunRecord
from glessner.toolbox import _step_result, start_load_job
from glessner.tools import load_registry


def finished(job):
    for _ in range(300):
        if job.finished:
            return job.state()
        time.sleep(0.1)
    raise AssertionError("the job didn't finish")


def case_with_output_for_a_run(tmp_path):
    """WS01's System log and one output file whose rows name it, with an EvtxECmd run on the log whose events stand for it."""
    ev = tmp_path / "evidence"
    (ev / SYSTEM_LOG).parent.mkdir(parents=True)
    (ev / SYSTEM_LOG).write_bytes(b"ElfFile\x00" + SYSTEM_LOG.encode())
    write_rows(ev / SAME, EVTX_COLUMNS, [{**row, "SourceFile": str(ev / SYSTEM_LOG)} for row in evtx_rows("WS01")])
    case = create_case(tmp_path / "case", "Found", ev, "cody")
    intake(case)
    evtxecmd_run(case)
    return case


def test_the_job_box_gives_the_note_of_a_found_load_that_left_out_every_row_as_its_reason(tmp_path):
    """A found-output load whose rows all name a file that a tool run's events stand for loads none of them, records
    status ok with 0 rows, and puts the count and why in its notes. The job's result for the group carries that note, as
    the Case overview's Gaps do, so the box doesn't read as a load that simply found nothing."""
    case = case_with_output_for_a_run(tmp_path)
    job = start_load_job(case, load_registry(), {}, "evtxecmd_csv", None, False, lambda job: None)
    state = finished(job)
    assert state["error"] == ""
    (result,) = state["results"]
    assert (result["host"], result["status"], result["rows"], result["evidence"]) == ("WS01", "ok", 0, "ok")
    assert result["reason"] == LEFT_OUT_NOTE


def test_a_found_load_that_loaded_rows_has_no_reason_and_a_failed_one_keeps_its_own():
    """The note is a reason only for a group that loaded nothing. A group that loaded rows gives none, though its runs
    note rows left out, and a failed run's reason is as it was."""
    def record(status, rows, reason="", notes=()):
        return RunRecord(run_id="r", tool="evtxecmd", tool_version="found output", executable="", host="WS01", argv=[], cwd="",
                         inputs=[SAME], started_utc="", status=status, reason=reason, loaded_rows=rows, notes=list(notes),
                         evidence_check="ok", from_output=True)

    group = {"tool": "evtxecmd", "host": "WS01", "label": "EvtxECmd CSV"}
    assert _step_result("WS01", group, [record("ok", 2, notes=[LEFT_OUT_NOTE])])["reason"] == ""
    failed = _step_result("WS01", group, [record("failed", None, reason="could not load: boom")])
    assert failed["reason"] == "could not load: boom"
    other = f"1 row naming other.evtx was not loaded: a run of this tool read the file itself, {READ_ITSELF_NOTE}"
    two = [record("ok", 0, notes=["x", LEFT_OUT_NOTE]), record("ok", 0, notes=[other, "2 rows weren't records."])]
    assert _step_result("WS01", group, two)["reason"] == f"{LEFT_OUT_NOTE}; {other}"
