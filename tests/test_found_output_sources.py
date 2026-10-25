"""Output found in the evidence names the files its tool read, which its load never reads. A load of it replaces only
rows that earlier loads of found output of the same tool put on the same host, and only for a file under that host's
folder or for output it reads again. It leaves out rows naming a file whose events a run of its tool on the host loaded
itself, since they have the same IDs. Its events cite the hash of the output their run read, not of the file they
name."""

import json
import shutil
import subprocess
import sys
from contextlib import contextmanager
from dataclasses import replace

import duckdb
import pytest
from conftest import junction
from rekey_fixtures import eve_records
from test_tool_outputs import EVTX_COLUMNS, evtx_rows, write_rows

from glessner import runner
from glessner.case import create_case
from glessner.events import _extended_forms, connect
from glessner.intake import add_new, intake, read_manifest, verify
from glessner.runner import (
    RunRecord,
    _check_outputs,
    _write_record,
    load_found_output,
    load_output,
    read_run,
    read_runs,
    rebuild,
)
from glessner.server import App, api_event
from glessner.toolbox import run_gaps
from glessner.tools import load_registry

LOG = "WS01/Windows/System32/winevt/Logs/Security.evtx"
SYSTEM_LOG = "WS01/Windows/System32/winevt/Logs/System.evtx"   # the log the EvtxECmd run below reads
# EvtxECmd output in WS01's folder whose rows name WS01's Security log by its path in the evidence
FOUND = "WS01/Modules/EventLogs/20240514_EvtxECmd_Output.csv"
AGAIN = "WS01/Modules/Copy/20240514_EvtxECmd_Output.csv"   # the same rows in a second file
# Output whose rows name the System log's records that the EvtxECmd run reads, so they take the IDs of the run's events
SAME = "WS01/Modules/Same/20240514_EvtxECmd_Output.csv"
# KAPE's output as KAPE writes it, whose rows name the log where KAPE read it, outside the evidence
KAPE = "WS01/Modules/Kape/20240514_EvtxECmd_Output.csv"
# On WS02, output whose rows name WS01's log, and output whose rows name the same file outside the evidence, two of each
OTHER_HOST = ("WS02/Modules/A/20240514_EvtxECmd_Output.csv", "WS02/Modules/B/20240514_EvtxECmd_Output.csv")
OUTSIDE = ("WS02/Modules/C/20240514_EvtxECmd_Output.csv", "WS02/Modules/D/20240514_EvtxECmd_Output.csv")


def found_case(tmp_path):
    """A two-host case built without running any tools: WS01 holds its Security and System logs, and WS01 and WS02 the
    output above."""
    ev = tmp_path / "evidence"
    for rel in (LOG, SYSTEM_LOG):
        (ev / rel).parent.mkdir(parents=True, exist_ok=True)
        (ev / rel).write_bytes(b"ElfFile\x00" + rel.encode())
    naming_the_log = [{**row, "SourceFile": str(ev / LOG)} for row in evtx_rows("WS01", records=(3, 4))]
    for rel in (FOUND, AGAIN, *OTHER_HOST):
        write_rows(ev / rel, EVTX_COLUMNS, naming_the_log)
    write_rows(ev / SAME, EVTX_COLUMNS, [{**row, "SourceFile": str(ev / SYSTEM_LOG)} for row in evtx_rows("WS01")])
    for rel in (KAPE, *OUTSIDE):
        write_rows(ev / rel, EVTX_COLUMNS, evtx_rows("WS01", records=(5, 6)))
    case = create_case(tmp_path / "case", "Found", ev, "cody")
    intake(case)
    return case


def evtxecmd_run(case, run_id="20240101T000000Z_evtxecmd_WS01", inputs=(SYSTEM_LOG,)):
    """An ok EvtxECmd run on WS01 whose output names its System log, written and hashed as runner.run records them,
    and loaded. Its inputs are the System log unless given."""
    folder = case.runs_folder / run_id
    output = folder / "output"
    output.mkdir(parents=True)
    write_rows(output / "evtxecmd.csv", EVTX_COLUMNS,
               [{**row, "SourceFile": str(case.evidence / SYSTEM_LOG)} for row in evtx_rows("WS01")])
    record = RunRecord(run_id=folder.name, tool="evtxecmd", tool_version="1.5", executable="", host="WS01", argv=[],
                       cwd="", inputs=list(inputs), started_utc="", status="ok", parser="evtxecmd_csv",
                       evidence_root=str(case.evidence))
    _check_outputs(load_registry()["evtxecmd"], output, record)
    load_output(case, record, folder)
    _write_record(folder, record)
    return record


def load(case, host, *files):
    """A load of EvtxECmd output found on the host, which succeeds."""
    record = load_found_output(case, "evtxecmd", "evtxecmd_csv", host, list(files))
    assert (record.status, record.reason) == ("ok", "")
    return record


def rows_by_run(case):
    con = connect(case.db_path, read_only=True)
    try:
        return dict(con.execute("SELECT run_id, count(*) FROM events GROUP BY 1").fetchall())
    finally:
        con.close()


def shared_ids(case):
    """The event IDs that more than one row holds."""
    con = connect(case.db_path, read_only=True)
    try:
        return con.execute("SELECT event_uid FROM events GROUP BY 1 HAVING count(*) > 1").fetchall()
    finally:
        con.close()


LEFT_OUT_NOTE = (f"2 rows naming {SYSTEM_LOG} were not loaded: a run of this tool on the host read the file itself, and "
                 "that run's events stand for it.")


def test_found_output_naming_a_file_a_tool_run_read_loads_none_of_its_rows(tmp_path):
    """Found output on WS01 whose rows name the System log an EvtxECmd run on WS01 read, record for record, would give
    those rows the IDs of the run's events. The load leaves them out and says so in a note, so each ID holds one row,
    the run's, which stays. Its rows naming another file load, and a rebuild gives the same rows."""
    case = found_case(tmp_path)
    direct = evtxecmd_run(case)
    found = load(case, "WS01", SAME, FOUND)
    assert (found.loaded_rows, found.replaced_rows) == (2, 0)
    assert LEFT_OUT_NOTE in found.notes
    assert rows_by_run(case) == {direct.run_id: 2, found.run_id: 2}
    assert shared_ids(case) == []
    rebuild(case)
    assert rows_by_run(case) == {direct.run_id: 2, found.run_id: 2}
    assert shared_ids(case) == []
    assert read_run(case, found.run_id).notes.count(LEFT_OUT_NOTE) == 1


def test_a_tool_run_replaces_found_rows_naming_its_file_and_a_rebuild_does_the_same(tmp_path):
    """Found output loaded on WS01 before an EvtxECmd run on the System log it names: the run replaces those rows, as it
    replaces its own on a rerun. A rebuild loads the two in the same order, by run ID, so it gives the same rows, and
    each run's record the same counts."""
    case = found_case(tmp_path)
    found = load(case, "WS01", SAME)
    direct = evtxecmd_run(case, "20990101T000000Z_evtxecmd_WS01")
    assert (found.loaded_rows, direct.replaced_rows) == (2, 2)
    assert rows_by_run(case) == {direct.run_id: 2}
    rebuild(case)
    assert rows_by_run(case) == {direct.run_id: 2}
    found_record, direct_record = read_run(case, found.run_id), read_run(case, direct.run_id)
    assert (found_record.loaded_rows, direct_record.replaced_rows) == (2, 2)
    assert LEFT_OUT_NOTE not in found_record.notes


def test_found_rows_load_once_a_rebuild_leaves_out_the_tool_run_whose_events_stood_for_their_file(tmp_path):
    """While an EvtxECmd run's events stand for the System log, found output naming the log loads none of its rows.
    Once the run's output changes, a rebuild leaves the run out, and the found rows load, so the log keeps its events.
    A load of the output again then replaces them."""
    case = found_case(tmp_path)
    direct = evtxecmd_run(case)
    found = load(case, "WS01", SAME)
    assert rows_by_run(case) == {direct.run_id: 2}
    with (case.runs_folder / direct.run_id / "output" / "evtxecmd.csv").open("ab") as f:
        f.write(b"\n")
    rebuild(case)
    assert read_run(case, direct.run_id).loaded_rows == 0
    assert rows_by_run(case) == {found.run_id: 2}
    record = read_run(case, found.run_id)
    assert (record.loaded_rows, LEFT_OUT_NOTE in record.notes) == (2, False)
    again = load(case, "WS01", SAME)
    assert (again.loaded_rows, again.replaced_rows) == (2, 2)
    assert rows_by_run(case) == {again.run_id: 2}


def test_found_rows_load_when_the_tool_run_on_their_file_failed(tmp_path):
    """A failed EvtxECmd run on the System log loaded no events, so none stand for the log, and found output naming it
    loads its rows."""
    case = found_case(tmp_path)
    failed = RunRecord(run_id="20240101T000000Z_evtxecmd_WS01", tool="evtxecmd", tool_version="1.5", executable="",
                       host="WS01", argv=[], cwd="", inputs=[SYSTEM_LOG], started_utc="", status="failed",
                       reason="exited with code 1", parser="evtxecmd_csv")
    (case.runs_folder / failed.run_id).mkdir(parents=True)
    _write_record(case.runs_folder / failed.run_id, failed)
    found = load(case, "WS01", SAME)
    assert found.loaded_rows == 2
    assert rows_by_run(case) == {found.run_id: 2}


def test_found_rows_load_when_the_tool_run_that_listed_their_file_loaded_no_events_from_it(tmp_path):
    """A run's inputs can list a file it loaded no events from, such as one its tool's name patterns skip. Found output
    whose rows name that file loads them, since no event of the run stands for it."""
    case = found_case(tmp_path)
    direct = evtxecmd_run(case, inputs=(SYSTEM_LOG, LOG))   # its output names the System log alone
    found = load(case, "WS01", FOUND)
    assert found.loaded_rows == 2
    assert rows_by_run(case) == {direct.run_id: 2, found.run_id: 2}


def test_a_found_load_whose_rows_a_tool_runs_events_stand_for_says_why_in_the_gaps(tmp_path):
    """A load of found output whose every row names the System log, which an EvtxECmd run's events stand for, loads
    nothing. The overview's Gaps and the Tools page list it with its note as the reason."""
    case = found_case(tmp_path)
    evtxecmd_run(case)
    found = load(case, "WS01", SAME)
    assert found.loaded_rows == 0
    gaps = run_gaps(read_runs(case), load_registry())
    assert [(gap["run_id"], gap["status"], gap["reason"]) for gap in gaps] == [(found.run_id, "ok", LEFT_OUT_NOTE)]


def test_a_second_load_of_found_output_on_the_host_replaces_the_first(tmp_path):
    """Loading the same output on WS01 again replaces the first load's rows, both those naming the log in WS01's folder
    and those naming KAPE's path outside the evidence, and leaves the EvtxECmd run's rows as they are. Other output whose
    rows name a file in WS01's folder replaces the rows naming that file."""
    case = found_case(tmp_path)
    direct = evtxecmd_run(case)
    first = load(case, "WS01", FOUND, KAPE)
    again = load(case, "WS01", FOUND, KAPE)
    assert (first.replaced_rows, again.loaded_rows, again.replaced_rows) == (0, 4, 4)
    assert rows_by_run(case) == {direct.run_id: 2, again.run_id: 4}
    copy = load(case, "WS01", AGAIN)
    assert copy.replaced_rows == 2
    assert rows_by_run(case) == {direct.run_id: 2, again.run_id: 2, copy.run_id: 2}


def test_a_load_of_more_files_replaces_the_earlier_load_whole(tmp_path):
    """Once Add new evidence puts another output file in a host's group, the group's next load reads every file the
    earlier load read, and more, so it replaces the earlier load's rows whole, those naming KAPE's path outside the
    evidence included."""
    case = found_case(tmp_path)
    load(case, "WS01", KAPE)
    second = load(case, "WS01", FOUND, KAPE)
    assert (second.loaded_rows, second.replaced_rows) == (4, 2)
    assert rows_by_run(case) == {second.run_id: 4}


def test_a_load_of_fewer_files_keeps_the_rows_of_files_it_does_not_read(tmp_path):
    """A load of one of the two files an earlier load read replaces the earlier rows naming the log in WS01's folder,
    which its own rows name, and keeps the rows naming KAPE's path, which the earlier load read from the other file."""
    case = found_case(tmp_path)
    first = load(case, "WS01", FOUND, KAPE)
    second = load(case, "WS01", FOUND)
    assert (second.loaded_rows, second.replaced_rows) == (2, 2)
    assert rows_by_run(case) == {first.run_id: 2, second.run_id: 2}


def test_a_reload_replaces_a_load_that_failed_its_check_after_loading(tmp_path):
    """A load of found output that put its rows in and then failed its check, as when the evidence changed while it was
    read, keeps its rows until the next load of the same output, which replaces them whole."""
    case = found_case(tmp_path)
    first = load(case, "WS01", FOUND, KAPE)
    first.status, first.reason = "failed", "evidence changed while it was read"
    _write_record(case.runs_folder / first.run_id, first)
    again = load(case, "WS01", FOUND, KAPE)
    assert (again.loaded_rows, again.replaced_rows) == (4, 4)
    assert rows_by_run(case) == {again.run_id: 4}


def test_a_path_outside_the_loading_hosts_folder_replaces_nothing(tmp_path):
    """On WS02, output whose rows name WS01's Security log, or a file outside the evidence, loads, and later output
    naming the same files replaces none of its rows."""
    case = found_case(tmp_path)
    for first, second in (OTHER_HOST, OUTSIDE):
        earlier = load(case, "WS02", first)
        later = load(case, "WS02", second)
        assert (earlier.loaded_rows, later.loaded_rows, later.replaced_rows) == (2, 2, 0)
        assert {earlier.run_id: 2, later.run_id: 2}.items() <= rows_by_run(case).items()


def test_a_single_host_cases_host_folder_is_the_evidence_folder(tmp_path):
    """In a single-host case, whose files sit at the top of the evidence folder, other output whose rows name the host's
    Security log replaces the rows naming it, as on a host of a multi-host case."""
    ev = tmp_path / "evidence"
    log = ev / "Windows" / "System32" / "winevt" / "Logs" / "Security.evtx"
    log.parent.mkdir(parents=True)
    log.write_bytes(b"ElfFile\x00raw")
    outputs = ("Modules/A/20240514_EvtxECmd_Output.csv", "Modules/B/20240514_EvtxECmd_Output.csv")
    for rel in outputs:
        write_rows(ev / rel, EVTX_COLUMNS, [{**row, "SourceFile": str(log)} for row in evtx_rows("WS01", records=(3, 4))])
    case = create_case(tmp_path / "case", "Single", ev, "cody", single_host="WS01")
    intake(case)
    first = load(case, "WS01", outputs[0])
    second = load(case, "WS01", outputs[1])
    assert (first.loaded_rows, second.loaded_rows, second.replaced_rows) == (2, 2, 2)
    assert rows_by_run(case) == {second.run_id: 2}


def test_found_output_events_keep_their_ids(tmp_path):
    """A found-output event's ID is made from the host, the artifact, the source file and record its row names, and its
    time's description, whichever run loads it, so the IDs of these rows are fixed values."""
    case = found_case(tmp_path)
    load(case, "WS01", FOUND, KAPE)
    con = connect(case.db_path, read_only=True)
    try:
        ids = con.execute("SELECT source_file, source_record, event_uid FROM events ORDER BY 1, 2").fetchall()
    finally:
        con.close()
    kape = "D:/KAPE/tout/C/Windows/System32/winevt/Logs/Security.evtx"
    assert ids == [(kape, "105", "46a750c3e0f79aa867b6536c813ed901"), (kape, "106", "9ab896a3991c50e5d542597709633e61"),
                   (LOG, "103", "d728193fe18a0707c6a4179120060c7c"), (LOG, "104", "c3c0e17bad1b8f389fb01625f813fd12")]


def event_on_page(app, run_id):
    """The Event page's answer for an event the run loaded."""
    uid = app.con.execute("SELECT event_uid FROM events WHERE run_id = ? ORDER BY event_uid LIMIT 1",
                          [run_id]).fetchone()[0]
    return api_event(app, {"uid": [uid]})["event"]


def test_a_found_output_event_cites_the_output_its_run_read_not_the_file_it_names(tmp_path):
    """An event of found output names WS01's Security log, which its load never read. Its page shows the hash of the
    output file its run read and hashed, named, on WS01 and on WS02 alike, and an event of the EvtxECmd run that read the
    System log shows the log's hash."""
    case = found_case(tmp_path)
    direct = evtxecmd_run(case)
    found = [load(case, "WS01", FOUND), load(case, "WS02", OTHER_HOST[0])]
    app = App(case)
    try:
        log_sha = app.manifest[LOG]
        for record in found:
            (output,) = record.inputs
            event = event_on_page(app, record.run_id)
            assert event["source_file"] == LOG
            assert event["evidence_sha256"] == event["provenance"]["sha256"] == app.manifest[output] != log_sha
            assert (event["provenance"]["state"], event["provenance"]["text"], event["provenance"]["files"]) == (
                "matches", "of the output file 20240514_EvtxECmd_Output.csv: matches intake", [output])
        ours = event_on_page(app, direct.run_id)
        system_sha = app.manifest[SYSTEM_LOG]
        assert (ours["source_file"], ours["evidence_sha256"]) == (SYSTEM_LOG, system_sha)
        assert ours["provenance"] | {"checks": 0} == {"sha256": system_sha, "state": "matches", "text": "matches intake",
                                                      "checks": 0, "unreadable_lines": 0, "files": [SYSTEM_LOG]}
    finally:
        app.con.close()


def test_an_event_of_found_output_read_from_several_files_names_them_all(tmp_path):
    """A load of two output files can't say which one an event came from, so its page names both and cites no one hash,
    and says when one of them differs from intake."""
    case = found_case(tmp_path)
    record = load(case, "WS01", FOUND, KAPE)
    app = App(case)
    try:
        provenance = event_on_page(app, record.run_id)["provenance"]
        assert (provenance["state"], provenance["text"]) == ("matches", "of the 2 output files the run read: all match intake")
        assert (provenance["sha256"], provenance["files"]) == ("", sorted([FOUND, KAPE]))
        (case.evidence / KAPE).write_text("changed", encoding="utf-8")
        assert verify(case, [KAPE], reason="test")
        provenance = event_on_page(app, record.run_id)["provenance"]
        assert (provenance["sha256"], provenance["state"]) == ("", "changed")
        assert provenance["text"].startswith(
            "of the output file 20240514_EvtxECmd_Output.csv, 1 of 2 the run read: differs from intake (")
        assert event_on_page(app, record.run_id)["evidence_sha256"] == ""
    finally:
        app.con.close()


EVE_HTTP = {"timestamp": "2024-01-01T00:00:00.000000+0000", "src_ip": "192.0.2.1", "src_port": 1000,
            "dest_ip": "198.51.100.2", "dest_port": 80, "proto": "TCP", "event_type": "http",
            "http": {"hostname": "example.test", "url": "/a"}}


def test_an_event_of_found_output_naming_its_own_file_cites_that_file_of_the_several_its_run_read(tmp_path):
    """Suricata's EVE output found in the evidence names its own file, as found Amcache, SRUM, and Autoruns output do. A
    load of two such files gives each event the hash of the file it names, one of the two its run read, as a match."""
    eve = ("SENSOR/a/eve.json", "SENSOR/b/eve.json")
    ev = tmp_path / "evidence"
    for tx_id, rel in enumerate(eve):
        (ev / rel).parent.mkdir(parents=True)
        (ev / rel).write_text(json.dumps({**EVE_HTTP, "tx_id": tx_id}) + "\n", encoding="utf-8")
    case = create_case(tmp_path / "case", "Two EVE files", ev, "cody")
    intake(case)
    record = load_found_output(case, "suricata", "suricata_eve", "SENSOR", list(eve))
    assert (record.status, record.loaded_rows) == ("ok", 2)
    app = App(case)
    try:
        assert app.manifest[eve[0]] != app.manifest[eve[1]]
        rows = app.con.execute("SELECT source_file, event_uid FROM events ORDER BY 1").fetchall()
        assert [source for source, _ in rows] == list(eve)
        for source, uid in rows:
            provenance = api_event(app, {"uid": [uid]})["event"]["provenance"]
            assert (provenance["files"], provenance["sha256"], provenance["text"]) == (
                [source], app.manifest[source], "matches intake")
    finally:
        app.con.close()


def test_an_event_of_found_output_whose_run_record_is_gone_cites_no_file(tmp_path):
    """Without its run's record, nothing says which output a found-output event was read from, so its page cites no
    hash rather than the one of the file it names."""
    case = found_case(tmp_path)
    record = load(case, "WS01", FOUND)
    shutil.rmtree(case.runs_folder / record.run_id)
    app = App(case)
    try:
        event = event_on_page(app, record.run_id)
        assert (event["evidence_sha256"], event["provenance"]["sha256"], event["provenance"]["state"]) == ("", "", "absent")
        assert event["provenance"]["files"] == []
    finally:
        app.con.close()


@pytest.mark.parametrize(("path", "folder", "under"), [
    ("WS01/Windows/System32/winevt/Logs/Security.evtx", "WS01", True),
    ("ws01/Windows/Security.evtx", "WS01", True),          # Windows folder names ignore case
    ("WS02/Windows/Security.evtx", "WS01", False),         # another host's file
    ("WS01", "WS01", False),                               # the folder itself
    ("WS01/../WS02/Security.evtx", "WS01", False),         # leaves the folder
    ("D:/KAPE/tout/C/Windows/Security.evtx", "WS01", False),
    ("Windows/System32/Security.evtx", "", True),          # a single-host case's host folder is the evidence folder
    ("C:/Windows/System32/Security.evtx", "", False),
    ("/Windows/System32/Security.evtx", "", False),
    ("//server/share/Security.evtx", "", False),
    ("", "", False),
])
def test_a_named_path_counts_as_seen_only_under_the_hosts_folder(path, folder, under):
    from glessner.events import under_folder

    assert under_folder(path, folder) is under


EVE_A, EVE_B = "SENSOR/a/eve.json", "SENSOR/b/eve.json"


def write_eve(evidence, rel):
    """An EVE file of the same records at `rel` under `evidence`."""
    (evidence / rel).parent.mkdir(parents=True, exist_ok=True)
    (evidence / rel).write_text("".join(json.dumps(r) + "\n" for r in eve_records(7)), encoding="utf-8")


def link_evidence(tmp_path):
    """The evidence moved to `tmp_path/moved` with a junction left at its old path, which case.yaml names. The test is
    skipped where the junction can't be made, as the suite's other tests of links are."""
    evidence = tmp_path / "evidence"
    evidence.rename(tmp_path / "moved")
    try:
        junction(evidence, tmp_path / "moved")
    except subprocess.CalledProcessError:
        pytest.skip("this account can't make a directory junction")


def linked_evidence_case(tmp_path, files=(EVE_A, EVE_B), link=True, single_host=""):
    """A case made on `tmp_path/evidence` with an EVE file at each of `files`, taken in, and then, with `link`, the
    evidence moved to `tmp_path/moved` with a junction left at the old path, which case.yaml still names. With
    `single_host`, a single-host case, whose host folder is the evidence folder."""
    evidence = tmp_path / "evidence"
    for rel in files:
        write_eve(evidence, rel)
    case = create_case(tmp_path / "case", "Linked", evidence, "cody", single_host=single_host)
    intake(case)
    if link:
        link_evidence(tmp_path)
    return case


@contextmanager
def loaded_under_the_written_root(monkeypatch):
    """Loads of found output name the files it reads against the evidence path as case.yaml writes it, so a case.yaml
    that names the evidence through a link gets extended-length paths in `source_file`."""
    current = runner.parse_context

    def parse_context(case, record, folder, former=0):
        context = current(case, record, folder, former)
        return replace(context, evidence_root=case.evidence, notes=[], skipped=[]) if record.from_output else context

    with monkeypatch.context() as patched:
        patched.setattr(runner, "parse_context", parse_context)
        yield


def sources_by_run(case):
    con = connect(case.db_path, read_only=True)
    try:
        return con.execute("SELECT run_id, source_file, count(*) FROM events GROUP BY ALL ORDER BY 2").fetchall()
    finally:
        con.close()


def test_a_load_replaces_rows_that_name_a_file_by_its_extended_length_path(tmp_path, monkeypatch):
    """Rows a load of found output put in the table naming a file by its extended-length path, as a case.yaml that names
    the evidence through a link gave them, are the rows of that file a later load of it replaces. Otherwise the file
    would have its events twice, under both names. The rows of the file the load doesn't read stay."""
    case = linked_evidence_case(tmp_path)
    moved = f"//?/{(tmp_path / 'moved').as_posix()}"
    with loaded_under_the_written_root(monkeypatch):
        first = load_found_output(case, "suricata", "suricata_eve", "SENSOR", [EVE_A, EVE_B])
    assert first.status == "ok"
    per_file = first.loaded_rows // 2
    assert {(run, source): n for run, source, n in sources_by_run(case)} == {
        (first.run_id, f"{moved}/{EVE_A}"): per_file, (first.run_id, f"{moved}/{EVE_B}"): per_file}
    second = load_found_output(case, "suricata", "suricata_eve", "SENSOR", [EVE_A])
    assert (second.status, second.loaded_rows, second.replaced_rows) == ("ok", per_file, per_file)
    assert {(run, source): n for run, source, n in sources_by_run(case)} == {
        (second.run_id, EVE_A): per_file, (first.run_id, f"{moved}/{EVE_B}"): per_file}


def extended_rows(*rows):
    """An events table of (run, source) rows for one tool and host, and the connection to it."""
    con = duckdb.connect()
    con.execute("CREATE TABLE events (tool VARCHAR, origin_host VARCHAR, run_id VARCHAR, source_file VARCHAR)")
    con.executemany("INSERT INTO events VALUES ('suricata', 'SENSOR', ?, ?)", list(rows))
    return con


@pytest.mark.parametrize(("read", "replaced"), [
    (["eve.json"], ["//?/D:/ev/eve.json"]),
    (["logs/eve.json"], ["//?/D:/ev/logs/eve.json"]),
    (["EVE.json", "logs/eve.json"], ["//?/D:/ev/eve.json", "//?/D:/ev/logs/eve.json"]),
    (["a/eve.json"], []),
])
def test_a_load_replaces_extended_length_rows_only_of_the_files_their_run_read(read, replaced):
    """A run that read `eve.json` and `logs/eve.json` named both by the whole path. A later load that reads only
    `eve.json` replaces the first file's rows: `logs/eve.json` ends in the same name, but is another file."""
    con = extended_rows(("r1", "//?/D:/ev/eve.json"), ("r1", "//?/D:/ev/logs/eve.json"))
    assert sorted(_extended_forms(con, "suricata", "SENSOR", {"r1": ["eve.json", "logs/eve.json"]}, read)) == replaced


def test_each_run_has_its_own_root_for_the_extended_length_rows_a_load_replaces():
    """Two runs loaded while the evidence was at two places each name the file by their own whole path."""
    con = extended_rows(("r1", "//?/D:/ev/eve.json"), ("r1", "//?/D:/ev/logs/eve.json"), ("r2", "//?/E:/moved/eve.json"),
                        ("r2", "//?/E:/moved/logs/eve.json"), ("r3", "eve.json"))
    read = ["eve.json", "logs/eve.json"]
    inputs = {"r1": read, "r2": read, "r3": ["eve.json"]}
    assert sorted(_extended_forms(con, "suricata", "SENSOR", inputs, ["eve.json"])) == [
        "//?/D:/ev/eve.json", "//?/E:/moved/eve.json"]
    assert _extended_forms(con, "suricata", "SENSOR", {"r2": read}, ["logs/eve.json"]) == {"//?/E:/moved/logs/eve.json"}


ROW = "//?/D:/ev/logs/eve.json"


@pytest.mark.parametrize(("inputs", "read", "replaced"), [
    (["logs/eve.json"], ["eve.json"], []),
    (["logs/eve.json"], ["logs/eve.json"], [ROW]),
    (["LOGS/EVE.json"], ["logs/eve.json"], [ROW]),
    (["eve.json"], ["eve.json"], [ROW]),
    (["eve.json", "logs/eve.json"], ["eve.json"], []),
    (["eve.json", "logs/eve.json"], ["logs/eve.json"], [ROW]),
])
def test_a_row_names_the_longest_file_its_run_read_that_its_path_ends_in(inputs, read, replaced):
    """A run's one row, `//?/D:/ev/logs/eve.json`, is the root `//?/D:/ev` and `logs/eve.json` or the root
    `//?/D:/ev/logs` and `eve.json`, which only the files the run read tell apart: it names the longest of them its path
    ends in. A load that reads `eve.json` leaves the row of a run that read `logs/eve.json`."""
    con = extended_rows(("r1", ROW))
    assert sorted(_extended_forms(con, "suricata", "SENSOR", {"r1": inputs}, read)) == replaced


@pytest.mark.parametrize(("root", "folder"), [("ev", "ev"), ("logs", "LOGS")])
def test_a_file_in_a_folder_named_like_the_last_folder_of_the_root_is_not_the_top_level_file(root, folder):
    """A run read `eve.json` and `<folder>/eve.json` under a root whose last folder is named `<root>`: the top-level file's
    path also ends in `<folder>/eve.json`. The root that explains both rows tells them apart, so a load of either file
    replaces its own rows and leaves the other's."""
    top, deeper = f"//?/D:/{root}/eve.json", f"//?/D:/{root}/{folder}/eve.json"
    con = extended_rows(("r1", top), ("r1", deeper))
    inputs = {"r1": ["eve.json", f"{folder}/eve.json"]}
    assert _extended_forms(con, "suricata", "SENSOR", inputs, ["eve.json"]) == {top}
    assert _extended_forms(con, "suricata", "SENSOR", inputs, [f"{folder}/eve.json"]) == {deeper}
    assert _extended_forms(con, "suricata", "SENSOR", inputs, ["eve.json", f"{folder}/eve.json"]) == {top, deeper}


def test_a_run_s_row_under_a_root_the_others_do_not_share_is_left():
    """A run named all its files under one root: the one that explains most of its rows. A row of a file it read under
    another root, such as one a hand edit left, is not a row of the load's file, so the load leaves it."""
    con = extended_rows(("r1", "//?/D:/ev/eve.json"), ("r1", "//?/D:/ev/logs/eve.json"), ("r1", "//?/E:/elsewhere/eve.json"))
    inputs = {"r1": ["eve.json", "logs/eve.json"]}
    assert _extended_forms(con, "suricata", "SENSOR", inputs, ["eve.json"]) == {"//?/D:/ev/eve.json"}


NESTED = ["eve.json", "ev/eve.json", "ev/ev/eve.json"]


@pytest.mark.parametrize(("rows", "inputs", "read", "replaced"), [
    (["//?/D:/ev/eve.json"], ["eve.json", "ev/eve.json"], ["eve.json"], ["//?/D:/ev/eve.json"]),
    (["//?/D:/ev/eve.json"], ["eve.json", "ev/eve.json"], ["ev/eve.json"], []),
    (["//?/D:/ev/eve.json", "//?/D:/ev/ev/eve.json"], NESTED, ["eve.json"], ["//?/D:/ev/eve.json"]),
    (["//?/D:/ev/eve.json", "//?/D:/ev/ev/eve.json"], NESTED, ["ev/eve.json"], ["//?/D:/ev/ev/eve.json"]),
    (["//?/D:/EV/eve.json"], ["eve.json", "ev/eve.json"], ["eve.json"], ["//?/D:/EV/eve.json"]),
])
def test_the_root_the_evidence_is_at_decides_between_roots_that_explain_the_same_rows(rows, inputs, read, replaced):
    """A run's rows of one file, or of nested files, fit two roots equally well when a folder named like the root's last
    folder holds a file of the same name. The load tells them apart by the evidence folder's own extended-length path,
    without regard to case."""
    con = extended_rows(*(("r1", row) for row in rows))
    assert sorted(_extended_forms(con, "suricata", "SENSOR", {"r1": inputs}, read, "//?/D:/ev")) == replaced


def test_a_root_the_evidence_is_not_at_leaves_the_shortest_of_the_roots_that_explain_the_most_rows():
    """With the evidence somewhere else now, the rows alone can't tell `//?/D:/ev` from its parent, so the shortest root
    is taken, as it is with no root given."""
    con = extended_rows(("r1", "//?/D:/ev/eve.json"))
    inputs = {"r1": ["eve.json", "ev/eve.json"]}
    assert _extended_forms(con, "suricata", "SENSOR", inputs, ["ev/eve.json"], "//?/E:/other") == {"//?/D:/ev/eve.json"}
    assert _extended_forms(con, "suricata", "SENSOR", inputs, ["eve.json"], "//?/E:/other") == set()


def test_a_row_that_ends_in_a_file_s_characters_without_a_slash_before_them_is_not_that_file_s():
    """`xeve.json` ends in the characters of `eve.json` but is another file. The run read only `eve.json`, so the row fits
    none of its files and the load leaves it."""
    con = extended_rows(("r1", "//?/D:/ev/xeve.json"))
    assert _extended_forms(con, "suricata", "SENSOR", {"r1": ["eve.json"]}, ["eve.json"]) == set()


def test_a_row_is_told_apart_by_the_files_of_its_own_run_not_those_of_another():
    """Run r1 read `eve.json` under an evidence folder named `logs`, and run r2 read `logs/eve.json`. The row of r1 also
    ends in `logs/eve.json`, but only r2 read that file, so a load of it replaces r2's row and leaves r1's."""
    con = extended_rows(("r1", "//?/D:/logs/eve.json"), ("r2", "//?/E:/ev/logs/eve.json"))
    inputs = {"r1": ["eve.json"], "r2": ["logs/eve.json"]}
    assert _extended_forms(con, "suricata", "SENSOR", inputs, ["logs/eve.json"]) == {"//?/E:/ev/logs/eve.json"}
    assert _extended_forms(con, "suricata", "SENSOR", inputs, ["eve.json"]) == {"//?/D:/logs/eve.json"}


def test_a_load_in_a_single_host_case_leaves_the_rows_of_a_deeper_file_of_the_same_name(tmp_path, monkeypatch):
    """A single-host case's host folder is the evidence folder, so a file's path under it has no host folder to show
    where the root ends. A load of `eve.json` after a load of `logs/eve.json`, both under the extended-length root
    case.yaml names, replaces nothing of the first, and a load of `logs/eve.json` again replaces its own rows."""
    case = linked_evidence_case(tmp_path, files=("logs/eve.json", "eve.json"), single_host="SENSOR")
    moved = f"//?/{(tmp_path / 'moved').as_posix()}"
    with loaded_under_the_written_root(monkeypatch):
        deeper = load_found_output(case, "suricata", "suricata_eve", "SENSOR", ["logs/eve.json"])
        top = load_found_output(case, "suricata", "suricata_eve", "SENSOR", ["eve.json"])
        assert (deeper.status, top.status) == ("ok", "ok")
        per_file = deeper.loaded_rows
        assert top.replaced_rows == 0 and top.loaded_rows == per_file
        assert {(run, source): n for run, source, n in sources_by_run(case)} == {
            (deeper.run_id, f"{moved}/logs/eve.json"): per_file, (top.run_id, f"{moved}/eve.json"): per_file}
        again = load_found_output(case, "suricata", "suricata_eve", "SENSOR", ["logs/eve.json"])
    assert (again.status, again.replaced_rows) == ("ok", per_file)
    assert {(run, source): n for run, source, n in sources_by_run(case)} == {
        (again.run_id, f"{moved}/logs/eve.json"): per_file, (top.run_id, f"{moved}/eve.json"): per_file}


def test_a_load_replaces_the_rows_of_the_file_the_evidence_folder_s_name_makes_ambiguous(tmp_path, monkeypatch):
    """A single-host case's evidence folder is `moved`, and a run read `eve.json` and `moved/eve.json`, an empty file with
    no rows. Its one stored name, `.../moved/eve.json`, is the first file under the evidence folder or the second under
    its parent. The load of `eve.json` replaces it, since the evidence folder is where the rows say, and no file's
    events stand twice."""
    (tmp_path / "evidence" / "moved").mkdir(parents=True)
    (tmp_path / "evidence" / "moved" / "eve.json").write_text("", encoding="utf-8")
    case = linked_evidence_case(tmp_path, files=("eve.json",), single_host="SENSOR")
    with loaded_under_the_written_root(monkeypatch):
        first = load_found_output(case, "suricata", "suricata_eve", "SENSOR", ["eve.json", "moved/eve.json"])
        assert first.status == "ok" and first.loaded_rows
    second = load_found_output(case, "suricata", "suricata_eve", "SENSOR", ["eve.json"])
    assert (second.status, second.loaded_rows, second.replaced_rows) == ("ok", first.loaded_rows, first.loaded_rows)
    assert {(run, source): n for run, source, n in sources_by_run(case)} == {(second.run_id, "eve.json"): first.loaded_rows}


def test_add_new_evidence_after_a_linked_load_ends_with_a_row_per_record(tmp_path, monkeypatch):
    """A file taken in with Add new evidence after found output was loaded under the extended-length name of its
    sibling: a load of both leaves each file's events once, under its path in the evidence folder, and none under the
    old name. Replaced by name alone, the first file's events would stand twice and the total would be three files'."""
    case = linked_evidence_case(tmp_path, files=(EVE_A,))
    with loaded_under_the_written_root(monkeypatch):
        first = load_found_output(case, "suricata", "suricata_eve", "SENSOR", [EVE_A])
    assert first.status == "ok"
    per_file = first.loaded_rows
    write_eve(tmp_path / "evidence", EVE_B)
    add_new(case)
    assert {e.path for e in read_manifest(case)} >= {EVE_A, EVE_B}
    second = load_found_output(case, "suricata", "suricata_eve", "SENSOR", [EVE_A, EVE_B])
    assert (second.status, second.loaded_rows, second.replaced_rows) == ("ok", 2 * per_file, per_file)
    assert {(run, source): n for run, source, n in sources_by_run(case)} == {
        (second.run_id, EVE_A): per_file, (second.run_id, EVE_B): per_file}


def test_a_test_that_links_the_evidence_is_skipped_where_the_link_cannot_be_made(tmp_path, monkeypatch):
    """Windows refuses a junction on some volumes, such as a FAT or network one, and the test is skipped there."""
    (tmp_path / "evidence").mkdir()

    def refused(link, target):
        raise subprocess.CalledProcessError(1, "mklink")

    monkeypatch.setattr(sys.modules[__name__], "junction", refused)
    with pytest.raises(pytest.skip.Exception):
        link_evidence(tmp_path)
