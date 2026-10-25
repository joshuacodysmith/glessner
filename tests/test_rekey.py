"""The case format 1 to 2 upgrade (rekey.py): what it places, what it checks before changing anything, its reload, its
record, its crash points, and every path that runs it. Each case is made at format 1 by tests/rekey_cases.py; the journal
side is test_rekey_journal.py's. Step numbers are those of rekey.py's comments; rekey._reached marks steps 4, 8, and 9."""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path, PureWindowsPath

import duckdb
import pytest
from chain_fixtures import append_unchained
from parser_fix_fixtures import EVIDENCE, EVTX_ROWS, write_csv
from rekey_cases import (
    HISTORY,
    Format1,
    case_format,
    digest,
    rebuild_format_1,
    run_files,
    state_of,
)
from rekey_fixtures import (
    AMCACHE_PROGRAM,
    TOOL_HIVE,
    TOOL_SRUDB,
    amcache_tables,
    eve_records,
    program,
    srum_row,
    srum_tables,
    write_rows,
)

from glessner import case as case_module
from glessner import rekey
from glessner.audit import describe
from glessner.case import CASE_FORMAT, CaseError, open_case
from glessner.cli import main
from glessner.events import EventIds, connect, event_uid
from glessner.journal import Journal, check
from glessner.parsers import PARSERS
from glessner.rekey import upgraded
from glessner.runner import (
    LEFT_OUT,
    _write_record,
    load_found_output,
    load_output,
    parse_context,
    read_runs,
    rebuild,
)
from glessner.server import App, api_audit, api_event, api_overview

WRITTEN = "Amcache program entry written"


def new_id(name: str) -> str:
    return hashlib.sha256(name.encode()).hexdigest()[:32]


def rel(f: Format1, paths) -> list[str]:
    return [p.relative_to(f.evidence).as_posix() for p in paths]


def the_upgrade(f: Format1) -> dict:
    (entry,) = f.upgrades()
    return entry


def opened(case) -> App:
    """The server's open for work, which upgrades the case; its connection closed, since the tests read the files."""
    app = App(case, for_work=True)
    app.con.close()
    return app


# ---------- the four parsers' cases ----------

def suricata(f: Format1) -> str:
    f.eve_run(7)   # every key time written at +0700 changes but the two to_us can't read
    return "suricata"


def amcache(f: Format1) -> str:
    """Found Amcache of two collections, K2 whole and K1 with the same program: format 1 cited K1's CSV for every row."""
    paths = amcache_tables(f.evidence / "DESKTOP" / "K2")
    paths.append(write_rows(f.evidence / "DESKTOP" / "K1" / "2024_Amcache_ProgramEntries.csv", AMCACHE_PROGRAM,
                            [program("p1", "Tool", "2020-09-19 01:32:10")]))
    f.take_in()
    f.found_run("amcacheparser", "amcache_csv", "DESKTOP", rel(f, paths))
    return "amcacheparser"


def srum(f: Format1) -> str:
    """Found SRUM of two collections in one load: format 1 cited no file, so the two Id 5 rows took #1 and #2."""
    paths = srum_tables(f.evidence / "DESKTOP" / "K1", [srum_row("5", "a.exe")])
    paths += srum_tables(f.evidence / "DESKTOP" / "K2", [srum_row("5", "b.exe"), srum_row("6", "c.exe")], resources=True)
    f.take_in()
    f.found_run("srumecmd", "srumecmd_csv", "DESKTOP", rel(f, paths))
    return "srumecmd"


def sqlecmd(f: Format1) -> str:
    """A SQLECmd run made before runs recorded their folders, whose output names bob's copies in another case's folder:
    format 1 kept the absolute path.
    Carol's copy in the run's own folder, and dave's database read in the evidence, kept their evidence paths."""
    f.sqlecmd_run(lambda elsewhere, own: [
        ("10", elsewhere / PureWindowsPath(HISTORY)), ("11", own / PureWindowsPath(HISTORY.replace("bob", "carol"))),
        ("12", PureWindowsPath(f.evidence) / PureWindowsPath(HISTORY.replace("bob", "dave")))])
    return "sqlecmd"


# The events whose IDs each case's runs change (tests/test_pivot_parser_fixes.py pins the same records' IDs)
CASES = {"suricata": (suricata, 5), "amcache": (amcache, 4), "srum": (srum, 4), "sqlecmd": (sqlecmd, 2)}
LABELS = {"suricata": "Suricata", "amcache": "Amcache", "srum": "SRUM", "sqlecmd": "SQLECmd"}


@pytest.mark.parametrize("kind", CASES)
def test_every_reference_to_a_changed_event_is_placed_on_one_event(tmp_path, kind):
    """With every event marked, each mark reaches one loaded event, one pair for each changed event; the journal is
    only appended to, by one case_upgrade, whose text counts them."""
    build, changed = CASES[kind]
    f = Format1(tmp_path)
    tool = build(f)
    before = f.uids(tool)
    f.mark(before)
    written = f.journal_bytes()
    case = opened(f.case).case
    entry = the_upgrade(f)
    pairs, after = entry["rekey"]["pairs"], f.uids(tool)
    assert len(pairs) == changed and len(after) == len(before) and case_format(case) == CASE_FORMAT
    assert set(pairs) <= set(before) - set(after) and set(pairs.values()) <= set(after)
    assert sorted(pairs.get(u, u) for u in before) == after
    assert set(state_of(case)["marks"]) == set(after)
    assert not entry["rekey"]["unplaced"] and not entry["rekey"]["merged"]
    assert entry["text"] == ("Event IDs no longer depend on where or in which time zone a tool ran: "
                             f"{changed} {LABELS[kind]} events took new IDs. {changed} journal references now name "
                             "their events' new IDs. None was left unplaced.")
    assert f.journal_bytes().startswith(written)
    assert json.loads(f.journal_bytes()[len(written):].splitlines()[0])["action"] == "case_upgrade"


def test_an_id_that_named_two_records_is_left_unplaced_with_both(tmp_path):
    """Found SRUM of one collection is marked, then another collection's load gives its own record the same ID, and the
    mark must not move to it silently. Both runs give the ID a successor, so it is unplaced, with both as candidates;
    each one's Event page says so, and the overview counts it."""
    f = Format1(tmp_path)
    f.take_in()
    srum_tables(f.evidence / "DESKTOP" / "K1", [srum_row("5", "a.exe")])
    f.take_in()
    f.found_run("srumecmd", "srumecmd_csv", "DESKTOP", ["DESKTOP/K1/2024_SrumECmd_NetworkUsages_Output.csv"])
    (uid,) = f.uids("srumecmd")
    f.mark([uid])
    srum_tables(f.evidence / "DESKTOP" / "K2", [srum_row("5", "b.exe")])
    f.take_in()
    f.found_run("srumecmd", "srumecmd_csv", "DESKTOP", ["DESKTOP/K2/2024_SrumECmd_NetworkUsages_Output.csv"])
    assert f.uids("srumecmd") == [uid]   # the one row, b.exe's
    app = App(f.case, for_work=True)
    try:
        rekeyed = the_upgrade(f)["rekey"]
        by_exe = dict(app.con.execute("SELECT process_executable, event_uid FROM events WHERE tool = 'srumecmd'")
                      .fetchall())
        assert rekeyed["unplaced"] == {uid: sorted(by_exe.values())} and not rekeyed["pairs"]
        for candidate in by_exe.values():
            seq = the_upgrade(f)["seq"]
            assert api_event(app, {"uid": [candidate]})["event"]["unplaced"] == [{"seq": seq, "id": uid, "others": 1}]
        # The ID itself names no event, so its mark is an orphan too
        assert (api_overview(app, {})["progress"]["unplaced"], app.orphans) == (1, 1)
        # The text counts it as unplaced, and not again among the references that name no loaded event
        assert the_upgrade(f)["text"].endswith(" 1 was left unplaced, each naming more than one event; the Case overview "
                                               "counts them, and each event they may mean says so.")
    finally:
        app.con.close()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows paths sort without regard to case")
def test_an_id_unchanged_in_one_run_and_changed_in_another_is_unplaced_with_itself(tmp_path):
    """Found Amcache in B, marked, then B and a together. Format 1 cited the group's first input, B's CSV by text
    order, while a's CSV is read first, as Windows sorts paths: a's program took the marked ID and B's its repeat. The ID
    names B's program in the first run and a's in the second, so it stays unplaced, itself a candidate; it still names a
    loaded event, so the overview counts it as unplaced and not as an orphan."""
    f = Format1(tmp_path)
    b = write_rows(f.evidence / "DESKTOP" / "B" / "2024_Amcache_ProgramEntries.csv", AMCACHE_PROGRAM,
                   [program("p1", "Tool", "2020-09-19 01:32:10")])
    f.take_in()
    f.found_run("amcacheparser", "amcache_csv", "DESKTOP", rel(f, [b]))
    (x,) = f.uids("amcacheparser", "ts_desc = ?", [WRITTEN])
    f.mark([x])
    a = write_rows(f.evidence / "DESKTOP" / "a" / "2024_Amcache_ProgramEntries.csv", AMCACHE_PROGRAM,
                   [program("p1", "Tool", "2020-09-19 01:32:10")])
    f.take_in()
    f.found_run("amcacheparser", "amcache_csv", "DESKTOP", rel(f, [b, a]))
    app = App(f.case, for_work=True)
    try:
        (y,), names = app.con.execute("SELECT list(event_uid) FILTER (WHERE source_file LIKE '%/a/%'), list(event_uid) "
                                      "FROM events WHERE ts_desc = ?", [WRITTEN]).fetchone()
        assert the_upgrade(f)["rekey"]["unplaced"] == {x: sorted([x, y])} and x in names
        assert (api_overview(app, {})["progress"]["unplaced"], app.orphans) == (1, 0)
    finally:
        app.con.close()


def test_the_entry_s_text_counts_the_events_a_rebuild_loads(tmp_path):
    """The sentence counts the events of the runs a rebuild loads whose IDs changed, not those of a superseded run of the
    same capture, which the map covers too."""
    f = Format1(tmp_path)
    extra = {**eve_records(7)[1], "alert": {"signature_id": 2000002, "signature": "OTHER", "severity": 2}}
    first = f.tool_run("suricata", "suricata_eve", "SENSOR", ["SENSOR/capture.pcap"], lambda out: (out / "eve.json").write_text(
        "".join(json.dumps(r) + "\n" for r in [*eve_records(7), extra]), encoding="utf-8"))
    latest = f.eve_run(5)   # the same capture again, on a machine in another zone
    upgraded(f.case)
    rekey_ = the_upgrade(f)["rekey"]
    n = rekey_["runs"][latest.run_id]["changed"]
    assert 0 < n == rekey_["runs"][first.run_id]["changed"] - 1
    assert the_upgrade(f)["text"] == ("Event IDs no longer depend on where or in which time zone a tool ran: "
                                      f"{n} Suricata events took new IDs. No journal reference changed.")


NO_NEW_ID = "Event IDs no longer depend on where or in which time zone a tool ran; no event here took a new ID."
UNPLACED = ("1 was left unplaced, each naming more than one event; the Case overview counts them, and each event they may "
            "mean says so.")


@pytest.mark.parametrize(
    ("pairs", "unplaced", "unreached", "tail"),
    [
        ({}, {}, None, " No journal reference changed."),
        ({}, {}, 0, " No journal reference changed."),
        ({}, {}, 1, " No journal reference changed. 1 journal reference names no loaded event."),
        ({}, {}, 2, " No journal reference changed. 2 journal references name no loaded event."),
        ({}, {}, 1234, " No journal reference changed. 1,234 journal references name no loaded event."),
        ({"a": "b"}, {}, None, " 1 journal reference now names its event's new ID. None was left unplaced."),
        ({"a": "b"}, {}, 0, " 1 journal reference now names its event's new ID. None was left unplaced."),
        ({"a": "b"}, {}, 1, " 1 journal reference now names its event's new ID. None was left unplaced. "
                            "1 journal reference names no loaded event."),
        ({"a": "b", "c": "d"}, {}, 3, " 2 journal references now name their events' new IDs. None was left unplaced. "
                                      "3 journal references name no loaded event."),
        ({}, {"u": ["x", "y"]}, None, f" No journal reference was placed on a new ID. {UNPLACED}"),
        ({}, {"u": ["x", "y"]}, 0, f" No journal reference was placed on a new ID. {UNPLACED}"),
        ({}, {"u": ["x", "y"]}, 2, f" No journal reference was placed on a new ID. {UNPLACED} "
                                   "2 journal references name no loaded event."),
        ({"a": "b"}, {"u": ["x", "y"]}, 1, f" 1 journal reference now names its event's new ID. {UNPLACED} "
                                           "1 journal reference names no loaded event."),
    ],
    ids=["none unchanged, no count", "none unchanged, 0", "none unchanged, 1", "none unchanged, 2", "none unchanged, 1,234",
         "one placed, no count", "one placed, 0", "one placed, 1", "two placed, 3", "unplaced, no count", "unplaced, 0",
         "unplaced, 2", "one placed and one unplaced, 1"],
)
def test_the_text_adds_the_count_of_references_that_name_no_loaded_event(pairs, unplaced, unreached, tail):
    """The sentence follows whatever the text says once the count is above 0; no count (None) and 0 leave the text as it
    was."""
    named = {*pairs, *unplaced}
    count = () if unreached is None else (unreached,)   # with None the argument is left out, for its default
    assert rekey._sentence({}, pairs, unplaced, named, *count) == NO_NEW_ID + tail


def test_each_reference_is_counted_at_the_event_its_pair_gives_it():
    """A reference counts when no event holds the ID its pair gives it, or its own ID when it has none, so two references
    to one missing event count twice; an ID left unplaced counts apart; with nothing named, nothing is counted."""
    pairs = {"moved_from": "moved_to", "old_a": "new_gone", "old_b": "new_gone"}
    named = {"here", "moved_from", "gone", "old_a", "old_b", "unplaced"}
    with duckdb.connect() as con:
        con.execute("CREATE TABLE events (event_uid VARCHAR)")
        con.execute("INSERT INTO events VALUES ('here'), ('moved_to')")
        assert rekey._unreached(con, named, pairs, {"unplaced": ["x", "y"]}) == 3   # gone, old_a, and old_b
        assert rekey._unreached(con, set(), pairs, {}) == 0


def test_a_superseded_run_whose_output_no_longer_gives_its_load_is_skipped(tmp_path):
    """A superseded run whose parse gives another count than its load did would place a former ID on a neighboring
    record, so it is skipped and named; the references place through the latest run."""
    f = Format1(tmp_path)
    first = f.eve_run(7)
    f.eve_run(7)
    first.loaded_rows = 6   # as if a parser change since had added a record
    _write_record(f.case.runs_folder / first.run_id, first)
    f.mark(f.uids("suricata"))
    upgraded(f.case)
    rekeyed = the_upgrade(f)["rekey"]
    assert rekeyed["skipped_runs"] == {first.run_id: "its output gives 7 events, where its load gave 6"}
    assert first.run_id not in rekeyed["runs"] and len(rekeyed["pairs"]) == 5


# ---------- what the step leaves alone ----------

def mixed(f: Format1) -> dict:
    """EvtxECmd's run, AmcacheParser's run on DESKTOP beside found Amcache there, Suricata's run on a capture, and an
    EVE file found in the evidence whose load committed and whose check after reading failed."""
    runs = {"evtx": f.tool_run("evtxecmd", "evtxecmd_csv", "FIXTURE", ["FIXTURE/Windows/System32/winevt/Logs/Security.evtx"],
                               lambda out: write_csv(out / "evtxecmd.csv", EVTX_ROWS.values()), evidence_root=EVIDENCE),
            "amcache_tool": f.tool_run("amcacheparser", "amcache_csv", "DESKTOP", [TOOL_HIVE], amcache_tables)}
    amcache(f)
    runs["eve"] = f.eve_run(7)
    f.eve_file("SENSOR/found/eve.json", 7)
    f.take_in()
    runs["failed"] = f.found_run("suricata", "suricata_eve", "SENSOR", ["SENSOR/found/eve.json"], status="failed")
    return runs


def test_nothing_outside_the_map_changes(tmp_path):
    """The event log's rows and AmcacheParser's own rows keep their IDs; the found run that loaded and
    failed drops as a rebuild drops it, listed with the reference to it; a mark whose event an unrelated cause removed
    stays as written, an orphan."""
    f = Format1(tmp_path, hosts=("DESKTOP", "SENSOR", "FIXTURE"))
    runs = mixed(f)
    in_run = lambda name: f.uids(where="run_id = ?", params=[runs[name].run_id])
    failed = in_run("failed")
    gone = new_id("an event a rerun dropped")
    f.mark([failed[0], gone, *in_run("evtx")[:2], *in_run("amcache_tool")])
    evtx, tool = digest(f.case, "tool = 'evtxecmd'"), in_run("amcache_tool")
    app = opened(f.case)
    rekeyed = the_upgrade(f)["rekey"]
    assert digest(f.case, "tool = 'evtxecmd'") == evtx and in_run("amcache_tool") == tool
    assert not in_run("failed") and rekeyed["dropped_runs"] == {runs["failed"].run_id: {"rows": 7, "references": [failed[0]]}}
    # Its reference pairs through its parse, to a record no run loads: an orphan the entry names
    assert rekeyed["pairs"][failed[0]] not in f.uids() and rekeyed["pairs"][failed[0]] in state_of(app.case)["marks"]
    assert gone not in rekeyed["pairs"] and gone in state_of(app.case)["marks"] and App(app.case).orphans == 2
    # The text counts those two, the references that name no loaded event, and not the event log's marks or
    # AmcacheParser's, whose events are loaded
    assert the_upgrade(f)["text"].endswith(" 1 journal reference now names its event's new ID. None was left unplaced. "
                                           "2 journal references name no loaded event.")


def test_a_failed_run_whose_evidence_changed_is_skipped_and_its_rows_drop(tmp_path):
    """A found-output run that loaded and then failed, whose evidence has changed since, can't be read again.
    Its rows are left out of the check of the loaded rows, drop as a rebuild drops them, and the entry names the run
    twice, with the reference to its rows taken from the database."""
    f = Format1(tmp_path, hosts=("SENSOR",))
    f.eve_run(7)
    f.eve_file("SENSOR/found/eve.json", 7)
    f.take_in()
    failed = f.found_run("suricata", "suricata_eve", "SENSOR", ["SENSOR/found/eve.json"], status="failed")
    (uid, *_) = f.uids(where="run_id = ?", params=[failed.run_id])
    f.mark([uid])
    f.eve_file("SENSOR/found/eve.json", 5)   # rewritten since its intake
    opened(f.case)
    rekeyed = the_upgrade(f)["rekey"]
    assert set(rekeyed["skipped_runs"]) == {failed.run_id} and uid not in rekeyed["pairs"]
    assert rekeyed["dropped_runs"] == {failed.run_id: {"rows": failed.loaded_rows, "references": [uid]}}
    assert not f.uids(where="run_id = ?", params=[failed.run_id]) and case_format(f.case) == CASE_FORMAT


def test_the_reload_equals_a_rebuild(tmp_path):
    """After the upgrade, every events row is as a full rebuild of the case gives it."""
    f = Format1(tmp_path, hosts=("DESKTOP", "SENSOR", "FIXTURE", "WS01"))
    mixed(f)
    sqlecmd(f)
    srum(f)
    upgraded(f.case)
    copy = open_case(Path(shutil.copytree(f.case.folder, tmp_path / "copy")))
    rebuild(copy)
    assert digest(f.case) == digest(copy)


def left_out(f: Format1, record) -> None:
    """The run as a format 1 rebuild leaves one whose output no longer matches its record: no rows, and 0 loaded."""
    con = connect(f.case.db_path)
    try:
        con.execute("DELETE FROM events WHERE run_id = ?", [record.run_id])
    finally:
        con.close()
    record.loaded_rows = 0
    record.notes = [*record.notes, f"Rebuild at 2024-01-01T00:00:00Z{LEFT_OUT}eve.json: SHA-256 changed"]
    _write_record(f.case.runs_folder / record.run_id, record)


def test_a_run_an_earlier_rebuild_left_out_is_skipped_not_refused(tmp_path):
    """The upgrade refuses a run a rebuild would load whose output fails its check while its rows are loaded. A run an
    earlier rebuild left out for that reason has no rows to protect: it is skipped and named, left out again, and the case
    opens."""
    f = Format1(tmp_path, hosts=("SENSOR",))
    f.eve_run(7)
    f.mark(f.uids("suricata"))
    other = f.eve_run(7, capture="SENSOR/other.pcap")
    with (f.case.runs_folder / other.run_id / "output" / "eve.json").open("a", encoding="utf-8") as out:
        out.write("\n")
    left_out(f, other)
    upgraded(f.case)
    rekeyed = the_upgrade(f)["rekey"]
    assert list(rekeyed["skipped_runs"]) == [other.run_id] and "SHA-256 changed" in rekeyed["skipped_runs"][other.run_id]
    assert case_format(f.case) == CASE_FORMAT and not f.uids(where="run_id = ?", params=[other.run_id])
    assert len(rekeyed["pairs"]) == 5 and set(state_of(f.case)["marks"]) == set(f.uids("suricata"))


def test_a_host_whose_only_run_loaded_and_then_failed_drops_its_rows(tmp_path):
    """Found EVE on a host with no other Suricata run, which loaded and then failed its check, joins the step:
    its rows drop as a rebuild drops them, named with the reference to them, and the events equal a rebuild's."""
    f = Format1(tmp_path, hosts=("SENSOR", "SENSOR2"))
    f.eve_run(7)
    f.eve_file("SENSOR2/found/eve.json", 7)
    f.take_in()
    failed = f.found_run("suricata", "suricata_eve", "SENSOR2", ["SENSOR2/found/eve.json"], status="failed")
    (uid, *_) = f.uids(where="run_id = ?", params=[failed.run_id])
    f.mark([uid])
    upgraded(f.case)
    assert the_upgrade(f)["rekey"]["dropped_runs"] == {failed.run_id: {"rows": 7, "references": [uid]}}
    assert not f.uids(where="run_id = ?", params=[failed.run_id])
    copy = open_case(Path(shutil.copytree(f.case.folder, tmp_path / "copy")))
    rebuild(copy)
    assert digest(f.case) == digest(copy)


def test_rows_of_a_run_the_step_can_t_read_and_no_rebuild_loads_drop_and_are_named(tmp_path):
    """Rows whose run has no record, its folder deleted by hand, or whose record a crash left running between its
    load and its record, have no output to check them against; no rule is at fault, and a rebuild drops them. They drop
    here too, each run named with its rows and the references to them, rather than stopping the open."""
    f = Format1(tmp_path, hosts=("SENSOR",))
    gone = f.eve_run(7, capture="SENSOR/gone.pcap")
    crashed = f.eve_run(7, capture="SENSOR/crashed.pcap")
    f.eve_run(7)
    refs = [f.uids(where="run_id = ?", params=[r.run_id])[0] for r in (gone, crashed)]
    f.mark(refs)
    shutil.rmtree(f.case.runs_folder / gone.run_id)
    crashed.status, crashed.loaded_rows = "running", None
    _write_record(f.case.runs_folder / crashed.run_id, crashed)
    upgraded(f.case)
    assert the_upgrade(f)["rekey"]["dropped_runs"] == {gone.run_id: {"rows": 7, "references": [refs[0]]},
                                                         crashed.run_id: {"rows": 7, "references": [refs[1]]}}
    assert not f.uids(where="run_id IN (?, ?)", params=[gone.run_id, crashed.run_id]) and case_format(f.case) == CASE_FORMAT
    assert not (f.case.folder / rekey.DROPPED_FILE).exists()


@pytest.mark.parametrize("record", ["missing", "running"])
def test_rows_of_the_only_run_of_a_tool_and_host_drop_when_no_record_selects_it(tmp_path, record):
    """The one Suricata run on a host has no record, or one a crash left running between its load and its
    record, and no other run of that tool on that host selects the group. Its rows still drop and are named, as in a
    rebuild, with the references to them; none stays under format 1's IDs in a format 2 case."""
    f = Format1(tmp_path, hosts=("SENSOR",))
    run = f.eve_run(7)
    old = f.uids("suricata")
    f.mark(old)
    if record == "missing":
        (f.case.runs_folder / run.run_id / "run.json").unlink()
    else:
        run.status, run.loaded_rows = "running", None
        _write_record(f.case.runs_folder / run.run_id, run)
    upgraded(f.case)
    assert the_upgrade(f)["rekey"]["dropped_runs"] == {run.run_id: {"rows": 7, "references": old}}
    assert not f.uids("suricata") and case_format(f.case) == CASE_FORMAT
    # Every mark now names no loaded event, so the count comes after the dropped run's rows are deleted
    assert the_upgrade(f)["text"].endswith(" No journal reference changed. 7 journal references name no loaded event.")
    assert not (f.case.folder / rekey.DROPPED_FILE).exists()
    copy = open_case(Path(shutil.copytree(f.case.folder, tmp_path / "copy")))
    rebuild(copy)
    assert digest(f.case) == digest(copy)


def test_a_crash_after_the_rows_of_an_unrecorded_run_dropped_gives_the_same_entry(tmp_path, monkeypatch):
    """The rows of the only run of a tool and host, with no record, are gone after step 8. The next run of the step
    doesn't find them, and reads their counts and references from the file the step kept, so the entry is the same."""
    base = Format1(tmp_path / "base", hosts=("SENSOR",))
    run = base.eve_run(7)
    base.mark(base.uids("suricata")[:3])
    (base.case.runs_folder / run.run_id / "run.json").unlink()
    clean = faulted(tmp_path, base, "clean")
    upgraded(clean.case)
    expected = outcome(clean)
    assert expected[1]["dropped_runs"][run.run_id]["rows"] == 7
    for step in (8, 9):
        f = faulted(tmp_path, base, f"step{step}")
        monkeypatch.setattr(rekey, "_reached", crash_at(step))
        with pytest.raises(Crash):
            upgraded(f.case)
        monkeypatch.undo()
        assert case_format(f.case) == 1 and not f.uids("suricata") and (f.case.folder / rekey.DROPPED_FILE).exists()
        upgraded(f.reopen())
        assert outcome(f) == expected and not (f.case.folder / rekey.DROPPED_FILE).exists()


def test_a_repair_drops_the_rows_of_an_unrecorded_run_a_format_1_build_loaded_meanwhile(tmp_path, monkeypatch):
    """Between the entry and case.yaml, a format 1 build loaded a Suricata run and was stopped before its
    record, and no other run of the tool on the host selects a group. The repair drops the rows as a rebuild does, so no
    format 1 ID is left in the format 2 case."""
    f = Format1(tmp_path, hosts=("SENSOR",))
    first = f.eve_run(7, capture="SENSOR/first.pcap")
    (f.case.runs_folder / first.run_id / "run.json").unlink()

    def crash_writing(folder, settings):
        raise Crash("stopped before case.yaml")

    monkeypatch.setattr(case_module, "_write_settings", crash_writing)
    with pytest.raises(Crash):
        upgraded(f.case)
    monkeypatch.undo()
    assert case_format(f.reopen()) == 1 and len(f.upgrades()) == 1 and not f.uids("suricata")
    late = f.eve_run(7, capture="SENSOR/late.pcap")
    late.status, late.loaded_rows = "running", None
    _write_record(f.case.runs_folder / late.run_id, late)
    assert len(f.uids("suricata")) == 7
    upgraded(f.reopen())
    assert case_format(f.case) == CASE_FORMAT and not f.uids("suricata")


@pytest.mark.parametrize("tool_run", ["intact", "no_folders_changed"])
def test_unrecorded_rows_beside_an_amcache_tool_run_drop_and_the_tool_run_stays(tmp_path, tool_run):
    """Found Amcache whose record is gone, on a host with an AmcacheParser tool run. No run record selects the
    group (the tool run has no found output beside it), but the rows with no record are named and drop as in a rebuild.
    Only they change: the tool run is not parsed, checked, reloaded, or pinned, so its rows and record are as they were,
    also when it was made before runs recorded their folders and its output no longer matches its record."""
    f = Format1(tmp_path)
    tool = f.tool_run("amcacheparser", "amcache_csv", "DESKTOP", [TOOL_HIVE], amcache_tables,
                      no_folders=tool_run == "no_folders_changed")
    paths = amcache_tables(f.evidence / "DESKTOP" / "K2")
    f.take_in()
    gone = f.found_run("amcacheparser", "amcache_csv", "DESKTOP", rel(f, paths))
    (uid, *_) = f.uids(where="run_id = ?", params=[gone.run_id])
    f.mark([uid])
    (f.case.runs_folder / gone.run_id / "run.json").unlink()
    if tool_run == "no_folders_changed":
        output = next((f.case.runs_folder / tool.run_id / "output").rglob("*.csv"))
        output.write_bytes(output.read_bytes() + b"\n")
    kept = digest(f.case, f"run_id = '{tool.run_id}'")
    record = run_files(f.case)
    rows = len(f.uids(where="run_id = ?", params=[gone.run_id]))
    upgraded(f.case)
    rekeyed = the_upgrade(f)["rekey"]
    assert rekeyed["dropped_runs"] == {gone.run_id: {"rows": rows, "references": [uid]}}
    assert tool.run_id not in rekeyed["runs"] and not rekeyed["skipped_runs"] and not rekeyed["unpinned_runs"]
    assert not f.uids(where="run_id = ?", params=[gone.run_id])
    assert digest(f.case, f"run_id = '{tool.run_id}'") == kept and run_files(f.case) == record
    if tool_run == "intact":   # a rebuild leaves out a run whose output changed, so it compares only with intact output
        copy = open_case(Path(shutil.copytree(f.case.folder, tmp_path / "copy")))
        rebuild(copy)
        assert digest(f.case) == digest(copy)


FOUND_ONLY_TOOLS = {
    "amcache": ("amcacheparser", "amcache_csv", "DESKTOP", [TOOL_HIVE], amcache_tables),
    "srum": ("srumecmd", "srumecmd_csv", "DESKTOP", [TOOL_SRUDB], lambda out: srum_tables(out, [srum_row("5", "a.exe")])),
}


def rerun_without_record(f: Format1, kind: str, record: str = "missing") -> tuple:
    """An AmcacheParser or SrumECmd tool run on a host with no found output, and a rerun on the same input whose load
    replaced the first run's rows, which have the same IDs, and then lost its record: gone, or left running by a crash
    after the load committed. One of the rerun's rows is marked."""
    first = f.tool_run(*FOUND_ONLY_TOOLS[kind])
    ids = f.uids(where="run_id = ?", params=[first.run_id])
    rerun = f.tool_run(*FOUND_ONLY_TOOLS[kind])
    assert not f.uids(where="run_id = ?", params=[first.run_id])
    assert f.uids(where="run_id = ?", params=[rerun.run_id]) == ids
    f.mark(ids[:1])
    if record == "missing":
        (f.case.runs_folder / rerun.run_id / "run.json").unlink()
    else:
        rerun.status, rerun.loaded_rows = "running", None
        _write_record(f.case.runs_folder / rerun.run_id, rerun)
    return first, rerun, ids


@pytest.mark.parametrize("record", ["missing", "running"])
@pytest.mark.parametrize("kind", FOUND_ONLY_TOOLS)
def test_a_tool_run_whose_rows_an_unrecorded_rerun_replaced_is_loaded_again(tmp_path, kind, record):
    """The rerun's rows drop and are named, and the first run, which a rebuild loads, is loaded again, since the
    rerun's load replaced its rows: the host keeps its events, and the mark on one of them is not orphaned. The events
    equal a rebuild's, and the mark is on a loaded event."""
    f = Format1(tmp_path)
    f.eve_run(7)
    first, rerun, ids = rerun_without_record(f, kind, record)
    upgraded(f.case)
    rekeyed = the_upgrade(f)["rekey"]
    assert rekeyed["dropped_runs"] == {rerun.run_id: {"rows": len(ids), "references": ids[:1]}}
    assert f.uids(where="run_id = ?", params=[first.run_id]) == ids
    assert not f.uids(where="run_id = ?", params=[rerun.run_id])
    assert ids[0] in state_of(f.case)["marks"] and set(state_of(f.case)["marks"]) <= set(f.uids())
    # The count comes after the first run's load, so the marked event is loaded when it is looked for
    assert "no loaded event" not in the_upgrade(f)["text"]
    copy = open_case(Path(shutil.copytree(f.case.folder, tmp_path / "copy")))
    rebuild(copy)
    assert digest(f.case) == digest(copy)


@pytest.mark.parametrize("point", ["before_the_reload", "inside_the_reload"])
def test_a_crash_between_the_unrecorded_delete_and_the_reload_gives_the_same_entry(tmp_path, monkeypatch, point):
    """Stopped after the rerun's rows were deleted and before the first run was loaded again, or
    after that reload deleted the tool's rows on the host and before its load, the case is format 1 with the run short
    of its rows. The next run of the step loads it again, with the same entry, events, and replay as one run through."""
    base = Format1(tmp_path / "base")
    base.eve_run(7)
    base.mark(base.uids("suricata")[:2])
    first, _, ids = rerun_without_record(base, "amcache")
    clean = faulted(tmp_path, base, "clean")
    upgraded(clean.case)
    expected = outcome(clean)
    f = faulted(tmp_path, base, point)
    if point == "before_the_reload":
        def stop(*args):
            raise Crash("stopped before the reload")

        monkeypatch.setattr(rekey, "_restore", stop)
    else:
        real = rekey.reload_run

        def stop(case, record, layout, report=None):
            if record.tool == "amcacheparser":
                raise Crash("stopped between the delete and the load")
            return real(case, record, layout, report)

        monkeypatch.setattr(rekey, "reload_run", stop)
    with pytest.raises(Crash):
        upgraded(f.case)
    monkeypatch.undo()
    assert case_format(f.reopen()) == 1 and not f.uids("amcacheparser") and (f.case.folder / rekey.DROPPED_FILE).exists()
    upgraded(f.reopen())
    assert outcome(f) == expected and f.uids(where="run_id = ?", params=[first.run_id]) == ids


def test_a_repair_loads_again_a_tool_run_whose_rows_an_unrecorded_rerun_replaced(tmp_path, monkeypatch):
    """Between the entry and case.yaml, a format 1 build reran AmcacheParser on the same input
    and was stopped before its record. The repair drops the rerun's rows and loads the first run's again, as a rebuild
    does."""
    f = Format1(tmp_path)
    f.eve_run(7)
    first = f.tool_run(*FOUND_ONLY_TOOLS["amcache"])
    ids = f.uids(where="run_id = ?", params=[first.run_id])

    def crash_writing(folder, settings):
        raise Crash("stopped before case.yaml")

    monkeypatch.setattr(case_module, "_write_settings", crash_writing)
    with pytest.raises(Crash):
        upgraded(f.case)
    monkeypatch.undo()
    assert case_format(f.reopen()) == 1 and len(f.upgrades()) == 1
    rerun = f.tool_run(*FOUND_ONLY_TOOLS["amcache"])
    rerun.status, rerun.loaded_rows = "running", None
    _write_record(f.case.runs_folder / rerun.run_id, rerun)
    assert not f.uids(where="run_id = ?", params=[first.run_id])
    upgraded(f.reopen())
    assert case_format(f.case) == CASE_FORMAT and f.uids("amcacheparser") == ids
    assert f.uids(where="run_id = ?", params=[first.run_id]) == ids
    copy = open_case(Path(shutil.copytree(f.case.folder, tmp_path / "copy")))
    rebuild(copy)
    assert digest(f.case) == digest(copy)


def test_amcache_and_srum_tool_runs_without_found_output_beside_them_are_left_alone(tmp_path):
    """Only the keys of Amcache and SRUM output found in the evidence changed, so their tool runs on a host with none of
    it don't join the step: not parsed, reloaded, or named, their rows and records as they were."""
    f = Format1(tmp_path)
    runs = [f.tool_run("amcacheparser", "amcache_csv", "DESKTOP", [TOOL_HIVE], amcache_tables),
            f.tool_run("srumecmd", "srumecmd_csv", "DESKTOP", [TOOL_SRUDB],
                       lambda out: srum_tables(out, [srum_row("5", "a.exe")]))]
    f.eve_run(7)
    tools = lambda: (digest(f.case, "tool <> 'suricata'"),
                     {k: v for k, v in run_files(f.case).items() if k.startswith(tuple(r.run_id for r in runs))})
    before = tools()
    upgraded(f.case)
    assert the_upgrade(f)["rekey"]["runs"] and not set(the_upgrade(f)["rekey"]["runs"]) & {r.run_id for r in runs}
    assert tools() == before


# ---------- the record ----------

def superseded_and_unplaced(f: Format1) -> None:
    """Two runs of one capture, both written at +0700, and found SRUM whose ID names two records."""
    f.eve_run(7)
    f.eve_run(7)
    f.take_in()
    for k, exe in (("K1", "a.exe"), ("K2", "b.exe")):
        srum_tables(f.evidence / "DESKTOP" / k, [srum_row("5", exe)])
        f.take_in()
        f.found_run("srumecmd", "srumecmd_csv", "DESKTOP", [f"DESKTOP/{k}/2024_SrumECmd_NetworkUsages_Output.csv"])
    f.mark(f.uids())


def test_the_map_is_deterministic_and_recomputable(tmp_path):
    """The step's fields from the case and from a hand copy of its folder are the same bytes, and the full map's size
    and SHA-256 come out of this definition: each run's distinct (old, new) pairs with old != new, as UTF-8 "old new"
    lines, sorted, joined with LF."""
    f = Format1(tmp_path)
    superseded_and_unplaced(f)
    copy = open_case(Path(shutil.copytree(f.case.folder, tmp_path / "copy")))
    with rekey.upgrade_ids(f.case) as first:
        pass
    with rekey.upgrade_ids(copy) as second:
        pass
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)
    lines = set()
    for record in read_runs(f.case):
        ids = EventIds(former=True)
        for ev in PARSERS[record.parser](parse_context(f.case, record, f.case.runs_folder / record.run_id, former=1)):
            new, old = ids(record.host, ev)
            if old != new:
                lines.add(f"{old} {new}")
    text = "\n".join(sorted(lines)).encode("utf-8")
    assert (first["rekey"]["map_size"], first["rekey"]["map_sha256"]) == (len(lines), hashlib.sha256(text).hexdigest())
    assert len(lines) == 5 + 2 and len(first["rekey"]["unplaced"]) == 1   # the capture's pairs count once


# ---------- crash points ----------

class Crash(Exception):
    pass


def crash_at(step):
    def reached(n):
        if n == step:
            raise Crash(f"stopped after step {n}")
    return reached


def faulted(tmp_path, base: Format1, name: str) -> Format1:
    copy = Format1.__new__(Format1)
    copy.__dict__.update(base.__dict__)
    copy.case = open_case(Path(shutil.copytree(base.case.folder, tmp_path / name)))
    return copy


def outcome(f: Format1) -> tuple:
    (entry,) = f.upgrades()
    return entry["text"], entry["rekey"], digest(f.case), state_of(f.case), case_format(f.case)


def test_the_step_runs_once_in_effect(tmp_path, monkeypatch):
    """Stopped after steps 4, 8, and 9, or between the entry and case.yaml, the next open finishes it with one entry,
    the same fields, events, and replay as an open that ran it through. A rebuild by a format 1 build in that last
    window is reloaded. A torn entry is moved aside to a side file the entry names, and the step runs again to the same
    outcome, since format 2's reader would stop the open at the torn entry's line number."""
    base = Format1(tmp_path / "base")
    base.eve_run(7)
    base.eve_run(-5)   # the same capture, rerun in another zone: its marks orphaned the first run's
    base.mark(base.uids("suricata")[:3])
    base.mark([new_id("an ID no run gives")])   # names no event before or after the step, so the text counts it
    base.sqlecmd_run()
    append_unchained(base.case.folder, "note", target=base.uids("sqlecmd")[0], text="bob's visit")
    clean = faulted(tmp_path, base, "clean")
    upgraded(clean.case)
    expected = outcome(clean)
    assert expected[0].endswith(" None was left unplaced. 1 journal reference names no loaded event.")
    for step in (4, 8, 9):
        f = faulted(tmp_path, base, f"step{step}")
        monkeypatch.setattr(rekey, "_reached", crash_at(step))
        with pytest.raises(Crash):
            upgraded(f.case)
        monkeypatch.setattr(rekey, "_reached", lambda n: None)
        assert case_format(f.case) == 1 and not f.upgrades()
        upgraded(f.reopen())
        assert outcome(f) == expected, step

    def crash_writing(folder, settings):
        raise Crash("stopped before case.yaml")

    windows = []
    for name in ("window", "window_rebuilt", "torn"):
        f = faulted(tmp_path, base, name)
        monkeypatch.setattr(case_module, "_write_settings", crash_writing)
        with pytest.raises(Crash):
            upgraded(f.case)
        monkeypatch.undo()
        assert case_format(f.reopen()) == 1 and len(f.upgrades()) == 1
        windows.append(f)
    window, rebuilt, torn = windows
    upgraded(window.reopen())
    assert outcome(window) == expected
    rebuild_format_1(rebuilt.case)   # an older build's rebuild before case.yaml took format 2
    assert digest(rebuilt.case) != expected[2]
    upgraded(rebuilt.reopen())
    assert outcome(rebuilt) == expected
    journal = torn.case.folder / "journal.jsonl"
    data = journal.read_bytes()
    journal.write_bytes(data[:-40])   # the entry's line, cut short by a crash
    upgraded(torn.reopen())
    (entry,) = torn.upgrades()
    side = sorted(torn.case.folder.glob("journal_torn_*.bin"))
    assert [r["saved_as"] for r in entry["recovered"]] == [side[0].name] and side[0].read_bytes() == data[
        data.rstrip(b"\n").rfind(b"\n") + 1:-40]
    assert outcome(torn) == expected
    # The side file the unchained entry names is checked too, though the entry lies before the chain
    assert check(journal).consistent
    side[0].write_bytes(side[0].read_bytes() + b"x")
    assert [p["kind"] for p in check(journal).problems] == ["side_file"]


def interrupted_open(original=Path.open):
    """Path.open that raises right after opening a case.yaml file, or its temporary file, for writing: the moment an
    in-place write has truncated the file."""
    def interrupted(path, mode="r", *args, **kwargs):
        stream = original(path, mode, *args, **kwargs)
        if path.name.startswith("case.yaml") and mode.startswith("w"):
            stream.close()
            raise OSError("interrupted after opening case.yaml for writing")
        return stream
    return interrupted


def test_an_interruption_inside_the_settings_write_leaves_the_previous_settings(tmp_path, monkeypatch):
    """case.yaml is written through a temporary file, so a stop inside the write, or a replace Windows refuses
    while another process has the file open, leaves the settings it had, at format 1 beside the one journaled step; the
    next open finishes the step with the same entry, events, and replay as an open that ran it through."""
    base = Format1(tmp_path / "base")
    base.eve_run(7)
    base.mark(base.uids("suricata")[:3])
    clean = faulted(tmp_path, base, "clean")
    upgraded(clean.case)
    expected = outcome(clean)
    real_replace = os.replace

    def refused(src, dst):
        if Path(dst).name == "case.yaml":
            raise PermissionError(13, "The process cannot access the file because it is being used by another process")
        return real_replace(src, dst)

    for name, fault in (("truncated", lambda: monkeypatch.setattr(Path, "open", interrupted_open())),
                        ("replace", lambda: monkeypatch.setattr(os, "replace", refused))):
        f = faulted(tmp_path, base, name)
        before = (f.case.folder / "case.yaml").read_bytes()
        fault()
        with pytest.raises(CaseError, match=r"case.yaml"):
            upgraded(f.case)
        monkeypatch.undo()
        assert (f.case.folder / "case.yaml").read_bytes() == before, name
        assert case_format(f.reopen()) == 1 and len(f.upgrades()) == 1, name
        upgraded(f.reopen())
        assert outcome(f) == expected, name


def test_a_crash_inside_the_reload_gives_the_same_entry(tmp_path, monkeypatch):
    """Inside step 8, stopped after a group's delete and before its load, the next run of the step gives the same
    entry, events, and replay. The rows only the database names, of a failed run whose evidence changed and of a run
    with no record, are gone by then; the step kept their counts and references outside it before the delete."""
    base = Format1(tmp_path / "base", hosts=("SENSOR",))
    gone = base.eve_run(7, capture="SENSOR/gone.pcap")
    base.eve_run(7)
    base.eve_file("SENSOR/found/eve.json", 7)
    base.take_in()
    failed = base.found_run("suricata", "suricata_eve", "SENSOR", ["SENSOR/found/eve.json"], status="failed")
    base.mark([base.uids(where="run_id = ?", params=[r.run_id])[0] for r in (gone, failed)])
    shutil.rmtree(base.case.runs_folder / gone.run_id)
    base.eve_file("SENSOR/found/eve.json", 5)   # rewritten since its intake, so the failed run can't be read again
    clean = faulted(tmp_path, base, "clean")
    upgraded(clean.case)
    expected = outcome(clean)
    dropped = expected[1]["dropped_runs"]
    assert set(dropped) == {gone.run_id, failed.run_id} and all(len(d["references"]) == 1 for d in dropped.values())

    def crash(*args, **kw):
        raise Crash("stopped between the delete and the load")

    f = faulted(tmp_path, base, "crashed")
    monkeypatch.setattr(rekey, "reload_run", crash)
    with pytest.raises(Crash):
        upgraded(f.case)
    monkeypatch.undo()
    assert case_format(f.case) == 1 and not f.uids("suricata") and (f.case.folder / rekey.DROPPED_FILE).exists()
    upgraded(f.reopen())
    assert outcome(f) == expected and not (f.case.folder / rekey.DROPPED_FILE).exists()


# ---------- refusals ----------

def tamper(f: Format1, run_id: str) -> None:
    """One of the run's loaded rows given an ID no rule gives, as a fault in a former rule would leave it."""
    con = connect(f.case.db_path)
    try:
        con.execute("UPDATE events SET event_uid = ? WHERE event_uid = (SELECT min(event_uid) FROM events "
                    "WHERE run_id = ?)", [new_id("tampered"), run_id])
    finally:
        con.close()


@pytest.mark.parametrize("fault", ["loaded_run", "failed_found_run", "amcache_tool_run", "output_changed"])
def test_a_failed_check_changes_nothing(tmp_path, fault):
    """A loaded row its run's output doesn't give under either rule, whether the run is loaded,
    a found run that loaded and failed, or AmcacheParser's own run beside found Amcache, and a loaded run whose output
    no longer matches its record, each stop the open, naming the run. The journal, case.yaml, the run records, and
    the database are as they were."""
    f = Format1(tmp_path, hosts=("DESKTOP", "SENSOR", "FIXTURE"))
    runs = mixed(f)
    f.mark(f.uids("suricata")[:2])
    run = {"loaded_run": runs["eve"], "failed_found_run": runs["failed"], "amcache_tool_run": runs["amcache_tool"],
           "output_changed": runs["eve"]}[fault]
    if fault == "output_changed":
        with (f.case.runs_folder / run.run_id / "output" / "eve.json").open("a", encoding="utf-8") as out:
            out.write("\n")
    else:
        tamper(f, run.run_id)
    before = (f.journal_bytes(), (f.case.folder / "case.yaml").read_bytes(), run_files(f.case), digest(f.case))
    said = "SHA-256 changed" if fault == "output_changed" else "1 loaded event of run"
    with pytest.raises(CaseError, match=f"{said}.*{run.run_id}|{run.run_id}.*{said}"):
        App(f.case, for_work=True)
    assert (f.journal_bytes(), (f.case.folder / "case.yaml").read_bytes(), run_files(f.case), digest(f.case)) == before


REBUILD = "import sys; from pathlib import Path; from glessner.case import open_case; from glessner.runner import rebuild; " \
          "rebuild(open_case(Path(sys.argv[1])))"


def test_another_process_can_t_take_the_database_while_the_step_holds_it(tmp_path, monkeypatch):
    """A rebuild in another process, started while the step runs, can't take the database."""
    f = Format1(tmp_path)
    f.eve_run(7)
    tries = []

    def reached(n):
        if n == 4:
            tries.append(subprocess.run([sys.executable, "-c", REBUILD, str(f.case.folder)], capture_output=True,
                                        text=True, timeout=120))

    monkeypatch.setattr(rekey, "_reached", reached)
    upgraded(f.case)
    assert tries[0].returncode != 0 and case_format(f.case) == CASE_FORMAT and f.case.db_path.exists()
    assert ("PermissionError" in tries[0].stderr or "IO Error" in tries[0].stderr), tries[0].stderr[-500:]


UPGRADE = "import sys; from pathlib import Path; from glessner.case import open_case; from glessner.rekey import upgraded; " \
          "upgraded(open_case(Path(sys.argv[1])))"


def test_a_second_upgrade_of_a_case_without_a_database_stops(tmp_path, monkeypatch):
    """A case with no events database, such as a fresh copy, has nothing loaded, and the step makes an empty
    one to hold, so another process's upgrade during the step stops rather than journaling the step a second time."""
    f = Format1(tmp_path)
    f.eve_run(7, load_it=False)
    f.case.db_path.unlink(missing_ok=True)
    tries = []

    def reached(n):
        if n == 4:
            tries.append(subprocess.run([sys.executable, "-c", UPGRADE, str(f.case.folder)], capture_output=True,
                                        text=True, timeout=120))

    monkeypatch.setattr(rekey, "_reached", reached)
    upgraded(f.case)
    assert tries[0].returncode != 0 and "another program has its events database open" in tries[0].stderr
    assert len(f.upgrades()) == 1 and case_format(f.case) == CASE_FORMAT


def test_the_text_of_a_case_without_a_database_counts_no_reference_that_names_no_event(tmp_path):
    """With nothing loaded there is no event to look for, so marks on an event the output gives and on an ID no run gives
    leave the text with no count of references that name no loaded event."""
    f = Format1(tmp_path)
    f.eve_run(7)
    f.mark([*f.uids("suricata")[:2], new_id("an ID no run gives")])
    f.case.db_path.unlink()
    upgraded(f.case)
    text = the_upgrade(f)["text"]
    assert text.endswith(" None was left unplaced.") and "no loaded event" not in text


def test_a_connection_in_this_process_stops_the_step_as_another_process_s_does(tmp_path, monkeypatch):
    """A read-only connection to the database in this process makes DuckDB refuse the step's with another error than
    another process's does; the step stops all the same, with its message and the case unchanged. A failure after the
    step's connection opens closes it."""
    f = Format1(tmp_path)
    f.eve_run(7)
    before = (f.journal_bytes(), digest(f.case))
    reader = connect(f.case.db_path, read_only=True)
    try:
        with pytest.raises(CaseError, match="another program has its events database open"):
            upgraded(f.case)
    finally:
        reader.close()
    assert case_format(f.case) == 1 and (f.journal_bytes(), digest(f.case)) == before

    def kept_out(path):
        raise CaseError("kept out")

    monkeypatch.setattr(rekey, "_undeletable", kept_out)
    with pytest.raises(CaseError, match="kept out") as caught:
        upgraded(f.case)
    connect(f.case.db_path, read_only=True).close()   # refused while the step's own were open, its traceback held
    assert caught.value and case_format(f.case) == 1


# ---------- older builds ----------

def test_a_build_that_reads_format_1_refuses_a_remapped_case(tmp_path, monkeypatch):
    """A remapped case is format 2, past which the seal takes it to 3, and a build that reads format 1 refuses it by
    number."""
    f = Format1(tmp_path)
    f.eve_run(7)
    upgraded(f.case)
    monkeypatch.setattr(case_module, "CASE_FORMAT", 1)
    with pytest.raises(CaseError, match=rf"is a case of format {CASE_FORMAT}, and this build .* reads formats up to 1\."):
        open_case(f.case.folder)


# ---------- every path that loads ----------

def found_eve_case(root: Path) -> tuple[Format1, str]:
    """A format 1 case with an EVE file found in the evidence, loaded and marked, another on a second host, taken in and
    ready to load, and a firewall log to import."""
    f = Format1(root, hosts=("SENSOR", "SENSOR2", "FW"))
    f.eve_file("SENSOR/found/eve.json", 7)
    f.eve_file("SENSOR2/found/eve.json", 7)
    (f.evidence / "FW" / "log.csv").write_text("time,src\n2024-02-05T10:00:00Z,10.0.0.1\n", encoding="utf-8")
    f.take_in()
    f.found_run("suricata", "suricata_eve", "SENSOR", ["SENSOR/found/eve.json"])
    uid = f.uids("suricata", "ts_desc <> ''")[0]
    f.mark([uid])
    return f, uid


LOADS = {"rebuild": [], "run": ["--all"], "import": ["FW/log.csv"], "load-output": ["suricata_eve", "--anyway"]}


@pytest.mark.parametrize("command", LOADS)
def test_every_command_that_loads_upgrades_the_case_first(tmp_path, command):
    """Rebuild, run, import, and load-output upgrade a format 1 case before they load, so its Suricata mark
    keeps its event, and the EVE file run --all and load-output load takes format 2's IDs."""
    f, uid = found_eve_case(tmp_path)
    assert main([command, str(f.case.folder), *LOADS[command]]) == 0
    case = open_case(f.case.folder)
    new = the_upgrade(f)["rekey"]["pairs"][uid]
    app = App(case)
    try:
        assert case_format(case) == CASE_FORMAT and app.orphans == 0 and app.journal.state.marks[new].value == "malicious"
    finally:
        app.con.close()
    loaded = [r for r in read_runs(case) if r.host == "SENSOR2"]
    assert len(loaded) == (command in ("run", "load-output"))
    for record in loaded:
        ids = EventIds(former=True)
        pairs = [ids(record.host, ev) for ev in PARSERS[record.parser](
            parse_context(case, record, case.runs_folder / record.run_id, former=1))]
        assert f.uids(where="run_id = ?", params=[record.run_id]) == sorted(n for n, _ in pairs) != sorted(o for _, o in pairs)


READS = {"import --list": (["--list"], 0), "import --preview": (["FW/log.csv", "--preview"], 0), "load-output": ([], 0),
         "runs": ([], 0), "load-output no_such_kind": (["no_such_kind"], 0),
         "run --tool no_such_tool": (["--tool", "no_such_tool"], 2),
         "import a missing mapping": (["FW/log.csv", "--mapping", "does_not_exist"], 2),   # a mapping that isn't a file
         "import that needs a choice": (["FW/no_time.csv"], 1),   # no time column, so its preview asks for one
         "run an option the tool lacks": (["--tool", "event_xml", "--option", "nosuch=1"], 2)}


@pytest.mark.parametrize("command", READS)
def test_a_command_that_loads_nothing_leaves_the_format_as_it_is(tmp_path, command):
    """A listing or a preview loads nothing, and neither does a command that stops before loading, such as one naming a
    kind or a tool there isn't, so it reads a format 1 case as it is; a command that writes upgrades the case first."""
    f, _ = found_eve_case(tmp_path)
    (f.evidence / "FW" / "no_time.csv").write_text("src,dst\n10.0.0.1,10.0.0.2\n", encoding="utf-8")
    (f.evidence / "FW" / "events.xml").write_text(   # evidence for event_xml, so run has a plan when it checks the option
        '<Events><Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System/></Event></Events>',
        encoding="utf-8")
    f.take_in()
    before = (f.journal_bytes(), digest(f.case))
    args, code = READS[command]
    assert main([command.split()[0], str(f.case.folder), *args]) == code
    assert case_format(f.case) == 1 and (f.journal_bytes(), digest(f.case)) == before


HOLD = "import sys, duckdb; con = duckdb.connect(sys.argv[1]); print('held', flush=True); sys.stdin.read()"


@pytest.mark.parametrize("command", LOADS)
def test_a_command_that_loads_refuses_while_an_app_holds_the_case(tmp_path, command, capsys):
    """Another process holding the events database, as a running app does, stops the upgrade, and so the load,
    the case unchanged."""
    f, _ = found_eve_case(tmp_path)
    before = (f.journal_bytes(), digest(f.case), run_files(f.case))
    holder = subprocess.Popen([sys.executable, "-c", HOLD, str(f.case.db_path)], stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, text=True)
    try:
        assert holder.stdout.readline().strip() == "held"
        assert main([command, str(f.case.folder), *LOADS[command]]) == 2
    finally:
        holder.communicate("", timeout=60)
    assert "another program has its events database open" in capsys.readouterr().err
    assert case_format(f.case) == 1 and (f.journal_bytes(), digest(f.case), run_files(f.case)) == before


def test_a_copy_of_a_format_1_case_is_upgraded_before_its_rebuild(tmp_path):
    """copy-case and the start page's copy upgrade the copy before its rebuild loads, so its journal holds format
    2's entry, the seal, case_created naming the source's journal, and the 3 to 4 entry; the copy's events take format
    2's IDs, and the source stays as it was."""
    from glessner.start import start_copy

    f, _ = found_eve_case(tmp_path / "source")
    before = f.journal_bytes()
    assert main(["copy-case", str(f.case.folder), str(tmp_path / "cli"), "--name", "Copy"]) == 0
    job = start_copy({"source": str(f.case.folder), "case_folder": str(tmp_path / "page"), "name": "Page"}, "cody")
    for _ in range(600):
        if job.finished:
            break
        time.sleep(0.1)
    assert job.finished and not job.error
    upgraded(f.case)
    expected = f.uids("suricata")
    for name in ("cli", "page"):
        copy = Format1.__new__(Format1)
        copy.case = open_case(tmp_path / name)
        (entry,) = copy.upgrades()
        rekeyed, seal, created, step = [json.loads(line) for line in copy.journal_bytes().splitlines()]
        assert case_format(copy.case) == CASE_FORMAT and rekeyed == entry and seal["sealed"]["lines"] == 1
        assert created["action"] == "case_created" and created["copied_from"]["bytes"] == len(before)
        assert (step["action"], step["from_format"], step["to_format"]) == ("case_upgrade", 3, 4)
        assert not entry["rekey"]["pairs"] and entry["rekey"]["runs"] and copy.uids("suricata") == expected
    assert f.journal_bytes().startswith(before)


# ---------- merges ----------

def test_references_that_reach_one_event_merge_and_the_later_mark_stands(tmp_path):
    """A mark on K2's program, then K1, which sorts first, joins the found Amcache, which orphans that mark, and a
    second mark is made on the program's new ID. Both reach one event, whose mark is the later, whose trail lists both,
    and the upgrade lists the merge."""
    f = Format1(tmp_path)
    k2 = amcache_tables(f.evidence / "DESKTOP" / "K2")
    f.take_in()
    f.found_run("amcacheparser", "amcache_csv", "DESKTOP", rel(f, k2))
    (x,) = f.uids("amcacheparser", "ts_desc = ?", [WRITTEN])
    f.mark([x])
    k1 = write_rows(f.evidence / "DESKTOP" / "K1" / "2024_Amcache_ProgramEntries.csv", AMCACHE_PROGRAM,
                    [program("p1", "Tool", "2020-09-19 01:32:10")])
    f.take_in()
    f.found_run("amcacheparser", "amcache_csv", "DESKTOP", rel(f, [*k2, k1]))
    later = event_uid("DESKTOP", "amcache", rel(f, [k1])[0], "program|p1#2", WRITTEN)
    assert x not in f.uids() and later in f.uids()
    f.mark([later], "authorized")
    merged(f, x, later)


def test_marks_before_and_after_a_move_of_a_case_without_run_folders_merge(tmp_path):
    """A SQLECmd run made before runs recorded their folders read its own copies by evidence path; the case moved, a
    format 1 rebuild gave the visit an absolute path and a new ID, and the visit was marked again. Both marks reach the
    one event."""
    f = Format1(tmp_path)
    f.sqlecmd_run(lambda elsewhere, own: [("11", own / PureWindowsPath(HISTORY))])
    (x,) = f.uids("sqlecmd", "artifact = 'browser'")
    f.mark([x])
    f.case = open_case(Path(shutil.move(f.case.folder, tmp_path / "moved")))
    rebuild_format_1(f.case)
    (later,) = f.uids("sqlecmd", "artifact = 'browser'")
    assert later != x
    f.mark([later], "authorized")
    merged(f, x, later)


def merged(f: Format1, x: str, later: str) -> None:
    app = App(f.case, for_work=True)
    try:
        entry = the_upgrade(f)
        assert entry["rekey"]["pairs"][later] == x and entry["rekey"]["merged"] == {x: sorted([x, later])}
        assert app.journal.state.marks[x].value == "authorized" and later not in app.journal.state.marks
        trail = [r for r in api_audit(app, {"event": [x]})["rows"] if r["action"] == "mark"]
        assert [(r["seq"], bool(r["rekeyed"])) for r in trail] == [(2, True), (1, False)]
        assert "Authorized" in trail[0]["text"] and "Malicious" in trail[1]["text"]
        assert "1 event now holds references made under more than one earlier ID" in describe(entry)
    finally:
        app.con.close()


# ---------- what the remap is for ----------

def test_found_amcache_and_srum_keep_their_ids_and_cite_their_own_csvs(tmp_path):
    """After the upgrade, an earlier-sorting CSV joining the found Amcache leaves the program's ID as it was,
    each event citing its own CSV; found SRUM's two Id 5 records take IDs of their own, with no repeat ordinal."""
    f = Format1(tmp_path)
    k2 = amcache_tables(f.evidence / "DESKTOP" / "K2")
    srum(f)
    f.found_run("amcacheparser", "amcache_csv", "DESKTOP", rel(f, k2))
    upgraded(f.case)
    program_id = f.uids("amcacheparser", "ts_desc = ? AND source_file LIKE '%/K2/%'", [WRITTEN])
    k1 = write_rows(f.evidence / "DESKTOP" / "K1" / "2024_Amcache_ProgramEntries.csv", AMCACHE_PROGRAM,
                    [program("p1", "Tool", "2020-09-19 01:32:10")])
    f.take_in()
    assert load_found_output(f.case, "amcacheparser", "amcache_csv", "DESKTOP", rel(f, [*k2, k1])).status == "ok"
    assert f.uids("amcacheparser", "ts_desc = ? AND source_file LIKE '%/K2/%'", [WRITTEN]) == program_id
    cited = f.rows("SELECT DISTINCT source_file FROM events WHERE tool = 'amcacheparser'")
    assert sorted(s for (s,) in cited) == sorted(rel(f, [*k2, k1]))
    fives = f.rows("SELECT source_file, source_record FROM events WHERE tool = 'srumecmd' AND source_record LIKE '%|5'")
    assert len(fives) == 3 and len({s for s, _ in fives}) == 3 and not any("#" in r for _, r in fives)


def test_a_rerun_in_another_zone_keeps_the_ids(tmp_path):
    """After the upgrade, Suricata run again on the capture by a machine five hours west of UTC gives the
    same IDs, so the marks keep their events."""
    f = Format1(tmp_path)
    f.eve_run(7)
    f.mark(f.uids("suricata"))
    upgraded(f.case)
    ids = f.uids("suricata")
    rerun = f.eve_run(-5, load_it=False)
    load_output(f.case, rerun, f.case.runs_folder / rerun.run_id)
    assert f.uids("suricata") == ids and f.uids(where="run_id = ?", params=[rerun.run_id]) == ids
    assert set(state_of(f.case)["marks"]) == set(ids)


def test_runs_without_recorded_folders_read_as_evidence_paths_and_are_pinned_where_they_can_be(tmp_path):
    """A SQLECmd run made before runs recorded their folders, read from another case's folder, loads evidence paths and
    bob's account; its output names that folder, so its record is left empty and named, as is such a run whose evidence
    moved before the upgrade. One whose output names only the evidence and its own run folder is pinned to them. A
    found-output run keeps its empty folder, so an evidence move, with case.yaml naming the new folder, and a rebuild
    leave its IDs and relative sources, and the pinned run's."""
    f = Format1(tmp_path)
    elsewhere = f.sqlecmd_run()
    pinned = f.sqlecmd_run(lambda elsewhere, own: [("11", own / PureWindowsPath(HISTORY))], host="WS03", notified_in="own")
    moved_before = f.sqlecmd_run(lambda elsewhere, own: [
        ("12", PureWindowsPath("D:/Evidence/before-the-move") / PureWindowsPath(HISTORY))], host="WS02", notified_in="own")
    f.eve_file("SENSOR/found/eve.json", 7)
    f.take_in()
    found = f.found_run("suricata", "suricata_eve", "SENSOR", ["SENSOR/found/eve.json"])
    upgraded(f.case)
    visits = f.rows("SELECT source_file, user_name FROM events WHERE run_id = ? AND artifact = 'browser'",
                    [elsewhere.run_id])
    assert visits == [(HISTORY, "bob")]
    records = {r.run_id: r for r in read_runs(f.case)}
    assert records[pinned.run_id].evidence_root == str(f.evidence)
    assert records[pinned.run_id].input_root == str(f.case.runs_folder / pinned.run_id / "input")
    assert [records[r.run_id].evidence_root for r in (elsewhere, moved_before, found)] == ["", "", ""]
    unpinned = the_upgrade(f)["rekey"]["unpinned_runs"]
    assert set(unpinned) == {elsewhere.run_id, moved_before.run_id}
    assert unpinned[elsewhere.run_id].startswith("2 of its events name a file outside the case's evidence folder")
    ids = f.uids("suricata")
    evidence = Path(shutil.move(f.evidence, tmp_path / "evidence_moved"))
    data = (f.case.folder / "case.yaml").read_text(encoding="utf-8").replace(str(tmp_path / "evidence"), str(evidence))
    (f.case.folder / "case.yaml").write_text(data, encoding="utf-8")
    rebuild(f.reopen())
    assert f.uids("suricata") == ids
    assert {s for (s,) in f.rows("SELECT DISTINCT source_file FROM events WHERE tool = 'suricata'")} == {
        "SENSOR/found/eve.json"}
    assert f.rows("SELECT source_file FROM events WHERE run_id = ? AND artifact = 'browser'", [pinned.run_id]) == [
        (HISTORY,)]


def test_a_final_entry_without_a_line_break_survives_the_upgrade(tmp_path):
    """The last entry is complete but has no LF, as a hand edit leaves it. The format 1 reader accepts it;
    this build's reader stops at the last LF, so the upgrade gives it its line end first, records that, and reads
    its reference. The entries it appends start lines of their own: the journal reads, its bytes and the LF are a prefix
    of the new file, the case is at this build's format, and the mark is on the event's new ID."""
    f = Format1(tmp_path, hosts=("SENSOR",))
    f.eve_run(7)
    old = f.uids("suricata")[:1]
    f.mark(old)
    journal = f.case.folder / "journal.jsonl"
    bare = journal.read_bytes().rstrip(b"\n")
    journal.write_bytes(bare)
    assert not Journal(f.case).state.marks
    upgraded(f.case)
    new = the_upgrade(f)["rekey"]["pairs"][old[0]]
    assert the_upgrade(f)["recovered"] == [{"completed": True, "entry": {"action": "mark", "seq": 1}}]
    assert new != old[0] and case_format(f.case) == CASE_FORMAT
    after = journal.read_bytes()
    assert after.startswith(bare + b"\n") and after.count(b"\n") == 5
    written = [json.loads(line) for line in after.splitlines()]
    assert [(e["action"], e.get("from_format"), e.get("to_format")) for e in written] == [
        ("mark", None, None), ("case_upgrade", 1, 2), ("case_upgrade", 2, 3), ("case_yaml", None, None),
        ("case_upgrade", 3, 4)]
    assert set(Journal(open_case(f.case.folder)).state.marks) == {new} and set(f.uids("suricata")) >= {new}


def mixed_zone_eve_case(root: Path) -> tuple[Format1, str]:
    """A format 1 case whose one EVE file spells one instant in two zones, a record at +0700 and one at +0000 with the
    same keys, told apart by their HTTP hostnames. Format 1 keyed them apart; format 2's rule keys them to one instant, so
    the first record takes the second's old ID and the second takes the repeat's. The second record's old ID is marked."""
    f = Format1(root, hosts=("SENSOR",))
    common = {"event_type": "http", "src_ip": "10.0.0.5", "src_port": 49200, "dest_ip": "203.0.113.9", "dest_port": 80,
              "proto": "TCP", "tx_id": 0}
    records = [
        {**common, "timestamp": "2024-05-14T19:00:00.000000+0700",
         "http": {"hostname": "first.example", "url": "/a", "http_method": "GET"}},
        {**common, "timestamp": "2024-05-14T12:00:00.000000+0000",
         "http": {"hostname": "second.example", "url": "/a", "http_method": "GET"}},
    ]
    f.tool_run("suricata", "suricata_eve", "SENSOR", ["SENSOR/capture.pcap"],
               lambda out: (out / "eve.json").write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8"))
    (old,) = [u for (u,) in f.rows("SELECT event_uid FROM events WHERE message LIKE '%second.example%'")]
    f.mark([old])
    return f, old


def test_an_id_that_names_a_loaded_event_and_is_also_an_earlier_id_of_another_says_so(tmp_path):
    """The second record's old ID is the first record's ID after the upgrade. The Event page and the trail keep the event
    the ID names, and say that an upgrade also moved the old ID to another event, naming it; the ID's successor opens
    its own event, without the notice."""
    f, old = mixed_zone_eve_case(tmp_path)
    app = App(upgraded(f.case))
    try:
        entry = the_upgrade(f)
        new = entry["rekey"]["pairs"][old]
        notice = {"now": new, "seqs": [entry["seq"]]}
        assert old != new and new in app.journal.state.marks and old not in app.journal.state.marks
        event = api_event(app, {"uid": [old]})["event"]
        assert event["event_uid"] == old and "first.example" in event["message"]
        assert event["id_also_named"] == notice and "id_changed" not in event
        trail = api_audit(app, {"event": [old]})
        assert trail["total"] == 0 and trail["id_also_named"] == notice
        successor = api_event(app, {"uid": [new]})["event"]
        assert "second.example" in successor["message"] and "id_also_named" not in successor
        assert successor["mark"]["label"] == "Malicious"
        trail = api_audit(app, {"event": [new]})
        assert trail["total"] == 1 and "id_also_named" not in trail
    finally:
        app.con.close()


def test_a_run_record_and_the_dropped_runs_file_reach_the_disk_before_they_take_their_names(tmp_path, monkeypatch):
    """run.json and upgrade_dropped_runs.json are written through a temporary file that is flushed to disk before
    the replace, so they survive a power loss as they survive a stopped process; a stop inside the write leaves the
    record as it was."""
    f = Format1(tmp_path, hosts=("SENSOR",))
    run = f.eve_run(7)
    gone = f.eve_run(7, capture="SENSOR/gone.pcap")
    (f.case.runs_folder / gone.run_id / "run.json").unlink()
    path = f.case.runs_folder / run.run_id / "run.json"
    before = path.read_bytes()
    original = Path.open

    def interrupted(p, mode="r", *args, **kwargs):
        stream = original(p, mode, *args, **kwargs)
        if p.name.startswith("run.json") and mode.startswith("w"):
            stream.close()
            raise OSError("interrupted after opening run.json for writing")
        return stream

    monkeypatch.setattr(Path, "open", interrupted)
    run.status = "failed"
    with pytest.raises(OSError, match="interrupted"):
        _write_record(path.parent, run)
    monkeypatch.undo()
    assert path.read_bytes() == before
    steps = []
    real_fsync, real_replace = os.fsync, os.replace
    monkeypatch.setattr(os, "fsync", lambda fd: (steps.append("fsync"), real_fsync(fd))[1])
    monkeypatch.setattr(os, "replace", lambda src, dst: (steps.append(Path(dst).name), real_replace(src, dst))[1])
    run.status = "ok"
    _write_record(path.parent, run)
    assert steps == ["fsync", "run.json"]
    steps.clear()
    upgraded(f.case)
    assert rekey.DROPPED_FILE in steps and steps[steps.index(rekey.DROPPED_FILE) - 1] == "fsync"


# ---------- the start page's open ----------

def open_job(folder, monkeypatch):
    """The start page's open of a case folder, run to its end: the job, and each stage it reported in order."""
    from glessner.server import Hub
    from glessner.start import StartJob, start_open_case

    stages = []
    report = StartJob.report

    def recorded(self, stage, done=0, total=0):
        stages.append((stage, done, total))
        report(self, stage, done, total)

    monkeypatch.setattr(StartJob, "report", recorded)
    hub = Hub()
    job = start_open_case(open_case(folder), hub.open)
    for _ in range(600):
        if job.finished:
            break
        time.sleep(0.1)
    assert job.finished
    return job, stages, hub


def test_the_start_page_s_open_reports_the_upgrade_s_stages(tmp_path, monkeypatch):
    """The open of a format 1 case runs as the start page's job, which reports the upgrade's stages with counts
    (checking, reading, reloading N events of a tool, pinning) and then "Opening", so the page can show them while the
    20 s of the Szechuan case's upgrade pass."""
    f, _ = found_eve_case(tmp_path)
    con = connect(f.case.db_path, read_only=True)
    rows = con.execute("SELECT count(*) FROM events WHERE tool = 'suricata' AND origin_host = 'SENSOR'").fetchone()[0]
    con.close()
    job, stages, hub = open_job(f.case.folder, monkeypatch)
    try:
        assert not job.error and job.opened and job.kind == "open" and job.result == {"opened": "Remap"}
        names = [s for s, _, _ in stages]
        assert names[0].startswith("Upgrading the case format: checking the output of the runs") and names[-1] == "Opening"
        assert f"Upgrading the case format: reloading {rows:,} Suricata events" in names and rows > 1
        reloading = f"Upgrading the case format: reloading {rows:,} Suricata events"
        assert names.index(reloading) < names.index("Upgrading the case format: recording where the runs read their files")
        assert [(d, t) for s, d, t in stages if "reading the output" in s][-1][1] >= 1   # counts, where the step has them
        # A counted stage counts the item it is on, so the last of each reads "N of N", not "N-1 of N"
        for part in ("checking the output", "reading the output", "reloading", "recording where"):
            counted = [(d, t) for s, d, t in stages if part in s]
            assert counted and counted[-1][0] == counted[-1][1] >= 1 and counted[0][0] == 1
        assert case_format(f.case) == CASE_FORMAT
        assert job.stage == "Opening"
    finally:
        hub.app.con.close()


def test_a_case_with_nothing_to_upgrade_reports_one_opening_stage(synthetic_case, monkeypatch):
    job, stages, hub = open_job(synthetic_case.folder, monkeypatch)
    try:
        assert not job.error and job.opened and job.stage == "Opening" and job.name == synthetic_case.settings.name
        assert stages == [("Opening", 0, 0)]
    finally:
        hub.app.con.close()


def test_the_serve_command_lists_the_upgrade_s_steps_as_each_starts(tmp_path, monkeypatch, capsys):
    """serve's open of a format 1 case says that it upgrades the case, and lists each stage the
    upgrade reports once, in order, then the open's own and "Opened", then the format the open left the case at, before
    the link. Each line is written as its step starts, not when the open ends: the reload's line is in the command
    window when its first run reloads."""
    from glessner import server
    from glessner.cli import OPENING

    f, _ = found_eve_case(tmp_path)
    con = connect(f.case.db_path, read_only=True)
    rows = con.execute("SELECT count(*) FROM events WHERE tool = 'suricata' AND origin_host = 'SENSOR'").fetchone()[0]
    con.close()
    before = []   # the window's lines when each run's reload starts
    reload_run = rekey.reload_run

    def watched(*args, **kwargs):
        before.append(capsys.readouterr().out)
        return reload_run(*args, **kwargs)

    monkeypatch.setattr(rekey, "reload_run", watched)
    monkeypatch.setattr(server.Server, "serve_forever", lambda self: None)
    assert main(["serve", str(f.case.folder), "--no-browser", "--port", "0"]) == 0
    lines = "".join([*before, capsys.readouterr().out]).splitlines()
    assert lines[1] == ("It is at case format 1, from an earlier build, so this open upgrades it to format 4 first. The "
                        "upgrade runs once, and on a large case it takes a while; each step is listed as it starts.")
    steps = [line[8:] for line in lines[2:] if line[:8].endswith(" s  ") and not line[8:].startswith("  still")]
    reloading = next(s for s in steps if s.startswith(f"Upgrading the case format: reloading {rows:,} Suricata events, "))
    assert rows > 1 and steps[0].startswith("Upgrading the case format: checking the output of the runs, 1 of ")
    assert steps[-2:] == [OPENING, "Opened."]
    assert steps.index(reloading) < next(i for i, s in enumerate(steps) if "recording where the runs read" in s)
    assert len(steps) == len({s.split(", ")[0] for s in steps})   # one line per stage, not per count
    assert before and " s  Upgrading the case format: reloading " in before[0].splitlines()[-1]
    assert reloading in "".join(before)
    opened = next(i for i, line in enumerate(lines) if line.endswith("  Opened."))
    assert opened < next(i for i, line in enumerate(lines) if line.startswith("Serving "))
    assert lines[opened + 1] == "It is now at case format 4, which older builds can't open."
    assert lines[opened + 2].startswith("Serving ")
    assert case_format(f.case) == CASE_FORMAT
