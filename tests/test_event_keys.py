"""The event keys: found Amcache and SRUM cite the CSV each row came from, Suricata's key holds its time in UTC, and
SQLECmd reads a working copy's path inside its run's folder wherever that folder was. Each parser gives format 1's key
beside the new one, from the same record, so the case format upgrade pairs them exactly."""

import dataclasses
import hashlib
import json

import pytest
from rekey_fixtures import (
    AMCACHE_FILE,
    AMCACHE_PROGRAM,
    FIXTURES,
    HISTORY,
    HOSTS,
    context,
    eve,
    found,
    program,
    sqlecmd,
    srum_found,
    write_rows,
)

from glessner.events import Event, EventIds, event_uid
from glessner.parsers import FORMER_RULES, PARSERS
from glessner.parsers.common import profile_name

# Each fixture's events as the parsers gave them in the last build that read only case format 1, digested over every
# field: made with that build's tree by fields_digest below.
FORMAT_1_FIELDS = {"amcache_found": "fdd063f56e51a635", "amcache_tool": "8271b18736cc6817",
                   "srum_found": "3da9745514125e91", "srum_tool": "9e9addef16f0aa7c", "eve": "aed27941a62cbb3e",
                   "eve_found": "0a2f3ed392907501", "sqlecmd": "6e0691062bb6ef6f"}
FIELDS = [f.name for f in dataclasses.fields(Event) if f.name != "former"]


def fields_digest(events) -> str:
    rows = [[getattr(e, name) for name in FIELDS] for e in events]
    text = json.dumps(rows, sort_keys=True, default=str, ensure_ascii=False)
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()[:16]


def as_format_1(ev: Event, parser: str) -> Event:
    """The event under format 1's rule, from its former key: SQLECmd's account is the profile its source names."""
    if ev.former is None:
        return dataclasses.replace(ev)
    source_file, source_record = ev.former
    user = profile_name(source_file) if parser == "sqlecmd_csv" else ev.user_name
    return dataclasses.replace(ev, source_file=source_file, source_record=source_record, user_name=user, former=None)


PARSER_OF = {"amcache_found": "amcache_csv", "amcache_tool": "amcache_csv", "srum_found": "srumecmd_csv",
             "srum_tool": "srumecmd_csv", "eve": "suricata_eve", "eve_found": "suricata_eve", "sqlecmd": "sqlecmd_csv"}


@pytest.mark.parametrize("name", FIXTURES)
def test_both_rules_name_one_record(tmp_path, name):
    """Each event carries its format 1 key beside its own, and is the event format 1 gave in every field but its
    source file and source record, and SQLECmd's account. In each run the former IDs and the new are one to one."""
    events = FIXTURES[name](tmp_path, former=1)
    assert PARSER_OF[name] in FORMER_RULES
    assert fields_digest(as_format_1(e, PARSER_OF[name]) for e in events) == FORMAT_1_FIELDS[name]
    assert all(e.former != (e.source_file, e.source_record) for e in events)   # set only when it differs
    pair = EventIds(former=True)
    pairs = [pair(HOSTS[name], e) for e in events]
    assert len({new for new, _ in pairs}) == len({old for _, old in pairs}) == len(set(pairs)) == len(events)
    assert not any(e.former for e in FIXTURES[name](tmp_path / "again"))   # only when asked


def test_found_amcache_cites_each_csv_and_keeps_its_ids_when_an_earlier_csv_joins(tmp_path):
    """Found output cites the CSV each row came from, not the group's first CSV, so a CSV that sorts earlier, added
    later, changes no other event's ID. Each event cites its own CSV, which a tool run's don't."""
    evidence = tmp_path / "evidence"
    programs = write_rows(evidence / "DESKTOP" / "2024_Amcache_ProgramEntries.csv", AMCACHE_PROGRAM,
                          [program("p1", "Tool", "2020-09-19 01:32:10")])
    parse = lambda paths: list(PARSERS["amcache_csv"](context(tmp_path / "out", evidence, *found(evidence, paths))))
    ids = lambda events: [event_uid("DESKTOP", e.artifact, e.source_file, e.source_record, e.ts_desc) for e in events]
    before = parse([programs])
    earlier = write_rows(evidence / "DESKTOP" / "2024_Amcache_AssociatedFileEntries.csv", AMCACHE_FILE, [
        {"ProgramId": "p1", "FileKeyLastWriteTimestamp": "2020-09-19 01:32:11", "FullPath": "c:\\tool\\tool.exe"}])
    after = parse([earlier, programs])
    assert ids(after)[1:] == ids(before) and len(after) == 3
    assert [e.source_file for e in after] == ["DESKTOP/2024_Amcache_AssociatedFileEntries.csv",
                                              "DESKTOP/2024_Amcache_ProgramEntries.csv",
                                              "DESKTOP/2024_Amcache_ProgramEntries.csv"]
    tool = list(PARSERS["amcache_csv"](context(evidence / "DESKTOP", evidence, ("DESKTOP/Amcache.hve",))))
    assert {e.source_file for e in tool} == {"DESKTOP/Amcache.hve"}


def test_found_srum_rows_of_one_table_and_id_take_their_own_ids(tmp_path):
    """Found SRUM cites its file, so two collections' records of one table and Id don't share a key, which would give
    the second loaded #2 and let a mark move from one to the other. Each has its base ID."""
    a, b = [e for e in srum_found(tmp_path, former=1) if e.source_record == "NetworkUsages|5"]
    assert (a.process_executable, b.process_executable) == ("a.exe", "b.exe")
    pair = EventIds(former=True)
    (a_new, a_old), (b_new, b_old) = pair("DESKTOP", a), pair("DESKTOP", b)
    assert a_new == event_uid("DESKTOP", "srum", "DESKTOP/K1/2024_SrumECmd_NetworkUsages_Output.csv", "NetworkUsages|5",
                              "SRUM network use recorded")
    assert b_new == event_uid("DESKTOP", "srum", "DESKTOP/K2/2024_SrumECmd_NetworkUsages_Output.csv", "NetworkUsages|5",
                              "SRUM network use recorded")
    assert (a_old, b_old) == (event_uid("DESKTOP", "srum", "", "NetworkUsages|5", "SRUM network use recorded"),
                              event_uid("DESKTOP", "srum", "", "NetworkUsages|5#2", "SRUM network use recorded"))


def test_one_eve_written_in_two_zones_gives_the_same_ids(tmp_path):
    """Suricata writes times in the zone of the machine it ran on, so a key that held them as written would give a
    rerun elsewhere no ID in common with the first (0 of 1,445 keys when measured). The key's time is in UTC, by each
    route: a flow's start, a record's own timestamp, and a flow record's flow.start. EVE written at +0000 keeps its
    IDs."""
    ids = lambda events: [event_uid("SENSOR", e.artifact, e.source_file, e.source_record, e.ts_desc) for e in events]
    east, west, utc = eve(tmp_path, hours=7), eve(tmp_path, hours=-5, former=1), eve(tmp_path, hours=0, former=1)
    assert ids(east) == ids(west) == ids(utc)
    assert not any(e.former for e in utc)   # written at +0000: format 1's key is the same
    assert sum(1 for e in west if e.former) == 5   # all but the two times to_us can't read
    http = west[0]
    assert http.source_record.startswith("eve|http|2020-09-19T03:21:50.000000+0000|")   # its flow's start, in UTC
    assert http.former[1].startswith("eve|http|2020-09-18T22:21:50.000000-0500|")


def test_a_run_without_recorded_folders_reads_its_copies_inside_another_cases_folder(tmp_path):
    """A SQLECmd run whose record names no working copies' folder names the copies in the case's run folder where it
    ran. Read in a case moved or copied since, that path is the other case's, and the account would come from it,
    such as the analyst's own. What follows runs\\<this run's ID>\\input\\ is the evidence path."""
    events = sqlecmd(tmp_path, former=1)
    by_code = {(e.event_code, e.source_record): e for e in events}
    moved = by_code[("visit", "visit|10")]
    assert (moved.source_file, moved.user_name) == (HISTORY, "bob")
    assert moved.former[0].startswith("C:/Users/analyst/cases/a/runs/") and profile_name(moved.former[0]) == "analyst"
    toast = by_code[("notification", "notification|1")]
    assert (toast.source_file, toast.user_name) == ("WS01/Users/bob/AppData/Local/Microsoft/Windows/Notifications/"
                                                    "wpndatabase.db", "bob")
    own = by_code[("visit", "visit|11")]   # this run's own folder: the same under both rules
    assert (own.source_file, own.user_name, own.former) == (HISTORY.replace("/bob/", "/carol/"), "carol", None)
    other = by_code[("visit", "visit|13")]   # another run's folder isn't this run's copies
    assert other.source_file.startswith("C:/Users/analyst/cases/a/runs/20261014T000000Z_sqlecmd_WS01/input/")
    assert other.former is None
