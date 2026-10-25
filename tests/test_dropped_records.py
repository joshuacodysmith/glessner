"""A line or a row that no event is made of is counted in a note on the run, which the next load of the output replaces,
and, for the parsers that count them, in the run's record once the case is at format 4."""

import csv
import json
from pathlib import Path

import pytest
from chain_fixtures import format3_case
from conftest import flip_a_byte, nested_list
from rekey_cases import Format1
from rekey_fixtures import eve_records
from test_file_parsers import write_csv
from test_runner import write_pecmd
from test_suricata import EVE

from glessner import runner
from glessner.case import create_case, open_case
from glessner.intake import intake
from glessner.parsers import PARSERS, ParseContext, suricata
from glessner.parsers.common import SKIPPED_NOTE
from glessner.rekey import upgraded
from glessner.runner import (
    LEFT_OUT,
    UNFINISHED_NOTE,
    _check_outputs,
    finish_run,
    load_output,
    read_runs,
    rebuild,
    start_run,
)
from glessner.tools import load_registry

EVIDENCE = Path("D:/Evidence/case")
INPUTS = ("SENSOR/capture.pcap",)
CUT = "not a JSON record, or nested too deep to read, such as a last line cut short when Suricata stopped."
GOOD = [EVE[0], EVE[1]]
STATS = EVE[3]


def write_eve(folder, records, tail=""):
    (folder / "eve.json").write_text("".join(json.dumps(r) + "\n" for r in records) + tail, encoding="utf-8")


def parse_eve(folder):
    ctx = ParseContext(folder, EVIDENCE, INPUTS)
    return list(PARSERS["suricata_eve"](ctx)), ctx.notes


def test_a_cut_short_last_line_is_counted_and_named(tmp_path):
    write_eve(tmp_path, GOOD, tail=json.dumps(EVE[2])[:40])
    events, notes = parse_eve(tmp_path)
    assert len(events) == 2
    assert notes == [f"{SKIPPED_NOTE}1 line of eve.json for SENSOR/capture.pcap: {CUT}"]


def test_lines_that_are_not_json_objects_are_counted_and_blank_lines_and_stats_records_are_not(tmp_path):
    write_eve(tmp_path, [GOOD[0], STATS, GOOD[1]], tail="\n   \n[1, 2]\n\"text\"\nnot json\n")
    events, notes = parse_eve(tmp_path)
    assert len(events) == 2
    assert notes == [f"{SKIPPED_NOTE}3 lines of eve.json for SENSOR/capture.pcap: {CUT}"]


def test_a_line_nested_too_deep_to_read_is_counted(tmp_path):
    deep = '{"timestamp": "2024-05-14T19:00:00.000000+0700", "event_type": "dns", "x": ' + "[" * 30_000 + "]" * 30_000 + "}"
    write_eve(tmp_path, GOOD, tail=deep + "\n")
    events, notes = parse_eve(tmp_path)
    assert len(events) == 2
    assert notes == [f"{SKIPPED_NOTE}1 line of eve.json for SENSOR/capture.pcap: {CUT}"]


def test_a_record_too_deep_to_write_back_is_counted(tmp_path, monkeypatch):
    monkeypatch.setattr(suricata, "_records", lambda path: iter([(1, {**GOOD[0], "x": nested_list(100_000)}), (2, GOOD[1])]))
    events, notes = parse_eve(tmp_path)
    assert len(events) == 1
    assert notes == [f"{SKIPPED_NOTE}1 line of eve.json for SENSOR/capture.pcap: {CUT}"]


def test_a_clean_file_has_no_note(tmp_path):
    write_eve(tmp_path, [*GOOD, STATS])
    assert parse_eve(tmp_path)[1] == []


def test_a_file_found_in_the_evidence_is_named_as_its_events_name_it(tmp_path):
    folder = tmp_path / "SENSOR"
    folder.mkdir()
    write_eve(folder, GOOD, tail="{\n")
    ctx = ParseContext(tmp_path / "output", tmp_path, files=(folder / "eve.json",))
    events = list(PARSERS["suricata_eve"](ctx))
    assert len(events) == 2
    assert ctx.notes == [f"{SKIPPED_NOTE}1 line of SENSOR/eve.json: {CUT}"]


MFT_ROW = {"EntryNumber": "41", "SequenceNumber": "4", "InUse": "True", "ParentPath": r".\Users\rick", "FileName": "a.exe",
           "Created0x10": "2020-09-19 03:24:06.0000000", "SourceFile": r"D:\Evidence\case\DESKTOP\$MFT"}


def test_mft_rows_with_no_readable_time_are_counted(tmp_path):
    columns = list(MFT_ROW)
    timeless = {**MFT_ROW, "EntryNumber": "42", "Created0x10": ""}
    unreadable = {**MFT_ROW, "EntryNumber": "43", "Created0x10": "not a time"}
    with (tmp_path / "mftecmd.csv").open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
        writer.writerows([MFT_ROW, timeless, unreadable])
    ctx = ParseContext(tmp_path, EVIDENCE)
    events = list(PARSERS["mftecmd_csv"](ctx))
    assert [e.source_record for e in events] == ["41-4:a.exe"]
    assert ctx.notes == [f"{SKIPPED_NOTE}2 rows of MFTECmd's CSV: none of their times could be read."]
    write_csv(tmp_path / "mftecmd.csv", [timeless])
    ctx = ParseContext(tmp_path, EVIDENCE)
    assert list(PARSERS["mftecmd_csv"](ctx)) == []
    assert ctx.notes == [f"{SKIPPED_NOTE}1 row of MFTECmd's CSV: none of its times could be read."]


def test_loading_the_same_output_twice_leaves_one_note(tmp_path):
    evidence = tmp_path / "evidence" / "SENSOR"
    evidence.mkdir(parents=True)
    (evidence / "capture.pcap").write_bytes(b"\xd4\xc3\xb2\xa1" + bytes(20))
    case = create_case(tmp_path / "case", "Dropped", tmp_path / "evidence", "cody")
    intake(case)
    record, folder = start_run(case, "suricata", "SENSOR", tool_version="8", host="SENSOR", parser="suricata_eve",
                               inputs=list(INPUTS))
    (folder / "output").mkdir()
    write_eve(folder / "output", GOOD, tail=json.dumps(EVE[2])[:40])
    for _ in range(2):
        load_output(case, record, folder)
    assert [n for n in record.notes if n.startswith(SKIPPED_NOTE)] == [
        f"{SKIPPED_NOTE}1 line of eve.json for SENSOR/capture.pcap: {CUT}"]
    assert record.loaded_rows == 2


FORMAT_4_KEYS = {"tool_files", "rows_skipped", "tool_check"}
CUT_LINE = json.dumps(EVE[2])[:40]
MFT_ROWS = [MFT_ROW, {**MFT_ROW, "EntryNumber": "42", "Created0x10": ""}, {**MFT_ROW, "EntryNumber": "43", "Created0x10": "x"}]


def capture_case(tmp_path):
    evidence = tmp_path / "evidence" / "SENSOR"
    evidence.mkdir(parents=True)
    (evidence / "capture.pcap").write_bytes(b"\xd4\xc3\xb2\xa1" + bytes(20))
    case = create_case(tmp_path / "case", "Dropped", tmp_path / "evidence", "cody")
    intake(case)
    return case


def loaded_run(case, tool, parser, write):
    """A tool's ok run on the capture, started and finished as a run is but without running a tool, so it records no
    tool files, its output written by write(output folder), and loaded."""
    record, folder = start_run(case, tool, "SENSOR", tool_version="1", host="SENSOR", parser=parser, inputs=list(INPUTS))
    (folder / "output").mkdir()
    write(folder / "output")
    _check_outputs(load_registry()[tool], folder / "output", record)
    record.status = "ok"
    load_output(case, record, folder)
    finish_run(folder, record)
    return record


def eve_run(case, tail=""):
    return loaded_run(case, "suricata", "suricata_eve", lambda out: write_eve(out, GOOD, tail=tail))


def saved(case, record) -> dict:
    return json.loads((case.runs_folder / record.run_id / "run.json").read_text(encoding="utf-8"))


def test_each_file_a_parser_reads_gives_its_own_count(tmp_path):
    """ParseContext.skipped holds a count for each file read, in the order read, 0 for a clean one."""
    for folder, tail in (("A", CUT_LINE), ("B", "")):
        (tmp_path / folder).mkdir()
        write_eve(tmp_path / folder, GOOD, tail=tail)
    ctx = ParseContext(tmp_path / "output", tmp_path, files=(tmp_path / "B" / "eve.json", tmp_path / "A" / "eve.json"))
    assert len(list(PARSERS["suricata_eve"](ctx))) == 4 and ctx.skipped == [1, 0]
    write_csv(tmp_path / "A" / "mftecmd.csv", MFT_ROWS)
    write_csv(tmp_path / "B" / "mftecmd.csv", MFT_ROWS[:2])
    ctx = ParseContext(tmp_path / "output", EVIDENCE, files=(tmp_path / "B" / "mftecmd.csv", tmp_path / "A" / "mftecmd.csv"))
    assert len(list(PARSERS["mftecmd_csv"](ctx))) == 2 and ctx.skipped == [2, 1]


def test_a_load_records_what_its_parser_made_no_event_of_for_the_parsers_that_count_it(tmp_path):
    """MFTECmd's and Suricata's parsers count what they drop, 0 for a clean file, and a load of the output again replaces
    the count rather than adding to it. PECmd's drops rows without counting them, so its run records none, rather than
    a 0 that would read as none dropped."""
    case = capture_case(tmp_path)
    cut = eve_run(case, tail=CUT_LINE)
    assert (cut.rows_skipped, saved(case, cut)["rows_skipped"]) == (1, 1)
    load_output(case, cut, case.runs_folder / cut.run_id)
    assert cut.rows_skipped == 1
    clean = eve_run(case)
    assert (clean.rows_skipped, saved(case, clean)["rows_skipped"]) == (0, 0)
    mft = loaded_run(case, "mftecmd", "mftecmd_csv", lambda out: write_csv(out / "mftecmd.csv", MFT_ROWS))
    assert (mft.loaded_rows, mft.rows_skipped) == (1, 2)
    pecmd = loaded_run(case, "pecmd", "pecmd_csv", lambda out: write_pecmd(out / "pecmd.csv", case, "A.EXE",
                                                                           "2024-01-01 00:00:00.0000000"))
    assert pecmd.loaded_rows == 1 and pecmd.rows_skipped is None and "rows_skipped" not in saved(case, pecmd)


def test_only_a_case_at_format_4_records_the_count_and_its_rebuild_counts_every_run(tmp_path):
    """A case below format 4 keeps run.json in the shape the builds of its format read, so neither a load nor a rebuild
    there records the count. Once the case is at format 4, a rebuild records it for each run it loads, a run made before
    included: the count comes from the run's own output, which the rebuild checks against its hashes."""
    case = format3_case(capture_case(tmp_path))
    record = eve_run(case, tail=CUT_LINE)
    rebuild(case)
    assert record.rows_skipped is None and not FORMAT_4_KEYS & set(saved(case, record))
    case = upgraded(open_case(case.folder))
    assert case.settings.case_format == 4 and not FORMAT_4_KEYS & set(saved(case, record))
    rebuild(case)
    assert saved(case, record)["rows_skipped"] == 1


def test_the_steps_from_format_1_record_no_count_and_a_rebuild_at_format_4_does(tmp_path):
    """The 1 to 2 step reloads Suricata's runs, and the steps pin a run made before runs recorded their folders, each in
    a case below format 4, so none of them records the count."""
    f = Format1(tmp_path)
    write = lambda out: (out / "eve.json").write_text(
        "".join(json.dumps(r) + "\n" for r in eve_records(7)) + CUT_LINE, encoding="utf-8")
    pinned = f.tool_run("suricata", "suricata_eve", "SENSOR", ["SENSOR/capture.pcap"], write, no_folders=True)
    case = upgraded(f.case)
    assert case.settings.case_format == 4 and saved(case, pinned)["evidence_root"]   # the steps wrote its record
    assert not FORMAT_4_KEYS & set(saved(case, pinned))
    rebuild(case)
    assert saved(case, pinned)["rows_skipped"] == 1


def test_a_run_a_rebuild_left_out_or_has_not_loaded_yet_has_no_count(tmp_path, monkeypatch):
    case = capture_case(tmp_path)
    record = eve_run(case, tail=CUT_LINE)
    output = case.runs_folder / record.run_id / "output" / "eve.json"
    original = output.read_bytes()
    flip_a_byte(output, at=3)
    rebuild(case)
    left_out = saved(case, record)
    assert LEFT_OUT in left_out["notes"][-1] and left_out["loaded_rows"] == 0 and "rows_skipped" not in left_out
    output.write_bytes(original)
    rebuild(case)
    assert saved(case, record)["rows_skipped"] == 1
    case.db_path.unlink()   # as a copy's first rebuild finds it: each record is written unloaded before the loads

    def refuse(*args, **kwargs):
        raise ValueError("a row the parser can't read")

    monkeypatch.setattr(runner, "load_output", refuse)
    with pytest.raises(ValueError):
        rebuild(case)
    unfinished = saved(case, record)
    assert unfinished["notes"][-1].endswith(UNFINISHED_NOTE) and "rows_skipped" not in unfinished
    assert [r.loaded_rows for r in read_runs(case)] == [0]
