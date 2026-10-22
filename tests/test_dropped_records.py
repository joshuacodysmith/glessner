"""A line or a row that no event is made of is counted in a note on the run, which the next load of the output replaces."""

import csv
import json
from pathlib import Path

from conftest import nested_list
from test_file_parsers import write_csv
from test_suricata import EVE

from glessner.case import create_case
from glessner.intake import intake
from glessner.parsers import PARSERS, ParseContext, suricata
from glessner.parsers.common import SKIPPED_NOTE
from glessner.runner import load_output, start_run

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
