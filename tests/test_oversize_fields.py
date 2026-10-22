"""A record whose CSV line is too long for DuckDB to read has its longest text fields cut to fit. The rest of the load,
the record's other fields, and every event ID are unchanged."""

import csv
import json

import pytest

from glessner.events import COLUMNS, CUT_CHECK, MESSAGE, Event, EventIds, _fit, connect, load
from glessner.parsers import PARSERS, ParseContext

HOST = "LAB"
SOURCE = "LAB/Sysmon.evtx"
BUDGET = 16_000_000  # bytes a row may take in the staging CSV


def event(record, **fields):
    message = fields.pop("message", f"event {record}")
    return Event(1600485708000000, "Event Recorded", "evtx", SOURCE, record, message, record_id=int(record), **fields)


def load_events(tmp_path, events):
    db = tmp_path / "events.duckdb"
    result = load(
        db, events, host=HOST, tool="evtxecmd", tool_version="1", run_id="r1", replaces_sources=[SOURCE], staging_dir=tmp_path
    )
    return db, result


def stored(db, columns="*", where="true"):
    """Every row's values as a dict, in record order."""
    con = connect(db, read_only=True)
    try:
        cursor = con.execute(f"SELECT {columns} FROM events WHERE {where} ORDER BY record_id")
        names = [d[0] for d in cursor.description]
        return [dict(zip(names, row)) for row in cursor.fetchall()]
    finally:
        con.close()


def csv_bytes(row):
    """The bytes of a stored row's text in the staging CSV: UTF-8, with each double quote written twice."""
    return sum(len(v.encode("utf-8")) + v.count('"') for v in row.values() if isinstance(v, str))


def marker(characters):
    return f" [cut to fit one row: {characters:,} characters in all]"


def test_a_message_too_long_for_one_line_is_cut_and_the_rest_of_the_load_is_kept(tmp_path):
    long = event("2", message="x" * 21_000_000)
    db, result = load_events(tmp_path, [event("1"), long])
    assert result.rows == 2
    normal, cut = stored(db)
    assert normal["message"] == "event 1"
    assert cut["message"].startswith("xxxx")
    assert cut["message"].endswith(marker(21_000_000))
    assert len(cut["message"].encode("utf-8")) < BUDGET
    assert cut["event_uid"] == EventIds()(HOST, long)[0]
    assert (cut["source_record"], cut["record_id"], cut["host"], cut["tool"]) == ("2", 2, HOST, "evtxecmd")
    assert not (tmp_path / "events_staging.csv").exists()


def test_a_row_that_fits_is_loaded_whole(tmp_path):
    """A 15,000,000 character message is within the budget, so nothing is cut."""
    message = "y" * 15_000_000
    db, _ = load_events(tmp_path, [event("1", message=message)])
    assert stored(db, "message")[0]["message"] == message


def test_a_row_of_four_byte_characters_loads_whole_under_the_budget_and_is_cut_over_it(tmp_path):
    """A message of 3,999,000 four-byte characters takes 15,996,000 bytes, which with its quotes and the row's other
    fields is under the 16,000,000 byte budget, so it loads whole. One of 4,000,002 takes 16,000,008 bytes, which is over
    it, so it is cut. The budget counts the quotes and the other fields, so the line between the two falls a little
    under four million characters."""
    under = "\U0001f600" * 3_999_000
    over = "\U0001f600" * 4_000_002
    db, _ = load_events(tmp_path, [event("1", message=under), event("2", message=over)])
    first, second = stored(db)
    assert first["message"] == under
    assert second["message"].endswith(marker(4_000_002))
    assert csv_bytes(second) < BUDGET


def test_a_row_of_check_length_characters_fits_the_budget_by_the_measure_the_cut_uses():
    """load measures a row only when it passes CUT_CHECK characters, so a row of CUT_CHECK four-byte characters, the
    most bytes a character takes, must already fit once the quotes around each field are counted."""
    row = [""] * len(COLUMNS)
    row[MESSAGE] = "\U0001f600" * CUT_CHECK
    assert _fit(tuple(row)) == tuple(row)


def test_two_long_command_lines_are_cut_to_share_the_row(tmp_path):
    """Each command line is 10,500,000 characters, which passes the limit together. The longest fields are cut first,
    and a field shorter than the others' share keeps all its text."""
    command = "a" * 10_500_000
    other = "c" * 3_000
    db, _ = load_events(
        tmp_path, [event("1", process_command_line=command, process_parent_command_line=command, file_path=other)]
    )
    [row] = stored(db)
    assert csv_bytes(row) < BUDGET
    for name in ("process_command_line", "process_parent_command_line"):
        assert row[name].startswith("aaaa")
        assert row[name].endswith(marker(10_500_000))
    assert row["file_path"] == other


def test_a_message_of_double_quotes_is_cut_by_the_bytes_the_csv_writes(tmp_path):
    """Each double quote takes two bytes in the CSV, so 11,000,000 of them make a 22 MB line."""
    db, _ = load_events(tmp_path, [event("1", message='"' * 11_000_000)])
    [row] = stored(db)
    assert csv_bytes(row) < BUDGET
    assert row["message"].endswith(marker(11_000_000))
    assert row["message"].startswith('""""')


def test_a_message_of_four_byte_characters_is_cut_by_its_bytes(tmp_path):
    """6,000,000 characters are only 6,000,000 long, but 24 MB in UTF-8."""
    db, _ = load_events(tmp_path, [event("1", message="\U0001f600" * 6_000_000)])
    [row] = stored(db)
    assert csv_bytes(row) < BUDGET
    assert row["message"].startswith("\U0001f600\U0001f600")
    assert row["message"].endswith(marker(6_000_000))


def test_a_message_with_many_line_breaks_is_cut_and_reads_back_as_one_row(tmp_path):
    db, _ = load_events(tmp_path, [event("1", message="ab\r\n" * 7_000_000), event("2")])
    first, second = stored(db)
    assert csv_bytes(first) < BUDGET
    assert first["message"].startswith("ab\r\nab\r\n")
    assert first["message"].endswith(marker(28_000_000))
    assert second["message"] == "event 2"


@pytest.mark.parametrize("serialized", [False, True], ids=["dict", "json text"])
def test_extra_is_cut_as_json_and_stays_readable_by_the_json_functions(tmp_path, serialized):
    extra = {"payload": "p" * 21_000_000, "kind": "big", "quote": 'say "hi"'}
    db, _ = load_events(tmp_path, [event("1", extra=json.dumps(extra) if serialized else extra)])
    [row] = stored(db)
    assert csv_bytes(row) < BUDGET
    con = connect(db, read_only=True)
    try:
        kind, quote, payload = con.execute(
            "SELECT json_extract_string(extra, '$.kind'), json_extract_string(extra, '$.quote'), "
            "json_extract_string(extra, '$.payload') FROM events"
        ).fetchone()
    finally:
        con.close()
    assert (kind, quote) == ("big", 'say "hi"')
    assert payload.startswith("pppp")
    assert payload.endswith(marker(21_000_000))
    assert row["message"] == "event 1"


def test_extra_text_with_json_escapes_is_cut_by_its_escaped_size(tmp_path):
    """A quote is written as \\" in JSON and then doubled in the CSV, so 5,000,000 of them take 15 MB there."""
    extra = {"payload": '"' * 5_000_000, "lines": "\n" * 5_000_000}
    db, _ = load_events(tmp_path, [event("1", extra=extra)])
    [row] = stored(db)
    assert csv_bytes(row) < BUDGET
    value = json.loads(row["extra"])
    assert value["payload"].startswith('""""')
    assert value["lines"].startswith("\n\n\n\n")


def test_extra_that_cannot_be_cut_is_left_out_and_the_message_says_so(tmp_path):
    """A 21,000,000 character key is not text the cut can shorten."""
    db, _ = load_events(tmp_path, [event("1", extra={"k" * 21_000_000: "v"}), event("2")])
    first, second = stored(db)
    assert first["extra"] is None
    assert first["message"] == "event 1 [extra fields left out to fit one row]"
    assert second["message"] == "event 2"


def test_the_id_fields_of_an_oversize_row_are_never_cut(tmp_path):
    long = event("1", message="m" * 21_000_000, process_command_line="c" * 21_000_000, extra={"e": "e" * 21_000_000})
    db, _ = load_events(tmp_path, [long])
    [row] = stored(db)
    assert csv_bytes(row) < BUDGET
    assert row["event_uid"] == EventIds()(HOST, long)[0]
    assert (row["host"], row["origin_host"], row["tool"], row["tool_version"], row["run_id"], row["artifact"]) == (
        HOST,
        HOST,
        "evtxecmd",
        "1",
        "r1",
        "evtx",
    )
    assert (row["source_file"], row["source_record"], row["ts_us"], row["ts_desc"]) == (
        SOURCE,
        "1",
        1600485708000000,
        "Event Recorded",
    )
    for value in (row["message"], row["process_command_line"], json.loads(row["extra"])["e"]):
        assert value.endswith(marker(21_000_000))


@pytest.mark.parametrize("field", ["host_name_recorded", "message", "process_command_line", "file_path"])
def test_a_text_field_left_as_none_loads_as_an_empty_field(tmp_path, field):
    """A parser can pass None for a text field, as a CSV row cut short does; the field is written empty and the rest
    of the load is kept."""
    db, result = load_events(tmp_path, [event("1"), event("2", **{field: None}), event("3")])
    assert result.rows == 3
    assert [row[field] for row in stored(db, field)][1] == ""
    assert [row["message"] for row in stored(db, "message")][::2] == ["event 1", "event 3"]


def test_a_number_in_a_text_field_loads_as_its_text(tmp_path):
    db, _ = load_events(tmp_path, [event("1", logon_type=3)])
    assert stored(db, "logon_type")[0]["logon_type"] == "3"


def test_a_row_with_a_none_field_is_cut_when_it_is_too_long(tmp_path):
    db, _ = load_events(tmp_path, [event("1", message="x" * 21_000_000, host_name_recorded=None)])
    [row] = stored(db)
    assert row["host_name_recorded"] == ""
    assert row["message"].endswith(marker(21_000_000))
    assert csv_bytes(row) < BUDGET


def test_an_evtxecmd_csv_with_a_row_cut_short_loads_every_row(tmp_path):
    """DictReader gives None for each column a short row lacks, and the parser passes the missing Computer through."""
    with (tmp_path / "evtxecmd.csv").open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "RecordNumber",
                "EventRecordId",
                "TimeCreated",
                "EventId",
                "Level",
                "Provider",
                "Channel",
                "Computer",
                "UserId",
                "Payload",
            ]
        )
        writer.writerow(["1", "1", "2020-09-19 04:21:48.0000000", "4624", "LogAlways", "Security", "Security", "LAB", "", "{}"])
        writer.writerow(["2", "2", "2020-09-19 04:21:49.0000000", "4624", "LogAlways", "Security", "Security"])
    events = list(PARSERS["evtxecmd_csv"](ParseContext(tmp_path, tmp_path)))
    assert events[1].host_name_recorded is None
    db, result = load_events(tmp_path, events)
    assert result.rows == 2
    assert [row["host_name_recorded"] for row in stored(db, "host_name_recorded")] == ["LAB", ""]
