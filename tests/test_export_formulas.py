"""CSV exports keep evidence text from running as a spreadsheet formula (OWASP, CSV Injection): the timeline CSV of each
scope and indicators.csv. JSONL keeps the text as recorded."""

import csv
import json
import re
from pathlib import Path

import duckdb
from conftest import SEC, T0

from glessner.events import NO_EXTENSION_FETCH
from glessner.export import FORMULA_STARTS, TIMELINE_COLUMNS, spreadsheet_sql, spreadsheet_text
from glessner.server import App, api_export, api_host, api_indicators, api_mark

# Text an attacker controls in evidence, by events column: each starts a formula in Excel or LibreOffice, at the start
# of the cell or, in Excel splitting on semicolons, after a semicolon or a line break in it
HOSTILE = {
    "message": '=HYPERLINK("http://evil.example","x")',
    "process_command_line": "+1+1",
    "process_executable": "-2+3",
    "user_name": "@SUM(1,1)",
    "user_domain": "",
    "file_path": "\t=1+1",
    "registry_path": "\r\n=1+1",
    "registry_value": "\uff1d1+1",
    "registry_data": "x;=1+1;y",
    "source_workstation": "a\n=2+2;b,c",
    "logon_id": "-",
    "process_parent_command_line": 'x;"=1+2;',
    "process_parent_executable": 'y\n"=3+4;',
}
OPERATOR_AFTER_SEPARATOR = re.compile("[;\r\n]\"?[=+\\-@\uff1d\uff0b\uff0d\uff20]")
NUMBERS = {"host_clock_offset_seconds", "winlog.record_id"}
HEADER = ",".join(name for _, name in TIMELINE_COLUMNS) + "\n"


def uid_at(app, ts):
    return app.con.execute("SELECT event_uid FROM events WHERE tool = 'evtxecmd' AND ts_us = ?", [ts]).fetchone()[0]


def read_csv(path):
    with Path(path).open(encoding="utf-8", newline="") as f:
        return list(csv.reader(f))


def read_jsonl(path):
    return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines()]


def assert_no_formula(cell):
    """Neither the cell's start nor a piece after a semicolon or line break in it begins a formula, other than the tab
    put in front."""
    assert cell[:1] not in FORMULA_STARTS or cell[:1] == "\t", repr(cell)
    assert not OPERATOR_AFTER_SEPARATOR.search(cell), repr(cell)


def test_each_timeline_csv_writes_formula_text_as_text(synthetic_case):
    """Every scope's CSV: each text cell is spreadsheet_text of the value JSONL writes as recorded, and is quoted; numbers
    are written bare, a negative offset among them; the header line is the column names, unquoted, as before; and an
    export with no events is that line alone."""
    app = App(synthetic_case, for_work=True)
    try:
        rdp = uid_at(app, T0)
        app.con.execute(f"UPDATE events SET {', '.join(f'{c} = ?' for c in HOSTILE)} WHERE event_uid = ?",
                        [*HOSTILE.values(), rdp])
        api_host(app, {"host": "DC01", "offset_seconds": -2.5})
        api_mark(app, {"uids": [rdp], "value": "malicious", "note": "=1+1;@x"})
        window = {"start": T0 - 10 * SEC, "end": T0 + 3600 * SEC}
        for scope in ({"marks": "all", **window}, {"marks": "marked"}, {"marks": "flagged"}):
            written = api_export(app, {"format": "csv", **scope})
            raw = Path(written["path"]).read_bytes().decode("utf-8")
            assert raw.startswith(HEADER) and raw.endswith("\n") and not raw.endswith("\n\n")
            header, *rows = read_csv(written["path"])
            recorded = read_jsonl(api_export(app, {"format": "jsonl", **scope})["path"])
            assert header == list(recorded[0]) and len(rows) == len(recorded) == written["rows"] >= 1
            for row, values in zip(rows, recorded, strict=True):
                for name, cell in zip(header, row, strict=True):
                    value = values[name]
                    if name in NUMBERS:
                        assert (cell == "" if value is None else float(cell) == value), (name, cell, value)
                    else:
                        assert cell == ("" if value is None else spreadsheet_text(value)), (name, cell, value)
                        assert_no_formula(cell)
            hostile = dict(zip(header, next(r for r in rows if r[header.index("event_uid")] == rdp), strict=True))
            assert (hostile["message"], hostile["process.command_line"], hostile["process.executable"],
                    hostile["user.name"], hostile["file.path"], hostile["registry.path"], hostile["registry.value"],
                    hostile["registry.data.strings"], hostile["winlog.event_data.WorkstationName"],
                    hostile["winlog.logon.id"], hostile["mark_note"], hostile["host_clock_offset_seconds"],
                    hostile["process.parent.command_line"], hostile["process.parent.executable"]) == (
                '\t=HYPERLINK("http://evil.example","x")', "\t+1+1", "\t-2+3", "\t@SUM(1,1)", "\t\t=1+1",
                "\t\r\n\t=1+1", "\t\uff1d1+1", "x;\t=1+1;y", "a\n\t=2+2;b,c", "\t-", "\t=1+1;\t@x", "-2.5",
                'x;"\t=1+2;', 'y\n"\t=3+4;')
            # Text cells are quoted, the hostile ones and the plain ones alike; numbers are not
            assert ',"Event Recorded","\t=HYPERLINK(""http://evil.example"",""x"")","20' in raw
            assert ',-2.5,"DC01",' in raw and ',101,' in raw
        before = api_export(app, {"format": "csv", "marks": "all", "start": T0 - 10 * SEC, "end": T0 - 5 * SEC})
        assert before["rows"] == 0 and Path(before["path"]).read_bytes() == HEADER.encode()
        assert read_jsonl(api_export(app, {"format": "jsonl", "marks": "flagged"})["path"])[0]["message"] == HOSTILE["message"]
    finally:
        app.con.close()


def test_indicators_csv_writes_formula_text_as_text(synthetic_case):
    """indicators.csv follows the same rule: each text cell through spreadsheet_text and quoted, the count bare, and the
    header the column names, unquoted."""
    app = App(synthetic_case, for_work=True)
    try:
        rdp = uid_at(app, T0)
        app.con.execute("UPDATE events SET user_name = '@SUM(1,1)', user_domain = '', file_path = '-2+3;=1+1;\"@x' "
                        "WHERE event_uid = ?", [rdp])
        api_mark(app, {"uids": [rdp], "value": "malicious"})
        found = api_indicators(app, {})
        raw = Path(found["path"]).read_bytes().decode("utf-8")
        assert raw.startswith("type,value,marked_events,first_seen,last_seen\r\n")
        _, *rows = read_csv(found["path"])
        assert [(r[0], r[1], r[2]) for r in rows] == [
            ("IP address", "194.61.24.102", "1"), ("Account", "\t@SUM(1,1)", "1"), ("File", '\t-2+3;\t=1+1;"\t@x', "1")]
        assert '"File","\t-2+3;\t=1+1;""\t@x",1,"2020-09-19T03:21:48.000000Z",' in raw
        for row in rows:
            for cell in row:
                assert_no_formula(cell)
    finally:
        app.con.close()


RULE_CASES = {"=1": "\t=1", "+1": "\t+1", "-": "\t-", "@x": "\t@x", "\t": "\t\t", "\r": "\t\r", "\n": "\t\n",
              "\uff1d1": "\t\uff1d1", "\uff0b1": "\t\uff0b1", "\uff0d1": "\t\uff0d1", "\uff201": "\t\uff201",
              "a;=b;+c": "a;\t=b;\t+c", "a\r-b\n@c": "a\r\t-b\n\t@c", "a;\uff20b": "a;\t\uff20b", "\n\n=1": "\t\n\n\t=1",
              "\r\n=1": "\t\r\n\t=1", ";=": ";\t=", ";;=": ";;\t=", "a;\t=b": "a;\t=b", "a; =b": "a; =b", "a,=b": "a,=b",
              "a=b-c+d@e": "a=b-c+d@e", "plain": "plain", "": "",
              'x;"=1;': 'x;"\t=1;', 'a\n"+b': 'a\n"\t+b', 'a\r\n"@b': 'a\r\n"\t@b', 'a;""=b': 'a;""=b', '"=1': '"=1',
              'a;"\t=b': 'a;"\t=b'}


def test_spreadsheet_text_marks_each_formula_start():
    """The rule on its own: a tab before a first character OWASP lists, and before an operator after a semicolon, CR, or
    LF; ordinary text, an operator after other characters, and values that aren't text are unchanged."""
    assert {value: spreadsheet_text(value) for value in RULE_CASES} == RULE_CASES
    assert [spreadsheet_text(v) for v in (None, 7, -2.5)] == [None, 7, -2.5]


def test_the_sql_rule_writes_what_spreadsheet_text_does():
    """spreadsheet_sql, which the timeline CSV runs in DuckDB, gives spreadsheet_text's result for every case above,
    every formula character at the start and after each separator, and NULL."""
    values = [*RULE_CASES, *(f"{c}x" for c in FORMULA_STARTS),
              *(f"a{s}{q}{c}x" for s in ";\r\n" for q in ("", '"') for c in FORMULA_STARTS), None]
    with duckdb.connect(config=dict(NO_EXTENSION_FETCH)) as con:
        con.execute("CREATE TABLE t (n INTEGER, v VARCHAR)")
        con.executemany("INSERT INTO t VALUES (?, ?)", list(enumerate(values)))
        got = [v for (v,) in con.execute(f"SELECT {spreadsheet_sql('v')} FROM t ORDER BY n").fetchall()]
    assert got == [spreadsheet_text(v) for v in values]
