import json

import duckdb

from glessner.events import BIGINT_COLUMNS, COLUMNS, Event, connect, event_uid, load, to_us, well_formed


def test_to_us_formats():
    assert to_us("2020-09-19 03:21:48.8910870") == 1600485708891087
    assert to_us("2020-09-19T03:21:48Z") == 1600485708000000
    assert to_us("2020-09-19T03:21:48.5Z") == 1600485708500000
    # An offset after the fraction, as Suricata's EVE writes the sensor's local time, is kept.
    assert to_us("2024-05-14T19:00:00.000000+0700") == to_us("2024-05-14T12:00:00Z") == 1715688000000000
    assert to_us("2024-05-14 12:00:00.123 +00:00") == 1715688000123000
    assert to_us("1601-01-01 00:00:00.0000000") is None
    assert to_us("") is None
    assert to_us("not a time") is None


def test_event_uid_is_stable_and_field_sensitive():
    a = event_uid("DC01", "evtx", "DC01/Security.evtx", "42", "Event Recorded")
    assert a == event_uid("DC01", "evtx", "DC01/Security.evtx", "42", "Event Recorded")
    assert a != event_uid("DESKTOP", "evtx", "DC01/Security.evtx", "42", "Event Recorded")
    assert len(a) == 32


def ev(record, source="DC01/Security.evtx", ts=1600485708000000):
    return Event(ts_us=ts, ts_desc="Event Recorded", artifact="evtx", source_file=source,
                 source_record=record, message=f"event {record}", record_id=int(record.split("#")[0]))


def test_load_replaces_rows_for_the_same_sources(tmp_path):
    db = tmp_path / "events.duckdb"
    first = load(db, [ev("1"), ev("2"), ev("3", source="DC01/System.evtx")], host="DC01", tool="evtxecmd",
                 tool_version="1", run_id="r1", replaces_sources=["DC01/Security.evtx", "DC01/System.evtx"],
                 staging_dir=tmp_path)
    assert (first.rows, first.replaced) == (3, 0)
    second = load(db, [ev("1"), ev("2")], host="DC01", tool="evtxecmd", tool_version="2", run_id="r2",
                  replaces_sources=["DC01/Security.evtx"], staging_dir=tmp_path)
    assert (second.rows, second.replaced) == (2, 2)
    con = connect(db, read_only=True)
    rows = con.execute("SELECT source_file, run_id, count(*) FROM events GROUP BY ALL ORDER BY ALL").fetchall()
    con.close()
    assert rows == [("DC01/Security.evtx", "r2", 2), ("DC01/System.evtx", "r1", 1)]
    assert not (tmp_path / "events_staging.csv").exists()


def test_an_older_database_gains_the_new_columns_last(tmp_path):
    """The parent process and registry data columns go last, so a database from before them is migrated with
    ADD COLUMN and loads by position."""
    db = tmp_path / "events.duckdb"
    older = COLUMNS[:COLUMNS.index("process_parent_executable")]
    con = duckdb.connect(str(db))
    con.execute("CREATE TABLE events (" + ", ".join(
        f"{c} {'BIGINT' if c in BIGINT_COLUMNS else 'VARCHAR'}" for c in older) + ")")
    con.close()
    shell = Event(1600485708000000, "Event Recorded", "evtx", "LAB/Sysmon.evtx", "1", "1 Process creation",
                  process_executable="C:\\Windows\\System32\\cmd.exe", process_parent_executable="C:\\w3wp.exe",
                  process_parent_command_line="w3wp.exe -ap x")
    load(db, [shell], host="LAB", tool="evtxecmd", tool_version="1", run_id="r1", replaces_sources=["LAB/Sysmon.evtx"],
         staging_dir=tmp_path)
    con = connect(db, read_only=True)
    assert [c for (c, *_) in con.execute("DESCRIBE events").fetchall()] == list(COLUMNS)
    assert con.execute("SELECT process_executable, process_parent_executable, process_parent_command_line "
                       "FROM events").fetchall() == [("C:\\Windows\\System32\\cmd.exe", "C:\\w3wp.exe", "w3wp.exe -ap x")]
    con.close()


def test_duplicate_records_get_distinct_deterministic_ids(tmp_path):
    db = tmp_path / "events.duckdb"
    load(db, [ev("7"), ev("7"), Event(None, "Event Recorded", "evtx", "DC01/Security.evtx", "8", "no time")],
         host="DC01", tool="evtxecmd", tool_version="1", run_id="r1", replaces_sources=["DC01/Security.evtx"],
         staging_dir=tmp_path)
    con = connect(db, read_only=True)
    uids = [u for (u,) in con.execute("SELECT event_uid FROM events ORDER BY source_record").fetchall()]
    nulls = con.execute("SELECT count(*) FROM events WHERE ts_us IS NULL").fetchone()[0]
    con.close()
    assert len(set(uids)) == 3
    assert event_uid("DC01", "evtx", "DC01/Security.evtx", "7#2", "Event Recorded") in uids
    assert nulls == 1


def test_any_text_loads_as_written(tmp_path):
    """Line breaks in the first row's values, a value of \\N, a NUL, and empty text load as written; a
    lone surrogate, which json.loads makes from cut UTF-16 text, loads as U+FFFD; and only a missing time, record
    number, or extra data is NULL."""
    db = tmp_path / "events.duckdb"
    cut = json.loads('"cut \\ud83d"')
    rows = [Event(1600485708000000, "Event Recorded", "evtx", "DC01/Security.evtx", "1", "4688 | line\nbreak",
                  process_command_line='powershell -c "a\rb"', user_name="\\N", extra={"CommandLine": cut}),
            Event(None, "Event Recorded", "evtx", "DC01/Security.evtx", "2", "\\N", user_name="", file_path=cut,
                  registry_data="a\x00b", process_command_line="c\r\nd")]
    result = load(db, rows, host="DC01", tool="evtxecmd", tool_version="1", run_id="r1",
                  replaces_sources=["DC01/Security.evtx"], staging_dir=tmp_path)
    con = connect(db, read_only=True)
    got = con.execute("SELECT ts_us, record_id, message, process_command_line, user_name, file_path, registry_data, extra "
                      "FROM events ORDER BY source_record").fetchall()
    con.close()
    assert result.rows == 2 and got == [
        (1600485708000000, None, "4688 | line\nbreak", 'powershell -c "a\rb"', "\\N", "", "",
         '{"CommandLine": "cut \ufffd"}'),
        (None, None, "\\N", "c\r\nd", "", "cut \ufffd", "a\x00b", None)]


def test_origin_host_goes_last_and_an_older_database_gets_it_from_host_in_one_transaction(tmp_path, monkeypatch):
    """origin_host, the host a row was loaded under, goes last, and only case format 3's account key and hash list
    follow it. A database from before it gains it filled from host in one transaction, so a migration that stops part
    way leaves the database as it was, never with NULLs that a rerun's delete, which matches on origin_host, would miss.
    The two format 3 columns are added NULL, for the format 3 step to fill (rekey._fill_columns)."""
    import types

    import glessner.events as events_module

    at = COLUMNS.index("origin_host")
    assert COLUMNS[at:] == ("origin_host", "account_key", "hashes")
    db = tmp_path / "events.duckdb"
    con = duckdb.connect(str(db))
    con.execute("CREATE TABLE events (" + ", ".join(
        f"{c} {'BIGINT' if c in BIGINT_COLUMNS else 'VARCHAR'}" for c in COLUMNS[:at]) + ")")
    con.execute("INSERT INTO events (event_uid, host, tool, source_file) VALUES ('a', 'DC01', 'evtxecmd', 'f'), "
                "('b', 'WS01', 'mftecmd', 'g')")
    con.close()

    class Failing:   # stops the migration at its UPDATE, as a crash or a full disk would
        def __init__(self, inner):
            self.inner = inner

        def execute(self, sql, *args):
            if sql.startswith("UPDATE events SET origin_host"):
                raise duckdb.IOException("disk full")
            return self.inner.execute(sql, *args)

        def __getattr__(self, name):
            return getattr(self.inner, name)

    opened = []
    fake = types.SimpleNamespace(connect=lambda *a, **k: opened.append(Failing(duckdb.connect(*a, **k))) or opened[-1])
    monkeypatch.setattr(events_module, "duckdb", fake)
    try:
        connect(db)
    except duckdb.IOException:
        pass
    else:
        raise AssertionError("the migration should have failed")
    opened[0].inner.close()
    monkeypatch.undo()
    con = duckdb.connect(str(db))
    assert "origin_host" not in [c for (c, *_) in con.execute("DESCRIBE events").fetchall()]
    con.close()
    con = connect(db)
    assert con.execute("SELECT event_uid, host, origin_host, account_key, hashes FROM events ORDER BY 1").fetchall() == [
        ("a", "DC01", "DC01", None, None), ("b", "WS01", "WS01", None, None)]
    con.close()


def recorded(record, computer, artifact="evtx", source="LAB/Security.evtx", lane=""):
    return Event(ts_us=1600485708000000 + record, ts_desc="Event Recorded", artifact=artifact, source_file=source,
                 source_record=str(record), message=f"event {record}", record_id=record, host_name_recorded=computer,
                 lane=lane)


def test_routes_move_event_log_and_hayabusa_rows_only_and_never_change_an_id(tmp_path):
    """A load with a split's routes puts event log and Hayabusa rows in their computer's lane, with the IDs a load
    without them gives. An LNK's MachineID and an import, even one whose artifact is evtx, stay on the host."""
    routes = {"pc01.example.corp": "PC01", "pc01": "PC01"}
    loads = [("evtxecmd", [recorded(1, "PC01.example.corp"), recorded(2, "WS02")], "LAB"),
             ("hayabusa", [recorded(1, "pc01", "hayabusa")], "LAB"),
             ("lecmd", [recorded(3, "pc01", "lnk", "LAB/a.lnk")], "LAB"),
             ("import", [recorded(4, "PC01.example.corp", "evtx", "LAB/export.xml", lane="LAB")], None)]
    tables = {}
    for name, with_routes in (("plain", None), ("split", routes)):
        db = tmp_path / f"{name}.duckdb"
        for tool, events, host in loads:
            load(db, events, host=host, tool=tool, tool_version="1", run_id="r", staging_dir=tmp_path,
                 replaces_sources=[e.source_file for e in events], routes=with_routes)
        con = connect(db, read_only=True)
        tables[name] = con.execute("SELECT tool, record_id, event_uid, host, origin_host FROM events ORDER BY 1, 2").fetchall()
        con.close()
    assert [r[:3] for r in tables["plain"]] == [r[:3] for r in tables["split"]]
    assert {(tool, n): (host, origin) for tool, n, _, host, origin in tables["split"]} == {
        ("evtxecmd", 1): ("PC01", "LAB"), ("evtxecmd", 2): ("LAB", "LAB"), ("hayabusa", 1): ("PC01", "LAB"),
        ("import", 4): ("LAB", "LAB"), ("lecmd", 3): ("LAB", "LAB")}


def test_a_rerun_on_a_split_host_replaces_every_lane_s_rows(tmp_path):
    """The rows a rerun replaces are matched by the host they were loaded under, so a rerun of a split host's log
    replaces its rows on every lane instead of adding a second copy of the moved ones."""
    db = tmp_path / "events.duckdb"
    routes = {"pc01.example.corp": "PC01"}
    events = [recorded(1, "PC01.example.corp"), recorded(2, "WS02")]
    load(db, events, host="LAB", tool="evtxecmd", tool_version="1", run_id="r1", replaces_sources=["LAB/Security.evtx"],
         staging_dir=tmp_path, routes=routes)
    again = load(db, events, host="LAB", tool="evtxecmd", tool_version="2", run_id="r2",
                 replaces_sources=["LAB/Security.evtx"], staging_dir=tmp_path, routes=routes)
    con = connect(db, read_only=True)
    lanes = con.execute("SELECT host, run_id FROM events ORDER BY 1").fetchall()
    con.close()
    assert again.replaced == 2 and lanes == [("LAB", "r2"), ("PC01", "r2")]


# IDs made by strict UTF-8 encoding, for keys in ASCII, Latin and CJK letters, an astral character, and U+FFFD. They
# must never change: the journal refers to events by them.
STRICT_UTF8_IDS = [
    (("DC01", "evtx", "DC01/Windows/System32/winevt/Logs/Security.evtx", "101", "Event Recorded"),
     "8116cec87c85b551d6ae79cbaa4fe27d"),
    (("WS01", "mft", "WS01/$MFT", "41-4:coreupdater.exe", "$SI MA.B"), "69c237b18b3e69093dad214a5be0387a"),
    (("SENSOR", "suricata", "SENSOR/eve.json",
      "eve|http|2024-01-01T00:00:00.000000+0000|192.0.2.1|1000|198.51.100.2|80|TCP|0||/caf\u00e9", "Flow Start"),
     "978c489ff8a3617de817a23b529f3315"),
    (("WS01", "lnk", "WS01/Users/\u00e9mile/Recent/\u65e5\u672c.lnk", "1", "Target Created"),
     "a08837dd1a3edc52d5bb193987434571"),
    (("WS01", "registry", "WS01/NTUSER.DAT", "ROOT\\Software|\U0001F600", "Registry Key LastWrite"),
     "3ed652d0ed24e024a60462947cfedf15"),
    (("FW01", "w3c_log", "FW01/pfirewall.log", "line 7 \ufffd", "Event Recorded"), "5284e0d67c70500901cb2b7681a8fec0"),
]


def test_every_id_without_a_lone_surrogate_stays_as_it_was():
    """event_uid encodes a lone surrogate as it stands. Text without one encodes to the bytes strict UTF-8 gives, so
    every ID a case already holds stays the same: the table above, made with strict UTF-8, and 20,000 random keys
    drawn from every plane but the surrogates, against the strict encoding."""
    import hashlib
    import random

    assert [event_uid(*key) for key, _ in STRICT_UTF8_IDS] == [uid for _, uid in STRICT_UTF8_IDS]
    rng = random.Random(106)
    for _ in range(20_000):
        parts = ["".join(chr(rng.choice((rng.randrange(0x20, 0xD800), rng.randrange(0xE000, 0x110000))))
                         for _ in range(rng.randrange(0, 12))) for _ in range(5)]
        strict = hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()[:32]
        assert event_uid(*parts) == strict, parts


def eve_records(field):
    """An ordinary EVE http record, and two that differ only in `field`'s value: one ending in a lone surrogate, as
    json.loads reads a \\ud83d escape, and one ending in U+FFFD, the character the stored text gets in its place."""
    ends = {"timestamp": "2024-01-01T00:00:00.000000+0000", "src_ip": "192.0.2.1", "dest_ip": "198.51.100.2",
            "dest_port": 80, "proto": "TCP", "tx_id": 0}
    shaped = {"url": lambda v: {"event_type": "http", "http": {"hostname": "example.test", "url": v}},
              "sni": lambda v: {"event_type": "tls", "tls": {"sni": v}},
              "rrname": lambda v: {"event_type": "dns", "dns": {"queries": [{"rrname": v}]}}}[field]
    return ({**ends, "src_port": 1000, **shaped("ok")},
            [{**ends, "src_port": 1001, **shaped("bad\ud83d")}, {**ends, "src_port": 1001, **shaped("bad\ufffd")}])


def test_a_lone_surrogate_in_an_eve_record_s_identity_loads_with_an_id_of_its_own(tmp_path):
    """The stored row has U+FFFD for a lone surrogate, but the event's ID is made from the key before that, and event_uid
    encodes the surrogate as it stands, not as strict UTF-8, so a surrogate in a Suricata URL, TLS SNI, or DNS name,
    which the record key holds, doesn't fail the whole file's load with UnicodeEncodeError. Each loads; the ordinary
    record keeps the ID it has in a file without them; and the surrogate's record and the one with U+FFFD in its place
    get IDs of their own, not a #2."""
    from glessner.case import create_case
    from glessner.intake import intake
    from glessner.runner import load_found_output

    for field in ("url", "sni", "rrname"):
        good, odd = eve_records(field)
        ids = {}
        for name, records in (("plain", [good]), ("odd", [good, *odd])):
            evidence = tmp_path / field / name / "evidence"
            (evidence / "SENSOR").mkdir(parents=True)
            (evidence / "SENSOR" / "eve.json").write_text("".join(json.dumps(r) + "\n" for r in records),
                                                          encoding="utf-8")
            assert ("\\ud83d" in (evidence / "SENSOR" / "eve.json").read_text(encoding="utf-8")) == (name == "odd")
            case = create_case(tmp_path / field / name / "case", "Surrogates", evidence, "cody")
            intake(case)
            record = load_found_output(case, "suricata", "suricata_eve", "SENSOR", ["SENSOR/eve.json"])
            assert (record.status, record.reason, record.loaded_rows) == ("ok", "", len(records)), field
            con = connect(case.db_path, read_only=True)
            ids[name] = dict(con.execute("SELECT source_port, list(event_uid ORDER BY event_uid) FROM events "
                                         "GROUP BY 1").fetchall())
            stored = [r for (r,) in con.execute("SELECT source_record FROM events WHERE source_port = '1001'").fetchall()]
            con.close()
        assert ids["odd"]["1000"] == ids["plain"]["1000"], field
        assert len(set(ids["odd"]["1001"])) == 2, field
        assert len(stored) == 2 and all(s.endswith("bad\ufffd") for s in stored), (field, stored)   # stored with U+FFFD
    # The two keys give different IDs directly. Made safe first, as the stored row is, they would share a base ID and
    # the later one would take the next by its place in the file (#2), so a record's ID would follow the file's order.
    # The surrogate's key gets an ID of its own.
    assert event_uid("H", "a", "f", "bad\ud83d", "t") != event_uid("H", "a", "f", "bad\ufffd", "t")


# IDs of one Suricata record under file names in ASCII, Latin and CJK letters, an astral character, U+FFFD, and lone
# surrogates. The journal refers to events by them, so a case that holds one keeps it.
SENSOR_FILE_IDS = [
    ("SENSOR/eve.json", "d17a5efa039be74ed7fa46c5addf73d0"),
    ("SENSOR/caf\u00e9.json", "0762312d263a322e3ca5564dad2a28a4"),
    ("SENSOR/\u65e5\u672c.json", "ce39c6181d4346a6a493e15644616a87"),
    ("SENSOR/\U0001F600.json", "454066a90897c44e02143b6ee64562a0"),
    ("SENSOR/eve\ufffd.json", "57d258725c171bd5e910ec28400f84a6"),
    ("SENSOR/eve\ud83d.json", "a550e85ec27d8cb7ee8b1b760426ad25"),
    ("SENSOR/eve\ude00x.json", "3e4b839737cd50dcdaad732689114b20"),
]


def test_a_lone_surrogate_in_a_file_name_loads_and_a_rerun_replaces_its_rows(tmp_path):
    """A source file named with a lone surrogate, which NTFS allows, loads: the replaced-sources list can't carry the
    surrogate (from_json refuses the escape), and the rows are stored with U+FFFD, so the rows to replace are named as
    the rows are stored. Every ID is the one the file name gives in the table above, loaded under each name."""
    for i, (name, uid) in enumerate(SENSOR_FILE_IDS):
        db = tmp_path / f"events{i}.duckdb"   # U+FFFD stands for any lone surrogate, so two such names share their rows
        events = [Event(ts_us=1600485708000000, ts_desc="Flow Start", artifact="suricata", source_file=name,
                        source_record="r1", message="flow"),
                  Event(ts_us=1600485709000000, ts_desc="Flow Start", artifact="suricata", source_file=name,
                        source_record="r2", message="flow")]
        first = load(db, events, host="SENSOR", tool="suricata", tool_version="1", run_id="a", replaces_sources=[name],
                     staging_dir=tmp_path)
        second = load(db, events[:1], host="SENSOR", tool="suricata", tool_version="2", run_id="b",
                      replaces_sources=[name], staging_dir=tmp_path)
        assert (first.rows, first.replaced, second.rows, second.replaced) == (2, 0, 1, 2), name
        stored = well_formed(name)
        con = connect(db, read_only=True)
        rows = con.execute("SELECT event_uid, source_file, run_id FROM events WHERE source_file = ?", [stored]).fetchall()
        con.close()
        assert rows == [(uid, stored, "b")], name   # the rerun's row alone, under the ID the name always gave


def test_an_evidence_file_named_with_a_lone_surrogate_loads_twice_and_its_hash_is_found(tmp_path):
    """Through the case: intake records a file named with a lone surrogate in the manifest, its EVE
    records load as found output, a second load replaces them, and the Event page and the findings summary find the
    file's hash."""
    from glessner.case import create_case
    from glessner.export import write_report
    from glessner.intake import check_files, intake, manifest_hashes
    from glessner.runner import load_found_output
    from glessner.server import App, api_event, api_mark

    name = "SENSOR/eve\ud83d.json"
    record = {"timestamp": "2024-01-01T00:00:00.000000+0000", "src_ip": "192.0.2.1", "src_port": 1000,
              "dest_ip": "198.51.100.2", "dest_port": 80, "proto": "TCP", "tx_id": 0, "event_type": "http",
              "http": {"hostname": "example.test", "url": "/a"}}
    evidence = tmp_path / "evidence"
    (evidence / "SENSOR").mkdir(parents=True)
    (evidence / name).write_text(json.dumps(record) + "\n", encoding="utf-8")
    case = create_case(tmp_path / "case", "Surrogate name", evidence, "cody")
    intake(case)
    for _ in range(2):
        run = load_found_output(case, "suricata", "suricata_eve", "SENSOR", [name])
        assert (run.status, run.reason, run.loaded_rows) == ("ok", "", 1)
    stored = well_formed(name)
    con = connect(case.db_path, read_only=True)
    rows = con.execute("SELECT event_uid, source_file FROM events").fetchall()
    con.close()
    assert len(rows) == 1 and rows[0][1] == stored
    sha = manifest_hashes(case)[stored]
    assert len(sha) == 64
    app = App(case)
    try:
        assert app.manifest[stored] == sha
        assert api_event(app, {"uid": [rows[0][0]]})["event"]["evidence_sha256"] == sha
        api_mark(app, {"uids": [rows[0][0]], "value": "malicious"})
        path, _ = write_report(app.con, case, app.identity, app.manifest, app.journal.state)
        assert f"evidence SHA-256 `{sha}`" in path.read_text(encoding="utf-8")
        # A change to the file since intake is found for it, the check naming the file by the path it was hashed under
        (evidence / name).write_text(json.dumps(record) + "\n\n", encoding="utf-8")
        check_files(case, reason="manual full verification")
        assert api_event(app, {"uid": [rows[0][0]]})["event"]["provenance"]["state"] == "changed"
    finally:
        app.con.close()
