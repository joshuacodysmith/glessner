"""Host clock offsets, the time-window relation, settings, and closing a case."""

import csv
import json

import pytest
from conftest import SEC, T0, links_in

from glessner.cli import main
from glessner.export import export_timeline, write_report
from glessner.intake import intake
from glessner.queries import QueryError, parse_groupby, related, view
from glessner.server import App, api_host, api_mark, api_setting


@pytest.fixture
def app(synthetic_case):
    a = App(synthetic_case)
    yield a
    a.con.close()


def uid_at(app, ts, host="DC01"):
    return app.con.execute("SELECT event_uid FROM events WHERE tool = 'evtxecmd' AND host = ? AND ts_us = ?",
                           [host, ts]).fetchone()[0]


def test_offset_shifts_one_host_everywhere(app):
    rdp = uid_at(app, T0)
    api_host(app, {"host": "DC01", "offset_seconds": 90})
    keys = parse_groupby("host")
    # The RDP happened at T0 by DC01's clock; with +90 s it sits at T0 + 90 s.
    before = view(app.con, app.identity, keys, T0 - SEC, T0 + SEC, 10, 1000, True)
    assert all(e["uid"] != rdp for e in before["events"])
    after = view(app.con, app.identity, keys, T0 + 89 * SEC, T0 + 91 * SEC, 10, 1000, True)
    assert [e["ts"] for e in after["events"] if e["uid"] == rdp] == [T0 + 90 * SEC]
    links = {link.uid: link.ts for link in links_in(app.con, T0 - 3600 * SEC, T0 + 3600 * SEC)}
    assert links[rdp] == T0 + 90 * SEC
    desktop = uid_at(app, T0 + 874 * SEC, "DESKTOP")
    assert links[desktop] == T0 + 874 * SEC   # the other host is unchanged
    line = json.loads((app.case.folder / "journal.jsonl").read_text().splitlines()[-1])
    assert (line["action"], line["host"], line["seconds"]) == ("host_offset", "DC01", 90.0)


def test_a_window_without_links_is_passed_over_by_their_recorded_times(app):
    """A view answers a window without links from logon_links' copy of each logon's recorded time,
    before it reads any event. The window's recorded-time bounds widen by the offsets, so a logon an offset moves into
    a window draws there and not where it was recorded; one by a machine account draws only while those are shown."""
    keys = parse_groupby("host")

    def link_uids(start, end, hide_machine=True):
        return [link["uid"] for link in view(app.con, app.identity, keys, start, end, 10, 1000, hide_machine)
                ["links"]["items"]]

    (machine,) = app.con.execute("SELECT ts_us FROM logon_links WHERE machine").fetchone()   # no offsets yet
    assert link_uids(machine, machine + 1) == [] and len(link_uids(machine, machine + 1, False)) == 1
    rdp = uid_at(app, T0)
    assert rdp in link_uids(T0 - SEC, T0 + SEC)
    api_host(app, {"host": "DC01", "offset_seconds": 3600})
    assert rdp not in link_uids(T0 - SEC, T0 + SEC)
    assert rdp in link_uids(T0 + 3599 * SEC, T0 + 3601 * SEC)


def test_an_event_is_found_at_the_time_it_shows_or_without_one(app):
    """The page sends the time it shows an event at, which narrows the lookup by ID. A time from
    before an offset edit, or none, still finds the event."""
    from glessner.server import api_event, api_related

    rdp = uid_at(app, T0)
    for offsets in ({"DC01": 90}, {"DC01": 90, "DESKTOP": -30}):   # two offset values, zero among them, then three
        for host, seconds in offsets.items():
            api_host(app, {"host": host, "offset_seconds": seconds})
        for ts in (T0 + 90 * SEC, T0, None):   # as it shows now, as it showed before the offset, and no time
            query = {"uid": [rdp], **({"ts": [str(ts)]} if ts is not None else {})}
            ev = api_event(app, query)["event"]
            assert (ev["event_uid"], ev["adjusted_ts_us"]) == (rdp, T0 + 90 * SEC)
            assert ev["hits"] == [{"title": "RDP from internet", "level": "high"}]
            session = api_related(app, {**query, "kind": ["session"]})
            assert session["anchor"] == {"host": "DC01", "logon_id": "0x510986"}
            assert {e["uid"]: e["gap_s"] for e in session["events"]}[rdp] == 0   # the anchor's time is the shown one
    with pytest.raises(QueryError, match="unknown event"):
        api_related(app, {"uid": ["0" * 32], "kind": ["session"], "ts": [str(T0)]})


def test_an_event_is_looked_up_in_the_events_alone(app):
    """The lookup reads the events table alone, by the recorded times the shown time allows when the case has at
    most LOOKUPS offset values, and by the ID otherwise; joined to the hosts first, it would take twice as long.
    A pivot's anchor joins the hosts to the one row found, for its clock-adjusted time."""
    from glessner.queries import LOOKUPS, TS, find_event

    class Recorder:   # the statements a lookup runs, and their parameters
        def __init__(self, con):
            self.con, self.sql, self.params = con, [], []

        def execute(self, sql, params):
            self.sql.append(sql)
            self.params.append(params)
            return self.con.execute(sql, params)

    rdp = uid_at(app, T0)
    api_host(app, {"host": "DC01", "offset_seconds": 90})
    assert LOOKUPS >= 2
    con = Recorder(app.reader())
    row, names = find_event(con, rdp, app.identity, T0 + 90 * SEC)
    assert dict(zip(names, row, strict=True))["event_uid"] == rdp
    assert len(con.sql) == 1 and "ts_us = ? AND" in con.sql[0] and "JOIN" not in con.sql[0]
    assert con.params[0] == [T0, rdp, T0 + 90 * SEC, rdp]   # recorded at the shown time less each offset, 90 s and none
    con.sql.clear()
    assert find_event(con, rdp, app.identity, T0 + 90 * SEC, f"{TS}")[0] == (T0 + 90 * SEC,)
    assert len(con.sql) == 1 and con.sql[0].startswith("WITH picked AS MATERIALIZED (SELECT * FROM events WHERE ts_us")
    api_host(app, {"host": "DESKTOP", "offset_seconds": -30})   # three offset values: by the ID alone
    con.sql.clear()
    assert find_event(con, rdp, app.identity, T0 + 90 * SEC)[0] is not None
    assert con.sql == ["SELECT * FROM events WHERE event_uid = ?"]
    assert find_event(con, "0" * 32, app.identity, T0) == (None, [])


def test_offset_in_exports_and_findings(app):
    api_host(app, {"host": "DC01", "offset_seconds": -2.5})
    rdp = uid_at(app, T0)
    api_mark(app, {"uids": [rdp], "value": "malicious"})
    path, _ = export_timeline(app.con, app.case, app.identity, T0 - 10 * SEC, T0 + 10 * SEC, "csv", "flagged")
    with path.open(encoding="utf-8", newline="") as f:
        (row,) = list(csv.DictReader(f))
    assert row["datetime"] == "2020-09-19T03:21:45.500000Z" and row["recorded_datetime"] == "2020-09-19T03:21:48.000000Z"
    assert float(row["host_clock_offset_seconds"]) == -2.5
    fpath, _ = write_report(app.con, app.case, app.identity, app.manifest, app.journal.state)
    text = fpath.read_text(encoding="utf-8")
    assert "**2020-09-19 03:21:45.500000 UTC, DC01, Malicious.**" in text
    assert "offset of -2.5 s is applied; the artifact recorded 2020-09-19 03:21:48.000000 UTC" in text
    assert ("| DC01 | Domain controllers (guessed) | Not recorded | CITADEL-DC01 | 10.42.85.10 | -2.5 s; not measured |"
            in text)


def test_offset_limits(app):
    with pytest.raises(QueryError, match="one day"):
        api_host(app, {"host": "DC01", "offset_seconds": 90_000})


def test_time_window_relation(app):
    rdp = uid_at(app, T0)
    near = related(app.con, rdp, "window", 61)
    assert [(e["gap_s"], e["code"]) for e in near["events"]] == [(60.0, "4624"), (61.0, "4624")]
    assert near["label"] == "same host within 61 seconds"
    assert related(app.con, rdp, "window", 10)["events"] == []
    with pytest.raises(QueryError):
        related(app.con, rdp, "window", 0)


def test_settings_are_validated_and_journaled(app):
    assert api_setting(app, {"name": "time_window_seconds", "value": 30}) == {"name": "time_window_seconds", "value": 30}
    assert app.time_window_seconds == 30
    with pytest.raises(QueryError):
        api_setting(app, {"name": "time_window_seconds", "value": 7200})
    with pytest.raises(QueryError):
        api_setting(app, {"name": "delete_everything", "value": 1})


def test_close_rehashes_and_records(synthetic_case, capsys):
    (synthetic_case.evidence / "DC01" / "Security.evtx").write_bytes(b"ElfFile\x00x")
    intake(synthetic_case)
    assert main(["close", str(synthetic_case.folder)]) == 0
    assert "The 1 evidence file matches the intake manifest" in capsys.readouterr().out
    line = json.loads((synthetic_case.folder / "journal.jsonl").read_text().splitlines()[-1])
    assert line["name"] == "closed" and line["value"]["hash_check"] == "ok"
    (synthetic_case.evidence / "DC01" / "Security.evtx").write_bytes(b"ElfFile\x00changed")
    assert main(["close", str(synthetic_case.folder)]) == 1
    line = json.loads((synthetic_case.folder / "journal.jsonl").read_text().splitlines()[-1])
    assert line["value"]["hash_check"] == "mismatch" and "SHA-256 changed" in line["value"]["problems"][0]
