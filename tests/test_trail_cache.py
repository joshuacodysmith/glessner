"""The audit trail's full check of the journal, kept between requests, and the trail export's reads of the events."""

import os

import pytest
from conftest import flip_a_byte

from glessner import heads, server
from glessner.audit import entry_targets
from glessner.server import App, _entries_events, _entry_events, _trail_check, api_audit, api_audit_export, api_mark


@pytest.fixture
def papp(synthetic_case):
    app = App(synthetic_case)
    yield app
    app.con.close()


def event_ids(app, count):
    return [uid for (uid,) in app.con.execute("SELECT event_uid FROM events ORDER BY event_uid LIMIT ?", [count]).fetchall()]


def count_checks(app, monkeypatch):
    """The journal's full checks run from now on, counted in the list this returns."""
    calls, real = [], app.journal.full_check
    monkeypatch.setattr(app.journal, "full_check", lambda *args, **kwargs: calls.append(1) or real(*args, **kwargs))
    return calls


def test_the_trail_checks_the_journal_once_until_it_changes(papp, monkeypatch):
    first, second, third = event_ids(papp, 3)
    api_mark(papp, {"uids": [first], "value": "suspicious", "note": "first"})
    api_mark(papp, {"uids": [second], "value": "malicious", "note": "second"})
    calls = count_checks(papp, monkeypatch)
    before = api_audit(papp, {})
    assert api_audit(papp, {})["rows"] == before["rows"] and len(calls) == 1
    api_mark(papp, {"uids": [third], "value": "suspicious", "note": "third"})
    assert api_audit(papp, {})["rows"][0]["seq"] == before["rows"][0]["seq"] + 1
    assert len(calls) == 2
    api_audit(papp, {})
    assert len(calls) == 2


def test_a_same_length_edit_of_an_earlier_line_is_found_on_the_next_audit(papp, monkeypatch):
    """The edit leaves the journal's size and its modified time as they were, so only the file's hash shows it."""
    first, second = event_ids(papp, 2)
    api_mark(papp, {"uids": [first], "value": "suspicious", "note": "first"})
    api_mark(papp, {"uids": [second], "value": "malicious", "note": "second"})
    calls = count_checks(papp, monkeypatch)
    assert api_audit(papp, {})["journal"]["state"] == "consistent" and not papp.journal.read_only
    path = papp.journal.path
    stat = path.stat()
    flip_a_byte(path, path.read_bytes().index(b"first"))
    os.utime(path, ns=(stat.st_atime_ns, stat.st_mtime_ns))
    assert (path.stat().st_size, path.stat().st_mtime_ns) == (stat.st_size, stat.st_mtime_ns)
    found = api_audit(papp, {})["journal"]
    assert len(calls) == 2 and found["state"] == "broken" and papp.journal.read_only
    api_audit(papp, {})
    assert len(calls) == 2   # the break is cached with the check that found it


def test_a_head_record_moved_ahead_of_the_journal_is_found_on_the_next_audit(papp, monkeypatch):
    """The journal file is as it was; only the head record kept outside the case changes, so the record is part of what a
    kept check depends on."""
    first, second = event_ids(papp, 2)
    api_mark(papp, {"uids": [first], "value": "suspicious"})
    api_mark(papp, {"uids": [second], "value": "malicious"})
    calls = count_checks(papp, monkeypatch)
    assert api_audit(papp, {})["journal"]["state"] == "consistent"
    folder = papp.journal.path.parent
    record = heads.read(folder)
    heads.write(folder, record["seq"] + 5, "0" * 64, record.get("build", ""))
    found = api_audit(papp, {})["journal"]
    assert len(calls) == 2 and found["state"] != "consistent"


def multi_event_entries(app):
    return [e for e in _trail_check(app)[0].entries if len(entry_targets(e)) > 1]


def mark_groups(app, groups):
    """One mark of several events for each group of event IDs, the marks alternating so the events differ in theirs."""
    for n, uids in enumerate(groups):
        api_mark(app, {"uids": uids, "value": ("suspicious", "malicious")[n % 2], "note": f"group {n}"})


class CountingCursor:
    """A DuckDB cursor that counts the statements it runs."""

    def __init__(self, cursor, statements):
        self.cursor, self.statements = cursor, statements

    def execute(self, sql, *args, **kwargs):
        self.statements.append(sql)
        return self.cursor.execute(sql, *args, **kwargs)

    def __getattr__(self, name):
        return getattr(self.cursor, name)


def test_the_events_of_all_multi_event_entries_are_listed_as_each_entry_lists_its_own(papp):
    uids = event_ids(papp, 12)
    missing = "0" * 32   # an ID no loaded event has: counted, but not listed
    mark_groups(papp, [uids[0:2], uids[1:4], [uids[4], uids[5], missing], uids[6:12], uids[0:12]])
    api_mark(papp, {"uids": [uids[3]], "value": "authorized"})   # a single-event entry the export doesn't list
    multi = multi_event_entries(papp)
    assert len(multi) == 5
    listed = _entries_events(papp, multi)
    assert listed == {e["seq"]: _entry_events(papp, e) for e in multi}
    assert [total for total, _ in listed.values()] == [2, 3, 3, 6, 12]
    assert any(len(shown) < total for total, shown in listed.values())


def test_each_entry_lists_at_most_the_listed_events_in_time_order(papp, monkeypatch):
    uids = event_ids(papp, 12)
    mark_groups(papp, [uids[0:2], uids[0:12], uids[4:12]])
    monkeypatch.setattr(server, "LISTED_EVENTS", 3)
    multi = multi_event_entries(papp)
    listed = _entries_events(papp, multi)
    assert listed == {e["seq"]: _entry_events(papp, e) for e in multi}
    assert [(total, len(shown)) for total, shown in listed.values()] == [(2, 2), (12, 3), (8, 3)]


def test_the_trail_export_reads_the_events_in_the_same_statements_however_many_entries_list_events(papp, monkeypatch):
    uids = event_ids(papp, 12)
    statements = []
    real = papp.reader
    monkeypatch.setattr(papp, "reader", lambda: CountingCursor(real(), statements))

    def statements_for_an_export():
        statements.clear()
        api_audit_export(papp, {})
        return len(statements)

    mark_groups(papp, [uids[0:2], uids[2:5]])
    few = statements_for_an_export()
    mark_groups(papp, [uids[n : n + 2] for n in range(10)])
    assert len(multi_event_entries(papp)) == 12
    assert statements_for_an_export() == few
