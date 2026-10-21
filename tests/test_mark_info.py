"""Who set an event's mark, and when, on the rows the page lists: the review-state badge's hover says "Suspicious,
marked by <analyst>, <date and time> UTC", and the server finds it with one lookup per row."""

import pytest
from test_page_batch import view_filter

from glessner.audit import read_entries
from glessner.server import (
    App,
    api_audit_events,
    api_mark,
    api_related,
    api_search,
    api_selected,
    api_undo,
    api_view_events,
)

QUERY = {"q": ["code:4624"]}


@pytest.fixture
def work(synthetic_case):
    """The case open for work, with two 4624s marked Suspicious and a third Malicious, each by its own entry."""
    app = App(synthetic_case, for_work=True)
    try:
        events = api_search(app, QUERY)["events"]
        assert len(events) >= 5 and any(e["mark"].startswith("Suggested: ") for e in events)
        unmarked = [e["uid"] for e in events if e["mark"] in ("Unreviewed",) or e["mark"].startswith("Suggested: ")]
        marked = {}
        for uid, value in zip(unmarked, ("suspicious", "suspicious", "malicious"), strict=False):
            marked[uid] = (value, api_mark(app, {"uids": [uid], "value": value, "note": ""})["seq"])
        yield app, marked
    finally:
        app.con.close()


def entry_at(app, seq):
    return next(e["at"] for e in read_entries(app.journal.path) if e["seq"] == seq)


def check_rows(app, marked, rows, name):
    by_uid = {r["uid"]: r for r in rows}
    assert set(marked) <= set(by_uid), name
    for uid, (value, seq) in marked.items():
        row = by_uid[uid]
        assert row["mark"] == value.capitalize(), (name, row["mark"])
        assert row["mark_who"] == app.journal.who and row["mark_at"] == entry_at(app, seq), (name, row)
    for uid, row in by_uid.items():
        if uid not in marked:   # Unreviewed, and "Suggested: X", have no mark to name
            assert row["mark"] == "Unreviewed" or row["mark"].startswith("Suggested: "), (name, row["mark"])
            assert "mark_who" not in row and "mark_at" not in row, (name, row)


def test_every_listing_names_who_marked_each_row_and_when(work):
    """Search, the related events, the selected events, an entry's events, and a View's events each carry `mark_who` and
    `mark_at` on a marked row. Unreviewed rows and pending suggestions carry none. Fails with a call left out."""
    app, marked = work
    first = next(iter(marked))
    check_rows(app, marked, api_search(app, QUERY)["events"], "api_search")
    check_rows(app, marked, api_selected(app, {"uid": list(marked)})["events"], "api_selected")
    for uid, (_, seq) in marked.items():   # an entry lists the events it touched
        check_rows(app, {uid: marked[uid]}, api_audit_events(app, {"seq": [str(seq)]})["events"], "api_audit_events")
    related = api_related(app, {"uid": [first], "kind": ["window"], "seconds": ["3600"]})["events"]
    assert any(e["uid"] in marked and e["uid"] != first for e in related)
    check_rows(app, {u: m for u, m in marked.items() if u in {e["uid"] for e in related}}, related, "api_related")
    view = view_filter(app, ["Malicious", "Suspicious"], [])
    check_rows(app, marked, api_view_events(app, {"filter": [view]})["events"], "api_view_events")


def test_a_mark_the_table_has_not_caught_up_with_names_nobody(work, monkeypatch):
    """Race guard: between a journal append and the table's rewrite the state is ahead of the table. The row still reads
    what the table says, so a mark whose label is not the row's gives it no detail, and the badge keeps its letter."""
    app, marked = work
    events = api_search(app, QUERY)["events"]
    target = next(e["uid"] for e in events if e["uid"] not in marked)
    monkeypatch.setattr(App, "rewrite", lambda self, **kw: None)
    api_mark(app, {"uids": [target], "value": "malicious", "note": ""})
    assert app.journal.state.marks[target].value == "malicious"   # the journal has it
    row = next(r for r in api_selected(app, {"uid": [target]})["events"])
    assert row["uid"] == target and row["mark"] != "Malicious"
    assert "mark_who" not in row and "mark_at" not in row


def test_after_an_undo_the_row_names_the_undo(work):
    """B5: after an undo, who and when are the undo's, as on the Event page. Mark Suspicious, mark Malicious, undo the
    second: the row reads Suspicious, marked at the undo entry's time."""
    app, marked = work
    uid = next(e["uid"] for e in api_search(app, QUERY)["events"] if e["uid"] not in marked)
    api_mark(app, {"uids": [uid], "value": "suspicious", "note": ""})
    second = api_mark(app, {"uids": [uid], "value": "malicious", "note": ""})["seq"]
    undone = api_undo(app, {"seq": second, "note": ""})["seq"]
    row = api_selected(app, {"uid": [uid]})["events"][0]
    assert row["mark"] == "Suspicious" and row["mark_who"] == app.journal.who
    assert row["mark_at"] == entry_at(app, undone) and undone > second
