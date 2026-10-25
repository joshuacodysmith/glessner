"""To investigate's worklist a page at a time: the flagged events in time order from an offset, how many there are in all,
and how many of all of them are ticked Followed up."""

from types import SimpleNamespace

import pytest
from conftest import SEC, T0
from test_splits import EDGE_SEC, PC01_SEC, lab_case, split, uid_of

from glessner import server
from glessner.queries import QueryError, flagged_events, investigate
from glessner.server import App, api_followup, api_host, api_investigate, api_mark, api_rule, api_tag

LOGONS = "id: logons\nsuggest: suspicious\nwhen: {field: event_code, equals: '4624'}\n"


@pytest.fixture
def papp(synthetic_case):
    app = App(synthetic_case)
    yield app
    app.con.close()


def flagged(app):
    """Three events marked Suspicious, the Hayabusa-hit RDP logon first, and their IDs in time order."""
    sql = "SELECT event_uid FROM events WHERE tool = 'evtxecmd' AND ts_us = ?"
    uids = [app.con.execute(sql, [T0 + seconds * SEC]).fetchone()[0] for seconds in (0, 60, 874)]
    api_mark(app, {"uids": uids, "value": "suspicious"})
    return uids


def test_the_worklist_comes_a_page_at_a_time_with_its_total(papp):
    first, second, third = flagged(papp)
    page = api_investigate(papp, {"limit": ["2"]})
    assert [i["uid"] for i in page["items"]] == [first, second]
    assert (page["total"], page["offset"], page["limit"]) == (3, 0, 2)
    rest = api_investigate(papp, {"offset": ["2"], "limit": ["2"]})
    assert [i["uid"] for i in rest["items"]] == [third]
    assert (rest["total"], rest["offset"]) == (3, 2)
    assert api_investigate(papp, {"offset": ["3"]})["items"] == []
    assert api_investigate(papp, {})["limit"] == 200   # the page the list starts with


def test_followed_up_counts_every_flagged_event_not_the_page(papp):
    first, second, third = flagged(papp)
    assert api_investigate(papp, {"limit": ["2"]})["followed"] == 0
    api_followup(papp, {"uids": [third], "done": True})
    page = api_investigate(papp, {"limit": ["2"]})
    assert [i["followup"] for i in page["items"]] == [None, None] and page["followed"] == 1
    api_followup(papp, {"uids": [first, second], "done": True})
    assert api_investigate(papp, {"limit": ["1"]})["followed"] == 3
    api_followup(papp, {"uids": [first], "done": False})
    assert api_investigate(papp, {"limit": ["1"]})["followed"] == 2


def test_a_mark_whose_event_is_gone_is_neither_listed_nor_counted(papp):
    flagged(papp)
    api_mark(papp, {"uids": ["0" * 32], "value": "malicious"})
    page = api_investigate(papp, {})
    assert page["total"] == len(page["items"]) == 3


@pytest.mark.parametrize("query", [{"limit": ["0"]}, {"offset": ["-1"]}, {"limit": ["1001"]}, {"limit": ["many"]},
                                   {"offset": ["1.5"]}])
def test_an_offset_or_limit_out_of_range_is_refused(papp, query):
    with pytest.raises(QueryError, match=r"offset|limit"):
        api_investigate(papp, query)


def test_an_offset_past_the_end_lists_nothing(papp):
    flagged(papp)
    page = api_investigate(papp, {"offset": [str(10**21)]})
    assert page["items"] == [] and page["total"] == 3


class HitRows:
    """A connection that keeps the rows the Hayabusa hits query returns, in `rows`."""

    def __init__(self, con):
        self.con, self.rows = con, []

    def execute(self, sql, *args, **kwargs):
        cur = self.con.execute(sql, *args, **kwargs)
        if "rule_title" not in sql:
            return cur
        found = cur.fetchall()
        self.rows.extend(found)
        return SimpleNamespace(fetchall=lambda: found)

    def __getattr__(self, name):
        return getattr(self.con, name)


def test_the_hits_come_only_for_the_events_of_the_page(papp):
    """The first event has a hit and the second none. The page that holds the second event alone reads no hit row, though
    the first event is flagged too."""
    first, second, _ = flagged(papp)
    items = investigate(papp.reader(), 0, 2)
    assert [i["uid"] for i in items] == [first, second]
    assert items[0]["event"]["hits"] == [{"title": "RDP from internet", "level": "high"}]
    assert items[1]["event"]["hits"] == []
    con = HitRows(papp.reader())
    assert [i["uid"] for i in investigate(con, 1, 1)] == [second]
    assert con.rows == []
    assert len(investigate(papp.reader())) == 3


def test_every_page_of_an_unchanged_worklist_names_the_same_order(papp):
    """The pages of one reading share an order, and a tick of Followed up, which moves no event, leaves it as it was."""
    flagged(papp)
    first = api_investigate(papp, {"limit": ["2"]})
    api_followup(papp, {"uids": [first["items"][0]["uid"]], "done": True})
    rest = api_investigate(papp, {"offset": ["2"], "limit": ["2"]})
    assert isinstance(first["order"], str)
    assert rest["order"] == first["order"]


def test_a_tag_a_rule_and_a_mark_that_changes_no_membership_leave_the_order_a_page_names(papp):
    """Each of these rewrites the derived tables but moves no flagged event, so a reader holding an earlier page has no
    reason to read the list again."""
    first, second, _ = flagged(papp)
    before = api_investigate(papp, {"limit": ["2"]})["order"]
    api_tag(papp, {"uids": [first], "add": ["tag:checked"], "confirmed": {"count": 1}})
    api_rule(papp, {"op": "add", "text": LOGONS})
    api_mark(papp, {"uids": [second], "value": "malicious"})   # Suspicious to Malicious: still flagged, in the same place
    after = api_investigate(papp, {"limit": ["2"]})
    assert [i["mark"] for i in after["items"]] == ["Suspicious", "Malicious"]
    assert after["order"] == before


def test_a_page_read_after_a_rewrite_committed_names_the_order_of_the_rows_it_lists(papp, monkeypatch):
    """A host edit rebuilds the derived tables in one transaction and counts the rewrite afterward. A page read between
    the two lists the events in their new order, and names that order: a counter that had not moved yet would name the
    order from before, and a reader would take the page for a continuation of the first."""
    first, second, third = flagged(papp)
    before = api_investigate(papp, {"limit": ["2"]})
    between = []
    real = server.outside_sources

    def outside_sources_after_the_commit(con):
        between.append(api_investigate(papp, {"offset": ["2"], "limit": ["2"]}))
        return real(con)

    monkeypatch.setattr(server, "outside_sources", outside_sources_after_the_commit)
    api_host(papp, {"host": "DESKTOP", "offset_seconds": -3600})
    (page,) = between
    after = api_investigate(papp, {"limit": ["3"]})
    assert [i["uid"] for i in after["items"]] == [third, first, second]
    assert [i["uid"] for i in page["items"]] == [second]
    assert page["order"] == after["order"] != before["order"]


def test_a_rewrite_that_commits_while_a_page_is_read_leaves_the_page_of_one_order(papp, monkeypatch):
    """The page and the order it names come from one reading of the tables. A host edit that commits after the order is
    read and before the rows are would otherwise list rows of the new order under a name for the old one."""
    first, second, _ = flagged(papp)
    before = api_investigate(papp, {"limit": ["2"]})
    edits = []
    real = server.investigate

    def investigate_after_an_edit(con, offset, limit):
        if not edits:
            edits.append(api_host(papp, {"host": "DESKTOP", "offset_seconds": -3600}))
        return real(con, offset, limit)

    monkeypatch.setattr(server, "investigate", investigate_after_an_edit)
    page = api_investigate(papp, {"limit": ["2"]})
    assert edits
    assert [i["uid"] for i in page["items"]] == [first, second]
    assert page["order"] == before["order"]
    monkeypatch.undo()
    assert api_investigate(papp, {"limit": ["2"]})["order"] != page["order"]


def test_the_marked_events_are_listed_in_the_order_the_worklist_names(papp):
    """The flagged IDs come in the order investigate lists the events, which is what the order a page names is a name for."""
    uids = flagged(papp)
    api_host(papp, {"host": "DESKTOP", "offset_seconds": -3600})
    listed = [i["uid"] for i in investigate(papp.reader())]
    assert [uid for uid, _, _ in flagged_events(papp.reader())] == listed
    assert listed == [uids[2], uids[0], uids[1]]


def test_a_host_offset_that_reorders_the_flagged_events_changes_the_order_a_page_names(papp):
    """DESKTOP's offset moves its event ahead of DC01's two without changing how many events are flagged, so the total
    is the same on both pages and only the order tells a page that its offset now counts from another event."""
    first, second, third = flagged(papp)
    before = api_investigate(papp, {"limit": ["2"]})
    api_host(papp, {"host": "DESKTOP", "offset_seconds": -3600})
    after = api_investigate(papp, {"offset": ["2"], "limit": ["2"]})
    assert [i["uid"] for i in before["items"]] == [first, second]
    assert [i["uid"] for i in after["items"]] == [second]   # the page repeats an event the first one listed
    assert after["total"] == before["total"] == 3
    assert after["order"] != before["order"]
    assert api_investigate(papp, {"limit": ["1"]})["items"][0]["uid"] == third


def test_a_mark_changes_the_order_a_page_names(papp):
    """One event marked while another is unmarked leaves the total as it was and moves the events between them."""
    first, *_ = flagged(papp)
    before = api_investigate(papp, {"limit": ["2"]})
    api_mark(papp, {"uids": [first], "value": "unreviewed"})
    api_mark(papp, {"uids": [papp.con.execute("SELECT event_uid FROM events WHERE tool = 'evtxecmd' AND ts_us = ?",
                                              [T0 + 62 * SEC]).fetchone()[0]], "value": "malicious"})
    after = api_investigate(papp, {"offset": ["2"], "limit": ["2"]})
    assert after["total"] == before["total"]
    assert after["order"] != before["order"]


def test_a_host_offset_that_moves_the_flagged_events_without_reordering_them_changes_the_order_a_page_names(papp):
    """DC01's offset moves its two events an hour earlier and leaves them ahead of DESKTOP's. No ID changes place, but a
    reader holding the first page lists rows with the old times, and a page that follows would list the new ones."""
    uids = flagged(papp)
    before = api_investigate(papp, {"limit": ["1"]})
    api_host(papp, {"host": "DC01", "offset_seconds": -3600})
    after = api_investigate(papp, {"offset": ["1"], "limit": ["1"]})
    assert [i["uid"] for i in api_investigate(papp, {})["items"]] == uids
    assert after["items"][0]["ts"] == T0 + (60 - 3600) * SEC
    assert after["total"] == before["total"]
    assert after["order"] != before["order"]


def test_a_split_that_renames_the_hosts_of_the_flagged_events_changes_the_order_a_page_names(tmp_path):
    """A split by recorded computer moves two flagged events from LAB to PC01 and MSEDGEWIN10 without changing their times
    or their place in the list. The rows show the host, so a reader holding an earlier page has rows under the old names."""
    case, _ = lab_case(tmp_path)
    app = App(case)
    try:
        api_mark(app, {"uids": [uid_of(app.con, PC01_SEC, 1), uid_of(app.con, EDGE_SEC, 1)], "value": "suspicious"})
        before = api_investigate(app, {})
        split(app)
        after = api_investigate(app, {})
        assert [i["uid"] for i in after["items"]] == [i["uid"] for i in before["items"]]
        assert [i["ts"] for i in after["items"]] == [i["ts"] for i in before["items"]]
        assert [i["host"] for i in before["items"]] == ["LAB", "LAB"]
        assert [i["host"] for i in after["items"]] == ["PC01", "MSEDGEWIN10"]
        assert after["order"] != before["order"]
    finally:
        app.con.close()
