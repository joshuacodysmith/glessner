"""To investigate's worklist a page at a time: the flagged events in time order from an offset, how many there are in all,
and how many of all of them are ticked Followed up."""

from types import SimpleNamespace

import pytest
from conftest import SEC, T0

from glessner.queries import QueryError, investigate
from glessner.server import App, api_followup, api_investigate, api_mark


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
