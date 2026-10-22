"""The Event page's message for an unplaced ID counts the events it may have meant as the Case overview does
(journal.unplaced): through the rekeys that come after the one that listed them."""

import pytest
from test_rekey_unplaced import rekey

from glessner.journal import unplaced
from glessner.queries import QueryError
from glessner.server import App, api_event

FIRST = "This event ID named more than one event before the case format upgrade at #5, so the journal's entries naming it"


@pytest.fixture
def app(synthetic_case):
    a = App(synthetic_case)
    yield a
    a.con.close()


def said(app, rekeys):
    """The message the Event page gives for the ID old1 when the journal's rekeys are `rekeys`."""
    app.journal.state.rekeys = rekeys
    with pytest.raises(QueryError) as refused:
        api_event(app, {"uid": ["old1"]})
    return str(refused.value)


def test_candidates_a_later_rekey_merged_are_counted_once(app):
    message = said(app, [rekey(5, unplaced={"old1": ["b1", "b2", "b3"]}), rekey(9, {"b1": "c1", "b2": "c1"})])
    assert message.startswith(FIRST)
    assert "It names none now; the 2 events it may have meant each say so, and the Case overview counts it." in message


def test_candidates_a_later_rekey_left_unplaced_are_counted_as_the_overview_lists_them(app):
    rekeys = [rekey(5, unplaced={"old1": ["b1", "b2"]}), rekey(9, unplaced={"b1": ["c1", "c2"]})]
    app.journal.state.rekeys = rekeys
    (listed,) = {len(u["candidates"]) for found in unplaced(app.journal.state).values() for u in found if u["id"] == "old1"}
    assert listed == 3
    assert f"the {listed} events it may have meant" in said(app, rekeys)


def test_one_candidate_left_is_worded_as_one_event(app):
    message = said(app, [rekey(5, unplaced={"old1": ["b1", "b2"]}), rekey(9, {"b1": "c1", "b2": "c1"})])
    assert "It names none now; the event it may have meant says so, and the Case overview counts it." in message


def test_no_candidate_left_is_worded_as_none(app):
    message = said(app, [rekey(5, unplaced={"old1": []})])
    assert "It names none now, and none of the events it may have meant is in the case now;" in message
    assert message.endswith("the Case overview counts it.")
