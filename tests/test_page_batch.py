"""The page items that ask the server for something: the search names what of the View hides its matches, and an
overview count's events are listed for the Details panel."""

from test_overview import app_with_work, overview_case  # noqa: F401

from glessner.server import App, api_filter, api_search, api_view_events


def view_filter(app, marks, values):
    return api_filter(app, {"only": [], "hide": [], "show": [], "view": {"marks": marks, "values": values}})["id"]


def test_a_search_names_the_terms_of_the_view_that_hide_its_matches(synthetic_case):
    """The View shows an event that meets any of its terms, so the matches it hides meet none, and the search answers
    with the terms in words for the page to say which part of the View hides them. With no View there are none."""
    app = App(synthetic_case)
    try:
        assert api_search(app, {"q": ["code:4624"]})["view_terms"] == []
        fid = view_filter(app, ["Malicious", "Suspicious"], [{"host": "DESKTOP"}, {"addr": "10.42.85.10"}])
        res = api_search(app, {"q": ["code:4624"], "filter": [fid]})
        assert res["view_terms"] == ["marked Malicious or Suspicious", "with IP 10.42.85.10 at either end", "with host DESKTOP"]
        hidden = [e for e in res["events"] if not e["shown"]]
        assert hidden and all(e["host"] != "DESKTOP" and e["mark"] not in ("Malicious", "Suspicious") for e in hidden)
        assert api_search(app, {"q": ["code:4624"], "filter": [view_filter(app, ["Unreviewed"], [])]})["view_terms"] == [
            "marked Unreviewed"]
    finally:
        app.con.close()


def test_the_events_a_view_shows_are_listed_for_the_details_panel(overview_case):  # noqa: F811
    """A click on an overview count lists the events its View shows, in time order, with their marks, whatever the
    Sources hide. A filter with no View is refused."""
    app, _ = app_with_work(overview_case)
    try:
        # the values the overview's pending count on DC01 opens (overview.js byHost): its three unmarked suggestions
        suggested = ("malicious", "suspicious", "authorized")
        pending = view_filter(app, [], [{"host": "DC01", "mark": f"Suggested: {v}"} for v in suggested])
        res = api_view_events(app, {"filter": [pending]})
        assert res["total"] == len(res["events"]) == 3 and not res["limited"]
        assert {e["host"] for e in res["events"]} == {"DC01"}
        assert {e["mark"] for e in res["events"]} == {"Suggested: suspicious", "Suggested: authorized"}
        assert [e["ts"] for e in res["events"]] == sorted(e["ts"] for e in res["events"])
        flagged = api_view_events(app, {"filter": [view_filter(app, ["Malicious", "Suspicious"], [])]})
        assert {e["mark"] for e in flagged["events"]} == {"Malicious", "Suspicious"} and flagged["total"] == 2
        hide = {"only": [], "hide": [{"host": "DC01"}], "show": [], "view": {"marks": ["Malicious"], "values": []}}
        sources = api_filter(app, hide)["id"]
        assert api_view_events(app, {"filter": [sources]})["total"] == 1   # DC01's mark, listed though the Sources hide it
        import pytest

        from glessner.queries import QueryError
        with pytest.raises(QueryError):
            api_view_events(app, {"filter": [api_filter(app, {"only": [], "hide": [], "show": []})["id"]]})
    finally:
        app.con.close()
