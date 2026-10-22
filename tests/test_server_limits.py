"""Limits the server puts on what a request may name or start: imports during a Tools job, pivot windows, and the number
of events one decision names."""

from types import SimpleNamespace

import pytest
from conftest import SEC, T0, WS_LOG, logon
from test_pivots import more, papp, pcase, pcase_events, uid_of  # noqa: F401

from glessner import server
from glessner.journal import JOURNAL_FILE
from glessner.queries import QueryError, pending_source_events, related
from glessner.server import App, api_import, api_meta, api_pending, api_pending_uids, api_pivot_count, api_rule, api_suggestion

LOGONS = "id: logons\nsuggest: suspicious\nwhen: {field: event_code, equals: '4624'}\n"


def run_names(case):
    return sorted(p.name for p in case.runs_folder.iterdir()) if case.runs_folder.exists() else []


def test_an_import_is_refused_while_a_tools_job_is_running(synthetic_case, tmp_path):
    """An import and a Tools job's load both write the events table, so an import waits for the job to finish. The refusal
    comes before any file is read, and no run is made."""
    app = App(synthetic_case)
    app.job = SimpleNamespace(finished=False, tool="EvtxECmd")
    source = tmp_path / "alerts.csv"
    source.write_text("when,what\n1,x\n", encoding="utf-8")
    runs = run_names(synthetic_case)
    try:
        with pytest.raises(ValueError, match="EvtxECmd is still running; import once it finishes"):
            api_import(app, {"paths": [str(source)], "mapping": {}})
        assert run_names(synthetic_case) == runs
    finally:
        app.con.close()


def test_the_connection_pivot_checks_its_time_window_as_the_window_pivot_does(papp):  # noqa: F811
    """The connection pivot bounds a reused port to `seconds` around the event, so it takes the window's range, 1 to 3600.
    A case-wide list uses no window and takes any value."""
    event = logon(T0 + 600 * SEC, 5001, WS_LOG, ltype="3", ip="10.9.1.1", computer="DESKTOP-SDN1RPT.C137.local")
    event.source_port = "49752"
    more(papp, [event], host="DESKTOP")
    uid = uid_of(papp.con, "source_record = '5001'")
    for seconds in (-5, 0, 3601, 10**21):
        with pytest.raises(QueryError, match="the time window must be 1 to 3600 seconds"):
            related(papp.con, uid, "connection", seconds, identity=papp.identity)
    for seconds in (1, 3600):
        assert related(papp.con, uid, "connection", seconds, identity=papp.identity)["seconds"] == seconds
    assert related(papp.con, uid, "connection", -5, identity=papp.identity, scope="case")["total"] == 1
    with pytest.raises(QueryError, match="the time window must be 1 to 3600 seconds"):
        api_pivot_count(papp, {"uid": [uid], "kind": ["connection"], "seconds": ["-5"]})


@pytest.fixture
def logons_app(synthetic_case):
    """An App whose rule "logons" suggests Suspicious for every 4624."""
    app = App(synthetic_case)
    api_rule(app, {"op": "add", "text": LOGONS})
    yield app
    app.con.close()


def journal_length(app):
    return len((app.case.folder / JOURNAL_FILE).read_text(encoding="utf-8").splitlines())


def test_reject_and_restore_refuse_a_decision_naming_more_events_than_one_can_hold(logons_app, monkeypatch):
    """A rejection or a restore names its events in one journal entry, as an accept names them in one mark, so all three
    stop at MAX_MARK_TARGETS before anything is written."""
    app = logons_app
    monkeypatch.setattr(server, "MAX_MARK_TARGETS", 1)
    uids = api_pending_uids(app, {"source": ["logons"]})["uids"][:2]
    assert len(uids) == 2
    groups = api_pending(app, {"source": ["logons"], "group_by": ["host"]})["groups"]
    group = max(groups, key=lambda g: g["count"])
    assert group["count"] >= 2
    before = journal_length(app)
    every_pending = "Reject them a group at a time from the source's Suggestions page."
    regrouped = "Group the suggestions another way, by rule, host, account, or event ID, and reject smaller groups."
    refused = [
        ({"decision": "reject"},
         f"Rejecting these would name .* events, more than the 1 one decision can name. {every_pending}"),
        ({"decision": "reject", "uids": uids, "confirmed": {"count": 2}},
         "Rejecting these would name 2 events, more than the 1 one decision can name. Reject fewer at a time."),
        ({"decision": "reject", "group_by": "host", "group": group["key"]},
         f"Rejecting these would name .* events, more than the 1 one decision can name. {regrouped}"),
        ({"decision": "restore", "uids": uids},
         "Restoring these would name 2 events, more than the 1 one decision can name. Restore fewer at a time."),
        ({"decision": "accept", "uids": uids},
         "Accepting these would mark 2 events, more than the 1 a mark can hold. Accept fewer at a time."),
    ]
    for body, message in refused:
        with pytest.raises(QueryError, match=f"^{message}"):
            api_suggestion(app, {"source": "logons", **body})
        assert journal_length(app) == before, body
    assert api_meta(app, {})["max_mark_targets"] == 1


def test_a_decision_within_the_limit_still_goes_through(logons_app):
    app = logons_app
    uids = api_pending_uids(app, {"source": ["logons"]})["uids"][:2]
    assert api_suggestion(app, {"source": "logons", "decision": "reject", "uids": uids})["changed"] == 2
    assert api_suggestion(app, {"source": "logons", "decision": "restore", "uids": uids})["changed"] == 2


def test_a_sources_pending_events_are_read_up_to_a_cap(logons_app):
    con = logons_app.reader()
    everything = pending_source_events(con, "logons")
    assert len(everything["uids"]) >= 3 and everything["more"] is False
    capped = pending_source_events(con, "logons", cap=2)
    assert capped["uids"] == everything["uids"][:2] and capped["more"] is True
    assert capped["first"] == everything["first"][:2]
    exact = pending_source_events(con, "logons", cap=len(everything["uids"]))
    assert exact["uids"] == everything["uids"] and exact["more"] is False
