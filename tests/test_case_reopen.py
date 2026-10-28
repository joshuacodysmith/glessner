"""Opening a case again, and closing the case before it: the hub's waits and what an App's close signals."""

import json
import threading
import time

import duckdb
import pytest
from test_server import login, request

from glessner import server
from glessner.case import copy_case
from glessner.server import Hub, serve_hub


class FailingClose:
    """A connection whose close() closes the real one and then raises, as a DuckDB error on close would."""

    def __init__(self, con):
        self.con = con

    def close(self):
        self.con.close()
        raise duckdb.IOException("close failed")

    def __getattr__(self, name):
        return getattr(self.con, name)


def test_a_connection_that_fails_to_close_still_lets_the_case_open_again(synthetic_case, tmp_path, monkeypatch, capsys):
    """Closing an App's connection sets its closed event whether or not the close raises, since a reopen waits on that
    event. The error is printed for the console the server runs in, and the case opens again."""
    monkeypatch.setattr(server, "REOPEN_WAIT_SECONDS", 0.2)
    other = copy_case(synthetic_case, tmp_path / "other", "Other", "cody")
    hub = Hub(synthetic_case)
    first = hub.app
    first.con = FailingClose(first.con)
    try:
        hub.open(other)
        assert first.closed.is_set()
        assert "close failed" in capsys.readouterr().err
        assert hub.open(synthetic_case).case.folder == synthetic_case.folder
    finally:
        hub.app.con.close()


def test_a_retired_app_closes_before_the_answer_that_ran_on_it_is_sent(synthetic_case, tmp_path, monkeypatch):
    """A request's answer is built on the App it ran on and sent after the request leaves that App. An App retired meanwhile
    closes when the request leaves, not when a slow client has read the answer."""
    other = copy_case(synthetic_case, tmp_path / "other", "Other", "cody")
    server_, hub, _ = serve_hub(Hub(synthetic_case), 0)
    threading.Thread(target=server_.serve_forever, daemon=True).start()
    port = server_.server_address[1]
    retired = hub.app
    closed_when_written = []

    class Probe:
        def __str__(self):   # called as the answer is written
            closed_when_written.append(retired.closed.is_set())
            return "probe"

    def probe_close(app, query):
        hub.open(other)   # retires the App this request runs on
        return {"probe": Probe()}

    monkeypatch.setitem(server.GET_ROUTES, "/api/probe_close", probe_close)
    try:
        session = login(port, hub)
        res, body = request(port, "GET", "/api/probe_close", session=session)
        assert res.status == 200 and json.loads(body)["probe"] == "probe"
        assert closed_when_written == [True]
    finally:
        server_.shutdown()
        server_.server_close()
        hub.app.con.close()


def reopen_in_a_thread(hub, case):
    """Open `case` on a thread; the list gets the App, or the exception that refused the open."""
    outcome = []

    def work():
        try:
            outcome.append(hub.open(case))
        except Exception as exc:  # noqa: BLE001
            outcome.append(exc)

    thread = threading.Thread(target=work)
    thread.start()
    return thread, outcome


def test_a_case_reopened_builds_its_new_app_only_after_the_open_one_has_closed(synthetic_case, monkeypatch):
    """Reopening the open case takes it out of service, waits for its requests to end and its connection to close, and
    only then builds the new App: two Apps of one case never share its database. Requests meanwhile are told no case is
    open."""
    monkeypatch.setattr(server, "REOPEN_WAIT_SECONDS", 3)
    hub = Hub(synthetic_case)
    live = hub.app
    assert live.enter()   # a request in flight
    built, real_app = [], server.App

    def recording_app(*args, **kwargs):
        built.append(live.closed.is_set())
        return real_app(*args, **kwargs)

    monkeypatch.setattr(server, "App", recording_app)
    thread, outcome = reopen_in_a_thread(hub, synthetic_case)
    try:
        time.sleep(0.3)
        assert built == [] and hub.app is None
        live.leave()
        thread.join(10)
        assert built == [True] and outcome == [hub.app] and hub.app is not live
    finally:
        thread.join(10)
        if hub.app:
            hub.app.con.close()


def test_a_reopen_that_waits_too_long_puts_the_open_case_back(synthetic_case, monkeypatch):
    """When the request on the open case outlasts the wait, the reopen is refused and the case is open as it was, taking
    requests again."""
    monkeypatch.setattr(server, "REOPEN_WAIT_SECONDS", 0.2)
    hub = Hub(synthetic_case)
    live = hub.app
    assert live.enter()
    try:
        with pytest.raises(ValueError, match="still finishing a request"):
            hub.open(synthetic_case)
        assert hub.app is live and not live.retired and not live.closed.is_set()
        assert live.enter()
        live.leave()
    finally:
        live.leave()
        hub.app.con.close()


def test_a_reopen_that_waits_too_long_leaves_a_case_opened_meanwhile_open(synthetic_case, tmp_path, monkeypatch):
    """The reopen takes its case out of service while it waits, so another case can be opened meanwhile. When the wait
    runs out, the case the reopen took out is not put back over the one opened since: it stays retired and closes when its
    last request ends."""
    monkeypatch.setattr(server, "REOPEN_WAIT_SECONDS", 2)
    other = copy_case(synthetic_case, tmp_path / "other", "Other", "cody")
    hub = Hub(synthetic_case)
    live = hub.app
    assert live.enter()   # a request in flight
    held, thread, opened = True, None, None
    try:
        thread, outcome = reopen_in_a_thread(hub, synthetic_case)
        for _ in range(100):   # until the reopen has taken its case out of service
            if hub.app is None:
                break
            time.sleep(0.05)
        assert hub.app is None
        opened = hub.open(other)
        thread.join(10)
        assert isinstance(outcome[0], ValueError) and "still finishing a request" in str(outcome[0])
        assert hub.app is opened and live.retired and not live.closed.is_set()
        live.leave()
        held = False
        assert live.closed.is_set()
    finally:
        if held:
            live.leave()
        if thread:
            thread.join(10)
        if not live.closed.is_set():
            live.con.close()
        if opened:
            opened.con.close()


def test_a_reopen_waiting_for_its_case_does_not_hold_up_the_open_of_another(synthetic_case, tmp_path, monkeypatch):
    """The wait for an earlier open of a case to close runs outside the hub's lock, so an open of a different case
    meanwhile goes through at once."""
    monkeypatch.setattr(server, "REOPEN_WAIT_SECONDS", 10)
    second = copy_case(synthetic_case, tmp_path / "second", "Second", "cody")
    third = copy_case(synthetic_case, tmp_path / "third", "Third", "cody")
    hub = Hub(synthetic_case)
    first = hub.app
    assert first.enter()
    held, thread = True, None
    try:
        hub.open(second)   # the first is retired but still open
        thread, outcome = reopen_in_a_thread(hub, synthetic_case)
        time.sleep(0.3)
        started = time.monotonic()
        hub.open(third)
        assert time.monotonic() - started < 5   # a lock held through the reopen's wait would take over 9.7 s
        first.leave()
        held = False
        thread.join(10)
        assert outcome == [hub.app] and hub.app.case.folder == synthetic_case.folder
    finally:
        if held:
            first.leave()
        if thread:
            thread.join(10)
        hub.app.con.close()
