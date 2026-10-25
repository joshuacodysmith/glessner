"""Stopping the server while requests run: the test server's teardown (conftest.serving) and `glessner serve` retire the
open case and wait, for a bounded time, for its requests to end before the events database closes."""

import contextlib
import json
import threading
import time
from types import SimpleNamespace

import duckdb
from conftest import serving
from test_server import request

from glessner import cli, server
from glessner.server import Hub


class Held:
    """The first statement of each request's cursor held, once it has run and before its result is read, until `release`
    is set. A test can then stop the server while requests are counting. `reached` is set once `wanted` requests are
    held."""

    def __init__(self, monkeypatch, wanted):
        self.reached, self.release = threading.Event(), threading.Event()
        self.inside, self.wanted, self.lock = 0, wanted, threading.Lock()
        monkeypatch.setattr(server.App, "reader", lambda app: Gated(app.con.cursor(), self))


class Gated:
    """A DuckDB cursor whose first execute waits at the gate of `held` before it returns its result."""

    def __init__(self, cursor, held):
        self.cursor, self.held, self.waited = cursor, held, False

    def execute(self, *args, **kwargs):
        result = self.cursor.execute(*args, **kwargs)
        if not self.waited:
            self.waited = True
            with self.held.lock:
                self.held.inside += 1
                if self.held.inside == self.held.wanted:
                    self.held.reached.set()
            self.held.release.wait(30)
        return result

    def __getattr__(self, name):
        return getattr(self.cursor, name)


def an_event(app):
    return app.con.execute("SELECT event_uid FROM events ORDER BY event_uid LIMIT 1").fetchone()[0]


def asking(app, port, answers, count):
    """`count` threads, each asking for a pivot count and keeping its status and body in `answers`, started."""
    path = f"/api/pivot_count?uid={an_event(app)}&kind=window"

    def ask():
        res, body = request(port, "GET", path, session=app.session)
        answers.append((res.status, json.loads(body)))

    threads = [threading.Thread(target=ask) for _ in range(count)]
    for thread in threads:
        thread.start()
    return threads


def finish(threads, *others):
    """Each thread joined, and an exception that one of `others` kept in its `failure` (stop_in_a_thread) raised."""
    for thread in (*threads, *others):
        thread.join(30)
        assert not thread.is_alive()
    for thread in others:
        if getattr(thread, "failure", None):
            raise thread.failure


def stop_in_a_thread(stopping):
    """The test server's teardown (serving's second step) on a thread that keeps what it raised in `failure`."""
    def teardown():
        try:
            next(stopping, None)
        except BaseException as exc:   # noqa: BLE001  (kept for finish to raise in the test's thread)
            thread.failure = exc

    thread = threading.Thread(target=teardown)
    thread.failure = None
    thread.start()
    return thread


def test_counts_running_when_the_test_server_stops_end_in_their_own_answers(synthetic_case, monkeypatch, capfd):
    """Counts running when the server stops finish in their own answers: the teardown waits for them before it closes the
    connection, so none answers 500 with `No open result set` and no traceback goes to stderr."""
    stopping = serving(synthetic_case)
    app, port, _ = next(stopping)
    held = Held(monkeypatch, 4)
    answers = []
    threads = asking(app, port, answers, 4)
    assert held.reached.wait(30)
    teardown = stop_in_a_thread(stopping)
    teardown.join(1.0)
    held.release.set()
    finish(threads, teardown)
    assert app.closed.is_set() and sorted(status for status, _ in answers) == [200] * 4, answers
    err = capfd.readouterr().err
    assert "No open result set" not in err and "Traceback" not in err


def test_the_test_teardown_closes_the_connection_only_after_the_requests_end(synthetic_case, monkeypatch):
    stopping = serving(synthetic_case)
    app, port, _ = next(stopping)
    held = Held(monkeypatch, 2)
    answers = []
    threads = asking(app, port, answers, 2)
    assert held.reached.wait(30)
    teardown = stop_in_a_thread(stopping)
    teardown.join(1.0)
    waiting = teardown.is_alive() and not app.closed.is_set()   # the teardown waits for the two counts
    held.release.set()
    finish(threads, teardown)
    assert waiting and app.closed.is_set()


def test_a_request_that_never_ends_cannot_hold_the_test_teardown_past_the_bound(synthetic_case, monkeypatch):
    monkeypatch.setattr(server, "SHUTDOWN_WAIT_SECONDS", 0.4, raising=False)
    stopping = serving(synthetic_case)
    app, port, _ = next(stopping)
    held = Held(monkeypatch, 1)
    answers = []
    threads = asking(app, port, answers, 1)
    assert held.reached.wait(30)
    began = time.monotonic()
    assert next(stopping, None) is None
    assert 0.3 < time.monotonic() - began < 3
    assert app.closed.is_set()   # closed under the request that did not end
    held.release.set()
    finish(threads)


def serve_in_a_thread(case, monkeypatch):
    """cmd_serve on a thread, with the server and hub it made kept in the returned namespace. serve_forever returns when
    `run.server.shutdown()` is called, as Ctrl+C ends it."""
    run = SimpleNamespace(server=None, hub=None, made=threading.Event(), code=None)
    real = server.serve_hub

    def serve_hub(hub, bound):
        run.server, run.hub, url = real(hub, bound)
        run.app = hub.app
        run.made.set()
        return run.server, run.hub, url

    monkeypatch.setattr(server, "serve_hub", serve_hub)

    def target():
        run.code = cli.cmd_serve(case, SimpleNamespace(port=0, no_browser=True))

    run.thread = threading.Thread(target=target)
    run.thread.start()
    assert run.made.wait(60)
    return run


def test_serve_stopped_with_requests_in_flight_closes_its_connection_after_they_end(synthetic_case, monkeypatch, capsys):
    run = serve_in_a_thread(synthetic_case, monkeypatch)
    app = run.app
    held = Held(monkeypatch, 3)
    answers = []
    threads = asking(app, run.server.server_address[1], answers, 3)
    assert held.reached.wait(30)
    run.server.shutdown()   # what Ctrl+C does to serve_forever
    run.thread.join(1.0)
    assert run.thread.is_alive() and not app.closed.is_set()   # serve waits for the three counts
    held.release.set()
    finish(threads, run.thread)
    assert run.code == 0 and app.closed.is_set()
    assert sorted(status for status, _ in answers) == [200] * 3
    assert "still running" not in capsys.readouterr().err


def test_serve_does_not_wait_past_the_bound_for_a_request_that_never_ends(synthetic_case, monkeypatch, capsys):
    monkeypatch.setattr(server, "SHUTDOWN_WAIT_SECONDS", 0.4, raising=False)
    run = serve_in_a_thread(synthetic_case, monkeypatch)
    app = run.app
    held = Held(monkeypatch, 1)
    answers = []
    threads = asking(app, run.server.server_address[1], answers, 1)
    assert held.reached.wait(30)
    run.server.shutdown()
    run.thread.join(10)
    assert not run.thread.is_alive() and run.code == 0 and app.closed.is_set()
    assert "1 request was still running" in capsys.readouterr().err
    held.release.set()
    finish(threads)


def test_serve_on_the_start_page_stops_with_no_case_to_close(monkeypatch):
    run = SimpleNamespace(made=threading.Event(), code=None)
    real = server.serve_hub

    def serve_hub(hub, bound):
        run.server, run.hub, url = real(hub, bound)
        run.made.set()
        return run.server, run.hub, url

    monkeypatch.setattr(server, "serve_hub", serve_hub)
    thread = threading.Thread(target=lambda: setattr(run, "code", cli.cmd_serve(None, SimpleNamespace(port=0, no_browser=True))))
    thread.start()
    assert run.made.wait(30)
    run.server.shutdown()
    finish([thread])
    assert run.code == 0 and run.hub.app is None


def test_closing_the_hub_waits_for_a_case_switched_away_from_whose_request_is_running(synthetic_case, tmp_path):
    """A case switched away from closes when its last request ends, and the hub's close waits for that too."""
    from conftest import new_synthetic_case

    other = new_synthetic_case(tmp_path / "other")
    hub = Hub(synthetic_case)
    first = hub.app
    assert first.enter()   # a request running on the first case
    hub.open(other)
    second = hub.app
    assert first is not second and not first.closed.is_set()
    closing = threading.Thread(target=lambda: setattr(hub, "left", hub.close(wait=10)))
    closing.start()
    closing.join(0.5)
    assert closing.is_alive() and second.closed.wait(5)   # the open case closes at once; the first waits for its request
    first.leave()
    finish([], closing)
    assert first.closed.is_set() and hub.left == 0 and hub.app is None


def test_closing_the_hub_closes_under_a_request_that_outlasts_the_bound(synthetic_case):
    hub = Hub(synthetic_case)
    app = hub.app
    assert app.enter()
    began = time.monotonic()
    assert hub.close(wait=0.3) == 1   # one App closed under a request still running
    assert 0.2 < time.monotonic() - began < 3 and app.closed.is_set()
    app.leave()   # the request ends later; its leave closes nothing twice
    assert app.closed.is_set()


# A statement that takes about ten seconds to answer unless it is interrupted. Closing a DuckDB connection waits for the
# statements its cursors are running, so a request inside one is what the bound has to cut off.
LONG_QUERY = "SELECT count(*) FROM range(600000000) a WHERE (a.range * 7) % 13 = 5"
INSIDE_A_QUERY = 0.7   # seconds for a statement just started to be running in DuckDB
CUT_OFF_WITHIN = 5     # seconds: the bound of 0.3 or 0.4 s, the interrupt, and the close, with room for a slow computer


def long_count(started):
    """A stand-in for the pivot count that runs LONG_QUERY on the request's own cursor, and sets `started` just before."""

    def count(con, *args, **kwargs):
        started.release()
        return {"count": con.execute(LONG_QUERY).fetchone()[0]}

    return count


def inside_queries(started, requests):
    """Wait until `requests` have reached the statement, then a moment for DuckDB to be running it."""
    for _ in range(requests):
        assert started.acquire(timeout=30)
    time.sleep(INSIDE_A_QUERY)


def test_closing_the_hub_interrupts_the_statement_of_a_request_that_outlasts_the_bound(synthetic_case):
    """A request inside a statement is cut off when the wait ends: the close doesn't wait for the statement, and the
    request's statement ends in an interrupt, not in a closed result."""
    hub = Hub(synthetic_case)
    app = hub.app
    assert app.enter()
    outcome = {}
    started = threading.Semaphore(0)

    def request():
        cursor = app.reader()
        started.release()
        try:
            outcome["rows"] = cursor.execute(LONG_QUERY).fetchall()
        except Exception as exc:   # noqa: BLE001  (the test reads what the statement raised)
            outcome["error"] = exc

    thread = threading.Thread(target=request)
    thread.start()
    inside_queries(started, 1)
    began = time.monotonic()
    assert hub.close(wait=0.3) == 1
    assert time.monotonic() - began < CUT_OFF_WITHIN and app.closed.is_set()
    finish([], thread)
    assert isinstance(outcome.get("error"), duckdb.InterruptException), outcome
    app.leave()


def test_closing_the_hub_interrupts_a_statement_on_the_connection_itself(synthetic_case):
    """The writes, which run on the App's own connection, are cut off too."""
    hub = Hub(synthetic_case)
    app = hub.app
    assert app.enter()
    outcome = {}
    started = threading.Semaphore(0)

    def request():
        started.release()
        try:
            outcome["rows"] = app.con.execute(LONG_QUERY).fetchall()
        except Exception as exc:   # noqa: BLE001  (the test reads what the statement raised)
            outcome["error"] = exc

    thread = threading.Thread(target=request)
    thread.start()
    inside_queries(started, 1)
    began = time.monotonic()
    assert hub.close(wait=0.3) == 1
    assert time.monotonic() - began < CUT_OFF_WITHIN and app.closed.is_set()
    finish([], thread)
    assert isinstance(outcome.get("error"), duckdb.InterruptException), outcome
    app.leave()


def test_a_request_cut_off_cannot_start_another_statement_to_hold_the_close_up(synthetic_case, monkeypatch):
    """After the interrupt a request may go on to its next statement, on a cursor of its own. The close refuses it one,
    so the close doesn't wait for that statement. The close is slowed to give the request time to ask."""
    real_close = server.App._close
    monkeypatch.setattr(server.App, "_close", lambda app: (time.sleep(1.5), real_close(app)))
    hub = Hub(synthetic_case)
    app = hub.app
    assert app.enter()
    outcome = {}
    started = threading.Semaphore(0)

    def request():
        started.release()
        with contextlib.suppress(duckdb.InterruptException):
            app.reader().execute(LONG_QUERY).fetchall()
        try:
            outcome["rows"] = app.reader().execute(LONG_QUERY).fetchall()   # the next statement of the same request
        except Exception as exc:   # noqa: BLE001  (the test reads what the statement raised)
            outcome["error"] = exc

    thread = threading.Thread(target=request)
    thread.start()
    inside_queries(started, 1)
    began = time.monotonic()
    assert hub.close(wait=0.3) == 1
    assert time.monotonic() - began < CUT_OFF_WITHIN + 1.5 and app.closed.is_set()
    finish([], thread)
    assert isinstance(outcome.get("error"), duckdb.ConnectionException), outcome
    app.leave()


A_LOAD_ENDED = SimpleNamespace(error=None, results=[{"loaded": True}])


def test_a_jobs_refresh_after_its_load_is_a_request_the_stop_waits_for_and_cuts_off(synthetic_case, monkeypatch):
    """The rebuild after a Tools job's load runs on the job's thread, on the App's connection. It counts as a request,
    so the stop's bound covers it: the close cuts the statement off instead of waiting for it."""
    hub = Hub(synthetic_case)
    app = hub.app
    outcome = {}
    started = threading.Semaphore(0)

    def refresh(events_changed=False):
        started.release()
        try:
            outcome["rows"] = app.con.execute(LONG_QUERY).fetchall()
        except Exception as exc:   # noqa: BLE001  (the test reads what the statement raised)
            outcome["error"] = exc

    monkeypatch.setattr(app, "refresh_identity", refresh)
    monkeypatch.setattr(app, "remember", lambda: None)
    thread = threading.Thread(target=app.after_job, args=(A_LOAD_ENDED,))
    thread.start()
    inside_queries(started, 1)
    began = time.monotonic()
    assert hub.close(wait=0.3) == 1
    assert time.monotonic() - began < CUT_OFF_WITHIN and app.closed.is_set()
    finish([], thread)
    assert isinstance(outcome.get("error"), duckdb.InterruptException), outcome


def test_a_jobs_refresh_is_skipped_on_an_app_the_hub_has_retired(synthetic_case, monkeypatch):
    """A job that ends after its case was switched away from has no connection left to rebuild on."""
    hub = Hub(synthetic_case)
    app = hub.app
    ran = []
    monkeypatch.setattr(app, "refresh_identity", lambda events_changed=False: ran.append("refresh"))
    monkeypatch.setattr(app, "remember", lambda: ran.append("remember"))
    app.retire()
    assert app.closed.is_set()
    app.after_job(A_LOAD_ENDED)
    assert ran == []
    hub.close(wait=0.3)


def test_a_jobs_refresh_leaves_the_app_when_it_fails(synthetic_case, monkeypatch):
    """The refresh's own fault does not leave the job counted as a request that never ends: the stop would wait the
    whole bound for it."""
    hub = Hub(synthetic_case)
    app = hub.app

    def refresh(events_changed=False):
        raise RuntimeError("the rebuild failed")

    monkeypatch.setattr(app, "refresh_identity", refresh)
    with contextlib.suppress(RuntimeError):
        app.after_job(SimpleNamespace(error="stopped", results=[]))
    assert app.inflight == 0
    hub.close(wait=0.3)


def test_the_test_teardown_cuts_off_counts_still_inside_a_statement(synthetic_case, monkeypatch):
    monkeypatch.setattr(server, "SHUTDOWN_WAIT_SECONDS", 0.4, raising=False)
    started = threading.Semaphore(0)
    monkeypatch.setattr(server, "count_pivot", long_count(started))
    stopping = serving(synthetic_case)
    app, port, _ = next(stopping)
    answers = []
    threads = asking(app, port, answers, 2)
    inside_queries(started, 2)
    began = time.monotonic()
    assert next(stopping, None) is None
    assert time.monotonic() - began < CUT_OFF_WITHIN and app.closed.is_set()
    finish(threads)
    assert sorted(status for status, _ in answers) == [500, 500]
    assert all("Interrupt" in body["error"] and "No open result set" not in body["error"] for _, body in answers), answers


def test_serve_cuts_off_a_count_still_inside_a_statement_when_the_wait_ends(synthetic_case, monkeypatch, capsys):
    monkeypatch.setattr(server, "SHUTDOWN_WAIT_SECONDS", 0.4, raising=False)
    started = threading.Semaphore(0)
    monkeypatch.setattr(server, "count_pivot", long_count(started))
    run = serve_in_a_thread(synthetic_case, monkeypatch)
    answers = []
    threads = asking(run.app, run.server.server_address[1], answers, 1)
    inside_queries(started, 1)
    began = time.monotonic()
    run.server.shutdown()
    run.thread.join(CUT_OFF_WITHIN)
    assert not run.thread.is_alive() and time.monotonic() - began < CUT_OFF_WITHIN
    assert run.code == 0 and run.app.closed.is_set()
    assert "1 request was still running" in capsys.readouterr().err
    finish(threads)
    assert [status for status, _ in answers] == [500]
