"""A tab left open from an earlier run of `glessner serve`. With the fixed port, the
tab reaches the next run's server, which must refuse it with a clear message and show it none of the new run's data. It
drives the installed Microsoft Edge through Playwright, as test_browser_smoke does, and is skipped without it."""

import socket
import threading

import pytest
from test_browser_smoke import LOAD_TIMEOUT_MS, PAGE_TIMEOUT_MS, VIEWPORT, browser, to_timeline  # noqa: F401

from glessner import server as mod
from glessner.server import STALE_SESSION, Hub, serve_hub

pytestmark = pytest.mark.browser
READY = "() => window.__ready === true && window.__app.S.data !== null"


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def run(case, port):
    """One run of serve on `port`, as the fixed port gives every run: its server on a thread, its hub, and its link."""
    server, hub, url = serve_hub(Hub(case), port)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, hub, url


def stop(server, hub):
    server.shutdown()
    server.server_close()
    hub.app.con.close()


def test_a_tab_from_an_earlier_run_is_refused_with_the_message_and_sees_no_data(browser, synthetic_case, monkeypatch):  # noqa: F811
    """The page's next request after the new run starts is answered 403 with STALE_SESSION: the page shows the band
    without a Reload button, puts the message on the status line, draws nothing, and sends nothing more. A reload of the
    tab gets the launch hint, not the page. The keep-alive is cut to a second, so the first run's handler threads close
    the tab's old connections as an exited process would have; both runs live in this one process."""
    monkeypatch.setattr(mod, "KEEP_ALIVE_SECONDS", 1)
    port = free_port()
    first, hub1, url = run(synthetic_case, port)
    context = browser.new_context(viewport=VIEWPORT)
    context.set_default_timeout(PAGE_TIMEOUT_MS)
    p = context.new_page()
    answered = []   # the status of every API answer the page gets
    p.on("response", lambda res: answered.append((res.url, res.status)) if "/api/" in res.url else None)
    try:
        p.goto(url, timeout=LOAD_TIMEOUT_MS)
        p.wait_for_function(READY)
        to_timeline(p)
        old_id = p.evaluate("() => window.__app.S.meta.case_id")
        stop(first, hub1)
        p.wait_for_timeout(2_000)   # the old handler threads time out and close their sockets
        second, hub2, _ = run(synthetic_case, port)
        try:
            assert second.server_address[1] == port and hub2.token != hub1.token and hub2.app.case_id != old_id
            del answered[:]
            p.locator("#investigateButton").click()
            band = p.locator("#caseChanged")
            band.wait_for()
            assert band.inner_text() == STALE_SESSION and band.locator("button").count() == 0
            assert p.locator("#status").inner_text() == STALE_SESSION
            assert p.locator("#details[data-page='investigate']").count() == 0
            assert answered and {status for _, status in answered} == {403}, answered
            before = len(answered)
            refused = p.evaluate("() => import('/js/core.js').then((m) => m.api('/api/marks')).catch((e) => e.message)")
            assert refused == STALE_SESSION and len(answered) == before   # nothing more was sent
            p.reload()
            assert "Open the link that `glessner serve` printed." in p.content()
            assert p.locator("#labels").count() == 0 and synthetic_case.settings.name not in p.content()
        finally:
            stop(second, hub2)
    finally:
        context.close()
