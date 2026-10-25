"""The start link in a real browser: the page trades the link's token for the session, drops the token from its address,
and keeps the session for a reload or a new tab; a link that was used already opens nothing in a browser with no session.
They drive the installed Microsoft Edge through Playwright, as test_browser_smoke does, and are skipped without it."""

import threading
from urllib.parse import urlsplit

import pytest
from conftest import close_first
from test_browser_smoke import LOAD_TIMEOUT_MS, PAGE_TIMEOUT_MS, VIEWPORT, browser, served_page  # noqa: F401

from glessner.server import LINK_USED, Hub, serve_hub

pytestmark = pytest.mark.browser
READY = "() => window.__ready === true && window.__app.S.data !== null"


def test_the_address_drops_the_token_and_a_new_tab_in_the_browser_opens_the_case(browser, synthetic_case):  # noqa: F811
    """Once the page has its session the address is the page's own, without the token, so it can't be copied from the
    address bar or the history. A new page in the same browser profile, opened at the plain address, finds the session
    in storage and loads the case."""
    for p in served_page(browser, synthetic_case):
        origin = f"http://{urlsplit(p.url).netloc}"
        assert p.url == f"{origin}/"
        tab = p.context.new_page()
        tab.goto(f"{origin}/")
        tab.wait_for_function(READY)
        assert tab.locator("#caseName").inner_text() == synthetic_case.settings.name
        assert tab.locator("#caseChanged").count() == 0
        tab.close()


def test_a_link_with_another_parameter_keeps_it(browser, synthetic_case):  # noqa: F811
    """The page removes the token and nothing else: a link that also opens the Tools page, as a new case's does, keeps
    its parameter and its hash."""
    for p in served_page(browser, synthetic_case):
        p.goto(f"{p.new_link()}&page=tools#top")
        p.wait_for_function(READY)
        p.wait_for_selector("#details[data-page='tools']")
        assert p.url.endswith("/?page=tools#top") and "token" not in p.url


def test_a_link_used_already_opens_nothing_in_a_browser_with_no_session(browser, synthetic_case):  # noqa: F811
    """The first browser trades the token. A second browser profile that opens the same link has no session in storage,
    so the page shows the server's words and draws no case data; a reload of the first browser still has its session."""
    server, hub, url = serve_hub(Hub(synthetic_case), 0)
    hang_up = close_first(server)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    contexts = [browser.new_context(viewport=VIEWPORT), browser.new_context(viewport=VIEWPORT)]
    try:
        for context in contexts:
            context.set_default_timeout(PAGE_TIMEOUT_MS)
        first, second = (context.new_page() for context in contexts)
        first.goto(url, timeout=LOAD_TIMEOUT_MS)
        first.wait_for_function(READY)
        second.goto(url, timeout=LOAD_TIMEOUT_MS)
        band = second.locator("#caseChanged")
        band.wait_for()
        assert band.inner_text() == LINK_USED and band.locator("button").count() == 0
        assert LINK_USED in second.locator("#status").inner_text()
        assert synthetic_case.settings.name not in second.content() and second.locator("#labels > *").count() == 0
        assert second.evaluate("() => localStorage.getItem('glessner.session')") is None
        first.reload()
        first.wait_for_function(READY)
        assert first.locator("#caseChanged").count() == 0
    finally:
        server.shutdown()
        hang_up()
        for context in contexts:
            context.close()
        server.server_close()
        hub.app.con.close()
