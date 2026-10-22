"""To investigate on a case with more flagged events or pending suggestions than the page takes at once, in a real browser:
Accept all and Reject all refuse a source larger than one decision can name, before any request, and the marked events
come a page at a time. They drive the installed Microsoft Edge through Playwright, as test_browser_smoke does, and are
skipped without it."""

import re

import pytest
from conftest import SEC, T0
from test_browser_investigate import COUNTED, INVESTIGATE, open_worklist, page_post, uid_at
from test_browser_smoke import browser, served_page  # noqa: F401

from glessner import server
from glessner.server import api_mark, api_rule

pytestmark = pytest.mark.browser
COUNT_POOL = 4   # the counts To investigate asks for at once
LOGONS = "id: logons\nsuggest: suspicious\nwhen: {field: event_code, equals: '4624'}\n"


def test_accept_all_and_reject_all_above_the_limit_are_refused_in_the_row_before_any_request(
        browser, synthetic_case, monkeypatch):  # noqa: F811
    """A source with more pending suggestions than one decision can name has its Accept all and Reject all refused in its
    row, in the server's words, without a request: the page does not fetch the pending events or post a decision."""
    monkeypatch.setattr(server, "MAX_MARK_TARGETS", 1)

    def rule(app):
        api_rule(app, {"op": "add", "text": LOGONS})

    for p in served_page(browser, synthetic_case, setup=rule):
        open_worklist(p)
        row = p.locator(f"{INVESTIGATE} .rule[data-source='logons']")
        pending = int(re.match(r"(\d+) events pending", row.locator(".rule-pending").inner_text())[1])
        assert pending >= 2
        sent = []
        p.on("request", lambda r: sent.append(r.url) if "/api/suggestion" in r.url or "/api/pending_uids" in r.url else None)  # noqa: B023
        block = row.locator(".confirm-block")
        for button, said in (
                ("Accept all", f"Accepting these would mark {pending} events, more than the 1 a mark can hold. "),
                ("Reject all", f"Rejecting these would name {pending} events, more than the 1 one decision can name. ")):
            row.get_by_role("button", name=button).click()
            block.wait_for()
            verb = button.split()[0]
            assert block.locator(".confirm-line").inner_text() == (
                f"{said}{verb} them a group at a time from the source's Suggestions page.")
            assert block.locator(".confirm-title").count() == 0
            block.get_by_role("button", name="Close").click()
            p.wait_for_selector(f"{INVESTIGATE} .confirm-block", state="detached")
        assert sent == []


def test_the_worklist_lists_a_page_of_the_marked_events_and_the_next_page_on_a_click(browser, synthetic_case, monkeypatch):  # noqa: F811
    """With more marked events than a page, To investigate lists the first page and a button for the next, the meter
    counts every marked event, the find box says which rows it covers, and the next page is added under the first with its
    own counts. A tick afterwards keeps every row shown."""
    monkeypatch.setattr(server, "WORKLIST_PAGE", 2)

    def marks(app):
        for seconds in (0, 60, 874):
            api_mark(app, {"uids": [uid_at(app, T0 + seconds * SEC)], "value": "suspicious"})

    for p in served_page(browser, synthetic_case, setup=marks):
        asked = []
        p.on("request", lambda r: asked.append(r.url.split("/api/investigate")[1]) if "/api/investigate" in r.url else None)  # noqa: B023
        open_worklist(p)
        details = p.locator("#details")
        rows = details.locator("ul.worklist li.rel-row")
        meter = details.locator(".inv-section .inv-head .meter-words").first
        find = details.locator(".inv-section input[type='search']")
        p.wait_for_function(COUNTED)
        assert rows.count() == 2 and meter.inner_text() == "0 of 3 followed up"
        assert find.get_attribute("placeholder") == "Find in the 2 listed"
        more = details.get_by_role("button", name="Show the next 1")
        more.click()
        p.wait_for_function(f"() => document.querySelectorAll(\"{INVESTIGATE} ul.worklist li.rel-row\").length === 3")
        p.wait_for_function(COUNTED)
        assert asked == ["", "?offset=2"]
        assert more.count() == 0 and meter.inner_text() == "0 of 3 followed up"
        assert find.get_attribute("placeholder") == "Find in this list"
        rows.nth(2).locator(".inv-tick").check()
        p.wait_for_function("() => document.querySelector('#details .meter-words')?.textContent === '1 of 3 followed up'")
        assert rows.count() == 3 and rows.nth(2).locator(".inv-followed").count() == 1


def test_the_counts_stop_when_another_page_takes_the_panel(browser, synthetic_case):  # noqa: F811
    """The page counts a few rows at a time after it draws. With the first counts held and an Event page opened over it,
    the rest of the rows are not asked for, and the page records no timing for counts that did not finish on it."""
    def marks(app):
        for seconds in (0, 60, 874):
            api_mark(app, {"uids": [uid_at(app, T0 + seconds * SEC)], "value": "suspicious"})

    for p in served_page(browser, synthetic_case, setup=marks):
        held = []
        p.route(lambda url: "/api/pivot_count" in url and "unreviewed=1" in url, lambda route: held.append(route))  # noqa: B023
        open_worklist(p)
        for _ in range(200):
            if len(held) == COUNT_POOL:
                break
            p.wait_for_timeout(50)
        assert len(held) == COUNT_POOL
        assert p.locator(f"{INVESTIGATE} .inv-count").count() > COUNT_POOL   # rows are left for the counts to ask for
        p.locator(f"{INVESTIGATE} ul.worklist li.rel-row .rel-text").first.click()
        p.wait_for_selector("#details[data-page='event'] .ev-ident")
        for route in held[:COUNT_POOL]:
            route.continue_()
        p.wait_for_timeout(500)
        assert len(held) == COUNT_POOL
        assert not p.evaluate("window.__timings.some((t) => t.page === 'investigate')")


LISTED_UIDS = """(want) => JSON.stringify([...document.querySelectorAll("#details ul.worklist li.rel-row")]
    .map((row) => row.dataset.uid)) === JSON.stringify(want)"""
CHANGED = "The marked events changed since this list was read, so it is listed again."


@pytest.mark.parametrize(("marked", "change", "listed", "next_page"), [
    pytest.param((0, 60, 874), (0, "unreviewed"), (60, 874), None, id="a marked event unmarked"),
    pytest.param((60, 62, 874), (0, "suspicious"), (0, 60), "Show the next 2", id="an earlier event marked"),
])
def test_a_mark_changed_since_the_first_page_was_read_lists_the_marked_events_again_on_the_next_page(
        browser, synthetic_case, monkeypatch, marked, change, listed, next_page):  # noqa: F811
    """The next page is read by an offset from the first marked event. With two of three events listed, an event unmarked in
    another tab would leave the offset past the end and the third never listed; one marked before them would repeat a listed
    row. The page reads the marked events again instead, and says so."""
    monkeypatch.setattr(server, "WORKLIST_PAGE", 2)
    uids = {}

    def setup(app):
        for seconds in (0, 60, 62, 874):
            uids[seconds] = uid_at(app, T0 + seconds * SEC)
        for seconds in marked:
            api_mark(app, {"uids": [uids[seconds]], "value": "suspicious"})

    for p in served_page(browser, synthetic_case, setup=setup):
        open_worklist(p)
        rows = p.locator("#details ul.worklist li.rel-row")
        assert rows.count() == 2
        seconds, value = change
        page_post(p, "/api/mark", {"uids": [uids[seconds]], "value": value, "note": ""})
        p.get_by_role("button", name="Show the next 1").click()
        p.wait_for_function(LISTED_UIDS, arg=[uids[s] for s in listed])
        assert p.locator("#status").inner_text() == CHANGED
        more = p.locator("#details .inv-more").get_by_role("button")
        assert (more.inner_text() if more.count() else None) == next_page
