"""To investigate on a case with more flagged events or pending suggestions than the page takes at once, in a real browser:
Accept all and Reject all refuse a source larger than one decision can name, before any request, and the marked events
come a page at a time. They drive the installed Microsoft Edge through Playwright, as test_browser_smoke does, and are
skipped without it."""

import json
import re

import pytest
from conftest import SEC, T0
from test_browser_investigate import COUNTED, INVESTIGATE, open_worklist, page_post, uid_at
from test_browser_smoke import RECORD_REQUESTS, asked, browser, case_menu, refused_with, served_page, wait_held  # noqa: F401

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


NEXT = "/api/investigate?offset"
FOUR = (0, 60, 62, 874)   # seconds after T0 of the events the tests below mark: DC01's first three, then DESKTOP's


def mark_four(uids):
    """A setup that marks the events at FOUR Suspicious and keeps their IDs by second in `uids`."""
    def setup(app):
        for seconds in FOUR:
            uids[seconds] = uid_at(app, T0 + seconds * SEC)
        api_mark(app, {"uids": list(uids.values()), "value": "suspicious"})
    return setup


def listed_uids(p):
    return p.evaluate("() => [...document.querySelectorAll('#details ul.worklist li.rel-row')].map((row) => row.dataset.uid)")


def taken_all(p, prefix):
    """Wait until the page's code has finished with the answer of each request it made under `prefix`."""
    p.wait_for_function("""(prefix) => {
        const made = window.__asked.filter((path) => path.startsWith(prefix)).length;
        return made > 0 && window.__taken.filter((path) => path.startsWith(prefix)).length === made;
    }""", arg=prefix)


def test_an_offset_edited_between_two_pages_lists_the_marked_events_again(browser, synthetic_case, monkeypatch):  # noqa: F811
    """A host's clock offset moves its events in the list's time order without changing how many there are, so the total
    that Show the next compares stays as it was. The page reads the marked events again instead of adding a page that
    repeats one listed and skips another, and goes on from the new order, listing each event once."""
    monkeypatch.setattr(server, "WORKLIST_PAGE", 2)
    uids = {}
    for p in served_page(browser, synthetic_case, setup=mark_four(uids)):
        open_worklist(p)
        assert listed_uids(p) == [uids[0], uids[60]]
        page_post(p, "/api/host", {"host": "DESKTOP", "offset_seconds": -3600})   # DESKTOP's event now comes first
        p.get_by_role("button", name="Show the next 2").click()
        p.wait_for_function("(want) => document.getElementById('status').textContent === want"
                            " || document.querySelectorAll('#details ul.worklist li.rel-row').length > 2", arg=CHANGED)
        assert p.locator("#status").inner_text() == CHANGED
        p.wait_for_function(LISTED_UIDS, arg=[uids[874], uids[0]])
        p.get_by_role("button", name="Show the next 2").click()
        p.wait_for_function(LISTED_UIDS, arg=[uids[874], uids[0], uids[60], uids[62]])
        assert p.locator("#details .inv-more button").count() == 0
        assert p.locator("#details .inv-section input[type='search']").get_attribute("placeholder") == "Find in this list"


def times_listed(p):
    return p.locator("#details ul.worklist li.rel-row .rel-time").all_inner_texts()


def test_an_offset_edited_between_two_pages_that_keeps_the_order_lists_the_marked_events_again(
        browser, synthetic_case, monkeypatch):  # noqa: F811
    """DC01's offset moves its events an hour earlier and leaves them ahead of DESKTOP's, so no event changes place and the
    total stays. The rows listed carry the old times, and the page that follows would carry the new, which puts a row from
    after the edit among rows from before it. The page reads the list again instead, and its button still offers the rest."""
    monkeypatch.setattr(server, "WORKLIST_PAGE", 2)
    uids = {}
    for p in served_page(browser, synthetic_case, setup=mark_four(uids)):
        open_worklist(p)
        before = times_listed(p)
        p.evaluate(RECORD_REQUESTS)
        page_post(p, "/api/host", {"host": "DC01", "offset_seconds": -3600})
        p.get_by_role("button", name="Show the next 2").click()
        p.wait_for_function("(old) => JSON.stringify([...document.querySelectorAll('#details ul.worklist li.rel-row .rel-time')]"
                            ".map((cell) => cell.textContent)) !== JSON.stringify(old)", arg=before)
        assert p.locator("#status").inner_text() == CHANGED
        assert listed_uids(p) == [uids[0], uids[60]]
        assert all(new != old for new, old in zip(times_listed(p), before, strict=True))
        assert p.get_by_role("button", name="Show the next 2").count() == 1
        assert asked(p, "/api/investigate") == [f"{NEXT}=2", "/api/investigate"]


def list_the_four(p, uids):
    """Open To investigate with a page of one event and press Show the next until all four marked events are listed."""
    open_worklist(p)
    for n in range(2, len(FOUR) + 1):
        p.get_by_role("button", name="Show the next 1").click()
        p.wait_for_function(LISTED_UIDS, arg=[uids[s] for s in FOUR[:n]])
    assert p.locator("#details .inv-more button").count() == 0


def test_a_list_read_again_over_several_pages_starts_over_when_the_order_changes_between_them(
        browser, synthetic_case, monkeypatch):  # noqa: F811
    """A tick draws the page again with the rows that were on it, which takes a request for each page. With the third
    request held, another tab edits a host's clock offset, so the page that answers is of another order than the first
    two. The read starts over, and the list holds each marked event once, the first of them the one that moved, and does
    not take itself for complete while an event is missing."""
    monkeypatch.setattr(server, "WORKLIST_PAGE", 1)
    uids = {}
    for p in served_page(browser, synthetic_case, setup=mark_four(uids)):
        list_the_four(p, uids)
        p.evaluate(RECORD_REQUESTS)
        held = []
        hold = lambda url: url.endswith(f"{NEXT}=2")
        p.route(hold, lambda route: held.append(route))  # noqa: B023
        p.locator("#details li.rel-row input.inv-tick").first.check()
        wait_held(p, held)
        page_post(p, "/api/host", {"host": "DESKTOP", "offset_seconds": -3600})
        for route in held:
            route.continue_()
        p.unroute(hold)
        p.wait_for_function(LISTED_UIDS, arg=[uids[874], uids[0], uids[60], uids[62]])
        assert p.locator("#details .inv-more button").count() == 0
        assert p.locator("#details .inv-section input[type='search']").get_attribute("placeholder") == "Find in this list"
        assert asked(p, "/api/investigate") == ["/api/investigate", f"{NEXT}=1", f"{NEXT}=2",
                                                "/api/investigate", f"{NEXT}=1", f"{NEXT}=2", f"{NEXT}=3"]


@pytest.mark.parametrize(("field", "value"), [("order", "another"), ("total", 5)])
def test_a_list_read_again_whose_marked_events_keep_changing_lists_the_rows_read_before_the_change_and_a_button_for_the_rest(
        browser, synthetic_case, monkeypatch, field, value):  # noqa: F811
    """When the third page and every later one names another order, or another total, than the first two, the read
    starts over a few times and then keeps the two rows it read in one order, with the button for the rest. The page does
    not call a list complete that holds only some of the marked events, and the button reads on once the answers agree."""
    monkeypatch.setattr(server, "WORKLIST_PAGE", 1)
    uids = {}
    for p in served_page(browser, synthetic_case, setup=mark_four(uids)):
        list_the_four(p, uids)
        p.evaluate(RECORD_REQUESTS)

        def another_order(route):
            body = route.fetch().json()
            body[field] = value
            route.fulfill(status=200, content_type="application/json", body=json.dumps(body))

        differ = lambda url: url.endswith((f"{NEXT}=2", f"{NEXT}=3"))
        p.route(differ, another_order)
        p.locator("#details li.rel-row input.inv-tick").first.check()
        p.wait_for_function("() => document.querySelector('#details .meter-words')?.textContent === '1 of 4 followed up'")
        p.wait_for_function(LISTED_UIDS, arg=[uids[0], uids[60]])
        p.unroute(differ)
        assert asked(p, "/api/investigate") == ["/api/investigate", f"{NEXT}=1", f"{NEXT}=2"] * 3
        assert p.locator("#details .inv-section input[type='search']").get_attribute("placeholder") == "Find in the 2 listed"
        for n in (3, 4):
            p.get_by_role("button", name="Show the next 1").click()
            p.wait_for_function(LISTED_UIDS, arg=[uids[s] for s in FOUR[:n]])


def test_a_list_read_again_adds_only_the_events_a_later_page_does_not_repeat(browser, synthetic_case, monkeypatch):  # noqa: F811
    """An answer holding an event the read has taken already adds the others once, so each offset after it counts the
    events taken and not the rows answered, and the list that results holds each marked event once."""
    monkeypatch.setattr(server, "WORKLIST_PAGE", 1)
    uids = {}
    for p in served_page(browser, synthetic_case, setup=mark_four(uids)):
        list_the_four(p, uids)
        p.evaluate(RECORD_REQUESTS)
        # The first two events answer the request for the second one
        overlap = lambda url: url.endswith(f"{NEXT}=1")
        p.route(overlap, lambda route: route.fulfill(
            response=route.fetch(url=route.request.url.replace("offset=1", "offset=0&limit=2"))))
        p.locator("#details li.rel-row input.inv-tick").first.check()
        p.wait_for_function("() => document.querySelector('#details .meter-words')?.textContent === '1 of 4 followed up'")
        p.wait_for_function(LISTED_UIDS, arg=[uids[s] for s in FOUR])
        p.unroute(overlap)
        assert asked(p, NEXT) == [f"{NEXT}=1", f"{NEXT}=2", f"{NEXT}=3"]
        assert p.locator("#details .inv-more button").count() == 0


def test_a_host_offset_edited_in_the_hosts_panel_lists_the_marked_events_again(browser, synthetic_case):  # noqa: F811
    """With To investigate on screen, an offset typed in the Hosts panel redraws it in the new time order, as it redraws
    the Event page, so the list does not keep the order from before the edit."""
    uids = {}
    for p in served_page(browser, synthetic_case, setup=mark_four(uids)):
        open_worklist(p)
        assert listed_uids(p) == [uids[s] for s in FOUR]
        case_menu(p, "hostsButton")
        offset = p.locator("#hostsTable tr[data-host='DESKTOP'] input[type=number]")
        offset.fill("-3600")
        offset.press("Enter")
        p.wait_for_function(LISTED_UIDS, arg=[uids[874], uids[0], uids[60], uids[62]])


@pytest.mark.parametrize("act", [
    pytest.param(lambda button: button.evaluate("(b) => { b.click(); b.click(); }"), id="two clicks"),
    pytest.param(lambda button: button.dblclick(), id="a double click"),
])
def test_a_second_click_on_show_the_next_waits_for_the_first_answer(browser, synthetic_case, monkeypatch, act):  # noqa: F811
    """With the first page's answer held, a second click sends no second request: the offset would be the same, both
    answers would add the same page, and the offset after them would skip the page between. The list holds each event
    once, the find box counts the events listed, and the next request asks for the offset after them."""
    monkeypatch.setattr(server, "WORKLIST_PAGE", 1)
    uids = {}
    for p in served_page(browser, synthetic_case, setup=mark_four(uids)):
        open_worklist(p)
        p.wait_for_function(COUNTED)
        p.evaluate(RECORD_REQUESTS)
        held = []
        hold = lambda url: NEXT in url
        p.route(hold, lambda route: held.append(route))  # noqa: B023
        act(p.get_by_role("button", name="Show the next 1"))
        wait_held(p, held)
        assert asked(p, NEXT) == [f"{NEXT}=1"]
        for route in held:
            route.continue_()
        p.unroute(hold)
        taken_all(p, NEXT)
        p.wait_for_function(COUNTED)
        assert listed_uids(p) == [uids[0], uids[60]]
        assert p.locator("#details .inv-section input[type='search']").get_attribute("placeholder") == "Find in the 2 listed"
        p.get_by_role("button", name="Show the next 1").click()
        taken_all(p, NEXT)
        assert asked(p, NEXT) == [f"{NEXT}=1", f"{NEXT}=2"]
        assert listed_uids(p) == [uids[0], uids[60], uids[62]]
        p.get_by_role("button", name="Show the next 1").click()
        taken_all(p, NEXT)
        assert listed_uids(p) == [uids[s] for s in FOUR]
        assert p.locator("#details .inv-more button").count() == 0


def test_show_the_next_answers_a_click_again_after_its_request_fails(browser, synthetic_case, monkeypatch):  # noqa: F811
    """The wait for an answer ends when the request fails: the status line gives the error, the button stays, and a click
    after the server answers again lists the page."""
    monkeypatch.setattr(server, "WORKLIST_PAGE", 2)
    uids = {}
    for p in served_page(browser, synthetic_case, setup=mark_four(uids)):
        open_worklist(p)
        refuse = lambda url: NEXT in url
        p.route(refuse, refused_with("the next page failed"))
        more = p.get_by_role("button", name="Show the next 2")
        more.click()
        p.wait_for_function("() => document.getElementById('status').textContent === 'the next page failed'")
        p.unroute(refuse)
        p.errors[:] = [e for e in p.errors if "/api/investigate" not in e]   # that refusal was the point
        assert more.is_enabled()
        more.click()
        p.wait_for_function(LISTED_UIDS, arg=[uids[s] for s in FOUR])


def test_a_page_that_repeats_a_listed_event_adds_only_the_events_not_listed(browser, synthetic_case, monkeypatch):  # noqa: F811
    """An answer holding an event the list shows already, as when an order changed without the page learning of it, adds
    the others once, and the next request asks for the offset after the events listed, not after the answer's rows."""
    monkeypatch.setattr(server, "WORKLIST_PAGE", 1)
    uids = {}
    for p in served_page(browser, synthetic_case, setup=mark_four(uids)):
        open_worklist(p)
        p.evaluate(RECORD_REQUESTS)
        # The first two events answer the request for the second one
        overlap = lambda url: url.endswith(f"{NEXT}=1")
        p.route(overlap, lambda route: route.fulfill(
            response=route.fetch(url=route.request.url.replace("offset=1", "offset=0&limit=2"))))
        p.get_by_role("button", name="Show the next 1").click()
        taken_all(p, NEXT)
        assert listed_uids(p) == [uids[0], uids[60]]
        p.unroute(overlap)
        p.wait_for_function(COUNTED)
        p.get_by_role("button", name="Show the next 1").click()
        taken_all(p, NEXT)
        assert listed_uids(p) == [uids[0], uids[60], uids[62]]
        assert asked(p, NEXT)[-1] == f"{NEXT}=2"


def test_a_page_of_events_all_listed_already_lists_the_marked_events_again(browser, synthetic_case, monkeypatch):  # noqa: F811
    """An answer with nothing the list does not show adds no rows and would leave the button asking for the same offset
    again, so the page reads the marked events again and says so."""
    monkeypatch.setattr(server, "WORKLIST_PAGE", 1)
    uids = {}
    for p in served_page(browser, synthetic_case, setup=mark_four(uids)):
        open_worklist(p)
        again = lambda url: url.endswith(f"{NEXT}=1")
        p.route(again, lambda route: route.fulfill(
            response=route.fetch(url=route.request.url.replace("offset=1", "offset=0"))))
        p.get_by_role("button", name="Show the next 1").click()
        p.wait_for_function("(want) => document.getElementById('status').textContent === want", arg=CHANGED)
        p.unroute(again)
        p.wait_for_function(COUNTED)
        assert listed_uids(p) == [uids[0]]
        p.get_by_role("button", name="Show the next 1").click()
        p.wait_for_function(LISTED_UIDS, arg=[uids[0], uids[60]])
