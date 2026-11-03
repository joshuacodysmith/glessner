"""The verdict buttons in a list's head, in a real browser: every list of ticked events offers the Event page header's four
marks, in its order and colors, and Reject N suggestions while a ticked event has a pending suggestion, which the server
turns into a rejection for each source that suggests it. They drive the installed Microsoft Edge through Playwright, as
test_browser_smoke does, and are skipped without it."""

import dataclasses
import json

import pytest
from conftest import SEC, T0, logon
from test_browser_details import NARROWEST_FITS, PLACEHOLDER_FITS
from test_browser_smoke import browser, served_page  # noqa: F401
from test_search import probe_case

from glessner.events import load
from glessner.journal import JOURNAL_FILE
from glessner.server import api_mark, api_rule

pytestmark = pytest.mark.browser
EXTRA_LOG = "DC01/Windows/System32/winevt/Logs/Extra.evtx"
ADDRESS = "10.42.85.50"
SEARCH_HEAD = "#details[data-page='search'] .sticky-head"
HEAD_MARKS = ["Malicious", "Suspicious", "Authorized", "Unreviewed"]


def entries(case):
    return [json.loads(line) for line in (case.folder / JOURNAL_FILE).read_text(encoding="utf-8").splitlines()]


def add_logons(case, **counts):
    """Network logons from ADDRESS on DC01, by each user the given number of times, a second apart. Each message names
    its user, so a list's find can narrow to one of them."""
    users = [user for user, n in counts.items() for _ in range(n)]
    events = [dataclasses.replace(logon(T0 + (120 + i) * SEC, 300 + i, EXTRA_LOG, user=user, ltype="3", ip=ADDRESS),
                                  message=f"4624 logon by {user}")
              for i, user in enumerate(users)]
    load(case.db_path, events, host="DC01", tool="evtxecmd", tool_version="t", run_id="more",
         replaces_sources=[EXTRA_LOG], staging_dir=case.folder)
    return case


def suggest_user(app, user):
    """A rule, named for the user, that suggests the user's logons suspicious."""
    api_rule(app, {"op": "add", "text": f"id: {user}-logons\nsuggest: suspicious\n"
                                        f"when: {{field: account, equals: 'c137\\{user}'}}\n"})


def search(p):
    p.locator("#search").fill(f"ip:{ADDRESS}")
    p.locator("#search").press("Enter")
    p.wait_for_selector("#details[data-page='search'] li.rel-row")
    return p.locator(SEARCH_HEAD)


def row(p, text):
    """The search list's rows that hold this text, as the event cell shows it."""
    return p.locator("#details li.rel-row").filter(has_text=text)


def rows_tagged(p, n):
    """Wait until this many rows of the list say they have a pending suggestion."""
    p.wait_for_function("(n) => [...document.querySelectorAll('#details li.rel-row .tag')]"
                        ".filter((t) => t.textContent.startsWith('suggests')).length === n", arg=n)


def status_says(p, text):
    """Wait until the status line holds this text."""
    p.wait_for_function("(text) => document.querySelector('#status').textContent.includes(text)", arg=text)


def test_a_search_list_offers_every_verdict_in_the_header_s_order_and_colors(browser, synthetic_case):  # noqa: F811
    """With nothing ticked the four marks show without a count and no reject. A ticked event with no pending suggestion
    brings no reject; a ticked event with one brings it, with the line saying what it does."""
    add_logons(synthetic_case, ann=1, zed=1)
    for p in served_page(browser, synthetic_case, setup=lambda app: suggest_user(app, "zed")):
        head = search(p)
        marks = head.locator("button[class*='mark-']")
        assert marks.all_inner_texts() == ["Mark Malicious", "Mark Suspicious", "Mark Authorized", "Set to Unreviewed"]
        assert [marks.nth(i).get_attribute("class") for i in range(4)] == [f"mark-{m.lower()}" for m in HEAD_MARKS]
        assert head.get_by_role("button", name="Reject").count() == 0
        head.get_by_role("button", name="Mark Authorized").click()   # nothing ticked: it says so and writes nothing
        status_says(p, "Tick the events to mark first.")
        row(p, "logon by ann").locator("input").click()
        assert marks.all_inner_texts() == ["Mark 1 Malicious", "Mark 1 Suspicious", "Mark 1 Authorized", "Set 1 to Unreviewed"]
        assert head.get_by_role("button", name="Reject").count() == 0 and head.locator(".list-hint").count() == 0
        row(p, "logon by zed").locator("input").click()
        assert marks.all_inner_texts() == ["Mark 2 Malicious", "Mark 2 Suspicious", "Mark 2 Authorized", "Set 2 to Unreviewed"]
        assert head.get_by_role("button", name="Reject 1 suggestion", exact=True).is_visible()
        assert head.locator(".list-hint").inner_text() == ("Reject leaves them unreviewed and stops their sources suggesting "
                                                           "them; the Event page can restore a rejected suggestion.")


def test_authorized_and_unreviewed_write_their_marks_from_a_list(browser, synthetic_case):  # noqa: F811
    add_logons(synthetic_case, ann=2)
    for p in served_page(browser, synthetic_case):
        head = search(p)
        for box in row(p, "logon by ann").locator("input").all():
            box.click()
        head.locator(".mark-note").fill("Change window")
        head.get_by_role("button", name="Mark 2 Authorized").click()
        p.wait_for_function("() => document.querySelectorAll('#details li.rel-row .badge.a').length === 2")
        entry = entries(synthetic_case)[-1]
        assert (entry["action"], entry["value"], entry["note"]) == ("mark", "authorized", "Change window")
        assert len(entry["targets"]) == 2
        assert p.locator("#details li.rel-row input:checked").count() == 0
        for box in row(p, "logon by ann").locator("input").all():
            box.click()
        head.get_by_role("button", name="Set 2 to Unreviewed").click()
        p.wait_for_function("() => document.querySelectorAll('#details li.rel-row .badge.a').length === 0")
        entry = entries(synthetic_case)[-1]
        assert (entry["action"], entry["value"], len(entry["targets"])) == ("mark", "unreviewed", 2)
        status_says(p, "Set 2 events back to Unreviewed")


def test_reject_suggestions_clears_the_ticked_events_suggestions(browser, synthetic_case):  # noqa: F811
    """The request names only the ticked events with a suggestion. They stay Unreviewed, an unticked event keeps its
    suggestion, a ticked event with none keeps its tick for a mark, and the status line says what happened."""
    add_logons(synthetic_case, ann=1, zed=3)
    for p in served_page(browser, synthetic_case, setup=lambda app: suggest_user(app, "zed")):
        head = search(p)
        rows_tagged(p, 3)
        row(p, "logon by ann").locator("input").click()
        zeds = row(p, "logon by zed")
        wanted = [zeds.nth(i).get_attribute("data-uid") for i in range(2)]
        for uid in wanted:
            p.locator(f"#details li.rel-row[data-uid='{uid}'] input").click()
        head.locator(".mark-note").fill("A known scanner")
        before = len(entries(synthetic_case))
        with p.expect_response("**/api/reject_ticked") as got:
            head.get_by_role("button", name="Reject 2 suggestions").click()
        body = json.loads(got.value.request.post_data)
        assert sorted(body["uids"]) == sorted(wanted) and "confirmed" not in body
        rows_tagged(p, 1)
        made = entries(synthetic_case)[before:]
        assert [(e["action"], e["source"], e["decision"], e["note"]) for e in made] == [
            ("suggestion_decision", "zed-logons", "rejected", "A known scanner")]
        assert sorted(made[0]["targets"]) == sorted(wanted)
        status_says(p, "Rejected suggestions on 2 events (zed-logons); they stay Unreviewed")
        assert all(p.locator(f"#details li.rel-row[data-uid='{uid}'] .badge.u").count() == 1 for uid in wanted)
        assert head.get_by_role("button", name="Mark 1 Authorized").count() == 1   # the ticked event with no suggestion
        assert head.get_by_role("button", name="Reject").count() == 0
        assert head.locator(".mark-note").input_value() == ""


@pytest.mark.parametrize("act", [
    pytest.param(lambda button: button.evaluate("(b) => { b.click(); b.click(); }"), id="two clicks"),
    pytest.param(lambda button: button.dblclick(), id="a double click"),
])
def test_a_second_click_on_reject_waits_for_the_first_answer(browser, synthetic_case, act):  # noqa: F811
    """With the first request's answer held, neither a second click nor a click on the button a tick then draws sends
    another: the server would skip every event, and its answer would replace the first's on the status line."""
    add_logons(synthetic_case, zed=3)
    for p in served_page(browser, synthetic_case, setup=lambda app: suggest_user(app, "zed")):
        head = search(p)
        rows_tagged(p, 3)
        zeds = row(p, "logon by zed")
        last = zeds.nth(2).get_attribute("data-uid")
        for i in range(2):
            zeds.nth(i).locator("input").click()
        before = len(entries(synthetic_case))
        sent, held = [], []
        p.on("request", lambda req: sent.append(req.url) if "/api/reject_ticked" in req.url else None)  # noqa: B023
        p.route("**/api/reject_ticked", lambda route: held.append(route))  # noqa: B023
        reject = head.get_by_role("button", name="Reject 2 suggestions")
        act(reject)
        p.wait_for_function("() => [...document.querySelectorAll('#details .sticky-head button')]"
                            ".some((b) => b.textContent === 'Reject 2 suggestions' && b.disabled)")
        p.locator(f"#details li.rel-row[data-uid='{last}'] input").click()   # draws the button again, on
        head.get_by_role("button", name="Reject 3 suggestions").click()
        assert len(sent) == 1
        held[0].continue_()
        status_says(p, "Rejected suggestions on 2 events (zed-logons); they stay Unreviewed")
        rows_tagged(p, 1)
        assert len(sent) == 1 and len(entries(synthetic_case)) == before + 1
        head.get_by_role("button", name="Reject 1 suggestion", exact=True).wait_for()   # the later tick stays


def test_a_refused_reject_leaves_the_button_on_with_the_ticks_for_another_try(browser, synthetic_case):  # noqa: F811
    add_logons(synthetic_case, zed=2)
    for p in served_page(browser, synthetic_case, setup=lambda app: suggest_user(app, "zed")):
        head = search(p)
        for box in row(p, "logon by zed").locator("input").all():
            box.click()
        before = len(entries(synthetic_case))
        refuse = lambda route: route.fulfill(status=400, json={"error": "the disk is full"})
        p.route("**/api/reject_ticked", refuse)
        reject = head.get_by_role("button", name="Reject 2 suggestions")
        reject.click()
        status_says(p, "Suggestion change failed: the disk is full")
        p.errors.clear()
        p.unroute("**/api/reject_ticked", refuse)
        assert reject.is_enabled() and len(entries(synthetic_case)) == before
        with p.expect_response("**/api/reject_ticked"):
            reject.click()
        rows_tagged(p, 0)


def test_an_event_decided_after_the_list_drew_is_skipped_and_named_on_the_status_line(browser, synthetic_case):  # noqa: F811
    add_logons(synthetic_case, zed=2)
    for p in served_page(browser, synthetic_case, setup=lambda app: suggest_user(app, "zed")):
        head = search(p)
        rows_tagged(p, 2)
        first = row(p, "logon by zed").first.get_attribute("data-uid")
        for box in row(p, "logon by zed").locator("input").all():
            box.click()
        api_mark(p.hub.app, {"uids": [first], "value": "authorized", "note": ""})
        with p.expect_response("**/api/reject_ticked"):
            head.get_by_role("button", name="Reject 2 suggestions").click()
        status_says(p, "Rejected suggestions on 1 event (zed-logons); it stays Unreviewed, 1 event skipped as decided meanwhile")
        assert first not in entries(synthetic_case)[-1]["targets"]


def test_reject_suggestions_asks_first_above_25_events_only(browser, synthetic_case):  # noqa: F811
    """Above 25 events it asks with the hand-picked question, which counts no unticked pending event as one that arrived
    after the page loaded. Cancel writes nothing, and the ticks stay. At 25 it acts at once."""
    add_logons(synthetic_case, zed=26, ann=25)

    def rules(app):
        suggest_user(app, "zed")
        suggest_user(app, "ann")

    for p in served_page(browser, synthetic_case, setup=rules):
        details = p.locator("#details")
        head = search(p)
        find = head.locator(".find input")
        find.fill("zed")
        head.get_by_role("button", name="Select the 26 shown").click()
        before = len(entries(synthetic_case))
        head.get_by_role("button", name="Reject 26 suggestions").click()
        block = details.locator(".confirm-block")
        block.wait_for()
        assert block.locator(".confirm-title").inner_text() == "Reject the suggestions on 26 events?"
        assert block.locator(".confirm-line").inner_text() == "A selection of 26 events you picked by hand."
        assert block.locator(".confirm-points li").all_inner_texts() == [
            "All 26 stay Unreviewed, and their sources stop suggesting them.",
            "The journal records one entry for each source, listing its events, with your name and the time."]
        assert block.locator(".confirm-warn").count() == 0   # ann's 25 pending events are not called new arrivals
        assert block.locator(".actions button").all_inner_texts() == ["Reject 26", "Cancel"]
        block.get_by_role("button", name="Cancel").click()
        p.wait_for_selector("#details .confirm-block", state="detached")
        assert len(entries(synthetic_case)) == before
        assert head.get_by_role("button", name="Reject 26 suggestions").count() == 1   # the ticks stay for another try
        head.get_by_role("button", name="Reject 26 suggestions").click()
        block.wait_for()
        with p.expect_response("**/api/reject_ticked") as got:
            block.get_by_role("button", name="Reject 26", exact=True).click()
        assert json.loads(got.value.request.post_data)["confirmed"] == {"count": 26}
        rows_tagged(p, 25)
        entry = entries(synthetic_case)[-1]
        assert entry["confirmed"] == {"count": 26, "skipped": 0} and len(entry["targets"]) == 26
        # 25 asks nothing
        find.fill("ann")
        head.get_by_role("button", name="Select the 25 shown").click()
        with p.expect_response("**/api/reject_ticked") as got:
            head.get_by_role("button", name="Reject 25 suggestions").click()
        assert "confirmed" not in json.loads(got.value.request.post_data)
        rows_tagged(p, 0)
        assert details.locator(".confirm-block").count() == 0 and "confirmed" not in entries(synthetic_case)[-1]


def test_a_tick_in_a_list_under_the_results_counts_for_the_head_s_reject(browser, synthetic_case):  # noqa: F811
    """A search's by-name list shares the results' ticks and has no buttons of its own, so its pending event brings the
    Reject to the head above."""
    probe_case(synthetic_case)
    for p in served_page(browser, synthetic_case):
        p.locator("#search").fill("internet")
        p.locator("#search").press("Enter")
        p.wait_for_selector("#searchByName li.rel-row")
        head = p.locator(SEARCH_HEAD)
        assert head.get_by_role("button", name="Reject").count() == 0
        p.locator("#searchByName li.rel-row input").first.click()
        with p.expect_response("**/api/reject_ticked"):
            head.get_by_role("button", name="Reject 1 suggestion", exact=True).click()
        status_says(p, "(hayabusa)")
        head.get_by_role("button", name="Reject").wait_for(state="detached")


# The head's controls that pass the panel's right edge or, for a button, clip their words
SPILLS = """(head) => {
  const edge = document.getElementById('detailsBody').getBoundingClientRect().right;
  const parts = [...head.querySelectorAll('button, input, strong, .list-hint')].filter((n) => n.getClientRects().length);
  return parts.filter((n) => n.getBoundingClientRect().right > edge + 1
                             || (n.tagName === 'BUTTON' && n.scrollWidth > n.clientWidth + 1)).map((n) => n.textContent);
}"""


def test_a_narrowed_pivot_list_on_the_event_page_offers_what_the_header_offers(browser, synthetic_case):  # noqa: F811
    """From an event with a pending suggestion, a pivot's list, narrowed by its find and ticked, offers the marks and the
    reject, and its head fits its column: nothing passes the panel's right edge."""
    add_logons(synthetic_case, zed=4)
    for p in served_page(browser, synthetic_case, setup=lambda app: suggest_user(app, "zed")):
        search(p)
        row(p, "logon by zed").first.locator(".rel-text").click()
        p.wait_for_selector("#details[data-page='event'] button.pv-go")
        p.locator("#details button.pv-go").first.click()
        p.wait_for_selector("#relatedList li.rel-row")
        head = p.locator("#relatedList .sticky-head")
        head.locator(".find input").fill("by zed")
        head.get_by_role("button", name="Select the 4 shown").click()
        head.get_by_role("button", name="Reject 4 suggestions").wait_for()
        names = head.locator("button").all_inner_texts()
        assert [name for name in names if name.split()[0] in ("Mark", "Set", "Reject")] == [
            "Mark 4 Malicious", "Mark 4 Suspicious", "Mark 4 Authorized", "Set 4 to Unreviewed", "Reject 4 suggestions"]
        assert head.evaluate(SPILLS) == []
        with p.expect_response("**/api/reject_ticked") as got:
            head.get_by_role("button", name="Reject 4 suggestions").click()
        # Read from the answer and the journal: the window's motion from the row's click can end after the answer, and its
        # "Window moved" then replaces the status line
        assert got.value.json()["changed"] == 4
        entry = entries(synthetic_case)[-1]
        assert (entry["action"], entry["source"], entry["decision"]) == ("suggestion_decision", "zed-logons", "rejected")
        assert len(entry["targets"]) == 4
        head.get_by_role("button", name="Reject").wait_for(state="detached")


@pytest.mark.parametrize("width", [1400, 1280, 961, 960, 800])
def test_the_head_of_a_search_list_holds_every_action_at_each_width(browser, synthetic_case, width):  # noqa: F811
    """With all five actions showing, each control of a search list's head is whole on screen, and the note box shows its
    placeholder."""
    add_logons(synthetic_case, zed=3, ann=1)
    for p in served_page(browser, synthetic_case, setup=lambda app: suggest_user(app, "zed")):
        p.set_viewport_size({"width": width, "height": 900})
        head = search(p)
        row(p, "logon by zed").first.locator("input").click()
        head.get_by_role("button", name="Reject 1 suggestion", exact=True).wait_for()
        assert head.evaluate(SPILLS) == []
        note = head.locator(".mark-note")
        assert note.evaluate(PLACEHOLDER_FITS) and note.evaluate(NARROWEST_FITS)
