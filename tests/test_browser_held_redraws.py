"""A page's redraw after an action, in a real browser, when it can't run as the action answers. A question open on the
page holds the redraw, which would take the question away, and so does a question opened while the redraw's read is
out; the page draws once the question has left it, however it left. A refusal asks nothing and holds nothing. A list
whose tag answers while its Event page is left or still loading is read again when the page draws, as the page draws
the list from the rows it kept, and only while the page still shows that list: another list opened in its place stays.
They drive the installed Microsoft Edge through Playwright, as test_browser_smoke does, and are skipped without it."""

import re

import pytest
from conftest import SEC, T0, logon
from test_browser_findings import uid_at
from test_browser_investigate import INVESTIGATE, open_worklist
from test_browser_page_guards import (
    LATERAL_MOVEMENT,
    SHOWN,
    TAKEN,
    VIEW_ON,
    Held,
    add_logons,
    open_suggestions,
    search_4624,
    settled,
    tag_lateral_movement,
)
from test_browser_pivots import STEP_TEXTS, pv, select, uid
from test_browser_smoke import RECORD_REQUESTS, asked, browser, case_menu, served_page, wait_held  # noqa: F401
from test_pivots import INSTALL, RDP, pcase, pcase_events  # noqa: F401

from glessner import server
from glessner.events import load
from glessner.server import api_mark

pytestmark = pytest.mark.browser
EXTRA_LOG = "DC01/Windows/System32/winevt/Logs/Extra.evtx"
# The tag on a list's row whose event the View hides
HIDDEN = re.compile(r"^hidden")


@pytest.fixture
def many_logons(synthetic_case):
    """Thirty more logons on DC01, so a search for code:4624 lists more events than a mark of hand-picked events makes
    without asking first."""
    events = [logon(T0 + (120 + i) * SEC, 300 + i, EXTRA_LOG, user=f"user{i}", ltype="3", ip="10.42.85.115")
              for i in range(30)]
    load(synthetic_case.db_path, events, host="DC01", tool="evtxecmd", tool_version="t", run_id="more",
         replaces_sources=[EXTRA_LOG], staging_dir=synthetic_case.folder)
    return synthetic_case


def hidden(row):
    return any(HIDDEN.match(t) for t in row.locator(".tag").all_inner_texts())


def search_with_the_view_on(p, found):
    """Turn the View on Lateral Movement and search for code:4624. Returns the search's page and the row of `found`'s
    event, which the View hides."""
    p.evaluate("(v) => import('/js/view.js').then((m) => m.addViewValue(v))", LATERAL_MOVEMENT)
    p.wait_for_function(VIEW_ON)
    details = search_4624(p)
    row = details.locator(f"li.rel-row[data-uid='{found['uid']}']")
    row.wait_for()
    assert hidden(row)
    return details, row


def ask_to_mark_every_row(details, listed=None):
    """Tick every row of a list on the page, `listed`, or the search's list, and ask to mark them Malicious, which asks
    first. Returns the question."""
    listed = listed or details
    listed.get_by_role("button", name="Select all").click()
    listed.get_by_role("button", name=re.compile(r"^Mark \d+ Malicious$")).click()
    block = details.locator(".confirm-block")
    block.wait_for()
    return block


def test_a_redraw_held_for_a_question_runs_once_a_tick_draws_the_list_over_it(browser, many_logons):  # noqa: F811
    """With the View on Lateral Movement, a search's row hidden by the View is tagged from the list, and while the tag is
    out the analyst ticks every row and asks to mark them. The tag's answer leaves the question open and the list as it
    was. A tick then draws the list again, without the question, and the search reads its rows again, so the tagged row
    is no longer hidden."""
    found = {}
    for p in served_page(browser, many_logons, setup=lambda app: found.update(uid=uid_at(app, T0 + 874 * SEC))):
        details, row = search_with_the_view_on(p, found)
        row.locator("input").check()
        p.evaluate(RECORD_REQUESTS)
        tagging = Held(p, "/api/tag")
        tag_lateral_movement(p, details)
        wait_held(p, tagging.routes)
        block = ask_to_mark_every_row(details)
        tagging.release()
        p.wait_for_function(TAKEN, arg="/api/tag")
        settled(p)
        assert block.count() == 1 and asked(p, "/api/search?") == [] and hidden(row)
        details.locator(f"li.rel-row:not([data-uid='{found['uid']}']) input").first.uncheck()
        settled(p)
        assert block.count() == 0 and len(asked(p, "/api/search?")) == 1
        assert p.evaluate(SHOWN) == "search" and not hidden(row)


def test_a_question_opened_while_a_lists_redraw_reads_stays_until_it_closes(browser, many_logons):  # noqa: F811
    """With the View on Lateral Movement, a search's row hidden by the View is tagged from the list, and the search reads
    its rows again to draw the tag. While that read is out the analyst ticks every row and asks to mark them. The read's
    answer leaves the question open. Cancel closes it, and the search then reads its rows and draws, with the tagged row
    no longer hidden."""
    found = {}
    for p in served_page(browser, many_logons, setup=lambda app: found.update(uid=uid_at(app, T0 + 874 * SEC))):
        details, row = search_with_the_view_on(p, found)
        row.locator("input").check()
        p.evaluate(RECORD_REQUESTS)
        reading = Held(p, "/api/search")
        tag_lateral_movement(p, details)
        wait_held(p, reading.routes)
        block = ask_to_mark_every_row(details)
        reading.release()
        p.wait_for_function(TAKEN, arg="/api/search")
        settled(p)
        assert block.count() == 1 and hidden(row)
        block.get_by_role("button", name="Cancel").click()
        settled(p)
        assert block.count() == 0 and len(asked(p, "/api/search?")) == 2
        assert p.evaluate(SHOWN) == "search" and not hidden(row)


def test_a_question_opened_while_a_follow_ups_redraw_reads_stays_until_it_closes(browser, synthetic_case):  # noqa: F811
    """On To investigate, the Followed up tick answers, and the worklist reads itself again to draw it. While that read is
    out the analyst asks to accept all of the logons rule's suggestions. The read's answer leaves the question open in
    the rule's row. Cancel closes it, and the worklist then draws the tick's Followed up line."""
    found = {}

    def setup(app):
        add_logons(app)
        found["uid"] = uid_at(app, T0 + 874 * SEC)
        api_mark(app, {"uids": [found["uid"]], "value": "suspicious"})

    for p in served_page(browser, synthetic_case, setup=setup):
        open_worklist(p)
        details = p.locator(INVESTIGATE)
        followed = details.locator(f"li.rel-row[data-uid='{found['uid']}'] .inv-followed")
        p.evaluate(RECORD_REQUESTS)
        reading = Held(p, "/api/investigate")
        details.locator(f"li.rel-row[data-uid='{found['uid']}'] input.inv-tick").check()
        wait_held(p, reading.routes)
        rule = details.locator(".rule[data-source='logons']")
        rule.get_by_role("button", name="Accept all").click()
        block = rule.locator(".confirm-block")
        block.wait_for()
        reading.release()
        p.wait_for_function(TAKEN, arg="/api/investigate")
        settled(p)
        assert block.count() == 1 and followed.count() == 0
        block.get_by_role("button", name="Cancel").click()
        followed.wait_for()
        settled(p)
        assert p.locator("#details .confirm-block").count() == 0
        assert len(asked(p, "/api/investigate")) == 2


def test_a_question_opened_while_a_searchs_redraw_after_a_mark_reads_stays_until_it_closes(browser, many_logons):  # noqa: F811
    """A search's row is marked Suspicious from its list, and the search reads its rows again to draw the mark. While
    that read is out the analyst ticks every row and asks to mark them Malicious. The read's answer leaves the question
    open. Cancel closes it, and the search then reads its rows and draws, with the row marked."""
    found = {}
    for p in served_page(browser, many_logons, setup=lambda app: found.update(uid=uid_at(app, T0 + 874 * SEC))):
        details = search_4624(p)
        row = details.locator(f"li.rel-row[data-uid='{found['uid']}']")
        row.locator("input").check()
        p.evaluate(RECORD_REQUESTS)
        reading = Held(p, "/api/search")
        details.get_by_role("button", name="Mark 1 Suspicious").click()
        wait_held(p, reading.routes)
        block = ask_to_mark_every_row(details)
        reading.release()
        p.wait_for_function(TAKEN, arg="/api/search")
        settled(p)
        assert block.count() == 1 and len(asked(p, "/api/search?")) == 1
        block.get_by_role("button", name="Cancel").click()
        settled(p)
        assert block.count() == 0 and len(asked(p, "/api/search?")) == 2
        assert p.evaluate(SHOWN) == "search" and row.locator(".badge").inner_text() == "S"


def test_a_question_opened_while_a_host_changes_redraw_reads_stays_until_it_closes(browser, many_logons):  # noqa: F811
    """An offset on DC01 applies while a DC01 logon's Event page shows, and the page reads the event again to show its
    time with the offset. While that read is out the analyst ticks every row of the logon's Same host within the window
    list and asks to mark them. The read's answer leaves the question open. Cancel closes it, and the page then reads the
    event again and draws its time with the offset."""
    found = {}
    for p in served_page(browser, many_logons, setup=lambda app: found.update(uid=uid_at(app, T0 + 60 * SEC))):
        select(p, found["uid"])
        before = p.evaluate("window.__app.S.focusEvent.adjusted")
        pv(p, "window").locator("button.pv-go").click()
        listed = p.locator("#relatedList")
        listed.locator("li.rel-row").first.wait_for()
        case_menu(p, "hostsButton")
        p.evaluate(RECORD_REQUESTS)
        reading = Held(p, "/api/event")
        offset = p.locator("#hostsTable tr[data-host='DC01'] input[type=number]")
        offset.fill("60")
        offset.press("Enter")
        wait_held(p, reading.routes)
        block = ask_to_mark_every_row(p.locator("#details"), listed)
        reading.release()
        p.wait_for_function(TAKEN, arg="/api/event")
        settled(p)
        assert block.count() == 1 and len(asked(p, "/api/event?")) == 1
        block.get_by_role("button", name="Cancel").click()
        settled(p)
        assert block.count() == 0 and len(asked(p, "/api/event?")) == 2
        assert p.evaluate(SHOWN) == "event"
        assert p.evaluate("window.__app.S.focusEvent.adjusted") == before + 60 * SEC


def test_a_refusal_left_open_holds_no_redraw(browser, synthetic_case, monkeypatch):  # noqa: F811
    """A refusal asks nothing, so it holds no redraw. With a mark limited to one event, Accept all on the logons rule's
    Suggestions page shows a refusal in place of its question. An event's Accept made while the refusal is open draws the
    page again, without the accepted event."""
    monkeypatch.setattr(server, "MAX_MARK_TARGETS", 1)
    for p in served_page(browser, synthetic_case, setup=add_logons):
        open_suggestions(p, "logons")
        details = p.locator("#details")
        rows = details.locator(".sg-events li")
        listed = rows.count()
        details.get_by_role("button", name="Accept all").click()
        details.locator(".confirm-block[role='alert']").wait_for()
        p.evaluate(RECORD_REQUESTS)
        rows.first.get_by_role("button", name="Accept", exact=True).click()
        p.wait_for_function(TAKEN, arg="/api/suggestion")
        settled(p)
        assert len(asked(p, "/api/pending?")) == 1
        assert rows.count() == listed - 1


def tag_the_sessions_4672(p, rdp):
    """With the View on Lateral Movement, open the Same logon session list of the RDP logon, `rdp`, tick the session's
    4672, which the View hides, and tag it Lateral Movement from the list. The tag is held. Returns the tag's hold and
    the row's locator."""
    p.evaluate("(v) => import('/js/view.js').then((m) => m.addViewValue(v))", LATERAL_MOVEMENT)
    p.wait_for_function(VIEW_ON)
    select(p, rdp)
    pv(p, "session").locator("button.pv-go").click()
    listed = p.locator("#relatedList")
    row = listed.locator("li.rel-row", has_text="4672")
    row.wait_for()
    assert hidden(row)
    row.locator("input").check()
    p.evaluate(RECORD_REQUESTS)
    tagging = Held(p, "/api/tag")
    tag_lateral_movement(p, listed)
    wait_held(p, tagging.routes)
    return tagging, row


def open_rules(p):
    case_menu(p, "rulesButton")
    p.wait_for_selector("#details[data-page='rules']")


def tag_the_sessions_4672_then_open_rules(p, rdp):
    """Tag the session's 4672 as tag_the_sessions_4672 does, and open Rules while the tag is out. Returns the tag's hold
    and the row's locator."""
    tagging, row = tag_the_sessions_4672(p, rdp)
    open_rules(p)
    return tagging, row


def test_an_event_page_opened_again_before_its_lists_tag_answers_reads_the_list_again(browser, pcase):  # noqa: F811
    """The session's 4672 is tagged from the RDP logon's list, and while the tag is out the analyst opens Rules and goes
    back to the Event page, which draws its list from the rows it kept. When the tag answers, the list is read again,
    and the row is no longer hidden."""
    rdp = uid(pcase, RDP)
    for p in served_page(browser, pcase):
        tagging, row = tag_the_sessions_4672_then_open_rules(p, rdp)
        p.locator("#detailsBand button.back").click()
        row.wait_for()
        settled(p, "/api/tag")
        assert hidden(row)
        tagging.release()
        p.wait_for_function(TAKEN, arg="/api/tag")
        settled(p)
        assert p.evaluate(SHOWN) == "event" and len(asked(p, "/api/related?")) == 1
        assert not hidden(row)


def test_an_event_page_still_loading_when_its_lists_tag_answers_reads_the_list_again(browser, pcase):  # noqa: F811
    """The session's 4672 is tagged from the RDP logon's list, and while the tag is out the analyst opens Rules and goes
    back to the Event page, whose read is held until the tag has answered. The page draws its list from the rows it
    kept, then reads the list again, not the event, and the row is no longer hidden."""
    rdp = uid(pcase, RDP)
    for p in served_page(browser, pcase):
        tagging, row = tag_the_sessions_4672_then_open_rules(p, rdp)
        reading = Held(p, "/api/event")
        p.locator("#detailsBand button.back").click()
        wait_held(p, reading.routes)
        tagging.release()
        p.wait_for_function(TAKEN, arg="/api/tag")
        settled(p, "/api/event")
        reading.release()
        p.wait_for_function(TAKEN, arg="/api/event")
        settled(p)
        assert p.evaluate(SHOWN) == "event" and len(asked(p, "/api/related?")) == 1
        assert len(asked(p, "/api/event?")) == 1
        assert not hidden(row)


def test_an_event_page_opened_again_after_its_lists_tag_answered_reads_the_list_again(browser, pcase):  # noqa: F811
    """The session's 4672 is tagged from the RDP logon's list, and the tag answers while the analyst is on Rules. Back to
    the Event page draws its list from the rows it kept, then reads the list again, and the row is no longer hidden."""
    rdp = uid(pcase, RDP)
    for p in served_page(browser, pcase):
        tagging, row = tag_the_sessions_4672_then_open_rules(p, rdp)
        tagging.release()
        p.wait_for_function(TAKEN, arg="/api/tag")
        settled(p)
        assert p.evaluate(SHOWN) == "rules" and asked(p, "/api/related?") == []
        p.locator("#detailsBand button.back").click()
        row.wait_for()
        settled(p)
        assert p.evaluate(SHOWN) == "event" and len(asked(p, "/api/related?")) == 1
        assert not hidden(row)


def test_a_lists_tag_that_answers_while_another_event_is_open_opens_no_list_on_its_event_page(browser, pcase):  # noqa: F811
    """The session's 4672 is tagged from the RDP logon's list, and while the tag is out the analyst opens the service
    install and its window list, where the tag answers. The RDP logon opened again draws as the analyst left it, with no
    list: the session's list isn't read again or opened, and the trail gains no step for it."""
    rdp, install = uid(pcase, RDP), uid(pcase, INSTALL)
    for p in served_page(browser, pcase):
        tagging, _ = tag_the_sessions_4672(p, rdp)
        select(p, install)
        pv(p, "window").locator("button.pv-go").click()
        p.locator("#relatedList li.rel-row").first.wait_for()
        tagging.release()
        p.wait_for_function(TAKEN, arg="/api/tag")
        settled(p)
        assert len(asked(p, "/api/related?")) == 1
        select(p, rdp)
        settled(p)
        assert p.evaluate(SHOWN) == "event" and len(asked(p, "/api/related?")) == 1
        assert p.locator("#relatedList strong").count() == 0
        assert not any(step.startswith("Same logon session") for step in p.evaluate(STEP_TEXTS))


@pytest.mark.parametrize("left", [False, True], ids=["stayed", "left_for_rules"])
def test_a_lists_tag_that_answers_after_another_list_was_opened_on_its_page_keeps_that_list(browser, pcase, left):  # noqa: F811
    """The session's 4672 is tagged from the RDP logon's list, and while the tag is out the analyst opens the logon's
    window list in its place, on the page as it was or after leaving for Rules and coming back. When the tag answers,
    the window list stays, with its trail step, and the session's list isn't read again."""
    rdp = uid(pcase, RDP)
    for p in served_page(browser, pcase):
        tagging, row = tag_the_sessions_4672(p, rdp)
        if left:
            open_rules(p)
            p.locator("#detailsBand button.back").click()
            row.wait_for()
        pv(p, "window").locator("button.pv-go").click()
        p.locator("#relatedList strong", has_text="Same host within").wait_for()
        settled(p, "/api/tag")
        heads, steps = p.locator("#relatedList strong").all_inner_texts(), p.evaluate(STEP_TEXTS)
        reads = len(asked(p, "/api/related?"))
        tagging.release()
        p.wait_for_function(TAKEN, arg="/api/tag")
        settled(p)
        assert p.evaluate(SHOWN) == "event" and len(asked(p, "/api/related?")) == reads
        assert p.locator("#relatedList strong").all_inner_texts() == heads
        assert p.evaluate(STEP_TEXTS) == steps
        assert steps[-1].startswith("Same host within")


def test_a_lists_tag_that_answers_after_the_whole_window_was_opened_in_its_place_keeps_the_window(browser, pcase):  # noqa: F811
    """A 7036 is tagged from the service install's window list narrowed to 7036, and while the tag is out the analyst
    opens the whole window in its place. When the tag answers, the whole window's list stays, with its trail step, and
    the narrowed list isn't read again."""
    install = uid(pcase, INSTALL)
    for p in served_page(browser, pcase):
        select(p, install)
        window = pv(p, "window")
        window.locator("button.pv-source", has_text="7036").click()
        listed = p.locator("#relatedList")
        listed.locator("strong", has_text="only 7036").wait_for()
        listed.locator("li.rel-row input").first.check()
        p.evaluate(RECORD_REQUESTS)
        tagging = Held(p, "/api/tag")
        tag_lateral_movement(p, listed)
        wait_held(p, tagging.routes)
        window.locator("button.pv-go").click()
        listed.locator("strong", has_text="±600 s: ").wait_for()
        settled(p, "/api/tag")
        heads, steps = listed.locator("strong").all_inner_texts(), p.evaluate(STEP_TEXTS)
        tagging.release()
        p.wait_for_function(TAKEN, arg="/api/tag")
        settled(p)
        assert len(asked(p, "/api/related?")) == 1
        assert listed.locator("strong").all_inner_texts() == heads
        assert p.evaluate(STEP_TEXTS) == steps
