"""The ticks on a Suggestions group's rows, in a real browser: only the ticked rows are decided and stay dimmed and labeled;
the head's select button follows a find; a ticked decision asks first above 25 events, in the hand-picked words; ticks
survive a redraw and leave a row no longer pending; the whole-group buttons still cover every event counted; and a double
click sends one request. They drive the installed Microsoft Edge through Playwright, as test_browser_smoke does, and are
skipped without it."""

import dataclasses

import pytest
from conftest import SEC, T0, logon
from test_browser_list_verdicts import SPILLS, entries
from test_browser_page_guards import Held, HeldAnswer
from test_browser_smoke import browser, served_page, wait_held  # noqa: F401
from test_browser_suggestion_decisions import (
    DECIDED,
    apply_mark,
    decided_count,
    group_uids,
    read_again,
    rows,
    said,
    small_groups,  # noqa: F401
    texts,
)
from test_browser_suggestion_folds import (
    ANN,
    COUNT_IS,
    EXTRA_LOG,
    LISTED_IS,
    ZED,
    add_logons,
    cut_group,  # noqa: F401
    group,
    is_open,
    open_logons,
    suggest_logons,
)

from glessner.events import load
from glessner.queries import PENDING_LIMIT
from glessner.server import LISTED_EVENTS, api_pending_uids, api_rule, api_suggestion

pytestmark = pytest.mark.browser
HAND_PICKED = "A selection of {} events you picked by hand."
RULE_FOR_ANN = "id: logons\nsuggest: suspicious\nwhen: {field: account, equals: 'c137\\ann'}\n"


def head(p, key):
    return group(p, key).locator(".sg-head")


def tick(p, key, index):
    return rows(p, key).nth(index).locator("input[type=checkbox]")


def named(p, key, name):
    """The button in the group's head with exactly this name, which counts only while it shows."""
    return head(p, key).get_by_role("button", name=name, exact=True)


def ticked(p, key):
    """Which of the group's rows show a ticked box, by place."""
    return rows(p, key).evaluate_all(
        "(ns) => ns.flatMap((n, i) => (n.querySelector('input[type=checkbox]')?.checked ? [i] : []))")


def row_offset(p, key):
    """How far below its group's top the group's first row sits, which a click's scrolling doesn't change."""
    return rows(p, key).nth(0).evaluate(
        "(n) => n.getBoundingClientRect().top - n.closest('.sg-group').getBoundingClientRect().top")


def decide_ticked(p, key, name, left):
    """Press a ticked button that acts at once, wait until the page has drawn again with `left` pending in the group, and
    give the request's body."""
    with p.expect_request("**/api/suggestion") as sent:
        named(p, key, name).click()
    p.wait_for_function(COUNT_IS, arg=[key, f"{left} pending"])
    return sent.value.post_data_json


@pytest.fixture
def worded_logons(synthetic_case):
    """Five logons by zed: a find on "alpha" holds the first three rows, and on "beta" the last two."""
    events = [dataclasses.replace(logon(T0 + (120 + i) * SEC, 300 + i, EXTRA_LOG, user="zed", ltype="3", ip="10.42.85.115"),
                                  message=f"4624 logon {word}")
              for i, word in enumerate(["alpha", "alpha", "alpha", "beta", "beta"])]
    load(synthetic_case.db_path, events, host="DC01", tool="evtxecmd", tool_version="t", run_id="more",
         replaces_sources=[EXTRA_LOG], staging_dir=synthetic_case.folder)
    return synthetic_case


def test_two_ticked_and_rejected_are_the_only_ones_decided_and_stay_dimmed(browser, small_groups):  # noqa: F811
    """A click on a tick, or just off its box, ticks and opens nothing. Reject 2 ticked acts at once on those two: they stay
    in place, dimmed and labeled, with Restore and no tick, and the other two stay pending and unticked. The buttons go, and the
    whole-group buttons count what is left. The journal's entry names the two, and a click on a row still opens its event."""
    seen = {}

    def rule(app):
        suggest_logons(app)
        seen["uids"] = group_uids(app, ZED)

    for p in served_page(browser, small_groups, setup=rule):
        open_logons(p)
        before = texts(p, ZED)
        assert not named(p, ZED, "Reject 0 ticked").count()
        tick(p, ZED, 0).click()
        rows(p, ZED).nth(2).locator(".sg-tick").click(position={"x": 19, "y": 3})
        assert ticked(p, ZED) == [0, 2]
        assert p.locator("#details").get_attribute("data-page") == "suggestions"
        assert named(p, ZED, "Accept 2 ticked").is_visible() and named(p, ZED, "Accept 4").is_visible()
        assert named(p, ZED, "Reject 2 ticked").is_visible() and named(p, ZED, "Reject 4").is_visible()
        sent = decide_ticked(p, ZED, "Reject 2 ticked", 2)
        assert sent["uids"] == [seen["uids"][0], seen["uids"][2]] and "confirmed" not in sent
        said(p, "Rejected 2 logons suggestions; the events stay Unreviewed · ")
        assert texts(p, ZED) == before and decided_count(p, ZED) == 2
        for index in (0, 2):
            row = rows(p, ZED).nth(index)
            assert row.get_attribute("class") == "sg-decided"
            assert row.locator(".sg-decision").inner_text() == "Rejected, stays Unreviewed"
            assert row.get_by_role("button").all_inner_texts() == ["Restore"]
            assert row.locator("input").count() == 0
        for index in (1, 3):
            assert rows(p, ZED).nth(index).get_by_role("button").all_inner_texts() == ["Accept", "Reject"]
        assert ticked(p, ZED) == []
        assert named(p, ZED, "Reject 2").is_visible() and not named(p, ZED, "Reject 2 ticked").count()
        entry = entries(small_groups)[-1]
        assert sorted(entry["targets"]) == sorted([seen["uids"][0], seen["uids"][2]]) and entry["decision"] == "rejected"
        lefts = rows(p, ZED).locator(".sg-text").evaluate_all("(ns) => ns.map((n) => n.getBoundingClientRect().left)")
        assert lefts[0] == lefts[1]   # a decided row's text starts where a pending row's does
        rows(p, ZED).nth(1).locator(".sg-text").click()
        p.wait_for_selector("#details[data-page='event']")


def test_an_accept_of_ticks_labels_each_row_with_the_mark_the_server_gave(browser, small_groups):  # noqa: F811
    """The rule changes to suggest Malicious after the page listed its events as Suspicious. Accept 2 ticked marks the two,
    the rows name what the server gave, and a read that follows keeps them."""
    seen = {}

    def rule(app):
        suggest_logons(app)
        seen["app"] = app

    for p in served_page(browser, small_groups, setup=rule):
        open_logons(p)
        changed = "id: logons\nsuggest: malicious\nwhen: {field: event_code, equals: '4624'}\n"
        api_rule(seen["app"], {"op": "change", "text": changed})
        tick(p, ZED, 1).click()
        tick(p, ZED, 2).click()
        decide_ticked(p, ZED, "Accept 2 ticked", 2)
        said(p, "Accepted 2 logons suggestions as Malicious · ")
        read_again(p)
        p.wait_for_function(COUNT_IS, arg=[ZED, "2 pending"])
        assert rows(p, ZED).locator(".sg-decision").all_inner_texts() == ["Accepted as Malicious"] * 2
        assert rows(p, ZED).nth(1).get_attribute("class") == "sg-decided"
        assert rows(p, ZED).nth(2).get_attribute("class") == "sg-decided"


def test_the_select_button_follows_a_find_and_covers_only_the_rows_shown(browser, worded_logons):  # noqa: F811
    """A decided row the find shows isn't one to tick, so the button counts the pending rows shown. Select the 2 shown ticks
    only those, and a tick the find hides stays, counts for the buttons, and is named in the find's row. It reads Unselect once
    they are ticked. With no find it reads Select all, then Select none once all are ticked, and a find that shows no row
    has nothing to select."""
    for p in served_page(browser, worded_logons, setup=suggest_logons):
        open_logons(p)
        press = rows(p, ZED).nth(0).get_by_role("button", name="Reject", exact=True)
        with p.expect_response("**/api/suggestion"):
            press.click()
        p.wait_for_function(COUNT_IS, arg=[ZED, "4 pending"])
        tick(p, ZED, 3).click()
        find = head(p, ZED).locator(".find input")
        find.fill("alpha")
        select = named(p, ZED, "Select the 2 shown")
        assert head(p, ZED).locator(".find-ticks").inner_text() == "1 ticked event isn't shown here"
        assert named(p, ZED, "Reject 1 ticked").is_visible()
        select.click()
        assert ticked(p, ZED) == [1, 2, 3]
        assert named(p, ZED, "Reject 3 ticked").is_visible()
        named(p, ZED, "Unselect the 2 shown").click()
        assert ticked(p, ZED) == [3]
        find.fill("no such row")
        assert named(p, ZED, "Select the 0 shown").is_disabled()
        find.fill("alpha")
        select.click()
        find.fill("")
        assert head(p, ZED).locator(".find-ticks").is_hidden()
        assert ticked(p, ZED) == [1, 2, 3]
        named(p, ZED, "Select all").click()
        assert ticked(p, ZED) == [1, 2, 3, 4]
        named(p, ZED, "Select none").click()
        assert ticked(p, ZED) == []
        assert not named(p, ZED, "Accept 0 ticked").count()
        find.fill("alpha")
        select.click()
        sent = decide_ticked(p, ZED, "Reject 2 ticked", 2)
        assert len(sent["uids"]) == 2
        assert decided_count(p, ZED) == 3
        assert head(p, ZED).locator(".find input").input_value() == "alpha"


def test_a_ticked_decision_asks_above_25_in_the_hand_picked_words_and_not_at_25(browser, synthetic_case):  # noqa: F811
    """26 ticked: Reject 26 ticked asks, in the words of a hand-picked selection and not the group's, and sends nothing. Cancel
    keeps the ticks. A change of the ticks takes an open question away, since it stated other events. At 25 it acts at once,
    with no count of consent on the request."""
    add_logons(synthetic_case, ["zed"] * 26)
    sent = []
    for p in served_page(browser, synthetic_case, setup=suggest_logons):
        open_logons(p)
        p.on("request", lambda req: sent.append(req) if req.url.endswith("/api/suggestion") else None)
        named(p, ZED, "Select all").click()
        named(p, ZED, "Reject 26 ticked").click()
        block = group(p, ZED).locator(".confirm-block")
        assert block.locator(".confirm-title").inner_text() == "Reject 26 logons suggestions?"
        assert block.locator(".confirm-line").inner_text() == HAND_PICKED.format(26)
        assert block.locator(".confirm-points li").first.inner_text() == (
            "All 26 stay Unreviewed, and logons stops suggesting them.")
        assert "counted when this page loaded" not in block.inner_text()
        block.get_by_role("button", name="Cancel").click()
        assert block.count() == 0 and sent == []
        assert named(p, ZED, "Reject 26 ticked").is_visible()
        named(p, ZED, "Reject 26 ticked").click()
        block.wait_for()
        tick(p, ZED, 0).click()
        assert block.count() == 0 and sent == []
        body = decide_ticked(p, ZED, "Reject 25 ticked", 1)
        assert len(body["uids"]) == 25 and "confirmed" not in body
        assert block.count() == 0
        assert decided_count(p, ZED) == 25


def test_a_confirmed_ticked_decision_carries_its_count_and_dims_its_rows(browser, synthetic_case):  # noqa: F811
    """Accept 26 ticked asks with the mark in its words, and its lead button repeats the number. The request and the journal's
    entry carry the count the question stated, and all 26 rows stay, dimmed and labeled."""
    add_logons(synthetic_case, ["zed"] * 26)
    for p in served_page(browser, synthetic_case, setup=suggest_logons):
        open_logons(p)
        named(p, ZED, "Select all").click()
        named(p, ZED, "Accept 26 ticked").click()
        block = group(p, ZED).locator(".confirm-block")
        assert block.locator(".confirm-title").inner_text() == "Accept 26 logons suggestions?"
        assert block.locator(".confirm-points li").first.inner_text() == "All 26 are marked Suspicious."
        with p.expect_request("**/api/suggestion") as sent:
            block.get_by_role("button", name="Accept 26", exact=True).click()
        p.wait_for_function(COUNT_IS, arg=[ZED, "0 pending"])
        assert sent.value.post_data_json["confirmed"] == {"count": 26}
        assert entries(synthetic_case)[-1]["confirmed"] == {"count": 26, "skipped": 0}
        assert rows(p, ZED).locator(".sg-decision").all_inner_texts() == ["Accepted as Suspicious"] * 26


def test_ticks_survive_a_redraw_a_fold_and_a_find_and_regrouping_or_leaving_clears_them(browser, small_groups):  # noqa: F811
    """Ticks in two groups stay through another row's single decision, each in its own group. A ticked row decided on its own
    leaves the ticks. A fold and a find keep them. Changing Group by clears them, and going back draws none, and so does
    leaving the page and coming back."""
    for p in served_page(browser, small_groups, setup=suggest_logons):
        open_logons(p)
        tick(p, ZED, 0).click()
        tick(p, ZED, 2).click()
        tick(p, ANN, 0).click()
        with p.expect_response("**/api/suggestion"):
            rows(p, ZED).nth(1).get_by_role("button", name="Reject", exact=True).click()
        p.wait_for_function(COUNT_IS, arg=[ZED, "3 pending"])
        assert ticked(p, ZED) == [0, 2] and ticked(p, ANN) == [0]
        assert named(p, ZED, "Reject 2 ticked").is_visible() and named(p, ANN, "Reject 1 ticked").is_visible()
        with p.expect_response("**/api/suggestion"):
            rows(p, ZED).nth(2).get_by_role("button", name="Accept", exact=True).click()
        p.wait_for_function(COUNT_IS, arg=[ZED, "2 pending"])
        assert ticked(p, ZED) == [0] and named(p, ZED, "Reject 1 ticked").is_visible()
        arrow = head(p, ZED).locator(".twisty")
        arrow.click()
        assert not is_open(p, ZED) and named(p, ZED, "Reject 1 ticked").is_visible()
        arrow.click()
        assert is_open(p, ZED) and ticked(p, ZED) == [0]
        find = head(p, ZED).locator(".find input")
        find.fill("no such row")
        assert named(p, ZED, "Reject 1 ticked").is_visible()
        find.fill("")
        assert ticked(p, ZED) == [0]
        select = p.locator("#details .actions select")
        select.select_option("host")
        p.wait_for_selector("#details .sg-head strong:text-is('DC01')")
        assert p.locator("#details .sg-events input:checked").count() == 0
        select = p.locator("#details .actions select")
        select.select_option("account")
        p.wait_for_function(COUNT_IS, arg=[ZED, "2 pending"])
        assert p.locator("#details .sg-events input:checked").count() == 0
        assert not named(p, ZED, "Reject 1 ticked").count()
        tick(p, ZED, 0).click()
        rows(p, ANN).nth(0).locator(".sg-text").click()
        p.wait_for_selector("#details[data-page='event'] .ev-ident")
        p.locator("#detailsBand button.back").click()
        p.wait_for_selector("#details[data-page='suggestions'] .sg-group")
        assert p.locator("#details .sg-events input:checked").count() == 0


def test_a_read_takes_a_tick_off_a_row_no_longer_pending(browser, small_groups):  # noqa: F811
    """A mark made elsewhere takes its row's tick off at the page's next read, and the buttons count what is left. A rule that
    stops suggesting a group's events takes its ticks with it. What Reject N ticked sends then matches its count."""
    seen = {}

    def rule(app):
        suggest_logons(app)
        seen["app"] = app
        seen["uids"] = group_uids(app, ZED)
        seen["ann"] = group_uids(app, ANN)

    for p in served_page(browser, small_groups, setup=rule):
        open_logons(p)
        for index in (0, 1, 2):
            tick(p, ZED, index).click()
        tick(p, ANN, 0).click()
        apply_mark(p, "Malicious", seen["uids"][0])
        read_again(p)
        p.wait_for_function(COUNT_IS, arg=[ZED, "3 pending"])
        assert ticked(p, ZED) == [0, 1]
        assert named(p, ZED, "Reject 2 ticked").is_visible()
        api_rule(seen["app"], {"op": "change", "text": RULE_FOR_ANN})
        read_again(p)
        p.wait_for_function("(key) => ![...document.querySelectorAll('#details .sg-head strong')]"
                            ".some((n) => n.textContent === key)", arg=ZED)
        assert named(p, ANN, "Reject 1 ticked").is_visible()
        assert decide_ticked(p, ANN, "Reject 1 ticked", 0)["uids"] == seen["ann"]


def test_a_tick_on_an_event_marked_since_the_last_read_gets_no_false_label(browser, small_groups):  # noqa: F811
    """A mark from the timeline draws no Suggestions page, so the tick still shows and is sent. The server skips that event,
    and the status line says so. The redraw's read drops that row, and the other stays dimmed and labeled, with no tick left
    on either."""
    seen = {}

    def rule(app):
        suggest_logons(app)
        seen["uids"] = group_uids(app, ZED)

    for p in served_page(browser, small_groups, setup=rule):
        open_logons(p)
        before = texts(p, ZED)
        tick(p, ZED, 0).click()
        tick(p, ZED, 1).click()
        apply_mark(p, "Malicious", seen["uids"][0])
        said(p, "Marked")
        assert named(p, ZED, "Reject 2 ticked").is_visible()
        decide_ticked(p, ZED, "Reject 2 ticked", 2)
        said(p, "Rejected 1 logons suggestion; the event stays Unreviewed. 1 skipped as decided meanwhile")
        p.wait_for_function("(key) => [...document.querySelectorAll('#details .sg-group')].some((g) => "
                            "g.querySelector('.sg-head strong').textContent === key "
                            "&& g.querySelectorAll('.sg-events li').length === 3)", arg=ZED)
        assert texts(p, ZED) == before[1:]
        assert rows(p, ZED).nth(0).locator(".sg-decision").inner_text() == "Rejected, stays Unreviewed"
        assert ticked(p, ZED) == []
        assert entries(small_groups)[-1]["targets"] == [seen["uids"][1]]


@pytest.mark.parametrize(("name", "line", "left_rows"), [
    ("Accept 3 ticked", "Accepted 1 logons suggestion as Suspicious. 2 skipped as decided meanwhile", [0, 2, 3]),
    ("Reject 3 ticked", "Rejected 1 logons suggestion; the event stays Unreviewed. 2 skipped as decided meanwhile", [1, 2, 3]),
], ids=["accept", "reject"])
def test_ticks_decided_elsewhere_are_skipped_and_the_journal_names_only_the_rest(browser, small_groups, name, line, left_rows):  # noqa: F811
    """Another tab accepts one ticked row and rejects another, which draws no page here. The button still counts three, but the
    server acts on and journals only the third, and the status line says the other two were skipped. All three leave the
    ticks. At the redraw's read a row whose label would be false has left the page, and one whose label is true stays."""
    seen = {}

    def rule(app):
        suggest_logons(app)
        seen["app"] = app
        seen["uids"] = group_uids(app, ZED)

    for p in served_page(browser, small_groups, setup=rule):
        open_logons(p)
        before = texts(p, ZED)
        for index in (0, 1, 2):
            tick(p, ZED, index).click()
        accepted, rejected, third, _ = seen["uids"]
        api_suggestion(seen["app"], {"decision": "accept", "source": "logons", "uids": [accepted]})
        api_suggestion(seen["app"], {"decision": "reject", "source": "logons", "uids": [rejected]})
        with p.expect_response("**/api/suggestion") as answered:
            named(p, ZED, name).click()
        said(p, line)
        answer = answered.value.json()
        assert (answer["changed"], answer["skipped"]) == (1, 2)
        assert entries(small_groups)[-1]["targets"] == [third]
        p.wait_for_function(COUNT_IS, arg=[ZED, "1 pending"])
        p.wait_for_function("([key, n]) => [...document.querySelectorAll('#details .sg-group')].some((g) => "
                            "g.querySelector('.sg-head strong').textContent === key "
                            "&& g.querySelectorAll('.sg-events li').length === n)", arg=[ZED, 3])
        assert texts(p, ZED) == [before[index] for index in left_rows]
        assert ticked(p, ZED) == []
        assert not named(p, ZED, name).count()


@pytest.mark.parametrize(("name", "line"), [
    ("Accept 2 ticked", "Accepted no logons suggestions. 2 skipped as decided meanwhile"),
    ("Reject 2 ticked", "Rejected no logons suggestions. 2 skipped as decided meanwhile"),
], ids=["accept", "reject"])
def test_ticks_all_decided_elsewhere_act_on_nothing_else(browser, small_groups, name, line):  # noqa: F811
    """With every ticked event decided elsewhere, the request decides none, not every pending event, and writes no entry."""
    seen = {}

    def rule(app):
        suggest_logons(app)
        seen["app"] = app
        seen["uids"] = group_uids(app, ZED)

    for p in served_page(browser, small_groups, setup=rule):
        open_logons(p)
        tick(p, ZED, 0).click()
        tick(p, ZED, 1).click()
        api_suggestion(seen["app"], {"decision": "reject", "source": "logons", "uids": seen["uids"][:2]})
        journaled = len(entries(small_groups))
        pending = api_pending_uids(seen["app"], {"source": ["logons"]})["uids"]
        named(p, ZED, name).click()
        said(p, line)
        assert len(entries(small_groups)) == journaled
        assert api_pending_uids(seen["app"], {"source": ["logons"]})["uids"] == pending
        p.wait_for_function(COUNT_IS, arg=[ZED, "2 pending"])
        assert ticked(p, ZED) == []


def test_a_rows_own_decision_closes_the_ticked_question_and_counts_again(browser, synthetic_case):  # noqa: F811
    """28 ticked with the question open. Row 0's own Accept takes its tick off, so the question, which stated 28, closes and the
    head counts 27. The next question covers those 27, and row 0 keeps what its own button did."""
    add_logons(synthetic_case, ["zed"] * 28)
    for p in served_page(browser, synthetic_case, setup=suggest_logons):
        open_logons(p)
        named(p, ZED, "Select all").click()
        named(p, ZED, "Reject 28 ticked").click()
        block = group(p, ZED).locator(".confirm-block")
        block.wait_for()
        with p.expect_response("**/api/suggestion"):
            rows(p, ZED).nth(0).get_by_role("button", name="Accept", exact=True).click()
        block.wait_for(state="detached")
        named(p, ZED, "Reject 27 ticked").wait_for()
        p.wait_for_function(COUNT_IS, arg=[ZED, "27 pending"])
        named(p, ZED, "Reject 27 ticked").click()
        assert block.locator(".confirm-title").inner_text() == "Reject 27 logons suggestions?"
        with p.expect_request("**/api/suggestion") as sent:
            block.get_by_role("button", name="Reject 27", exact=True).click()
        p.wait_for_function(COUNT_IS, arg=[ZED, "0 pending"])
        assert len(sent.value.post_data_json["uids"]) == 27
        assert decided_count(p, ZED) == 28
        assert rows(p, ZED).nth(0).locator(".sg-decision").inner_text() == "Accepted as Suspicious"
        assert rows(p, ZED).locator(".sg-decision").all_inner_texts()[1:] == ["Rejected, stays Unreviewed"] * 27


def test_a_ticked_decision_keeps_the_label_a_rows_own_button_gave_first(browser, synthetic_case):  # noqa: F811
    """The question is confirmed while row 0's own Accept is out, and the server takes the Accept first. It skips that event
    in the ticked decision, and the row keeps its own label, rather than one the redraw's read would find false."""
    add_logons(synthetic_case, ["zed"] * 26)
    for p in served_page(browser, synthetic_case, setup=suggest_logons):
        open_logons(p)
        named(p, ZED, "Select all").click()
        named(p, ZED, "Reject 26 ticked").click()
        block = group(p, ZED).locator(".confirm-block")
        block.wait_for()
        held = Held(p, "/api/suggestion")
        rows(p, ZED).nth(0).get_by_role("button", name="Accept", exact=True).click()
        wait_held(p, held.routes)
        block.get_by_role("button", name="Reject 26", exact=True).click()
        wait_held(p, held.routes, 2)
        with p.expect_response("**/api/suggestion"):
            held.routes[0].continue_()
        with p.expect_response("**/api/suggestion") as answered:
            held.routes[1].continue_()
        p.unroute(held.match)
        assert answered.value.json()["skipped"] == 1
        # The first answer's redraw can show 0 pending with one row kept, so the wait is for all 26
        p.wait_for_function("() => document.querySelectorAll('#details .sg-events li.sg-decided').length === 26")
        assert rows(p, ZED).nth(0).locator(".sg-decision").inner_text() == "Accepted as Suspicious"
        assert rows(p, ZED).locator(".sg-decision").all_inner_texts()[1:] == ["Rejected, stays Unreviewed"] * 25


def test_a_read_older_than_a_ticked_decision_draws_its_rows_with_no_tick(browser, small_groups):  # noqa: F811
    """A read that reached the server before the decision still lists its rows as pending, and it answers after the decision
    did. They draw unticked for that moment, with no ticked buttons to send them again, and the redraw the decision owes
    draws them as decided."""
    for p in served_page(browser, small_groups, setup=suggest_logons):
        open_logons(p)
        tick(p, ZED, 0).click()
        tick(p, ZED, 1).click()
        deciding = Held(p, "/api/suggestion")
        named(p, ZED, "Reject 2 ticked").click()
        wait_held(p, deciding.routes)
        reading = HeldAnswer(p, "/api/pending")
        p.evaluate("() => { import('/js/suggestions.js').then((m) => m.showSuggestions('logons')); }")
        wait_held(p, reading.routes)
        deciding.release()
        said(p, "Rejected 2 logons suggestions")
        reading.answer()
        wait_held(p, reading.routes, 2)
        assert decided_count(p, ZED) == 0 and ticked(p, ZED) == []
        assert not named(p, ZED, "Reject 2 ticked").count()
        reading.release()
        p.wait_for_function(COUNT_IS, arg=[ZED, "2 pending"])
        assert decided_count(p, ZED) == 2


def test_the_whole_group_buttons_still_cover_every_event_with_ticks_on(browser, small_groups):  # noqa: F811
    """With one row ticked, Reject 4 asks the group's question and covers all four, ticked or not. They leave the list with no
    dimmed rows, and the tick goes with them. Accept all then covers the rest, ticks included, with none dimmed either."""
    for p in served_page(browser, small_groups, setup=suggest_logons):
        open_logons(p)
        tick(p, ZED, 1).click()
        named(p, ZED, "Reject 4").click()
        block = group(p, ZED).locator(".confirm-block")
        assert block.locator(".confirm-title").inner_text() == "Reject 4 logons suggestions?"
        assert "counted when this page loaded" in block.inner_text()
        with p.expect_request("**/api/suggestion") as sent:
            block.get_by_role("button", name="Reject 4", exact=True).click()
        p.wait_for_function("(key) => ![...document.querySelectorAll('#details .sg-head strong')]"
                            ".some((n) => n.textContent === key)", arg=ZED)
        assert len(sent.value.post_data_json["uids"]) == 4
        assert p.locator(f"#details {DECIDED}").count() == 0
        tick(p, ANN, 0).click()
        p.locator("#details .actions").get_by_role("button", name="Accept all").click()
        p.locator("#details .confirm-slot .confirm-block button.primary").click()
        p.get_by_text("Nothing is pending from this source.").wait_for()
        assert p.locator(f"#details {DECIDED}").count() == 0


def test_a_cut_groups_select_button_says_how_many_it_reaches_until_show_all_lists_the_rest(browser, cut_group):  # noqa: F811
    """On a group cut at the limit the button reads as it does under a find, and never Select all or Select none, since it
    can't reach the rows not listed. Show all N first lists them, and it reads Select all again, with the ticks kept."""
    shown = f"the {PENDING_LIMIT} shown"
    total = PENDING_LIMIT + 10
    for p in served_page(browser, cut_group, setup=suggest_logons):
        open_logons(p)
        assert not named(p, ZED, "Select all").count()
        named(p, ZED, f"Select {shown}").click()
        assert named(p, ZED, f"Reject {PENDING_LIMIT} ticked").is_visible() and not named(p, ZED, "Select none").count()
        named(p, ZED, f"Unselect {shown}").click()
        assert ticked(p, ZED) == [] and named(p, ZED, f"Select {shown}").is_visible()
        tick(p, ZED, 1).click()
        named(p, ZED, f"Reject {total}").click()
        group(p, ZED).get_by_role("button", name=f"Show all {total} first").click()
        p.wait_for_function(LISTED_IS, arg=[ZED, total])
        assert ticked(p, ZED) == [1]
        named(p, ZED, "Select all").click()
        assert named(p, ZED, f"Reject {total} ticked").is_visible()
        named(p, ZED, "Select none").click()
        assert ticked(p, ZED) == []


def test_select_on_a_cut_group_ticks_the_rows_listed_and_the_group_buttons_cover_the_rest(browser, cut_group):  # noqa: F811
    """The select button reaches the rows the group lists. Rejecting them, by the question above 25, keeps those rows dimmed,
    leaves the ones not listed pending, and the read after it names every row kept. Reject N then covers what remains."""
    left = 10
    for p in served_page(browser, cut_group, setup=suggest_logons):
        open_logons(p)
        named(p, ZED, f"Select the {PENDING_LIMIT} shown").click()
        named(p, ZED, f"Reject {PENDING_LIMIT} ticked").click()
        block = group(p, ZED).locator(".confirm-block")
        assert block.locator(".confirm-line").inner_text() == HAND_PICKED.format(PENDING_LIMIT)
        with p.expect_request("**/api/suggestion") as sent:
            block.get_by_role("button", name=f"Reject {PENDING_LIMIT}", exact=True).click()
        p.wait_for_function(COUNT_IS, arg=[ZED, f"{left} pending"])
        assert len(sent.value.post_data_json["uids"]) == PENDING_LIMIT
        assert decided_count(p, ZED) == PENDING_LIMIT
        assert rows(p, ZED).count() == PENDING_LIMIT + left
        named(p, ZED, f"Reject {left}").click()
        with p.expect_request("**/api/suggestion") as sent:
            group(p, ZED).locator(".confirm-block").get_by_role("button", name=f"Reject {left}", exact=True).click()
        p.wait_for_function(COUNT_IS, arg=[ZED, "0 pending"])
        assert len(sent.value.post_data_json["uids"]) == left
        assert decided_count(p, ZED) == PENDING_LIMIT


def test_rows_kept_by_a_ticked_decision_stop_at_what_a_read_can_name(browser, synthetic_case):  # noqa: F811
    """More decided rows than a read can name: the page text says so, and the latest LISTED_EVENTS stay dimmed. Row 0, decided
    first on its own, and then the first rows of the ticked batch leave the list, and the read that names the rest answers."""
    count = LISTED_EVENTS + 5
    add_logons(synthetic_case, ["zed"] * count)
    for p in served_page(browser, synthetic_case, setup=suggest_logons):
        open_logons(p)
        p.evaluate("(n) => import('/js/suggestions.js').then((m) => m.showSuggestions('logons', '', n))", count)
        p.wait_for_function(LISTED_IS, arg=[ZED, count])
        assert p.locator("#details p.muted", has_text=f"the latest {LISTED_EVENTS} such rows").count() == 1
        before = texts(p, ZED)
        with p.expect_response("**/api/suggestion"):
            rows(p, ZED).nth(0).get_by_role("button", name="Reject", exact=True).click()
        p.wait_for_function(COUNT_IS, arg=[ZED, f"{count - 1} pending"])
        named(p, ZED, "Select all").click()
        named(p, ZED, f"Reject {count - 1} ticked").click()
        group(p, ZED).locator(".confirm-block").get_by_role("button", name=f"Reject {count - 1}", exact=True).click()
        p.wait_for_function(COUNT_IS, arg=[ZED, "0 pending"])
        assert decided_count(p, ZED) == LISTED_EVENTS
        assert texts(p, ZED) == before[-LISTED_EVENTS:]


def test_a_double_click_sends_one_request(browser, small_groups):  # noqa: F811
    """While the first request is out the buttons are off, and even a button turned on again sends nothing. The answer then
    settles it once: the two rows are decided, and the journal has one entry for them."""
    for p in served_page(browser, small_groups, setup=suggest_logons):
        open_logons(p)
        tick(p, ZED, 0).click()
        tick(p, ZED, 1).click()
        journaled = len(entries(small_groups))
        held = Held(p, "/api/suggestion")
        button = named(p, ZED, "Reject 2 ticked")
        button.dblclick()
        wait_held(p, held.routes)
        p.wait_for_timeout(100)
        assert len(held.routes) == 1
        assert button.is_disabled() and named(p, ZED, "Accept 2 ticked").is_disabled()
        button.evaluate("(n) => { n.disabled = false; n.click(); }")
        named(p, ZED, "Accept 2 ticked").evaluate("(n) => { n.disabled = false; n.click(); }")
        p.wait_for_timeout(100)
        assert len(held.routes) == 1
        held.release()
        p.wait_for_function(COUNT_IS, arg=[ZED, "2 pending"])
        assert decided_count(p, ZED) == 2
        assert len(entries(small_groups)) == journaled + 1


def test_a_refused_decision_keeps_the_ticks_for_another_try(browser, small_groups):  # noqa: F811
    """A request the server refuses leaves the ticks and turns the buttons on again, with no row dimmed, and the next click
    goes through."""
    refuse = lambda route: route.fulfill(status=400, json={"error": "the disk is full"})
    for p in served_page(browser, small_groups, setup=suggest_logons):
        open_logons(p)
        tick(p, ZED, 0).click()
        tick(p, ZED, 1).click()
        p.route("**/api/suggestion", refuse)
        with p.expect_response("**/api/suggestion"):
            named(p, ZED, "Reject 2 ticked").click()
        said(p, "Suggestion change failed: the disk is full")
        p.unroute("**/api/suggestion", refuse)
        p.errors.clear()
        p.wait_for_function(COUNT_IS, arg=[ZED, "4 pending"])
        assert decided_count(p, ZED) == 0 and ticked(p, ZED) == [0, 1]
        assert named(p, ZED, "Reject 2 ticked").is_enabled()
        decide_ticked(p, ZED, "Reject 2 ticked", 2)
        assert decided_count(p, ZED) == 2


@pytest.mark.parametrize("width", [1400, 800, 380])
def test_the_head_holds_every_action_at_each_width(browser, synthetic_case, width):  # noqa: F811
    """With a long account name, ticked rows, a find on, and a tick it hides, each head control is whole inside the panel."""
    long_name = "svc_" + "very_long_account_name_" * 6
    add_logons(synthetic_case, ["zed"] * 3 + [long_name] * 3)
    for p in served_page(browser, synthetic_case, setup=suggest_logons):
        p.set_viewport_size({"width": width, "height": 900})
        open_logons(p)
        for key in (ZED, f"C137\\{long_name}"):
            assert head(p, key).evaluate(SPILLS) == []
            assert head(p, key).locator("strong").evaluate("(n) => n.scrollWidth <= n.clientWidth + 1")   # the name wraps
            tick(p, key, 0).click()
            tick(p, key, 1).click()
            assert named(p, key, "Accept 2 ticked").is_visible() and named(p, key, "Reject 2 ticked").is_visible()
            assert head(p, key).evaluate(SPILLS) == []
            head(p, key).locator(".find input").fill("no such row")
            assert head(p, key).locator(".find-ticks").is_visible()
            assert head(p, key).evaluate(SPILLS) == []
            head(p, key).locator(".find input").fill("")


def test_a_tick_or_the_select_button_moves_no_row_at_any_width(browser, synthetic_case):  # noqa: F811
    """With no find on, the first tick, the select button ticking the rest, and the select button unticking them all leave every
    row where it was, so the next click lands where the pointer is. This holds for a group of one row, of twelve, of the
    limit, and of more than the limit, at each window width, including those where a head sits at the edge of wrapping."""
    names = {"dee": 1, "eli": 12, "fay": PENDING_LIMIT, "zed": PENDING_LIMIT + 10}
    add_logons(synthetic_case, [name for name, n in names.items() for _ in range(n)])
    keys = {f"C137\\{name}": n for name, n in names.items()}
    for p in served_page(browser, synthetic_case, setup=suggest_logons):
        open_logons(p)
        for key, n in keys.items():
            assert head(p, key).locator(".muted").inner_text() == f"{n} pending"
            if not is_open(p, key):
                head(p, key).locator(".twisty").click()
        for width in (380, 620, 800, 960, 980, 990, 1000, 1400):
            p.set_viewport_size({"width": width, "height": 900})
            for key in keys:
                before = row_offset(p, key)
                select = head(p, key).locator(".sg-ticks button").first
                room = select.bounding_box()["width"]
                tick(p, key, 0).click()
                assert (row_offset(p, key), select.bounding_box()["width"]) == (before, room), (width, key, "the first tick")
                select.click()
                assert (row_offset(p, key), select.bounding_box()["width"]) == (before, room), (width, key, "the select button")
                select.click()
                if ticked(p, key):   # a one-row group: its tick ticked it whole, so the button unticked it, then ticked it
                    select.click()
                assert ticked(p, key) == [], (width, key)
                assert (row_offset(p, key), select.bounding_box()["width"]) == (before, room), (width, key, "the last untick")
