"""A decision on one event of the Suggestions page, and what the status line says of any suggestion decision, in a real
browser. The row stays where it sat, dimmed and labeled, until the analyst leaves the page; a rejected row has Restore;
the group's count and buttons cover what is still pending. They drive the installed Microsoft Edge through Playwright, as
test_browser_smoke does, and are skipped without it."""

import pytest
from conftest import SEC, T0
from test_browser_investigate import uid_at
from test_browser_page_guards import Held, HeldAnswer
from test_browser_smoke import browser, served_page, wait_held  # noqa: F401
from test_browser_suggestion_folds import ANN, COUNT_IS, ZED, add_logons, group, open_logons, order, suggest_logons

from glessner.server import api_pending, api_rule

pytestmark = pytest.mark.browser
DECIDED = ".sg-decided"
DESKTOP_LOGONS = ("id: logons\nsuggest: suspicious\nwhen:\n  all:\n"
                  "    - {field: event_code, equals: '4624'}\n    - {field: host, equals: DESKTOP}\n")


@pytest.fixture
def small_groups(synthetic_case):
    """Four logons by zed and one by ann on DC01. A rule that suggests every 4624 groups them by account, zed's first,
    and with the synthetic case's own logons every group opens at first."""
    return add_logons(synthetic_case, ["zed"] * 4 + ["ann"])


def rows(p, key):
    return group(p, key).locator(".sg-events li")


def decided_count(p, key):
    return group(p, key).locator(f".sg-events li{DECIDED}").count()


def texts(p, key):
    return rows(p, key).locator(".sg-text").all_inner_texts()


def press(p, key, index, name, left):
    """Press a button of the group's row at `index`, and wait until the page has drawn again with `left` pending in it."""
    with p.expect_response("**/api/suggestion"):
        rows(p, key).nth(index).get_by_role("button", name=name, exact=True).click()
    p.wait_for_function(COUNT_IS, arg=[key, f"{left} pending"])


def said(p, line):
    """Wait until the status line starts with `line`."""
    p.wait_for_function("(line) => document.getElementById('status').textContent.startsWith(line)", arg=line)


def color(row):
    return row.evaluate("(n) => getComputedStyle(n).color")


def group_uids(app, key):
    """The IDs of the group's events, in the order the page lists them."""
    groups = api_pending(app, {"source": ["logons"], "group_by": ["account"]})["groups"]
    return next([e["uid"] for e in g["events"]] for g in groups if g["key"] == key)


def apply_mark(p, label, uid):
    """Mark one event as the timeline's buttons and the right-click menu do, which draws no Suggestions page."""
    p.evaluate("([label, uid]) => import('/js/event_page.js').then((m) => m.applyMark(label, '', [uid]))", [label, uid])


def read_again(p):
    """Have the Suggestions page on screen read its events and draw again."""
    p.evaluate("() => import('/js/suggestions.js').then((m) => m.showSuggestions('logons'))")


def test_a_rejected_row_stays_where_it_sat_and_restore_brings_it_back_pending(browser, small_groups):  # noqa: F811
    """Reject leaves the row in its place, dimmed, with its label and Restore and no badge, since the label spells the
    state out. The group's count and buttons drop by one, and the status line says the decision. A second Reject keeps both
    in place. Restore brings the row back as pending, in the same place."""
    for p in served_page(browser, small_groups, setup=suggest_logons):
        open_logons(p)
        before = texts(p, ZED)
        assert len(before) == 4
        pending_color = color(rows(p, ZED).nth(0))
        press(p, ZED, 1, "Reject", 3)
        said(p, "Rejected 1 logons suggestion; the event stays Unreviewed · ")
        row = rows(p, ZED).nth(1)
        assert texts(p, ZED) == before and decided_count(p, ZED) == 1
        assert row.locator(".sg-decision").inner_text() == "Rejected, stays Unreviewed"
        assert row.get_by_role("button").all_inner_texts() == ["Restore"]
        assert row.locator(".badge").count() == 0
        assert color(row) != pending_color
        head = group(p, ZED).locator(".sg-head")
        assert head.get_by_role("button", name="Accept 3", exact=True).count() == 1
        assert head.get_by_role("button", name="Reject 3", exact=True).count() == 1
        press(p, ZED, 3, "Reject", 2)
        assert texts(p, ZED) == before and decided_count(p, ZED) == 2
        press(p, ZED, 1, "Restore", 3)
        said(p, "Restored 1 logons suggestion · ")
        assert texts(p, ZED) == before and decided_count(p, ZED) == 1
        restored = rows(p, ZED).nth(1)
        assert restored.get_by_role("button").all_inner_texts() == ["Accept", "Reject"]
        assert restored.locator(".badge.u").count() == 1
        assert p.locator("#details h2").inner_text() == "logons suggests suspicious: 10 pending"


def test_an_accepted_row_names_the_mark_it_gave_and_opens_its_event(browser, small_groups):  # noqa: F811
    """A rule that suggests Malicious: Accept's label and the status line name that mark, and the row has no Restore. A click
    on the row still opens the event. Back draws the page afresh, without the decided row."""
    def rule(app):
        api_rule(app, {"op": "add", "text": "id: logons\nsuggest: malicious\nwhen: {field: event_code, equals: '4624'}\n"})

    for p in served_page(browser, small_groups, setup=rule):
        open_logons(p)
        before = texts(p, ZED)
        press(p, ZED, 0, "Accept", 3)
        said(p, "Accepted 1 logons suggestion as Malicious · ")
        row = rows(p, ZED).nth(0)
        assert row.locator(".sg-decision").inner_text() == "Accepted as Malicious"
        assert row.get_by_role("button").count() == 0
        assert texts(p, ZED) == before
        row.locator(".sg-text").click()
        p.wait_for_selector("#details[data-page='event'] .ev-verdict .status.malicious")
        p.locator("#detailsBand button.back").click()
        p.wait_for_selector("#details[data-page='suggestions'] .sg-group")
        assert p.locator(f"#details {DECIDED}").count() == 0
        assert texts(p, ZED) == before[1:]


def test_a_group_whose_last_row_was_decided_stays_in_place_with_its_row(browser, small_groups):  # noqa: F811
    """The group of one event, once decided, stays where it was with its row, reads 0 pending, and has no group buttons and
    no find. Restore brings its buttons back. Other groups of one event, decided from the last up, each keep their place."""
    for p in served_page(browser, small_groups, setup=suggest_logons):
        open_logons(p)
        groups = order(p)
        ones = [key for key in groups if rows(p, key).count() == 1]
        assert ANN in ones and len(ones) >= 3 and groups[-1] == ones[-1]
        press(p, ANN, 0, "Reject", 0)
        assert order(p) == groups
        assert group(p, ANN).locator(".sg-head").get_by_role("button", name="Reject").count() == 0
        assert group(p, ANN).locator(".sg-head .find").count() == 0
        assert rows(p, ANN).nth(0).locator(".sg-decision").inner_text() == "Rejected, stays Unreviewed"
        press(p, ANN, 0, "Restore", 1)
        assert group(p, ANN).locator(".sg-head").get_by_role("button", name="Reject 1", exact=True).count() == 1
        assert group(p, ANN).locator(".sg-head .find").count() == 1
        for key in reversed(ones):
            press(p, key, 0, "Accept", 0)
            assert order(p) == groups


def test_a_page_with_nothing_left_pending_keeps_its_decided_rows(browser, synthetic_case):  # noqa: F811
    """With every row decided the page says nothing is pending, drops Accept all and Reject all, still names the mark in
    its heading, and keeps the rows. Group by stays."""
    def rule(app):
        api_rule(app, {"op": "add", "text": DESKTOP_LOGONS})

    for p in served_page(browser, synthetic_case, setup=rule):
        open_logons(p)
        details = p.locator("#details")
        pending = details.locator(f".sg-events li:not({DECIDED})")
        assert pending.count() == 2
        for done in (1, 2):
            pending.first.get_by_role("button", name="Reject").click()
            p.wait_for_function(f"(n) => document.querySelectorAll('#details {DECIDED}').length === n", arg=done)
        details.get_by_text("Nothing is pending from this source.").wait_for()
        assert details.locator("h2").inner_text() == "logons suggests suspicious: 0 pending"
        assert details.get_by_role("button", name="Accept all").count() == 0
        assert details.get_by_role("button", name="Reject all").count() == 0
        assert details.locator(f".sg-events {DECIDED}").count() == 2
        assert details.locator(".actions select").count() == 1


def test_a_group_action_adds_no_dimmed_rows_and_keeps_those_decided_before_it(browser, small_groups):  # noqa: F811
    """Accept 3 on a group with one decided row asks first and covers the three still pending: they leave the list, and the
    decided row stays. The status line counts the three."""
    for p in served_page(browser, small_groups, setup=suggest_logons):
        open_logons(p)
        press(p, ZED, 2, "Reject", 3)
        kept = rows(p, ZED).nth(2).locator(".sg-text").inner_text()
        group(p, ZED).locator(".sg-head").get_by_role("button", name="Accept 3", exact=True).click()
        block = group(p, ZED).locator(".confirm-block")
        assert block.locator(".confirm-title").inner_text() == "Accept 3 logons suggestions?"
        with p.expect_response("**/api/suggestion"):
            block.get_by_role("button", name="Accept 3", exact=True).click()
        p.wait_for_function(COUNT_IS, arg=[ZED, "0 pending"])
        said(p, "Accepted 3 logons suggestions as Suspicious · ")
        assert texts(p, ZED) == [kept]
        assert rows(p, ZED).nth(0).locator(".sg-decision").inner_text() == "Rejected, stays Unreviewed"


def test_a_decided_row_keeps_to_the_grouping_it_was_decided_under(browser, small_groups):  # noqa: F811
    """Regrouping draws the other grouping's groups without the row. Going back to the first draws it where it sat."""
    for p in served_page(browser, small_groups, setup=suggest_logons):
        open_logons(p)
        before = texts(p, ZED)
        press(p, ZED, 1, "Reject", 3)
        p.locator("#details .actions select").select_option("host")
        p.wait_for_selector("#details .sg-head strong:text-is('DC01')")
        assert p.locator(f"#details {DECIDED}").count() == 0
        p.locator("#details .actions select").select_option("account")
        p.wait_for_function(COUNT_IS, arg=[ZED, "3 pending"])
        assert texts(p, ZED) == before
        assert rows(p, ZED).nth(1).get_attribute("class") == "sg-decided"


def test_the_event_page_and_the_menu_say_the_decision_in_plain_words(browser, synthetic_case):  # noqa: F811
    """The status line on the Event page's Reject, Restore, and Accept. The right-click menu offers Reject on an event the
    Accept marked, and the line then says the mark stands."""
    uids = {}

    def rule(app):
        suggest_logons(app)
        uids["logon"] = uid_at(app, T0 + 60 * SEC)

    for p in served_page(browser, synthetic_case, setup=rule):
        uid = uids["logon"]
        p.evaluate("(uid) => window.__app.select(uid, false)", uid)
        details = p.locator("#details")
        details.get_by_role("button", name="Reject", exact=True).click()
        said(p, "Rejected 1 logons suggestion; the event stays Unreviewed · ")
        details.get_by_role("button", name="Restore", exact=True).click()
        said(p, "Restored 1 logons suggestion · ")
        details.get_by_role("button", name="Accept as Suspicious").click()
        said(p, "Accepted 1 logons suggestion as Suspicious · ")
        details.locator(".ev-verdict .status.suspicious").wait_for()
        p.evaluate("(uid) => import('/js/quick_menu.js').then((m) => m.openQuickMenu(uid, 300, 300))", uid)
        p.locator("#quickMenu:not([hidden])").get_by_role("menuitem", name="Reject the logons suggestion").click()
        said(p, "Rejected 1 logons suggestion; the event keeps its mark · ")


WORDS = [
    ("accept", {"changed": 1, "skipped": 0, "accepted": {"suspicious": 1}}, "Accepted 1 hayabusa suggestion as Suspicious"),
    ("accept", {"changed": 1200, "skipped": 0, "accepted": {"suspicious": 1200}},
     "Accepted 1,200 hayabusa suggestions as Suspicious"),
    ("accept", {"changed": 5, "skipped": 0, "accepted": {"suspicious": 2, "malicious": 3}},
     "Accepted 5 hayabusa suggestions: 3 as Malicious, 2 as Suspicious"),
    ("accept", {"changed": 2, "skipped": 1, "accepted": {"authorized": 2}},
     "Accepted 2 hayabusa suggestions as Authorized. 1 skipped as decided meanwhile"),
    ("accept", {"changed": 0, "skipped": 3}, "Accepted no hayabusa suggestions. 3 skipped as decided meanwhile"),
    ("accept", {"changed": 0, "skipped": 0}, "Accepted no hayabusa suggestions"),
    ("reject", {"changed": 1, "skipped": 0, "marked": 0}, "Rejected 1 hayabusa suggestion; the event stays Unreviewed"),
    ("reject", {"changed": 3, "skipped": 0, "marked": 0}, "Rejected 3 hayabusa suggestions; the events stay Unreviewed"),
    ("reject", {"changed": 2, "skipped": 1, "marked": 0},
     "Rejected 2 hayabusa suggestions; the events stay Unreviewed. 1 skipped as decided meanwhile"),
    ("reject", {"changed": 0, "skipped": 2, "marked": 0}, "Rejected no hayabusa suggestions. 2 skipped as decided meanwhile"),
    ("reject", {"changed": 1, "skipped": 0, "marked": 1}, "Rejected 1 hayabusa suggestion; the event keeps its mark"),
    ("reject", {"changed": 2, "skipped": 0, "marked": 2}, "Rejected 2 hayabusa suggestions; the events keep their marks"),
    ("reject", {"changed": 3, "skipped": 0, "marked": 1},
     "Rejected 3 hayabusa suggestions; 1 event keeps its mark and 2 stay Unreviewed"),
    ("reject", {"changed": 3, "skipped": 1, "marked": 2},
     "Rejected 3 hayabusa suggestions; 2 events keep their marks and 1 stays Unreviewed. 1 skipped as decided meanwhile"),
    ("restore", {"changed": 1, "skipped": 0}, "Restored 1 hayabusa suggestion"),
    ("restore", {"changed": 4, "skipped": 0}, "Restored 4 hayabusa suggestions"),
]


def test_a_row_leaves_the_page_when_a_later_mark_makes_its_label_false(browser, small_groups):  # noqa: F811
    """A mark from the timeline or the right-click menu draws no Suggestions page. At its next read, a rejected row marked
    since and an accepted row marked another way have left it. A rejected row nothing touched keeps its label, and an accepted
    row set back to Unreviewed is pending again."""
    seen = {}

    def rule(app):
        suggest_logons(app)
        seen["uids"] = group_uids(app, ZED)

    for p in served_page(browser, small_groups, setup=rule):
        open_logons(p)
        before = texts(p, ZED)
        rejected_then_marked, accepted_then_remarked, _, accepted_then_cleared = seen["uids"]
        press(p, ZED, 0, "Reject", 3)
        press(p, ZED, 1, "Accept", 2)
        press(p, ZED, 2, "Reject", 1)
        press(p, ZED, 3, "Accept", 0)
        apply_mark(p, "Malicious", rejected_then_marked)
        apply_mark(p, "Malicious", accepted_then_remarked)
        apply_mark(p, "Unreviewed", accepted_then_cleared)
        read_again(p)
        assert texts(p, ZED) == before[2:]
        assert rows(p, ZED).nth(0).locator(".sg-decision").inner_text() == "Rejected, stays Unreviewed"
        assert rows(p, ZED).nth(1).get_by_role("button").all_inner_texts() == ["Accept", "Reject"]
        assert group(p, ZED).locator(".sg-head .muted").inner_text() == "1 pending"


def test_a_row_restored_from_the_menu_is_pending_and_a_group_accept_takes_it(browser, small_groups):  # noqa: F811
    """A rejected row restored from the right-click menu, which draws no Suggestions page, reads as pending at the page's next
    read, and no longer as decided. The group's Accept 4 then marks it with the rest, and nothing says it was rejected."""
    seen = {}

    def rule(app):
        suggest_logons(app)
        seen["uids"] = group_uids(app, ZED)

    for p in served_page(browser, small_groups, setup=rule):
        open_logons(p)
        press(p, ZED, 1, "Reject", 3)
        p.evaluate("(uid) => import('/js/event_page.js').then((m) => m.decide('restore', 'logons', [uid]))", seen["uids"][1])
        read_again(p)
        assert decided_count(p, ZED) == 0
        assert rows(p, ZED).nth(1).get_by_role("button").all_inner_texts() == ["Accept", "Reject"]
        group(p, ZED).locator(".sg-head").get_by_role("button", name="Accept 4", exact=True).click()
        group(p, ZED).locator(".confirm-block").get_by_role("button", name="Accept 4", exact=True).click()
        said(p, "Accepted 4 logons suggestions as Suspicious · ")
        p.wait_for_function("(key) => ![...document.querySelectorAll('#details .sg-head strong')]"
                            ".some((n) => n.textContent === key)", arg=ZED)
        assert p.locator(f"#details {DECIDED}").count() == 0


def test_a_read_older_than_a_decision_leaves_its_row_decided(browser, small_groups):  # noqa: F811
    """A read that reached the server before a decision still lists the event as pending, and it answers after the decision
    did. The row draws as pending for that moment, and the redraw the decision owes draws it as decided."""
    for p in served_page(browser, small_groups, setup=suggest_logons):
        open_logons(p)
        before = texts(p, ZED)
        deciding = Held(p, "/api/suggestion")
        rows(p, ZED).nth(1).get_by_role("button", name="Reject", exact=True).click()
        wait_held(p, deciding.routes)
        reading = HeldAnswer(p, "/api/pending")
        p.evaluate("() => { import('/js/suggestions.js').then((m) => m.showSuggestions('logons')); }")
        wait_held(p, reading.routes)
        deciding.release()
        said(p, "Rejected 1 logons suggestion")
        reading.release()
        p.wait_for_function(COUNT_IS, arg=[ZED, "3 pending"])
        assert texts(p, ZED) == before
        assert rows(p, ZED).nth(1).get_attribute("class") == "sg-decided"


def test_an_accepted_row_names_the_mark_the_server_gave(browser, small_groups):  # noqa: F811
    """The rule changes to suggest Malicious after the page listed its events as Suspicious. The row's label and the status
    line both name what the server marked."""
    seen = {}

    def rule(app):
        suggest_logons(app)
        seen["app"] = app

    for p in served_page(browser, small_groups, setup=rule):
        open_logons(p)
        changed = "id: logons\nsuggest: malicious\nwhen: {field: event_code, equals: '4624'}\n"
        api_rule(seen["app"], {"op": "change", "text": changed})
        press(p, ZED, 0, "Accept", 3)
        said(p, "Accepted 1 logons suggestion as Malicious · ")
        assert rows(p, ZED).nth(0).locator(".sg-decision").inner_text() == "Accepted as Malicious"
        read_again(p)
        assert rows(p, ZED).nth(0).locator(".sg-decision").inner_text() == "Accepted as Malicious"


# What the status line does with its text: `full` says every word shows, in the two lines it takes beside the case's name
# or in the one it takes elsewhere. A line clamp's ellipsis draws only with left-aligned text.
LINE = """() => {
    const n = document.getElementById('status'), shown = n.firstElementChild, words = document.createRange();
    words.selectNodeContents(shown);
    const lines = getComputedStyle(shown), two = lines.webkitLineClamp === '2';
    return { text: n.textContent, hover: n.title, two,
             ellipsis: two ? lines.textAlign === 'left' : getComputedStyle(n).textOverflow === 'ellipsis',
             full: two ? words.getClientRects().length <= 2 : n.scrollWidth <= n.clientWidth,
             header: document.querySelector('header').getBoundingClientRect().height };
}"""
SAY = f"""async ([decision, answer, note]) => {{
    const [page, core] = await Promise.all([import('/js/event_page.js'), import('/js/core.js')]);
    core.S.viewStatus = note;
    core.reportAction(page.decisionWords(decision, 'hayabusa', answer), 38);
    return ({LINE})();
}}"""
FOLDED_NOTE = "Logon links inside a folded group aren't drawn; open the group to see them."


def status_after(p, decision, answer, note=""):
    """The status line right after an action, read in the same task, since a redraw of the timeline rewrites the view's notes."""
    return p.evaluate(SAY, [decision, answer, note])


@pytest.mark.parametrize("setup", [None, suggest_logons], ids=["no pending count", "a pending count"])
def test_a_one_event_decision_reads_in_full_at_1280_px_and_wider(browser, synthetic_case, setup):  # noqa: F811
    """At each width the sentence shows whole, in two lines beside the case's name or in one on a row of its own, whichever
    the header's other items leave it, and the header keeps its height."""
    for p in served_page(browser, synthetic_case, setup=setup):
        for width in (1280, 1300, 1320, 1340, 1366, 1400, 1440, 1600, 1920):
            p.set_viewport_size({"width": width, "height": 800})
            p.wait_for_timeout(150)
            short = status_after(p, "restore", {"changed": 1})["header"]
            for decision, answer in (("reject", {"changed": 1}), ("accept", {"changed": 1, "accepted": {"suspicious": 1}})):
                line = status_after(p, decision, answer)
                assert line["full"] and line["header"] == short, (width, line)


@pytest.mark.parametrize("width", [1024, 1400])
def test_a_long_sentence_is_cut_after_the_decisions_words_with_all_of_it_in_the_hover(browser, synthetic_case, width):  # noqa: F811
    """A sentence with a skipped clause and the view's note after it doesn't fit. It is cut with an ellipsis, the decision's
    words come first, the hover holds all of it, and the header keeps its height."""
    for p in served_page(browser, synthetic_case):
        p.set_viewport_size({"width": width, "height": 800})
        p.wait_for_timeout(150)
        short = status_after(p, "restore", {"changed": 1})["header"]
        line = status_after(p, "reject", {"changed": 2, "skipped": 1}, FOLDED_NOTE)
        words = "Rejected 2 hayabusa suggestions; the events stay Unreviewed. 1 skipped as decided meanwhile"
        assert line["text"].startswith(words) and line["text"].endswith(FOLDED_NOTE)
        assert line["hover"] == line["text"]
        assert not line["full"] and line["ellipsis"]
        assert line["header"] == short


def test_the_words_hold_for_counts_mixed_marks_and_skipped_events(browser, synthetic_case):  # noqa: F811
    """What decide() reports for each shape of the server's answer: one event or many, an accept of different marks, events
    skipped as decided meanwhile, and nothing decided at all."""
    for p in served_page(browser, synthetic_case):
        words = p.evaluate("""(cases) => import('/js/event_page.js').then((m) =>
            cases.map(([decision, answer]) => m.decisionWords(decision, 'hayabusa', answer)))""", [[d, a] for d, a, _ in WORDS])
        assert words == [line for _, _, line in WORDS]
