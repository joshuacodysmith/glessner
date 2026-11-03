"""One Suggestions group as a page of its own, in a real browser. A group's title opens it alone, led by Review one by one over
every event the group counts, with the group's buttons, its find, and its ticks. Back returns to the page of groups with true
counts, whenever the decision answers. A reload comes back to it, and a review stops there. A Hayabusa group links to the
rule's search. A double click opens one page, and the head holds its controls at the narrowest width. They drive the installed
Microsoft Edge through Playwright, as test_browser_smoke does, and are skipped without it."""

import re
from urllib.parse import urlsplit

import pytest
from conftest import METASPLOIT, SEC, T0, logon
from test_browser_investigate import BAR_READS, INVESTIGATE, entries, open_worklist
from test_browser_list_verdicts import SPILLS
from test_browser_page_guards import Held, confirm, open_suggestions
from test_browser_reload import reload, status
from test_browser_smoke import RECORD_REQUESTS, browser, served_page, wait_held  # noqa: F401
from test_browser_suggestion_decisions import DECIDED, group_uids, rows, small_groups  # noqa: F401
from test_browser_suggestion_folds import ANN, COUNT_IS, ZED, add_logons, cut_group, group, open_logons, order, suggest_logons  # noqa: F401
from test_browser_suggestion_ticks import ticked

from glessner.events import Event, load
from glessner.queries import PENDING_LIMIT
from glessner.search import MAX_QUERY
from glessner.server import api_mark, api_pending

pytestmark = pytest.mark.browser
TITLE = ".sg-head button.sg-title"
HEAD = "#details .sg-group .sg-head"
RULE_LINK = "Every event this rule hit, in any state"
HIT_TITLE = "Suspicious logon"
QUOTED_TITLE = 'Odd "quoted" rule'
HIT_LOG = "DC01/Windows/System32/winevt/Logs/Hits.evtx"
ON_PAGE = "(key) => document.getElementById('details').dataset.key === key"
PAGE_COUNT_IS = f"(text) => document.querySelector('{HEAD} .muted')?.textContent === text"
SUBMITTED = "**/api/suggestion"
LONGEST_TITLE = MAX_QUERY - len('rule:""')
# Whether the page shows this search with this many rows
SEARCH_LISTS = ("([q, n]) => document.querySelector('#detailsBand .title')?.textContent === `Search: ${q}` && "
                "document.querySelectorAll('#details[data-page=\"search\"] li.rel-row').length === n")


def zed_page(by="account", key=ZED, source="logons"):
    return f"suggestions:{source}:{by}:{key}"


def on_page(p, key):
    p.wait_for_function(ON_PAGE, arg=key)


def open_group(p, key=ZED, by="account", source="logons"):
    """Click the group's title and wait for the group's page."""
    group(p, key).locator(TITLE).click()
    on_page(p, zed_page(by, key, source))


def back(p, key):
    p.locator("#detailsBand button.back").click()
    on_page(p, key)


def back_says(p):
    """The Back link's words, after its arrow."""
    return p.locator("#detailsBand button.back").inner_text().split(" ", 1)[1]


def page_rows(p):
    return p.locator("#details .sg-group .sg-events li")


def page_count_is(p, n):
    p.wait_for_function(PAGE_COUNT_IS, arg=f"{n} pending")


def head_button(p, name):
    return p.locator(HEAD).get_by_role("button", name=name, exact=True)


def press_row(p, index, name, left):
    """Press a button of the group page's row at `index`, and wait until the page has drawn again with `left` pending."""
    with p.expect_response(SUBMITTED):
        page_rows(p).nth(index).get_by_role("button", name=name, exact=True).click()
    page_count_is(p, left)


def page_ticked(p):
    return page_rows(p).evaluate_all(
        "(ns) => ns.flatMap((n, i) => (n.querySelector('input[type=checkbox]')?.checked ? [i] : []))")


def start_review(p, first):
    head_button(p, "Review one by one").click()
    p.wait_for_function(BAR_READS, arg=first)


def total(p):
    """The source's pending count as the page of groups heads it."""
    return int(re.search(r"(\d+) pending$", p.locator("#details h2").inner_text()).group(1))


def add_hits(case, title, count, level="high", start=1000):
    """`count` logons on DC01, a second apart, each with a Hayabusa hit of the rule `title`, which suggests Suspicious."""
    logons = [logon(T0 + (start + i) * SEC, start + i, HIT_LOG, user="eve", ltype="3") for i in range(count)]
    hits = [Event(T0 + (start + i) * SEC, "Event Recorded", "hayabusa", HIT_LOG, f"{start + i}:rule", f"{title} [{level}]",
                  record_id=start + i, log_channel="Security", rule_title=title, rule_level=level) for i in range(count)]
    for tool, events in (("evtxecmd", logons), ("hayabusa", hits)):
        load(case.db_path, events, host="DC01", tool=tool, tool_version="t", run_id=f"{tool}-{start}", replaces_sources=[],
             staging_dir=case.folder)
    return case


@pytest.fixture
def hit_case(synthetic_case):
    """Three events a rule hit, and one that a rule with a double quote in its title hit."""
    add_hits(synthetic_case, HIT_TITLE, 3)
    return add_hits(synthetic_case, QUOTED_TITLE, 1, start=2000)


def test_a_title_opens_its_group_alone_and_back_returns_to_the_groups(browser, small_groups):  # noqa: F811
    """The title is a button. The page lists that group alone under its name, led by Review one by one, with Accept N, Reject N,
    the ticks, and the find, and without the page-wide buttons or the fold. The timeline highlights only its events. Back returns
    to the page of groups, as it was grouped."""
    seen = {}

    def rule(app):
        suggest_logons(app)
        seen["uids"] = group_uids(app, ZED)

    for p in served_page(browser, small_groups, setup=rule):
        open_logons(p)
        groups = order(p)
        assert group(p, ZED).locator(TITLE).evaluate("(n) => n.classList.contains('linklike')")
        assert p.locator("#details").get_by_text("Click a group's title to open it alone").count() == 1
        open_group(p)
        assert p.locator("#details h2").inner_text() == ZED
        help_text = p.locator("#details .sg-body > p.muted").first.inner_text()
        assert help_text.startswith("Review one by one opens each pending event of this group on its Event page in turn: ")
        assert "Accept N and Reject N cover every event the page counted" in help_text
        assert p.locator("#details .sg-group").count() == 1
        assert p.locator(HEAD).locator(".muted").first.inner_text() == "4 pending"
        assert p.locator(HEAD).locator("button.primary").inner_text() == "Review one by one"
        for name in ("Review one by one", "Accept 4", "Reject 4", "Select all"):
            assert head_button(p, name).count() == 1
        assert p.locator(f"{HEAD} .find input").count() == 1
        assert p.locator(f"{HEAD} .twisty").count() == 0
        assert p.locator("#details select").count() == 0
        assert p.locator("#details").get_by_role("button", name="Accept all").count() == 0
        assert page_rows(p).evaluate_all("(ns) => ns.map((n) => n.dataset.uid)") == seen["uids"]
        assert p.evaluate("() => [...window.__app.S.related].sort()") == sorted(seen["uids"])
        assert back_says(p) == "Back to logons suggestions"
        back(p, "suggestions:logons")
        assert order(p) == groups
        assert p.locator("#details select").input_value() == "account"
        group(p, ANN).locator(TITLE).click()
        on_page(p, zed_page(key=ANN))
        assert page_rows(p).count() == 1


def test_the_review_walks_every_event_the_group_counts_past_those_it_lists(browser, cut_group):  # noqa: F811
    """A group cut at the limit lists fewer rows than its count, and the review's queue is the count."""
    n = PENDING_LIMIT + 10
    seen = {}

    def rule(app):
        suggest_logons(app)
        seen["uids"] = next(g["uids"] for g in api_pending(app, {"source": ["logons"], "group_by": ["account"]})["groups"]
                            if g["key"] == ZED)

    for p in served_page(browser, cut_group, setup=rule):
        open_logons(p)
        assert group(p, ZED).locator(".sg-head .muted").first.inner_text() == f"{n} pending"
        cut_note = f"Showing the first {PENDING_LIMIT} of {n}. Ticks reach these rows; "
        covers = f"Accept {n} and Reject {n} cover all of them, and ask first."
        assert group(p, ZED).locator(".sg-more").inner_text() == f"{cut_note}{covers}"   # the groups have no review
        open_group(p)
        assert page_rows(p).count() == PENDING_LIMIT + 1   # with the row that says the list is cut
        assert p.locator("#details .sg-more").inner_text() == f"{cut_note}Review one by one walks all of them; {covers}"
        start_review(p, f"{ZED} (logons): 1 of {n}")
        assert p.evaluate("() => window.__app.S.focus") == seen["uids"][0]


def test_the_review_walks_the_listed_events_when_a_group_comes_without_its_ids(browser, small_groups):  # noqa: F811
    """A read takes a group's events and its IDs in two queries, so a group can come without `uids`. The review then walks the
    events listed, as Accept N covers them."""
    def no_ids(route):
        answer = route.fetch()
        body = answer.json()
        for read in body["groups"]:
            del read["uids"]
        route.fulfill(response=answer, json=body)

    for p in served_page(browser, small_groups, setup=suggest_logons):
        p.route(lambda url: urlsplit(url).path == "/api/pending", no_ids)
        open_logons(p)
        open_group(p)
        start_review(p, f"{ZED} (logons): 1 of 4")


def test_the_review_names_the_group_and_back_shows_true_counts(browser, small_groups):  # noqa: F811
    """The bar's position and end text name the group, and the keys decide and move on, in time order, over this group's events
    alone. Back from the review reaches the group's page in one step, with what the review left pending and no row kept as
    decided, and the next Back reaches the page of groups with the same count."""
    seen = {}

    def rule(app):
        suggest_logons(app)
        seen["uids"] = group_uids(app, ZED)

    for p in served_page(browser, small_groups, setup=rule):
        open_logons(p)
        before = total(p)
        journaled = len(entries(small_groups))
        open_group(p)
        start_review(p, f"{ZED} (logons): 1 of 4")
        focus = "() => window.__app.S.focus"
        assert p.evaluate(focus) == seen["uids"][0]
        with p.expect_response(SUBMITTED):
            p.keyboard.press("a")
        p.wait_for_function(BAR_READS, arg=f"{ZED} (logons): 2 of 4")
        assert p.evaluate(focus) == seen["uids"][1]
        with p.expect_response(SUBMITTED):
            p.keyboard.press("r")
        p.wait_for_function(BAR_READS, arg=f"{ZED} (logons): 3 of 4")
        p.keyboard.press("n")
        p.wait_for_function(BAR_READS, arg=f"{ZED} (logons): 4 of 4")
        assert p.evaluate(focus) == seen["uids"][3]
        assert len(entries(small_groups)) == journaled + 2
        p.keyboard.press("n")
        p.wait_for_function(BAR_READS, arg=f"{ZED} (logons): 4 events reviewed")
        assert p.locator("#details .review-bar .muted").inner_text() == "That was the last of the set the group's page counted."
        assert back_says(p) == f"Back to logons: {ZED}"
        back(p, zed_page())
        page_count_is(p, 2)
        assert page_rows(p).count() == 2 and p.locator(f"#details li{DECIDED}").count() == 0
        p.keyboard.press("a")   # no review bar on this page, so the key does nothing
        p.wait_for_timeout(100)
        assert len(entries(small_groups)) == journaled + 2
        back(p, "suggestions:logons")
        p.wait_for_function(COUNT_IS, arg=[ZED, "2 pending"])
        assert total(p) == before - 2


def test_back_reaches_the_group_page_from_a_review_longer_than_backs_history(browser, synthetic_case):  # noqa: F811
    """Back's history holds 20 pages, and the review's Event pages take one place in it, so a long review still leads back."""
    add_logons(synthetic_case, ["zed"] * 24)
    for p in served_page(browser, synthetic_case, setup=suggest_logons):
        open_logons(p)
        open_group(p)
        start_review(p, f"{ZED} (logons): 1 of 24")
        for at in range(2, 25):
            p.keyboard.press("n")
            p.wait_for_function(BAR_READS, arg=f"{ZED} (logons): {at} of 24")
        history = p.evaluate("() => window.__app.S.back.map((page) => page.key)")
        assert history == ["investigate", "suggestions:logons", zed_page()]
        back(p, zed_page())
        page_count_is(p, 24)
        back(p, "suggestions:logons")


def test_rows_decided_on_the_group_page_stay_dimmed_and_labeled(browser, small_groups):  # noqa: F811
    """As on the page of groups: the row stays in place with its label, a rejected one has Restore, and the counts and buttons
    cover what is left. Leaving the page drops the rows, and Back shows the true count."""
    for p in served_page(browser, small_groups, setup=suggest_logons):
        open_logons(p)
        before = total(p)
        open_group(p)
        listed = page_rows(p).locator(".sg-text").all_inner_texts()
        p.evaluate(RECORD_REQUESTS)
        press_row(p, 1, "Reject", 3)
        p.wait_for_timeout(100)
        assert p.evaluate("() => window.__asked.filter((path) => path.startsWith('/api/pending?')).length") == 1   # one redraw
        press_row(p, 2, "Accept", 2)
        assert page_rows(p).locator(".sg-text").all_inner_texts() == listed
        rejected, accepted = page_rows(p).nth(1), page_rows(p).nth(2)
        assert rejected.locator(".sg-decision").inner_text() == "Rejected, stays Unreviewed"
        assert rejected.get_by_role("button").all_inner_texts() == ["Restore"]
        assert accepted.locator(".sg-decision").inner_text() == "Accepted as Suspicious"
        assert p.locator(f"#details li{DECIDED}").count() == 2
        assert head_button(p, "Accept 2").count() == 1 and head_button(p, "Reject 2").count() == 1
        press_row(p, 1, "Restore", 3)
        assert page_rows(p).nth(1).get_by_role("button").all_inner_texts() == ["Accept", "Reject"]
        press_row(p, 1, "Reject", 2)
        start_review(p, f"{ZED} (logons): 1 of 2")   # the queue is what is still pending
        back(p, zed_page())
        page_count_is(p, 2)
        assert p.locator(f"#details li{DECIDED}").count() == 0
        back(p, "suggestions:logons")
        p.wait_for_function(COUNT_IS, arg=[ZED, "2 pending"])
        assert total(p) == before - 2


def test_the_whole_group_decided_leaves_an_empty_page_and_back_shows_the_group_gone(browser, small_groups):  # noqa: F811
    """Accept N asks first and covers the group. The page then says nothing is pending, a reload keeps it, and Back's page has no
    such group."""
    for p in served_page(browser, small_groups, setup=suggest_logons):
        open_logons(p)
        before = total(p)
        open_group(p)
        head_button(p, "Accept 4").click()
        with p.expect_response(SUBMITTED):
            confirm(p.locator("#details .sg-group"))
        p.locator("#details").get_by_text("Nothing is pending in this group.").wait_for()
        assert p.locator("#details .sg-group").count() == 0
        assert p.locator("#details h2").inner_text() == ZED
        reload(p)
        on_page(p, zed_page())
        p.locator("#details").get_by_text("Nothing is pending in this group.").wait_for()
        back(p, "suggestions:logons")
        assert ZED not in order(p)
        assert total(p) == before - 4


def test_ticks_stay_per_page_and_a_decided_row_leaves_them(browser, small_groups):  # noqa: F811
    """A tick on the page of groups isn't one on the group's page, or the other way round. A ticked decision acts on those rows
    and dims them, and a row's own decision takes its tick off. A find narrows the rows and stays through a decision."""
    for p in served_page(browser, small_groups, setup=suggest_logons):
        open_logons(p)
        rows(p, ZED).nth(0).locator("input[type=checkbox]").click()
        open_group(p)
        assert page_ticked(p) == []
        for index in (0, 1, 2):
            page_rows(p).nth(index).locator("input[type=checkbox]").click()
        assert head_button(p, "Reject 3 ticked").is_visible()
        press_row(p, 0, "Reject", 3)
        assert page_ticked(p) == [1, 2]   # the decided row has no tick to show
        assert head_button(p, "Reject 2 ticked").is_visible()
        with p.expect_request(SUBMITTED) as sent:
            head_button(p, "Accept 2 ticked").click()
        page_count_is(p, 1)
        assert len(sent.value.post_data_json["uids"]) == 2
        assert p.locator(f"#details li{DECIDED}").count() == 3
        assert page_ticked(p) == []
        page_rows(p).nth(3).locator("input[type=checkbox]").click()
        back(p, "suggestions:logons")
        assert ticked(p, ZED) == []
        open_group(p)
        assert page_ticked(p) == []
        box = p.locator(f"{HEAD} .find input")
        box.fill("no such row")
        assert p.locator(f"{HEAD} .find-words").inner_text() == "0 of 1 row matches"
        box.fill("logon")
        press_row(p, 0, "Reject", 0)
        assert p.locator(f"{HEAD} .find input").count() == 0   # a group with none pending has no find
        assert p.locator(f"#details li{DECIDED}").count() == 1


def test_show_all_first_keeps_the_group_page_and_a_reload_keeps_the_list(browser, cut_group):  # noqa: F811
    """The confirm's Show all N first lists the whole group on its own page, and a reload lists it again, whether on that page or
    during its review. Back's page is then the page of groups as it first draws, cut at the limit."""
    n = PENDING_LIMIT + 10
    for p in served_page(browser, cut_group, setup=suggest_logons):
        open_logons(p)
        open_group(p)
        head_button(p, f"Reject {n}").click()
        p.locator("#details .confirm-block").get_by_role("button", name=f"Show all {n} first").click()
        p.wait_for_function("(n) => document.querySelectorAll('#details .sg-events li').length === n", arg=n)
        on_page(p, zed_page())
        reload(p)
        on_page(p, zed_page())
        assert page_rows(p).count() == n
        start_review(p, f"{ZED} (logons): 1 of {n}")
        reload(p)
        on_page(p, zed_page())
        assert page_rows(p).count() == n
        back(p, "suggestions:logons")
        p.wait_for_function(COUNT_IS, arg=[ZED, f"{n} pending"])
        assert rows(p, ZED).count() == PENDING_LIMIT + 1   # with the row that says the list is cut


def test_a_decision_out_on_the_group_page_reaches_the_page_back_opened(browser, small_groups):  # noqa: F811
    """Back while a row's decision is out: the page of groups reads the group as the server still has it, and draws again with the
    true count once the decision answers."""
    for p in served_page(browser, small_groups, setup=suggest_logons):
        open_logons(p)
        open_group(p)
        held = Held(p, "/api/suggestion")
        page_rows(p).nth(0).get_by_role("button", name="Reject", exact=True).click()
        wait_held(p, held.routes)
        back(p, "suggestions:logons")
        p.wait_for_function(COUNT_IS, arg=[ZED, "4 pending"])
        held.release()
        p.wait_for_function(COUNT_IS, arg=[ZED, "3 pending"])


def test_a_late_redraw_keeps_the_find_box_in_use_and_its_caret(browser, small_groups):  # noqa: F811
    """Typing in a group's find on the page Back opened while a decision is out: the decision's redraw draws a new box, which has
    the text, the focus, and the caret, so typing goes on where it was."""
    for p in served_page(browser, small_groups, setup=suggest_logons):
        open_logons(p)
        open_group(p)
        held = Held(p, "/api/suggestion")
        page_rows(p).nth(0).get_by_role("button", name="Reject", exact=True).click()
        wait_held(p, held.routes)
        back(p, "suggestions:logons")
        p.wait_for_function(COUNT_IS, arg=[ZED, "4 pending"])
        box = group(p, ZED).locator(".find input")
        box.click()
        p.keyboard.type("abc")
        p.keyboard.press("ArrowLeft")
        held.release()
        p.wait_for_function(COUNT_IS, arg=[ZED, "3 pending"])
        p.keyboard.type("x")
        assert box.input_value() == "abxc"


def test_a_review_decision_out_reaches_the_page_back_opened(browser, small_groups):  # noqa: F811
    """Back while a review's decision is out: the group's page draws again with the true count, and the review doesn't move on."""
    for p in served_page(browser, small_groups, setup=suggest_logons):
        open_logons(p)
        open_group(p)
        start_review(p, f"{ZED} (logons): 1 of 4")
        held = Held(p, "/api/suggestion")
        p.keyboard.press("a")
        wait_held(p, held.routes)
        back(p, zed_page())
        page_count_is(p, 4)
        held.release()
        page_count_is(p, 3)
        assert p.evaluate("() => document.getElementById('details').dataset.key") == zed_page()


def test_a_decision_out_on_the_groups_reaches_the_group_page_its_title_opened(browser, small_groups):  # noqa: F811
    """A title clicked while a row's decision is out: the group's page reads the group as the server still has it, and draws again
    once the decision answers, so its count and its review's queue are true."""
    for p in served_page(browser, small_groups, setup=suggest_logons):
        open_logons(p)
        held = Held(p, "/api/suggestion")
        rows(p, ZED).nth(0).get_by_role("button", name="Reject", exact=True).click()
        wait_held(p, held.routes)
        open_group(p)
        page_count_is(p, 4)
        held.release()
        page_count_is(p, 3)
        start_review(p, f"{ZED} (logons): 1 of 3")


def test_an_accept_out_reaches_another_sources_page_asked_for_meanwhile(browser, hit_case):  # noqa: F811
    """An event two sources suggest: the accept marks it, so it leaves the other source's pending events too, and that page, read
    while the accept was out, draws again with the true count."""
    eve = "C137\\eve"
    for p in served_page(browser, hit_case, setup=suggest_logons):
        open_suggestions(p)
        open_group(p, HIT_TITLE, "rule", "hayabusa")
        held = Held(p, "/api/suggestion")
        page_rows(p).nth(0).get_by_role("button", name="Accept", exact=True).click()
        wait_held(p, held.routes)
        p.evaluate("() => import('/js/suggestions.js').then((m) => m.showSuggestions('logons'))")
        on_page(p, "suggestions:logons")
        p.wait_for_function(COUNT_IS, arg=[eve, "4 pending"])
        held.release()
        p.wait_for_function(COUNT_IS, arg=[eve, "3 pending"])


@pytest.mark.parametrize(("press", "read"), [
    pytest.param(lambda p: p.locator(f"#details {TITLE}", has_text=HIT_TITLE), "/api/pending", id="title"),
    pytest.param(lambda p: head_button(p, "Review one by one"), "/api/event", id="review"),
    pytest.param(lambda p: p.locator("#details").get_by_role("button", name=RULE_LINK), "/api/search", id="rule search"),
])
def test_a_double_click_sends_one_request_and_opens_one_page(browser, hit_case, press, read):  # noqa: F811
    """With the read held so the second click comes before the page draws, one read goes out and one page joins Back."""
    for p in served_page(browser, hit_case):
        open_suggestions(p)
        if read != "/api/pending":
            open_group(p, HIT_TITLE, "rule", "hayabusa")
        back_before = p.evaluate("() => window.__app.S.back.length")
        held = Held(p, read)
        press(p).dblclick()
        wait_held(p, held.routes)
        p.wait_for_timeout(100)
        assert len(held.routes) == 1
        page = p.evaluate("() => document.getElementById('details').dataset.key")
        held.release()
        p.wait_for_function("(key) => document.getElementById('details').dataset.key !== key", arg=page)
        p.wait_for_timeout(100)
        assert p.evaluate("() => window.__app.S.back.length") == back_before + 1


def test_the_second_click_lands_on_nothing_when_the_page_drew_between_the_clicks(browser, synthetic_case):  # noqa: F811
    """The group's page draws before the second click, which lands on a row: the row doesn't open."""
    add_logons(synthetic_case, ["zed"] * 13 + ["ann"] * 12)
    for p in served_page(browser, synthetic_case, setup=suggest_logons):
        open_logons(p)
        title = group(p, ANN).locator(TITLE)
        title.scroll_into_view_if_needed()
        box = title.bounding_box()
        x, y = box["x"] + 5, box["y"] + box["height"] / 2
        p.mouse.move(x, y)
        p.mouse.down(click_count=1)
        p.mouse.up(click_count=1)
        on_page(p, zed_page(key=ANN))
        assert p.evaluate("([x, y]) => !!document.elementFromPoint(x, y).closest('.sg-events li')", [x, y])
        p.evaluate(RECORD_REQUESTS)
        p.mouse.down(click_count=2)
        p.mouse.up(click_count=2)
        p.wait_for_timeout(200)
        on_page(p, zed_page(key=ANN))
        assert p.evaluate("() => window.__asked") == []
        # A later click is an ordinary one, and opens the row
        p.mouse.down(click_count=1)
        p.mouse.up(click_count=1)
        p.wait_for_selector("#details[data-page='event'] .ev-ident")


def test_a_reload_returns_to_the_group_page_with_back_to_the_groups(browser, small_groups):  # noqa: F811
    """F5 comes back to the group's page, its ticks gone and its count true, and Back still leads to the page of groups, as it was
    grouped. F5 on the page of groups stays there."""
    for p in served_page(browser, small_groups, setup=suggest_logons):
        open_logons(p)
        open_group(p)
        press_row(p, 0, "Reject", 3)
        reload(p)
        on_page(p, zed_page())
        page_count_is(p, 3)
        assert p.locator("#details h2").inner_text() == ZED
        assert status(p).startswith("Back where the page was before the reload.")
        assert back_says(p) == "Back to logons suggestions"
        back(p, "suggestions:logons")
        p.wait_for_function(COUNT_IS, arg=[ZED, "3 pending"])
        assert p.locator("#details select").input_value() == "account"
        reload(p)
        on_page(p, "suggestions:logons")
        assert p.locator("#detailsBand button.back").count() == 0


def test_a_reload_during_a_group_review_lands_on_the_group_page_with_no_review(browser, small_groups):  # noqa: F811
    """F5 on a review's Event page lands on the group's page and says why. No review runs: no bar, and the keys do nothing."""
    for p in served_page(browser, small_groups, setup=suggest_logons):
        open_logons(p)
        open_group(p)
        start_review(p, f"{ZED} (logons): 1 of 4")
        p.keyboard.press("n")
        p.wait_for_function(BAR_READS, arg=f"{ZED} (logons): 2 of 4")
        journaled = len(entries(small_groups))
        reload(p)
        on_page(p, zed_page())
        assert p.locator("#details .review-bar").count() == 0
        assert "A review stops at a reload, so this is the group's page." in status(p)
        p.keyboard.press("a")
        p.wait_for_timeout(100)
        assert len(entries(small_groups)) == journaled
        page_rows(p).nth(1).locator(".sg-text").click()
        p.wait_for_selector("#details[data-page='event'] .ev-ident")
        assert p.locator("#details .review-bar").count() == 0


@pytest.mark.parametrize("stopped", [True, False], ids=["group review stopped", "whole source review"])
def test_a_reload_keeps_the_event_page_outside_a_group_review(browser, small_groups, stopped):  # noqa: F811
    """A group's review that was stopped, and To investigate's review of a whole source, leave a reload on the Event page."""
    for p in served_page(browser, small_groups, setup=suggest_logons):
        if stopped:
            open_logons(p)
            open_group(p)
            start_review(p, f"{ZED} (logons): 1 of 4")
            p.locator("#details .review-bar").get_by_role("button", name="Stop reviewing").click()
            p.wait_for_selector("#details .review-bar", state="detached")
        else:
            open_worklist(p)
            p.locator(f"{INVESTIGATE} .rule[data-source='logons']").get_by_role("button", name="Review one by one").click()
            p.wait_for_selector("#details .review-bar")
            assert re.fullmatch(r"logons: 1 of \d+", p.locator("#details .review-bar strong").inner_text())
            assert p.locator("#details .review-bar .muted.keys").count() == 1
        event = p.evaluate("() => document.getElementById('details').dataset.key")
        assert event.startswith("event:")
        reload(p)
        on_page(p, event)


def test_a_whole_source_review_keeps_its_words_and_its_steps_back(browser, small_groups):  # noqa: F811
    """To investigate's review names no group, and Back steps through its events, each a place in the history."""
    for p in served_page(browser, small_groups, setup=suggest_logons):
        open_worklist(p)
        row = p.locator(f"{INVESTIGATE} .rule[data-source='logons']")
        pending = int(re.match(r"\d+", row.locator(".rule-pending").inner_text()).group())
        row.get_by_role("button", name="Review one by one").click()
        p.wait_for_function(BAR_READS, arg=f"logons: 1 of {pending}")
        p.keyboard.press("n")
        p.wait_for_function(BAR_READS, arg=f"logons: 2 of {pending}")
        p.locator("#detailsBand button.back").click()
        p.wait_for_function(BAR_READS, arg=f"logons: 1 of {pending}")
        for at in range(2, pending + 1):
            p.keyboard.press("n")
            p.wait_for_function(BAR_READS, arg=f"logons: {at} of {pending}")
        p.keyboard.press("n")
        p.wait_for_function(BAR_READS, arg=f"logons: {pending} events reviewed")
        assert p.locator("#details .review-bar .muted").inner_text() == "That was the last of the set To investigate counted."


def test_a_hayabusa_group_links_to_every_event_the_rule_hit_in_any_state(browser, hit_case):  # noqa: F811
    """The link runs the search the Overview's rule titles run, without their host, and lists the event already marked, which the
    group's count leaves out. Back returns to the group's page, with the same count."""
    def mark_one(app):
        marked = app.con.execute("SELECT event_uid FROM events WHERE tool = 'evtxecmd' AND source_file = ? ORDER BY ts_us",
                                 [HIT_LOG]).fetchone()[0]
        api_mark(app, {"uids": [marked], "value": "malicious"})

    for p in served_page(browser, hit_case, setup=mark_one):
        open_suggestions(p)
        open_group(p, HIT_TITLE, "rule", "hayabusa")
        assert p.locator("#details h2 .chip").inner_text() == "high"
        page_count_is(p, 2)
        p.locator("#details").get_by_role("button", name=RULE_LINK).click()
        query = f'rule:"{HIT_TITLE}"'
        p.wait_for_function(SEARCH_LISTS, arg=[query, 3])
        assert p.locator("#search").input_value() == query
        back(p, zed_page("rule", HIT_TITLE, "hayabusa"))
        page_count_is(p, 2)


def test_no_rule_link_for_a_quoted_title_another_grouping_or_a_signature(browser, suricata_case):  # noqa: F811
    """A title holding a double quote can't be written as a search, a group by host isn't a rule, and a signature isn't a Hayabusa
    rule. Each page still has the review."""
    add_hits(suricata_case, QUOTED_TITLE, 1, start=2000)
    for p in served_page(browser, suricata_case):
        no_link = p.locator("#details").get_by_role("button", name=RULE_LINK)
        open_suggestions(p)
        open_group(p, QUOTED_TITLE, "rule", "hayabusa")
        assert no_link.count() == 0 and head_button(p, "Review one by one").count() == 1
        back(p, "suggestions:hayabusa")
        p.locator("#details select").select_option("host")
        p.wait_for_function("() => document.querySelector('#details select').value === 'host' && "
                            "[...document.querySelectorAll('#details .sg-head strong')].some((n) => n.textContent === 'DC01')")
        group(p, "DC01").locator(TITLE).click()
        on_page(p, zed_page("host", "DC01", "hayabusa"))
        assert no_link.count() == 0 and head_button(p, "Review one by one").count() == 1
        open_suggestions(p, "suricata")
        group(p, METASPLOIT).locator(TITLE).click()
        on_page(p, zed_page("rule", METASPLOIT, "suricata"))
        assert p.locator("#details h2 .chip").inner_text() == "severity 1"
        assert no_link.count() == 0 and head_button(p, "Review one by one").count() == 1


@pytest.mark.parametrize("title", ["Wild * card", "x" * (LONGEST_TITLE + 1)], ids=["a wildcard", "past the longest search"])
def test_no_rule_link_where_the_search_would_not_list_that_rule(browser, synthetic_case, title):  # noqa: F811
    """A * in a title is a wildcard in rule:, so the search would list the other rule's event too, and the server refuses a search
    past the longest. The page still has its count and the review."""
    add_hits(synthetic_case, title, 2)
    add_hits(synthetic_case, "Wild xyz card", 1, start=2000)
    for p in served_page(browser, synthetic_case):
        open_suggestions(p)
        open_group(p, title, "rule", "hayabusa")
        page_count_is(p, 2)
        assert p.locator("#details").get_by_role("button", name=RULE_LINK).count() == 0
        assert head_button(p, "Review one by one").count() == 1


@pytest.mark.parametrize("title", ["x" * LONGEST_TITLE, "Wild %_? card"], ids=["the longest", "LIKE's own wildcards"])
def test_a_rule_link_lists_that_rule_alone(browser, synthetic_case, title):  # noqa: F811
    """The longest title a search can hold still links, and % and _ are plain in rule:, so its search lists this rule's two events
    and not the other rule's."""
    add_hits(synthetic_case, title, 2)
    add_hits(synthetic_case, "Wild xyz? card", 1, start=2000)
    for p in served_page(browser, synthetic_case):
        open_suggestions(p)
        open_group(p, title, "rule", "hayabusa")
        p.locator("#details").get_by_role("button", name=RULE_LINK).click()
        p.wait_for_function(SEARCH_LISTS, arg=[f'rule:"{title}"', 2])


@pytest.mark.parametrize("width", [1400, 800, 380])
def test_the_group_page_holds_its_head_and_the_bar_its_name_at_each_width(browser, synthetic_case, width):  # noqa: F811
    """With a long unbroken group name, ticks, and a find, each head control is whole inside the panel, and the page's name, the
    review bar, and the band stay inside it too."""
    long_name = "svc_" + "very_long_account_name_" * 6
    add_logons(synthetic_case, [long_name] * 3)
    key = f"C137\\{long_name}"
    for p in served_page(browser, synthetic_case, setup=suggest_logons):
        p.set_viewport_size({"width": width, "height": 900})
        open_logons(p)
        wide = "(n) => n.scrollWidth <= n.clientWidth + 1"
        among_the_groups = group(p, key).locator(".sg-head")
        assert among_the_groups.evaluate(SPILLS) == [] and among_the_groups.locator("strong").evaluate(wide)
        open_group(p, key)
        head = p.locator(HEAD)
        assert p.locator("#details h2 span").first.evaluate(wide)
        # The review leads the page: in view with no scrolling, even with the panel at its narrowest
        panel_bottom = p.locator("#detailsBody").bounding_box()
        review = head_button(p, "Review one by one").bounding_box()
        assert review["y"] + review["height"] <= panel_bottom["y"] + panel_bottom["height"]
        assert p.locator("#detailsBody").evaluate(wide)
        assert head.evaluate(SPILLS) == []
        page_rows(p).nth(0).locator("input[type=checkbox]").click()
        assert head_button(p, "Accept 1 ticked").is_visible() and head.evaluate(SPILLS) == []
        p.locator(f"{HEAD} .find input").fill("no such row")
        assert p.locator(f"{HEAD} .find-ticks").is_visible() and head.evaluate(SPILLS) == []
        p.locator(f"{HEAD} .find input").fill("")
        assert p.locator("#detailsBand").evaluate(SPILLS) == []
        start_review(p, f"{key} (logons): 1 of 3")
        assert p.locator("#details .review-bar").evaluate(SPILLS) == []
        assert p.locator("#detailsBody").evaluate(wide)
        assert p.locator("#detailsBand").evaluate(SPILLS) == []
