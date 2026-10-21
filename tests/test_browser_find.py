"""The find box on each list of events in the Details panel, in a real browser: its
match rule, its count, the rows hidden and the words marked, the text kept through a tick, a mark, and the counts drawn
later, a new page starting empty, the reach line on a cut list with the search over every match, and Select all under a
find. They drive the installed Microsoft Edge through Playwright, as test_browser_smoke does, and are skipped without it."""

import pytest
from conftest import DC_LOG, SEC, T0, logon
from test_browser_investigate import COUNTED, INVESTIGATE, open_worklist, uid_at
from test_browser_smoke import browser, event_point, served_page  # noqa: F401
from test_pivots import load_events

from glessner.server import api_mark, api_rule

pytestmark = pytest.mark.browser
SEARCH = "#details[data-page='search']"


def find_box(p, scope):
    return p.locator(f"{scope} .find input")


def shown_rows(p, scope, rows="li.rel-row"):
    return p.locator(f"{scope} {rows}:not(.find-out)")


def marks_in(p, scope):
    return p.locator(f"{scope} mark.find-hit").all_inner_texts()


def search(p, query):
    p.locator("#search").fill(query)
    p.locator("#search").press("Enter")
    p.wait_for_selector(f"{SEARCH} li.rel-row")


def mark_three(found):
    """The RDP logon Malicious and two more Suspicious, two on DC01 and one on DESKTOP, before the page opens."""
    def setup(app):
        found["rdp"] = uid_at(app, T0)
        found["morty"] = uid_at(app, T0 + 60 * SEC)
        found["ws"] = uid_at(app, T0 + 874 * SEC)
        api_mark(app, {"uids": [found["rdp"]], "value": "malicious", "note": "RDP from the internet"})
        api_mark(app, {"uids": [found["morty"], found["ws"]], "value": "suspicious", "note": ""})
    return setup


def test_the_find_narrows_to_investigate_and_keeps_its_text_through_a_tick_and_the_counts(browser, synthetic_case):  # noqa: F811
    """The box in the list's head: every word must match, in any order and letter case, against the row's time, host, and
    event; the rows that don't are hidden, the words are marked, the count reads "2 of 3 rows match", and the foot says
    what stays whole. The meter and the counts never change. A tick redraws the page with the find kept, the counts drawn
    later land in the hidden rows too, Escape and Clear empty it, and a new page starts empty."""
    found = {}
    for p in served_page(browser, synthetic_case, setup=mark_three(found)):
        open_worklist(p)
        head = p.locator(f"{INVESTIGATE} .inv-head.sticky-head")
        box = head.locator(".find input")
        assert box.get_attribute("placeholder") == box.get_attribute("aria-label") == "Find in this list"
        assert box.get_attribute("title") == ("Shows only the rows holding every word, in any column. The meter and the counts "
                                              "still cover every row.")
        assert head.locator(".find-words").is_hidden() and head.locator(".find-clear").is_hidden()
        rows = f"{INVESTIGATE} ul.worklist li.rel-row"
        assert p.locator(rows).count() == 3
        box.fill("DC01 4624")
        assert shown_rows(p, f"{INVESTIGATE} ul.worklist").locator(".rel-host").all_inner_texts() == ["DC01", "DC01"]
        hidden = p.locator(f"{rows}.find-out")
        assert hidden.count() == 1 and hidden.is_hidden() and hidden.locator(".rel-host").text_content() == "DESKTOP"
        assert head.locator(".find-words").inner_text() == "2 of 3 rows match"
        assert marks_in(p, f"{INVESTIGATE} ul.worklist") == ["DC01", "4624", "DC01", "4624"]
        assert head.locator(".meter-words").inner_text() == "0 of 3 followed up"
        foot = p.locator(f"{INVESTIGATE} .find-foot")
        assert foot.inner_text() == ("1 row doesn't hold every word of the find. The meter and the counts still cover all 3. "
                                     "Clear the find")
        with p.expect_response("**/api/followup"):
            shown_rows(p, f"{INVESTIGATE} ul.worklist").first.locator(".inv-tick").click()
        p.wait_for_function(f'() => document.querySelector("{INVESTIGATE} .meter-words").textContent === "1 of 3 followed up"')
        assert find_box(p, INVESTIGATE).input_value() == "DC01 4624"
        assert shown_rows(p, f"{INVESTIGATE} ul.worklist").count() == 2
        p.wait_for_function(COUNTED)
        assert shown_rows(p, f"{INVESTIGATE} ul.worklist").count() == 2
        assert p.locator(rows).count() == 3 and p.locator(f"{INVESTIGATE} .find-words").inner_text() == "2 of 3 rows match"
        box = find_box(p, INVESTIGATE)
        box.fill("4624 dc01")
        assert p.locator(f"{INVESTIGATE} .find-words").inner_text() == "2 of 3 rows match"
        box.fill("4648")
        assert p.locator(f"{INVESTIGATE} .find-words").inner_text() == "0 of 3 rows match"
        assert p.locator(f"{INVESTIGATE} .find-foot").inner_text().startswith("3 rows don't hold every word of the find.")
        box.press("Escape")
        assert box.input_value() == "" and shown_rows(p, f"{INVESTIGATE} ul.worklist").count() == 3
        assert p.locator(f"{INVESTIGATE} .find-foot").is_hidden() and p.locator(f"{INVESTIGATE} .find-words").is_hidden()
        assert p.locator(f"{INVESTIGATE} mark.find-hit").count() == 0
        box.fill("desktop")
        assert shown_rows(p, f"{INVESTIGATE} ul.worklist").locator(".rel-host").all_inner_texts() == ["DESKTOP"]
        p.locator(f"{INVESTIGATE} .find-foot").get_by_role("button", name="Clear the find").click()
        assert box.input_value() == "" and p.locator(f"{INVESTIGATE} .find-foot").is_hidden()
        box.fill("desktop")
        p.locator(f"{INVESTIGATE} .find").get_by_role("button", name="Clear").click()
        assert box.input_value() == "" and shown_rows(p, f"{INVESTIGATE} ul.worklist").count() == 3
        box.fill("desktop")
        p.locator("#tabTimeline").click()
        open_worklist(p)
        assert find_box(p, INVESTIGATE).input_value() == "" and shown_rows(p, f"{INVESTIGATE} ul.worklist").count() == 3


def test_select_all_under_a_find_ticks_the_shown_rows_and_the_ticks_made_before_stay(browser, synthetic_case):  # noqa: F811
    """On a search's list: a tick made before the find stays and counts for the mark buttons, the head says how many ticked
    rows the find hides, Select all reads "Select the 3 shown" and ticks those rows only, and reads "Unselect the 3 shown"
    once they are all ticked. The heading's count never changes. Without a find, Select all is about every row again."""
    for p in served_page(browser, synthetic_case):
        search(p, "DC01")
        rows = p.locator(f"{SEARCH} li.rel-row")
        n = rows.count()
        assert n >= 5
        heading = p.locator(f"{SEARCH} .sticky-head strong").inner_text()
        rows.filter(has_text="4672").first.locator("input[type=checkbox]").check()
        head = p.locator(f"{SEARCH} .sticky-head")
        assert head.get_by_role("button", name="Mark 1 Malicious").count() == 1
        find_box(p, SEARCH).fill("desktop")
        shown = shown_rows(p, SEARCH)
        k = shown.count()
        assert 0 < k < n and shown.locator(".rel-host").all_inner_texts() == ["DESKTOP"] * k
        assert head.locator(".find-words").inner_text() == f"{k} of {n} rows match"
        assert head.locator(".find-ticks").inner_text() == "1 ticked event isn't shown here"
        assert p.locator(f"{SEARCH} .sticky-head strong").inner_text() == heading
        head.get_by_role("button", name=f"Select the {k} shown").click()
        assert p.evaluate("() => window.__app.S.searchChecked.set.size") == k + 1
        head = p.locator(f"{SEARCH} .sticky-head")   # the list redrew
        assert head.get_by_role("button", name=f"Mark {k + 1} Malicious").count() == 1
        assert head.get_by_role("button", name=f"Unselect the {k} shown").count() == 1
        assert find_box(p, SEARCH).input_value() == "desktop" and shown_rows(p, SEARCH).count() == k
        assert head.locator(".find-ticks").inner_text() == "1 ticked event isn't shown here"
        assert p.locator(f"{SEARCH} .sticky-head strong").inner_text() == heading
        head.get_by_role("button", name=f"Unselect the {k} shown").click()
        assert p.evaluate("() => window.__app.S.searchChecked.set.size") == 1   # the hidden tick stays
        head = p.locator(f"{SEARCH} .sticky-head")
        assert head.get_by_role("button", name=f"Select the {k} shown").count() == 1
        find_box(p, SEARCH).fill("")
        assert head.get_by_role("button", name="Select all").count() == 1 and head.locator(".find-ticks").is_hidden()
        assert shown_rows(p, SEARCH).count() == n


def test_the_find_on_a_cut_search_list_says_its_reach_and_offers_the_search_over_every_match(browser, synthetic_case):  # noqa: F811
    """A search of 600 matches lists 500: the box reads "Find in the 500 listed", the count "11 of the 500 listed match", and
    a line over the list says the find reaches the listed rows only, with the search run again with the find's words
    added, which starts a new page with an empty find."""
    bulk = [logon(T0 + (2000 + i) * SEC, 5000 + i, DC_LOG, user=f"bulk{i}", ltype="3") for i in range(600)]
    load_events(synthetic_case, bulk, "DC01", run="p-bulk")
    for p in served_page(browser, synthetic_case):
        search(p, "bulk")
        assert p.locator(f"{SEARCH} li.rel-row").count() == 500
        box = find_box(p, SEARCH)
        assert box.get_attribute("placeholder") == box.get_attribute("aria-label") == "Find in the 500 listed"
        assert box.get_attribute("title") == ("Shows only the listed rows holding every word. It reaches the 500 listed, not "
                                              "every match.")
        box.fill("bulk7")
        head = p.locator(f"{SEARCH} .sticky-head")
        assert head.locator(".find-words").inner_text() == "11 of the 500 listed match"
        assert shown_rows(p, SEARCH).count() == 11
        foot = p.locator(f"{SEARCH} .find-foot")
        assert foot.inner_text() == ('The find reaches the 500 listed rows only; 100 more matches aren\'t listed. '
                                     'Search all 600 for "bulk7"')
        assert foot.bounding_box()["y"] < p.locator(f"{SEARCH} ul.rows").bounding_box()["y"]   # over the list
        # The search is offered only for plain words: one with a leading "-", a ":", a quote, or a "*" would mean
        # something else in the search box, so the line keeps its reach and loses the link
        for text in ("bulk7 -logon", "bulk7 code:4624", 'bulk7 "logon"', "bulk*"):
            box.fill(text)
            assert foot.inner_text() == "The find reaches the 500 listed rows only; 100 more matches aren't listed.", text
            assert foot.locator("button").count() == 0, text
        box.fill("bulk7")
        foot.get_by_role("button", name='Search all 600 for "bulk7"').click()
        p.wait_for_selector("#details[data-key='search:bulk bulk7'] li.rel-row")
        assert p.locator("#search").input_value() == "bulk bulk7"
        assert p.locator(f"{SEARCH} .sticky-head strong").inner_text().startswith("11 matching events")
        assert find_box(p, SEARCH).input_value() == "" and shown_rows(p, SEARCH).count() == 11
        assert find_box(p, SEARCH).get_attribute("placeholder") == "Find in this list"


def test_the_find_on_a_pivot_list_is_kept_through_a_mark_and_the_next_pivot_starts_empty(browser, synthetic_case):  # noqa: F811
    """The pivot list's head has the box; a mark from the list redraws it with the find kept; another pivot on the same Event
    page is another list and starts empty."""
    for p in served_page(browser, synthetic_case):
        rdp = event_point(p, "4624", hit=True)
        p.evaluate("(uid) => window.__app.select(uid, false)", rdp["uid"])
        p.wait_for_selector("#details[data-page='event'] .pv")
        p.locator('#details .pv[data-pivot="session"] button.pv-go').click()
        p.locator("#relatedList strong", has_text="with the same host and logon ID").wait_for()
        n = p.locator("#relatedList li.rel-row").count()
        heading = p.locator("#relatedList .sticky-head strong").inner_text()
        find_box(p, "#relatedList").fill("4672")
        shown = shown_rows(p, "#relatedList")
        assert shown.count() == 1 and "4672" in shown.inner_text()
        assert p.locator("#relatedList .find-words").inner_text() == f"1 of {n} {'row matches' if n == 1 else 'rows match'}"
        assert p.locator("#relatedList .sticky-head strong").inner_text() == heading
        shown.first.locator("input[type=checkbox]").check()
        p.locator("#relatedList").get_by_role("button", name="Mark 1 Suspicious").click()
        p.wait_for_function("() => document.querySelector('#relatedList li.rel-row:not(.find-out) .badge')?.textContent === 'S'")
        assert find_box(p, "#relatedList").input_value() == "4672" and shown_rows(p, "#relatedList").count() == 1
        p.locator('#details .pv[data-pivot="window"] button.pv-go').click()
        p.locator("#relatedList strong", has_text="within").wait_for()
        assert find_box(p, "#relatedList").input_value() == ""
        # A tick another pivot left in the shared set counts too, find or no find: the mark buttons act on it
        assert p.locator("#relatedList .find-ticks").is_hidden()
        p.evaluate("() => { window.__app.S.pivotChecked.add('left-by-another-pivot'); }")
        p.evaluate("() => import('/js/pages.js').then((m) => m.renderRelated())")
        assert p.locator("#relatedList .find-ticks").inner_text() == "1 ticked event isn't shown here"
        assert p.locator("#relatedList").get_by_role("button", name="Mark 1 Malicious").count() == 1
        find_box(p, "#relatedList").fill("no such row")
        assert p.locator("#relatedList .find-ticks").inner_text() == "1 ticked event isn't shown here"


def test_each_suggestions_group_has_a_find_kept_through_a_decision(browser, synthetic_case):  # noqa: F811
    """A rule that suggests every 4624: its group's head has the box, the find narrows the group's rows, and an Accept on a
    shown row refreshes the page with the find kept."""
    def rule(app):
        api_rule(app, {"op": "add", "text": "id: logons\nsuggest: suspicious\nwhen: {field: event_code, equals: '4624'}\n"})

    for p in served_page(browser, synthetic_case, setup=rule):
        open_worklist(p)
        p.locator(f"{INVESTIGATE} .rule[data-source='logons'] button.rule-name").click()
        p.wait_for_selector("#details[data-page='suggestions'] .sg-group")
        group = p.locator("#details .sg-group").first   # the rule's pending events group by account; the first is the largest
        rows = "li:not(.sg-more)"
        n = group.locator(f".sg-events {rows}").count()
        total = p.locator(f"#details .sg-group .sg-events {rows}").count()
        on_desktop = group.locator(f".sg-events {rows}", has_text="DESKTOP").count()
        assert n >= 3 and 0 < on_desktop < n and total >= n
        box = group.locator(".sg-head .find input")
        assert box.get_attribute("placeholder") == "Find in this list"
        box.fill("desktop")
        assert group.locator(f".sg-events {rows}:not(.find-out)").count() == on_desktop
        assert group.locator(".find-words").inner_text() == f"{on_desktop} of {n} rows match"
        assert group.locator("mark.find-hit").all_inner_texts() == ["DESKTOP"] * on_desktop
        assert group.locator(".sg-head .muted").first.inner_text() == f"{n} pending"   # the group's count never changes
        with p.expect_response("**/api/suggestion"):
            group.locator(f".sg-events {rows}:not(.find-out)").first.get_by_role("button", name="Accept").click()
        p.wait_for_function(f"() => document.querySelectorAll('#details .sg-group .sg-events {rows}').length === {total - 1}")
        group = p.locator("#details .sg-group").first
        assert group.locator(f".sg-events {rows}").count() == n - 1
        assert group.locator(".sg-head .find input").input_value() == "desktop"
        assert group.locator(f".sg-events {rows}:not(.find-out)").count() == on_desktop - 1


def test_the_pile_list_has_a_find(browser, synthetic_case):  # noqa: F811
    """The events under one pixel list with the box in their head; the find narrows them and marks the words."""
    for p in served_page(browser, synthetic_case):
        pile = event_point(p, "4672")
        p.mouse.click(pile["x"], pile["y"])
        p.wait_for_selector("#details[data-page='pile'] li")
        scope = "#details[data-page='pile']"
        n = p.locator(f"{scope} ul.badged li").count()
        assert n > 2
        find_box(p, scope).fill("4672")
        assert shown_rows(p, scope, "ul.badged li").count() == 1
        assert p.locator(f"{scope} .find-words").inner_text() == f"1 of {n} rows match"
        assert marks_in(p, scope) == ["4672"]
        assert p.locator(f"{scope} .find-foot").inner_text().startswith(f"{n - 1} rows don't hold every word of the find. "
                                                                        f"The count still covers all {n}.")


def test_the_show_them_list_has_a_find(browser, synthetic_case):  # noqa: F811
    """The Findings page's list of marked events in no finding has the box; Select the 1 shown ticks that row, and the
    find is kept through the redraw."""
    found = {}
    for p in served_page(browser, synthetic_case, setup=mark_three(found)):
        p.locator("#tabFindings").click()
        p.wait_for_selector("#details[data-page='findings'] .unassigned")
        p.locator("#details .unassigned").get_by_role("button", name="Show them").click()
        p.wait_for_function("() => document.querySelectorAll('#details .unassigned-list li.rel-row').length === 3")
        scope = "#details .unassigned-list"
        find_box(p, scope).fill("desktop")
        assert shown_rows(p, scope).count() == 1 and p.locator(f"{scope} .find-words").inner_text() == "1 of 3 rows match"
        assert p.locator(f"{scope} .actions strong").inner_text() == "3 marked events in no finding"
        p.locator(scope).get_by_role("button", name="Select the 1 shown").click()
        assert p.locator(scope).get_by_role("button", name="New finding from the 1 ticked").count() == 1
        assert find_box(p, scope).input_value() == "desktop" and shown_rows(p, scope).count() == 1
        assert p.locator(scope).get_by_role("button", name="Unselect the 1 shown").count() == 1
