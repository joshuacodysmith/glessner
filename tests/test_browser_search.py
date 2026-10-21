"""Search in a real browser: quotes as whole words, the Whole word tick, highlights that follow the bound, the help,
the forgiving-search line, the zero-result hint, and the rule links. They drive the installed Microsoft Edge through
Playwright, as test_browser_smoke does, and are skipped without it."""

import re

import pytest
from conftest import SEC, T0
from test_browser_smoke import browser, served_page  # noqa: F401

from glessner.events import Event, load

pytestmark = pytest.mark.browser
SOURCE = "DC01/Windows/System32/winevt/Logs/Application.evtx"
# A word inside another (WinMaps), after an underscore, and before a digit; one with a line break after it; and one between
# accented letters, which RE2's boundary, Python's lookarounds, and the page's all read as ends of a word: the shapes real
# messages have and the synthetic case lacks.
MESSAGES = {"both": "WinMaps ran, x_nmap and nmap2, then nmap -sS\r\nsecond line", "inside": "WinMaps.dll loaded",
            "accents": "énmapé seen"}
BOX = "#details .sticky-head label.whole-word input"
TEXT = ("(li) => [...li.querySelector('.rel-text').childNodes].map((n) => n.nodeName === 'MARK' ? `[${n.textContent}]` : "
        "n.textContent).join('')")


def words(case):
    load(case.db_path, [Event(T0 + (10 + i) * SEC, "Event Recorded", "evtx", SOURCE, label, text, event_code="9000")
                        for i, (label, text) in enumerate(MESSAGES.items())],
         host="DC01", tool="evtxecmd", tool_version="t", run_id="r9", replaces_sources=[SOURCE], staging_dir=case.folder)


def listed(p, query, rows):
    """Wait for the page of the search for `query`, listing `rows` events."""
    p.wait_for_function("([q, n]) => document.querySelector('#detailsBand .title')?.textContent === `Search: ${q}` && "
                        "document.querySelectorAll('#details[data-page=\"search\"] li.rel-row').length === n", arg=[query, rows])


def search(p, query, rows):
    p.locator("#search").fill(query)
    p.locator("#search").press("Enter")
    listed(p, query, rows)


def cells(p):
    """Each listed event's text, a match in brackets."""
    return p.locator("#details li.rel-row").evaluate_all(f"(rows) => rows.map({TEXT})")


def test_the_whole_word_tick_switches_between_the_word_alone_and_the_text_anywhere(browser, synthetic_case):  # noqa: F811
    """The bare word finds all three events and marks the match inside WinMaps; the tick quotes it, the list falls to the
    two events that hold the word alone, and the highlights follow, among the accented letters too; unticked, it returns."""
    words(synthetic_case)
    for p in served_page(browser, synthetic_case):
        search(p, "nmap", 3)
        tick = p.locator(BOX)
        assert not tick.is_checked() and not tick.evaluate("(n) => n.indeterminate")
        both, inside, accents = cells(p)
        assert "Wi[nMap]s ran, x_[nmap] and [nmap]2, then [nmap] -sS" in both and "Wi[nMap]s.dll loaded" in inside
        assert "é[nmap]é seen" in accents
        tick.click()
        listed(p, '"nmap"', 2)   # the tick ran the search itself
        assert p.locator("#search").input_value() == '"nmap"' and p.locator(BOX).is_checked()
        both, accents = cells(p)
        assert "WinMaps ran, x_nmap and nmap2, then [nmap] -sS" in both and "é[nmap]é seen" in accents   # no mark inside WinMaps
        assert p.locator("#details li.rel-row mark").all_inner_texts() == ["nmap", "nmap"]
        assert p.locator("#details .sticky-head strong").inner_text().startswith("2 matching events")
        assert "Whole words only" in p.locator("#details .sticky-head label.whole-word").get_attribute("title")
        p.locator(BOX).click()
        listed(p, "nmap", 3)
        assert p.locator("#search").input_value() == "nmap" and not p.locator(BOX).is_checked()


def test_the_whole_word_tick_is_part_checked_for_a_mixed_query_and_a_phrase_stays_whole_words(browser, synthetic_case):  # noqa: F811
    """A search of a bare word and a quoted phrase shows the tick part-checked; a click quotes the bare word and keeps the
    phrase, and the hover says a phrase stays whole words."""
    words(synthetic_case)
    for p in served_page(browser, synthetic_case):
        search(p, 'nmap "then nmap"', 1)
        tick = p.locator(BOX)
        assert tick.evaluate("(n) => n.indeterminate") and not tick.is_checked()
        title = p.locator("#details .sticky-head label.whole-word").get_attribute("title")
        assert title.endswith("A phrase in quotes stays whole words.")
        tick.click()
        listed(p, '"nmap" "then nmap"', 1)
        assert p.locator(BOX).is_checked() and not p.locator(BOX).evaluate("(n) => n.indeterminate")
        p.locator(BOX).click()   # off: the phrase stays quoted, so the tick is part-checked again
        listed(p, 'nmap "then nmap"', 1)
        assert p.locator(BOX).evaluate("(n) => n.indeterminate")


def test_a_search_of_fields_alone_has_no_tick_and_a_search_with_no_match_keeps_it(browser, synthetic_case):  # noqa: F811
    """The tick is for free-text words: none for code:4624, but a quoted word that matches nothing keeps it, so it can be
    unticked."""
    words(synthetic_case)
    for p in served_page(browser, synthetic_case):
        p.locator("#search").fill("code:4624")
        p.locator("#search").press("Enter")
        p.wait_for_selector("#details[data-page='search'] li.rel-row")
        assert p.locator("#details .sticky-head label.whole-word").count() == 0
        p.locator("#search").fill('"nmapp"')
        p.locator("#search").press("Enter")
        p.wait_for_selector("#details .sticky-head label.whole-word")
        assert p.locator(BOX).is_checked()
        assert p.locator("#details .sticky-head strong").inner_text().startswith("0 matching events")


def test_the_forgiving_line_counts_what_the_quotes_leave_out_and_a_word_of_it_runs(browser, synthetic_case):  # noqa: F811
    """Choice 6: a quoted word's page offers a line that waits for a click; it counts the events without the quotes, how many
    hold the word only inside others, and names those words, each a search. The time is the server's, in the status line, and
    the line stays through a tick and goes with Hide. A bare word has no line, and a search with no match keeps it."""
    words(synthetic_case)
    for p in served_page(browser, synthetic_case):
        search(p, "nmap", 3)
        assert p.locator("#searchAddsGo").count() == 0
        search(p, '"nmap"', 2)
        go = p.locator("#searchAddsGo")
        assert go.inner_text() == "Show what the forgiving search adds" and "second scan" in go.get_attribute("title")
        go.click()
        p.wait_for_selector("#searchAdds")
        line = p.locator("#searchAdds")
        assert line.inner_text() == "Without Whole word: 3 events, 1 of them inside other words: WinMaps 1. Hide"
        assert "event holding two" in line.get_attribute("title")
        status = p.locator("#status").inner_text()
        assert status.startswith("Counted what the forgiving search adds: 3 events · ") and " ms" in status
        assert p.locator("#searchAddsGo").count() == 0
        p.locator("#details li.rel-row input").first.check()   # a tick redraws the page and keeps the line
        assert p.locator("#searchAdds").count() == 1
        p.locator("#searchAdds").get_by_role("button", name="Hide").click()
        assert p.locator("#searchAdds").count() == 0 and p.locator("#searchAddsGo").count() == 1
        p.locator("#searchAddsGo").click()
        p.wait_for_selector("#searchAdds")
        p.locator("#searchAdds").get_by_role("button", name="3 events").click()   # the forgiving search itself
        listed(p, "nmap", 3)
        search(p, '"WinMaps nmapp"', 0)
        assert p.locator("#searchAddsGo").count() == 0   # a phrase with a space has no forgiving form
        search(p, '"nmapp"', 0)
        p.locator("#searchAddsGo").click()
        p.wait_for_selector("#searchAdds")
        assert p.locator("#searchAdds").inner_text() == "Without Whole word: 0 events, none of them inside other words. Hide"
        search(p, '"nmap"', 2)   # a group runs its quoted word: WinMaps is a word on its own in both events that hold it
        p.locator("#searchAddsGo").click()
        p.wait_for_selector("#searchAdds")
        p.locator("#searchAdds").get_by_role("button", name="WinMaps 1").click()
        listed(p, '"WinMaps"', 2)


def test_a_search_reports_itself_to_the_status_line_with_the_servers_time(browser, synthetic_case):  # noqa: F811
    """A search writes its count to the status line as the last action, with the server's time, so a redraw of the line
    doesn't put back the action before it, "Counted what the forgiving search adds" here. A mark's reload of the same
    results keeps the mark's line instead."""
    words(synthetic_case)
    for p in served_page(browser, synthetic_case):
        search(p, '"nmap"', 2)
        p.locator("#searchAddsGo").click()
        p.wait_for_selector("#searchAdds")
        assert p.locator("#status").inner_text().startswith("Counted what the forgiving search adds")
        search(p, "nmap", 3)
        p.evaluate("import('/js/core.js').then((core) => core.renderStatus())")   # what any redraw of the line does
        said = p.locator("#status").inner_text().split(" | ")[0]
        assert re.fullmatch(r"Search: 3 matching events · [\d.]+ ms", said), said
        p.locator("#details li.rel-row input").first.check()
        p.get_by_role("button", name="Mark 1 Suspicious").click()
        p.wait_for_function("() => document.querySelectorAll('#details li.rel-row .badge.s').length === 1")
        assert p.locator("#status").inner_text().startswith("Marked one event Suspicious · ")


def test_a_late_forgiving_answer_leaves_another_pages_count_alone(browser, synthetic_case):  # noqa: F811
    """The answer of a forgiving count the analyst has left behind doesn't clear the count running for the page now
    shown, and a tick on that page doesn't offer the button again for a second scan."""
    words(synthetic_case)
    for p in served_page(browser, synthetic_case):
        held = []
        p.route("**/api/search_adds*", lambda route: held.append(route))   # noqa: B023  (answers wait for the test)
        search(p, '"nmap"', 2)
        p.locator("#searchAddsGo").click()
        p.wait_for_selector("#searchAddsBusy")
        search(p, '"WinMaps"', 2)
        p.locator("#searchAddsGo").click()
        p.wait_for_selector("#searchAddsBusy")
        while len(held) < 2:
            p.wait_for_timeout(50)
        with p.expect_response("**/api/search_adds*"):
            held[0].continue_()   # the first page's answer arrives while the second page counts
        p.evaluate("() => new Promise((resolve) => setTimeout(resolve, 200))")
        p.locator("#details li.rel-row input").first.check()   # a tick redraws the page that is counting
        assert p.locator("#searchAddsBusy").count() == 1 and p.locator("#searchAddsGo").count() == 0
        held[1].continue_()
        p.wait_for_selector("#searchAdds")


def test_a_search_with_no_match_names_what_free_text_skips_and_the_links_run(browser, synthetic_case):  # noqa: F811
    """A word only a Hayabusa rule's title holds finds no event; the page says what free text covers and skips, lists
    the rule with its field form and level, and runs the search for it. A host role is a View value, shown in the View."""
    for p in served_page(browser, synthetic_case):
        search(p, "internet", 0)
        assert p.locator("#details .list-head strong").inner_text() == "No event matches internet as free text."
        reach = p.locator("#details p.reach").nth(1).inner_text()
        assert reach.startswith("Free text searches the message, domain, account, source IP,") and "and event data." in reach
        assert "It does not search the tool, artifact, run, source file, mark, role, tag, or Hayabusa rule titles." in reach
        assert reach.endswith("These hold it:")
        row = p.locator("#searchHint li")
        assert row.count() == 1 and row.locator("code").inner_text() == 'rule:"RDP from internet"'
        assert row.locator(".muted").inner_text() == "a Hayabusa rule (high) that hit 1 event"
        host = p.evaluate("window.__app.S.meta.hosts[0].host")   # a name from the case, not a placeholder to copy
        assert p.locator("#details p.muted").last.inner_text() == ('Other forms: "internet" for the whole word in free text; '
                                                                   f'internet* for a prefix; -host:{host} to leave a host out.')
        row.get_by_role("button").click()
        p.wait_for_function("(q) => document.querySelector('#detailsBand .title')?.textContent === `Search: ${q}`",
                           arg='rule:"RDP from internet"')
        p.wait_for_selector("#details[data-page='search'] li.rel-row")
        assert p.locator("#details li.rel-row").count() == 1 and p.locator("#search").input_value() == 'rule:"RDP from internet"'
        reach = p.locator("#details p.reach").first
        assert reach.inner_text() == 'Looking for events hit by the Hayabusa rule "RDP from internet".'
        search(p, "controllers", 0)
        row = p.locator("#searchHint li")
        assert row.locator("code").inner_text() == "Role Domain controllers"
        assert "a host role" in row.locator(".muted").inner_text()
        redraws = p.evaluate("window.__timings.length")
        row.get_by_role("button", name="Show in the View").click()
        # The view's redraw keeps this as the last action; the line had flashed it, and the redraw put the search's back
        p.wait_for_function("(n) => window.__timings.length > n", arg=redraws)
        assert p.locator("#status").inner_text().startswith("Added to the view filter: Role")
        search(p, "qqqqzzzz", 0)
        assert p.locator("#searchHint").count() == 0 and "These hold it" not in p.locator("#details p.reach").nth(1).inner_text()
        search(p, "qqqqzzzz host:DC01", 0)
        assert p.locator("#details .list-head strong").inner_text() == "No event matches qqqqzzzz host:DC01."
        search(p, "code:9999", 0)   # no free-text word: the older words
        assert p.locator("#details p", has_text="No event matches.").count() == 1
        assert p.locator("#details .list-head").count() == 0


def test_free_text_lists_the_rules_it_finds_by_title_under_the_results(browser, synthetic_case):  # noqa: F811
    """Choice 7: the results of a word that a rule's title holds are followed by a box naming the rules; each lists the events
    it hit that the results leave out, says how many the results share, and its field form runs."""
    from test_search import probe_case

    probe_case(synthetic_case)
    for p in served_page(browser, synthetic_case):
        p.locator("#search").fill("internet")
        p.locator("#search").press("Enter")
        p.wait_for_selector("#searchByName")
        box = p.locator("#searchByName")
        text = box.inner_text()
        assert text.startswith("Also found by name:") and "the Hayabusa rule Internet Probe Seen (medium) hit 1 event" in text
        assert "the Hayabusa rule RDP from internet (high) hit 1 event" in text
        assert text.count("1 of them is in the results above.") == 1
        assert box.locator("li.rel-row").count() == 1 and "4624 logon" in box.locator("li.rel-row").inner_text()
        badge = box.locator("li.rel-row .badge")
        assert badge.get_attribute("title").startswith("Unreviewed, with a pending")   # a high rule suggests a mark
        assert p.locator("#details li.rel-row").count() == 2   # the one result and the one found by name
        # The two lists share their ticks, but the head's Select all is about its own list: one tick below is not all of it
        box.locator("li.rel-row input").check()
        head = p.locator("#details .sticky-head")
        head.get_by_role("button", name="Mark 1 Malicious").wait_for()
        assert head.get_by_role("button", name="Select all").count() == 1
        assert head.get_by_role("button", name="Select none").count() == 0
        box.locator("li.rel-row input").uncheck()
        box.get_by_role("button", name='rule:"RDP from internet"').click()
        p.wait_for_function("(q) => document.querySelector('#detailsBand .title')?.textContent === `Search: ${q}`",
                           arg='rule:"RDP from internet"')
        p.wait_for_selector("#details li.rel-row")
        assert p.locator("#details li.rel-row").count() == 1 and p.locator("#searchByName").count() == 0


LINK = "#details #searchByNameLink"
STRIP = "#details .match-strip-box"


def more_matches(case, count, rule_hits=0):
    """`count` more events whose text holds "internet", so the results are a long list with a strip over time and the rules
    found by name sit far below the head; and `rule_hits` events whose text does not, hit by the rule "Internet Probe Seen", so
    the box under the results is taller than the panel."""
    from test_search import probe_case

    probe_case(case)
    source, plain = "DC01/Windows/System32/winevt/Logs/Probe2.evtx", "DC01/Windows/System32/winevt/Logs/Probe3.evtx"
    load(case.db_path, [Event(T0 + (600 + i) * SEC, "Event Recorded", "evtx", source, str(8000 + i), f"internet probe again {i}",
                              record_id=8000 + i, log_channel="Security", event_code="9300") for i in range(count)],
         host="DC01", tool="evtxecmd", tool_version="t", run_id="r11", replaces_sources=[source], staging_dir=case.folder)
    if rule_hits:
        load(case.db_path, [Event(T0 + (700 + i) * SEC, "Event Recorded", "evtx", plain, str(9000 + i), f"service {i} started",
                                  record_id=9000 + i, log_channel="Security", event_code="9400") for i in range(rule_hits)],
             host="DC01", tool="evtxecmd", tool_version="t", run_id="r12", replaces_sources=[plain], staging_dir=case.folder)
        load(case.db_path, [Event(ts_us=T0 + (700 + i) * SEC, ts_desc="Event Recorded", artifact="hayabusa", source_file=plain,
                                  source_record=f"{9000 + i}:rule", record_id=9000 + i, message="Internet Probe Seen [medium]",
                                  log_channel="Security", rule_title="Internet Probe Seen", rule_level="medium")
                             for i in range(rule_hits)],
             host="DC01", tool="hayabusa", tool_version="t", run_id="r13", replaces_sources=[plain], staging_dir=case.folder)


def test_the_search_head_links_to_the_rules_found_by_name(browser, synthetic_case):  # noqa: F811
    """When the box of rules found by name exists, a link to the right of the match strip says how many rules and events
    it holds, and scrolls it into view below the sticky head. A search with no strip shows the link after the count
    line, and a search with no rule found by name has none."""
    more_matches(synthetic_case, 40, rule_hits=15)
    for p in served_page(browser, synthetic_case):
        p.locator("#search").fill("internet")
        p.locator("#search").press("Enter")
        p.wait_for_selector(LINK)
        link = p.locator(LINK)
        assert link.inner_text() == "Also found by name: 2 rules, 16 events below"
        strip, mine = p.locator(STRIP).bounding_box(), link.bounding_box()
        assert mine["x"] >= strip["x"] + strip["width"] - 1, (strip, mine)   # to its right
        assert mine["y"] < strip["y"] + strip["height"] and mine["y"] + mine["height"] > strip["y"]   # on its row
        body = p.locator("#detailsBody").bounding_box()
        assert p.locator("#searchByName").bounding_box()["y"] > body["y"] + body["height"]   # out of sight, far down the list
        link.click()
        box = p.locator("#searchByName").bounding_box()
        head = p.locator("#details .sticky-head").bounding_box()
        # in view, and not under the head
        assert head["y"] + head["height"] - 1 <= box["y"] < body["y"] + body["height"], (head, box, body)
        p.locator("#search").fill("code:4624")
        p.locator("#search").press("Enter")
        p.wait_for_function("() => document.querySelector('#detailsBand .title')?.textContent === 'Search: code:4624'")
        p.wait_for_selector("#details[data-page='search'] li.rel-row")
        assert p.locator(LINK).count() == 0 and p.locator("#searchByName").count() == 0


def test_a_search_with_no_strip_shows_the_link_after_the_count_line(browser, synthetic_case):  # noqa: F811
    """One match has no strip over time, so the link to the rules found by name follows the count line, above the
    list, and still scrolls to the box."""
    from test_search import probe_case

    probe_case(synthetic_case)
    for p in served_page(browser, synthetic_case):
        p.locator("#search").fill("internet")
        p.locator("#search").press("Enter")
        p.wait_for_selector(LINK)
        assert p.locator(STRIP).count() == 0
        assert p.locator(LINK).inner_text() == "Also found by name: 2 rules, 1 event below"
        count = p.locator("#details .sticky-head strong").bounding_box()
        mine = p.locator(LINK).bounding_box()
        first = p.locator("#details ul.rows li.rel-head").first.bounding_box()
        assert count["y"] + count["height"] <= mine["y"] + 1, (count, mine)
        assert mine["y"] + mine["height"] <= first["y"] + 1, (mine, first)
        p.locator(LINK).click()
        assert p.locator("#searchByName").is_visible()


def test_the_search_help_names_whole_words_and_the_rule_field(browser, synthetic_case):  # noqa: F811
    """The Search help page has the whole-word row and the rule: row, and the example for a phrase says whole words."""
    for p in served_page(browser, synthetic_case):
        p.locator("#searchHelp").click()
        p.wait_for_selector("#details[data-page='searchHelp'] .help-table")
        table = p.locator("#details .help-table").first.inner_text()
        assert '"word" or "a phrase"' in table and "Whole word" in table and "WinMaps" in table
        assert "Whole words only" in table and "touching either end of the match rules it out" in table   # not "end a match"
        fields = p.locator("#details .help-table").nth(1)
        row = fields.locator("tr", has_text="Hayabusa rule title")
        assert row.locator("td").first.inner_text() == "rule" and row.locator("button").inner_text() == 'rule:"*Mimikatz*"'
        assert p.locator("#details .help-examples").get_by_text("A phrase, as whole words").count() == 1
        assert '"nmap" or "a phrase" in quotes matches whole words only' in p.locator("#search").get_attribute("title")
