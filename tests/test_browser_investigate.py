"""To investigate as a worklist with ask-first group actions, in a real browser: the two sections and their meters,
the Followed up tick and its line, a count that opens the pivot's list kept to unreviewed events, Review one by one with
its keys, the confirm before a group action on both pages with Cancel, and a hand-picked selection above 25 events. They
drive the installed Microsoft Edge through Playwright, as test_browser_smoke does, and are skipped without it."""

import json
import re

import pytest
from conftest import DC_LOG, SEC, T0, logon
from test_browser_smoke import browser, served_page  # noqa: F401

from glessner.events import load
from glessner.journal import JOURNAL_FILE
from glessner.server import api_followup, api_mark, api_rule

pytestmark = pytest.mark.browser
INVESTIGATE = "#details[data-page='investigate']"
COUNTED = f'() => [...document.querySelectorAll("{INVESTIGATE} .inv-n")].every((n) => n.textContent !== "…")'
BAR_READS = "(text) => document.querySelector('#details .review-bar strong')?.textContent === text"


def entries(case):
    return [json.loads(line) for line in (case.folder / JOURNAL_FILE).read_text(encoding="utf-8").splitlines()]


def uid_at(app, ts, tool="evtxecmd"):
    return app.con.execute("SELECT event_uid FROM events WHERE tool = ? AND ts_us = ?", [tool, ts]).fetchone()[0]


def open_worklist(p):
    p.locator("#investigateButton").click()
    p.wait_for_selector(f"{INVESTIGATE} .inv-section")


def heading_of(p):
    return p.locator("#relatedList .actions strong").inner_text()


def page_post(p, path, body):
    """A change made through the page's own API while the test runs, as another tab would: the server serializes it."""
    return p.evaluate("async ([path, body]) => (await import('/js/core.js')).post(path, body)", [path, body])


def test_the_worklist_lists_marked_events_with_their_meters_tick_and_counts(browser, synthetic_case):  # noqa: F811
    """The page: a sticky head of Done, Mark, Time, Host, Event, and the counts over
    the marked events; each row's badge, time, host, and event; the meters in words; the Followed up tick, journaled through
    /api/followup, with its line under the event and its who and when in the hover, kept when the mark changes later with the
    row saying so; and the pending rules with why they fired."""
    found = {}

    def marks(app):
        found["rdp"] = uid_at(app, T0)
        found["morty"] = uid_at(app, T0 + 60 * SEC)
        api_mark(app, {"uids": [found["rdp"]], "value": "malicious", "note": "RDP from the internet"})
        api_mark(app, {"uids": [found["morty"]], "value": "suspicious"})
        api_followup(app, {"uids": [found["morty"]], "done": True})

    for p in served_page(browser, synthetic_case, setup=marks):
        open_worklist(p)
        details = p.locator("#details")
        head = details.locator("ul.worklist li.rel-head")
        assert head.locator(":scope > span").all_inner_texts() == [
            "Done", "Mark", "Time (UTC)", "Host", "Event", "Still unreviewed around it"]
        assert p.evaluate("getComputedStyle(document.querySelector('#details ul.worklist li.rel-head')).position") == "sticky"
        rows = details.locator("ul.worklist li.rel-row")
        assert rows.count() == 2
        first, second = rows.nth(0), rows.nth(1)
        assert [first.locator(sel).inner_text() for sel in (".badge", ".rel-time", ".rel-host", ".rel-text")] == [
            "M", "2020-09-19 03:21:48.000000", "DC01", "4624 logon"]
        assert first.locator(".inv-note").inner_text() == "Note: RDP from the internet"
        assert first.locator(".badge").get_attribute("title").startswith("Malicious, marked by cody, ")
        assert first.locator(".inv-tick").is_checked() is False and second.locator(".inv-tick").is_checked() is True
        assert re.fullmatch(r"Followed up \d\d:\d\d by cody", second.locator(".inv-followed").inner_text())
        assert re.fullmatch(r"Followed up \d{4}-\d\d-\d\d \d\d:\d\d UTC by cody \(entry #\d+\)",
                            second.locator(".inv-followed").get_attribute("title"))
        assert "done" in second.get_attribute("class") and "done" not in first.get_attribute("class")
        meters = details.locator(".inv-section .inv-head .meter-words")
        assert meters.nth(0).inner_text() == "1 of 2 followed up"
        assert re.fullmatch(r"\d+ of \d+ decided", meters.nth(1).inner_text())
        assert details.locator(".meter .bar").first.evaluate("(n) => n.style.width") == "50%"
        # The counts beside each event: the ranked pivots, counted as unreviewed events after the page drew
        p.wait_for_function(COUNTED)
        labels = first.locator(".inv-count .inv-count-label").all_inner_texts()
        assert labels == ["Same logon session", "Same IP at either end 194.61.24.102", "Same host within ±300 s"]
        assert first.locator(".inv-count").evaluate_all("(ns) => ns.map((n) => n.dataset.pivot)") == ["session", "addr", "window"]
        # The 4672 in the RDP session; nothing else from the client's address; DC01's window less the Suspicious event
        assert first.locator(".inv-count .inv-n").all_inner_texts() == ["1", "0", "3"]
        assert first.locator(".inv-count button.inv-n").count() == 2   # the zero is information, not a link
        timing = p.evaluate("window.__timings.find((t) => t.page === 'investigate')")
        assert timing["counts"] == details.locator(".inv-count").count() and timing["ms"] > 0 and timing["slowest_ms"] > 0
        # The pending rules: name, who added it, why it fired, progress, and the three actions
        rule = details.locator(".rule[data-source='machine-accounts-authorized']")
        assert rule.locator(".rule-why").inner_text().startswith("Why it fired: Machine-account network logons between collected")
        assert rule.locator(".rule-pending").inner_text() == "1 event pending, would be Authorized"
        assert rule.locator(".meter-words").inner_text() == "0 of 1 decided"
        assert rule.locator(".rule-acts button").all_inner_texts() == ["Review one by one", "Accept all", "Reject all"]
        assert rule.locator("button.primary").inner_text() == "Review one by one"
        # The tick goes through /api/followup, the line appears, and the meter follows; the counts are not asked again
        before = len(entries(synthetic_case))
        with p.expect_response("**/api/followup"):
            first.locator(".inv-tick").click()
        p.wait_for_function(f'() => document.querySelector("{INVESTIGATE} .meter-words").textContent === "2 of 2 followed up"')
        rows = details.locator("ul.worklist li.rel-row")
        assert rows.nth(0).locator(".inv-followed").count() == 1 and "done" in rows.nth(0).get_attribute("class")
        assert rows.nth(0).locator(".inv-count .inv-n").all_inner_texts() == ["1", "0", "3"]
        tick = entries(synthetic_case)[-1]
        assert (tick["action"], tick["done"], tick["targets"]) == ("followup", True, [found["rdp"]])
        assert len(entries(synthetic_case)) == before + 1
        assert p.locator("#status").inner_text().startswith("Marked one event followed up")
        # A mark after the tick leaves it, and the row says so
        page_post(p, "/api/mark", {"uids": [found["rdp"]], "value": "suspicious", "note": ""})
        p.locator("#tabTimeline").click()
        open_worklist(p)
        p.wait_for_selector(f"{INVESTIGATE} ul.worklist li.rel-row")
        line = details.locator("ul.worklist li.rel-row").nth(0).locator(".inv-followed")
        assert re.fullmatch(r"Followed up \d\d:\d\d by cody; marked Suspicious at \d\d:\d\d, after the tick", line.inner_text())
        assert "after the tick, which stays" in line.get_attribute("title")
        assert details.locator("ul.worklist li.rel-row").nth(0).locator(".inv-tick").is_checked()
        # Clearing the tick
        with p.expect_response("**/api/followup"):
            details.locator("ul.worklist li.rel-row").nth(0).locator(".inv-tick").click()
        p.wait_for_function(f'() => document.querySelector("{INVESTIGATE} .meter-words").textContent === "1 of 2 followed up"')
        assert entries(synthetic_case)[-1]["done"] is False


def test_a_count_opens_the_pivot_kept_to_unreviewed_events_with_the_count_as_its_total(browser, synthetic_case):  # noqa: F811
    """A count is a link that opens the event's page with that pivot narrowed to unreviewed events, through
    unreviewed=1 on /api/related, so the list's total equals the count; the heading and the trail step say so; and a mark
    from that list redraws it still narrowed."""
    def marks(app):
        api_mark(app, {"uids": [uid_at(app, T0)], "value": "malicious"})
        api_mark(app, {"uids": [uid_at(app, T0 + 62 * SEC)], "value": "authorized"})   # DC01 to itself, in the window

    for p in served_page(browser, synthetic_case, setup=marks):
        open_worklist(p)
        p.wait_for_function(COUNTED)
        row = p.locator(f"{INVESTIGATE} ul.worklist li.rel-row").first
        window = row.locator(".inv-count[data-pivot='window'] button.inv-n")
        n = int(window.inner_text())
        assert n == 3   # the four events on DC01 in the window less the authorized one
        with p.expect_response(lambda r: "/api/related?" in r.url and "unreviewed=1" in r.url and "kind=window" in r.url) as got:
            window.click()
        res = got.value.json()
        assert res["unreviewed"] is True and res["total"] == n == len(res["events"])
        p.wait_for_selector("#details[data-page='event'] #relatedList li.rel-row")
        assert heading_of(p) == f"Same host within ±300 s, unreviewed only: {n} events"
        assert p.locator("#relatedList li.rel-row").count() == n
        assert all(t == "U" for t in p.locator("#relatedList li.rel-row .badge").all_inner_texts())
        assert "Same host within ±300 s, unreviewed only" in p.locator("#detailsBand .trail").inner_text()
        # A mark from the narrowed list redraws it still narrowed, so the marked event leaves it
        p.locator("#relatedList li.rel-row").first.locator("input").click()
        with p.expect_response(lambda r: "/api/related?" in r.url and "unreviewed=1" in r.url):
            p.locator("#relatedList").get_by_role("button", name="Mark 1 Suspicious").click()
        p.wait_for_function("(n) => document.querySelectorAll('#relatedList li.rel-row').length === n", arg=n - 1)
        assert heading_of(p) == f"Same host within ±300 s, unreviewed only: {n - 1} events"


def test_review_one_by_one_walks_the_counted_set_with_its_keys(browser, synthetic_case):  # noqa: F811
    """Review one by one opens the source's first pending event on the Event page with a review bar ("logons: 1 of 3"),
    Accept as the suggested mark, Reject with its note, and the keys A, R, and N. The queue is the set the page counted; a
    decision moves to the next, N skips, and the last says the set is done. Each decision journals as one event's."""
    def rule(app):
        api_rule(app, {"op": "add", "text": "id: logons\nsuggest: suspicious\nwhen:\n  all:\n"
                                            "    - {field: event_code, equals: '4624'}\n    - {field: host, equals: DC01}\n"})

    for p in served_page(browser, synthetic_case, setup=rule):
        open_worklist(p)
        # The heading stands above the first source, so that row has no rule over it
        assert p.locator(f"{INVESTIGATE} .inv-section .rule").first.evaluate("(n) => getComputedStyle(n).borderTopWidth") == "0px"
        row = p.locator(f"{INVESTIGATE} .rule[data-source='logons']")
        assert row.locator(".rule-pending").inner_text() == "4 events pending, would be Suspicious"
        row.get_by_role("button", name="Review one by one").click()
        p.wait_for_selector("#details[data-page='event'] .review-bar")
        bar = p.locator("#details .review-bar")
        assert bar.locator("strong").inner_text() == "logons: 1 of 4"
        assert p.locator("#details .ev-ident .time").inner_text() == "2020-09-19 03:21:48.000000 UTC"   # the first in time
        buttons = bar.locator("button").all_inner_texts()
        assert buttons[:2] + buttons[3:] == ["Accept as Suspicious", "Reject", "Stop reviewing"] and buttons[2].startswith("Next")
        assert bar.locator("button.primary").inner_text() == "Accept as Suspicious"
        assert bar.locator(".keys").inner_text() == "Keys: A accept, R reject, N next"
        before = len(entries(synthetic_case))
        # A accepts and moves on
        with p.expect_response("**/api/suggestion"):
            p.keyboard.press("a")
        p.wait_for_function(BAR_READS, arg="logons: 2 of 4")
        accepted = entries(synthetic_case)[-1]
        assert (accepted["action"], accepted["value"], len(accepted["targets"])) == ("mark", "suspicious", 1)
        # R rejects with the note typed in the bar. The note's letters are the review keys' (R and N): typed in the box they
        # are the note's, and nothing is decided or skipped; fill() sends no key events, so the keys are typed one by one
        note = bar.locator(".mark-note")
        note.click()
        note.press_sequentially("routine")
        assert note.input_value() == "routine"
        assert len(entries(synthetic_case)) == before + 1 and bar.locator("strong").inner_text() == "logons: 2 of 4"
        p.keyboard.press("Tab")   # out of the field, the review keys work again
        with p.expect_response("**/api/suggestion"):
            p.keyboard.press("r")
        p.wait_for_function(BAR_READS, arg="logons: 3 of 4")
        rejected = entries(synthetic_case)[-1]
        assert (rejected["action"], rejected["decision"], rejected["note"]) == ("suggestion_decision", "rejected", "routine")
        assert len(rejected["targets"]) == 1
        # N moves on without deciding
        p.keyboard.press("n")
        p.wait_for_function(BAR_READS, arg="logons: 4 of 4")
        assert len(entries(synthetic_case)) == before + 2
        assert bar.locator("button", has_text="Finish").count() == 1
        p.keyboard.press("n")
        p.wait_for_function(BAR_READS, arg="logons: 4 events reviewed")
        assert bar.locator("button").all_inner_texts() == ["Stop reviewing"]
        bar.get_by_role("button", name="Stop reviewing").click()
        p.wait_for_selector("#details .review-bar", state="detached")
        assert p.locator("#details[data-page='event'] .ev-ident").count() == 1
        # Back on the worklist, the rule shows its progress: one accepted, one rejected, two still pending
        open_worklist(p)
        row = p.locator(f"{INVESTIGATE} .rule[data-source='logons']")
        assert row.locator(".rule-pending").inner_text() == "2 events pending, would be Suspicious"
        assert row.locator(".meter-words").inner_text() == "2 of 4 decided"


def test_a_group_action_asks_first_on_both_pages_and_cancel_changes_nothing(browser, synthetic_case):  # noqa: F811
    """Accept all and Reject all on To investigate, and the group buttons and Accept all on the Suggestions
    page, open a confirm block that names the action, the mark, the source or group, the count counted when the page loaded,
    what it covers, the first events, and how many arrived later; the confirm button repeats the number; Escape and Cancel
    change nothing; the confirmed action sends the counted events with the count, and the entry records confirmed."""
    found = {}

    def rule(app):
        api_rule(app, {"op": "add", "text": "id: logons\nsuggest: suspicious\nwhen: {field: event_code, equals: '4624'}\n"})
        found["late"] = app.con.execute("SELECT event_uid FROM events WHERE event_code = '4648'").fetchone()[0]
        found["rdp"] = uid_at(app, T0)

    for p in served_page(browser, synthetic_case, setup=rule):
        open_worklist(p)
        details = p.locator("#details")
        row = details.locator(".rule[data-source='logons']")
        pending = int(re.match(r"(\d+) events pending", row.locator(".rule-pending").inner_text())[1])
        assert pending >= 5
        before = len(entries(synthetic_case))
        # Accept all on To investigate: the block, then Escape
        row.get_by_role("button", name="Accept all").click()
        block = row.locator(".confirm-block")
        block.wait_for()
        assert block.locator(".confirm-title").inner_text() == f"Accept {pending} logons suggestions?"
        assert re.fullmatch(r"Source: logons, counted when this page loaded at \d\d:\d\d:\d\d UTC\.",
                            block.locator(".confirm-line").inner_text())
        points = block.locator(".confirm-points li").all_inner_texts()
        assert points[0] == f"All {pending} are marked Suspicious: none is listed on this page; the first are shown below."
        assert points[1] == "The journal records this as one entry listing every event, with your name and the time."
        assert block.locator(".confirm-warn").count() == 0
        assert block.locator("h3").text_content() == f"First of the {pending}"   # the section-label caps are the style's
        sample = block.locator(".confirm-sample div").all_text_contents()
        assert len(sample) == 4 and sample[0] == "2020-09-19 03:21:48  DC01  4624 logon"
        assert sample[3] == f"and {pending - 3} more"
        assert block.locator(".actions button").all_inner_texts() == [f"Accept {pending}", f"Show all {pending} first", "Cancel"]
        assert block.locator("button.primary").evaluate("(n) => n.className") == "primary mark-suspicious"
        assert p.evaluate("document.activeElement.textContent") == f"Accept {pending}"
        # Show all N first lists the whole group: the Suggestions page is asked for the source's pending count as its limit,
        # not the usual 200 of each group (the confirm's own click counts as a cancel, so nothing changed)
        with p.expect_request(lambda r: "/api/pending?" in r.url) as asked:
            block.get_by_role("button", name=f"Show all {pending} first").click()
        assert f"limit={pending}" in asked.value.url
        p.wait_for_selector("#details[data-page='suggestions'] .sg-group")
        assert len(entries(synthetic_case)) == before
        open_worklist(p)
        row.get_by_role("button", name="Accept all").click()
        block.wait_for()
        p.keyboard.press("Escape")
        p.wait_for_selector(f"{INVESTIGATE} .confirm-block", state="detached")
        assert len(entries(synthetic_case)) == before
        # Reject all, then Cancel; then a suggestion arrives after the page counted, and the block says so
        row.get_by_role("button", name="Reject all").click()
        block.wait_for()
        assert block.locator(".confirm-title").inner_text() == f"Reject {pending} logons suggestions?"
        block.get_by_role("button", name="Cancel").click()
        p.wait_for_selector(f"{INVESTIGATE} .confirm-block", state="detached")
        assert len(entries(synthetic_case)) == before
        wider = "id: logons\nsuggest: suspicious\nwhen: {field: event_code, in: ['4624', '4648']}\n"
        page_post(p, "/api/rule", {"op": "change", "text": wider})   # the 4648 is pending, after the page counted
        # One of the counted, decided elsewhere meanwhile
        page_post(p, "/api/mark", {"uids": [found["rdp"]], "value": "authorized", "note": ""})
        row.get_by_role("button", name="Accept all").click()
        block.wait_for()
        warn = block.locator(".confirm-warn").inner_text()
        assert warn.startswith("1 more suggestion for this source arrived after the page loaded. It is not included.")
        assert "Reload the page to review it." in warn
        assert f"1 of the {pending} was decided elsewhere since the page loaded and will be skipped." in warn
        # The button says what the server will act on: the counted less the one decided elsewhere
        assert block.locator("button.primary").inner_text() == f"Accept {pending - 1}"
        with p.expect_response("**/api/suggestion") as got:
            block.get_by_role("button", name=f"Accept {pending - 1}", exact=True).click()
        sent = json.loads(got.value.request.post_data)
        assert sent["confirmed"] == {"count": pending} and len(sent["uids"]) == pending and found["late"] not in sent["uids"]
        assert got.value.json()["skipped"] == 1
        p.wait_for_function(f'() => document.querySelector("{INVESTIGATE} .rule .rule-pending")?.textContent'
                            '.startsWith("1 event pending")')
        entry = entries(synthetic_case)[-1]
        assert (entry["action"], entry["confirmed"]) == ("mark", {"count": pending, "skipped": 1})
        assert len(entry["targets"]) == pending - 1
        # The status line's "1 skipped as decided meanwhile" is not asserted: a later "Window moved" can replace it
        # The Suggestions page's group button and Accept all use the same block; one event's Accept acts at once
        details.get_by_role("button", name="logons", exact=True).click()
        p.wait_for_selector("#details[data-page='suggestions'] .sg-group")
        group = details.locator(".sg-group").first
        group.get_by_role("button", name="Reject 1").click()
        gblock = group.locator(".confirm-block")
        gblock.wait_for()
        assert gblock.locator(".confirm-title").inner_text() == "Reject 1 logons suggestion?"
        assert re.fullmatch(r"Group: .+ \(account\), counted when this page loaded at \d\d:\d\d:\d\d UTC\.",
                            gblock.locator(".confirm-line").inner_text())
        assert gblock.locator(".confirm-points li").first.inner_text() == (
            "All 1 stay Unreviewed, and logons stops suggesting them: every one is listed on this page.")
        assert gblock.locator(".actions button").all_inner_texts() == ["Reject 1", "Cancel"]   # nothing unlisted, so no Show all
        gblock.get_by_role("button", name="Cancel").click()
        details.get_by_role("button", name="Accept all", exact=True).click()
        top = details.locator(".confirm-slot .confirm-block")
        top.wait_for()
        assert top.locator(".confirm-title").inner_text() == "Accept 1 logons suggestion?"
        p.keyboard.press("Escape")
        p.wait_for_selector("#details .confirm-block", state="detached")
        with p.expect_response("**/api/suggestion") as got:
            group.locator(".sg-events li").first.get_by_role("button", name="Accept").click()   # one event: at once
        assert "confirmed" not in json.loads(got.value.request.post_data)
        details.get_by_text("Nothing is pending from this source.").wait_for()


def test_a_hand_picked_selection_above_25_events_asks_first(browser, synthetic_case):  # noqa: F811
    """A mark of a selection ticked by hand asks first above 25 events, in the list; Cancel marks nothing, and the
    confirmed mark records the count. A selection of 25 or fewer acts at once. A tag of the same selection asks too."""
    many = [logon(T0 + (1000 + n) * SEC, 9900 + n, DC_LOG, user="bulk", ltype="3", ip="10.42.85.50", logon_id=f"0x{9900 + n:x}")
            for n in range(30)]
    load(synthetic_case.db_path, many, host="DC01", tool="evtxecmd", tool_version="t", run_id="bulk", replaces_sources=[],
         staging_dir=synthetic_case.folder)
    for p in served_page(browser, synthetic_case):
        details = p.locator("#details")
        p.locator("#search").fill("ip:10.42.85.50")
        p.locator("#search").press("Enter")
        p.wait_for_selector("#details[data-page='search'] li.rel-row")
        assert details.locator("li.rel-row").count() == 30
        details.get_by_role("button", name="Select all").click()
        before = len(entries(synthetic_case))
        details.get_by_role("button", name="Mark 30 Suspicious").click()
        block = details.locator(".confirm-block")
        block.wait_for()
        assert block.locator(".confirm-title").inner_text() == "Mark 30 events Suspicious?"
        assert block.locator(".confirm-line").inner_text() == "A selection of 30 events you picked by hand."
        assert block.locator(".confirm-sample div").all_text_contents()[-1] == "and 27 more"
        assert block.locator(".actions button").all_inner_texts() == ["Mark 30", "Cancel"]
        block.get_by_role("button", name="Cancel").click()
        p.wait_for_selector("#details .confirm-block", state="detached")
        assert len(entries(synthetic_case)) == before
        assert details.locator("li.rel-row input:checked").count() == 30   # the ticks stay for another try
        # A tag of the same selection asks too
        details.get_by_role("button", name="Tag 30 as...").click()
        p.locator("#quickMenu").get_by_role("menuitem", name="Lateral Movement").click()
        block.wait_for()
        assert block.locator(".confirm-title").inner_text() == "Tag 30 events: Lateral Movement?"
        p.keyboard.press("Escape")
        p.wait_for_selector("#details .confirm-block", state="detached")
        assert len(entries(synthetic_case)) == before
        # Confirmed: one entry with the count
        details.get_by_role("button", name="Mark 30 Suspicious").click()
        block.wait_for()
        with p.expect_response("**/api/mark") as got:
            block.get_by_role("button", name="Mark 30", exact=True).click()
        assert json.loads(got.value.request.post_data)["confirmed"] == {"count": 30}
        p.wait_for_function("() => document.querySelectorAll('#details li.rel-row .badge.s').length === 30")
        entry = entries(synthetic_case)[-1]
        assert (entry["action"], entry["value"], entry["confirmed"]) == ("mark", "suspicious", {"count": 30, "skipped": 0})
        assert len(entry["targets"]) == 30
        # 25 or fewer acts at once (the mark cleared the ticks)
        for box in details.locator("li.rel-row input").all()[:5]:
            box.click()
        details.get_by_role("button", name="Mark 5 Malicious").click()
        p.wait_for_function("() => document.querySelectorAll('#details li.rel-row .badge.m').length === 5")
        assert details.locator(".confirm-block").count() == 0 and "confirmed" not in entries(synthetic_case)[-1]
