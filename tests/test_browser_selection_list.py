"""The Event page's selection list in a real browser: the list a lead's Open on timeline fills, under the buttons that
mark the ticked events. Its caption gives the count and says when the list scrolls; each row has a tick that is the
event's place in the timeline selection, and a click elsewhere on a row opens its event and keeps the list; a find box
narrows its rows. They drive the installed Microsoft Edge through Playwright, as test_browser_smoke does, and are
skipped without it."""

import json

import pytest
from conftest import DC_LOG, SEC, T0, logon
from test_browser_badges import journal_length
from test_browser_frame import no_tool_scan
from test_browser_reload import reload
from test_browser_smoke import browser, served_page  # noqa: F401
from test_overview import app_with_work, overview_case  # noqa: F401

from glessner.events import load
from glessner.journal import JOURNAL_FILE
from glessner.server import api_finding

pytestmark = pytest.mark.browser
LIST = "#details .selection-list"
CAPTION = "#details .sel-caption"


def entries(case):
    return [json.loads(line) for line in (case.folder / JOURNAL_FILE).read_text(encoding="utf-8").splitlines()]


def open_lead(p):
    """Open on timeline for the first lead, three events on DC01, once the window has moved to it; returns the
    events' IDs as the list shows them, in time order."""
    p.wait_for_selector("#ovLeads .ov-lead")
    p.locator("#ovLeads .ov-lead").nth(0).get_by_role("button", name="Open on timeline").click()
    p.wait_for_function(f"() => document.querySelectorAll('{LIST} li').length === 3 && !window.__app.S.anim")
    return rows(p)


def rows(p, shown=False):
    """The IDs of the list's rows, or of those its find shows"""
    return p.locator(f"{LIST} li{':not(.find-out)' if shown else ''}").evaluate_all("(ns) => ns.map((n) => n.dataset.uid)")


def ticks(p):
    return p.locator(f"{LIST} li input[type=checkbox]").evaluate_all("(ns) => ns.map((n) => n.checked)")


def selected(p):
    return p.evaluate("[...window.__app.S.selected].sort()")


def on_page(p):
    """The ID of the highlighted row, whose event the page shows"""
    row = p.locator(f"{LIST} li.on-page")
    assert row.count() == 1 and row.get_attribute("aria-current") == "true"
    return row.get_attribute("data-uid")


def wait_heading(p, text):
    p.wait_for_function("(text) => document.querySelector('#details .ev-verdict h3')?.textContent === text", arg=text)


def wait_status(p, text):
    p.wait_for_function("(text) => document.getElementById('status').textContent.startsWith(text)", arg=text)


def test_a_lead_s_list_names_its_events_and_its_ticks_mark_part_of_them(browser, overview_case):  # noqa: F811
    """Open on timeline for a lead of three events: the list under the mark buttons has a caption with its count, a tick
    on each row whose hover says it selects the event, and the earliest event's row highlighted, as the page shows that
    event. An untick takes the event out of the timeline selection and leaves its row listed, and the marks then act on
    the ticked rows only. The page stays on its event when that one is unticked. Select all ticks every row and then
    reads Select none, which leaves nothing to mark: the marks, the tag button, and + Finding ask for a tick and write
    nothing."""
    app, _ = app_with_work(overview_case)
    app.con.close()
    for p in served_page(browser, overview_case, tab="overview", setup=no_tool_scan):
        uids = open_lead(p)
        caption = p.locator(CAPTION)
        assert caption.locator("strong").inner_text() == "The 3 selected events, in time order"
        assert caption.locator(".sel-in-view").is_hidden()   # three rows fit in the box
        assert ticks(p) == [True, True, True]
        box = p.locator(f"{LIST} li input[type=checkbox]").first
        assert box.get_attribute("aria-label") == "Tick to mark"
        assert box.get_attribute("title") == ("A tick selects the event on the timeline, and the marks above act on the "
                                              "selected events")
        wait_heading(p, "Verdict for 3 selected events")
        assert p.evaluate("window.__app.S.focus") == uids[0] and on_page(p) == uids[0]
        # An untick: out of the selection, still listed, and the marks act on the two ticked
        p.locator(f"{LIST} li[data-uid='{uids[2]}'] input").click()
        wait_heading(p, "Verdict for 2 selected of 3 listed events")
        assert selected(p) == sorted(uids[:2]) and ticks(p) == [True, True, False] and rows(p) == uids
        assert caption.locator("strong").inner_text() == "The 3 listed events, in time order"
        p.locator("#details .ev-verdict").get_by_role("button", name="Suspicious (2)").click()
        wait_status(p, "Marked 2 events Suspicious")
        p.wait_for_function(f"() => [...document.querySelectorAll('{LIST} .badge')].map((b) => b.textContent).join() "
                            "=== 'S,S,U'")
        # The page's own event unticked: the page stays on it, its row still highlighted
        p.locator(f"{LIST} li[data-uid='{uids[0]}'] input").click()
        wait_heading(p, "Verdict for 1 selected of 3 listed events")
        assert p.locator("#details").get_attribute("data-key") == f"event:{uids[0]}" and on_page(p) == uids[0]
        assert ticks(p) == [False, True, False]
        # One button: Select all ticks every row, then reads Select none, which leaves nothing to mark
        caption.get_by_role("button", name="Select all").click()
        wait_heading(p, "Verdict for 3 selected events")
        assert selected(p) == sorted(uids) and ticks(p) == [True, True, True]
        assert caption.get_by_role("button", name="Select all").count() == 0
        caption.get_by_role("button", name="Select none").click()
        wait_heading(p, "Verdict for 0 selected of 3 listed events")
        assert selected(p) == [] and rows(p) == uids
        written = journal_length(overview_case)
        verdict = p.locator("#details .ev-verdict")
        verdict.get_by_role("button", name="Malicious (0)").click()
        wait_status(p, "Tick the events to mark first.")
        verdict.get_by_role("button", name="Tag 0 selected events").click()
        wait_status(p, "Tick the events to tag first.")
        assert p.locator("#quickMenu").is_hidden()
        verdict.get_by_role("button", name="+ Finding").click()
        p.locator("#details .finding-add select").select_option("new")
        p.locator("#details .finding-add button").first.click()
        wait_status(p, "Tick the events to add first.")
        assert p.locator("#details").get_attribute("data-page") == "event"
        assert journal_length(overview_case) == written
        caption.get_by_role("button", name="Select all").click()
        wait_heading(p, "Verdict for 3 selected events")


def test_a_click_on_a_listed_row_opens_its_event_and_keeps_the_list(browser, overview_case):  # noqa: F811
    """A click on a row of a lead's list opens that event on the page and keeps the selection, the lead's window, and the
    list, with that row now highlighted. It adds no Back step, which would reopen the event alone. Back from a page
    opened after the list brings the list back, with its ticks as they were left, and so does Back after a plain click
    on the page's own event, which selects that event alone."""
    app, _ = app_with_work(overview_case)
    app.con.close()
    for p in served_page(browser, overview_case, tab="overview", setup=no_tool_scan):
        uids = open_lead(p)
        view = p.evaluate("() => ({ ...window.__app.S.view })")
        p.locator(f"{LIST} li[data-uid='{uids[1]}'] .sel-text").click()
        p.wait_for_selector(f"#details[data-key='event:{uids[1]}'] .selection-list")
        assert selected(p) == sorted(uids) and rows(p) == uids and on_page(p) == uids[1]
        assert p.evaluate("() => ({ ...window.__app.S.view })") == view
        assert p.locator("#detailsBand .back-bar").count() == 0
        p.locator(f"{LIST} li[data-uid='{uids[2]}'] input").click()
        wait_heading(p, "Verdict for 2 selected of 3 listed events")
        p.locator("#search").fill("code:4624")
        p.locator("#search").press("Enter")
        p.wait_for_selector("#details[data-page='search']")
        p.locator("#detailsBand .back-bar button").click()
        p.wait_for_selector(f"#details[data-key='event:{uids[1]}'] .selection-list")
        wait_heading(p, "Verdict for 2 selected of 3 listed events")
        assert selected(p) == sorted(uids[:2]) and ticks(p) == [True, True, False] and on_page(p) == uids[1]
        p.evaluate("(u) => window.__app.select(u, false)", uids[1])
        wait_heading(p, "Verdict")
        assert p.locator(LIST).count() == 0 and selected(p) == [uids[1]]
        assert p.locator("#detailsBand .back-bar").inner_text() == "\u2039 Back to the 3 listed events"
        p.locator("#detailsBand .back-bar button").click()
        wait_heading(p, "Verdict for 2 selected of 3 listed events")
        assert selected(p) == sorted(uids[:2]) and ticks(p) == [True, True, False] and on_page(p) == uids[1]
        assert p.locator("#detailsBand .back-bar").count() == 0


def test_the_notes_typed_on_the_page_stay_through_the_list_s_redraws_until_they_are_written(browser,  # noqa: F811
                                                                                           overview_case):  # noqa: F811
    """A tick draws the page again, and the note typed for the mark stays with the list, through the tick and a row's
    click that opens another event, until the mark journals it. The Notes box keeps its text through a tick until the
    note is added."""
    app, _ = app_with_work(overview_case)
    app.con.close()
    for p in served_page(browser, overview_case, tab="overview", setup=no_tool_scan):
        uids = open_lead(p)
        mark_note = p.locator("#details .ev-verdict .mark-note")
        event_note = p.locator("#details .ev-facts").get_by_placeholder("Add a note to this event")
        mark_note.fill("the two RDP logons")
        event_note.fill("asked the DC01 owner")
        p.locator(f"{LIST} li[data-uid='{uids[2]}'] input").click()
        wait_heading(p, "Verdict for 2 selected of 3 listed events")
        assert mark_note.input_value() == "the two RDP logons" and event_note.input_value() == "asked the DC01 owner"
        p.locator(f"{LIST} li[data-uid='{uids[1]}'] .sel-text").click()
        p.wait_for_selector(f"#details[data-key='event:{uids[1]}'] .selection-list")
        assert mark_note.input_value() == "the two RDP logons" and event_note.input_value() == ""
        written = journal_length(overview_case)
        p.locator("#details .ev-verdict").get_by_role("button", name="Suspicious (2)").click()
        wait_status(p, "Marked 2 events Suspicious")
        mark = entries(overview_case)[written]
        assert (mark["action"], sorted(mark["targets"]), mark["note"]) == ("mark", sorted(uids[:2]), "the two RDP logons")
        p.wait_for_function(f"() => [...document.querySelectorAll('{LIST} .badge')].map((b) => b.textContent).join() "
                            "=== 'S,S,U'")
        assert mark_note.input_value() == ""
        event_note.fill("seen on the firewall too")
        p.locator(f"{LIST} li[data-uid='{uids[2]}'] input").click()
        wait_heading(p, "Verdict for 3 selected events")
        assert event_note.input_value() == "seen on the firewall too"
        p.locator("#details .ev-facts").get_by_role("button", name="Add note").click()
        p.locator("#details .ev-facts .notes li", has_text="seen on the firewall too").wait_for()
        assert event_note.input_value() == ""


def test_back_and_a_reload_after_a_shift_click_takes_out_the_last_ticked_event_bring_the_list_back(
        browser, overview_case):  # noqa: F811
    """A shift-click on the timeline takes a ticked event out of the list. One that takes out the last ticked event sends
    the page to the opening hint and leaves the list as it was, so Back brings it back with that event ticked, a mark
    then marks that event alone, and F5 keeps the list."""
    app, _ = app_with_work(overview_case)
    app.con.close()
    for p in served_page(browser, overview_case, tab="overview", setup=no_tool_scan):
        uids = open_lead(p)
        p.evaluate("(u) => window.__app.select(u, true)", uids[1])
        p.wait_for_function(f"() => document.querySelectorAll('{LIST} li').length === 2")
        wait_heading(p, "Verdict for 2 selected events")
        assert rows(p) == [uids[0], uids[2]] and on_page(p) == uids[0]
        p.locator(f"{LIST} li[data-uid='{uids[0]}'] input").click()
        wait_heading(p, "Verdict for 1 selected of 2 listed events")
        p.evaluate("(u) => window.__app.select(u, true)", uids[2])
        p.wait_for_selector("#details[data-page='hint']")
        assert selected(p) == [] and p.evaluate("window.__app.S.focus") is None
        p.locator("#detailsBand .back-bar button").click()
        p.wait_for_selector(f"#details[data-key='event:{uids[0]}'] .selection-list")
        wait_heading(p, "Verdict for 1 selected of 2 listed events")
        assert rows(p) == [uids[0], uids[2]] and ticks(p) == [False, True] and selected(p) == [uids[2]]
        written = journal_length(overview_case)
        page_mark = p.locator(f"{LIST} li[data-uid='{uids[0]}'] .badge").inner_text()
        p.locator("#details .ev-verdict").get_by_role("button", name="Suspicious (1)").click()
        wait_status(p, "Marked one event Suspicious")
        p.wait_for_function(f"() => [...document.querySelectorAll('{LIST} .badge')].map((b) => b.textContent).join() === "
                            f"'{page_mark},S'")
        assert journal_length(overview_case) == written + 1
        reload(p)
        p.wait_for_function(f"() => document.querySelectorAll('{LIST} li').length === 2")
        wait_heading(p, "Verdict for 1 selected of 2 listed events")
        assert ticks(p) == [False, True] and selected(p) == [uids[2]] and on_page(p) == uids[0]


def test_the_selection_list_s_find_narrows_its_rows_and_stays_through_the_events_they_open(browser,  # noqa: F811
                                                                                          overview_case):  # noqa: F811
    """The selection list's find box shows only the rows holding its words, and its one select button acts on the rows
    it shows, reading Unselect once every shown row is ticked; the box says how many selected events it hides, and the
    line under the list that the selection and the marks still cover every row. Its text stays through a tick's redraw
    and when a row opens another event, as the list does. Clear shows every row."""
    app, _ = app_with_work(overview_case)
    app.con.close()
    for p in served_page(browser, overview_case, tab="overview", setup=no_tool_scan):
        uids = open_lead(p)
        texts = p.locator(f"{LIST} .sel-text").all_inner_texts()
        word = texts[2].split()[1]   # the last event's time of day
        assert sum(word in t for t in texts) == 1, texts
        caption = p.locator(CAPTION)
        find = caption.locator(".find input")
        find.fill(word)
        assert rows(p, shown=True) == [uids[2]]
        assert caption.locator(".find-words").inner_text() == "1 of 3 rows match"
        assert caption.locator(".find-ticks").inner_text() == "2 selected events aren't shown here"
        assert p.locator("#details .find-foot").inner_text().startswith(
            "2 rows don't hold every word of the find. The selection and the marks still cover all 3.")
        assert caption.get_by_role("button", name="Select the 1 shown", exact=True).count() == 0
        caption.get_by_role("button", name="Unselect the 1 shown").click()
        wait_heading(p, "Verdict for 2 selected of 3 listed events")
        assert selected(p) == sorted(uids[:2])
        assert find.input_value() == word and rows(p, shown=True) == [uids[2]]
        p.locator(f"{LIST} li[data-uid='{uids[2]}'] .sel-text").click()
        p.wait_for_selector(f"#details[data-key='event:{uids[2]}'] .selection-list")
        assert find.input_value() == word and rows(p, shown=True) == [uids[2]] and on_page(p) == uids[2]
        assert caption.get_by_role("button", name="Unselect the 1 shown").count() == 0
        caption.get_by_role("button", name="Select the 1 shown", exact=True).click()
        wait_heading(p, "Verdict for 3 selected events")
        assert selected(p) == sorted(uids) and find.input_value() == word
        caption.locator(".find-clear").click()
        assert rows(p, shown=True) == uids and find.input_value() == ""
        # One selected event the find hides
        p.locator(f"{LIST} li[data-uid='{uids[0]}'] input").click()
        wait_heading(p, "Verdict for 2 selected of 3 listed events")
        find.fill(word)
        assert rows(p, shown=True) == [uids[2]]
        assert caption.locator(".find-ticks").inner_text() == "1 selected event isn't shown here"


def test_a_shift_click_that_adds_an_event_the_find_hides_leaves_the_list_where_it_was(browser,  # noqa: F811
                                                                                      overview_case):  # noqa: F811
    """With a find on, a shift-click on the timeline that adds an event the find doesn't show opens that event, and the
    list stays where it was scrolled rather than moving to the hidden row."""
    for p in served_page(browser, overview_case, setup=no_tool_scan):
        accepted = p.evaluate("() => [...new Set(window.__app.S.data.events.filter((e) => e.code === '131').map((e) => e.uid))]")
        flow = p.evaluate("() => window.__app.S.data.events.find((e) => (e.msg || '').startsWith('Flow ')).uid")
        assert len(accepted) == 10
        p.evaluate("(us) => { const a = window.__app; a.select(us[0], false); for (const u of us.slice(1)) a.select(u, true); }",
                   accepted)
        p.wait_for_function(f"() => document.querySelectorAll('{LIST} li').length === 10")
        wait_heading(p, "Verdict for 10 selected events")
        p.locator(f"{CAPTION} .find input").fill("accepted")
        assert len(rows(p, shown=True)) == 10
        box = p.locator(LIST)
        box.evaluate("(n) => { n.scrollTop = n.scrollHeight; }")
        p.wait_for_function("() => window.__app.S.listed.scroll > 0")
        top = box.evaluate("(n) => n.scrollTop")
        p.evaluate("(u) => window.__app.select(u, true)", flow)
        p.wait_for_selector(f"#details[data-key='event:{flow}'] .selection-list")
        wait_heading(p, "Verdict for 11 selected events")
        assert on_page(p) == flow and flow not in rows(p, shown=True)
        assert box.evaluate("(n) => n.scrollTop") == top


def test_a_long_selection_list_says_how_many_rows_are_in_view_and_a_reload_keeps_its_unticked_rows(
        browser, synthetic_case):  # noqa: F811
    """A list longer than its box says how many of its rows are in view and that it scrolls for the rest. A row opened
    from low in the list keeps the list where it was scrolled. F5 brings back the list's rows, an unticked one still
    unticked and left out of the selection. A shift-click on the timeline that adds an event out of the box's view
    scrolls the list to its row."""
    for p in served_page(browser, synthetic_case):
        # Eleven events: the latest is added last, so its row lands below the box's view
        events = p.evaluate("() => [...new Map(window.__app.S.data.events.map((e) => [e.uid, e.ts]))].slice(0, 11)")
        assert len(events) == 11
        late = max(events, key=lambda e: e[1])[0]
        picked = [uid for uid, _ in events if uid != late]
        p.evaluate("(us) => { const a = window.__app; a.select(us[0], false); for (const u of us.slice(1)) a.select(u, true); }",
                   picked)
        p.wait_for_function(f"() => document.querySelectorAll('{LIST} li').length === 10")
        wait_heading(p, "Verdict for 10 selected events")
        assert p.locator(f"{CAPTION} .sel-in-view").inner_text() == "8 of 10 in view; scroll for the rest"
        box = p.locator(LIST)
        assert box.evaluate("(n) => Math.floor(n.clientHeight / n.querySelector('li').offsetHeight)") == 8
        listed = rows(p)
        box.evaluate("(n) => { n.scrollTop = n.scrollHeight; }")
        top = box.evaluate("(n) => n.scrollTop")
        assert top > 0
        target = next(u for u in reversed(listed) if u != on_page(p))
        p.locator(f"{LIST} li[data-uid='{target}'] .sel-text").click()
        p.wait_for_selector(f"#details[data-key='event:{target}'] .selection-list")
        assert box.evaluate("(n) => n.scrollTop") == top and on_page(p) == target
        p.locator(f"{LIST} li[data-uid='{listed[0]}'] input").click()
        wait_heading(p, "Verdict for 9 selected of 10 listed events")
        reload(p)
        p.wait_for_function(f"() => document.querySelectorAll('{LIST} li').length === 10")
        wait_heading(p, "Verdict for 9 selected of 10 listed events")
        assert rows(p) == listed and ticks(p) == [False] + [True] * 9
        assert selected(p) == sorted(listed[1:]) and p.evaluate("window.__app.S.focus") == target
        box.evaluate("(n) => { n.scrollTop = 0; }")
        p.wait_for_function("() => window.__app.S.listed.scroll === 0")
        p.evaluate("(u) => window.__app.select(u, true)", late)
        p.wait_for_selector(f"#details[data-key='event:{late}'] .selection-list")
        wait_heading(p, "Verdict for 10 selected of 11 listed events")
        assert rows(p).index(late) >= 8 and on_page(p) == late
        assert box.evaluate("(n) => { const r = n.querySelector('li.on-page').getBoundingClientRect(), "
                            "b = n.getBoundingClientRect(); return r.top >= b.top && r.bottom <= b.bottom; }")


def bulk_logons(case, count):
    """Load `count` logons on DC01 into the case, a second apart. Returns a list, and the served page's setup, which
    fills it with their IDs in time order."""
    many = [logon(T0 + (2000 + n) * SEC, 20000 + n, DC_LOG, user="bulk", ltype="3", ip="10.42.85.50") for n in range(count)]
    load(case.db_path, many, host="DC01", tool="evtxecmd", tool_version="t", run_id="bulk", replaces_sources=[],
         staging_dir=case.folder)
    bulk = []

    def setup(app):
        bulk.extend(r[0] for r in app.con.execute("SELECT event_uid FROM events WHERE run_id = 'bulk' ORDER BY ts_us")
                    .fetchall())

    return bulk, setup


def list_all(p, uids):
    """Select the events and open the first, as Open on timeline does, once the list shows them, up to the 500 it holds"""
    p.evaluate("(us) => { const a = window.__app; a.S.selected = new Set(us); a.jumpTo({ uid: us[0], ts: null }, true); }",
               uids)
    wait_rows(p, min(len(uids), 500))
    wait_heading(p, f"Verdict for {len(uids)} selected events")


def wait_rows(p, n):
    p.wait_for_function(f"() => document.querySelectorAll('{LIST} li').length === {n}", timeout=60000)


def test_a_reload_of_a_list_over_500_with_none_or_a_few_ticked_keeps_the_list_and_the_unticked_event_on_the_page(
        browser, synthetic_case):  # noqa: F811
    """F5 on a list of more than 500 events, with the event on the page unticked, brings back the whole list and its
    ticks, with none ticked and then with three. That event stays unticked, so the next mark leaves it out."""
    bulk, setup = bulk_logons(synthetic_case, 510)
    for p in served_page(browser, synthetic_case, setup=setup):
        list_all(p, bulk)
        p.locator(CAPTION).get_by_role("button", name="Select none").click()
        wait_heading(p, "Verdict for 0 selected of 510 listed events")
        reload(p)
        wait_rows(p, 500)
        wait_heading(p, "Verdict for 0 selected of 510 listed events")
        assert rows(p) == bulk[:500] and ticks(p) == [False] * 500 and on_page(p) == bulk[0] and selected(p) == []
        for n, uid in enumerate(bulk[1:4], 1):
            p.locator(f"{LIST} li[data-uid='{uid}'] input").click()
            wait_heading(p, f"Verdict for {n} selected of 510 listed events")
        reload(p)
        wait_rows(p, 500)
        wait_heading(p, "Verdict for 3 selected of 510 listed events")
        assert rows(p) == bulk[:500] and ticks(p) == [False, True, True, True] + [False] * 496 and on_page(p) == bulk[0]
        assert selected(p) == sorted(bulk[1:4])


def test_a_reload_of_a_long_list_keeps_500_and_501_ticked_events_and_the_unticked_event_on_the_page(
        browser, synthetic_case):  # noqa: F811
    """F5 on a list of more than 500 events, with the event on the page unticked and 501 or exactly 500 others ticked,
    brings back the whole list with every ticked event, and that event still unticked. The 500 a list holds doesn't cut
    the ticked events to the event on the page alone, which would select it, nor does it tick that event again."""
    bulk, setup = bulk_logons(synthetic_case, 510)
    for p in served_page(browser, synthetic_case, setup=setup):
        list_all(p, bulk)
        # 501 ticked: the last 8 events out of the selection, then the event on the page unticked
        p.evaluate("(us) => { for (const u of us) window.__app.S.selected.delete(u); }", bulk[502:])
        p.locator(f"{LIST} li[data-uid='{bulk[0]}'] input").click()
        wait_heading(p, "Verdict for 501 selected of 510 listed events")
        reload(p)
        wait_rows(p, 500)
        wait_heading(p, "Verdict for 501 selected of 510 listed events")
        assert selected(p) == sorted(bulk[1:502]) and on_page(p) == bulk[0]
        assert rows(p) == bulk[:500] and ticks(p) == [False] + [True] * 499
        # Exactly 500 ticked
        p.locator(f"{LIST} li[data-uid='{bulk[1]}'] input").click()
        wait_heading(p, "Verdict for 500 selected of 510 listed events")
        reload(p)
        wait_rows(p, 500)
        wait_heading(p, "Verdict for 500 selected of 510 listed events")
        assert selected(p) == sorted(bulk[2:502]) and on_page(p) == bulk[0]
        assert rows(p) == bulk[:500] and ticks(p) == [False, False] + [True] * 498


def test_a_reload_of_a_long_list_keeps_it_whole_with_the_ticked_event_on_the_page_among_its_rows(
        browser, synthetic_case):  # noqa: F811
    """F5 on a list of more than 500 events, with the event on the page ticked and past the list's 500th row, and two
    others unticked, brings back the whole list with its ticks. That event stays ticked and on the page, and its row is
    among the 500 the list shows, rather than the selection coming back as that event alone. With every row ticked, the
    list is a selection of more than 500, which F5 keeps as that event alone."""
    bulk, setup = bulk_logons(synthetic_case, 510)
    for p in served_page(browser, synthetic_case, setup=setup):
        focus = bulk[505]
        p.evaluate("([us, u]) => { const a = window.__app; a.S.selected = new Set(us); a.jumpTo({ uid: u, ts: null }, true); }",
                   [bulk, focus])
        p.wait_for_selector(f"#details[data-key='event:{focus}'] .selection-list")
        wait_rows(p, 500)
        wait_heading(p, "Verdict for 510 selected events")
        assert rows(p) == bulk[:500]
        # Two unticked: one past the rows the list shows, then the first row
        p.evaluate("(u) => window.__app.S.selected.delete(u)", bulk[507])
        p.locator(f"{LIST} li[data-uid='{bulk[0]}'] input").click()
        wait_heading(p, "Verdict for 508 selected of 510 listed events")
        kept = sorted(set(bulk) - {bulk[0], bulk[507]})
        assert selected(p) == kept
        reload(p)
        wait_rows(p, 500)
        wait_heading(p, "Verdict for 508 selected of 510 listed events")
        assert p.evaluate("[...window.__app.S.listed.uids].sort()") == sorted(bulk)
        assert p.evaluate("window.__app.S.listed.of === window.__app.S.selected") and selected(p) == kept
        assert p.evaluate("window.__app.S.focus") == focus and on_page(p) == focus
        assert rows(p) == [*bulk[:499], focus] and ticks(p) == [False] + [True] * 499
        # Every row ticked: a selection of 510, kept as the event on the page alone
        p.locator(CAPTION).get_by_role("button", name="Select all").click()
        wait_heading(p, "Verdict for 510 selected events")
        assert selected(p) == sorted(bulk)
        reload(p)
        p.wait_for_selector(f"#details[data-key='event:{focus}'] .ev-ident")
        wait_heading(p, "Verdict")
        assert selected(p) == [focus] and p.evaluate("window.__app.S.focus") == focus
        assert p.locator(LIST).count() == 0


def test_a_tick_while_the_mark_question_shows_takes_it_away_and_the_next_mark_covers_the_ticked_events(
        browser, synthetic_case):  # noqa: F811
    """A mark of more than 25 listed events asks first, under the list. A tick while the question shows draws the page
    again without the question and writes nothing; the next mark asks for the ticked events and marks them alone."""
    bulk, setup = bulk_logons(synthetic_case, 30)
    for p in served_page(browser, synthetic_case, setup=setup):
        list_all(p, bulk)
        question = p.locator("#details .confirm-slot .confirm-block")
        verdict = p.locator("#details .ev-verdict")
        written = journal_length(synthetic_case)
        verdict.get_by_role("button", name="Suspicious (30)").click()
        question.locator(".confirm-title", has_text="Mark 30 events Suspicious?").wait_for()
        p.locator(f"{LIST} li[data-uid='{bulk[29]}'] input").click()
        wait_heading(p, "Verdict for 29 selected of 30 listed events")
        assert question.count() == 0 and journal_length(synthetic_case) == written
        verdict.get_by_role("button", name="Suspicious (29)").click()
        question.locator(".confirm-title", has_text="Mark 29 events Suspicious?").wait_for()
        question.get_by_role("button", name="Mark 29", exact=True).click()
        wait_status(p, "Marked 29 events Suspicious")
        assert journal_length(synthetic_case) == written + 1
        mark = entries(synthetic_case)[written]
        assert (mark["action"], mark["value"], sorted(mark["targets"]), mark["confirmed"]["count"]) == (
            "mark", "suspicious", sorted(bulk[:29]), 29)


def test_tag_and_add_to_a_finding_act_on_the_ticked_events_and_the_tag_picker_names_them(browser,  # noqa: F811
                                                                                        overview_case):  # noqa: F811
    """With a row unticked, the tag button and + Finding's Add act on the ticked events alone. With one row ticked and
    the page on another event, the tag picker's head repeats the button's "Tag 1 selected event" rather than reading
    "Tag this event", which would name the page's."""
    app, uid = app_with_work(overview_case)
    fid = api_finding(app, {"op": "add", "title": "The log clear", "severity": "Low", "targets": [uid[301]]})["finding"]
    app.con.close()
    for p in served_page(browser, overview_case, tab="overview", setup=no_tool_scan):
        uids = open_lead(p)
        verdict = p.locator("#details .ev-verdict")
        menu = p.locator("#quickMenu")
        own_tag = menu.get_by_label("Your own tag")
        p.locator(f"{LIST} li[data-uid='{uids[2]}'] input").click()
        wait_heading(p, "Verdict for 2 selected of 3 listed events")
        written = journal_length(overview_case)
        verdict.get_by_role("button", name="Tag 2 selected events").click()
        own_tag.wait_for()
        assert menu.locator(".menu-head > div").first.inner_text() == "Tag 2 selected events"
        own_tag.fill("rdp pair")
        own_tag.press("Enter")
        wait_status(p, "Tagged 2 events: rdp pair")
        verdict.get_by_role("button", name="+ Finding").click()
        p.wait_for_function("() => document.querySelector('#details .finding-add select option[value=\"new\"]') !== null")
        row = p.locator("#details .finding-add")
        row.get_by_label("Finding to add to").select_option(str(fid))
        row.get_by_role("button", name="Add the 2 selected events").click()
        wait_status(p, "Linked 2 events to the finding")
        tag, link = entries(overview_case)[written:]
        assert (tag["action"], sorted(tag["targets"]), tag["add"]) == ("tag", sorted(uids[:2]), ["tag:rdp pair"])
        assert (link["action"], link["op"], link["finding"], sorted(link["targets"])) == (
            "finding", "link", fid, sorted(uids[:2]))
        # One row ticked, and the page on another event
        p.locator(f"{LIST} li[data-uid='{uids[0]}'] input").click()
        wait_heading(p, "Verdict for 1 selected of 3 listed events")
        assert selected(p) == [uids[1]] and on_page(p) == uids[0]
        verdict.get_by_role("button", name="Tag 1 selected event").click()
        own_tag.wait_for()
        assert menu.locator(".menu-head > div").first.inner_text() == "Tag 1 selected event"
        own_tag.fill("lateral")
        own_tag.press("Enter")
        wait_status(p, "Tagged one event: lateral")
        tag = entries(overview_case)[-1]
        assert (tag["action"], tag["targets"], tag["add"]) == ("tag", [uids[1]], ["tag:lateral"])
