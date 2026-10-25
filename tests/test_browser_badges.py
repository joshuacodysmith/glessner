"""The review-state badge in a real browser: one component in every event list and the identity line, its tokens in
both schemes, the list's row grid and its sticky Mark header, and the hover that names who marked an event and when.
They also cover the right-click menu's head, the tooltip, and the state and status lines' totals.
They drive the installed Microsoft Edge through Playwright, as test_browser_smoke does, and are skipped without it."""

import json
import re
from dataclasses import replace

import pytest
from conftest import DC_LOG, SEC, T0, logon
from test_browser_design import computed, near, open_event, token
from test_browser_frame import no_tool_scan
from test_browser_pivots import select
from test_browser_smoke import (  # noqa: F401
    POINT,
    RECORD_REQUESTS,
    browser,
    case_menu,
    event_point,
    latest_lone_point,
    open_all,
    point_of,
    served_page,
    shift_click,
)
from test_overview import app_with_work, overview_case  # noqa: F401

from glessner.events import load
from glessner.journal import JOURNAL_FILE
from glessner.server import api_mark, api_search, api_undo

pytestmark = pytest.mark.browser
SCHEMES = ["light", "dark"]
HOVER = re.compile(r"^(Suspicious|Malicious|Authorized), marked by \S+, \d{4}-\d\d-\d\d \d\d:\d\d UTC$")
NODE_BOX = ("(n) => { const b = n.getBoundingClientRect(); "
           "return { top: b.top, bottom: b.bottom, left: b.left, right: b.right }; }")
BODY = "#detailsBody"
# The events drawn within 3 px of a point of the lanes canvas (page coordinates), as the pile list takes them
UNDER = """([x, y]) => { const r = document.getElementById('lanes').getBoundingClientRect();
    return window.__app.S.index[Math.floor((y - r.top) / 20)].filter((it) => it.kind === 'event'
        && Math.abs(it.x - (x - r.left)) <= 3).map((it) => it.e.uid); }"""
EPOCH_1980 = 315_532_800 * SEC + 120_000   # 40 years before the case, and not on a whole second
LONG_HOST = "ALPHA-BACKUP-FILESERVER-01"
LONG_MESSAGE = "4624 logon " + "a very long message that has to wrap inside the event column, and keep the cells at the top " * 3


def box(p, selector):
    return p.locator(selector).first.evaluate(NODE_BOX)


def search(p, query):
    p.locator("#search").fill(query)
    p.locator("#search").press("Enter")
    p.wait_for_selector("#details[data-page='search'] li.rel-row")


def letters(p, scope):
    return p.locator(f"{scope} .badge").all_inner_texts()


def titles(p, scope):
    return p.locator(f"{scope} .badge").evaluate_all("(ns) => ns.map((n) => n.title)")


def badge_beside_text(p, selector):
    """A list that puts the badge before the row's text has no bullet and a gap between the two (it is the list itself, class
    related badged, not a list inside a .related)."""
    return p.locator(selector).first.evaluate("""(ul) => { const li = ul.querySelector('li'), b = li.querySelector('.badge');
        const text = [...li.children].find((n) => !n.matches('.badge'));
        const gap = text.getBoundingClientRect().left - b.getBoundingClientRect().right;
        return getComputedStyle(ul).listStyleType === 'none' && gap >= 6; }""")


def check_badged_rows(p, scope):
    """Every row of the list has one badge as its second child, and the heading row starts with "Mark"."""
    rows = p.locator(f"{scope} li.rel-row").all()
    assert rows
    for r in rows:
        assert r.evaluate("(n) => n.children[1].matches('span.badge') && n.querySelectorAll('.badge').length === 1")
    assert p.locator(f"{scope} li.rel-head").inner_text().startswith("Mark")


@pytest.mark.parametrize("scheme", SCHEMES)
def test_badges_take_their_tokens(browser, synthetic_case, scheme):  # noqa: F811
    """One badge of each class computes its color, background, and border from the tokens in both schemes: U a hollow ring
    in the text blue, A and M filled with --on-fill, S in amber with a dark letter and an amber-text border."""
    want = {"u": ("--unreviewed-text", None, "--unreviewed-text"), "a": ("--on-fill", "--fill-authorized", "--fill-authorized"),
            "s": ("--on-amber", "--fill-suspicious", "--suspicious-text"),
            "m": ("--on-fill", "--fill-malicious", "--fill-malicious")}
    for p in served_page(browser, synthetic_case, color_scheme=scheme):
        p.evaluate("""async () => {
            const { markBadge } = await import('/js/core.js');
            for (const mark of ['Unreviewed', 'Authorized', 'Suspicious', 'Malicious']) {
                const holder = document.createElement('div');
                holder.className = 'badge-probe';
                holder.append(markBadge({ mark }));
                document.body.append(holder);
            }
        }""")
        for cls, (text, fill, edge) in want.items():
            sel = f".badge-probe .badge.{cls}"
            assert near(computed(p, sel, "color"), token(p, text)), (scheme, cls)
            assert near(computed(p, sel, "borderTopColor"), token(p, edge)), (scheme, cls)
            if fill:
                assert near(computed(p, sel, "backgroundColor"), token(p, fill)), (scheme, cls)
            else:
                hollow = p.locator(sel).first.evaluate("(n) => getComputedStyle(n).backgroundColor")
                assert hollow == "rgba(0, 0, 0, 0)", (scheme, cls, hollow)   # U is hollow
            b = box(p, sel)
            assert (b["right"] - b["left"], b["bottom"] - b["top"]) == (16, 16), (scheme, cls)


def test_the_correction_tag_keeps_its_width(browser, synthetic_case):  # noqa: F811
    """The audit trail's "correction: accident" label is a .correction-tag, not a .badge, so the review-state badge's
    16 px box doesn't squeeze it: the tag is wider than the badge."""
    def undone(app):
        uid = api_search(app, {"q": ["code:4624"]})["events"][0]["uid"]
        seq = api_mark(app, {"uids": [uid], "value": "malicious", "note": ""})["seq"]
        api_undo(app, {"seq": seq, "note": ""})

    for p in served_page(browser, synthetic_case, setup=undone):
        case_menu(p, "auditButton")
        p.wait_for_selector("#details .audit-row.correction")
        tag = p.locator("#details .audit-row.correction .correction-tag")
        assert tag.inner_text() == "correction: accident"
        b = box(p, "#details .audit-row.correction .correction-tag")
        assert b["right"] - b["left"] > 60
        assert p.locator("#details .audit-row .badge").count() == 0


def test_every_search_row_has_a_badge_and_a_mark_reads_who_and_when(browser, synthetic_case):  # noqa: F811
    """Each result row has a badge; two ticked rows marked Suspicious read S after the re-search, with a hover that
    names the analyst and the time, and an unmarked row's hover is the word alone. The account pivot's list works the same."""
    for p in served_page(browser, synthetic_case):
        search(p, "code:4624")
        check_badged_rows(p, "#details")
        plain = p.locator("#details li.rel-row:not(:has(.tag)) .badge.u").first
        assert plain.get_attribute("title") == "Unreviewed" and plain.get_attribute("aria-label") == "Unreviewed"
        for i in (0, 1):
            p.locator("#details li.rel-row input").nth(i).check()
        p.get_by_role("button", name="Mark 2 Suspicious").click()
        p.wait_for_function("() => document.querySelectorAll('#details li.rel-row .badge.s').length === 2")
        marked = p.locator("#details li.rel-row .badge.s")
        assert marked.all_inner_texts() == ["S", "S"]
        hovers = marked.evaluate_all("(ns) => ns.map((n) => n.title)")
        assert all(HOVER.match(t) for t in hovers), hovers
        assert marked.first.get_attribute("aria-label") == hovers[0]
        # The account pivot's list, from one of the marked events
        p.locator("#details li.rel-row:has(.badge.s) .rel-text").first.click()
        p.wait_for_selector("#details[data-page='event'] .ev-ident")
        p.locator('#details .pv[data-pivot="account"] button.pv-go').click()
        p.wait_for_selector("#relatedList li.rel-row")
        check_badged_rows(p, "#relatedList")
        assert p.locator("#relatedList li.rel-row .badge.s").count() >= 1
        assert p.locator("#relatedList li.rel-row .badge.u").count() > 0
        p.locator("#relatedList li.rel-row:has(.badge.u) input").first.check()
        p.locator("#relatedList").get_by_role("button", name="Mark 1 Malicious").click()
        p.wait_for_function("() => document.querySelectorAll('#relatedList li.rel-row .badge.m').length === 1")
        assert HOVER.match(p.locator("#relatedList li.rel-row .badge.m").first.get_attribute("title"))


def test_the_list_an_overview_count_opens_has_badges(browser, overview_case):  # noqa: F811
    """The list an overview count opens: the events marked Suspicious each read S, with the analyst and the time, and
    the ones DC01 has a suggestion for read U with the suggestion in the hover."""
    app, _ = app_with_work(overview_case)
    app.con.close()
    for p in served_page(browser, overview_case, setup=no_tool_scan):
        p.locator("#tabOverview").click()
        p.locator("#ovProgress .ov-legend").get_by_role("button").nth(1).click()   # the Suspicious count
        p.wait_for_selector("#details h2:text-is('Events marked Suspicious')")
        check_badged_rows(p, "#details")
        assert letters(p, "#details li.rel-row") == ["S"]   # app_with_work marks one event Suspicious
        assert all(HOVER.match(t) for t in titles(p, "#details li.rel-row"))
        p.locator("#tabOverview").click()
        p.locator("#ovByHost tr[data-host='DC01'] td.num").nth(1).get_by_role("button").click()   # DC01's pending count
        p.wait_for_selector("#details h2:text-is('DC01: events with a pending suggestion')")
        check_badged_rows(p, "#details")
        assert set(letters(p, "#details li.rel-row")) == {"U"}
        assert all(t.startswith("Unreviewed, with a pending ") for t in titles(p, "#details li.rel-row"))


def test_an_event_opened_from_an_overview_list_starts_a_new_trail(browser, overview_case):  # noqa: F811
    """An event opened from the Case overview's list isn't added to the pivot trail on screen as if that pivot had
    listed it, so Save trail journals no path that was never taken. Only a pivot's list and a search the trail ran
    continue the trail."""
    app, uid = app_with_work(overview_case)
    app.con.close()
    for p in served_page(browser, overview_case, setup=no_tool_scan):
        select(p, uid[101])
        p.locator('#details .pv[data-pivot="window"] button.pv-go').click()
        p.wait_for_function("() => window.__app.S.trail.length === 2")
        p.locator("#tabOverview").click()
        p.locator("#ovProgress .ov-legend").get_by_role("button").nth(1).click()   # the Suspicious count
        p.wait_for_selector("#details h2:text-is('Events marked Suspicious')")
        p.locator("#details li.rel-row").first.click()
        p.wait_for_selector("#details[data-page='event'] .ev-ident")
        assert p.evaluate("[window.__app.S.trail.length, window.__app.S.trailAt]") == [1, 0]
        assert p.locator("#details nav.trail").count() == 0


def test_the_mark_header_stays_over_the_rows(browser, synthetic_case, tmp_path):  # noqa: F811
    """At a 200 px panel, after scrolling to the last row, the Mark header is inside the panel just under the sticky head. Its
    Mark label starts where the first row's tick box does, and its Event label where the row's event cell does, on a
    search and on an address pivot's list, whose End column lines up as well."""
    from test_analysis_relations import load_inbound

    uids = load_inbound(synthetic_case, tmp_path)
    for p in served_page(browser, synthetic_case):
        p.evaluate("() => { document.getElementById('details').style.flex = '0 0 200px'; }")
        search(p, "code:4624")
        assert p.locator("#details li.rel-row").count() > 3
        p.locator(BODY).evaluate("(n) => { n.scrollTop = n.scrollHeight; }")
        body, head, header = box(p, BODY), box(p, "#details .sticky-head"), box(p, "#details li.rel-head")
        assert body["top"] <= header["top"] and header["bottom"] <= body["bottom"], (body, header)
        assert abs(header["top"] - head["bottom"]) <= 2, (header, head)
        assert abs(box(p, "#details li.rel-head .rel-mark")["left"] - box(p, "#details li.rel-row input")["left"]) <= 1
        assert abs(box(p, "#details li.rel-head .rel-event")["left"] - box(p, "#details li.rel-row .rel-event")["left"]) <= 1
        # An address pivot's list, in the work column, has the End column as well
        p.locator("#tabTimeline").click()
        select(p, uids["inbound"])
        p.locator('#details .pv[data-pivot="addr"] button.pv-go').first.click()
        p.wait_for_selector("#relatedList li.rel-row")
        p.locator("#details .ev-work").evaluate("(n) => { n.scrollTop = n.scrollHeight; }")
        work, header = box(p, "#details .ev-work"), box(p, "#relatedList li.rel-head")
        assert work["top"] <= header["top"] + 1 and header["bottom"] <= work["bottom"] + 1, (work, header)
        for cell, row in (("rel-mark", "input"), ("rel-event", ".rel-event"), ("rel-col", ".rel-col")):
            gap = box(p, f"#relatedList li.rel-head .{cell}")["left"] - box(p, f"#relatedList li.rel-row {row}")["left"]
            assert abs(gap) <= 1, (cell, gap)
        head = p.locator("#relatedList li.rel-head .rel-col")
        assert head.inner_text() == "End" and head.get_attribute("title") == "Which end of the connection held the address"


def test_a_search_row_has_no_offset_and_keeps_its_highlight(browser, synthetic_case):  # noqa: F811
    """A search has no event to measure from, so its rows have no Offset cell and the five-column grid; the host cell holds
    the highlight of the host's own search term."""
    for p in served_page(browser, synthetic_case):
        search(p, "DC01")
        assert "search" in p.locator("#details ul.rows").get_attribute("class").split()
        assert p.locator("#details li.rel-row .off").count() == 0 and p.locator("#details li.rel-head .off").count() == 0
        assert "Offset" not in p.locator("#details li.rel-head").inner_text()
        hosts = p.locator("#details li.rel-row .rel-host:has(mark)")
        assert hosts.count() >= 3 and set(hosts.locator("mark").all_inner_texts()) == {"DC01"}
        assert p.locator("#details li.rel-row .rel-event mark").count() > 0   # the message and the excerpt keep theirs
        grid = "(n) => getComputedStyle(n).gridTemplateColumns.split(' ').length"
        tracks = p.locator("#details li.rel-row").first.evaluate(grid)
        assert tracks == 5


def test_the_selection_list_has_badges(browser, synthetic_case):  # noqa: F811
    """The selection list leads each row with the badge, M and U here, the marked one with the analyst and the time; the
    end pill that said the mark in words is gone."""
    for p in served_page(browser, synthetic_case):
        rdp = event_point(p, "4624", hit=True)
        p.evaluate("(uid) => window.__app.select(uid, false)", rdp["uid"])
        p.locator("#details .ev-verdict").get_by_role("button", name="Malicious", exact=True).click()
        p.wait_for_function("(uid) => window.__app.S.data.events.some((e) => e.uid === uid && e.mark === 'Malicious')",
                            arg=rdp["uid"])
        p.evaluate("(uid) => window.__app.select(uid, true)", event_point(p, "4672")["uid"])
        p.wait_for_selector("#details .ev-head-more .selection-list .badge")
        assert letters(p, "#details .selection-list li") == ["M", "U"]   # in time order
        first, second = titles(p, "#details .selection-list")
        assert HOVER.match(first) and first.startswith("Malicious, marked by ") and second == "Unreviewed"
        assert p.locator("#details .selection-list .status").count() == 0
        assert p.locator("#details .selection-list li").first.evaluate("(n) => n.children[0].matches('span.badge')")


def test_a_suggestions_page_row_has_a_badge_that_names_the_suggestion(browser, synthetic_case):  # noqa: F811
    """Every event on a Suggestions page is unreviewed with a guess, so each reads U, and the hover names what the rule
    suggests and whose guess it is."""
    for p in served_page(browser, synthetic_case):
        p.evaluate("async () => (await import('/js/suggestions.js')).showSuggestions('hayabusa')")
        p.wait_for_selector("#details .sg-events li .badge")
        rows = p.locator("#details .sg-events li:has(.sg-text)")
        assert rows.count() > 0 and all(r.locator(".badge.u").count() == 1 for r in rows.all())
        want = re.compile(r"Unreviewed, with a pending \w+ suggestion from hayabusa")
        assert all(want.fullmatch(t) for t in titles(p, "#details .sg-events"))


def test_an_audit_entrys_events_have_badges_and_no_mark_word(browser, synthetic_case):  # noqa: F811
    """The events a journal entry touched list with the badge in place of the mark word."""
    def marked(app):
        found = api_search(app, {"q": ["code:4624"]})["events"][:3]
        api_mark(app, {"uids": [e["uid"] for e in found], "value": "malicious", "note": ""})

    for p in served_page(browser, synthetic_case, setup=marked):
        case_menu(p, "auditButton")
        p.locator("#details .audit-row", has_text="3 events").get_by_role("button", name="3 events").click()
        p.wait_for_selector("#details .audit-confirm li .badge")
        assert letters(p, "#details .audit-confirm li") == ["M", "M", "M"]
        assert all(HOVER.match(t) for t in titles(p, "#details .audit-confirm li"))
        assert not any("Malicious" in t for t in p.locator("#details .audit-confirm li").all_inner_texts())
        assert badge_beside_text(p, "#details .audit-confirm ul")


def test_the_pile_lists_badges_that_match_the_ticks(browser, synthetic_case):  # noqa: F811
    """Events under one pixel list with a badge each, with the mark the tick has and the word alone for a hover, since
    ticks carry no analyst. They read U, then M after the pile is marked: they stay stacked in the Malicious lane."""
    for p in served_page(browser, synthetic_case):
        pile = event_point(p, "4672")
        ids = p.evaluate(UNDER, [pile["x"], pile["y"]])
        assert len(ids) > 2
        p.mouse.click(pile["x"], pile["y"])
        p.wait_for_selector("#details[data-page='pile'] li")
        assert letters(p, "#details[data-page='pile']") == ["U"] * len(ids)
        assert set(titles(p, "#details[data-page='pile']")) == {"Unreviewed"}
        assert badge_beside_text(p, "#details[data-page='pile'] ul")
        p.evaluate("(ids) => ids.forEach((uid, i) => window.__app.select(uid, i > 0))", ids)
        p.locator("#details .ev-verdict").get_by_role("button", name=f"Malicious ({len(ids)})", exact=True).click()
        p.wait_for_function("(n) => window.__app.S.data.events.filter((e) => e.mark === 'Malicious').length === n", arg=len(ids))
        again = event_point(p, "4672")
        p.mouse.click(again["x"], again["y"])
        p.wait_for_selector("#details[data-page='pile'] li")
        assert letters(p, "#details[data-page='pile']") == ["M"] * len(ids)
        assert set(titles(p, "#details[data-page='pile']")) == {"Malicious"}


def test_the_verdict_and_identity_badges(browser, synthetic_case):  # noqa: F811
    """The verdict pill is its word alone, since the badge never sits beside its word. The identity line starts
    with a U badge for an unmarked event; after Mark Suspicious it reads S, and says who marked it and when."""
    for p in served_page(browser, synthetic_case):
        open_event(p, "4672", hit=False)
        pill = p.locator("#details .ev-verdict .status")
        assert pill.inner_text() == "Unreviewed" and pill.locator(".badge").count() == 0
        first = p.locator("#details .ev-ident > *").first
        assert first.evaluate("(n) => n.matches('span.badge.u')") and first.get_attribute("title") == "Unreviewed"
        p.locator("#details .ev-verdict").get_by_role("button", name="Suspicious", exact=True).click()
        p.wait_for_selector("#details .ev-verdict .status.suspicious")
        ident = p.locator("#details .ev-ident .badge.s")
        ident.wait_for()
        assert HOVER.match(ident.get_attribute("title"))
        assert pill.inner_text() == "Suspicious" and pill.locator(".badge").count() == 0


def awkward(case):
    """Events with the shapes real cases have and the synthetic one lacks: a host name longer than its column, a message
    that wraps, and an entry 40 years from the others, whose offset is the longest string the formatter writes."""
    old = logon(EPOCH_1980, 901, DC_LOG, ip="10.42.85.10")
    wrapped = replace(logon(T0 + 20 * SEC, 902, "ALPHA/Windows/System32/winevt/Logs/Security.evtx", ip="10.42.85.10"),
                      message=LONG_MESSAGE)
    load(case.db_path, [old], host="DC01", tool="evtxecmd", tool_version="t", run_id="r20", replaces_sources=[],
         staging_dir=case.folder)
    load(case.db_path, [wrapped], host=LONG_HOST, tool="evtxecmd", tool_version="t", run_id="r21", replaces_sources=[],
         staging_dir=case.folder)


def test_the_columns_line_up_on_rows_with_the_shapes_of_real_cases(browser, synthetic_case):  # noqa: F811
    """The grid's widths are for the shapes real lists have: a host name past 52 px, a message that wraps, and an offset
    of 40 years. Each cell of such rows starts where its heading does, nothing overflows the row or the list,
    a cut cell keeps its whole text in its hover, and a wrapped row keeps its tick, badge, and time at its top."""
    awkward(synthetic_case)
    for p in served_page(browser, synthetic_case):
        select(p, event_point(p, "4624", hit=True)["uid"])
        p.locator('#details .pv[data-pivot="account"] button.pv-go').click()
        p.wait_for_selector("#relatedList li.rel-row")
        rows = p.locator("#relatedList li.rel-row")
        cut = "(ns) => ns.map((n) => [n.textContent, n.title, n.scrollWidth > n.clientWidth, getComputedStyle(n).overflowX])"
        assert [LONG_HOST, LONG_HOST, True, "hidden"] in rows.locator(".rel-host").evaluate_all(cut)   # cut, name in hover
        far = [o for o in rows.locator(".off").evaluate_all(cut) if " y " in o[0]]
        # A gap of 40 years reads in units, whole in the wide cell, with the exact seconds in the hover
        assert far and far[0][0].startswith("-40 y ") and far[0][1].endswith(" s") and far[0][2:] == [False, "hidden"], far
        assert "wide-off" in p.locator("#relatedList ul.rows").get_attribute("class").split()
        width = p.locator("#relatedList ul.rows").evaluate("(n) => [n.scrollWidth, n.clientWidth]")
        assert width[0] <= width[1] + 1, width
        head = {c: box(p, f"#relatedList li.rel-head .{c}")["left"] for c in ("rel-time", "off", "rel-host", "rel-event")}
        for r in rows.all():
            cells = r.evaluate("""(n) => [...n.children].map((c) => { const b = c.getBoundingClientRect();
                                  return [c.className.split(' ')[0], b.left, b.right, b.top]; })""")
            lefts = {cls: left for cls, left, _, _ in cells}
            for cls, want in head.items():
                assert abs(lefts[cls] - want) <= 1, (cls, lefts[cls], want)
            row_right = r.evaluate("(n) => n.getBoundingClientRect().right")
            assert all(right <= row_right + 1 for _, _, right, _ in cells)
            tops = [top for cls, _, _, top in cells if cls in ("badge", "rel-time", "off", "rel-host", "rel-event")]
            assert max(tops) - min(tops) <= 2, tops   # every cell starts at the row's top
        # The work column's row is one line, cut with an ellipsis and whole in the hover
        one_line = rows.filter(has_text="a very long message").first
        assert one_line.evaluate("(n) => n.getBoundingClientRect().height") <= 30
        text = one_line.locator(".rel-text")
        assert text.evaluate("(n) => n.scrollWidth > n.clientWidth") and "a very long message" in text.get_attribute("title")
        # A search is as wide as the panel, so the same message wraps there, with its tick, badge, and time at the row's top
        p.locator("#search").fill("a very long message")
        p.locator("#search").press("Enter")
        p.wait_for_selector("#details[data-page='search'] li.rel-row")
        wrapped = p.locator("#details[data-page='search'] li.rel-row").filter(has_text="a very long message").first
        assert wrapped.evaluate("(n) => n.getBoundingClientRect().height") > 30   # it did wrap
        tops = wrapped.evaluate("""(n) => [...n.children]
            .filter((c) => c.matches('input, .badge, .rel-time, .off, .rel-host, .rel-event'))
            .map((c) => c.getBoundingClientRect().top)""")
        assert len(tops) >= 4
        assert max(tops) - min(tops) <= 2, tops


# ---------- the menu's head, the tooltip, and the totals ----------

STATUS = "document.getElementById('status').textContent"
# The tick pairs of one lane that share a pixel, as the hit test and the pile see them: [x, row] of each
PAIR = """() => { const S = window.__app.S;
    for (const [row, items] of S.index.entries()) {
        const ev = (items || []).filter((it) => it.kind === 'event');
        for (let i = 1; i < ev.length; i++) {
            if (ev[i].x === ev[i - 1].x) return { x: ev[i].x, row, uids: ev.map((it) => it.e.uid) };
        }
    }
    return null; }"""


def twins(case, count=2):
    """`count` events of DC01 at one timestamp, 20 s into the case, so their ticks share a pixel on one lane."""
    events = [logon(T0 + 20 * SEC, 910 + i, DC_LOG, ip="10.42.85.10") for i in range(count)]
    load(case.db_path, events, host="DC01", tool="evtxecmd", tool_version="t", run_id="r30", replaces_sources=[],
         staging_dir=case.folder)


def lane_point(p, x, row):
    """The page coordinates of a tick's x on a lane, with the lane scrolled into view (the lane area holds about eight
    rows at the Details panel's two-thirds default)."""
    return p.evaluate(f"([x, row]) => ({POINT})(row, {{ x }}, null)", [x, row])


def right_click_at(p, x, row):
    """Right-click the lanes canvas at a tick's x and lane."""
    point = lane_point(p, x, row)
    p.mouse.click(point["x"], point["y"], button="right")
    p.locator("#quickMenu:not([hidden])").wait_for()


def test_the_menu_names_its_event(browser, synthetic_case):  # noqa: F811
    """Of two ticks on one pixel the hit test returns the later one, the one on top. The right-click menu's head says
    which event it is for with its badge, kind, host, and time, counts the others within 3 px and links to them, and opens
    with focus on the menu and no item selected, so the link is one arrow down. The Mark items are words with no badge.
    A lone tick says nothing of others, and with several events selected the head names the selection and the clicked
    event as one it includes."""
    twins(synthetic_case)
    for p in served_page(browser, synthetic_case):
        rdp, lone = event_point(p, "4624", hit=True), latest_lone_point(p, "4624")   # at Fit case, where DESKTOP's is alone
        # A lone tick: the head names it and counts no others
        p.mouse.click(lone["x"], lone["y"], button="right")
        menu = p.locator("#quickMenu:not([hidden])")
        menu.wait_for()
        head = menu.locator(".menu-head")
        assert head.locator(".for").text_content() == "Menu for this event"
        assert head.locator(".what .badge").count() == 1 and head.locator(".what").inner_text().endswith("UTC")
        assert "DESKTOP" in head.locator(".what").inner_text() and "within" not in head.inner_text()
        assert head.locator("button").count() == 0
        p.keyboard.press("Escape")
        # Several selected: the head says so, and the Mark items act on all of them
        p.mouse.click(lone["x"], lone["y"])
        p.wait_for_selector("#details[data-page='event'] .ev-verdict")
        shift_click(p, rdp)
        p.locator("#details .ev-head-more .selection-list").wait_for()
        p.mouse.click(rdp["x"], rdp["y"], button="right")
        menu.wait_for()
        assert head.locator(".for").text_content() == "Menu for 2 selected events"
        assert head.locator(".what").inner_text().startswith("including") and "DC01" in head.locator(".what").inner_text()
        assert menu.get_by_role("menuitem", name="Mark Malicious (2 events)").count() == 1
        p.keyboard.press("Escape")
        # Two ticks on one pixel: the later in the lane's index is the hit
        at = T0 // 1000 + 20_000   # the twins' time, in ms
        p.evaluate("([a, b]) => window.__app.setView(a, b)", [at - 1500, at + 1500])
        p.wait_for_function("() => window.__app.S.data.mode === 'events' && window.__app.S.data.count >= 2")
        pair = p.evaluate(PAIR)
        assert pair and len(pair["uids"]) >= 2, pair
        hit = p.evaluate("""async ([x, row]) => { const { hitTest } = await import('/js/interaction.js');
                            return hitTest(x, row * 20 + 10).e.uid; }""", [pair["x"], pair["row"]])
        assert hit == pair["uids"][-1] != pair["uids"][0]
        right_click_at(p, pair["x"], pair["row"])
        assert head.locator(".for").text_content() == "Menu for this event"
        what = head.locator(".what").inner_text()
        assert "4624 logon" in what and "DC01" in what and head.locator(".what .badge").count() == 1
        last = head.locator(":scope > div").last.inner_text()
        assert last.endswith("1 other event within 3 px: show all 2 here"), last
        link = head.get_by_role("menuitem", name="show all 2 here")
        assert link.get_attribute("title") == "Events drawn within 3 pixels of the pointer"
        # The menu opens with nothing selected: focus is on the menu itself. The first arrow down reaches the head's
        # link, which comes first in the menu, and the next the first Mark item. The Mark items spell the state out, so they
        # hold no badge.
        assert p.evaluate("document.activeElement.id") == "quickMenu"
        p.keyboard.press("ArrowDown")
        assert p.evaluate("document.activeElement.textContent") == "show all 2 here"
        p.keyboard.press("ArrowDown")
        assert p.evaluate("document.activeElement.textContent") == "Mark Malicious"
        marks = menu.locator("button[role=menuitem][class*='mark-']")
        assert marks.count() == 4
        for item in marks.all():
            assert item.locator(".badge").count() == 0
            assert item.evaluate("(n) => getComputedStyle(n, '::before').content") == "none"
        link.click()
        p.wait_for_selector("#details[data-page='pile']")
        assert p.locator("#detailsBand .title").inner_text() == "2 events under the cursor"
        assert p.locator("#details[data-page='pile'] h2").count() == 0
        assert menu.is_hidden()


def journal_length(case):
    path = case.folder / JOURNAL_FILE
    return len(path.read_text(encoding="utf-8").splitlines()) if path.exists() else 0


def test_the_menu_opens_with_nothing_selected(browser, synthetic_case):  # noqa: F811
    """A right-click menu opens with no item focused, so Enter or Space right after the click marks nothing. The first
    arrow down takes the first enabled item, Mark Malicious, and Enter then marks. The first arrow up takes the last
    item, and Escape closes the menu."""
    for p in served_page(browser, synthetic_case):
        rdp = event_point(p, "4624", hit=True)
        mark_of = """(uid) => window.__app.S.data.events.find((e) => e.uid === uid).mark"""
        start = p.evaluate(mark_of, rdp["uid"])   # Unreviewed, with the Hayabusa hit's suggestion pending
        assert start.startswith(("Unreviewed", "Suggested"))
        before = journal_length(synthetic_case)
        p.mouse.click(rdp["x"], rdp["y"], button="right")
        menu = p.locator("#quickMenu:not([hidden])")
        menu.wait_for()
        assert p.evaluate("document.activeElement.id") == "quickMenu" and menu.get_attribute("role") == "menu"
        assert menu.locator(":focus").count() == 0   # no item inside it has the focus
        assert menu.locator(".menu-head .what .badge").inner_text() == "U"
        # Enter and Space do nothing: the menu stays, the event stays Unreviewed, and the journal gains no entry
        p.keyboard.press("Enter")
        p.keyboard.press("Space")
        p.wait_for_timeout(400)   # time for a mark's request to be sent, were one coming
        assert menu.is_visible() and p.evaluate("document.activeElement.id") == "quickMenu"
        assert p.evaluate(mark_of, rdp["uid"]) == start and journal_length(synthetic_case) == before
        # The first arrow down is the first enabled item, and Enter on it marks
        p.keyboard.press("ArrowDown")
        assert p.evaluate("document.activeElement.textContent") == "Mark Malicious"
        p.keyboard.press("Enter")
        p.wait_for_function("(uid) => window.__app.S.data.events.some((e) => e.uid === uid && e.mark === 'Malicious')",
                            arg=rdp["uid"])
        assert menu.is_hidden() and journal_length(synthetic_case) == before + 1
        # The first arrow up is the last item; Escape closes the menu. The mark moved the event to the Malicious group,
        # which opens folded, so its point is taken again with every group open.
        open_all(p)
        rdp = point_of(p, rdp["uid"])
        p.mouse.click(rdp["x"], rdp["y"], button="right")
        menu.wait_for()
        assert p.evaluate("document.activeElement.id") == "quickMenu"
        p.keyboard.press("ArrowUp")
        assert p.evaluate("document.activeElement.textContent") == "Customize this menu…"
        p.keyboard.press("Escape")
        assert menu.is_hidden()


def test_the_menu_head_and_tooltip_fit_events_with_the_shapes_of_real_cases(browser, synthetic_case):  # noqa: F811
    """Real events have hosts longer than any column, messages that wrap, and times 40 years from the rest. The menu's head
    keeps all its text inside the menu and the menu inside the window, and the tooltip stays inside the window."""
    awkward(synthetic_case)
    for p in served_page(browser, synthetic_case):
        for at, text in ((T0 // 1000 + 20_000, "a very long message"), (EPOCH_1980 // 1000, "4624 logon")):
            p.evaluate("([a, b]) => window.__app.setView(a, b)", [at - 1500, at + 1500])
            p.wait_for_function("(t) => window.__app.S.data.events && window.__app.S.data.events.some((e) => e.msg.includes(t))",
                                arg=text)
            where = p.evaluate("""(t) => { const S = window.__app.S;
                for (const [row, items] of S.index.entries()) {
                    for (const it of items || []) if (it.kind === 'event' && it.e.msg.includes(t)) return { x: it.x, row };
                }
                return null; }""", text)
            right_click_at(p, where["x"], where["row"])
            fit = p.evaluate("""() => { const m = document.getElementById('quickMenu'), h = m.querySelector('.menu-head');
                const r = m.getBoundingClientRect();
                return { inside: h.scrollWidth <= h.clientWidth + 1, right: r.right <= innerWidth,
                         bottom: r.bottom <= innerHeight, text: h.querySelector('.what').textContent }; }""")
            assert fit["inside"] and fit["right"] and fit["bottom"], fit
            assert "UTC" in fit["text"] and len(fit["text"]) < 140, fit   # the kind is cut at 60, not the whole message
            p.keyboard.press("Escape")
            lanes = lane_point(p, where["x"], where["row"])
            tip = tooltip_for(p, lanes["x"], lanes["y"])
            box_ = tip.evaluate("(n) => { const r = n.getBoundingClientRect(); return [r.left, r.right, r.bottom]; }")
            assert box_[0] >= 0 and box_[1] <= p.evaluate("innerWidth") and box_[2] <= p.evaluate("innerHeight"), box_
            p.mouse.move(0, 0)


def tooltip_for(p, x, y):
    p.mouse.move(x, y)
    p.mouse.move(x + 1, y)
    p.wait_for_selector("#tooltip:not([hidden]) .l1")
    return p.locator("#tooltip")


def test_the_tooltip_leads_with_the_state_word(browser, synthetic_case):  # noqa: F811
    """The tooltip is built from nodes: its first line is the review state, the kind, and the host, with no badge since the
    state is a word; the time, the message, and a Hayabusa hit are under it. A bar keeps its text. A tick on a
    grouping with no host key names its lane."""
    for p in served_page(browser, synthetic_case):
        rdp = event_point(p, "4624", hit=True)
        tip = tooltip_for(p, rdp["x"], rdp["y"])
        assert tip.locator(".badge").count() == 0
        assert tip.locator(".l1").text_content().endswith("Unreviewed · 4624 logon · DC01")
        assert tip.inner_text().splitlines()[-1].startswith("2020-09-19 03:") and tip.inner_text().endswith("· Hayabusa hit")
        p.mouse.click(rdp["x"], rdp["y"])
        p.wait_for_selector("#details[data-page='event'] .ev-verdict")
        p.locator("#details .ev-verdict").get_by_role("button", name="Malicious", exact=True).click()
        p.wait_for_function("(uid) => window.__app.S.data.events.some((e) => e.uid === uid && e.mark === 'Malicious')",
                            arg=rdp["uid"])
        p.mouse.move(0, 0)
        open_all(p)   # the mark moved the event to the Malicious group, which opens folded
        rdp = point_of(p, rdp["uid"])
        tip = tooltip_for(p, rdp["x"], rdp["y"])
        assert tip.locator(".badge").count() == 0
        assert tip.locator(".l1").text_content().endswith("Malicious · 4624 logon · DC01")
        # The words of a kind are cut at 60 characters, and a lane without a host key is named by its label
        said = p.evaluate("""async () => { const { describe, tickKind } = await import('/js/interaction.js');
            const S = window.__app.S, groupby = S.groupby;
            const e = { mark: 'Unreviewed', msg: 'x'.repeat(80), ts: 1, code: '', hit: 0, keys: ['Unreviewed', 'Servers'] };
            S.groupby = ['mark', 'role'];
            const nodes = describe({ kind: 'event', e }, 0);
            S.groupby = groupby;
            return [tickKind(e).length, nodes[0].textContent.endsWith(S.rows[0].label)]; }""")
        assert said == [61, True]


def test_the_badge_never_sits_beside_its_state_word(browser, synthetic_case):  # noqa: F811
    """The badge stands for the state word, so where the word is spelled out there is no badge. With the event in each
    of the four states, the menu's four Mark items, the verdict pill, and the tooltip's first line hold none, and the
    badge appears where it stands alone, the identity line and the menu head's event line, with the state's letter."""
    for p in served_page(browser, synthetic_case):
        rdp = event_point(p, "4624", hit=True)
        p.mouse.click(rdp["x"], rdp["y"])
        p.wait_for_selector("#details[data-page='event'] .ev-verdict")
        states = (("Unreviewed", "U"), ("Suspicious", "S"), ("Malicious", "M"), ("Authorized", "A"), ("Unreviewed", "U"))
        lane_mark = "(uid) => window.__app.S.data.events.find((e) => e.uid === uid)?.mark"
        for word, letter in states:
            pill = p.locator("#details .ev-verdict .status")
            if word not in pill.inner_text():
                was = p.evaluate(lane_mark, rdp["uid"])
                p.locator("#details .ev-verdict").get_by_role("button", name=word, exact=True).click()
                p.wait_for_function("(w) => document.querySelector('#details .ev-verdict .status')?.textContent === w", arg=word)
                p.wait_for_function(f"(uid) => ({lane_mark})(uid) !== {json.dumps(was)}", arg=rdp["uid"])   # the lanes redrew
                open_all(p)   # the mark moved the event to another group, and a new group opens folded
                rdp = point_of(p, rdp["uid"])
            assert pill.locator(".badge").count() == 0, word
            ident = p.locator("#details .ev-ident .badge")
            assert ident.count() == 1 and ident.inner_text() == letter, word
            p.mouse.click(rdp["x"], rdp["y"], button="right")
            menu = p.locator("#quickMenu:not([hidden])")
            menu.wait_for()
            assert menu.locator(".menu-head .what .badge").inner_text() == letter, word   # alone, so it names the state
            marks = menu.locator("button[role=menuitem][class*='mark-']")
            assert marks.all_inner_texts() == [f"Mark {m}" for m in ("Malicious", "Suspicious", "Authorized", "Unreviewed")], word
            assert menu.locator("button[role=menuitem] .badge").count() == 0, word
            p.keyboard.press("Escape")
            p.mouse.move(0, 0)
            tip = tooltip_for(p, rdp["x"], rdp["y"])
            assert tip.locator(".badge").count() == 0 and tip.locator(".l1").text_content().startswith(f"{word} · "), word
            p.mouse.move(0, 0)


def test_one_total_and_the_window_count(browser, synthetic_case):  # noqa: F811
    """The state line keeps one total, "Showing X of Y events on the timeline", and adds "In this window: N", the
    window's count, which reads "…" from a window change until the data answers. The status line reports the last action and
    the server's time, keeps it through the redraw, and says "Window moved" after a pan. It doesn't count events."""
    for p in served_page(browser, synthetic_case):
        total = p.evaluate("window.__app.S.meta.rows")
        assert p.locator("#stShown").inner_text() == f"Showing {total:,} of {total:,} events on the timeline"
        # A mark is the last action, with the server's time, and the redraw after it keeps the line
        rdp = event_point(p, "4624", hit=True)
        p.mouse.click(rdp["x"], rdp["y"], button="right")
        p.locator("#quickMenu").get_by_role("menuitem", name="Mark Malicious").click()
        p.wait_for_function(f"() => {STATUS}.startsWith('Marked one event Malicious · ')")
        p.wait_for_timeout(400)   # time for any redraw still to come
        line = p.evaluate(f"() => {STATUS}")
        assert re.fullmatch(r"Marked one event Malicious · \d+ ms", line), line
        # A pan is a new action
        p.evaluate("() => { const v = window.__app.S.view; return window.__app.setView(v.start + 1000, v.end + 1000); }")
        p.wait_for_function(f"() => {STATUS}.startsWith('Window moved · ')")
        line = p.evaluate(f"() => {STATUS}")
        assert re.fullmatch(r"Window moved · \d+ ms", line), line   # no "Events: ..." and no draw time
        # The count waits for its window: "…" while the data is held, then the number the lanes drew from
        start = T0 // 1000
        held = []
        # Holds the first request; the lambda takes exactly one argument, since Playwright passes the request too to a handler
        # with two. The for loop runs once, so the closure is bound (ruff B023).
        p.route("**/api/view?*", lambda route: held.append(route) if not held else route.continue_())  # noqa: B023
        p.evaluate("([a, b]) => { window.__moved = window.__app.setView(a, b); }", [start, start + 60_000])
        p.wait_for_function("() => document.getElementById('stInWindow').textContent === 'In this window: …'")
        assert p.locator("#stInWindow").get_attribute("title") == "Counting the events in the new window."
        for _ in range(500):
            if held:
                break
            p.wait_for_timeout(20)
        assert held, "the view request never reached the route"
        held[0].continue_()
        p.wait_for_function("() => !document.getElementById('stInWindow').textContent.includes('…')")
        count = p.evaluate("window.__app.S.data.count")
        assert p.locator("#stInWindow").inner_text() == f"In this window: {count:,}"
        assert "logon link" in p.locator("#stInWindow").get_attribute("title")


def test_a_redraw_of_the_same_window_keeps_the_last_action(browser, synthetic_case):  # noqa: F811
    """Only a new window replaces the line's action. A Sources change redraws the same window, and the mark's line stays
    ahead of the notes the view adds."""
    for p in served_page(browser, synthetic_case):
        rdp = event_point(p, "4624", hit=True)
        p.mouse.click(rdp["x"], rdp["y"], button="right")
        p.locator("#quickMenu").get_by_role("menuitem", name="Mark Suspicious").click()
        p.wait_for_function(f"() => {STATUS}.startsWith('Marked one event Suspicious · ')")
        p.locator("#filtersButton").click()
        p.evaluate(RECORD_REQUESTS)
        p.locator("#fpTree").get_by_role("checkbox", name="Show DESKTOP", exact=True).uncheck()
        # The window drawn under the filter. A redraw asked for as the panel opened can answer first, under the lanes from
        # before the change, so the line it gives isn't the one to check.
        p.wait_for_function("() => window.__taken.some((path) => path.startsWith('/api/view?') && path.includes('&filter='))")
        # With DESKTOP hidden, DC01's logons from it have no lane to start from, and the view's note says so
        assert re.fullmatch(r"Marked one event Suspicious · \d+ ms \| Logon links from DESKTOP aren't drawn: [^|]+ \| "
                            r"Sources filtered", p.evaluate(f"() => {STATUS}"))
