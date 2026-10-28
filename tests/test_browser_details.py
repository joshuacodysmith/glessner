"""The Details panel and the Event page's header in a real browser: the band and its one scroller, the default height, the
trail in the band, the header's two rows, the provenance strip, the folds, and the reasons' layout. They drive the
installed Microsoft Edge through Playwright, as test_browser_smoke does, and are skipped without it."""

import re

import pytest
from conftest import SEC, T0, WS_LOG, logon
from test_browser_design import computed, near, open_event, token
from test_browser_frame import no_tool_scan, paint
from test_browser_pivots import COUNTED, INSTALL, pv, select, uid, walk
from test_browser_smoke import (  # noqa: F401
    RECORD_REQUESTS,
    browser,
    case_menu,
    clock_page,
    event_point,
    page,
    served_page,
    to_timeline,
)
from test_clock import accepted, flow
from test_found_output_sources import FOUND, KAPE, OTHER_HOST, SYSTEM_LOG, evtxecmd_run, found_case
from test_found_output_sources import load as load_found
from test_pivots import RDP, load_events, pcase, pcase_events  # noqa: F401
from test_timezones import add_zone

from glessner.events import Event, load
from glessner.imports import run_import
from glessner.intake import intake, manifest_hashes
from glessner.parsers.autoruns import BUILT
from glessner.server import api_mark, api_rule

pytestmark = pytest.mark.browser
READY = "() => window.__ready === true && window.__app.S.data !== null"
PANEL = "(h) => { document.getElementById('details').style.flexBasis = `${h}px`; }"   # a panel of this height
NODE_BOX = """(n) => { const b = n.getBoundingClientRect();
    return { top: b.top, bottom: b.bottom, left: b.left, right: b.right, height: b.height, width: b.width }; }"""
BOX = f"(sel) => ({NODE_BOX})(document.querySelector(sel))"
DETAILS_KEY = "glessner.detailsShare"
OLD_KEYS = ("glessner.detailsHeight", "glessner.detailsHeight2")   # legacy pixel heights: removed, never read
PLAIN_DC01 = """() => {
    for (const [row, items] of window.__app.S.index.entries()) {
        if (window.__app.S.rows[row].label !== 'DC01') continue;
        for (const it of items || []) if (it.kind === 'event' && it.e.code === '4624') return it.e.uid;
    }
    return null;
}"""   # a drawn 4624 on DC01, which has no pair in the capture


def box(p, selector):
    return p.evaluate(BOX, selector)


def inside(inner, outer, slack=1):
    return inner["top"] >= outer["top"] - slack and inner["bottom"] <= outer["bottom"] + slack


def stored(p, key):
    return p.evaluate("(k) => localStorage.getItem(k)", key)


def reload(p):
    p.reload()
    p.wait_for_function(READY)
    to_timeline(p)


@pytest.fixture
def layout_page(browser, synthetic_case):  # noqa: F811
    """The app with the browser's layout preferences untouched: served_page seeds a half-stage share for the other tests."""
    yield from served_page(browser, synthetic_case, share=None)


def stage_height(p):
    return p.evaluate("() => document.getElementById('stage').clientHeight")


def two_thirds_of_the_stage(p):
    return round(stage_height(p) * 2 / 3)


def test_the_panel_opens_at_two_thirds_of_the_stage(layout_page):
    """The panel opens at two-thirds of the panel area, and the Timeline keeps the rest. The divider's hover says so."""
    p = layout_page
    height = box(p, "#details")["height"]
    assert abs(height - two_thirds_of_the_stage(p)) <= 2, (height, two_thirds_of_the_stage(p))
    assert height > 500
    assert "Double-click to reset to two-thirds of the panel area." in p.locator("#divider").get_attribute("title")


SPLIT = """() => {
    const g = (id) => document.getElementById(id);
    const stage = g('stage').clientHeight, details = g('details').offsetHeight, divider = g('divider').offsetHeight;
    const fixed = g('tlToolbar').offsetHeight + g('stateLine').offsetHeight + g('axisRow').offsetHeight;
    const lanes = g('scroller').clientHeight, rows = window.__app.S.tree.children.length;
    const around = stage - details - divider - fixed - lanes;
    const left = stage - divider - around - fixed - rows * 20;
    return { stage, details, lanes, rows, around, two: Math.round(stage * 2 / 3), half: Math.round(stage / 2),
             rule: Math.round(Math.max(stage / 2, Math.min(Math.round(stage * 2 / 3), left))) }; }"""


def test_the_default_split_keeps_every_first_level_row_in_view(browser, synthetic_case):  # noqa: F811
    """Details takes two-thirds of the stage unless that leaves the Timeline too short for every first-level row of the
    preset folded; then it takes what is left, never under half the stage. With seven groups the synthetic case stays at
    two-thirds at 1440 by 900, gives way at 1280 by 720 and 1280 by 600 with all seven rows in view, and holds the half
    floor at 1280 by 560. The rows are counted from the tree's root, so opening a group moves nothing; a saved share still
    wins, and a double-click returns to the rule."""
    def marks(app):
        for ts, value in ((T0 + 62 * SEC, "malicious"), (T0 + 60 * SEC, "suspicious"), (T0 + 874 * SEC, "authorized")):
            uid_ = app.con.execute("SELECT event_uid FROM events WHERE tool = 'evtxecmd' AND ts_us = ?", [ts]).fetchone()[0]
            api_mark(app, {"uids": [uid_], "value": value, "note": ""})

    for p in served_page(browser, synthetic_case, setup=marks, share=None, folds=True):
        assert p.evaluate("() => window.__app.S.tree.children.length") == 7
        for size, where in (((1440, 900), "two"), ((1280, 720), "left"), ((1280, 600), "left"), ((1280, 560), "half")):
            p.set_viewport_size({"width": size[0], "height": size[1]})
            p.wait_for_timeout(300)
            m = p.evaluate(SPLIT)
            assert abs(m["details"] - m["rule"]) <= 2 and m["around"] == 24, (size, m)
            if where == "two":
                assert m["details"] == m["two"] == 570 and m["lanes"] >= 7 * 20, m
            elif where == "left":
                assert m["half"] < m["details"] < m["two"] and m["lanes"] == 7 * 20, m
            else:   # the floor costs rows: the panel keeps half the stage
                assert abs(m["details"] - m["half"]) <= 1 and m["lanes"] < 7 * 20, m
        p.set_viewport_size({"width": 1280, "height": 720})
        p.wait_for_timeout(300)
        before = box(p, "#details")["height"]
        p.locator("#labels .row.group", has_text="Unreviewed").click()   # opened groups don't move the default
        p.wait_for_timeout(200)
        assert box(p, "#details")["height"] == before
        assert p.evaluate("() => document.querySelectorAll('#labels .row').length") > 7
        p.evaluate("(k) => localStorage.setItem(k, '0.6500')", DETAILS_KEY)   # a saved share wins
        reload(p)
        assert abs(box(p, "#details")["height"] - 0.65 * stage_height(p)) <= 2
        p.locator("#divider").dblclick()
        assert abs(box(p, "#details")["height"] - p.evaluate(SPLIT)["rule"]) <= 2 and stored(p, DETAILS_KEY) is None


def test_the_timeline_keeps_its_minimum(layout_page):
    """A guard for the clamp against the two-thirds default: in a short window the Timeline keeps 160 px."""
    p = layout_page
    p.set_viewport_size({"width": 1280, "height": 400})
    p.wait_for_timeout(300)
    assert box(p, "#timeline")["height"] >= 160
    assert box(p, "#details")["height"] >= 80


def test_the_stored_heights_from_before_are_removed_once_and_never_read(layout_page):
    """The legacy height keys hold a pixel height that is as often a default (240 px, or half the stage) as one the
    analyst chose, so each is dropped, not read. A share that isn't one is ignored."""
    p = layout_page
    for key, value in zip(OLD_KEYS, ("240", "428"), strict=True):
        p.evaluate("([k, v]) => localStorage.setItem(k, v)", [key, value])
    p.evaluate("(k) => localStorage.setItem(k, '428')", DETAILS_KEY)
    reload(p)
    assert abs(box(p, "#details")["height"] - two_thirds_of_the_stage(p)) <= 2
    assert all(stored(p, key) is None for key in OLD_KEYS)


def test_a_dragged_height_is_kept_as_a_share_of_the_stage_and_a_double_click_resets(layout_page):
    """A drag is kept under glessner.detailsShare as the panel's share of the stage, so a reload keeps the height and
    a window of another size keeps the split; a double-click goes back to two-thirds and drops the key."""
    p = layout_page
    before = box(p, "#details")["height"]
    grip = box(p, "#divider")
    x, y = (grip["left"] + grip["right"]) / 2, (grip["top"] + grip["bottom"]) / 2
    p.mouse.move(x, y)
    p.mouse.down()
    p.mouse.move(x, y + 120, steps=5)
    p.mouse.up()
    dragged = box(p, "#details")["height"]
    assert dragged < before - 100
    share = float(stored(p, DETAILS_KEY))
    assert abs(share - dragged / stage_height(p)) < 0.001
    reload(p)
    assert abs(box(p, "#details")["height"] - dragged) <= 1
    p.set_viewport_size({"width": 1280, "height": 720})
    p.wait_for_timeout(300)
    assert abs(box(p, "#details")["height"] - share * stage_height(p)) <= 2 and stage_height(p) < 700
    assert stored(p, DETAILS_KEY) == f"{share:.4f}"   # a resize sets nothing
    p.set_viewport_size({"width": 1400, "height": 900})
    p.wait_for_timeout(300)
    assert abs(box(p, "#details")["height"] - dragged) <= 1
    p.locator("#divider").dblclick()
    assert abs(box(p, "#details")["height"] - two_thirds_of_the_stage(p)) <= 2
    assert stored(p, DETAILS_KEY) is None
    reload(p)
    assert abs(box(p, "#details")["height"] - two_thirds_of_the_stage(p)) <= 2
    # The arrow keys set a share too
    p.locator("#divider").focus()
    p.keyboard.press("ArrowDown")
    stepped = box(p, "#details")["height"]
    assert abs(stepped - (two_thirds_of_the_stage(p) - 20)) <= 2
    assert abs(float(stored(p, DETAILS_KEY)) - stepped / stage_height(p)) < 0.001


def show_page(p, name, event):
    """Open the event's page, a search's, or the Tools page, whichever `name` says."""
    if name == "event":
        select(p, event)
    elif name == "search":
        p.locator("#search").fill("DC01")
        p.locator("#search").press("Enter")
    else:
        case_menu(p, "toolsButton")


def test_the_details_band_stays_put(browser, pcase):  # noqa: F811
    """Every page opens under the Details band: its name, what the page shows, the 3 px edge. The band is outside the
    scroller, so scrolling the body to its end moves nothing in it, at the default width and at 900 px."""
    install = uid(pcase, INSTALL)
    for p in served_page(browser, pcase, setup=no_tool_scan):
        edge = token(p, "--band-details-edge")
        assert computed(p, "#details", "borderTopWidth") == "3px"
        assert near(computed(p, "#details", "borderTopColor"), edge)
        assert near(computed(p, "#detailsBand", "backgroundColor"), token(p, "--band-details"))
        assert p.locator("#detailsBand .name").inner_text() == "DETAILS"
        for width in (1400, 900):
            p.set_viewport_size({"width": width, "height": 900})
            p.evaluate(PANEL, 200)
            for name, title in (("event", "the DC01 event at 03:21:53"), ("search", "Search: DC01"), ("tools", "Tools")):
                show_page(p, name, install)
                p.wait_for_selector(f"#details[data-page='{name}']")
                if name == "search":
                    p.wait_for_selector("#details li.rel-row")
                if name == "tools":
                    p.wait_for_selector("#details .tools-table")
                assert p.locator("#detailsBand .title").inner_text() == title, (name, width)
                top = box(p, "#detailsBand")["top"]
                p.locator("#detailsBody").evaluate("(n) => { n.scrollTop = n.scrollHeight; }")
                if name != "tools":
                    assert p.locator("#detailsBody").evaluate("(n) => n.scrollTop") > 0, (name, width)
                assert box(p, "#detailsBand")["top"] == top, (name, width)
                assert p.locator("#detailsBand .name").is_visible()


def test_the_trail_stays_in_view_after_a_pivot(browser, pcase):  # noqa: F811
    """A pivot never scrolls the trail away, nor the list out of the work column, at the default height and at a 200 px
    panel."""
    rdp = uid(pcase, RDP)
    for panel in (None, 200):
        for p in served_page(browser, pcase):
            if panel:
                p.evaluate(PANEL, panel)
            select(p, rdp)
            pv(p, "session").locator("button.pv-go").click()
            p.locator("#relatedList strong", has_text="with the same host and logon ID").wait_for()
            trail = box(p, "#details nav.trail")
            assert trail["top"] - box(p, "#details")["top"] <= 40, (panel, trail)
            assert trail["bottom"] <= box(p, "#detailsBody")["top"] + 1, panel   # in the band, over the scroller
            assert inside(box(p, "#relatedList strong"), box(p, ".ev-work")), panel


def test_the_trail_shows_on_a_search_taken_as_a_pivot(browser, pcase):  # noqa: F811
    """A search run from a pivot keeps the trail, and the band shows it on the search page with that step current."""
    reasoned = logon(T0 + 200 * SEC, 9600, WS_LOG, code="4625", user="admin", domain="", ltype="3",
                     computer="DESKTOP-SDN1RPT.C137.local", extra={"SubStatus": "0xC000006A"})
    load_events(pcase, [reasoned], "DESKTOP", run="p33")
    with_reason = uid(pcase, "event_code = '4625' AND record_id = 9600")   # its "Same failure reason" row is a search
    for p in served_page(browser, pcase):
        select(p, with_reason)
        pv(p, "search").locator("button.pv-go").click()
        p.wait_for_selector("#details[data-page='search']")
        trail = p.locator("#detailsBand nav.trail")
        trail.wait_for()
        assert trail.locator("[aria-current='step']").inner_text().startswith("Search ")
        assert trail.locator("button.linklike").count() == 1   # the event it was taken from
        trail.locator("button.linklike").click()   # back to the event
        p.wait_for_selector("#details[data-page='event']")
        p.wait_for_function("() => window.__app.S.trailAt === 0")   # the trail keeps the search step, dimmed
        assert p.evaluate("window.__app.S.trail.length") == 2
        assert p.locator("#detailsBand nav.trail button.dim").inner_text().startswith("Search ")


def test_a_dimmed_step_is_still_a_link(browser, pcase):  # noqa: F811
    """A step the analyst went back from keeps the link color and goes lighter and dashed, so the affordance rule holds;
    the step on screen is bold. The dashes are a background of 6 px dashes and 4 px gaps in the link color, so their
    spacing is fixed, where a dotted text-decoration is hard to make out; a hover underlines the text."""
    rdp = uid(pcase, RDP)
    for p in served_page(browser, pcase):
        walk(p, rdp)
        p.locator("#details nav.trail").get_by_role("button", name="Same logon session (2)").click()
        p.wait_for_function("() => window.__app.S.trailAt === 1")
        # the band is drawn last
        p.locator("#relatedList strong", has_text="2 events with the same host and logon ID").wait_for()
        step, link = "#details nav.trail button.dim", "#details nav.trail button.linklike:not(.dim)"
        assert near(computed(p, step, "color"), token(p, "--accent"))
        assert near(computed(p, link, "color"), token(p, "--accent"))
        assert computed(p, step, "textDecorationLine") == "none" and computed(p, link, "backgroundImage") == "none"
        assert computed(p, step, "backgroundSize") == "10px 1px" and computed(p, step, "backgroundRepeat") == "repeat-x"
        stops = p.locator(step).first.evaluate("(n) => getComputedStyle(n).backgroundImage")
        dashes = re.fullmatch(r"linear-gradient\(to right, (rgb\(\d+, \d+, \d+\)) 0px, \1 6px, "
                              r"rgba\(0, 0, 0, 0\) 6px, rgba\(0, 0, 0, 0\) 10px\)", stops)
        assert dashes, stops   # 6 px of the color, then 4 px of nothing, every 10 px
        assert near(paint(dashes.group(1)), token(p, "--accent"))   # the link's color
        p.locator(step).first.hover()
        assert computed(p, step, "textDecorationLine") == "underline" and computed(p, step, "backgroundImage") == "none"
        p.mouse.move(0, 0)
        assert computed(p, step, "fontWeight") == "400"
        assert int(computed(p, "#details nav.trail .here", "fontWeight")) >= 600


def test_the_work_column_is_the_one_scroll_box(browser, pcase):  # noqa: F811
    """A list in the work column has no height limit of its own, so the column scrolls and the list's heading sticks to
    the top of it."""
    rdp = uid(pcase, RDP)
    for p in served_page(browser, pcase):
        select(p, rdp)
        pv(p, "window").locator("button.pv-go").click()
        p.locator("#relatedList .sticky-head").wait_for()
        assert computed(p, "#relatedList", "maxHeight") == "none"
        assert computed(p, "#details .ev-work", "overflowY") == "auto"
        p.locator("#details .ev-work").evaluate("(n) => { n.scrollTop = n.scrollHeight; }")
        assert p.locator("#details .ev-work").evaluate("(n) => n.scrollTop") > 0
        assert inside(box(p, "#relatedList .sticky-head"), box(p, ".ev-work"))
        assert p.locator("#relatedList").evaluate("(n) => n.scrollTop") == 0


def test_a_typed_search_starts_a_new_trail(browser, pcase):  # noqa: F811
    """A search typed in the box begins a new trail, so the band does not carry the steps of an earlier one onto it. An
    event opened from its list is then the one step."""
    rdp = uid(pcase, RDP)
    for p in served_page(browser, pcase):
        select(p, rdp)
        pv(p, "session").locator("button.pv-go").click()
        p.wait_for_selector("#detailsBand nav.trail")
        p.locator("#search").fill("code:4672")
        p.locator("#search").press("Enter")
        p.wait_for_selector("#details[data-page='search'] li.rel-row")
        assert p.evaluate("window.__app.S.trail.length") == 0
        assert p.locator("#detailsBand nav.trail").count() == 0
        p.locator("#details li.rel-row").first.click()
        p.wait_for_selector("#details[data-page='event'] .ev-ident")
        assert p.evaluate("window.__app.S.trail.length") == 1
        assert p.locator("#detailsBand nav.trail").count() == 0


def test_the_header_is_two_rows(browser, synthetic_case):  # noqa: F811
    """With a pending suggestion the decision sits level with the identity, and the header is two rows, at most 72 px. Two
    suggested tags wait behind a toggle, and opened they show in the third row."""
    from test_tags import ATTACK_HIT

    load(synthetic_case.db_path, [ATTACK_HIT], host="DC01", tool="hayabusa", tool_version="t", run_id="r6",
         replaces_sources=[ATTACK_HIT.source_file], staging_dir=synthetic_case.folder)
    for p in served_page(browser, synthetic_case):
        open_event(p)
        decision = p.locator("#details .ev-head .decision")
        decision.wait_for()
        assert abs(box(p, ".ev-head .decision")["top"] - box(p, ".ev-ident")["top"]) <= 4
        assert box(p, ".ev-head")["height"] <= 72
        toggle = p.locator("#details .ev-head button.tw")
        suggested = p.locator("#details .ev-head-more .tagchip.suggested")
        assert toggle.inner_text().strip().startswith(f"{suggested.count()} suggested tags")
        assert toggle.get_attribute("aria-expanded") == "false" and suggested.count() >= 2
        assert suggested.first.is_hidden()
        toggle.click()
        assert toggle.get_attribute("aria-expanded") == "true"
        assert suggested.first.is_visible()
        p.set_viewport_size({"width": 1100, "height": 900})   # between 960 and 1,150 px the right cells drop under the left
        assert box(p, ".ev-head .decision")["top"] > box(p, ".ev-ident")["bottom"] - 1


def test_a_highlight_opens_its_fold(page):  # noqa: F811
    """A search's match inside the closed Record and source fold opens it for that page, with the match in view and the
    stored state unchanged; a plain open of another event shows it closed again."""
    page.locator("#search").fill("C137.local")
    page.locator("#search").press("Enter")
    page.wait_for_selector("#details[data-page='search'] li.rel-row")
    page.locator("#details .related li.rel-row span").first.click()
    page.wait_for_selector("#details[data-page='event'] .ev-facts")
    record = page.locator("#details .ev-facts details.fold", has=page.locator("summary", has_text="Record and source"))
    assert record.evaluate("(d) => d.open")
    assert record.locator("mark").first.is_visible()
    page.wait_for_timeout(200)   # time for the toggle event of the page's own opening
    assert stored(page, "glessner.recordSourceOpen") is None
    page.locator("#searchHelp").click()   # another page clears the highlight
    page.wait_for_selector("#details[data-page='searchHelp']")
    open_event(page, "4672", hit=False)
    record = page.locator("#details .ev-facts details.fold", has=page.locator("summary", has_text="Record and source"))
    assert not record.evaluate("(d) => d.open")


def test_the_provenance_strip_is_one_line(browser, synthetic_case):  # noqa: F811
    """A long evidence path ellipsizes in the strip with the whole path in its hover; the strip is one line on --panel-2 and
    the hash check is never cut."""
    long_path = "DC01/" + "/".join(["a_folder_with_a_long_name"] * 12) + "/Security.evtx"
    odd = Event(T0 + 5 * SEC, "Event Recorded", "evtx", long_path, "R" * 90, "a record from a long path", record_id=77)
    load(synthetic_case.db_path, [odd], host="DC01", tool="evtxecmd", tool_version="t", run_id="r9",
         replaces_sources=[long_path], staging_dir=synthetic_case.folder)
    target = uid(synthetic_case, f"source_file = '{long_path}'")
    for p in served_page(browser, synthetic_case):
        select(p, target)
        assert box(p, ".prov")["height"] <= 24
        assert near(computed(p, ".prov", "backgroundColor"), token(p, "--panel-2"))
        assert computed(p, ".prov", "flexWrap") == "nowrap"
        part = p.locator(".prov .prov-part.file")
        assert part.evaluate("(n) => n.scrollWidth > n.clientWidth")   # cut with an ellipsis
        assert long_path in part.get_attribute("title")
        check = p.locator(".prov .prov-check")
        assert check.evaluate("(n) => n.scrollWidth <= n.clientWidth") and check.is_visible()
        assert box(p, ".prov .prov-part.sha")["right"] <= box(p, ".prov")["right"] + 1
        p.set_viewport_size({"width": 1000, "height": 900})
        assert box(p, ".prov")["height"] <= 24


def test_record_and_source_folds_and_remembers(browser, pcase):  # noqa: F811
    """Record and source is closed on a fresh profile and its count is its rows; once opened it stays open on the next
    event and after a reload. History says how many entries it holds, in a fold of its own."""
    first, second = uid(pcase, RDP), uid(pcase, INSTALL)
    for p in served_page(browser, pcase):
        select(p, first)
        record = p.locator("#details .ev-facts details.fold", has=p.locator("summary", has_text="Record and source"))
        assert not record.evaluate("(d) => d.open")
        count = int(record.locator("summary").text_content().split("(")[1].rstrip(")"))
        assert count == record.locator("dd").count() > 5
        assert p.locator("#details .ev-facts details.fold").evaluate_all("(n) => n.map((d) => d.open)") == [False] * 3
        record.locator("summary").click()
        p.wait_for_function("() => localStorage.getItem('glessner.recordSourceOpen') === '1'")
        select(p, second)
        assert record.evaluate("(d) => d.open")
        reload(p)
        select(p, first)
        assert record.evaluate("(d) => d.open")
        history = p.locator("#details .history-fold summary")
        p.wait_for_function("() => /^History \\(\\d+\\+?\\)$/.test("
                            "document.querySelector('#details .history-fold summary').textContent)")
        assert history.text_content() == "History (0)"


def test_the_reasons_layout(browser, pcase):  # noqa: F811
    """A pivot's reason reads 12 px in --muted; the window row's breakdown is a child of the row and spans it; the work
    column is wider than the facts."""
    install = uid(pcase, INSTALL)
    for p in served_page(browser, pcase):
        select(p, install)
        assert computed(p, "#details .pv-reason", "fontSize") == "12px"
        assert near(computed(p, "#details .pv-reason", "color"), token(p, "--muted"))
        window = pv(p, "window")
        window.locator(".pv-sources button").first.wait_for()
        sources = window.locator(".pv-sources")
        assert sources.evaluate("(n, row) => n.parentElement === row", window.element_handle())
        row = '#details .pv[data-pivot="window"]'
        assert box(p, f"{row} .pv-sources")["width"] > box(p, row)["width"] / 2
        assert box(p, ".ev-work")["width"] > box(p, ".ev-facts")["width"]


def test_the_ranked_rows_are_in_view(browser, pcase):  # noqa: F811
    """The 7045's five ranked rows: at 1440 by 900 and the default height, three or more lie fully inside the work column
    with their reasons showing."""
    install = uid(pcase, INSTALL)
    for p in served_page(browser, pcase):
        p.set_viewport_size({"width": 1440, "height": 900})
        p.wait_for_timeout(300)
        select(p, install)
        p.wait_for_function(COUNTED)
        work = box(p, ".ev-work")
        rows = [r for r in p.locator("#details .pv").all() if inside(r.evaluate(NODE_BOX), work)]
        assert len(rows) >= 3
        assert all(r.locator(".pv-reason").is_visible() for r in rows)


@pytest.mark.parametrize("size", [(1440, 900), (1280, 720)])
def test_a_pivot_list_in_the_work_column_is_one_line_a_row(browser, pcase, size):  # noqa: F811
    """A row's event text is one line cut with an ellipsis, whole in the hover, so the list shows its rows instead of three
    or four lines a row at the work column's width. A search is as wide as the panel and still wraps."""
    install = uid(pcase, INSTALL)
    for p in served_page(browser, pcase):
        p.set_viewport_size({"width": size[0], "height": size[1]})
        p.wait_for_timeout(300)
        select(p, install)
        pv(p, "window").locator("button.pv-go").click()
        p.wait_for_selector("#relatedList li.rel-row")
        rows = p.locator("#relatedList li.rel-row")
        heights = rows.evaluate_all("(rs) => rs.map((r) => r.getBoundingClientRect().height)")
        assert max(heights) <= 24, heights
        text = rows.first.locator(".rel-text")
        assert text.get_attribute("title") == text.inner_text() != ""
        work = box(p, ".ev-work")
        assert sum(1 for r in rows.all() if inside(r.evaluate(NODE_BOX), work)) >= 5
        p.locator("#search").fill("code:4624")
        p.locator("#search").press("Enter")
        p.wait_for_selector("#details[data-page='search'] li.rel-row")
        assert p.locator("#details li.rel-row .rel-text").first.evaluate("(n) => getComputedStyle(n).whiteSpace") == "normal"


def test_folded_reasons_leave_all_five_rows_in_view(browser, pcase):  # noqa: F811
    """With the reasons folded the 7045's five ranked rows all lie inside the work column at 1400 by 900 and the default
    height."""
    install = uid(pcase, INSTALL)
    for p in served_page(browser, pcase):
        p.set_viewport_size({"width": 1400, "height": 900})
        p.wait_for_timeout(300)
        select(p, install)
        p.wait_for_function(COUNTED)
        p.locator("#details .pv-h input[type=checkbox]").uncheck()
        work = box(p, ".ev-work")
        rows = [r for r in p.locator("#details .pv").all() if inside(r.evaluate(NODE_BOX), work)]
        assert len(rows) == 5
        assert not any(r.locator(".pv-reason").is_visible() for r in rows)


def test_the_search_head_stays_under_the_band_and_a_short_panel_lets_it_go(browser, synthetic_case):  # noqa: F811
    """At 1280 by 720, in a panel at half the stage (where the search head was measured; at the default two-thirds the whole
    list fits and nothing scrolls), the count line and buttons stay under the band while the list scrolls past them, with
    eight or more rows beneath. In a panel too short for its head to leave rows, the head scrolls away."""
    for p in served_page(browser, synthetic_case):
        p.set_viewport_size({"width": 1280, "height": 720})
        p.wait_for_timeout(300)
        p.evaluate(PANEL, round(stage_height(p) / 2))
        p.locator("#search").fill("DC01")
        p.locator("#search").press("Enter")
        p.wait_for_selector("#details[data-page='search'] li.rel-row")
        body = box(p, "#detailsBody")
        head = box(p, "#details .sticky-head")
        assert head["height"] / body["height"] < 0.2   # the head measured 16 percent of the body
        assert not p.locator("#details").evaluate("(n) => n.classList.contains('short')")
        p.locator("#detailsBody").evaluate("(n) => { n.scrollTop = n.scrollHeight; }")
        head = box(p, "#details .sticky-head")
        assert abs(head["top"] - body["top"]) <= 1   # stuck under the band
        rows = [r for r in p.locator("#details li.rel-row").all()
                if r.evaluate("(n, h) => n.getBoundingClientRect().top >= h - 1 && n.getBoundingClientRect().bottom <= "
                              "document.getElementById('detailsBody').getBoundingClientRect().bottom", head["bottom"])]
        assert len(rows) >= 8
        p.evaluate(PANEL, 80)   # the head is more than half the body
        p.wait_for_function("() => document.getElementById('details').classList.contains('short')")
        assert computed(p, "#details .sticky-head", "position") == "static"
        p.evaluate(PANEL, 400)
        p.wait_for_function("() => !document.getElementById('details').classList.contains('short')")
        assert computed(p, "#details .sticky-head", "position") == "sticky"


def test_the_hosts_panel_opens_with_the_details_band(browser, synthetic_case):  # noqa: F811
    """Hosts edits case records as the Details pages do, so it opens with the same band and its 3 px edge, and its body
    scrolls under the band, which stays."""
    for p in served_page(browser, synthetic_case):
        p.set_viewport_size({"width": 1400, "height": 420})
        case_menu(p, "hostsButton")
        p.wait_for_selector("#hostsTable tbody tr")
        assert p.locator("#hostsPanel .band .name").text_content() == "Hosts"
        assert near(computed(p, "#hostsPanel .band", "backgroundColor"), token(p, "--band-details"))
        assert computed(p, "#hostsPanel", "borderTopWidth") == "3px"
        assert near(computed(p, "#hostsPanel", "borderTopColor"), token(p, "--band-details-edge"))
        assert computed(p, "#hostsBody", "overflowY") == "auto"
        top = box(p, "#hostsPanel .band")["top"]
        p.locator("#hostsBody").evaluate("(n) => { n.scrollTop = n.scrollHeight; }")
        assert box(p, "#hostsPanel .band")["top"] == top


def test_an_aligned_hosts_plain_event_keeps_a_two_row_header(clock_page):  # noqa: F811
    """On a case aligned to its capture, nearly every event is on an aligned host, so the clock note must not draw a
    third row. Its sentence is the hover of the chip that starts row 2, "Aligned -3599.5 s". An event with a pair in the
    capture still draws the note, since it has Show the pair."""
    p = clock_page
    p.locator("#clockAligned").click()
    p.wait_for_selector("#clockAligned[aria-pressed='true']")
    plain = p.evaluate(PLAIN_DC01)
    assert plain, "no drawn 4624 on DC01"
    select(p, plain)
    chip = p.locator("#details .ev-sum .clock-chip")
    assert chip.inner_text() == "Aligned -3599.5 s"
    assert "Times here are aligned to the capture." in chip.get_attribute("title")
    assert "DC01's clock ran 59 m 59.5 s ahead of the capture (10 of 10 pairs agree)." in chip.get_attribute("title")
    assert p.locator("#details .ev-clock").count() == 0
    assert not p.locator("#details .ev-head-more").is_visible()
    assert box(p, ".ev-head")["height"] <= 72
    paired = event_point(p, "131")["uid"]
    p.evaluate("(uid) => window.__app.select(uid, false)", paired)
    p.locator("#details .ev-clock", has_text="Times here are aligned to the capture.").wait_for()
    assert p.locator("#details .ev-head-more").is_visible()


@pytest.mark.parametrize(("panel", "height"), [(300, 800), (200, 800)])
def test_a_pivot_at_900_px_lands_under_the_header(browser, pcase, panel, height):  # noqa: F811
    """At 960 px and below the body scrolls as one. The header sticks unless it is taller than half the body, and the
    pivot's list lands straight under whatever sticks, with its heading stuck there on scrolling and no row hidden behind
    the header."""
    rdp = uid(pcase, RDP)
    for p in served_page(browser, pcase):
        p.set_viewport_size({"width": 900, "height": height})
        p.wait_for_timeout(300)
        p.evaluate(PANEL, panel)
        select(p, rdp)
        pv(p, "window").locator("button.pv-go").click()
        p.locator("#relatedList .sticky-head").wait_for()
        p.wait_for_timeout(200)
        body, head = box(p, "#detailsBody"), box(p, ".ev-head")
        sticky = computed(p, ".ev-head", "position") == "sticky"
        assert sticky == (head["height"] <= body["height"] / 2), (head, body)
        assert sticky == (panel == 300)   # a roomy panel keeps the header, a short one lets it go
        assert p.evaluate("document.getElementById('details').classList.contains('head-tall')") == (not sticky)
        under = head["bottom"] if sticky else body["top"]
        assert abs(box(p, "#relatedList .sticky-head")["top"] - under) <= 2   # landed straight under it
        fits = "(n, [t, b]) => n.getBoundingClientRect().top >= t - 1 && n.getBoundingClientRect().bottom <= b + 1"
        visible = [r for r in p.locator("#relatedList li").all() if r.evaluate(fits, [under, body["bottom"]])]
        assert visible, (panel, under, body)
        p.locator("#detailsBody").evaluate("(n) => { n.scrollTop = n.scrollTop + 150; }")
        assert p.locator("#detailsBody").evaluate("(n) => n.scrollTop") > 100
        assert abs(box(p, "#relatedList .sticky-head")["top"] - under) <= 1   # stuck under it, none of it cut
        if sticky:
            assert abs(box(p, ".ev-head")["top"] - body["top"]) <= 1


def test_aligning_a_plain_event_keeps_the_focus_on_its_clock(clock_page):  # noqa: F811
    """Align DC01 to the capture, pressed on a plain DC01 event, folds the clock note into the chip's hover, so the button
    and the note are gone. The focus goes to the chip, and not to the page's body."""
    p = clock_page
    select(p, p.evaluate(PLAIN_DC01))
    p.locator("#details .ev-clock").get_by_role("button", name="Align DC01 to the capture").focus()
    p.keyboard.press("Enter")
    p.locator("#details .ev-sum .clock-chip", has_text="Aligned -3599.5 s").wait_for()
    p.wait_for_selector("#clockSwitch button[aria-disabled]", state="detached")
    assert p.locator("#details .ev-clock").count() == 0
    p.wait_for_function("() => document.activeElement.matches('#details .ev-sum .clock-chip')")


def test_the_kind_gives_way_with_an_ellipsis(clock_page):  # noqa: F811
    """Where row 1 is short of room, the event's kind is cut inside its row with an ellipsis. A minimum width above the
    room the kind gets would cut it at the row's edge with no ellipsis, and the cut wouldn't show. The window is 1160 px
    wide, inside the two-column header, which starts at 1151 px, where the plain event's short kind has less room than it
    needs."""
    p = clock_page
    p.locator("#clockAligned").click()
    p.wait_for_selector("#clockAligned[aria-pressed='true']")
    select(p, p.evaluate(PLAIN_DC01))
    p.set_viewport_size({"width": 1160, "height": 900})
    p.wait_for_timeout(300)
    kind, ident = box(p, ".ev-ident .kind"), box(p, ".ev-ident")
    assert kind["width"] > 0 and kind["right"] <= ident["right"] + 0.5, (kind, ident)
    assert p.locator(".ev-ident .kind").evaluate("(n) => n.scrollWidth > n.clientWidth")   # cut, so the ellipsis shows


def test_a_host_whose_clock_was_right_keeps_a_two_row_header(browser, synthetic_case):  # noqa: F811
    """A host whose clock agrees with the capture as recorded needs no offset, so its events have no chip. The clock
    note still must not draw a third row on each of them: its sentence is the hover of the time."""
    flows, accepts = [], []
    for i in range(10):
        client, start = f"194.61.24.102:{51000 + i}", T0 - 3480 * SEC + i * 20 * SEC
        flows.append(flow(start, client, "10.42.85.10:3389"))
        accepts.append(accepted(start + SEC // 5, client, "DC01"))   # 0.2 s ahead, inside what agrees
    for i, (host, loaded, tool) in enumerate((("network", flows, "suricata"), ("DC01", accepts, "evtxecmd"))):
        load(synthetic_case.db_path, loaded, host=host, tool=tool, tool_version="t", run_id=f"right-{i}",
             replaces_sources=[], staging_dir=synthetic_case.folder)
    for p in served_page(browser, synthetic_case):
        assert p.evaluate("window.__app.S.meta.hosts.find((h) => h.host === 'DC01').clock.state") == "agrees"
        select(p, p.evaluate(PLAIN_DC01))
        assert p.locator("#details .clock-chip").count() == 0
        assert p.locator("#details .ev-clock").count() == 0
        assert not p.locator("#details .ev-head-more").is_visible()
        assert box(p, ".ev-head")["height"] <= 72
        title = p.locator("#details .ev-ident .time").get_attribute("title")
        assert "DC01's clock ran 0.2 s ahead of the capture (10 of 10 pairs agree). Times here are aligned" in title


def test_the_verdict_note_box_shows_its_whole_label(browser, synthetic_case):  # noqa: F811
    """The note box's placeholder is its only visible label, so the 120 px box must not cut it, as to
    'Note for this mark (optional'. The placeholder is short and the long wording is the box's title and its name. The
    box is 120 px wide at 1280 by 720, which leaves the identity line room for the kind."""
    for p in served_page(browser, synthetic_case):
        p.set_viewport_size({"width": 1280, "height": 720})
        open_event(p)
        note = p.locator("#details .ev-verdict .mark-note")
        note.wait_for()
        assert box(p, "#details .ev-verdict .mark-note")["width"] == 120
        assert note.evaluate(
            "(i) => { i.value = i.placeholder; const fits = i.scrollWidth <= i.clientWidth; i.value = ''; return fits; }")
        assert note.get_attribute("placeholder") == "Note (optional)"
        assert note.get_attribute("title") == "Note for this mark (optional)"


LOGON_LOG = "DC01/Windows/System32/winevt/Logs/Security_header.evtx"
LOGON_KIND = "4624 Successful logon, Security"
LONG_KIND = "4624 Successful logon of a remote interactive session, Security"
LOGON_TEXT = ("{} | Target: C137\\Administrator | LogonType 10 | Source: 203.0.113.50:49822 (WS02) | "
              "AuthenticationPackage: Negotiate")
HIT_TITLE = "Logon (RemoteInteractive) from the internet"
TWO_TAGS = {"MitreTactics": "LatMov", "MitreTags": "T1021.001"}   # Hayabusa suggests TA0008 and T1021.001
KIND_ROOM = """() => {
    const kind = document.querySelector('#details .ev-ident .kind');
    const k = kind.getBoundingClientRect(), row = document.querySelector('#details .ev-ident').getBoundingClientRect();
    return { text: kind.textContent, width: k.width, needs: kind.scrollWidth, shown: kind.clientWidth, right: k.right,
             edge: row.right, overflow: getComputedStyle(kind).textOverflow };
}"""


def add_logon(case, tags=False, kind=LOGON_KIND):
    """A 4624 on DC01 whose kind reads `kind`, with a medium Hayabusa hit on it, which suggests Suspicious, and with the
    hit's ATT&CK tags when `tags` is true, which Hayabusa suggests too. The event's ID."""
    text = LOGON_TEXT.format(kind.removesuffix(", Security"))
    logon_event = Event(T0 + 5 * SEC, "Event Recorded", "evtx", LOGON_LOG, "401", text, record_id=401,
                        event_code="4624", log_channel="Security", user_name="Administrator", user_domain="C137",
                        logon_type="10", source_ip="203.0.113.50", source_port="49822", source_workstation="WS02")
    hit = Event(T0 + 5 * SEC, "Event Recorded", "hayabusa", LOGON_LOG, "401:rule", f"{HIT_TITLE} [medium]", record_id=401,
                log_channel="Security", rule_title=HIT_TITLE, rule_level="medium", extra=TWO_TAGS if tags else None)
    for i, (loaded, tool) in enumerate(((logon_event, "evtxecmd"), (hit, "hayabusa"))):
        load(case.db_path, [loaded], host="DC01", tool=tool, tool_version="t", run_id=f"header-{i}",
             replaces_sources=[], staging_dir=case.folder)
    return uid(case, f"tool = 'evtxecmd' AND source_file = '{LOGON_LOG}'")


@pytest.fixture
def logon_event(synthetic_case, request):
    """add_logon's event in the case before a page serves it. A test parametrizes it, indirectly, with add_logon's
    keywords to add the suggested tags or to lengthen the kind."""
    return add_logon(synthetic_case, **getattr(request, "param", {}))


@pytest.fixture
def aligned_logon(logon_event, clock_page):  # noqa: F811
    """clock_page with DC01 aligned to the capture at 1280 by 720, and the event's ID: DC01's events are offset by
    -3599.5 s, so each has a chip."""
    clock_page.locator("#clockAligned").click()
    clock_page.wait_for_selector("#clockAligned[aria-pressed='true']")
    clock_page.set_viewport_size({"width": 1280, "height": 720})
    clock_page.wait_for_timeout(300)
    return clock_page, logon_event


@pytest.fixture
def plain_logon(logon_event, browser, synthetic_case):  # noqa: F811
    """The page on the synthetic case at 1280 by 720 and the event's ID: DC01 has no capture to be measured against, so
    its events have no offset and no chip."""
    for p in served_page(browser, synthetic_case):
        p.set_viewport_size({"width": 1280, "height": 720})
        p.wait_for_timeout(300)
        yield p, logon_event


def open_logon(p, logon, mark=None, tags_open=False):
    """The Event page of `logon`, marked `mark` first when it names one, with Hayabusa's suggested tags open when asked, and
    the kind's measure as KIND_ROOM reads it."""
    select(p, logon)
    if mark:
        p.locator("#details .ev-verdict").get_by_role("button", name=mark, exact=True).click()
        p.locator(f"#details .ev-verdict .status.{mark.lower()}").wait_for()
    if tags_open:
        toggle = p.locator("#details .ev-verdict button.tw")
        toggle.click()
        assert toggle.get_attribute("aria-expanded") == "true"
        p.locator("#details .ev-head-more .tagchip.suggested").first.wait_for()
    return p.evaluate(KIND_ROOM)


def test_the_clock_chip_starts_the_summary_row(aligned_logon):
    """The chip that names a host's clock offset, "Aligned -3599.5 s", is the first item of the header's second row, before
    Hayabusa's chips and under the time it explains. Row 1 holds the badge, the time, the host, and the kind. The chip's
    hover is the clock note's sentence and the recorded time."""
    p, logon = aligned_logon
    open_logon(p, logon, "Suspicious")
    assert p.locator("#details .ev-ident .chip").count() == 0
    assert p.locator("#details .ev-ident > *").evaluate_all("(nodes) => nodes.map((n) => n.className)") == [
        "badge s", "time", "host", "kind"]
    assert p.locator("#details .ev-sum > .chip").evaluate_all("(nodes) => nodes.map((n) => n.textContent)") == [
        "Aligned -3599.5 s", f"Hayabusa medium: {HIT_TITLE}"]
    assert p.locator("#details .ev-sum > *").first.get_attribute("class") == "chip clock-chip"
    chip, hayabusa, time = box(p, ".ev-sum .clock-chip"), box(p, ".ev-sum .level-medium"), box(p, ".ev-ident .time")
    assert chip["right"] <= hayabusa["left"] and abs(chip["top"] - hayabusa["top"]) <= 2
    assert chip["top"] >= time["bottom"] - 1 and chip["left"] < time["right"] and chip["right"] > time["left"]
    assert p.locator("#details .ev-sum .clock-chip").evaluate("(n) => n.scrollWidth <= n.clientWidth")   # its words are whole
    title = p.locator("#details .ev-sum .clock-chip").get_attribute("title")
    assert "Times here are aligned to the capture." in title and "Recorded 2020-09-19 03:21:53.000000 UTC" in title


def test_a_host_with_no_offset_leaves_no_empty_slot_at_the_start_of_the_summary_row(plain_logon):
    """Where the host has no clock offset there is no chip, and the summary row starts with Hayabusa's chip at the row's
    own left edge, with no empty item or gap before it."""
    p, logon = plain_logon
    open_logon(p, logon, "Suspicious")
    assert p.locator("#details .clock-chip").count() == 0
    assert p.locator("#details .ev-sum > *").first.get_attribute("class") == "chip level-medium"
    assert abs(box(p, ".ev-sum .level-medium")["left"] - box(p, ".ev-sum")["left"]) <= 0.5


@pytest.mark.parametrize("mark", ["Suspicious", None], ids=["marked", "suggestion_waiting"])
def test_the_kind_draws_in_full_when_the_header_is_not_crowded(aligned_logon, mark):
    """At 1280 by 720 a 4624's kind, "4624 Successful logon, Security", is drawn whole in row 1 when the event is marked
    Suspicious, and when Hayabusa's mark suggestion waits for a decision: the clock chip is in row 2 and the note box is
    narrow."""
    p, logon = aligned_logon
    room = open_logon(p, logon, mark)
    assert room["text"] == LOGON_KIND
    assert room["needs"] <= room["shown"] and room["right"] <= room["edge"] + 0.5, room


NARROW_WINDOW = {"width": 1151, "height": 800}   # the first width of the two-column header, where the kind has the least room


@pytest.mark.parametrize("window", [None, NARROW_WINDOW], ids=["1280", "1151"])
@pytest.mark.parametrize(
    ("logon_event", "mark", "tags_open"),
    [({"tags": True, "kind": LONG_KIND}, "Suspicious", True), ({"tags": True, "kind": LONG_KIND}, None, False)],
    indirect=["logon_event"], ids=["marked_tags_open", "suggestion_and_tags_waiting"])
def test_the_kind_is_cut_with_an_ellipsis_not_hidden_when_the_header_is_crowded(aligned_logon, mark, tags_open, window):
    """With Hayabusa's suggested tags open, and with a mark suggestion and suggested tags both waiting, the verdict column
    is at its widest, and a kind longer than the room it gets, here LONG_KIND, is wider than 0 and cut inside its row with
    an ellipsis, not at the row's edge. That holds at 1280 px and at 1151 px, where the room is under 50 px: the kind has
    no minimum width, since one above the room it gets is cut at the row's edge with no ellipsis."""
    p, logon = aligned_logon
    if window:
        p.set_viewport_size(window)
        p.wait_for_timeout(300)
    room = open_logon(p, logon, mark, tags_open)
    assert room["text"] == LONG_KIND
    assert room["width"] > 0 and room["needs"] > room["shown"] + 50, room
    assert room["overflow"] == "ellipsis" and room["right"] <= room["edge"] + 0.5, room


@pytest.mark.parametrize(
    ("logon_event", "mark", "tags_open"), [({"tags": True}, "Suspicious", True), ({"tags": True}, None, False)],
    indirect=["logon_event"], ids=["marked_tags_open", "suggestion_and_tags_waiting"])
def test_a_host_with_no_offset_gives_the_kind_as_much_room_as_an_aligned_one(plain_logon, mark, tags_open):
    """With no chip to leave, the kind of a host with no clock offset gets room for most of its text beside Hayabusa's
    suggested tags, and is cut inside its row with an ellipsis if at all."""
    p, logon = plain_logon
    room = open_logon(p, logon, mark, tags_open)
    assert room["text"] == LOGON_KIND
    assert room["width"] >= 150 and room["right"] <= room["edge"] + 0.5, room
    assert room["needs"] <= room["shown"] or room["overflow"] == "ellipsis", room


@pytest.mark.parametrize(
    ("logon_event", "mark", "tags_open"), [({"tags": True}, "Suspicious", True), ({"tags": True}, None, False)],
    indirect=["logon_event"], ids=["marked_tags_open", "suggestion_and_tags_waiting"])
def test_a_host_with_no_offset_cuts_the_kind_with_an_ellipsis_in_the_narrowest_two_column_header(plain_logon, mark, tags_open):
    """At 1151 px, the first width of the two-column header, the kind of a host with no clock offset has under 50 px beside
    Hayabusa's suggested tags. It is wider than 0 and ends in an ellipsis inside its row, not cut at the row's edge."""
    p, logon = plain_logon
    p.set_viewport_size(NARROW_WINDOW)
    p.wait_for_timeout(300)
    room = open_logon(p, logon, mark, tags_open)
    assert room["text"] == LOGON_KIND
    assert room["width"] > 0 and room["needs"] > room["shown"], room
    assert room["overflow"] == "ellipsis" and room["right"] <= room["edge"] + 0.5, room


def test_the_band_does_not_grow_when_a_trail_shows(browser, pcase):  # noqa: F811
    """The bordered 'Save trail as a note' button must not be taller than the band's content, or the band grows and the
    page drops on the first pivot. Checked at 1440 by 900 and 1280 by 720."""
    rdp = uid(pcase, RDP)
    for size in ((1440, 900), (1280, 720)):
        for p in served_page(browser, pcase):
            p.set_viewport_size({"width": size[0], "height": size[1]})
            select(p, rdp)
            before = box(p, "#detailsBand")["height"]
            top = box(p, ".ev-work")["top"]
            pv(p, "session").locator("button.pv-go").click()
            p.locator("#details nav.trail button.trail-save").wait_for()
            assert box(p, "#detailsBand")["height"] == before, size
            assert box(p, ".ev-work")["top"] == top, size


def test_a_page_does_not_repeat_the_band_title_as_a_heading(browser, synthetic_case):  # noqa: F811
    """The band names every Details page, so the Audit trail, Import, Tools, Export, and To investigate pages don't repeat
    the name as an h2. The Rules page keeps its h2, which says more than the band's 'Rules', and so do the Findings page's
    two columns."""
    headings = "() => [...document.querySelectorAll('#details h2')].map((n) => n.textContent)"
    intake(synthetic_case)   # the Import page lists the manifest's files
    for p in served_page(browser, synthetic_case, setup=no_tool_scan):
        for item, title in (("auditButton", "Audit trail"), ("importButton", "Import"), ("toolsButton", "Tools"),
                            ("exportButton", "Findings")):   # Export opens the Findings page
            case_menu(p, item)
            p.wait_for_function("(t) => document.querySelector('#detailsBand .title')?.textContent === t", arg=title)
            assert title not in p.evaluate(headings), title
        p.locator("#investigateButton").click()
        p.wait_for_function("() => document.querySelector('#detailsBand .title')?.textContent === 'To investigate'")
        assert p.evaluate(headings) == ["Marked events to follow up", "Pending suggestions, by rule"]   # the worklist
        case_menu(p, "rulesButton")
        p.wait_for_function("() => document.querySelector('#detailsBand .title')?.textContent === 'Rules'")
        assert p.evaluate(headings) == ["Suggestion rules"]


def test_a_focused_control_scrolls_in_with_room_for_its_ring(browser, pcase):  # noqa: F811
    """Tab must scroll a field near the bottom of the facts column in with room for its ring, or the column cuts the ring's
    bottom 3 px. A focused control scrolls in with 4 px to spare."""
    install = uid(pcase, INSTALL)
    for p in served_page(browser, pcase, setup=no_tool_scan):
        p.evaluate(PANEL, 200)
        select(p, install)
        p.wait_for_selector("#details .ev-facts button")
        p.evaluate("() => document.querySelector('#details .ev-facts button').focus()")
        tight, seen = [], 0
        for _ in range(120):   # Tab through the page, so each ring is the keyboard's
            p.keyboard.press("Tab")
            gaps = p.evaluate("""() => {
                const a = document.activeElement, facts = document.querySelector('#details .ev-facts');
                if (!facts.contains(a)) return null;
                const r = a.getBoundingClientRect(), f = facts.getBoundingClientRect();
                return [f.bottom - r.bottom, r.top - f.top, getComputedStyle(a).scrollMarginBottom];
            }""")
            if gaps:
                seen += 1
                if gaps[0] < 3.5 or gaps[1] < 3.5:
                    tight.append(gaps)
        assert seen > 5, seen
        assert not tight, tight


def test_a_long_case_name_and_state_keep_the_case_panel_on_one_row(browser, synthetic_case):  # noqa: F811
    """A long case name and state line must not widen #caseId, or the Case panel takes two rows at 1440 and at 1280 and the
    stage loses 27 to 33 px. The name and the line ellipsize, with all their text in the hover."""
    name = "Szechuan Sauce incident, DFIR Madness 2020"
    for p in served_page(browser, synthetic_case):
        p.evaluate("""(name) => {
            document.getElementById('caseName').textContent = name;
            document.getElementById('caseState').textContent =
                'Open · full re-hash matched on 2026-10-18 · analyst Ana Lyst'; }""", name)
        for size in ((1440, 900), (1280, 720)):
            p.set_viewport_size({"width": size[0], "height": size[1]})
            p.wait_for_timeout(100)
            assert box(p, "header")["height"] <= 50, (size, box(p, "header"))
        assert p.locator("#caseName").evaluate("(n) => n.scrollWidth > n.clientWidth")   # cut, so the ellipsis shows


# The page's own badge and verdict zone for an unreviewed event with these suggestions: the badge's hover, and each
# pending decision's words, the one beside the identity first.
DECISIONS = """async (suggestions) => {
    const page = await import('/js/event_page.js');
    const ev = { mark: { label: 'Unreviewed' }, suggestions, tags: [], tag_suggestions: [], findings: [],
                 rejection_notes: {} };
    const { zone, more } = page.verdictZone(ev, 'x', 1);
    const decisions = [...zone.querySelectorAll('.decision'), ...more.filter((n) => n.matches?.('.decision'))];
    return { badge: page.eventBadge(ev).title, decisions: decisions.map((d) => d.querySelector('span').textContent) };
}"""


def test_the_badge_and_the_first_decision_are_the_most_severe_pending_suggestion(browser, synthetic_case):  # noqa: F811
    """An event with several pending suggestions reads as its most severe one, as the lists read it: Malicious, then
    Suspicious, then Authorized, with ties by source name. The verdict zone puts that decision beside the identity and the
    others below it in the same order. A rule named before Hayabusa that suggests Authorized doesn't come first on a
    real Event page."""
    def rule(app):
        api_rule(app, {"op": "add", "text": "id: admin_tools\nsuggest: authorized\nwhen: {field: event_code, equals: '4624'}\n"})

    for p in served_page(browser, synthetic_case, setup=rule):
        two = p.evaluate(DECISIONS, [{"value": "authorized", "source": "admin_tools", "rejected": False},
                                     {"value": "suspicious", "source": "hayabusa", "rejected": False}])
        assert two == {"badge": "Unreviewed, with a pending Suspicious suggestion from hayabusa",
                       "decisions": ["Decision needed: hayabusa suggests suspicious",
                                     "Decision needed: admin_tools suggests authorized"]}
        many = p.evaluate(DECISIONS, [{"value": "authorized", "source": "a_rule", "rejected": False},
                                      {"value": "suspicious", "source": "z_rule", "rejected": False},
                                      {"value": "malicious", "source": "b_rule", "rejected": True},
                                      {"value": "suspicious", "source": "m_rule", "rejected": False},
                                      {"value": "malicious", "source": "q_rule", "rejected": False}])
        assert many["badge"] == "Unreviewed, with a pending Malicious suggestion from q_rule"
        assert [d.split(": ")[1].split()[0] for d in many["decisions"]] == ["q_rule", "m_rule", "z_rule", "a_rule"]
        rdp = p.evaluate("() => window.__app.S.data.events.find((e) => e.code === '4624' && e.hit >= 3).uid")
        p.evaluate("(u) => window.__app.select(u, false)", rdp)
        line = p.locator(f"#details[data-key='event:{rdp}'] .verdict-line")
        line.wait_for()
        assert p.locator("#details .ev-ident .badge").get_attribute("title") == (
            "Unreviewed, with a pending Suspicious suggestion from hayabusa")
        assert line.locator(".decision > span").inner_text() == "Decision needed: hayabusa suggests suspicious"
        assert p.locator("#details .ev-head-more .decision > span").inner_text() == (
            "Decision needed: admin_tools suggests authorized")


# The page's own reads of its tables for values named after a property every object has, constructor and __proto__: an
# artifact's name and fields, an event log record's logon type, a Hayabusa level, and a rejected suggestion's source
# with no note
ODD_KEYS = """async () => {
    const page = await import('/js/event_page.js');
    return ['constructor', '__proto__'].map((key) => {
        const logon = { artifact: 'evtx', message: 'An account was successfully logged on', user_name: 'admin',
                        logon_type: key };
        const hits = page.hitChips([{ level: key, title: 'odd' }, { level: 'high', title: 'known' }]);
        const ev = { mark: { label: 'Unreviewed' }, suggestions: [{ value: 'suspicious', source: key, rejected: true }],
                     tags: [], tag_suggestions: [], findings: [], rejection_notes: {} };
        const rejected = page.verdictZone(ev, 'x', 1).more.map((n) => n.querySelector?.('span.muted')?.textContent || '')
          .filter((t) => t.startsWith('Rejected'));
        return { summary: page.eventSummary(logon), lead: hits.lead[0].textContent, rejected, name: page.artifactName(key),
                 group: page.artifactGroup({ artifact: key }, {}) };
    });
}"""


def test_an_event_whose_values_name_a_built_in_property_reads_as_written(browser, synthetic_case):  # noqa: F811
    """An import whose artifact is named constructor, with a logon type of constructor, opens on an Event page that
    reads both as written, rather than as a property every JavaScript object has. So do an artifact's name, an event log
    record's logon type, a Hayabusa level, and a rejected suggestion's source named constructor or __proto__."""
    (synthetic_case.evidence / "DC01" / "odd.csv").write_text(
        "Time,LogonType,Message\n2020-09-19T03:25:00Z,constructor,an odd logon\n", encoding="utf-8", newline="")
    intake(synthetic_case)
    mapping = {"format": "csv", "delimiter": ",", "header": True, "artifact": "constructor",
               "time": {"columns": ["Time"], "format": "ymd", "zone": "UTC"},
               "fields": {"logon_type": "LogonType", "message": "Message"}, "host": {"from": "folder"},
               "message": "{Message}", "ignore": []}
    record = run_import(synthetic_case, "DC01/odd.csv", mapping, zones={})
    assert record.status == "ok", record.reason
    found = {}
    setup = lambda app: found.update(uid=app.con.execute(
        "SELECT event_uid FROM events WHERE artifact = 'constructor'").fetchone()[0])
    for p in served_page(browser, synthetic_case, setup=setup):
        assert p.evaluate(ODD_KEYS) == [{"summary": [f"admin, logon type {key}"], "lead": "Hayabusa high: known",
                                         "rejected": [f"Rejected: {key} suggested suspicious"], "name": key, "group": None}
                                        for key in ("constructor", "__proto__")]
        p.evaluate(RECORD_REQUESTS)
        p.evaluate("(u) => window.__app.select(u, false)", found["uid"])
        p.wait_for_function("() => window.__taken.some((path) => path.startsWith('/api/event?'))")
        assert p.errors == []
        head = p.locator(f"#details[data-key='event:{found['uid']}'] .ev-ident")
        assert head.locator(".kind").inner_text().startswith("constructor")
        logon_type = p.locator("#details .ev-facts dt", has_text="Logon type").locator("xpath=following-sibling::dd[1]")
        assert logon_type.evaluate("(dd) => dd.firstChild.textContent") == "constructor"
        assert p.evaluate("window.__app.S.focusEvent.label") == "constructor on DC01"


# Whether a text box shows its whole placeholder: as drawn, and at the narrowest width the page lets it shrink to
PLACEHOLDER_FITS = "(i) => { i.value = i.placeholder; const fits = i.scrollWidth <= i.clientWidth; i.value = ''; return fits; }"
NARROWEST_FITS = f"""(i) => {{
    const style = i.style.cssText;
    i.style.flex = 'none';
    i.style.width = getComputedStyle(i).minWidth;
    const fits = ({PLACEHOLDER_FITS})(i);
    i.style.cssText = style;
    return fits;
}}"""


def test_a_list_note_box_shows_its_whole_placeholder(browser, synthetic_case):  # noqa: F811
    """A list's note box beside its mark buttons is labeled by its placeholder until a row is ticked. On a search's list
    at 1400 by 900, with matches the View hides and so a button to show them, the row is crowded and the box shrinks;
    a find on the list changes Select all to "Select the N shown". The box shows its whole placeholder either way, and
    would at the narrowest the page lets it shrink to."""
    for p in served_page(browser, synthetic_case):
        p.evaluate("() => import('/js/view.js').then((m) => m.addViewValue({ host: 'DC01' }))")
        p.wait_for_function("() => window.__app.S.filterId !== null && !window.__app.S.windowPending")
        p.locator("#search").fill("code:4624")
        p.locator("#search").press("Enter")
        p.locator("#searchShowHidden").wait_for()
        head = p.locator("#details[data-page='search'] .sticky-head")
        note = head.locator(".mark-note")
        assert note.get_attribute("placeholder").startswith("Note")
        assert note.evaluate(PLACEHOLDER_FITS)
        head.locator(".find input").fill("DC01")
        head.locator("button", has_text=re.compile(r"^Select the \d+ shown$")).wait_for()
        assert note.evaluate(PLACEHOLDER_FITS)
        assert note.evaluate(NARROWEST_FITS)


PE_BUILT = 1_200_000_000 * SEC   # 2008-01-10 21:20:00 UTC


@pytest.fixture
def pe_time(synthetic_case):
    """An Autoruns entry on DC01 dated by its image's PE link time, and DC01's time zone, in the case before clock_page
    serves it."""
    image = "C:\\Windows\\System32\\coreupdater.exe"
    entry = Event(ts_us=PE_BUILT, ts_desc=BUILT, artifact="autoruns", source_file="DC01/autoruns.csv", source_record="5",
                  message=f"Services: coreupdater | {image}", file_path=image,
                  extra={"Category": "Services", "Entry": "coreupdater", "Image Path": image})
    load(synthetic_case.db_path, [entry], host="DC01", tool="autoruns", tool_version="t", run_id="pe", replaces_sources=[],
         staging_dir=synthetic_case.folder)
    add_zone(synthetic_case, "DC01", 1, {"TimeZoneKeyName": "Pacific Standard Time", "Bias": "480"})


@pytest.mark.usefixtures("pe_time")
def test_a_time_the_hosts_clock_did_not_write_has_no_clock_note_or_local_time(clock_page):  # noqa: F811
    """An Autoruns PE link time says when the image was built, not anything DC01's clock wrote, so its header has no clock
    note and no local time on DC01, while an event log record on DC01 has both. An offset typed for DC01 still moves the
    time, and the chip says so, with the recorded time in its hover; the Recorded time row calls it the host's offset.
    Raw fields don't list the server's flag for such a time."""
    p = clock_page
    pe = p.hub.app.con.execute("SELECT event_uid FROM events WHERE artifact = 'autoruns'").fetchone()[0]
    select(p, p.evaluate(PLAIN_DC01))
    assert p.locator("#details .ev-clock").count() == 1
    assert "Local time on DC01" in p.locator("#details .ev-ident .time").get_attribute("title")
    p.evaluate("(u) => window.__app.select(u, false)", pe)
    ident = p.locator(f"#details[data-key='event:{pe}'] .ev-ident")
    ident.wait_for()
    assert p.locator("#details .ev-clock").count() == 0
    assert "Local time on" not in (ident.locator(".time").get_attribute("title") or "")
    assert p.locator("#details .clock-chip").count() == 0
    case_menu(p, "hostsButton")
    offset = p.locator("#hostsTable tr[data-host='DC01'] input[type=number]")
    offset.fill("86400")
    offset.dispatch_event("change")
    p.wait_for_function("() => window.__app.S.meta.hosts.find((h) => h.host === 'DC01').offset_seconds === 86400")
    p.evaluate("(u) => window.__app.select(u, false)", pe)
    p.locator("#details .ev-ident .time", has_text="2008-01-11 21:20:00.000000 UTC").wait_for()
    chip = p.locator("#details .ev-sum .clock-chip")
    assert chip.inner_text() == "Host offset +86400 s"
    assert "Recorded 2008-01-10 21:20:00.000000 UTC" in chip.get_attribute("title")
    assert "Local time on" not in (p.locator("#details .ev-ident .time").get_attribute("title") or "")
    assert p.locator("#details .ev-clock").count() == 0
    recorded = p.locator("#details dt", has_text=re.compile(r"^Recorded time$")).locator("xpath=following-sibling::dd[1]")
    assert recorded.evaluate("(dd) => dd.textContent") == "2008-01-10 21:20:00.000000 UTC, before the +86400 s host offset"
    assert p.locator("#details dt", has_text=re.compile(r"^host_clock$")).count() == 0   # not one of Raw fields


FOLD_HASH = """() => [...document.querySelectorAll('#details .ev-facts dt')].filter((dt) => dt.textContent.includes('SHA-256'))
    .map((dt) => [dt.textContent, dt.nextElementSibling.textContent])"""   # the Record and source fold's hash row


def test_the_record_fold_names_the_file_whose_hash_it_cites(browser, tmp_path):  # noqa: F811
    """An event of output found in the evidence names a file its load never read. The Record and source fold gives the
    hash of the output file its run read, under that file's name, and when the run read several output files, it points
    to the provenance line. An event of a tool's run gives its own evidence file's hash as Evidence SHA-256."""
    case = found_case(tmp_path)
    runs = {"tool": evtxecmd_run(case), "one": load_found(case, "WS02", OTHER_HOST[0]),
            "several": load_found(case, "WS01", FOUND, KAPE)}
    hashes = manifest_hashes(case)
    expected = {"tool": ["Evidence SHA-256", hashes[SYSTEM_LOG]],
                "one": ["SHA-256 of 20240514_EvtxECmd_Output.csv", hashes[OTHER_HOST[0]]],
                "several": ["Evidence SHA-256", "see the provenance line"]}
    events = {name: uid(case, f"run_id = '{record.run_id}'") for name, record in runs.items()}
    for p in served_page(browser, case):
        for name, event in events.items():
            select(p, event)
            p.wait_for_selector(f"#details[data-key='event:{event}'] .ev-facts")
            assert p.evaluate(FOLD_HASH) == [expected[name]], name
