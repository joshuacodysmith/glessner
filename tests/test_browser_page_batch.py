"""Browser tests for the start page's open job, the search results' fixed heading, the Audit trail tab, the search rows
the View hides, and an overview count's events in the Details panel. They run as test_browser_smoke.py's do, on the
installed Edge, and are skipped without it."""

import threading

import pytest
from test_browser_frame import current, no_tool_scan
from test_browser_smoke import browser, case_menu, event_point, served_page  # noqa: F401
from test_overview import app_with_work, overview_case  # noqa: F401

from glessner.case import CaseError, create_case
from glessner.intake import intake
from glessner.server import Hub
from glessner.start import remember

pytestmark = pytest.mark.browser
START_READY = "() => window.__start && window.__start.info !== null"


@pytest.fixture
def remembered(tmp_path):
    """A case the start page lists under Recent cases."""
    ev = tmp_path / "evidence"
    (ev / "DC01").mkdir(parents=True)
    (ev / "DC01" / "notes.txt").write_text("evidence")
    case = create_case(tmp_path / "cases" / "opening", "Opening case", ev, "cody")
    intake(case)
    remember(case, 1)
    return case


def test_an_open_from_the_start_page_shows_its_stage_with_a_moving_mark_and_then_the_timeline(browser, remembered, monkeypatch):  # noqa: F811
    """Open is a job. Its box under the buttons names the case and the stage the upgrade reports, with a count,
    and a spinner that moves unless the browser asks for less motion; the buttons wait; and the page goes to the timeline
    when the job ends."""
    gate = threading.Event()
    real = Hub.open

    def slow(self, case, report=None):
        report("Upgrading the case format: reloading 67,858 Suricata events", 2, 5)
        assert gate.wait(30)
        return real(self, case, report)

    monkeypatch.setattr(Hub, "open", slow)
    # The box is drawn again at each poll, 700 ms apart, so the mark is found and read in one step. A locator takes two,
    # and under a full suite's load the box it found can be gone by the read, which then returns ''.
    spin = "() => getComputedStyle(document.querySelector('#start .start-recent .start-job .start-spinner')).animationName"
    for p in served_page(browser, None, ready=START_READY):
        start = p.locator("#start")
        start.get_by_role("button", name="Open Opening case").first.click()
        box = start.locator(".start-recent .start-job")
        box.get_by_text("Opening Opening case: upgrading the case format, reloading 67,858 Suricata events, 2 of 5...").wait_for()
        assert p.evaluate(spin) == "start-spin"
        assert all(b.is_disabled() for b in start.get_by_role("button", name="Open Opening case").all())
        assert start.get_by_role("button", name="Open", exact=True).is_disabled()
        p.emulate_media(reduced_motion="reduce")
        assert p.evaluate(spin) == "none"
        gate.set()
        p.wait_for_function("() => location.pathname === '/'")
        p.wait_for_function("() => window.__ready === true && window.__app.S.data !== null")


def test_an_open_that_fails_says_why_in_its_box_and_stays_on_the_start_page(browser, remembered, monkeypatch):  # noqa: F811
    """The job's error shows in the box, where the analyst clicked, and the page does not leave."""
    def refuse(self, case, report=None):
        report("Upgrading the case format: checking the output of the runs", 1, 2)
        raise CaseError("The upgrade cannot go on: a run's output changed.")

    monkeypatch.setattr(Hub, "open", refuse)
    for p in served_page(browser, None, ready=START_READY):
        p.locator("#start").get_by_role("button", name="Open Opening case").first.click()
        box = p.locator("#start .start-recent .start-job.failed")
        box.get_by_text("Opening Opening case failed: The upgrade cannot go on: a run's output changed.").wait_for()
        assert box.locator(".start-spinner").count() == 0
        assert p.locator("#status").inner_text() == "Stopped. See the message under Recent cases."
        assert p.locator("#start").get_by_role("button", name="Open Opening case").first.is_enabled()


def test_the_search_heading_and_buttons_stay_at_the_top_of_the_panel_while_the_list_scrolls(browser, synthetic_case):  # noqa: F811
    """The heading, the count line, and the buttons are fixed over the rows, with the Mark header under them, so the mark
    buttons are in reach from the last row; a pivot's list shares the rule. The Whole word tick is in the fixed head,
    first, so it stays in reach too."""
    for p in served_page(browser, synthetic_case):
        p.evaluate("() => { document.getElementById('details').style.flex = '0 0 200px'; }")   # fewer rows fit than there are
        p.locator("#search").fill("logon code:4624")
        p.locator("#search").press("Enter")
        p.wait_for_selector("#details[data-page='search'] li.rel-row")
        assert p.locator("#details li.rel-row").count() > 3
        p.locator("#detailsBody").evaluate("(n) => { n.scrollTop = n.scrollHeight; }")   # the one scroller
        assert p.locator("#detailsBody").evaluate("(n) => n.scrollTop") > 0
        panel = p.locator("#detailsBody").bounding_box()
        for sel in ("label.whole-word", ".actions strong", "button:text-is('Select all')", "button:text-is('Mark Malicious')"):
            box = p.locator(f"#details .sticky-head {sel}").first.bounding_box()
            assert panel["y"] <= box["y"] and box["y"] + box["height"] <= panel["y"] + panel["height"], sel
        header, head = p.locator("#details li.rel-head").bounding_box(), p.locator("#details .sticky-head").bounding_box()
        assert panel["y"] <= header["y"] and header["y"] + header["height"] <= panel["y"] + panel["height"]   # Mark too
        assert abs(header["y"] - (head["y"] + head["height"])) <= 2   # and it sits under the head
        assert p.locator("#detailsBand .title").inner_text() == "Search: logon code:4624"   # the band names it, not the head
        assert p.locator("#details .sticky-head").evaluate("(n) => getComputedStyle(n).backgroundColor") != "rgba(0, 0, 0, 0)"
        # A pivot's list: the same class, sticky inside its own scrolling box
        p.locator("#tabTimeline").click()
        point = event_point(p, "4624")
        p.evaluate("(uid) => window.__app.select(uid, false)", point["uid"])
        p.locator('#details .pv[data-pivot="account"] button.pv-go').click()
        p.wait_for_selector("#relatedList .sticky-head")
        assert p.locator("#relatedList .sticky-head").evaluate("(n) => getComputedStyle(n).position") == "sticky"


def test_the_audit_trail_is_a_tab_after_findings_and_the_case_menu_opens_the_same_tab(browser, synthetic_case):  # noqa: F811
    """Audit trail follows Findings in the path and opens the audit page; the Case menu's entry opens the same tab; the
    Timeline step takes the panel off it."""
    for p in served_page(browser, synthetic_case, tab="overview", setup=no_tool_scan):
        assert p.locator("#path button").all_inner_texts()[-2:] == ["Findings", "Audit trail"]
        p.locator("#tabAudit").click()
        p.wait_for_selector("#details[data-page='audit']")
        assert current(p) == "Audit trail" and p.locator("#overview").is_hidden()
        p.locator("#tabTimeline").click()
        p.wait_for_selector("#details[data-page='hint']")
        assert current(p) == "Timeline"
        case_menu(p, "auditButton")
        p.wait_for_selector("#details[data-page='audit']")
        assert current(p) == "Audit trail" and p.locator("#caseMenu").is_hidden()


def test_a_search_marks_the_rows_the_view_hides_says_which_part_hides_them_and_shows_them(browser, synthetic_case):  # noqa: F811
    """With the Chain preset on and nothing marked, every match is hidden. Each row says so, the line names the View's
    terms, and the button adds this search to the View, so its matches show and the rows lose the mark."""
    for p in served_page(browser, synthetic_case):
        p.locator("#viewButton").click()
        p.locator("#viewPanel").get_by_role("button", name="Chain", exact=True).click()
        p.wait_for_function("() => window.__app.S.viewSpec !== null && window.__app.S.filterId !== null")
        p.locator("#search").fill("code:4624")
        p.locator("#search").press("Enter")
        p.wait_for_selector("#details[data-page='search'] li.rel-row")
        total = p.locator("#details li.rel-row").count()
        assert total and p.locator("#details li.rel-row .tag", has_text="hidden by the View").count() == total
        assert p.locator("#searchHidden").inner_text() == f"{total} listed are hidden by the View"
        assert p.locator("#searchHiddenWhy").inner_text().startswith(
            'The View shows only events marked Malicious or Suspicious. The rows marked "hidden by the View" meet none of that.')
        p.locator("#searchShowHidden").click()
        p.wait_for_function("() => document.getElementById('searchHidden').textContent === '0 listed are hidden by the View'")
        assert p.locator("#details li.rel-row .tag", has_text="hidden").count() == 0
        assert p.locator("#searchShowHidden").count() == 0
        assert p.evaluate("window.__app.S.viewSpec.values.map((v) => Object.keys(v).join())") == ["search"]
        p.wait_for_function("() => window.__app.S.data.events.length > 0")


def test_an_overview_count_that_opens_the_timeline_also_lists_its_events_to_mark(browser, overview_case):  # noqa: F811
    """DC01's pending count opens the timeline on its three events with a pending suggestion and lists them in the Details
    panel under what was clicked; ticking one and marking it takes it out of the set, and a mark count and a host's event
    count list theirs too."""
    app, _ = app_with_work(overview_case)
    app.con.close()
    for p in served_page(browser, overview_case, setup=no_tool_scan):
        p.locator("#tabOverview").click()
        p.locator("#ovByHost tr[data-host='DC01'] td.num").nth(1).get_by_role("button").click()
        p.wait_for_selector("#details[data-page='opened'] li.rel-row")
        assert current(p) == "Timeline"
        assert p.locator("#details h2").inner_text() == "DC01: events with a pending suggestion"
        assert p.locator("#details .sticky-head strong").inner_text() == "3 events"
        assert p.locator("#details li.rel-row").count() == 3
        p.locator("#details li.rel-row input").first.check()
        p.locator("#details").get_by_role("button", name="Mark 1 Suspicious").click()
        p.wait_for_function("() => document.querySelectorAll('#details li.rel-row').length === 2")
        assert p.locator("#details .sticky-head strong").inner_text() == "2 events"
        p.locator("#tabOverview").click()
        p.locator("#ovProgress .ov-legend").get_by_role("button").nth(1).click()   # the Suspicious count
        p.wait_for_selector("#details h2:text-is('Events marked Suspicious')")
        assert p.locator("#details li.rel-row").count() == 2
        p.locator("#tabOverview").click()
        p.locator("#ovHosts tr[data-host='DESKTOP'] td.num").get_by_role("button").click()
        p.wait_for_selector("#details h2:text-is('DESKTOP: all events')")
        assert p.locator("#details li.rel-row").count() > 0
