"""The Event page's next pivots, trail, and provenance in a real browser. They drive the installed Microsoft
Edge through Playwright against the synthetic case, as test_browser_smoke does."""

import hashlib
import json
import re

import pytest
from conftest import SEC, T0, WS_LOG, logon
from test_browser_smoke import browser, case_menu, point_of, served_page, to_timeline  # noqa: F401
from test_pivots import (  # noqa: F401
    RDP,
    ids_event,
    load_events,
    named,
    pcase,
    pcase_events,
    security_event,
    system_event,
    uid_of,
)

from glessner import pivots, queries
from glessner.events import connect
from glessner.intake import intake, verify
from glessner.journal import JOURNAL_FILE

pytestmark = pytest.mark.browser
COUNTED = "() => [...document.querySelectorAll('#details .pv-n')].every((n) => !n.textContent.includes('counting'))"
INSTALL = "event_code = '7045' AND file_path LIKE '%wu.exe'"
SECURITY = "DC01/Windows/System32/winevt/Logs/Security.evtx"


def uid(case, where):
    con = connect(case.db_path, read_only=True)
    try:
        return uid_of(con, where)
    finally:
        con.close()


def select(page, event):
    page.evaluate("(uid) => window.__app.select(uid, false)", event)
    page.wait_for_function("(uid) => window.__app.S.focusEvent && window.__app.S.focusEvent.uid === uid", arg=event)
    page.wait_for_selector("#details[data-page='event'] .pv")
    page.wait_for_function(COUNTED)


def pv(page, pivot):
    """The next-pivots row of a pivot."""
    return page.locator(f'#details .pv[data-pivot="{pivot}"]')


def rows(page):
    """Each next-pivot row as (pivot, label, value, count text)."""
    return [(r.get_attribute("data-pivot"), r.locator("button.pv-go").inner_text(),
             r.locator(".pv-value").inner_text() if r.locator(".pv-value").count() else "", r.locator(".pv-n").inner_text())
            for r in page.locator("#details .pv").all()]


def journal(case):
    return [json.loads(line) for line in (case.folder / JOURNAL_FILE).read_text(encoding="utf-8").splitlines()]


def test_a_service_install_shows_its_ranked_pivots_and_the_counts_follow(browser, pcase):  # noqa: F811
    """The order for a service install: the file, the window around it, the service name, the account, and the file's
    name. Each row has its value, a reason, and the exact count the click then lists; the pivots the event can't take go on
    one line."""
    install = uid(pcase, INSTALL)
    for page in served_page(browser, pcase):
        select(page, install)
        assert [r[:3] for r in rows(page)] == [
            ("file", "Same file (the service binary)", "C:\\Users\\Public\\wu.exe"), ("window", "Same host within ±", ""),
            ("service_name", "Same service name", "Windows Update Svc"),
            ("account", "Same account (from the System element)", "C137\\Administrator"),
            ("file_name", "Same file name", "wu.exe")]
        assert page.locator("#details .pivots h3").inner_text() == "NEXT PIVOTS FOR 7045 AND 4697, SERVICE INSTALLED"
        counts = {r[0]: r[3] for r in rows(page)}
        assert counts["file"] == "1 event" and counts["service_name"] == "6 events" and counts["account"] == "8 events"
        assert counts["file_name"] == "1 event"
        assert counts["window"].endswith("events") and pv(page, "window").locator("input.pv-seconds").input_value() == "600"
        assert "inference" in pv(page, "window").locator(".pv-basis").inner_text()
        assert pv(page, "window").locator(".pv-basis").get_attribute("title").startswith(
            "The guidance table infers this size from ATT&CK's examples")
        assert pv(page, "service_name").locator(".pv-reason").inner_text().startswith("The same service on other hosts")
        # One line for what the event can't take, each with its reason; the unranked offered pivots follow with no count
        not_offered = page.locator("#details .pv-not").inner_text()
        assert not_offered.startswith("Not offered for this event: Same logon session: A 7045 records no logon ID.")
        assert "Same IP at either end: A service install records no address." in not_offered
        # A pivot that finds only the event says why, in the pivot table's words
        assert pv(page, "file").locator(".pv-empty").inner_text().startswith("No other source names this path.")
        # Each count is the click's total: the service name's 6 events, from the table's alias pairs
        pv(page, "service_name").locator("button.pv-go").click()
        page.locator("#relatedList strong", has_text="6 events with the same service name").wait_for()
        assert len(page.locator("#relatedList li.rel-row").all()) == 6


def test_the_window_row_names_its_top_sources_and_each_one_opens_the_window_narrowed_to_it(browser, pcase):  # noqa: F811
    """The window row always shows its top sources; a click on one lists that source across the window, and the
    heading says what it was narrowed to."""
    install = uid(pcase, INSTALL)
    for page in served_page(browser, pcase):
        select(page, install)
        window = pv(page, "window")
        total = int(window.locator(".pv-n").inner_text().split()[0])
        labels = window.locator("button.pv-source").all_inner_texts()
        assert labels[:4] == ["4625 type 3 4", "4624 type 3 3", "TaskScheduler 140 2", "7036 2"]
        assert sum(int(t.rsplit(" ", 1)[1]) for t in labels) <= total
        assert "more sources" in window.locator(".pv-sources").inner_text()
        window.locator("button.pv-source", has_text="7036").click()
        page.locator("#relatedList strong", has_text="Same host within ±600 s, only 7036: 2 events").wait_for()
        listed = [(r.locator(".rel-host").inner_text(), r.locator(".rel-text").inner_text())   # host and event cells
                  for r in page.locator("#relatedList li.rel-row").all()]
        assert listed == [("DC01", "7036 system")] * 2
        assert page.evaluate("window.__app.S.pivotResult.res.source") == ["evtx", "System", "7036"]
        assert page.evaluate("window.__app.S.trail.map((s) => s.label)")[-1] == "Same host within ±600 s, only 7036"


def test_a_window_edit_is_kept_for_that_kind_through_the_settings_and_a_reset_goes_back(browser, pcase):  # noqa: F811
    """The size is editable in its row, saved as the case's pivot_windows setting, and a kind keeps it for the next
    event of its kind."""
    install, logon10 = uid(pcase, INSTALL), uid(pcase, RDP)
    for page in served_page(browser, pcase):
        select(page, install)
        box = pv(page, "window").locator("input.pv-seconds")
        box.fill("8")
        box.press("Enter")
        page.wait_for_function("() => (window.__app.S.meta.pivot_windows || {}).service_install === 8")
        page.wait_for_function(COUNTED)
        entry = journal(pcase)[-1]
        assert (entry["action"], entry["name"], entry["value"]) == ("case_setting", "pivot_windows", {"service_install": 8})
        assert pv(page, "window").locator(".pv-n").inner_text() == "5 events"   # within 8 s of the install
        select(page, logon10)
        select(page, install)
        assert pv(page, "window").locator("input.pv-seconds").input_value() == "8"
        pv(page, "window").get_by_role("button", name="reset").click()
        page.wait_for_function(
            "() => document.querySelector('#details .pv[data-pivot=\"window\"] input.pv-seconds').value === '600'")
        # The box shows 600 as soon as the button is clicked; the page has the saved size back only when the save's answer
        # arrives, and a box refused after that goes back to the saved size.
        page.wait_for_function("() => !('service_install' in (window.__app.S.meta.pivot_windows || {}))")
        assert journal(pcase)[-1]["value"] == {}
        # An out of range size is refused in the page, and the box goes back
        box.fill("5000")
        box.press("Enter")
        page.wait_for_function("() => document.getElementById('status').textContent.includes('1 to 3,600')")
        assert box.input_value() == "600"


def test_a_row_over_the_lists_limit_is_flagged_broad_and_shows_its_sources(browser, pcase, monkeypatch):  # noqa: F811
    """A counted row over the limit is broad, with its count, and its sources follow in a second pass; a row under it
    shows neither."""
    monkeypatch.setattr(queries, "RELATED_LIMIT", 2)
    monkeypatch.setattr(pivots, "RELATED_LIMIT", 2)
    install = uid(pcase, INSTALL)
    for page in served_page(browser, pcase):
        select(page, install)
        row = pv(page, "service_name")
        row.locator(".pv-broad").wait_for()
        assert row.locator(".pv-broad").inner_text() == "Broad: 6 events. The list shows the 500 nearest in time."
        page.wait_for_function("() => document.querySelector("
                               "'#details .pv[data-pivot=\"service_name\"] .pv-sources').textContent.includes('7036')")
        assert "7040 1" in row.locator(".pv-sources").inner_text()
        assert pv(page, "file").locator(".pv-broad").count() == 0   # one event: not broad
        # A window longer than the list says how far in time the nearest ones reach
        pv(page, "window").locator("button.pv-go").click()
        heading = page.locator("#relatedList .actions strong")
        heading.wait_for()
        assert re.fullmatch(r"Same host within ±600 s: the 2 nearest of [\d,]+ events", heading.inner_text())
        assert re.search(r"reaching ±(\d+ [a-z]+ ?)+ of this event", page.locator("#relatedList .pv-reach").inner_text())


def test_a_value_on_the_studys_lists_is_broad_with_its_reason_before_any_count(browser, pcase):  # noqa: F811
    system = logon(T0 + 70 * SEC, 9400, WS_LOG, code="4672", logon_id="0x3e7", user="SYSTEM", domain="NT AUTHORITY",
                   computer="DESKTOP-SDN1RPT.C137.local")
    load_events(pcase, [system], "DESKTOP", run="p30")
    special = uid(pcase, "event_code = '4672' AND logon_id = '0x3e7'")
    for page in served_page(browser, pcase):
        select(page, special)
        assert pv(page, "session").locator(".pv-broad").inner_text().startswith(
            "Broad: this is a system session (SYSTEM, NETWORK SERVICE, LOCAL SERVICE, or ANONYMOUS LOGON).")
        assert pv(page, "account").locator(".pv-broad").inner_text() == (
            "Broad: a Windows service account. It acts on every host.")


def test_same_account_counts_another_spelling_of_the_account_without_a_caveat(browser, pcase):  # noqa: F811
    """Same account matches on the account key, so a 4769 that writes the account as Administrator@C137.LOCAL joins
    the count once loaded, and the row shows no caveat about other spellings."""
    rdp = uid(pcase, RDP)
    for page in served_page(browser, pcase):
        select(page, rdp)
        assert pv(page, "account").locator(".pv-caveat").inner_text() == ""
        before = int(pv(page, "account").locator(".pv-n").inner_text().split()[0])
    kerberos = logon(T0 + 300 * SEC, 9500, WS_LOG, code="4769", user="Administrator@C137.LOCAL", domain="",
                     computer="DESKTOP-SDN1RPT.C137.local")
    load_events(pcase, [kerberos], "DESKTOP", run="p31")
    for page in served_page(browser, pcase):
        select(page, rdp)
        assert pv(page, "account").locator(".pv-caveat").inner_text() == ""
        assert pv(page, "account").locator(".pv-n").inner_text() == f"{before + 1} events"


FIRST = "4624 type 10 on DC01 from 194.61.24.102"
STEP_TEXTS = "() => window.__app.S.trail.map((s) => s.label)"


def walk(page, rdp):
    """Four steps from the RDP logon: its Same logon session list, the 4672 opened from it, and that event's window."""
    select(page, rdp)
    pv(page, "session").locator("button.pv-go").click()
    page.locator("#relatedList strong", has_text="with the same host and logon ID").wait_for()
    page.locator("#relatedList li.rel-row", has_text="4672").click()
    page.wait_for_function("() => window.__app.S.trail.length === 3")
    pv(page, "window").locator("button.pv-go").click()
    page.wait_for_function("() => window.__app.S.trail.length === 4")
    page.locator("#relatedList strong").wait_for()


def at(page):
    return page.evaluate("window.__app.S.trailAt")


def dim(page):
    return page.locator("#details nav.trail button.dim")


def dimmed(page, n):
    """Wait until the band shows n dimmed steps: it redraws when the page for a step has loaded."""
    page.wait_for_function("(n) => document.querySelectorAll('#details nav.trail button.dim').length === n", arg=n)


def test_the_trail_records_each_pivot_and_event(browser, pcase):  # noqa: F811
    """A bar over the page of every pivot taken and event opened from its list, the step on screen current."""
    rdp, explicit = uid(pcase, RDP), uid(pcase, "event_code = '4648'")
    for page in served_page(browser, pcase):
        select(page, rdp)
        assert page.locator("#details nav.trail").count() == 0   # nothing taken yet
        pv(page, "session").locator("button.pv-go").click()
        page.locator("#relatedList strong", has_text="with the same host and logon ID").wait_for()
        assert page.evaluate(STEP_TEXTS) == [FIRST, "Same logon session"]
        # The bar shows the step at once, and the list is in view without a scroll
        assert page.locator("#details nav.trail .here").inner_text() == "Same logon session (2)"
        assert page.evaluate("""() => { const r = document.querySelector('#relatedList strong').getBoundingClientRect();
          const w = document.querySelector('#details .ev-work').getBoundingClientRect();
          return r.top >= w.top - 1 && r.bottom <= w.bottom + 1; }""")
        page.locator("#relatedList li.rel-row", has_text="4672").click()
        page.wait_for_function("() => window.__app.S.trail.length === 3")
        trail = page.locator("#details nav.trail")
        trail.wait_for()
        assert trail.locator(".here").inner_text() == "4672 on DC01"
        assert trail.locator("button.linklike").all_inner_texts() == [FIRST, "Same logon session (2)"]
        assert dim(page).count() == 0 and at(page) == 2
        # Taking another pivot from the new event adds a step
        pv(page, "window").locator("button.pv-go").click()
        page.wait_for_function("() => window.__app.S.trail.length === 4")
        page.locator("#relatedList strong").wait_for()
        bar = page.locator("#details nav.trail")
        assert bar.locator("button.linklike").count() == 3 and bar.locator(".here").inner_text().startswith("Same host within")
        assert at(page) == 3
        # A new start, a click on the timeline, begins a new trail
        select(page, explicit)
        assert page.evaluate("window.__app.S.trail.length") == 1 and page.locator("#details nav.trail").count() == 0
        assert at(page) == 0


def test_a_pivot_list_reports_itself_to_the_status_line_with_the_servers_time(browser, pcase):  # noqa: F811
    """A pivot's list is the status line's last action, with the server's time. The list drawn again after a mark
    keeps the mark's line."""
    rdp = uid(pcase, RDP)
    for page in served_page(browser, pcase):
        select(page, rdp)
        pv(page, "session").locator("button.pv-go").click()
        page.locator("#relatedList strong", has_text="with the same host and logon ID").wait_for()
        said = page.locator("#status").inner_text().split(" | ")[0]
        assert re.fullmatch(r"Same logon session: 2 events · [\d.]+ ms", said), said
        page.locator("#relatedList li.rel-row input").first.check()
        page.locator("#relatedList").get_by_role("button", name="Mark 1 Suspicious").click()
        page.wait_for_function("() => document.querySelectorAll('#relatedList li.rel-row .badge.s').length === 1")
        assert page.locator("#status").inner_text().startswith("Marked one event Suspicious · ")


def test_going_back_keeps_the_later_steps(browser, pcase):  # noqa: F811
    """A click on an earlier step keeps the later ones, dimmed but still links, and the step on screen is current. A
    click on a dimmed step goes forward again, a mark leaves the trail alone, an event or pivot the trail already has next
    only moves forward, and a different pivot replaces the later steps. A typed search ends the trail."""
    rdp, other = uid(pcase, RDP), uid(pcase, "event_code = '4648'")
    for page in served_page(browser, pcase):
        walk(page, rdp)
        page.locator("#details nav.trail").get_by_role("button", name="Same logon session (2)").click()
        page.locator("#relatedList strong", has_text="2 events with the same host and logon ID").wait_for()
        assert page.evaluate("window.__app.S.trail.length") == 4 and at(page) == 1
        assert page.locator("#details nav.trail .here").inner_text() == "Same logon session (2)"
        assert page.locator("#details nav.trail [aria-current='step']").count() == 1
        texts = dim(page).all_inner_texts()
        assert len(texts) == 2 and texts[0] == "4672 on DC01" and texts[1].startswith("Same host within ±300 s (")
        assert dim(page).first.get_attribute("title") == (
            "A step you went back from; it stays until a new pivot replaces it. Click to return to it.")
        assert page.locator("#details nav.trail button.linklike:not(.dim)").all_inner_texts() == [FIRST]
        # A mark while back keeps the later steps (the page draws the same event again)
        page.locator("#details").get_by_role("button", name="Suspicious", exact=True).first.click()
        # The verdict line names who marked it; the status line is not waited on, since the timeline's own window move
        # can replace "Marked one event Suspicious" before a slow page polls it
        page.locator("#details").get_by_text(re.compile(r"^by \w+, ")).first.wait_for()
        assert page.evaluate("window.__app.S.trail.length") == 4 and at(page) == 1 and dim(page).count() == 2
        # A dimmed step opens its page and moves the step on screen
        dim(page).first.click()
        page.wait_for_function("() => window.__app.S.trailAt === 2")
        page.locator("#details nav.trail .here", has_text="4672 on DC01").wait_for()
        assert page.evaluate("window.__app.S.trail.length") == 4 and dim(page).count() == 1
        # An event from a list that the trail has next only moves forward
        page.locator("#details nav.trail").get_by_role("button", name="Same logon session (2)").click()
        page.wait_for_function("() => window.__app.S.trailAt === 1")
        page.locator("#relatedList li.rel-row", has_text="4672").click()
        page.wait_for_function("() => window.__app.S.trailAt === 2")
        page.locator("#details nav.trail .here", has_text="4672 on DC01").wait_for()
        assert page.evaluate("window.__app.S.trail.length") == 4 and dim(page).count() == 1
        # A different pivot cuts the later steps
        page.locator("#details nav.trail").get_by_role("button", name="Same logon session (2)").click()
        page.wait_for_function("() => window.__app.S.trailAt === 1")
        pv(page, "account").locator("button.pv-go").click()
        page.wait_for_function("() => window.__app.S.trail.length === 3 && window.__app.S.trailAt === 2")
        assert page.evaluate(STEP_TEXTS)[:2] == [FIRST, "Same logon session"] and dim(page).count() == 0
        # A pivot equal to the next step advances to it, with the later steps still dimmed
        page.locator("#details nav.trail").get_by_role("button", name=FIRST, exact=True).click()
        page.wait_for_function("() => window.__app.S.trailAt === 0 && !!document.querySelector('#details .pv')")
        dimmed(page, 2)
        pv(page, "session").locator("button.pv-go").click()
        page.wait_for_function("() => window.__app.S.trailAt === 1")
        page.locator("#relatedList strong", has_text="with the same host and logon ID").wait_for()
        assert page.evaluate("window.__app.S.trail.length") == 3 and dim(page).count() == 1
        # So does another event from the list: a window's events are not the one the trail has next
        select(page, other)
        select(page, rdp)   # a new start
        pv(page, "window").locator("button.pv-go").click()
        page.wait_for_selector("#relatedList li.rel-row")
        page.locator("#relatedList li.rel-row").nth(1).click()
        page.wait_for_function("() => window.__app.S.trail.length === 3 && window.__app.S.trailAt === 2")
        first_event = page.evaluate("window.__app.S.focus")
        page.locator("#details nav.trail").get_by_role("button", name=re.compile("^Same host within")).click()
        page.wait_for_function("() => window.__app.S.trailAt === 1")
        dimmed(page, 1)
        page.locator("#relatedList li.rel-row").nth(2).click()
        page.wait_for_function("(uid) => window.__app.S.focus !== uid && window.__app.S.trailAt === 2", arg=first_event)
        assert page.evaluate("window.__app.S.trail.length") == 3
        dimmed(page, 0)
        # A typed search ends the trail, and an event opened from its results starts another
        page.locator("#search").fill("code:4672")
        page.locator("#search").press("Enter")
        page.wait_for_selector("#details[data-page='search'] li.rel-row")
        assert page.evaluate("[window.__app.S.trail.length, window.__app.S.trailAt]") == [0, -1]
        page.locator("#details li.rel-row").first.click()
        page.wait_for_selector("#details[data-page='event'] .ev-ident")
        assert page.evaluate("[window.__app.S.trail.length, window.__app.S.trailAt]") == [1, 0]
        pv(page, "window").locator("button.pv-go").click()
        page.wait_for_selector("#details nav.trail")
        assert page.locator("#details nav.trail button.trail-save").inner_text() == "Save trail as a note on the 4672 (start)"


def test_a_click_on_the_list_kept_after_going_back_continues_the_trail(browser, pcase):  # noqa: F811
    """Going back to the event a pivot was taken from keeps that pivot's list on screen, and a click on one of its
    rows continues the trail from the pivot's step, as the click on the same list does before going back, rather than
    starting a new trail that throws every step away."""
    rdp = uid(pcase, RDP)
    for page in served_page(browser, pcase):
        select(page, rdp)
        pv(page, "session").locator("button.pv-go").click()
        page.locator("#relatedList strong", has_text="with the same host and logon ID").wait_for()
        page.locator("#relatedList li.rel-row", has_text="4672").click()
        page.wait_for_function("() => window.__app.S.trail.length === 3")
        page.locator("#details nav.trail").get_by_role("button", name=FIRST, exact=True).click()
        page.wait_for_function("() => window.__app.S.trailAt === 0")
        page.locator("#relatedList strong", has_text="with the same host and logon ID").wait_for()   # the list taken from it
        dimmed(page, 2)
        page.locator("#relatedList li.rel-row", has_text="4672").click()
        page.wait_for_function("() => window.__app.S.trailAt === 2")
        assert page.evaluate("window.__app.S.trail.length") == 3 and page.evaluate(STEP_TEXTS) == [
            FIRST, "Same logon session", "4672 on DC01"]
        dimmed(page, 0)


def test_back_in_the_band_keeps_the_trail(browser, pcase):  # noqa: F811
    """The band's Back link goes back to the step the trail holds for that event, the later steps dimmed, rather than
    reopening the Event page and beginning a new trail, since going back keeps the steps."""
    rdp = uid(pcase, RDP)
    for page in served_page(browser, pcase):
        walk(page, rdp)
        assert at(page) == 3
        page.locator("#detailsBand button.back").click()
        page.wait_for_function("() => window.__app.S.trailAt === 0")
        page.locator("#details[data-page='event'] .ev-ident .host").wait_for()
        assert page.evaluate("window.__app.S.trail.length") == 4
        dimmed(page, 3)
        assert page.locator("#details nav.trail .here").inner_text() == FIRST


def test_back_from_a_page_that_is_not_a_step_leaves_the_pivot_on_screen_current(browser, pcase):  # noqa: F811
    """Back from the audit trail to the Event page whose pivot list was the step on screen shows that list again, and
    the pivot stays current: the band doesn't dim it as a step gone back from, since nothing was gone back from."""
    rdp = uid(pcase, RDP)
    for page in served_page(browser, pcase):
        select(page, rdp)
        pv(page, "session").locator("button.pv-go").click()
        page.locator("#relatedList strong", has_text="with the same host and logon ID").wait_for()
        assert at(page) == 1
        case_menu(page, "auditButton")
        page.wait_for_function("() => document.querySelector('#detailsBand .title')?.textContent === 'Audit trail'")
        page.locator("#detailsBand button.back").click()
        page.locator("#relatedList strong", has_text="with the same host and logon ID").wait_for()
        assert at(page) == 1 and dim(page).count() == 0
        assert page.locator("#details nav.trail .here").inner_text() == "Same logon session (2)"


def test_the_trail_note_goes_on_the_start_event(browser, pcase):  # noqa: F811
    """Save trail as a note names the event the trail started from, journals every step, dimmed ones included, as a
    note on that event, and leaves the page on the event on screen."""
    rdp = uid(pcase, RDP)
    for page in served_page(browser, pcase):
        walk(page, rdp)
        page.locator("#details nav.trail").get_by_role("button", name="4672 on DC01").click()
        page.wait_for_function("() => window.__app.S.trailAt === 2")
        # The pan from walk's click on the 4672 row is a last action of its own, "Window moved". Under load its data can land
        # after the save and replace the save's line (seen twice in full suites), so the save waits for it.
        page.wait_for_function("() => window.__app.S.anim === null && !window.__app.S.windowPending")
        shown = page.evaluate("window.__app.S.focus")
        save = page.locator("#details nav.trail button.trail-save")
        assert save.inner_text() == "Save trail as a note on the 4624 (start)"
        assert save.get_attribute("title") == (
            f"Journals the 4 steps as a note on the event the trail started from, {FIRST}, not the one on screen")
        save.click()
        page.wait_for_function("() => document.getElementById('status').textContent.startsWith('Saved the trail as note #')")
        said = page.locator("#status").inner_text().split(" | ")[0]
        assert re.fullmatch(r"Saved the trail as note #\d+ on the 4624 · [\d.]+ ms", said)
        note = journal(pcase)[-1]
        assert (note["action"], note["target"]) == ("note", rdp)
        assert note["text"].startswith(f"Trail: {FIRST} > Same logon session (2) > 4672 on DC01 > Same host within ±300 s (")
        # The page still shows the 4672, and the start event lists the note
        assert page.evaluate("window.__app.S.focus") == shown and page.locator("#details .ev-ident .host").inner_text() == "DC01"
        assert page.locator("#details nav.trail .here").inner_text() == "4672 on DC01"
        page.locator("#details nav.trail").get_by_role("button", name=FIRST, exact=True).click()
        page.wait_for_selector("#details ul.notes li")
        assert note["text"] in page.locator("#details ul.notes li").inner_text()
        save = page.locator("#details nav.trail button.trail-save")
        assert save.get_attribute("title").endswith(f"{FIRST}, which is on screen")
        # A trail that a pivot began names the event the pivot was taken from
        page.evaluate("() => { window.__app.S.trail = []; window.__app.S.trailAt = -1; }")
        pv(page, "window").locator("button.pv-go").click()
        page.wait_for_function("() => window.__app.S.trail.length === 1")
        pv(page, "session").locator("button.pv-go").click()
        page.wait_for_function("() => window.__app.S.trail.length === 2")
        assert page.locator("#details nav.trail button.trail-save").inner_text() == "Save trail as a note on the 4624 (start)"


def test_show_reasons_folds_and_remembers(browser, pcase, monkeypatch):  # noqa: F811
    """The Show reasons tick folds every row's reason, flags, and caveat at once and is remembered in this
    browser; a folded row keeps the words Broad and caveat beside its title, from the list it is on and from its count; a row's
    arrow opens that row alone, through a mark's redraw and until another event's panel draws; a caveat begins "Caveat:"."""
    monkeypatch.setattr(queries, "RELATED_LIMIT", 2)
    monkeypatch.setattr(pivots, "RELATED_LIMIT", 2)
    system = logon(T0 + 70 * SEC, 9400, WS_LOG, code="4672", logon_id="0x3e7", user="SYSTEM", domain="NT AUTHORITY",
                   computer="DESKTOP-SDN1RPT.C137.local")
    load_events(pcase, [system], "DESKTOP", run="p30")
    load_events(pcase, [ids_event(T0 + 200 * SEC, 5001, "10.42.85.10", "203.0.113.50")], "network", run="p41")
    special, install = uid(pcase, "event_code = '4672' AND logon_id = '0x3e7'"), uid(pcase, INSTALL)
    alert = uid(pcase, "source_record = '5001'")
    for page in served_page(browser, pcase):
        select(page, special)
        tick = page.locator("#details .pv-h input[type=checkbox]")
        reasons, shorts = page.locator("#details .pv-reason"), page.locator("#details .pv-short")
        account = pv(page, "account")
        arrow = account.locator("button.pv-tw")
        # A fresh profile shows every reason, and the arrows say so
        assert tick.is_checked() and tick.locator("xpath=..").inner_text().strip() == "Show reasons"
        assert reasons.count() >= 3 and all(r.is_visible() for r in reasons.all())
        assert not any(s.is_visible() for s in shorts.all())
        assert arrow.inner_text() == "▾" and arrow.get_attribute("aria-expanded") == "true"
        assert account.locator(".pv-caveat").inner_text() == "" and account.locator(".pv-flags").is_visible()
        select(page, alert)
        window = pv(page, "window")
        assert window.locator(".pv-caveat").inner_text().startswith("Caveat: The network lane only")
        assert window.locator(".pv-caveat").is_visible() and not window.locator(".pv-short").is_visible()
        # Unticked, the reasons, flags, and caveats go, and Broad and caveat stay as words
        tick.uncheck()
        assert not any(r.is_visible() for r in reasons.all())
        assert not window.locator(".pv-caveat").is_visible() and window.locator(".pv-short .cv").inner_text() == "caveat"
        assert window.locator(".pv-short").is_visible()
        select(page, special)
        assert account.locator(".pv-short .br").inner_text() == "Broad" and account.locator(".pv-short .cv").count() == 0
        assert pv(page, "session").locator(".pv-short .br").inner_text() == "Broad"
        assert account.locator(".pv-short").is_visible() and not account.locator(".pv-flags").is_visible()
        assert arrow.inner_text() == "▸" and arrow.get_attribute("aria-expanded") == "false"
        assert arrow.get_attribute("title") == "Why this pivot, and its caveat"
        assert page.evaluate("localStorage.getItem('glessner.showReasons')") == "0"
        # A row that is broad only by its count shows the word once the count is in; its sources and its empty note stay
        select(page, install)
        service = pv(page, "service_name")
        service.locator(".pv-short .br").wait_for()
        assert not service.locator(".pv-broad").is_visible() and not service.locator(".pv-reason").is_visible()
        pv(page, "window").locator(".pv-short .br").wait_for()   # the window row's own text counts too
        service.locator(".pv-sources button").first.wait_for()
        assert service.locator(".pv-sources").is_visible() and pv(page, "file").locator(".pv-empty").is_visible()
        # The choice outlasts a reload
        page.reload()
        page.wait_for_function("() => window.__ready === true && window.__app.S.data !== null")
        to_timeline(page)
        select(page, special)
        assert not tick.is_checked() and not any(r.is_visible() for r in reasons.all())
        # A row's arrow opens that row alone, through a mark's redraw, until another event's panel draws
        arrow.click()
        assert account.locator(".pv-reason").is_visible() and account.locator(".pv-flags").is_visible()
        assert not account.locator(".pv-short").is_visible() and not pv(page, "session").locator(".pv-reason").is_visible()
        assert arrow.inner_text() == "▾" and arrow.get_attribute("aria-expanded") == "true"
        assert arrow.get_attribute("title") == "Fold the reason"
        page.locator("#details").get_by_role("button", name="Suspicious", exact=True).first.click()
        page.wait_for_selector("#details .ev-head.suspicious")
        page.wait_for_function(COUNTED)
        assert account.locator(".pv-reason").is_visible() and not pv(page, "session").locator(".pv-reason").is_visible()
        select(page, install)
        select(page, special)
        assert not account.locator(".pv-reason").is_visible()
        # The tick sets every row, so it takes the rows' own choices with it
        arrow.click()
        tick.check()
        assert all(r.is_visible() for r in reasons.all())
        tick.uncheck()
        assert not any(r.is_visible() for r in reasons.all()) and not account.locator(".pv-reason").is_visible()
    # A new profile opens with the reasons shown
    for page in served_page(browser, pcase):
        select(page, special)
        assert page.locator("#details .pv-h input[type=checkbox]").is_checked()
        assert page.evaluate("localStorage.getItem('glessner.showReasons')") is None
        assert all(r.is_visible() for r in page.locator("#details .pv-reason").all())
    # Where storage is blocked the tick still works for the page
    for page in served_page(browser, pcase):
        page.add_init_script("Object.defineProperty(window, 'localStorage', { get() { throw new Error('blocked'); } });")
        page.reload()
        page.wait_for_function("() => window.__ready === true && window.__app.S.data !== null")
        to_timeline(page)
        select(page, special)
        page.locator("#details .pv-h input[type=checkbox]").uncheck()
        assert not any(r.is_visible() for r in page.locator("#details .pv-reason").all())


def test_provenance_is_one_line_with_the_hash_against_intake_and_the_build(browser, pcase):  # noqa: F811
    (pcase.evidence / "DC01" / "Windows" / "System32" / "winevt" / "Logs").mkdir(parents=True, exist_ok=True)
    (pcase.evidence / SECURITY).write_bytes(b"security log")
    intake(pcase)
    rdp, other = uid(pcase, RDP), uid(pcase, "event_code = '4672'")
    registry = uid(pcase, "tool = 'recmd' AND registry_value = 'ComputerName'")
    for page in served_page(browser, pcase):
        select(page, rdp)
        line = page.locator("#details .prov")
        text = line.inner_text()
        assert text.startswith("Read by evtxecmd t, run r1") and f"from {SECURITY}, record 101" in text
        assert "the intake hash; nothing has re-checked the file since" in text
        assert f"shown by build {page.evaluate('window.__app.S.meta.build')}" in text
        assert line.locator("b").nth(3).get_attribute("title") == hashlib.sha256(b"security log").hexdigest()
        assert verify(pcase, [SECURITY], reason="test") == []
        select(page, other)
        select(page, rdp)
        check = line.locator(".prov-check")
        assert check.inner_text() == "matches intake" and "matches" in check.get_attribute("class")
        (pcase.evidence / SECURITY).write_bytes(b"changed")
        assert verify(pcase, [SECURITY], reason="test")
        select(page, other)
        select(page, rdp)
        assert check.inner_text() == "differs from intake (SHA-256 changed)"
    # A file intake never saw has no hash to show
    for page in served_page(browser, pcase):
        select(page, registry)
        assert "SHA-256 not in the intake manifest" in page.locator("#details .prov").inner_text()


def test_same_source_ip_and_port_lists_within_the_window_and_the_case_wide_list_is_a_click_away(browser, pcase):  # noqa: F811
    """A reused source port joins other connections, so the list is bounded to the case's window, with the case-wide
    list one click away."""
    def connection(record, at):
        e = logon(T0 + at * SEC, record, WS_LOG, ltype="3", ip="10.9.1.1", computer="DESKTOP-SDN1RPT.C137.local")
        e.source_port = "49752"
        return e
    load_events(pcase, [connection(5001, 600), connection(5002, 603), connection(5003, 4000)], "DESKTOP", run="p32")
    first = uid(pcase, "source_record = '5001'")
    for page in served_page(browser, pcase):
        select(page, first)
        row = pv(page, "connection")
        assert row.locator(".pv-value").inner_text() == "10.9.1.1:49752" and row.locator(".pv-n").inner_text() == "2 events"
        assert "within ±60 s" in row.locator(".pv-basis").inner_text()
        row.locator("button.pv-go").click()
        page.locator("#relatedList strong", has_text="2 events with the same source IP and port within 60 seconds").wait_for()
        page.locator("#relatedList").get_by_role("button", name="Show the case-wide list").click()
        page.locator("#relatedList strong", has_text="3 events with the same source IP and port, case-wide").wait_for()


def test_a_search_row_runs_the_search_and_a_row_without_its_field_says_so(browser, pcase):  # noqa: F811
    failed = uid(pcase, "event_code = '4625' AND record_id = 9200")
    reasoned = logon(T0 + 200 * SEC, 9600, WS_LOG, code="4625", user="admin", domain="", ltype="3",
                     computer="DESKTOP-SDN1RPT.C137.local", extra={"SubStatus": "0xC000006A"})
    load_events(pcase, [reasoned], "DESKTOP", run="p33")
    with_reason = uid(pcase, "event_code = '4625' AND record_id = 9600")
    for page in served_page(browser, pcase):
        select(page, failed)
        assert pv(page, "search").count() == 0
        assert "Same failure reason: this event has no SubStatus." in page.locator("#details .pv-not").inner_text()
        select(page, with_reason)
        row = pv(page, "search")
        assert row.locator("button.pv-go").inner_text() == "Same failure reason"
        assert row.locator(".pv-value").inner_text() == "code:4625 SubStatus:0xC000006A"
        assert row.locator(".pv-n").inner_text() == "1 event"
        row.locator("button.pv-go").click()
        page.wait_for_selector("#details[data-page='search'] .related li.rel-row")
        assert page.locator("#search").input_value() == "code:4625 SubStatus:0xC000006A"
        assert page.evaluate("window.__app.S.trail.map((s) => s.label)")[-1] == "Search code:4625 SubStatus:0xC000006A"


def test_a_fault_in_the_pivots_is_shown_where_they_would_be_and_the_event_still_opens(browser, pcase, monkeypatch):  # noqa: F811
    from glessner import server

    def broken(*args, **kwargs):
        raise RuntimeError("the table broke")
    monkeypatch.setattr(server, "guidance", broken)
    rdp = uid(pcase, RDP)
    for page in served_page(browser, pcase):
        page.evaluate("(uid) => window.__app.select(uid, false)", rdp)
        page.locator("#details .pivots p.muted").wait_for()
        shown = page.locator("#details .pivots p.muted").inner_text()
        assert shown == "Not available for this event: RuntimeError: the table broke"
        assert page.locator("#details .ev-ident .time").inner_text().startswith("2020-09-19 03:21:48")
        assert page.locator("#details .prov").count() == 1


# ---------- Same file name and the right-click menu's Find related ----------

FILE_NAME_WARNING = "Joins every file of this name, in any folder and on any host, whatever the file is."


def add_file_names(case):
    """Copies of the install's wu.exe in another folder and as SRUM's bare name, a service with a file of its own, and a log
    clear with the two records of wevtutil.exe the table fixes its name from."""
    load_events(case, [
        named(330, "wu-copy", "mft", file_path="C:\\Windows\\Temp\\WU.EXE", file_key="\\windows\\temp\\wu.exe"),
        named(331, "wu-bare", "srum", process_executable="wu.exe"),
        system_event(T0 + 332 * SEC, 9990, "7045", {"ServiceName": "Solo Svc", "ImagePath": "C:\\Solo\\solo.exe"},
                     file_path="C:\\Solo\\solo.exe", file_key="\\solo\\solo.exe", user_name="Administrator", user_domain="C137"),
        security_event(T0 + 333 * SEC, 9991, "1102", user_name="Administrator", user_domain="C137", logon_id="0x9"),
        named(334, "wevtutil-pf", "prefetch", file_path="\\VOLUME{01d6}\\WINDOWS\\SYSTEM32\\WEVTUTIL.EXE",
              file_key="\\windows\\system32\\wevtutil.exe"),
        named(335, "wevtutil-proc", "evtx", process_executable="C:\\Windows\\System32\\wevtutil.exe"),
    ], "DESKTOP", run="fn")


def test_same_file_name_counts_the_name_in_any_folder_warns_on_hover_and_lists_what_the_count_says(browser, pcase):  # noqa: F811
    """The row matches the name alone, with a bare name and another folder's copy counted, warns on hover that it joins
    every file of that name, and says when nothing else has the name. A log clear takes the table's fixed name."""
    add_file_names(pcase)
    install, solo, clear = (uid(pcase, w) for w in (INSTALL, "event_code = '7045' AND file_path LIKE '%solo.exe'",
                                                    "event_code = '1102'"))
    prefetch = uid(pcase, "artifact = 'prefetch' AND file_key LIKE '%wevtutil.exe'")
    for page in served_page(browser, pcase):
        select(page, install)
        row = pv(page, "file_name")
        assert row.locator(".pv-value").inner_text() == "wu.exe" and row.locator(".pv-n").inner_text() == "3 events"
        assert row.locator("button.pv-go").get_attribute("title") == FILE_NAME_WARNING
        assert pv(page, "file").locator(".pv-n").inner_text() == "1 event"   # Same file still matches the exact path
        row.locator("button.pv-go").click()
        page.locator("#relatedList strong", has_text="3 events with the file name wu.exe").wait_for()
        assert len(page.locator("#relatedList li.rel-row").all()) == 3
        select(page, solo)
        assert pv(page, "file_name").locator(".pv-n").inner_text() == "1 event"
        assert pv(page, "file_name").locator(".pv-empty").inner_text() == "No other file of this name in the case."
        # A kind with a fixed name carries it in the click, and the trail keeps it
        select(page, clear)
        fixed = pv(page, "file_name")
        assert fixed.locator("button.pv-go").inner_text() == "Same file name: wevtutil.exe"
        assert fixed.locator(".pv-value").count() == 0
        assert fixed.locator(".pv-n").inner_text() == "2 events"
        fixed.locator("button.pv-go").click()
        page.locator("#relatedList strong", has_text="2 events with the file name wevtutil.exe").wait_for()
        assert page.evaluate("window.__app.S.trail.map((s) => s.label)")[-1] == "Same file name: wevtutil.exe"
        # A Prefetch record's window size comes from a source, which the reason's hover names
        select(page, prefetch)
        window = pv(page, "window")
        assert window.locator(".pv-basis").inner_text() == "sourced"
        assert window.locator(".pv-basis").get_attribute("title") == (
            "This size comes from a source about the artifact, named in the hover on the row's reason.")
        assert window.locator(".pv-reason").get_attribute("title") == "Sources: Valhuntir, Prefetch"


def test_a_fixed_name_row_whose_name_has_one_record_is_not_alone(browser, pcase):  # noqa: F811
    """A log clear never matches wevtutil.exe itself, so one record of that name is another event, not the event alone."""
    load_events(pcase, [
        security_event(T0 + 333 * SEC, 9991, "1102", user_name="Administrator", user_domain="C137", logon_id="0x9"),
        named(334, "wevtutil-pf", "prefetch", file_path="\\VOLUME{01d6}\\WINDOWS\\SYSTEM32\\WEVTUTIL.EXE",
              file_key="\\windows\\system32\\wevtutil.exe"),
    ], "DESKTOP", run="fn1")
    clear = uid(pcase, "event_code = '1102'")
    for page in served_page(browser, pcase):
        select(page, clear)
        fixed = pv(page, "file_name")
        page.wait_for_function("(row) => row.querySelector('.pv-n').textContent === '1 event'", arg=fixed.element_handle())
        assert fixed.locator(".pv-empty").inner_text() == ""


def test_the_right_click_menu_words_a_pivot_the_event_cannot_take_as_the_page_does(browser, synthetic_case):  # noqa: F811
    """The disabled window item reads 'Same host within ±N s', as the page's not-offered line does."""
    from test_analysis_relations import load_untimed_pivots

    untimed, _, _ = load_untimed_pivots(synthetic_case)
    for page in served_page(browser, synthetic_case):
        page.evaluate("async (uid) => { const m = await import('/js/quick_menu.js'); await m.openQuickMenu(uid, 60, 60, false) }",
                      untimed)
        page.locator("#quickMenu:not([hidden])").wait_for()
        assert ["Same host within ±N s", True, "This event has no time recorded"] in menu_texts(page)


def menu_texts(page):
    """The right-click menu's items: (text, disabled, title)."""
    return page.locator("#quickMenu [role=menuitem]").evaluate_all(
        "(items) => items.map((i) => [i.textContent, i.disabled, i.title])")


def right_click(page, event):
    """Right-click an event of the case: the timeline is zoomed to three seconds around it, so its tick is the one under the
    pointer, and the tick is found by the event's ID."""
    page.evaluate("(uid) => window.__app.select(uid, false)", event)
    page.wait_for_function("(uid) => window.__app.S.focusEvent && window.__app.S.focusEvent.uid === uid", arg=event)
    at = page.evaluate("window.__app.S.focusEvent.adjusted / 1000")
    page.evaluate("([s, e]) => window.__app.setView(s, e)", [at - 1500, at + 1500])
    page.wait_for_function("(uid) => window.__app.S.index.some((items) => (items || []).some((it) => it.kind === 'event' "
                           "&& it.e.uid === uid))", arg=event)
    point = point_of(page, event)   # the lane scrolled into view, as the Details panel's two-thirds default needs
    page.mouse.click(point["x"], point["y"], button="right")
    page.locator("#quickMenu:not([hidden])").wait_for()


def test_the_right_click_menu_offers_the_pivots_the_event_page_offers_in_the_kinds_order(browser, pcase):  # noqa: F811
    """Find related lists the page's pivots for the event, with the page's labels and sizes and no counts, then what
    the event can't take, disabled, with the page's reason."""
    add_file_names(pcase)
    install, failed = uid(pcase, INSTALL), uid(pcase, "event_code = '4625' AND record_id = 9200")
    alert = uid(pcase, "tool = 'suricata' AND log_channel = 'alert' AND event_code = '2000001' AND source_ip = '10.42.85.10'")
    for page in served_page(browser, pcase):
        menu = page.locator("#quickMenu")
        # A service install: file, window (the kind's 600 s, not the case's 60), service name, account, file name
        right_click(page, install)
        items = menu_texts(page)
        related = [i for i in items if i[0].startswith("Same")]
        assert [(t, d) for t, d, _ in related] == [
            ("Same file (the service binary)", False), ("Same host within ±600 s", False), ("Same service name", False),
            ("Same account (from the System element)", False), ("Same file name", False),
            ("Same logon session", True), ("Same source IP", True), ("Same source IP and port", True),
            ("Same IP at either end", True)]
        assert {t: title for t, _, title in related}["Same file name"] == FILE_NAME_WARNING
        assert {t: title for t, d, title in related if d}["Same logon session"] == "A 7045 records no logon ID."
        assert menu.get_by_role("menuitem", name="Same IP at either end").get_attribute("title") == \
            "A service install records no address."
        assert not any("events" in t for t, _, _ in related)   # no counts
        # The new pivots run from the menu, with the page's own count: the service name's 6 events
        menu.get_by_role("menuitem", name="Same service name").click()
        page.locator("#relatedList strong", has_text="6 events with the same service name").wait_for()
        right_click(page, install)
        menu.get_by_role("menuitem", name="Same file name").click()
        page.locator("#relatedList strong", has_text="3 events with the file name wu.exe").wait_for()
        assert page.evaluate("window.__app.S.trail.filter((s) => s.type === 'pivot').map((s) => s.label)")[-1] == "Same file name"
        # A failed logon with no domain: its account is name only, and its client workstation is a pivot
        right_click(page, failed)
        related = [t for t, _, _ in menu_texts(page) if t.startswith("Same")]
        assert related[:3] == ["Same IP at either end: 203.0.113.7", "Same workstation", "Same account (name only, any domain)"]
        menu.get_by_role("menuitem", name="Same workstation").click()
        page.locator("#relatedList strong", has_text="with the same source workstation").wait_for()
        # An alert takes the page's end of the address, not both: the collected host's, and the other as an unranked item
        page.keyboard.press("Escape")
        right_click(page, alert)
        addresses = [t for t, _, _ in menu_texts(page) if t.startswith("Same IP at either end")]
        assert addresses == ["Same IP at either end: 10.42.85.10", "Same IP at either end: 10.42.85.115"]
        names = [t for t, _, _ in menu_texts(page) if t.startswith("Same")]
        assert names.index("Same flow") < names.index(addresses[0]) < names.index("Same rule or signature")
        menu.get_by_role("menuitem", name="Same flow").click()
        page.locator("#relatedList strong", has_text="with the same flow").wait_for()


def test_a_saved_hidden_set_still_hides_its_pivots_and_a_pivot_added_later_shows_until_it_is_hidden(browser, pcase):  # noqa: F811
    add_file_names(pcase)
    install = uid(pcase, INSTALL)
    for page in served_page(browser, pcase):
        menu = page.locator("#quickMenu")
        # A saved set names two pivots and knows nothing of the others
        page.evaluate("localStorage.setItem('glessner.quickActionsHidden', JSON.stringify(['pivot:file', 'pivot:addr']))")
        right_click(page, install)
        shown = [t for t, _, _ in menu_texts(page) if t.startswith("Same")]
        assert shown == ["Same host within ±600 s", "Same service name", "Same account (from the System element)",
                         "Same file name", "Same logon session", "Same source IP", "Same source IP and port"]
        # The new pivots are in Customize, unchecked only where the analyst unchecks them
        menu.get_by_role("menuitem", name="Customize this menu…").click()
        for label in ("Same file name", "Same service name", "Same workstation", "Same flow", "Same task name",
                      "Same rule or signature"):
            assert menu.get_by_label(label, exact=True).is_checked(), label
        assert not menu.get_by_label("Same file", exact=True).is_checked()
        menu.get_by_label("Same service name", exact=True).uncheck()
        menu.get_by_role("button", name="Done").click()
        assert json.loads(page.evaluate("localStorage.getItem('glessner.quickActionsHidden')")) == [
            "pivot:file", "pivot:addr", "pivot:service_name"]
        right_click(page, install)
        assert "Same service name" not in [t for t, _, _ in menu_texts(page)]


def test_a_loopback_pivot_says_it_stays_on_the_seeds_host_and_to_investigate_says_a_system_session_is_not_counted(
        browser, pcase):  # noqa: F811
    """The Same source IP list's heading and the IP-at-either-end heading name the host the loopback address is
    matched on, and To investigate says why a flagged event in a system session has no session count."""
    from glessner.server import api_mark
    local = [logon(T0 + (600 + n) * SEC, 9800 + n, SECURITY, ltype="3", ip="::1", logon_id=f"0x{9800 + n:x}") for n in range(2)]
    load_events(pcase, local, "DC01", run="p31")
    load_events(pcase, [logon(T0 + 610 * SEC, 9810, WS_LOG, ltype="3", ip="::1", logon_id="0x9810")], "DESKTOP", run="p32")
    system = logon(T0 + 620 * SEC, 9820, WS_LOG, code="4672", logon_id="0x3e7", user="SYSTEM", domain="NT AUTHORITY",
                   computer="DESKTOP-SDN1RPT.C137.local")
    load_events(pcase, [system], "DESKTOP", run="p33")
    seed = uid(pcase, "record_id = 9800 AND host = 'DC01'")
    flagged = uid(pcase, "event_code = '4672' AND logon_id = '0x3e7'")
    for page in served_page(browser, pcase, setup=lambda app: api_mark(app, {"uids": [flagged], "value": "suspicious"})):
        select(page, seed)
        heading = page.locator("#relatedList .actions strong")
        pv(page, "addr").locator("button.pv-go").click()
        heading.wait_for()
        assert heading.inner_text() == "::1 at either end, on DC01 only: 2 events"   # DC01's two, not DESKTOP's as well
        page.locator("#details .pivots").get_by_text("Same source IP", exact=False).last.click()
        page.wait_for_function(
            "() => document.querySelector('#relatedList .actions strong')?.textContent.includes('same source IP')")
        assert "on DC01 only" in heading.inner_text()
        # The worklist counts the event's ranked pivots, and leaves Same logon session out for a system session
        page.locator("#investigateButton").click()
        page.wait_for_selector("#details[data-page='investigate'] ul.worklist li.rel-row")
        row = page.locator("#details[data-page='investigate'] ul.worklist li.rel-row").first
        assert "4672" in row.locator(".rel-text").inner_text()
        assert "session" not in row.locator(".inv-count").evaluate_all("(ns) => ns.map((n) => n.dataset.pivot)")


# ---------- narrowed breakdowns, offsets, the window's reach, and the outside end ----------

def fmt_gaps(page, gaps, reach=False):
    """The page's own fmtGap over some gaps in seconds."""
    return page.evaluate("async ([gs, reach]) => { const { fmtGap } = await import('/js/core.js'); "
                         "return gs.map((g) => fmtGap(g, { reach })); }", [gaps, reach])


def test_a_breakdown_entry_opens_the_rows_list_narrowed(browser, pcase, monkeypatch):  # noqa: F811
    """A breakdown entry of any row is a link that opens the row's list narrowed to its source. A
    search row can only ask for a source as field terms, so an entry whose logon type is empty, which a search drops, is
    information; the sources past the largest few are text with a title."""
    monkeypatch.setattr(queries, "RELATED_LIMIT", 2)
    monkeypatch.setattr(pivots, "RELATED_LIMIT", 2)
    reason = {"SubStatus": "0xC000006A"}
    typed = [security_event(T0 + (300 + i) * SEC, 9700 + i, "4625", logon_type="3", extra=reason, user_name="probe")
             for i in range(3)]
    untyped = [security_event(T0 + (310 + i) * SEC, 9710 + i, "4625", logon_type="", extra=reason, user_name="probe")
               for i in range(2)]
    load_events(pcase, [*typed, *untyped], "DC01", run="p40")
    failed, install = uid(pcase, "record_id = 9700"), uid(pcase, INSTALL)
    for page in served_page(browser, pcase):
        select(page, failed)
        search = pv(page, "search")
        assert search.locator(".pv-n").inner_text() == "5 events"
        search.locator("button.pv-source").first.wait_for()
        assert search.locator("button.pv-source").all_inner_texts() == ["4625 type 3 3"]
        empty = search.locator("span.pv-source-info")
        assert empty.inner_text() == "4625 2" and search.locator(".pv-sources button").count() == 1
        assert empty.get_attribute("title").startswith("This source has no logon type, which a search can't ask for")
        search.locator("button.pv-source").click()
        page.wait_for_selector("#details[data-page='search'] li.rel-row")
        assert page.locator("#search").input_value() == (
            "code:4625 SubStatus:0xC000006A artifact:evtx channel:Security code:4625 logon_type:3")
        assert page.locator("#details li.rel-row").count() == 3   # the entry's count
        # A row that is no search: the entry lists that source across the row, and the heading and trail say so
        select(page, install)
        service = pv(page, "service_name")
        service.locator("button.pv-source").first.wait_for()
        entry = service.locator("button.pv-source", has_text="7036")
        assert entry.get_attribute("title") == "List the 1 event of 7036 in this row"
        entry.click()
        page.locator("#relatedList strong", has_text="1 event with the same service name, only 7036").wait_for()
        assert page.locator("#relatedList li.rel-row").count() == 1
        assert page.evaluate("window.__app.S.pivotResult.res.source") == ["evtx", "System", "7036"]
        assert page.evaluate("window.__app.S.trail.map((s) => s.label)")[-1] == "Same service name, only 7036"
        # The sources past the six largest are a span with a title, not a button
        more = pv(page, "window").locator(".pv-more")
        more.wait_for()
        title = more.get_attribute("title")
        assert more.evaluate("(n) => n.tagName") == "SPAN" and more.locator("button").count() == 0
        assert title.startswith("Sources past the 6 largest: ") and title.endswith("They open only from this row's own list.")


def test_offsets_read_in_units(browser, pcase):  # noqa: F811
    """One formatter writes every gap, in whole units from a minute up, with the exact seconds in the hover, and the
    window list's offset cell and the dashed window links use it. The case has events 4 s, 62 s, and a few hundred
    milliseconds from the RDP logon, which is the shape of a real window list (a domain controller's 500 rows can fall
    within 0.6 s)."""
    probes = [security_event(T0 + 4 * SEC, 9901, "4690"), security_event(T0 + 62 * SEC, 9902, "4691"),
              security_event(T0 + 412_700, 9903, "4692")]
    load_events(pcase, probes, "DC01", run="p42")
    rdp = uid(pcase, RDP)
    vectors = [(4.12, "+4 s"), (-5, "-5 s"), (0.4127, "+412 ms"), (-0.0004, "-0 ms"), (59.999, "+59 s"), (60, "+1 min"),
               (62, "+1 min 2 s"), (220, "+3 min 40 s"), (3601, "+1 h"), (-8510, "-2 h 21 min"), (187200, "+2 d 4 h"),
               (-297614267, "-9 y 159 d"), (-329203309.5, "-10 y 160 d"), (-1280627680.76, "-40 y 222 d"), (0, "0 s")]
    for page in served_page(browser, pcase):
        assert fmt_gaps(page, [v for v, _ in vectors]) == [w for _, w in vectors]
        assert fmt_gaps(page, [232.7, 4], reach=True) == ["±3 min 52 s", "±4 s"]
        assert fmt_gaps(page, [None]) == [""]
        assert page.evaluate("async () => { const { gapTitle } = await import('/js/core.js'); "
                             "return [gapTitle(4.12), gapTitle(-8510), gapTitle(0), gapTitle(null)]; }") == [
            "+4.120 s", "-8,510.000 s", "this event", ""]
        select(page, rdp)
        pv(page, "window").locator("button.pv-go").click()
        page.wait_for_selector("#relatedList li.rel-row")
        assert int(pv(page, "window").locator("input.pv-seconds").input_value()) >= 62
        cells = {}
        for code in ("4690", "4691", "4692"):
            off = page.locator("#relatedList li.rel-row", has_text=f"{code} security").locator(".off")
            cells[code] = (off.inner_text(), off.get_attribute("title"), "far" in off.get_attribute("class").split())
        assert cells == {"4690": ("+4 s", "+4.000 s", False), "4691": ("+1 min 2 s", "+62.000 s", True),
                         "4692": ("+413 ms", "+0.413 s", False)}   # the server rounds a gap to the millisecond
        # The dashed links of the window drawn on the timeline write the same text (draw.js)
        texts = page.evaluate("""async () => {
            const { drawWindowLinks } = await import('/js/draw.js');
            const { S } = await import('/js/core.js');
            const saved = [S.focus, S.windowLinks, S.index];
            S.focus = 'a';
            S.windowLinks = [{ uid: 'b', gap_s: 62 }, { uid: 'c', gap_s: -0.4 }];
            S.index = [[{ kind: 'event', x: 10, e: { uid: 'a' } }, { kind: 'event', x: 50, e: { uid: 'b' } },
                        { kind: 'event', x: 90, e: { uid: 'c' } }]];
            const said = [];
            const ctx = { save() {}, restore() {}, setLineDash() {}, beginPath() {}, moveTo() {}, quadraticCurveTo() {},
                          stroke() {}, fillText: (t) => said.push(t) };
            drawWindowLinks(ctx, { related: 'red' });
            [S.focus, S.windowLinks, S.index] = saved;
            return said; }""")
        assert texts == ["+1 min 2 s", "-400 ms"]


def test_the_window_list_says_what_it_holds(browser, pcase, monkeypatch):  # noqa: F811
    """The window's heading says it is the nearest N of M and how far they reach, the reach line points to the row that
    holds the rest, and the window row is flagged broad past the limit. Another list cut at the limit gives its signed
    reach, and a list that holds everything gives none."""
    monkeypatch.setattr(queries, "RELATED_LIMIT", 2)
    monkeypatch.setattr(pivots, "RELATED_LIMIT", 2)
    install = uid(pcase, INSTALL)
    for page in served_page(browser, pcase):
        select(page, install)
        window = pv(page, "window")
        rank = window.locator(".pv-rank").inner_text()
        total = int(window.locator(".pv-n").inner_text().split()[0])
        window.locator(".pv-broad").wait_for()
        assert window.locator(".pv-broad").inner_text() == (
            f"Broad: {total} events. The list shows the 500 nearest in time; open one source from the breakdown to reach "
            "the rest.")
        window.locator("button.pv-go").click()
        heading, reach = page.locator("#relatedList .actions strong"), page.locator("#relatedList .pv-reach")
        reach.wait_for()
        res = page.evaluate("window.__app.S.pivotResult.res")
        assert heading.inner_text() == f"Same host within ±600 s: the 2 nearest of {res['total']:,} events"
        [want] = fmt_gaps(page, [res["reach_s"]], reach=True)
        assert reach.inner_text() == (
            f"The 2 nearest of {res['total']:,}, reaching {want} of this event, not the whole ±600 s window. "
            f"For the rest, open one source in row {rank} above. Hover an offset for the exact seconds.")
        offs = page.locator("#relatedList li.rel-row .off")
        titles = offs.evaluate_all("(ns) => ns.map((n) => n.title)")
        assert all(abs(float(t.replace(",", "").removesuffix(" s"))) <= res["reach_s"] + 1e-9 for t in titles)
        assert offs.all_inner_texts() == fmt_gaps(page, [e["gap_s"] for e in res["events"]])
        # Narrowed to a source, the rest is in a smaller window; so it is from a click with no row (the menu)
        select(page, install)
        entry = pv(page, "window").locator("button.pv-source").first
        label = entry.get_attribute("data-source")
        entry.click()
        page.locator("#relatedList strong", has_text=f", only {label}").wait_for()
        heading_text = page.locator("#relatedList .actions strong").inner_text()
        assert heading_text.startswith(f"Same host within ±600 s, only {label}: the 2 nearest of ")
        assert "For the rest, make the window smaller." in reach.inner_text() and "open one source" not in reach.inner_text()
        page.evaluate("async (uid) => (await import('/js/quick_menu.js')).pivotFromMenu(uid, 'window', 600, null, {})", install)
        assert page.locator("#relatedList .actions strong").inner_text().startswith("Same host within ±600 s: the 2 nearest of ")
        assert "For the rest, make the window smaller." in reach.inner_text()
        # A list that isn't a window and is cut gives its signed reach; one that holds everything gives none
        select(page, install)
        pv(page, "service_name").locator("button.pv-go").click()
        page.locator("#relatedList strong", has_text="the 2 nearest of 6 events with the same service name").wait_for()
        res = page.evaluate("window.__app.S.pivotResult.res")
        lo, hi = fmt_gaps(page, [min(e["gap_s"] for e in res["events"]), max(e["gap_s"] for e in res["events"])])
        assert reach.inner_text() == f"These 2 reach {lo} to {hi} around this event."
        select(page, install)
        pv(page, "file").locator("button.pv-go").click()
        page.locator("#relatedList strong", has_text="1 event with the same file path").wait_for()
        assert page.locator("#relatedList .pv-reach").count() == 0


def test_an_alerts_outside_end_is_a_ranked_row(browser, pcase):  # noqa: F811
    """An IDS alert's outside address is a ranked row directly after the internal end, saying which end
    it is, and the list it opens heads its last column End."""
    load_events(pcase, [ids_event(T0 + 200 * SEC, 5001, "10.42.85.10", "203.0.113.50")], "network", run="p41")
    alert = uid(pcase, "source_record = '5001'")
    for page in served_page(browser, pcase):
        select(page, alert)
        assert [r.get_attribute("data-pivot") for r in page.locator("#details .pv").all()] == [
            "flow", "addr", "addr", "rule", "window"]   # the alert records no source port, so no connection row
        ranked = page.locator('#details .pv[data-pivot="addr"]')
        internal, outside = ranked.nth(0), ranked.nth(1)
        assert internal.locator(".pv-value").inner_text() == "10.42.85.10"
        assert internal.locator(".pv-end").inner_text().startswith("the internal end, ")
        assert outside.locator(".pv-value").inner_text() == "203.0.113.50"
        assert outside.locator(".pv-end").inner_text() == "the outside end"
        assert outside.locator(".pv-reason").inner_text().startswith("The other end of the connection, outside the case")
        counted = outside.locator(".pv-n").inner_text()   # "1 event": the alert itself, which has the address at one end
        count = int(counted.split()[0])
        outside.locator("button.pv-go").click()
        page.wait_for_selector("#relatedList li.rel-row")
        assert page.locator("#relatedList li.rel-head .rel-col").inner_text() == "End"
        assert page.locator("#relatedList .actions strong").inner_text() == f"203.0.113.50 at either end: {counted}"
        assert page.locator("#relatedList li.rel-row").count() == count
