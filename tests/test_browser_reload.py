"""A reload comes back to the page that was shown, in a real browser. F5 in the same
tab and serve run brings back the path's step, the Details page with its pivot list and trail, the selection, the search
box, the Lanes preset, and the timeline's window, and on the overview keeps the Details page behind it. On the Findings
page it brings back an open finding form, new or an edit, and the report summary's unsaved text. When the Findings page
can't draw them, as its read fails or another page comes first, they wait for its next draw, which says what of them it
couldn't open; New finding from an Event page then opens the kept form's words over its own events. A new tab, the link
opened again in the same tab, another open of the case, and blocked storage still start on the Case overview, and the
status line says what a reload drops. The window isn't put back when the case had no events, nor when it lies wholly
before the case's first event or after its last, as after a load that moves them all elsewhere in time: the reload fits
the events. They drive the installed Microsoft Edge through Playwright, as test_browser_smoke does, and are skipped
without it."""

import json
import re
from datetime import UTC, datetime
from urllib.parse import urlsplit

import pytest
from conftest import SEC, T0
from test_browser_findings import FINDINGS, entries, open_findings, pick_technique, select, uid_at
from test_browser_smoke import browser, case_menu, refused_with, served_page, to_timeline, wait_held  # noqa: F401

from glessner.server import api_finding, api_mark, api_setting

pytestmark = pytest.mark.browser
READY = "() => window.__ready === true && window.__app.S.data !== null"
BACK = "Back where the page was before the reload."
WINDOW = "() => [window.__app.S.view.start, window.__app.S.view.end]"
# What a reload puts back, read from the page: the window, the selection and focus, the trail, and the Details page.
# Back's history is not kept (its pages reopen through functions), so the band is read without its Back link.
PLACE = """() => {
    const S = window.__app.S, d = document.getElementById('details');
    return { view: { ...S.view }, focus: S.focus, selected: [...S.selected].sort(), trail: S.trail.map((s) => s.label),
             at: S.trailAt, page: d.dataset.page, key: d.dataset.key,
             listed: document.querySelectorAll('#relatedList li.rel-row').length,
             band: (() => { const band = document.getElementById('detailsBand').cloneNode(true);
                            band.querySelector('.back-bar')?.remove(); return band.textContent; })() };
}"""


def reload(p):
    p.reload()
    p.wait_for_function(READY)


def current(p):
    return p.locator("#path button[aria-current='page']").inner_text()


def status(p):
    return p.evaluate("() => { const s = document.getElementById('status'); return s.title || s.textContent; }")


def first_logon(p):
    """A 4624 drawn in the window: a logon, whose account pivot lists others."""
    return p.evaluate("() => window.__app.S.data.events.find((e) => e.code === '4624').uid")


def open_event(p, uid):
    p.evaluate("(u) => window.__app.select(u, false)", uid)
    p.wait_for_selector(f"#details[data-key='event:{uid}'] .ev-ident")


def test_a_reload_comes_back_to_the_event_its_pivot_list_and_trail_the_window_and_the_preset(
        browser, synthetic_case):  # noqa: F811
    """The Timeline with an Event page and the account pivot's list under it: after F5 the same window, the same event in
    focus with its page and list, the trail with the same steps and the same step on screen, the second Lanes preset, and
    the status line saying the page came back."""
    for p in served_page(browser, synthetic_case):
        presets = p.evaluate("() => window.__app.S.meta.presets")
        p.locator("#groupby").select_option("1")
        p.wait_for_function("(want) => window.__app.S.groupby.join() === want.join()", arg=presets[1])
        uid = first_logon(p)
        # A window of its own around the logon, narrower than the case's
        p.evaluate("(u) => { const S = window.__app.S, e = S.data.events.find((x) => x.uid === u); "
                   "const w = S.view.end - S.view.start; "
                   "return window.__app.setView(e.ts / 1000 - w / 8, e.ts / 1000 + w / 8); }", uid)
        open_event(p, uid)
        p.locator('#details .pv[data-pivot="account"] button.pv-go').click()
        p.wait_for_selector("#relatedList li.rel-row")
        # Another event from the list, and the same pivot from it: four steps, which the reload's own redraw of the last
        # event and its pivot could not make again
        other = p.locator(f"#relatedList li.rel-row:not([data-uid='{uid}'])").first
        second = other.get_attribute("data-uid")
        other.locator(".rel-text").click()
        p.wait_for_selector(f"#details[data-key='event:{second}'] .ev-ident")
        p.locator('#details .pv[data-pivot="account"] button.pv-go').click()
        p.wait_for_function("(u) => window.__app.S.pivotResult && window.__app.S.pivotResult.uid === u", arg=second)
        p.wait_for_selector("#relatedList li.rel-row")
        p.wait_for_function("() => window.__app.S.anim === null")   # the list's click moves the window, animated
        before = p.evaluate(PLACE)
        assert before["listed"] > 0 and len(before["trail"]) == 4 and before["at"] == 3 and before["focus"] == second
        reload(p)
        p.wait_for_selector("#relatedList li.rel-row")
        p.wait_for_function("(text) => (document.getElementById('status').title || '').startsWith(text)", arg=BACK)
        assert p.evaluate(PLACE) == before
        assert p.locator("#overview").is_hidden() and current(p) == "Timeline"
        assert p.locator("#groupby").input_value() == "1"
        assert p.evaluate("() => window.__app.S.groupby") == presets[1]
        assert status(p) == BACK
        # F5 while the window is still moving (450 ms) keeps where it was going
        target = p.evaluate("""async () => {
            const v = window.__app.S.view, w = v.end - v.start, to = [v.start + w / 4, v.end - w / 4];
            const m = await import('/js/data.js');
            m.animateView(...to);
            return to;
        }""")
        reload(p)
        assert p.evaluate("() => [window.__app.S.view.start, window.__app.S.view.end]") == pytest.approx(target, abs=1)


@pytest.mark.parametrize(("times", "button"), [
    (["2020-09-19T03:21:50Z"], "Import 1 record"),
    (["1969-12-31T23:59:00Z", "2020-09-19T03:21:50Z"], "Import 2 records"),
], ids=["after_1970", "before_1970"])
def test_the_reload_after_a_first_load_in_a_case_with_no_events_fits_the_events_loaded(
        browser, tmp_path, times, button):  # noqa: F811
    """A case with no events has no span to fit, so its window is 2 s around 1970. The Import page's first load reloads
    the page, which fits the events loaded rather than putting that window back, also when one is from before 1970, as a
    file's link time can be, and their span takes in that window. The status line says the page is back, with no word on
    the window. The case is made and taken in as the start page makes one."""
    from glessner.case import create_case
    from glessner.intake import intake

    evidence = tmp_path / "evidence"
    (evidence / "DC01").mkdir(parents=True)
    case = create_case(tmp_path / "case", "Empty", evidence, "cody")
    intake(case)
    for p in served_page(browser, case):
        assert p.evaluate(WINDOW) == [-1000, 1000]
        records = [{"@timestamp": when, "user": "u1", "action": "login"} for when in times]
        (evidence / "DC01" / "export.json").write_text(json.dumps(records), newline="\n")
        details = p.locator("#details")
        case_menu(p, "importButton")
        p.wait_for_selector("#details[data-page='import']")
        details.get_by_role("button", name="Add new evidence").click()
        go = details.get_by_role("button", name=button, exact=True)
        with p.expect_navigation():
            go.click()
        p.wait_for_function(READY)
        start, end = p.evaluate(WINDOW)
        assert all(start < datetime.fromisoformat(when).timestamp() * 1000 < end for when in times)
        p.wait_for_function("(n) => document.getElementById('stInWindow').textContent === `In this window: ${n}`",
                            arg=len(times))
        p.wait_for_function("(text) => (document.getElementById('status').title || '').startsWith(text)", arg=BACK)
        assert status(p) == BACK


def test_the_reload_after_a_load_that_moves_every_event_elsewhere_in_time_fits_the_events(browser, tmp_path):  # noqa: F811
    """A log imported with the wrong time field, then again with the right one, has its only event replaced by one five
    years later. The reload after the second import fits that event rather than putting back the first one's window,
    which now shows nothing. The status line says the page is back, with no word on the window. A window takes in its
    start and not its end, so one that ends at the event isn't put back either, and one that starts at it is."""
    from glessner.case import create_case
    from glessner.imports import guess_mapping, run_import, sniff
    from glessner.intake import intake
    from glessner.server import api_import

    evidence = tmp_path / "evidence"
    (evidence / "DC01").mkdir(parents=True)
    record = [{"@timestamp": "2020-09-19T03:21:50Z", "seen": "2015-01-01T00:00:00Z", "user": "u1", "action": "login"}]
    (evidence / "DC01" / "export.json").write_text(json.dumps(record), newline="\n")
    case = create_case(tmp_path / "case", "Moved", evidence, "cody")
    intake(case)
    right = guess_mapping(sniff(case, "DC01/export.json"))
    run_import(case, "DC01/export.json", {**right, "time": {**right["time"], "columns": ["seen"]}})
    first = datetime(2015, 1, 1, tzinfo=UTC).timestamp() * 1000
    when = datetime(2020, 9, 19, 3, 21, 50, tzinfo=UTC).timestamp() * 1000
    for p in served_page(browser, case):
        start, end = p.evaluate(WINDOW)
        assert start < first < end
        assert api_import(p.hub.app, {"paths": ["DC01/export.json"], "mapping": right})["runs"][0]["replaced"] == 1
        reload(p)   # as the Import page does after an import
        fitted = p.evaluate(WINDOW)
        assert fitted[0] < when < fitted[1]
        p.wait_for_function("(text) => (document.getElementById('status').title || '').startsWith(text)", arg=BACK)
        assert status(p) == BACK
        for window, kept in (([when - 5000, when], False), ([when, when + 5000], True)):
            p.evaluate("(w) => window.__app.setView(...w)", window)
            reload(p)
            assert p.evaluate(WINDOW) == pytest.approx(window if kept else fitted, abs=1)


def test_a_reload_comes_back_to_the_path_s_step_a_search_and_a_page_of_the_case_menu(browser, synthetic_case):  # noqa: F811
    """To investigate, Findings, and the Audit trail come back as their step; a search comes back with its text in the box
    and its matches listed; the Tools page comes back as itself."""
    for p in served_page(browser, synthetic_case):
        steps = (("To investigate", "#investigateButton", "investigate"), ("Findings", "#tabFindings", "findings"),
                 ("Audit trail", "#tabAudit", "audit"))
        for step, button, page in steps:
            p.locator(button).click()
            p.wait_for_selector(f"#details[data-page='{page}']")
            reload(p)
            p.wait_for_selector(f"#details[data-page='{page}']")
            assert current(p).startswith(step) and p.locator("#overview").is_hidden(), step   # To investigate adds its counts
        p.locator("#search").fill("DC01")
        p.locator("#search").press("Enter")
        p.wait_for_selector("#details[data-key='search:DC01'] li.rel-row")
        listed = p.locator("#details li.rel-row").count()
        reload(p)
        p.wait_for_selector("#details[data-key='search:DC01'] li.rel-row")
        assert p.locator("#details li.rel-row").count() == listed and p.locator("#search").input_value() == "DC01"
        assert current(p) == "Timeline"
        case_menu(p, "toolsButton")
        p.wait_for_selector("#details[data-page='tools'] h2, #details[data-page='tools'] table")
        reload(p)
        p.wait_for_selector("#details[data-page='tools'] h2, #details[data-page='tools'] table")
        assert current(p) == "Timeline"


def test_a_reload_on_the_overview_keeps_it_up_with_the_details_page_behind_it(browser, synthetic_case):  # noqa: F811
    """The overview comes back first, with its step lit; the Event page shown before it is drawn behind
    it, so the Timeline step shows that page again with no new load."""
    for p in served_page(browser, synthetic_case):
        uid = first_logon(p)
        open_event(p, uid)
        p.locator("#tabOverview").click()
        p.wait_for_selector("#overview", state="visible")
        reload(p)
        p.wait_for_function("(text) => (document.getElementById('status').title || '').startsWith(text)", arg=BACK)
        assert p.locator("#overview").is_visible() and current(p) == "Overview"
        assert p.locator("#details").get_attribute("data-key") == f"event:{uid}"
        assert p.evaluate("() => document.getElementById('details').inert")
        loads = []
        p.on("request", lambda r: loads.append(r.url) if "/api/event?" in r.url else None)   # noqa: B023
        p.locator("#tabTimeline").click()
        p.wait_for_selector("#overview", state="hidden")
        assert current(p) == "Timeline" and p.locator("#details").get_attribute("data-key") == f"event:{uid}"
        assert p.locator(f"#details[data-key='event:{uid}'] .ev-ident").is_visible() and loads == []


def test_a_new_tab_the_link_again_another_open_and_blocked_storage_start_on_the_overview(browser, synthetic_case):  # noqa: F811
    """Only a reload of the same open in the same tab comes back. A new tab from the link has storage of its own, the link
    opened again in the tab is a navigation, a place saved under another open's ID (a new serve run, or the case opened
    again) is not this open's, and a tab that can't read its storage opens on the overview."""
    for p in served_page(browser, synthetic_case):
        p.locator("#investigateButton").click()
        p.wait_for_selector("#details[data-page='investigate']")
        url = p.url
        tab = p.context.new_page()
        tab.goto(url)
        tab.wait_for_function(READY)
        assert tab.locator("#overview").is_visible() and current(tab) == "Overview"
        tab.close()
        p.goto(url)
        p.wait_for_function(READY)
        assert p.locator("#overview").is_visible() and current(p) == "Overview"
        to_timeline(p)
        p.locator("#investigateButton").click()
        p.wait_for_selector("#details[data-page='investigate']")
        # Runs after the page's own pagehide listener, which init added first
        p.evaluate("""() => window.addEventListener('pagehide', () => {
            const saved = JSON.parse(sessionStorage.getItem('glessner.place'));
            sessionStorage.setItem('glessner.place', JSON.stringify({ ...saved, open: 'an earlier open' }));
        })""")
        reload(p)
        assert p.locator("#overview").is_visible() and current(p) == "Overview" and not status(p).startswith(BACK)
        to_timeline(p)
        p.locator("#investigateButton").click()
        p.wait_for_selector("#details[data-page='investigate']")
        p.add_init_script("Object.defineProperty(window, 'sessionStorage', { get() { throw new Error('blocked'); } });")
        reload(p)
        assert p.locator("#overview").is_visible() and current(p) == "Overview"


def test_the_status_line_says_what_a_reload_turned_off_and_could_not_keep(browser, synthetic_case):  # noqa: F811
    """A Case overview number sets the View and lists its events, and the Sources hide a host. After F5 the page is back on
    the Timeline with the Details panel's opening hint, and the status line says the list is not kept and both filters
    are off, as on every load."""
    def marks(app):
        api_mark(app, {"uids": [uid_at(app, T0)], "value": "malicious"})

    for p in served_page(browser, synthetic_case, setup=marks):
        p.locator("#filtersButton").click()
        p.locator("#fpTree").get_by_role("checkbox", name="Show DESKTOP", exact=True).uncheck()
        p.wait_for_function("() => window.__app.S.filter.hide.length === 1 && window.__app.S.filterId !== null")
        p.locator("#filtersButton").click()
        p.locator("#tabOverview").click()
        p.locator("#ovProgress .ov-legend button").first.click()   # the Sources stay on
        p.wait_for_selector("#details[data-page='opened'] li.rel-row")
        assert p.evaluate("() => [window.__app.S.filter.hide.length, window.__app.S.viewSpec.marks]") == [1, ["Malicious"]]
        reload(p)
        p.wait_for_function("(text) => (document.getElementById('status').title || '').startsWith(text)", arg=BACK)
        assert status(p) == (f"{BACK} Its list of events is not kept across a reload. The reload turned the Sources and View "
                             "filters off, as every load does.")
        assert current(p) == "Timeline" and p.locator("#details .hint").is_visible()
        assert p.evaluate("() => [window.__app.S.viewSpec, window.__app.S.filterId]") == [None, None]


def test_a_reload_on_findings_still_names_the_event_in_focus(browser, synthetic_case):  # noqa: F811
    """With an event in focus, Findings' New finding names it, as "the 4624 on DC01". After F5 on Findings, which draws
    the Findings page and not the event's, the button still names the event, and the reload's own fetch of it leaves
    the Findings page on screen."""
    for p in served_page(browser, synthetic_case):
        uid = first_logon(p)
        open_event(p, uid)
        p.locator("#tabFindings").click()
        p.wait_for_selector("#details[data-page='findings']")
        new = p.locator("#details .inv-head button")
        before = new.inner_text()
        assert before.startswith("New finding from the 4624 on ")
        reload(p)
        p.wait_for_function("(text) => (document.getElementById('status').title || '').startsWith(text)", arg=BACK)
        assert new.inner_text() == before
        assert p.evaluate("document.getElementById('details').dataset.page") == "findings"


def back_on_findings(p):
    """F5, and wait until the reload has drawn the Findings page and said so on the status line."""
    reload(p)
    p.wait_for_function("(text) => (document.getElementById('status').title || '').startsWith(text)", arg=BACK)
    p.wait_for_selector(f"{FINDINGS} .findings-col")


def form_fields(form):
    """An open finding form's title, severity, narrative, and the ATT&CK techniques picked, in order."""
    return (form.get_by_label("Title").input_value(), form.get_by_label("Severity").input_value(),
            form.get_by_label("Narrative").input_value(),
            form.locator(".attack-chip").evaluate_all("(chips) => chips.map((c) => c.dataset.technique)"))


def finding_card(p, fid):
    return p.locator(f"{FINDINGS} .finding[data-finding='{fid}']")


def report_summary(p):
    """The report's Summary box, once the exports' read has filled it."""
    p.wait_for_function("() => !document.querySelector('#details .report-outline .ex-count')?.textContent.startsWith('…')")
    return p.locator("#details").get_by_label("Summary", exact=True)


def click_and_redraw(p, button):
    """Click `button`, which makes a change on the Findings page, and wait until the page has drawn again after it."""
    p.evaluate("() => { window.__drawnBefore = document.querySelector('#details .findings-page'); }")
    button.click()
    p.wait_for_function("() => { const page = document.querySelector('#details .findings-page'); "
                        "return page !== null && page !== window.__drawnBefore; }")


def test_a_reload_on_findings_brings_back_an_open_new_finding_form(browser, synthetic_case):  # noqa: F811
    """F5 with New finding's form open over two selected events brings the form back as it was: its title, severity,
    narrative, and picked ATT&CK techniques, still for the same two events, and the status line says the page is back.
    The finding added from it links both events."""
    found = {}

    def setup(app):
        found["rdp"], found["morty"] = uid_at(app, T0), uid_at(app, T0 + 60 * SEC)

    for p in served_page(browser, synthetic_case, setup=setup):
        select(p, [found["rdp"], found["morty"]])
        open_findings(p)
        p.locator("#details").get_by_role("button", name="New finding from the 2 selected events").click()
        form = p.locator(f"{FINDINGS} .finding-new .finding-form")
        form.get_by_label("Title").fill("RDP from the internet")
        form.get_by_label("Severity").select_option("High")
        pick_technique(form, "1021.001", "T1021.001")
        pick_technique(form, "valid accounts", "T1078")
        form.get_by_label("Narrative").fill("Administrator logged on over RDP.")
        before = form_fields(form)
        back_on_findings(p)
        assert form_fields(form) == before
        assert status(p) == BACK
        form.get_by_role("button", name="Add the finding with 2 events").click()
        p.locator(f"{FINDINGS} .finding", has_text="1. RDP from the internet").wait_for()
        assert p.locator("#details .finding-form").count() == 0   # the page drawn after the add opens no form again
        entry = entries(synthetic_case)[-1]
        assert (entry["op"], entry["title"], entry["severity"], entry["techniques"], entry["targets"]) == (
            "add", "RDP from the internet", "High", ["T1021.001", "T1078"], [found["rdp"], found["morty"]])


def test_a_reload_on_findings_brings_back_a_new_finding_form_over_the_ticked_events(browser, synthetic_case):  # noqa: F811
    """A new finding's form opened from Show them's ticked rows, with no event selected, is for those events. F5 brings
    it back for the same events, and the finding added from it links them."""
    found = {}

    def setup(app):
        found["uids"] = [uid_at(app, T0), uid_at(app, T0 + 60 * SEC)]
        api_mark(app, {"uids": found["uids"], "value": "malicious"})

    for p in served_page(browser, synthetic_case, setup=setup):
        open_findings(p)
        details = p.locator("#details")
        details.locator(".unassigned").get_by_role("button", name="Show them").click()
        rows = details.locator(".unassigned-list li.rel-row")
        p.wait_for_function("() => document.querySelectorAll('#details .unassigned-list li.rel-row').length === 2")
        rows.nth(0).locator("input").check()
        rows.nth(1).locator("input").check()
        details.get_by_role("button", name="New finding from the 2 ticked").click()
        form = p.locator(f"{FINDINGS} .finding-new .finding-form")
        form.get_by_label("Title").fill("Two marked logons")
        form.get_by_label("Severity").select_option("Medium")
        assert p.evaluate("window.__app.S.selected.size") == 0
        back_on_findings(p)
        assert form.get_by_label("Title").input_value() == "Two marked logons"
        add = form.get_by_role("button", name="Add the finding")
        assert add.inner_text() == "Add the finding with 2 events"
        add.click()
        p.locator(f"{FINDINGS} .finding", has_text="1. Two marked logons").wait_for()
        entry = entries(synthetic_case)[-1]
        assert (entry["op"], entry["title"], sorted(entry["targets"])) == ("add", "Two marked logons", sorted(found["uids"]))


def reloaded_with_the_findings_unread(p):
    """On Findings, open a new finding's form and type its title and the Summary's words, then F5 while the findings
    can't be read. Waits for the page that says so, and returns the form's locator."""
    open_findings(p)
    p.locator("#details .inv-head").get_by_role("button", name="New finding").click()
    form = p.locator(f"{FINDINGS} .finding-new .finding-form")
    form.get_by_label("Title").fill("Kept through a failed read")
    report_summary(p).fill("Typed and not saved.")
    failing = lambda url: urlsplit(url).path == "/api/findings_page"
    p.route(failing, refused_with("The findings are busy."))
    reload(p)
    p.wait_for_selector(f"{FINDINGS} >> text=Could not load the findings: The findings are busy.")
    assert p.locator(FINDINGS).get_by_text("are kept until the page loads").count() == 1
    p.unroute(failing)
    p.errors[:] = [e for e in p.errors if "/api/findings_page" not in e]   # that refusal was the point
    return form


def assert_the_draft_is_back(p, form):
    assert form.count() == 1
    assert form.get_by_label("Title").input_value() == "Kept through a failed read"
    assert report_summary(p).input_value() == "Typed and not saved."


def test_a_reload_whose_findings_read_fails_keeps_the_draft_for_the_next(browser, synthetic_case):  # noqa: F811
    """F5 on Findings with a new finding's form open and the Summary's words typed, while the findings can't be read:
    the page says so and that its forms and words are kept. The next F5, with the read working, brings them back."""
    for p in served_page(browser, synthetic_case):
        form = reloaded_with_the_findings_unread(p)
        back_on_findings(p)
        assert_the_draft_is_back(p, form)


def test_a_draft_kept_from_a_failed_read_waits_through_a_reload_on_another_step(browser, synthetic_case):  # noqa: F811
    """The draft a failed findings read kept waits for the Findings page to draw, whichever step a later F5 is made
    on: after the Timeline step and F5 there, the Findings step brings back the form and the Summary's words."""
    for p in served_page(browser, synthetic_case):
        form = reloaded_with_the_findings_unread(p)
        p.locator("#tabTimeline").click()
        p.wait_for_selector("#details[data-page='hint']")
        reload(p)
        p.wait_for_function("(text) => (document.getElementById('status').title || '').startsWith(text)", arg=BACK)
        assert current(p) == "Timeline" and p.locator("#details .finding-form").count() == 0
        open_findings(p)
        assert_the_draft_is_back(p, form)


def test_a_draft_a_reload_could_not_draw_comes_back_on_the_findings_step(browser, synthetic_case):  # noqa: F811
    """F5 on Findings with a new finding's form open, and an event opened while the reload reads the event in focus:
    the event keeps the panel, and the form waits for the Findings step, which brings it back."""
    for p in served_page(browser, synthetic_case):
        uid = first_logon(p)
        other = p.evaluate("(u) => window.__app.S.data.events.find((e) => e.uid !== u).uid", uid)
        open_event(p, uid)
        open_findings(p)
        p.locator("#details .inv-head button").click()
        form = p.locator(f"{FINDINGS} .finding-new .finding-form")
        form.get_by_label("Title").fill("Kept while another page drew")
        held = []
        reading = lambda url: urlsplit(url).path == "/api/event"
        p.route(reading, holding_the_first(held))
        p.reload(wait_until="commit")
        wait_held(p, held)
        p.evaluate("(u) => import('/js/interaction.js').then((m) => m.select(u, false))", other)
        p.wait_for_selector(f"#details[data-key='event:{other}'] .ev-ident")
        held[0].continue_()
        p.wait_for_function(READY)
        p.unroute(reading)
        assert p.evaluate("document.getElementById('details').dataset.key") == f"event:{other}"
        open_findings(p)
        assert form.count() == 1
        assert form.get_by_label("Title").input_value() == "Kept while another page drew"


def test_a_reload_on_the_overview_over_findings_keeps_no_form_the_findings_step_would_not(
        browser, synthetic_case):  # noqa: F811
    """The Findings step draws its page anew, without the forms open when the analyst left it for another step. F5 on
    the overview, with the Findings page and an open form behind it, keeps no form either: the Findings step after it
    opens none."""
    for p in served_page(browser, synthetic_case):
        open_findings(p)
        p.locator("#details .inv-head").get_by_role("button", name="New finding").click()
        p.locator(f"{FINDINGS} .finding-new .finding-form").get_by_label("Title").fill("Left behind the overview")
        p.locator("#tabOverview").click()
        p.wait_for_selector("#overview", state="visible")
        reload(p)
        p.wait_for_function("(text) => (document.getElementById('status').title || '').startsWith(text)", arg=BACK)
        assert current(p) == "Overview"
        open_findings(p)
        assert p.locator("#details .finding-form").count() == 0


def test_a_reload_on_findings_brings_back_an_open_edit_form(browser, synthetic_case):  # noqa: F811
    """F5 with a finding's Edit form open brings that card back in edit mode with the fields as the analyst left them,
    a technique removed and another picked among them; Save changes then sends what changed from the finding."""
    found = {}

    def setup(app):
        rdp = uid_at(app, T0)
        found["fid"] = api_finding(app, {"op": "add", "title": "A logon", "severity": "Low", "narrative": "First words.",
                                         "techniques": ["T1078"], "targets": [rdp]})["finding"]

    for p in served_page(browser, synthetic_case, setup=setup):
        open_findings(p)
        card = finding_card(p, found["fid"])
        card.get_by_role("button", name="Edit").click()
        form = card.locator(".finding-form")
        form.get_by_label("Title").fill("RDP from the internet")
        form.get_by_label("Severity").select_option("Critical")
        form.get_by_label("Narrative").fill("Administrator logged on over RDP.")
        form.get_by_role("button", name="Remove T1078").click()
        pick_technique(form, "1021.001", "T1021.001")
        before = form_fields(form)
        assert before == ("RDP from the internet", "Critical", "Administrator logged on over RDP.", ["T1021.001"])
        back_on_findings(p)
        assert form_fields(form) == before
        assert status(p) == BACK
        click_and_redraw(p, form.get_by_role("button", name="Save changes"))
        assert card.locator(".finding-form").count() == 0
        assert card.locator(".finding-narr").inner_text() == "Administrator logged on over RDP."
        entry = entries(synthetic_case)[-1]
        assert (entry["op"], entry["finding"], entry["title"], entry["severity"], entry["narrative"],
                entry["techniques"]) == ("edit", found["fid"], *before)


def changed_since_opened(*fields):
    """What an Edit form says of the fields the finding changed after the form opened."""
    return (f"Changed since this form opened: {', '.join(fields)}. It shows the finding's current values, except in a field "
            "you edited, which keeps your words.")


def finding_to_edit(found):
    """A setup that adds a Low finding, A logon, and keeps its ID in `found`."""
    def setup(app):
        found["fid"] = api_finding(app, {"op": "add", "title": "A logon", "severity": "Low", "narrative": "First words.",
                                         "techniques": ["T1078"], "targets": [uid_at(app, T0)]})["finding"]

    return setup


def test_a_reload_keeps_a_title_another_tab_changed_when_the_edit_form_left_it_alone(browser, synthetic_case):  # noqa: F811
    """An Edit form with only the narrative changed, a title changed from another tab, and F5: the restored form shows
    the new title, says the title changed since the form opened, and Save changes sends the narrative alone. The new
    title stays, and the journal holds no title from this tab."""
    found = {}
    for p in served_page(browser, synthetic_case, setup=finding_to_edit(found)):
        open_findings(p)
        card = finding_card(p, found["fid"])
        card.get_by_role("button", name="Edit").click()
        form = card.locator(".finding-form")
        form.get_by_label("Narrative").fill("Administrator logged on over RDP.")
        api_finding(p.hub.app, {"op": "edit", "finding": found["fid"], "title": "Renamed elsewhere"})
        back_on_findings(p)
        assert form_fields(form) == ("Renamed elsewhere", "Low", "Administrator logged on over RDP.", ["T1078"])
        assert form.locator(".finding-changed").all_inner_texts() == [changed_since_opened("title")]
        click_and_redraw(p, form.get_by_role("button", name="Save changes"))
        assert card.locator(".finding-title").inner_text() == "1. Renamed elsewhere"
        assert card.locator(".finding-narr").inner_text() == "Administrator logged on over RDP."
        elsewhere, entry = entries(synthetic_case)[-2:]
        assert (elsewhere["op"], elsewhere["title"]) == ("edit", "Renamed elsewhere")
        assert (entry["op"], entry["finding"], entry["narrative"]) == ("edit", found["fid"], "Administrator logged on over RDP.")
        assert {"title", "severity", "techniques"}.isdisjoint(entry)


def test_a_draft_kept_through_a_failed_findings_read_leaves_the_severity_another_tab_set(browser, synthetic_case):  # noqa: F811
    """An Edit form with only the narrative changed is kept by an F5 whose findings read fails. Another tab sets the
    severity to Critical, and the next F5 brings the form back showing Critical, with the severity named as changed.
    Save changes sends the narrative alone, and the finding stays Critical."""
    found = {}
    for p in served_page(browser, synthetic_case, setup=finding_to_edit(found)):
        open_findings(p)
        card = finding_card(p, found["fid"])
        card.get_by_role("button", name="Edit").click()
        form = card.locator(".finding-form")
        form.get_by_label("Narrative").fill("Administrator logged on over RDP.")
        failing = lambda url: urlsplit(url).path == "/api/findings_page"
        p.route(failing, refused_with("The findings are busy."))
        reload(p)
        p.wait_for_selector(f"{FINDINGS} >> text=Could not load the findings: The findings are busy.")
        p.unroute(failing)
        p.errors[:] = [e for e in p.errors if "/api/findings_page" not in e]   # that refusal was the point
        api_finding(p.hub.app, {"op": "edit", "finding": found["fid"], "severity": "Critical"})
        back_on_findings(p)
        assert form_fields(form) == ("A logon", "Critical", "Administrator logged on over RDP.", ["T1078"])
        assert form.locator(".finding-changed").all_inner_texts() == [changed_since_opened("severity")]
        click_and_redraw(p, form.get_by_role("button", name="Save changes"))
        assert card.locator(".chip").inner_text() == "Critical"
        entry = entries(synthetic_case)[-1]
        assert (entry["op"], entry["finding"], entry["narrative"]) == ("edit", found["fid"], "Administrator logged on over RDP.")
        assert {"title", "severity", "techniques"}.isdisjoint(entry)


def test_a_reload_keeps_the_words_typed_in_a_field_another_tab_changed_and_names_it(browser, synthetic_case):  # noqa: F811
    """Title and severity are changed from another tab after an Edit form's title was edited. After F5 the form keeps the
    title as typed and shows the new severity, and the line names both as changed. After a second F5 the form is the same
    and the line names the title, since the severity has been shown. Save changes sends the title typed: an edit the
    analyst made, and not the severity, which the analyst did not touch."""
    found = {}
    for p in served_page(browser, synthetic_case, setup=finding_to_edit(found)):
        open_findings(p)
        card = finding_card(p, found["fid"])
        card.get_by_role("button", name="Edit").click()
        form = card.locator(".finding-form")
        form.get_by_label("Title").fill("Mine")
        api_finding(p.hub.app, {"op": "edit", "finding": found["fid"], "title": "Theirs", "severity": "High"})
        for named in (("title", "severity"), ("title",)):
            back_on_findings(p)
            assert form_fields(form) == ("Mine", "High", "First words.", ["T1078"])
            assert form.locator(".finding-changed").all_inner_texts() == [changed_since_opened(*named)]
        click_and_redraw(p, form.get_by_role("button", name="Save changes"))
        assert card.locator(".finding-title").inner_text() == "1. Mine" and card.locator(".chip").inner_text() == "High"
        entry = entries(synthetic_case)[-1]
        assert (entry["op"], entry["finding"], entry["title"]) == ("edit", found["fid"], "Mine")
        assert {"severity", "narrative", "techniques"}.isdisjoint(entry)


def test_a_field_set_back_to_its_value_from_when_the_form_opened_is_saved_over_a_change_from_another_tab(browser, synthetic_case):  # noqa: F811
    """The title is edited in an Edit form, another tab changes it, and F5 brings the form back with the title as typed.
    The title is then set back to what it was when the form opened. Save changes writes that title over the other tab's,
    since the form shows it, and the journal entry holds the title alone."""
    found = {}
    for p in served_page(browser, synthetic_case, setup=finding_to_edit(found)):
        open_findings(p)
        card = finding_card(p, found["fid"])
        card.get_by_role("button", name="Edit").click()
        form = card.locator(".finding-form")
        form.get_by_label("Title").fill("Mine")
        api_finding(p.hub.app, {"op": "edit", "finding": found["fid"], "title": "Theirs"})
        back_on_findings(p)
        assert form_fields(form)[0] == "Mine"
        assert form.locator(".finding-changed").all_inner_texts() == [changed_since_opened("title")]
        form.get_by_label("Title").fill("A logon")
        click_and_redraw(p, form.get_by_role("button", name="Save changes"))
        assert card.locator(".finding-title").inner_text() == "1. A logon"
        entry = entries(synthetic_case)[-1]
        assert (entry["op"], entry["finding"], entry["title"]) == ("edit", found["fid"], "A logon")
        assert {"severity", "narrative", "techniques"}.isdisjoint(entry)


@pytest.mark.parametrize("changed_again", [False, True], ids=["not changed again", "changed again"])
def test_a_field_set_back_stays_set_back_through_a_second_reload(browser, synthetic_case, changed_again):  # noqa: F811
    """The title is edited, another tab changes it, F5 brings the form back, and the title is set back to what it was
    when the form opened. After a second F5 the form still shows that title, with a line naming the title only when the
    other tab changed it again in between. Save changes writes the title and the narrative typed, and no other field."""
    found = {}
    for p in served_page(browser, synthetic_case, setup=finding_to_edit(found)):
        open_findings(p)
        card = finding_card(p, found["fid"])
        card.get_by_role("button", name="Edit").click()
        form = card.locator(".finding-form")
        form.get_by_label("Title").fill("Mine")
        form.get_by_label("Narrative").fill("Administrator logged on over RDP.")
        api_finding(p.hub.app, {"op": "edit", "finding": found["fid"], "title": "Theirs"})
        back_on_findings(p)
        assert form_fields(form)[0] == "Mine"
        form.get_by_label("Title").fill("A logon")
        if changed_again:
            api_finding(p.hub.app, {"op": "edit", "finding": found["fid"], "title": "Theirs again"})
        back_on_findings(p)
        assert form_fields(form) == ("A logon", "Low", "Administrator logged on over RDP.", ["T1078"])
        assert form.locator(".finding-changed").all_inner_texts() == ([changed_since_opened("title")] if changed_again else [])
        click_and_redraw(p, form.get_by_role("button", name="Save changes"))
        assert card.locator(".finding-title").inner_text() == "1. A logon"
        entry = entries(synthetic_case)[-1]
        assert (entry["op"], entry["finding"], entry["title"], entry["narrative"]) == (
            "edit", found["fid"], "A logon", "Administrator logged on over RDP.")
        assert {"severity", "techniques"}.isdisjoint(entry)


@pytest.mark.parametrize("narrative", [None, "Administrator logged on over RDP."], ids=["title only", "title and narrative"])
def test_a_field_edited_to_the_value_another_tab_set_is_not_written_again(browser, synthetic_case, narrative):  # noqa: F811
    """The title typed in an Edit form is the title another tab sets. After F5, Save changes writes the narrative alone
    when it was changed too, and with nothing else changed closes the form and writes nothing."""
    found = {}
    for p in served_page(browser, synthetic_case, setup=finding_to_edit(found)):
        open_findings(p)
        card = finding_card(p, found["fid"])
        card.get_by_role("button", name="Edit").click()
        form = card.locator(".finding-form")
        form.get_by_label("Title").fill("Theirs")
        if narrative:
            form.get_by_label("Narrative").fill(narrative)
        api_finding(p.hub.app, {"op": "edit", "finding": found["fid"], "title": "Theirs"})
        back_on_findings(p)
        written = len(entries(synthetic_case))
        if narrative:
            click_and_redraw(p, form.get_by_role("button", name="Save changes"))
            entry = entries(synthetic_case)[-1]
            assert (entry["op"], entry["finding"], entry["narrative"]) == ("edit", found["fid"], narrative)
            assert {"title", "severity", "techniques"}.isdisjoint(entry)
        else:
            form.get_by_role("button", name="Save changes").click()
            form.wait_for(state="detached")
            assert len(entries(synthetic_case)) == written
        assert card.locator(".finding-title").inner_text() == "1. Theirs"


def test_a_second_reload_shows_a_title_another_tab_changed_again_since_the_first(browser, synthetic_case):  # noqa: F811
    """Another tab changes the title, F5 brings the Edit form back showing it, the other tab changes it again, and a
    second F5 shows the newest title with the title named as changed. Save changes sends the narrative alone."""
    found = {}
    for p in served_page(browser, synthetic_case, setup=finding_to_edit(found)):
        open_findings(p)
        card = finding_card(p, found["fid"])
        card.get_by_role("button", name="Edit").click()
        form = card.locator(".finding-form")
        form.get_by_label("Narrative").fill("Administrator logged on over RDP.")
        for title in ("Second title", "Third title"):
            api_finding(p.hub.app, {"op": "edit", "finding": found["fid"], "title": title})
            back_on_findings(p)
            assert form_fields(form)[0] == title
            assert form.locator(".finding-changed").all_inner_texts() == [changed_since_opened("title")]
        click_and_redraw(p, form.get_by_role("button", name="Save changes"))
        assert card.locator(".finding-title").inner_text() == "1. Third title"
        entry = entries(synthetic_case)[-1]
        assert (entry["op"], entry["finding"], entry["narrative"]) == ("edit", found["fid"], "Administrator logged on over RDP.")
        assert {"title", "severity", "techniques"}.isdisjoint(entry)


def test_an_edit_form_that_nothing_changed_under_says_nothing_after_a_reload(browser, synthetic_case):  # noqa: F811
    """With no change from another tab, the restored Edit form has no line about changes."""
    found = {}
    for p in served_page(browser, synthetic_case, setup=finding_to_edit(found)):
        open_findings(p)
        card = finding_card(p, found["fid"])
        card.get_by_role("button", name="Edit").click()
        card.get_by_label("Narrative").fill("Administrator logged on over RDP.")
        back_on_findings(p)
        assert card.get_by_label("Narrative").input_value() == "Administrator logged on over RDP."
        assert card.locator(".finding-changed").count() == 0


def test_a_reload_on_findings_brings_back_the_summary_s_unsaved_text(browser, synthetic_case):  # noqa: F811
    """F5 with words typed in the report's Summary and not saved brings them back in the box; they are still not saved."""
    for p in served_page(browser, synthetic_case, setup=lambda app: api_setting(app, {"name": "report_summary",
                                                                                      "value": "Saved words."})):
        open_findings(p)
        summary = report_summary(p)
        assert summary.input_value() == "Saved words."
        summary.fill("Saved words, then more typed and not saved.")
        back_on_findings(p)
        assert report_summary(p).input_value() == "Saved words, then more typed and not saved."
        assert status(p) == BACK
        assert p.hub.app.journal.state.settings["report_summary"] == "Saved words."


def test_a_saved_finding_form_or_summary_leaves_no_draft_for_a_reload(browser, synthetic_case):  # noqa: F811
    """A finding added or edited closes its form, and F5 then opens no form. A saved Summary is no draft either: after
    it is changed elsewhere, F5 shows that change, not the words saved here."""
    found = {}
    for p in served_page(browser, synthetic_case, setup=lambda app: found.update(rdp=uid_at(app, T0))):
        select(p, [found["rdp"]])
        open_findings(p)
        details = p.locator("#details")
        details.locator(".inv-head button").click()
        form = details.locator(".finding-new .finding-form")
        form.get_by_label("Title").fill("RDP from the internet")
        form.get_by_label("Severity").select_option("High")
        form.get_by_role("button", name="Add the finding with 1 event").click()
        p.locator(f"{FINDINGS} .finding", has_text="1. RDP from the internet").wait_for()
        fid = entries(synthetic_case)[-1]["seq"]
        assert details.locator(".finding-form").count() == 0
        back_on_findings(p)
        assert details.locator(".finding-form").count() == 0
        finding_card(p, fid).get_by_role("button", name="Edit").click()
        finding_card(p, fid).get_by_label("Title").fill("RDP from outside")
        finding_card(p, fid).get_by_role("button", name="Save changes").click()
        p.wait_for_function("(fid) => !document.querySelector(`#details .finding[data-finding='${fid}'] .finding-form`)",
                            arg=fid)
        summary = report_summary(p)
        summary.fill("Saved here.")
        details.get_by_role("button", name="Save summary").click()
        p.wait_for_function("() => document.querySelector('#details .report-outline .ex-count').textContent"
                            " === 'written: 2 words'")
        api_setting(p.hub.app, {"name": "report_summary", "value": "Changed elsewhere."})
        back_on_findings(p)
        assert details.locator(".finding-form").count() == 0
        assert report_summary(p).input_value() == "Changed elsewhere."
        assert status(p) == BACK


def test_a_reload_says_when_the_finding_being_edited_was_retired_meanwhile(browser, synthetic_case):  # noqa: F811
    """An Edit form can't come back on a finding retired since the page was left, as from another tab: F5 shows the
    finding under Retired findings, and the status line says its changes are not kept."""
    ids = {}

    def setup(app):
        ids["fid"] = api_finding(app, {"op": "add", "title": "A logon", "severity": "Low", "targets": [uid_at(app, T0)]})[
            "finding"]

    for p in served_page(browser, synthetic_case, setup=setup):
        open_findings(p)
        finding_card(p, ids["fid"]).get_by_role("button", name="Edit").click()
        finding_card(p, ids["fid"]).get_by_label("Title").fill("RDP from the internet")
        api_finding(p.hub.app, {"op": "retire", "finding": ids["fid"], "reason": "Elsewhere."})
        back_on_findings(p)
        assert p.locator("#details .finding-form").count() == 0
        assert status(p) == f"{BACK} The finding being edited was retired, so its changes are not kept."


def test_the_findings_step_says_when_a_kept_edit_form_s_finding_was_retired(browser, synthetic_case):  # noqa: F811
    """An Edit form a failed findings read kept can't open on a finding retired since. The Findings step, which then draws
    the page with the rest of the draft, says on the status line that the form's changes are not kept."""
    ids = {}

    def setup(app):
        ids["fid"] = api_finding(app, {"op": "add", "title": "A logon", "severity": "Low", "targets": [uid_at(app, T0)]})[
            "finding"]

    for p in served_page(browser, synthetic_case, setup=setup):
        open_findings(p)
        finding_card(p, ids["fid"]).get_by_role("button", name="Edit").click()
        finding_card(p, ids["fid"]).get_by_label("Title").fill("RDP from the internet")
        report_summary(p).fill("Typed and not saved.")
        failing = lambda url: urlsplit(url).path == "/api/findings_page"
        p.route(failing, refused_with("The findings are busy."))
        reload(p)
        p.wait_for_selector(f"{FINDINGS} >> text=Could not load the findings: The findings are busy.")
        p.unroute(failing)
        p.errors[:] = [e for e in p.errors if "/api/findings_page" not in e]   # that refusal was the point
        api_finding(p.hub.app, {"op": "retire", "finding": ids["fid"], "reason": "Elsewhere."})
        p.locator("#tabTimeline").click()
        p.wait_for_selector("#details[data-page='hint']")
        open_findings(p)
        assert report_summary(p).input_value() == "Typed and not saved."
        assert p.locator("#details .finding-form").count() == 0
        assert status(p) == "The finding being edited was retired, so its changes are not kept."


def test_new_finding_from_an_event_page_opens_the_kept_form_s_words_over_its_event(browser, synthetic_case):  # noqa: F811
    """A new finding's form a failed findings read kept waits for the Findings page. New finding… from an Event page
    draws that page with the form over the event, holding the kept title, beside the Summary's kept words, and the status
    line says so. The finding added from it links that event."""
    for p in served_page(browser, synthetic_case):
        form = reloaded_with_the_findings_unread(p)
        uid = first_logon(p)
        open_event(p, uid)
        details = p.locator("#details")
        details.get_by_role("button", name="+ Finding").click()
        p.wait_for_function("() => document.querySelector('#details .finding-add select option[value=\"new\"]') !== null")
        picker = details.locator(".finding-add")
        picker.get_by_label("Finding to add to").select_option("new")
        picker.get_by_role("button", name=re.compile("^Add ")).click()
        p.wait_for_selector(f"{FINDINGS} .finding-new .finding-form")
        assert_the_draft_is_back(p, form)
        assert status(p).startswith("The new finding's form kept from before the reload is back with what was typed in it,")
        form.get_by_label("Severity").select_option("High")
        form.get_by_role("button", name="Add the finding with 1 event").click()
        p.locator(f"{FINDINGS} .finding", has_text="1. Kept through a failed read").wait_for()
        entry = entries(synthetic_case)[-1]
        assert (entry["op"], entry["title"], entry["targets"]) == ("add", "Kept through a failed read", [uid])


def test_new_finding_from_an_event_page_says_what_of_the_kept_draft_came_back_and_what_did_not(browser, synthetic_case):  # noqa: F811
    """A failed findings read keeps a new finding's form and an Edit form, and the finding being edited is retired
    meanwhile. New finding… from an Event page opens the kept form's words over the event, and the status line says
    both that and that the Edit form's changes are not kept."""
    ids = {}

    def setup(app):
        ids["fid"] = api_finding(app, {"op": "add", "title": "A logon", "severity": "Low", "targets": [uid_at(app, T0)]})[
            "finding"]

    for p in served_page(browser, synthetic_case, setup=setup):
        open_findings(p)
        p.locator("#details .inv-head").get_by_role("button", name="New finding").click()
        form = p.locator(f"{FINDINGS} .finding-new .finding-form")
        form.get_by_label("Title").fill("Kept through a failed read")
        finding_card(p, ids["fid"]).get_by_role("button", name="Edit").click()
        finding_card(p, ids["fid"]).get_by_label("Title").fill("RDP from the internet")
        failing = lambda url: urlsplit(url).path == "/api/findings_page"
        p.route(failing, refused_with("The findings are busy."))
        reload(p)
        p.wait_for_selector(f"{FINDINGS} >> text=Could not load the findings: The findings are busy.")
        p.unroute(failing)
        p.errors[:] = [e for e in p.errors if "/api/findings_page" not in e]   # that refusal was the point
        api_finding(p.hub.app, {"op": "retire", "finding": ids["fid"], "reason": "Elsewhere."})
        open_event(p, first_logon(p))
        details = p.locator("#details")
        details.get_by_role("button", name="+ Finding").click()
        p.wait_for_function("() => document.querySelector('#details .finding-add select option[value=\"new\"]') !== null")
        picker = details.locator(".finding-add")
        picker.get_by_label("Finding to add to").select_option("new")
        picker.get_by_role("button", name=re.compile("^Add ")).click()
        p.wait_for_selector(f"{FINDINGS} .finding-new .finding-form")
        assert form.get_by_label("Title").input_value() == "Kept through a failed read"
        said = status(p)
        assert said.startswith("The new finding's form kept from before the reload is back with what was typed in it,")
        assert said.endswith(" The finding being edited was retired, so its changes are not kept.")


def holding_the_first(held):
    """A route handler that holds the first request it sees in `held` and lets the later ones through."""
    def handle(route):
        if held:
            route.continue_()
        else:
            held.append(route)
    return handle


def test_an_event_opened_while_a_reload_reads_the_event_in_focus_keeps_the_panel(browser, synthetic_case):  # noqa: F811
    """After F5 on Findings, the reload reads the event in focus before it draws Findings. An event the analyst opens
    during that read keeps the panel, and the reload doesn't draw Findings over it."""
    for p in served_page(browser, synthetic_case):
        uid = first_logon(p)
        other = p.evaluate("(u) => window.__app.S.data.events.find((e) => e.uid !== u).uid", uid)
        open_event(p, uid)
        p.locator("#tabFindings").click()
        p.wait_for_selector("#details[data-page='findings']")
        held = []
        p.route(lambda url: urlsplit(url).path == "/api/event", holding_the_first(held))
        p.reload(wait_until="commit")
        wait_held(p, held)
        p.evaluate("(u) => import('/js/interaction.js').then((m) => m.select(u, false))", other)
        p.wait_for_selector(f"#details[data-key='event:{other}'] .ev-ident")
        held[0].continue_()
        p.wait_for_function(READY)
        assert p.evaluate("document.getElementById('details').dataset.key") == f"event:{other}"
