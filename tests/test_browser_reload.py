"""A reload comes back to the page that was shown, in a real browser. F5 in the same
tab and serve run brings back the path's step, the Details page with its pivot list and trail, the selection, the search
box, the Lanes preset, and the timeline's window, and on the overview keeps the Details page behind it. A new tab, the
link opened again in the same tab, another open of the case, and blocked storage still start on the Case overview,
and the status line says what a reload drops. They drive the installed Microsoft Edge through Playwright, as
test_browser_smoke does, and are skipped without it."""

import pytest
from conftest import T0
from test_browser_findings import uid_at
from test_browser_smoke import browser, case_menu, served_page, to_timeline  # noqa: F401

from glessner.server import api_mark

pytestmark = pytest.mark.browser
READY = "() => window.__ready === true && window.__app.S.data !== null"
BACK = "Back where the page was before the reload."
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
