"""Browser smoke tests: the page's main interactions in a real browser, against the synthetic case.

They drive the installed Microsoft Edge through Playwright, so no browser is downloaded. Set
GLESSNER_BROWSER_CHANNEL=chrome to use Chrome instead. Skipped when Playwright or the browser is missing.
Deselect them with `-m "not browser"`.
"""

import getpass
import json
import os
import re
import threading
import time
from datetime import UTC, datetime

import pytest
from conftest import DC_LOG, SEC, T0, junction, logon, registry
from test_analysis_relations import UNTIMED_NOTE, load_untimed_pivots
from test_clock import AHEAD, accepted, evtx_time, flow, time_changed
from test_timezones import add_zone

from glessner.audit import read_entries
from glessner.case import open_case
from glessner.events import Event, load
from glessner.journal import JOURNAL_FILE
from glessner.server import Hub, serve_hub

playwright_api = pytest.importorskip("playwright.sync_api")

pytestmark = pytest.mark.browser
VIEWPORT = {"width": 1400, "height": 900}
# 30 s, not 10: under a full-suite run's load, a View filter round trip passed 10 s while it took under 1 s alone
# A wait that times out still fails the test.
PAGE_TIMEOUT_MS = 30_000
# The page's load keeps the full 30 s when a test shortens PAGE_TIMEOUT_MS to time out its ready wait: with two suites
# running at once, a load took over 2 s.
LOAD_TIMEOUT_MS = 30_000
# What the ready checks read, for the report when the page isn't ready in time, and how long the report waits for a
# stalled page to answer.
READ_TIMEOUT_MS = 5_000
READY_INPUTS = """() => ({
    ready: window.__ready ?? null,
    data: window.__app ? window.__app.S.data !== null : null,
    start_info: window.__start ? window.__start.info !== null : null,
})"""


@pytest.fixture(scope="module")
def browser():
    with playwright_api.sync_playwright() as pw:
        try:
            b = pw.chromium.launch(channel=os.environ.get("GLESSNER_BROWSER_CHANNEL", "msedge"))
        except playwright_api.Error as exc:
            pytest.skip(f"no browser to drive: {exc.message.splitlines()[0]}")
        yield b
        b.close()


@pytest.fixture
def page(browser, synthetic_case):
    """The app on a fresh case and a fresh browser profile, so per-browser preferences start clean."""
    add_zone(synthetic_case, "DC01", 1, {"TimeZoneKeyName": "Pacific Standard Time", "Bias": "480"})
    yield from served_page(browser, synthetic_case)


@pytest.fixture
def clock_page(browser, synthetic_case):
    """synthetic_case plus a capture that the hosts' clocks are checked against. DC01 and
    DESKTOP each logged 10 RDP connections 3,599.5 s after the capture's flows, as on the Szechuan case, and one kind
    of pair takes 10 to suggest an offset. DESKTOP's clock was set back an hour and forward again before them, as on
    the Szechuan case. WS02's 10 split into two groups, 3,599.5 s and 1,800 s, so they suggest nothing. All of it goes in this
    case only, so the other tests' lanes and counts stay the same."""
    flows, events = [], {"DC01": [], "DESKTOP": [], "WS02": []}

    def rdp(host, ip, port, start, skew):
        client = f"194.61.24.102:{port}"
        flows.append(flow(start, client, f"{ip}:3389"))
        events[host].append(accepted(start + skew, client, host))

    for i in range(10):
        rdp("DC01", "10.42.85.10", 51000 + i, T0 - 3480 * SEC + i * 20 * SEC, AHEAD)   # from 02:23:48 in the capture
        rdp("DESKTOP", "10.42.85.115", 52000 + i, T0 - 3400 * SEC + i * 20 * SEC, AHEAD)
        rdp("WS02", "10.42.85.120", 53000 + i, T0 - (3300 if i < 5 else 3000) * SEC + i * 20 * SEC,
            AHEAD if i < 5 else 1800 * SEC)
    back, forward = T0 - 7200 * SEC, T0 - 5400 * SEC   # host times: set back 3,599.6 s, then forward 3,599.2 s
    events["DESKTOP"] += [time_changed(evtx_time(back), evtx_time(back - 3_599_600_000)),
                          time_changed(evtx_time(forward), evtx_time(forward + 3_599_200_000))]
    hive = registry("WS02/Windows/System32/config/SYSTEM",
                    "ROOT\\ControlSet001\\Services\\Tcpip\\Parameters\\Interfaces\\{1}", "IPAddress", "10.42.85.120")
    loads = [("network", flows, "suricata"), *((h, e, "evtxecmd") for h, e in events.items()), ("WS02", [hive], "recmd")]
    for i, (host, loaded, tool) in enumerate(loads):
        load(synthetic_case.db_path, loaded, host=host, tool=tool, tool_version="t", run_id=f"clock-{i}",
             replaces_sources=[], staging_dir=synthetic_case.folder)
    yield from served_page(browser, synthetic_case)


def served_page(browser, case, setup=None, ready="() => window.__ready === true && window.__app.S.data !== null",
                tab="timeline", color_scheme="light", folds=False, share=0.5):
    """Serve a case, or the start page when case is None, open it in a new browser context, and fail the test on any
    page error, console error, or HTTP status of 400 or more. setup(app), when given, runs before the page opens. A case
    opens on its overview; `tab` "timeline" goes on to the timeline, as most tests start there, and
    "overview" stays. `color_scheme` is the one the browser reports, light or dark. The lanes open folded to their first
    level; every group is opened unless `folds` is true, since the tests here look for host rows. The
    Details panel opens at two-thirds of the stage, which leaves the lanes about eight rows; `share` seeds the
    browser's own preference, glessner.detailsShare, before the page loads, so the tests here keep the half-stage lanes
    they were written for, where the synthetic case's rows all fit; None leaves the default.
    Tests use it as a for loop that runs once, so a closure made in the loop's body runs within that pass, and ruff's
    B023 is silenced on it."""
    server, hub, url = serve_hub(Hub(case), 0)   # the start page when case is None
    app = hub.app
    if setup:
        setup(app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    context = browser.new_context(viewport=VIEWPORT, color_scheme=color_scheme)
    context.set_default_timeout(PAGE_TIMEOUT_MS)
    if case is not None and share is not None:
        context.add_init_script(f"try {{ if (localStorage.getItem('glessner.detailsShare') === null) "
                                f"localStorage.setItem('glessner.detailsShare', '{share}'); }} catch (_) {{}}")

    def close():
        context.close()
        server.shutdown()
        server.server_close()
        if hub.app:
            hub.app.con.close()

    p = context.new_page()
    p.errors, p.console = [], []
    # A start link that has not been used: the one in `url` works once, and a page that loses its session, as when its
    # storage is blocked and it reloads, takes a new one
    p.new_link = lambda: f"http://127.0.0.1:{server.server_address[1]}/?token={hub.new_token()}"
    p.hub = hub
    p.on("pageerror", lambda exc: p.errors.append(f"page error: {exc}"))
    p.on("console", lambda msg: p.console.append(f"{msg.type}: {msg.text}"))
    # Failed loads are checked by URL below; the console's own copy of them names no URL.
    p.on("console", lambda msg: p.errors.append(f"console: {msg.text}")
         if msg.type == "error" and not msg.text.startswith("Failed to load resource") else None)
    p.on("response", lambda res: p.errors.append(f"HTTP {res.status}: {res.url}") if res.status >= 400 else None)
    # A request that got no answer, such as one Windows refused or had no port left for (net::ERR_NO_BUFFER_SPACE).
    # Such a failure otherwise shows only as a 30 s wait. The page cancels requests of its own, as when the analyst
    # zooms on, and a navigation cancels those in flight: those end in net::ERR_ABORTED.
    p.on("requestfailed", lambda req: p.errors.append(f"request failed: {req.method} {req.url} {req.failure}")
         if req.failure != "net::ERR_ABORTED" else None)
    p.goto(url, timeout=LOAD_TIMEOUT_MS)
    try:
        p.wait_for_function(ready)
    except playwright_api.TimeoutError:
        report = not_ready(p, ready)
        close()
        pytest.fail(report)
    if case is not None and tab == "timeline":
        to_timeline(p)
    if case is not None and not folds:
        open_all(p)
    try:
        yield p
    except GeneratorExit:
        # The test body raised. A wait that timed out says little (a request Windows refused shows as a 30 s wait), so
        # print what the page lost, which pytest shows with the failure.
        if p.errors:
            print("page errors before the failure:", *p.errors, sep="\n")
        raise
    finally:
        errors = list(p.errors)
        close()
    assert errors == [], errors


def to_timeline(p):
    """Leave the Case overview, which a case opens on, for the timeline loaded behind it."""
    if p.locator("#overview").is_visible():
        p.locator("#tabTimeline").click()
        p.wait_for_selector("#overview", state="hidden")


def open_all(p):
    """Open every lane group, as the toolbar's Open all does: the lanes open folded to their first level,
    and most tests here look for host rows. The choice is kept for the case and preset, so a reload keeps them open; a
    preset change starts from that preset's own folds."""
    p.evaluate("() => import('/js/lanes.js').then((m) => m.openAll())")


def filtered_view(p):
    """Wait for the answer to the view the page asks for under a Sources or View change made inside the `with`. The page
    asks for it once the lanes have answered, and until it answers, the window's count and the status line's notes are
    still the last filter's. The answer's JSON holds the view's `count`."""
    return p.expect_response(lambda res: "/api/view?" in res.url and "&filter=" in res.url)


def wait_held(p, held, n=1):
    """Wait until a route that holds its requests in `held` holds `n` of them, and fail the test when it doesn't within
    PAGE_TIMEOUT_MS. The route's handler runs only while the page is waited on, so the wait is the page's."""
    deadline = time.monotonic() + PAGE_TIMEOUT_MS / 1000
    while len(held) < n:
        if time.monotonic() > deadline:
            pytest.fail(f"The route held {len(held)} of {n} requests after {PAGE_TIMEOUT_MS / 1000:g} s")
        p.wait_for_timeout(20)


# Whether the Sources panel's box for a host reads checked. The panel draws its boxes from the counts the filter shows,
# which it asks for when it opens and after each change, so until they answer a box can read the filter before.
HOST_BOX_CHECKED = ("([host, checked]) => "
                    "document.querySelector(`#fpTree input[aria-label=\"Show ${host}\"]`)?.checked === checked")

# Keep in window.__asked the path of each request the page's code makes from now on, as it makes it, and in
# window.__taken each path whose answer the page's code has finished with. A path joins __taken in a task queued when
# its JSON resolves, so after the page's code for that answer has run: that code goes on in microtasks.
RECORD_REQUESTS = """() => {
    window.__asked = [];
    window.__taken = [];
    const fetch = window.fetch.bind(window);
    window.fetch = async (path, opts) => {
        window.__asked.push(String(path));
        const res = await fetch(path, opts);
        const json = res.json.bind(res);
        res.json = () => json().then((body) => {
            setTimeout(() => window.__taken.push(String(path)));
            return body;
        });
        return res;
    };
}"""


def asked(p, prefix):
    """The paths starting with `prefix` that the page's code has asked for since RECORD_REQUESTS ran. The page runs this
    check once the task it is in has ended, so a request made in the same task as one the test waited on is listed."""
    return p.evaluate("(prefix) => window.__asked.filter((path) => path.startsWith(prefix))", prefix)


def refused_with(message):
    """A route handler that answers each request with HTTP 500 and `message` as the error."""
    return lambda route: route.fulfill(status=500, content_type="application/json", body=json.dumps({"error": message}))


def case_menu(p, item):
    """Choose an item of the Case menu, which holds the setup and record work."""
    p.locator("#caseMenuButton").click()
    p.locator(f"#{item}").click()


def not_ready(p, ready):
    """Why the page isn't ready: what the ready check reads, and the console's last messages. A page that can't answer
    within READ_TIMEOUT_MS is stalled; one that answers with the data not yet loaded is waiting for the server. The
    read is a wait rather than an evaluate: Playwright times a wait out from outside the page, while
    an evaluate waits for as long as the page's main thread stays busy."""
    try:
        inputs = p.wait_for_function(READY_INPUTS, timeout=READ_TIMEOUT_MS).json_value()
    except playwright_api.Error as exc:
        inputs = f"no answer ({exc.message.splitlines()[0]})"
    return (f"The page wasn't ready after {PAGE_TIMEOUT_MS / 1000:g} s. Ready check: {ready}. What it reads: {inputs}. "
            f"Last console messages: {p.console[-20:]}. Errors: {p.errors}")


def view(p):
    return p.evaluate("({...window.__app.S.view})")


# The page coordinates of a drawn tick: the lanes are scrolled so its row is in view first, since the lane area holds
# about eight rows at the Details panel's two-thirds default, and a click below it lands on the panel. The page's
# CSP forbids eval, so the test goes in as data rather than as code.
POINT = """(row, it, uid) => {
    const scroller = document.getElementById('scroller');
    if (row * 20 < scroller.scrollTop || row * 20 + 20 > scroller.scrollTop + scroller.clientHeight) {
        scroller.scrollTop = Math.max(0, row * 20 - Math.floor(scroller.clientHeight / 2));
    }
    const rect = document.getElementById('lanes').getBoundingClientRect();
    return { x: rect.left + it.x, y: rect.top + row * 20 + 10, uid };
}"""


def event_point(p, code, hit=False):
    """The page coordinates of the first drawn event with this event code, and a Hayabusa hit if `hit`."""
    point = p.evaluate(f"""([code, hit]) => {{
        const fn = (e) => e.code === code && (!hit || e.hit >= 3);
        for (const [row, items] of window.__app.S.index.entries()) {{
            for (const it of items || []) {{
                if (it.kind === 'event' && fn(it.e)) return ({POINT})(row, it, it.e.uid);
            }}
        }}
        return null;
    }}""", [code, hit])
    assert point, f"no drawn event with code {code}"
    return point


def point_of(p, uid):
    """The page coordinates where this event is drawn now. A mark moves an event to another group, and a new group opens
    folded, so a point taken before the mark lands elsewhere."""
    point = p.evaluate(f"""(uid) => {{
        for (const [row, items] of window.__app.S.index.entries()) {{
            for (const it of items || []) {{
                if (it.kind === 'event' && it.e.uid === uid) return ({POINT})(row, it, uid);
            }}
        }}
        return null;
    }}""", uid)
    assert point, f"the event {uid} isn't drawn"
    return point


def labels(p):
    return p.locator("#labels .row").all_inner_texts()


# Whether anything is drawn on the time axis: any pixel that isn't transparent.
AXIS_DRAWN = """() => { const c = document.getElementById('axis');
    return c.getContext('2d').getImageData(0, 0, c.width, c.height).data.some((v, i) => i % 4 === 3 && v > 0); }"""


def test_page_loads_with_lanes_for_both_hosts(page):
    text = "\n".join(labels(page))
    assert "DC01" in text and "DESKTOP" in text
    assert page.evaluate("window.__app.S.width") > 200
    assert "Could not start" not in page.locator("#status").inner_text()
    assert page.locator("#clockSwitch").is_hidden()   # no capture, so no clock to align


def test_a_page_not_ready_in_time_reports_what_it_read(browser, synthetic_case, monkeypatch):
    """A page that isn't ready in time fails the test with what the ready check reads and the console's last messages,
    so the report tells a stalled page from a slow server."""
    monkeypatch.setitem(globals(), "PAGE_TIMEOUT_MS", 2_000)
    never = "() => { console.warn('still waiting'); return false; }"
    with pytest.raises(pytest.fail.Exception) as failed:
        for _ in served_page(browser, synthetic_case, ready=never):
            pass
    report = str(failed.value)
    # What it reads depends on how far the page got in 2 s, which the test below checks on a loaded page.
    assert report.startswith(f"The page wasn't ready after 2 s. Ready check: {never}. What it reads: {{'ready': ")
    assert "'warning: still waiting'" in report


def test_the_report_reads_a_loaded_page(page):
    assert "What it reads: {'ready': True, 'data': True, 'start_info': None}." in not_ready(page, "() => false")


def test_a_stalled_page_fails_without_waiting_for_it(browser, synthetic_case, monkeypatch):
    """A page whose main thread stays busy can't answer the report's read, and the report says so rather than wait
    for it. Waiting would hang the suite for as long as the page stays busy."""
    monkeypatch.setitem(globals(), "PAGE_TIMEOUT_MS", 2_000)
    stall_s = 30
    stall = f"() => {{ const t = Date.now(); while (Date.now() - t < {stall_s * 1000}) {{}} return false; }}"
    started = time.monotonic()
    with pytest.raises(pytest.fail.Exception) as failed:
        for _ in served_page(browser, synthetic_case, ready=stall):
            pass
    assert "What it reads: no answer (" in str(failed.value)
    assert time.monotonic() - started < stall_s


def test_a_request_without_an_answer_fails_the_test_by_name(browser, synthetic_case):
    """A request that fails in the network, as Edge's did with net::ERR_NO_BUFFER_SPACE when Windows had no port left,
    fails the test and is named. One the page cancels doesn't."""
    def abort(route):
        route.abort("connectionrefused" if route.request.url.endswith("/refused") else "aborted")

    with pytest.raises(AssertionError) as failed:
        for page in served_page(browser, synthetic_case):
            page.route("**/probe/*", abort)
            page.evaluate("Promise.all(['refused', 'canceled'].map((n) => fetch('/probe/' + n).catch(() => null)))")
    report = str(failed.value)
    assert re.search(r"request failed: GET http://127\.0\.0\.1:\d+/probe/refused net::ERR_CONNECTION_REFUSED", report)
    assert "/probe/canceled" not in report


def test_click_opens_the_event_page_without_moving_the_timeline(page):
    before = view(page)
    rdp = event_point(page, "4624", hit=True)
    page.mouse.move(rdp["x"], rdp["y"])
    page.mouse.down()
    page.mouse.move(rdp["x"] + 2, rdp["y"])   # a wobble under the drag threshold still counts as a click
    page.mouse.up()
    page.wait_for_selector("#details[data-page='event'] .ev-ident")
    assert "DC01" in page.locator("#details .ev-ident").inner_text()
    assert "Local time on DC01" in page.locator("#details .ev-ident .time").get_attribute("title")   # the time's hover
    assert page.evaluate("[...window.__app.S.selected]") == [rdp["uid"]]
    assert view(page) == before   # no jump on a click


def test_drag_pans_and_the_wheel_zooms(page):
    before = view(page)
    box = page.locator("#lanes").bounding_box()
    y = box["y"] + box["height"] - 5   # below the lanes, where nothing is drawn
    page.mouse.move(box["x"] + 400, y)
    page.mouse.down()
    page.mouse.move(box["x"] + 300, y, steps=5)
    page.mouse.up()
    panned = view(page)
    assert panned["start"] > before["start"] and round(panned["end"] - panned["start"]) == round(before["end"] - before["start"])
    page.mouse.move(box["x"] + 400, y)
    page.mouse.wheel(0, -200)
    page.wait_for_function("(span) => window.__app.S.view.end - window.__app.S.view.start < span",
                           arg=panned["end"] - panned["start"])


def test_right_click_menu_marks_the_event(page):
    rdp = event_point(page, "4624", hit=True)
    page.mouse.click(rdp["x"], rdp["y"], button="right")
    menu = page.locator("#quickMenu")
    menu.get_by_role("menuitem", name="Mark Malicious").click()
    page.wait_for_function("""(uid) => window.__app.S.data.events.some((e) => e.uid === uid && e.mark === 'Malicious')""",
                           arg=rdp["uid"])
    assert menu.is_hidden()
    page.wait_for_selector("#flaggedCount:not([hidden])")
    assert page.locator("#flaggedCount").inner_text().strip().startswith("1")


def test_suggestions_page_and_back(page):
    page.locator("#investigateButton").click()
    page.wait_for_selector("#details[data-page='investigate']")
    page.locator("#details").get_by_role("button", name="hayabusa", exact=True).click()
    page.wait_for_selector("#details[data-page='suggestions']")
    assert "RDP from internet" in page.locator("#details").inner_text()
    page.locator("#details .back-bar button").click()
    page.wait_for_selector("#details[data-page='investigate']")


def test_to_investigate_lists_an_event_without_a_time_last_and_opens_it_in_place(browser, synthetic_case):
    """Rules match events without a time, so accepting a rule's suggestions can flag one. To investigate and the
    Suggestions page don't show its time as 1970-01-01 00:00:00, and a click doesn't move the timeline to 1970. It reads
    No time recorded, after the timed events, and a click opens its Event page without moving the timeline."""
    from glessner.events import Event
    from glessner.server import api_mark, api_rule

    bag = "DESKTOP/Users/rick/NTUSER.DAT"
    load(synthetic_case.db_path, [Event(None, "ShellBag without a time", "shellbags", bag, "bag1", "ShellBag loot")],
         host="DESKTOP", tool="sbecmd", tool_version="t", run_id="r9", replaces_sources=[bag],
         staging_dir=synthetic_case.folder)
    found = {}

    def flag(app):
        api_rule(app, {"op": "add", "text": "id: loot\nsuggest: malicious\nwhen: {field: artifact, equals: shellbags}\n"})
        rdp = app.con.execute("SELECT event_uid FROM events WHERE tool = 'evtxecmd' AND ts_us = ?", [T0]).fetchone()[0]
        api_mark(app, {"uids": [rdp], "value": "suspicious"})
        found["bag"] = app.con.execute("SELECT event_uid FROM events WHERE source_file = ?", [bag]).fetchone()[0]

    for page in served_page(browser, synthetic_case, setup=flag):
        details = page.locator("#details")
        page.locator("#investigateButton").click()
        page.wait_for_selector("#details[data-page='investigate']")
        # To investigate's question lists the first event itself, so an event with no time reads "no time" there
        row = details.locator(".rule[data-source='loot']")
        row.get_by_role("button", name="Accept all", exact=True).click()
        sample = row.locator(".confirm-sample div")
        sample.first.wait_for()
        assert sample.all_text_contents() == ["no time  DESKTOP  ShellBag loot"]   # not "orded"
        row.get_by_role("button", name="Cancel", exact=True).click()
        details.get_by_role("button", name="loot", exact=True).click()
        page.wait_for_selector("#details[data-page='suggestions']")
        assert details.locator(".sg-text").all_text_contents() == ["No time recorded  DESKTOP  ShellBag loot"]
        details.get_by_role("button", name="Accept all", exact=True).click()   # asks first, then acts
        block = details.locator(".confirm-block")
        block.get_by_role("button", name="Accept 1", exact=True).click()
        details.get_by_text("Nothing is pending from this source.").wait_for()
        page.locator("#investigateButton").click()
        items = page.locator("#details[data-page='investigate'] ul.worklist li.rel-row")
        items.nth(1).wait_for()
        cells = lambda row: [row.locator(sel).inner_text() for sel in (".rel-time", ".rel-host", ".rel-text")]
        assert cells(items.nth(0)) == ["2020-09-19 03:21:48.000000", "DC01", "4624 logon"]
        assert cells(items.nth(1)) == ["No time recorded", "DESKTOP", "ShellBag loot"]
        assert items.nth(1).locator(".inv-note").inner_text() == "Note: Accepted suggestion from loot"
        assert items.locator(".badge").all_inner_texts() == ["S", "M"]
        assert items.nth(1).locator("input.inv-tick").get_attribute("aria-label") == "Followed up: the DESKTOP event at no time"
        before = view(page)
        items.nth(1).click()
        page.wait_for_selector("#details[data-page='event'] .ev-ident")
        assert details.locator(".ev-ident .time").inner_text() == "No time"
        assert "DESKTOP" in details.locator(".ev-ident").inner_text()
        assert page.evaluate("[...window.__app.S.selected]") == [found["bag"]]
        assert view(page) == before


def test_pivots_from_an_event_without_a_time_list_the_first_with_no_gap(browser, synthetic_case, monkeypatch):
    """From an event without a time, Same IP at either end answers, and no pivot says the event has no host or no
    logon ID. The pivots list from the first in time order with no gap, the heading says first rather than nearest,
    and Same host within ± is not offered and says why."""
    from glessner import queries
    from glessner.server import api_mark

    untimed, _, by_time = load_untimed_pivots(synthetic_case)
    monkeypatch.setattr(queries, "RELATED_LIMIT", 2)
    for page in served_page(browser, synthetic_case, setup=lambda app: api_mark(app, {"uids": [untimed],
                                                                                      "value": "suspicious"})):
        details = page.locator("#details")
        page.locator("#investigateButton").click()
        page.locator("#details[data-page='investigate'] ul.worklist li.rel-row .rel-text").first.click()
        page.wait_for_selector("#details[data-page='event'] .ev-ident")
        assert details.locator(".ev-ident .time").inner_text() == "No time"
        assert "Same host within ±N s: This event has no time recorded." in details.locator(".pv-not").inner_text()
        assert details.get_by_role("button", name="Same host within ±").count() == 0
        related, row = page.locator("#relatedList"), ["2020-09-19 03:21:48.000000", "DESKTOP", "4624 logon"]
        for button, heading in ((details.get_by_role("button", name="Same source IP 10.0.0.5", exact=True),
                                 "The first 2 of 4 events with the same source IP"),
                                (details.get_by_role("button", name="Same IP at either end 10.0.0.5", exact=True),
                                 "10.0.0.5 at either end: the first 2 of 4 events")):
            button.click()
            related.locator("strong", has_text=heading).wait_for()
            assert related.locator("p.muted").all_text_contents() == [UNTIMED_NOTE]
            cells = [[r.locator(sel).inner_text() for sel in (".rel-time", ".rel-host", ".rel-text")]
                     for r in related.locator("li.rel-row").all()]
            assert cells == [row, row] and related.locator(".off").count() == 0   # no gap, so no Offset column
        assert page.evaluate("[...window.__app.S.related]") == by_time[:2]


def test_filter_panel_hides_a_host_and_clear_all_restores_it(page):
    page.locator("#filtersButton").click()
    tree = page.locator("#fpTree")
    tree.get_by_role("checkbox", name="Show DC01", exact=True).uncheck()
    page.wait_for_function("() => ![...document.querySelectorAll('#labels .row')].some((r) => r.textContent.includes('DC01'))")
    assert "Hiding DC01" in page.locator("#fpChips").inner_text()
    assert page.locator("#filterCount").inner_text() == "1 on"
    page.locator("#filterPanel").get_by_role("button", name="Clear all").click()
    page.wait_for_function("() => [...document.querySelectorAll('#labels .row')].some((r) => r.textContent.includes('DC01'))")
    assert page.locator("#filterCount").is_hidden()


DC01_DRAWN = "(drawn) => [...document.querySelectorAll('#labels .row')].some((r) => r.textContent.includes('DC01')) === drawn"
# Keep each text the status line takes from now on in window.__statusTexts. setStatus replaces the line's text node, and
# a replaced node keeps its text, so a text the line held only between two of the observer's callbacks is kept too.
STATUS_TEXTS = """() => {
    window.__statusTexts = [];
    new MutationObserver((records) => {
        for (const record of records) for (const node of record.addedNodes) window.__statusTexts.push(node.textContent);
    }).observe(document.getElementById('status'), { childList: true });
}"""


def test_the_sources_counts_of_a_filter_changed_since_are_dropped(page):
    """The Sources panel's boxes come from the counts the filter shows. Counts asked under a filter that has changed
    since they were asked are dropped when they answer: drawn, they would read DC01 hidden after it was shown again,
    and the next click on its box would hide it."""
    box = page.locator("#fpTree").get_by_role("checkbox", name="Show DC01", exact=True)
    page.locator("#filtersButton").click()
    with page.expect_response("**/api/shown?*"):   # the counts with DC01 hidden, asked once the filter is set
        box.uncheck()
    page.wait_for_function(HOST_BOX_CHECKED, arg=["DC01", False])
    page.wait_for_function(DC01_DRAWN, arg=False)
    page.locator("#filtersButton").click()
    held = []
    page.route("**/api/shown?*", lambda route: held.append(route))
    with page.expect_request("**/api/shown?*"):
        page.locator("#filtersButton").click()   # opened again, the panel asks for the counts with DC01 hidden
    box.check()   # no filter is left, so no counts are asked
    page.wait_for_function(DC01_DRAWN, arg=True)
    with page.expect_response("**/api/shown?*"):
        held[0].continue_()
    page.unroute("**/api/shown?*")
    # The page takes an answer as soon as it arrives, so half a second covers the redraw that taking it would make
    page.wait_for_timeout(500)
    assert box.is_checked() and page.locator("#filterCount").is_hidden()


@pytest.mark.parametrize("failed", [False, True], ids=["registered", "failed"])
def test_a_filter_registered_after_a_later_change_is_dropped(page, failed):
    """A Sources or View change registers its filter with the server, and the timeline redraws under the id it gets
    back. A registration that answers after a later change is dropped: taken, it would draw the filter that change
    replaced, here DC01 hidden after Clear all. One that fails then says nothing, since "Filter failed" would stand over
    the later change's filter."""
    box = page.locator("#fpTree").get_by_role("checkbox", name="Show DC01", exact=True)
    page.locator("#filtersButton").click()
    held = []
    page.route("**/api/filter", lambda route: held.append(route))
    with page.expect_request("**/api/filter"):
        box.uncheck()   # hides DC01, under a filter the server registers
    drawn = page.evaluate("window.__timings.length")
    # No filter is left, so nothing is registered and the timeline redraws at once
    page.locator("#filterPanel").get_by_role("button", name="Clear all").click()
    page.wait_for_function("(n) => window.__timings.length > n", arg=drawn)
    # Every text the status line takes from here on is kept: Clear all's redraws rewrite the line, and would hide a
    # "Filter failed" written before them
    page.evaluate(STATUS_TEXTS)
    with page.expect_response("**/api/filter"):
        if failed:
            held[0].fulfill(status=500, content_type="application/json", body=json.dumps({"error": "the server stopped"}))
        else:
            held[0].continue_()
    page.unroute("**/api/filter")
    page.errors[:] = [e for e in page.errors if "/api/filter" not in e]   # that refusal was the point
    # The page takes an answer as soon as it arrives, so half a second covers the redraw that taking it would make
    page.wait_for_timeout(500)
    assert page.evaluate("window.__app.S.filterId") is None
    assert page.evaluate(DC01_DRAWN, True) and box.is_checked()
    assert [text for text in page.evaluate("window.__statusTexts") if "Filter failed" in text] == []


def test_a_filter_change_made_while_an_earlier_one_draws_replaces_it(page):
    """applyFilter resolves to { id, applied }, where applied says whether its change is the filter in force once
    drawn. A change made while an earlier one's lanes reload replaces it, though the earlier registration answered
    first, so the earlier call resolves to applied false and the later one to applied true."""
    held = []

    def hold_first(route):   # the earlier change's reload of the lanes; the later one's goes through
        if held:
            route.continue_()
        else:
            held.append(route)

    page.route("**/api/lanes?*", hold_first)
    # Each call's result is kept in window and waited for there, since an evaluate that awaits it has no time limit
    with page.expect_request("**/api/lanes?*"):
        page.evaluate("() => import('/js/filters.js').then((m) => {"
                      " m.showOnly({ host: 'DC01' }).then((r) => { window.__earlier = r; }); })")
    wait_held(page, held)
    page.evaluate("() => import('/js/filters.js').then((m) => { m.clearFilters().then((r) => { window.__later = r; }); })")
    page.wait_for_function("() => window.__later !== undefined")
    assert page.evaluate("window.__later")["applied"]
    held[0].continue_()
    page.unroute("**/api/lanes?*")
    page.wait_for_function("() => window.__earlier !== undefined")
    assert page.evaluate("window.__earlier")["applied"] is False


OVERVIEW_DC01 = "#ovHosts tr[data-host='DC01'] td.num"


def test_events_opened_from_the_overview_are_not_listed_once_a_later_change_replaces_the_view(page):
    """A number on the Case overview sets a View and lists the View's events in the Details panel. When a later change
    replaces the View before the View's registration has answered, here Show all, the number's events are no longer what
    the timeline shows, so nothing is listed."""
    asked = []
    page.on("request", lambda req: asked.append(req.url) if "/api/view_events" in req.url else None)
    page.locator("#tabOverview").click()
    held = []
    page.route("**/api/filter", lambda route: held.append(route))
    with page.expect_request("**/api/filter"):
        page.locator(OVERVIEW_DC01).get_by_role("button").click()   # DC01's events, as a View
    page.locator("#viewButton").click()
    page.locator("#viewPanel").get_by_role("button", name="Show all").click()   # no filter is left to register
    page.wait_for_function("() => window.__app.S.viewSpec === null")
    wait_held(page, held)
    with page.expect_response("**/api/filter"):
        held[0].continue_()
    page.unroute("**/api/filter")
    # The page takes an answer as soon as it arrives, so half a second covers the request that taking it would make
    page.wait_for_timeout(500)
    assert asked == [] and page.locator("#details").get_attribute("data-page") != "opened"


def test_events_opened_from_the_overview_are_listed_when_a_later_sources_change_keeps_the_view(page):
    """When a Sources change replaces the filter of a View a Case overview number set before the View's registration has
    answered, the View stays. The events are listed under the id registered for the View: /api/view_events lists only a
    filter's View part, so the list holds the events the number stands for."""
    asked = []
    page.on("request", lambda req: asked.append(req.url) if "/api/view_events" in req.url else None)
    page.locator("#tabOverview").click()
    number = page.locator(OVERVIEW_DC01).get_by_role("button")
    stands_for = number.inner_text()
    held = []
    page.route("**/api/filter", lambda route: held.append(route))
    with page.expect_request("**/api/filter"):
        number.click()   # DC01's events, as a View
    page.locator("#filtersButton").click()
    with page.expect_request("**/api/filter"):
        page.locator("#fpTree").get_by_role("checkbox", name="Show DESKTOP", exact=True).uncheck()
    wait_held(page, held, 2)
    with filtered_view(page):   # the Sources change's registration answers first, and the timeline draws under it
        held[1].continue_()
    with page.expect_response("**/api/filter") as registered:
        held[0].continue_()
    page.unroute("**/api/filter")
    page.wait_for_selector("#details[data-page='opened']")
    assert [url.split("?")[1] for url in asked] == [f"filter={registered.value.json()['id']}"]
    assert page.locator("#details .sticky-head .actions > strong").inner_text() == f"{stands_for} events"


def test_a_page_opened_while_an_overview_number_sets_its_view_keeps_the_panel(page):
    """A number on the Case overview claims the Details panel when clicked, and lists its events there once its View
    has registered and drawn. A page the analyst opens meanwhile, here Rules, keeps the panel, and the list isn't asked
    for. The View's registration is held here until Rules shows."""
    page.locator("#tabOverview").click()
    held = []
    page.route("**/api/filter", lambda route: held.append(route))
    with page.expect_request("**/api/filter"):
        page.locator(OVERVIEW_DC01).get_by_role("button").click()   # DC01's events, as a View
    case_menu(page, "rulesButton")
    page.wait_for_selector("#details[data-page='rules']")
    page.evaluate(RECORD_REQUESTS)
    with page.expect_response("**/api/filter") as registered:
        held[0].continue_()
    page.unroute("**/api/filter")
    # The page asks for the list once the timeline has taken the view drawn under the View's filter
    page.wait_for_function("""(id) => window.__taken.some((path) => path.startsWith('/api/view?')
                              && new URLSearchParams(path.split('?')[1]).get('filter') === String(id))""",
                           arg=registered.value.json()["id"])
    assert asked(page, "/api/view_events") == []
    assert page.locator("#details").get_attribute("data-page") == "rules"


def test_zone_axis_from_the_hosts_zone_is_kept_across_a_reload(page):
    page.locator("#addZone").click()
    page.locator("#quickMenu").get_by_role("menuitem", name="Pacific").first.click()
    page.wait_for_selector(".zone-label")
    assert "Pacific" in page.locator(".zone-label").inner_text() or "Los_Angeles" in page.locator(".zone-label").inner_text()
    page.reload()
    page.wait_for_function("() => window.__ready === true")
    to_timeline(page)
    assert page.locator(".zone-label").count() == 1
    page.locator(".zone-label button").click()
    page.wait_for_function("() => document.querySelectorAll('.zone-label').length === 0")


def test_lane_label_divider_fits_the_longest_label(page):
    page.locator("#groupby").select_option(label="Role > Host > User")
    page.wait_for_function("() => window.__app.S.rows.some((r) => r.depth === 0 && r.key === 'role')")
    open_all(page)   # the preset opens folded; the user lanes are the longest labels
    page.wait_for_function("() => [...document.querySelectorAll('#labels .row')]"
                           ".some((r) => r.textContent.includes('Administrator'))")
    page.locator("#labelDivider").dblclick()
    cut = page.evaluate("[...document.querySelectorAll('#labels .row')].filter((r) => r.scrollWidth > r.clientWidth + 1).length")
    assert cut == 0


def test_details_divider_resizes_the_details_panel(page):
    """A drag down shrinks the panel: it opens at two-thirds of the stage, so a drag up soon meets the Timeline's
    minimum."""
    before = page.locator("#details").bounding_box()["height"]
    box = page.locator("#divider").bounding_box()
    x, y = box["x"] + box["width"] / 2, box["y"] + box["height"] / 2
    page.mouse.move(x, y)
    page.mouse.down()
    page.mouse.move(x, y + 120, steps=5)
    page.mouse.up()
    after = page.locator("#details").bounding_box()["height"]
    assert after < before - 100


def test_hosts_panel_lists_both_hosts(page):
    case_menu(page, "hostsButton")
    rows = page.locator("#hostsTable tbody tr").all_inner_texts()
    assert any("DC01" in r for r in rows) and any("DESKTOP" in r for r in rows)
    # An OS column after Role; this synthetic case has no SOFTWARE hive rows, so each host says so.
    headers = page.locator("#hostsTable thead th").all_inner_texts()
    assert headers[:4] == ["Host", "Role", "OS", "Needs review"]
    assert page.locator("#hostsTable tbody td.muted", has_text="Not recorded").count() == 2


def test_rapid_zoom_keeps_one_view_request_in_flight(page):
    """Canceled requests would keep the server busy and delay the last view by seconds, so the page sends one view
    request at a time and fetches the newest window when it returns. Responses are slowed here to the pace of a large
    case."""
    page.evaluate("""() => {
        const original = window.fetch;
        window.__inflight = 0; window.__maxInflight = 0;
        window.fetch = async (...args) => {
            const isView = String(args[0]).startsWith('/api/view');
            if (!isView) return original(...args);
            window.__inflight++; window.__maxInflight = Math.max(window.__maxInflight, window.__inflight);
            try { await new Promise((r) => setTimeout(r, 400)); return await original(...args); }
            finally { window.__inflight--; }
        };
    }""")
    box = page.locator("#lanes").bounding_box()
    page.mouse.move(box["x"] + 500, box["y"] + 10)
    for _ in range(12):
        page.mouse.wheel(0, -100)
        page.wait_for_timeout(150)
    page.wait_for_function("""() => { const { S } = window.__app;
        return S.data.start === Math.floor(S.view.start * 1000) && S.data.end === Math.ceil(S.view.end * 1000); }""")
    assert page.evaluate("window.__maxInflight") == 1


def test_view_flyout_builds_the_chain(page):
    """Show the chain, pivot, see hidden results faded, mark what belongs, and it stays."""
    rdp = event_point(page, "4624", hit=True)
    page.mouse.click(rdp["x"], rdp["y"], button="right")
    page.locator("#quickMenu").get_by_role("menuitem", name="Mark Malicious").click()
    page.wait_for_function("(uid) => window.__app.S.data.events.some((e) => e.uid === uid && e.mark === 'Malicious')",
                           arg=rdp["uid"])
    page.locator("#viewButton").click()
    page.locator("#viewPanel").get_by_role("button", name="Chain", exact=True).click()
    page.wait_for_function("""() => { const rows = [...document.querySelectorAll('#labels .row')].map((r) => r.textContent);
        return rows.some((t) => t.includes('Malicious')) && !rows.some((t) => t.includes('Unreviewed')); }""")
    assert page.locator("#viewCount").inner_text() == "2 on"
    page.evaluate("(uid) => window.__app.select(uid, false)", rdp["uid"])
    page.locator('#details .pv[data-pivot="account"] button.pv-go').click()
    page.wait_for_function("() => window.__app.S.data.events.some((e) => e.faded)")
    hidden_row = page.locator("#relatedList li.rel-row", has_text="hidden").first
    target = page.evaluate("""() => window.__app.S.data.events.filter((e) => e.faded).map((e) => e.uid)""")
    hidden_row.locator("input").check()
    page.locator("#relatedList").get_by_role("button", name="Mark 1 Malicious").click()
    page.wait_for_function("(uids) => window.__app.S.data.events.some((e) => uids.includes(e.uid) "
                           "&& e.mark === 'Malicious' && !e.faded)", arg=target)
    assert "View: Malicious, Suspicious" in page.locator("#status").inner_text()


def test_event_page_columns_scroll_on_their_own_and_any_field_joins_the_view(page):
    """The header band stays put while each column scrolls by itself, and an
    event-data field's Add to view filter pins that value, and the same button then removes it."""
    explicit = event_point(page, "4648")
    page.evaluate("(uid) => window.__app.select(uid, false)", explicit["uid"])
    page.wait_for_selector("#details[data-page='event'] .ev-facts")
    page.evaluate("() => document.querySelector('#details .raw').open = true")   # enough rows to scroll
    page.evaluate("() => { document.getElementById('details').style.flexBasis = '200px'; }")   # short: the fields overflow
    layout = page.evaluate("""() => {
        const facts = document.querySelector('#details .ev-facts'), work = document.querySelector('#details .ev-work');
        const head = document.querySelector('#details .ev-head').getBoundingClientRect().top;
        facts.scrollTop = 10000;
        return { panel: document.getElementById('detailsBody').scrollTop, facts: facts.scrollTop, work: work.scrollTop,
                 headMoved: document.querySelector('#details .ev-head').getBoundingClientRect().top - head,
                 overflow: getComputedStyle(facts).overflowY };
    }""")
    assert layout["overflow"] == "auto" and layout["facts"] > 0
    assert layout["panel"] == 0 and layout["work"] == 0 and layout["headMoved"] == 0
    page.locator("#details .ev-facts summary", has_text="Record and source").click()   # Computer name recorded is in this fold
    row = page.locator("#details .ev-facts dd", has_text="CITADEL-DC01.C137.local").first
    row.hover()
    row.get_by_role("button", name="Add to view filter").click()
    page.wait_for_function("() => document.querySelector('#viewCount').textContent === '1 on'")
    page.wait_for_function("(uid) => window.__app.S.data && window.__app.S.data.events.length >= 1 && "
                           "window.__app.S.data.events.every((e) => e.uid === uid)", arg=explicit["uid"])
    # Active: the row reads Remove, shown without hovering; clicking it takes the value out and the view goes off.
    remove = row.get_by_role("button", name="Remove from view filter")
    page.mouse.move(5, 5)
    assert remove.evaluate("(b) => getComputedStyle(b).opacity") == "1"
    remove.click()
    page.wait_for_function("() => document.querySelector('#viewCount').hidden")
    assert row.get_by_role("button", name="Add to view filter").count() == 1


def test_event_page_shows_the_parent_process_and_registry_data(browser, synthetic_case):
    """A Sysmon 1's parent and a Sysmon 13's data have rows of their own, in the
    fields and in Raw fields, with the View and search names the server reads; the parent joins the View filter under
    its own label, and the header reads key = data. RECmd's data shows once, as Registry data, but a row without it
    keeps ValueData in the Registry value group."""
    from test_parsers import DLL, RUN_KEY, W3WP

    from glessner.events import Event, connect

    sysmon = "DC01/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx"
    common = {"ts_desc": "Event Recorded", "artifact": "evtx", "source_file": sysmon,
              "event_provider": "Microsoft-Windows-Sysmon", "log_channel": "Microsoft-Windows-Sysmon/Operational"}
    parent_command = f"{W3WP} -ap DefaultAppPool"
    shell = Event(ts_us=T0 + 300 * SEC, source_record="301", record_id=301, event_code="1",
                  message="1 Process creation | parent w3wp.exe | cmd.exe /c whoami",
                  process_executable="C:\\Windows\\System32\\cmd.exe", process_command_line="cmd.exe /c whoami",
                  process_parent_executable=W3WP, process_parent_command_line=parent_command, **common)
    value_set = Event(ts_us=T0 + 600 * SEC, source_record="302", record_id=302, event_code="13",
                      message=f"13 Registry value set | Details: {DLL} | TargetObject: {RUN_KEY}", registry_path=RUN_KEY,
                      registry_data=DLL, **common)
    load(synthetic_case.db_path, [shell, value_set], host="DC01", tool="evtxecmd", tool_version="t", run_id="r6",
         replaces_sources=[sysmon], staging_dir=synthetic_case.folder)
    software = "DC01/Windows/System32/config/SOFTWARE"
    run = Event(ts_us=T0 - 3600 * SEC, ts_desc="Registry Key LastWrite", artifact="registry", source_file=software,
                source_record="run|Updater", message=f"Run: Updater = {DLL}", registry_path="ROOT\\Run",
                registry_value="Updater", registry_data=DLL, extra={"ValueType": "RegSz", "ValueData": DLL})
    load(synthetic_case.db_path, [run], host="DC01", tool="recmd", tool_version="t", run_id="r7",
         replaces_sources=[software], staging_dir=synthetic_case.folder)
    con = connect(synthetic_case.db_path, read_only=True)
    run_uid, name_uid = (con.execute("SELECT event_uid FROM events WHERE host = 'DC01' AND registry_value = ?",
                                     [name]).fetchone()[0] for name in ("Updater", "ComputerName"))
    con.close()
    for page in served_page(browser, synthetic_case):
        facts = page.locator("#details .ev-facts")
        field = lambda label: facts.locator(f"xpath=.//dt[.='{label}']/following-sibling::dd[1]")   # noqa: B023
        pred = lambda label: field(label).locator("button.viewtoggle").get_attribute("data-pred")   # noqa: B023
        shell_uid, value_uid = event_point(page, "1")["uid"], event_point(page, "13")["uid"]
        page.evaluate("(uid) => window.__app.select(uid, false)", value_uid)
        field("Registry data").wait_for()
        assert DLL in field("Registry data").inner_text()
        assert f"{RUN_KEY} = {DLL}" in page.locator("#details .ev-summary").all_inner_texts()
        assert json.loads(pred("Registry data")) == json.loads(pred("registry_data")) == {"registry_data": DLL}
        page.evaluate("(uid) => window.__app.select(uid, false)", shell_uid)
        field("Parent process").wait_for()
        assert W3WP in field("Parent process").inner_text()
        assert parent_command in field("Parent command line").inner_text()
        assert json.loads(pred("process_parent_executable")) == {"parent": W3WP}
        assert json.loads(pred("Parent command line")) == json.loads(pred("process_parent_command_line")) == {
            "parent_command_line": parent_command}
        parent = field("Parent process")
        parent.hover()
        parent.get_by_role("button", name="Add to search").click()
        assert page.locator("#search").input_value() == f"parent:{W3WP}"
        parent.hover()
        parent.get_by_role("button", name="Add to view filter").click()
        page.wait_for_function("() => document.querySelector('#viewCount').textContent === '1 on'")
        page.wait_for_function("(uid) => window.__app.S.data && window.__app.S.data.events.length === 1 && "
                               "window.__app.S.data.events[0].uid === uid", arg=shell_uid)
        assert f"View: Parent process {W3WP}" in page.locator("#status").inner_text()
        group = facts.locator("xpath=.//div[h3='Registry value']/dl/dt")
        page.evaluate("(uid) => window.__app.select(uid, false)", run_uid)
        field("Registry data").wait_for()
        assert group.all_inner_texts() == ["ValueType"] and DLL in field("Registry data").inner_text()
        page.evaluate("(uid) => window.__app.select(uid, false)", name_uid)   # no registry_data, as a plugin's key row
        group.filter(has_text="ValueData").wait_for()
        assert group.all_inner_texts() == ["ValueData"] and field("Registry data").count() == 0


def test_event_page_says_an_account_was_looked_up(browser, synthetic_case, tmp_path):
    """A PowerShell 4104 known only by its SID shows the name DC01's logons record for it, with a Looked up row beneath
    the account naming the SID and the events. The Event data group leaves the marker and the SID beside it to that
    row; Raw fields keep both."""
    from test_accounts import LOOKED_UP, SID, load_run, logons, parsed, script_block

    load_run(synthetic_case.db_path, parsed(tmp_path / "ps", [script_block(1, SID)]), "DC01", "r20", tmp_path)
    load_run(synthetic_case.db_path, parsed(tmp_path / "sec", logons()), "DC01", "r21", tmp_path)
    for page in served_page(browser, synthetic_case):
        facts = page.locator("#details .ev-facts")
        field = lambda label: facts.locator(f"xpath=.//dt[.='{label}']/following-sibling::dd[1]")   # noqa: B023
        page.evaluate("(uid) => window.__app.select(uid, false)", event_point(page, "4104")["uid"])
        field("Looked up").wait_for()
        assert "CORP\\alice" in field("Account").inner_text()
        assert field("Looked up").inner_text() == LOOKED_UP
        data = facts.locator("xpath=.//div[h3='Event data']/dl/dt").all_inner_texts()
        assert "SecurityUserID" in data and "AccountLookedUp" not in data and "AccountLookedUpSid" not in data
        assert field("extra.AccountLookedUp").count() == 1 and field("extra.SecurityUserID").count() == 1
        assert field("extra.AccountLookedUpSid").text_content().startswith(SID)   # Raw fields starts closed


def test_ip_pivot_and_view_at_either_end(browser, synthetic_case, tmp_path, monkeypatch):
    """On an inbound Sysmon 3, Same IP at either end has a button per address; the attacker's lists the Sysmon 3 as
    destination and the attacker's logons as source, in a column under a heading that names the address. The
    Destination IP row's View menu offers View at either end, which shows the same events and reads "IP ... at either
    end", and Search addr:, which the search box runs. An event without an address says why."""
    from test_analysis_relations import ATTACKER, load_inbound

    from glessner import queries

    uids = load_inbound(synthetic_case, tmp_path)
    for page in served_page(browser, synthetic_case):
        details, menu = page.locator("#details"), page.locator("#quickMenu")
        page.evaluate("(uid) => window.__app.select(uid, false)", uids["inbound"])
        # An inbound Sysmon 3 ranks the end that isn't the host's own address, the remote one: the attacker's, and not DC01's
        row = details.locator('.pv[data-pivot="addr"]')
        row.wait_for()
        assert row.locator("button.pv-go").inner_text() == "Same IP at either end"
        assert row.locator(".pv-value").inner_text() == ATTACKER
        assert details.locator('.pv[data-pivot="addr"]').count() == 1
        row.locator("button.pv-go").click()
        page.wait_for_selector("#relatedList li.rel-head")
        assert details.locator("#relatedList .actions strong").inner_text() == f"{ATTACKER} at either end: 3 events"
        assert details.locator("#relatedList li.rel-head .rel-col").inner_text() == "End"
        listed = [(r.locator(".rel-text").inner_text(), r.locator(".rel-col").inner_text())
                  for r in details.locator("#relatedList li.rel-row").all()]
        # In time order: the Sysmon 3 a second before the attacker's 4624, then the 4625.
        assert [end for _, end in listed] == ["destination", "source", "source"]
        assert "3 Network connection | inbound" in listed[0][0] and "4625" in listed[2][0]
        add_view = details.locator("#relatedList").get_by_role("button", name=f"Add IP {ATTACKER} at either end to view filter")
        assert add_view.count() == 1

        # The Destination IP row's View menu: the address as recorded, at either end, or as a search term.
        dest = details.locator(".ev-facts").locator("xpath=.//dt[.='Destination IP']/following-sibling::dd[1]")
        dest.hover()
        dest.get_by_role("button", name="Add to view filter").click()
        assert menu.get_by_role("menuitemcheckbox").all_inner_texts() == ["View as destination IP", "View at either end"]
        assert menu.get_by_role("menuitem").inner_text() == f"Search addr:{ATTACKER}"
        menu.get_by_role("menuitemcheckbox", name="View at either end").click()
        page.wait_for_function("() => document.querySelector('#viewCount').textContent === '1 on'")
        page.wait_for_function("(uids) => window.__app.S.data && window.__app.S.data.events.length === uids.length && "
                               "window.__app.S.data.events.every((e) => uids.includes(e.uid))",
                               arg=[uids["inbound"], uids["rdp"], uids["failed"]])
        assert f"View: IP {ATTACKER} at either end" in page.locator("#status").inner_text()
        page.locator("#viewButton").click()
        assert page.locator("#viewPanel .fchip").inner_text().startswith(f"IP {ATTACKER} at either end")
        # The row's button reads In view filter, shown without hovering, and its menu has the choice checked.
        toggle = dest.locator("button.viewtoggle")
        page.mouse.move(5, 5)
        assert toggle.inner_text().startswith("In view filter") and toggle.evaluate("(b) => getComputedStyle(b).opacity") == "1"
        toggle.click()
        checked = lambda name: menu.get_by_role("menuitemcheckbox", name=name).get_attribute("aria-checked")   # noqa: B023
        assert (checked("View as destination IP"), checked("View at either end")) == ("false", "true")
        menu.get_by_role("menuitemcheckbox", name="View at either end").click()
        page.wait_for_function("() => document.querySelector('#viewCount').hidden")
        assert toggle.inner_text().startswith("Add to view filter")
        # View as destination IP adds the address as recorded, the row's own end.
        toggle.click()
        menu.get_by_role("menuitemcheckbox", name="View as destination IP").click()
        page.wait_for_function("() => document.querySelector('#viewCount').textContent === '1 on'")
        assert page.evaluate("window.__app.S.viewSpec.values") == [{"dest_ip": ATTACKER}]
        assert page.locator("#viewPanel .fchip").inner_text().startswith(f"Destination IP {ATTACKER}")
        # The toggle is a menu button: it says when its menu is open, Escape and a choice hand focus back to it, and a
        # second press closes the menu.
        focused = lambda: toggle.evaluate("(b) => b === document.activeElement")   # noqa: B023
        toggle.click()
        assert toggle.get_attribute("aria-expanded") == "true" and checked("View as destination IP") == "true"
        page.keyboard.press("Escape")
        assert menu.is_hidden() and toggle.get_attribute("aria-expanded") == "false" and focused()
        toggle.click()
        toggle.click()
        assert menu.is_hidden() and toggle.get_attribute("aria-expanded") == "false"
        page.keyboard.press("Enter")   # from the keyboard, on the button: the menu opens on its first choice
        assert page.evaluate("document.activeElement.textContent") == "View as destination IP"
        page.keyboard.press("Enter")
        page.wait_for_function("() => document.querySelector('#viewCount').hidden")
        assert focused()
        # The Source IP row's menu names its own end; Search addr: puts the term in the box, and Enter runs it.
        source = details.locator(".ev-facts").locator("xpath=.//dt[.='Source IP']/following-sibling::dd[1]")
        source.hover()
        source.get_by_role("button", name="Add to view filter").click()
        assert menu.get_by_role("menuitemcheckbox").first.inner_text() == "View as source IP"
        page.keyboard.press("Escape")
        dest.hover()
        dest.get_by_role("button", name="Add to view filter").click()
        menu.get_by_role("menuitem", name=f"Search addr:{ATTACKER}").click()
        assert page.locator("#search").input_value() == f"addr:{ATTACKER}"
        page.locator("#search").press("Enter")
        page.wait_for_selector("#details[data-page='search'] .related li.rel-row")
        assert details.locator(".related .actions strong").inner_text().startswith("3 matching events")
        page.locator("#searchHelp").click()   # Search help lists the field with an example
        example = details.locator(".help-table tr", has_text="IP at either end").get_by_role("button")
        assert example.inner_text() == "addr:10.42.85.10"

        # An event without an address: the next pivots say so, on the not-offered line. The timeline without a view
        # filter, asked for when the last one came off, can answer after the search; until then it draws an earlier
        # filter's events, and each of those has an address.
        page.wait_for_function("() => window.__app.S.data.events.some((e) => e.code === '4672')")
        page.evaluate("(uid) => window.__app.select(uid, false)", event_point(page, "4672")["uid"])
        page.wait_for_function("() => document.querySelector('#details .pv-not')")
        assert "Same IP at either end: This event has no source or destination IP." in details.locator(".pv-not").inner_text()

        # More events than the list holds: the heading says how many of how many.
        monkeypatch.setattr(queries, "RELATED_LIMIT", 2)
        page.evaluate("(uid) => window.__app.select(uid, false)", uids["inbound"])
        details.locator('.pv[data-pivot="addr"] button.pv-go').click()
        page.wait_for_function("(h) => { const s = document.querySelector('#relatedList .actions strong'); "
                               "return !!s && s.textContent === h; }",
                               arg=f"{ATTACKER} at either end: the 2 nearest of 3 events")
        assert details.locator("#relatedList li.rel-row .rel-col").all_inner_texts() == ["destination", "source"]


def test_search_lists_matches_and_joins_the_view(page):
    """The / key focuses the search box; Enter lists the matches; the view filter shows only them."""
    page.locator("#lanes").click(position={"x": 5, "y": 5})   # focus off any field, as when reading the timeline
    page.keyboard.press("/")
    assert page.evaluate("document.activeElement.id") == "search"
    page.keyboard.type("user:administrator code:4624")
    page.keyboard.press("Enter")
    page.wait_for_selector("#details[data-page='search'] .related li.rel-row")
    header = page.locator("#details .related .actions strong").inner_text()
    assert header.startswith("4 matching events") or header.split()[0].isdigit()
    count = int(header.split()[0])
    page.locator("#details").get_by_role("button", name="Add this search to view filter").click()
    page.wait_for_function("() => document.querySelector('#viewCount').textContent === '1 on'")
    assert page.locator("#details").get_by_role("button", name="Remove this search from view filter").count() == 1
    page.wait_for_function("""(n) => window.__app.S.data && window.__app.S.data.events
        && window.__app.S.data.events.length === n && window.__app.S.data.events.every((e) => e.code === '4624')""", arg=count)
    page.locator("#search").fill("-only")
    page.locator("#search").press("Enter")
    page.wait_for_function("() => document.querySelector('#details').textContent.includes(\"isn't excluded\")")
    page.errors[:] = [e for e in page.errors if "/api/search?q=-only" not in e]   # that refusal was the point


def test_tags_from_the_event_page_menus_lanes_and_view_filter(page):
    """Tag from the picker and the right-click menu, see Tactic lanes, and filter on a tactic."""
    rdp = event_point(page, "4624", hit=True)
    page.evaluate("(uid) => window.__app.select(uid, false)", rdp["uid"])
    page.wait_for_selector("#details[data-page='event'] .ev-verdict")
    page.locator("#details").get_by_role("button", name="+ Tag").click()
    page.locator("#quickMenu").get_by_role("menuitem", name="Lateral Movement", exact=True).click()
    page.wait_for_function("() => [...document.querySelectorAll('#details .tagchip')]"
                           ".some((c) => c.textContent.startsWith('Lateral Movement'))")
    # The right-click menu's Tag as opens the same picker; the analyst's own tag goes in by typing.
    rdp = event_point(page, "4624", hit=True)
    page.mouse.click(rdp["x"], rdp["y"], button="right")
    page.locator("#quickMenu").get_by_role("menuitem", name="Tag as...").click()
    page.locator("#quickMenu").get_by_label("Your own tag").fill("Beachhead")
    page.locator("#quickMenu").get_by_label("Your own tag").press("Enter")
    page.wait_for_function("() => [...document.querySelectorAll('#details .tagchip')]"
                           ".some((c) => c.textContent.startsWith('beachhead'))")
    # Raw fields leave the tags out: they're lists of objects, shown in the Tags row instead.
    raw = page.locator("#details details", has=page.locator("summary", has_text="Raw fields"))
    if raw.get_attribute("open") is None:
        raw.locator("summary").click()
    assert "[object Object]" not in raw.inner_text()
    # Tactic lanes, in kill-chain order with Untagged last.
    page.locator("#groupby").select_option(label="Tactic > Host")
    page.wait_for_function("() => [...document.querySelectorAll('#labels .row')]"
                           ".some((r) => r.textContent.startsWith('▸Lateral Movement'))")   # a preset opens folded
    rows = page.locator("#labels .row.group").all_inner_texts()
    assert rows[-1].startswith("▸Untagged")
    # The View filter's Tactics and tags section shows the tag; checking it leaves only the tagged event.
    page.locator("#viewButton").click()
    page.locator("#viewPanel").get_by_role("button", name="Tactics and tags").click()   # folded while none of its values is on
    page.locator("#viewPanel").get_by_role("checkbox", name="Show events tagged Lateral Movement").check()
    page.wait_for_function("(uid) => window.__app.S.data.events.length === 1 && window.__app.S.data.events[0].uid === uid",
                           arg=rdp["uid"])
    # Removing the tag with its x takes the chip away.
    chip = page.locator("#details .tagchip", has_text="beachhead")
    chip.get_by_role("button", name="Remove the tag beachhead").click()
    page.wait_for_function("() => ![...document.querySelectorAll('#details .tagchip')]"
                           ".some((c) => c.textContent.startsWith('beachhead'))")


def test_audit_trail_undoes_an_accident_and_retracts_a_note(page):
    """Undo a mark from the audit trail as a correction; retract a note from the Event page."""
    rdp = event_point(page, "4624", hit=True)
    page.mouse.click(rdp["x"], rdp["y"], button="right")
    page.locator("#quickMenu").get_by_role("menuitem", name="Mark Malicious").click()
    page.wait_for_function("(uid) => window.__app.S.data.events.some((e) => e.uid === uid && e.mark === 'Malicious')",
                           arg=rdp["uid"])
    case_menu(page, "auditButton")
    row = page.locator("#details .audit-row", has_text="Malicious").first
    row.get_by_role("button", name="Undo").click()
    confirm = row.locator(".audit-confirm").get_by_role("button", name="Undo 1 event")
    confirm.wait_for()
    # One event reads in the singular
    assert "1 event goes back to how it was before #" in row.locator(".audit-confirm").inner_text()
    confirm.click()
    page.wait_for_function("(uid) => window.__app.S.data.events.some((e) => e.uid === uid && e.mark !== 'Malicious')",
                           arg=rdp["uid"])
    page.wait_for_selector("#details .audit-row.correction")
    page.wait_for_function("() => [...document.querySelectorAll('#details .audit-row')]"
                           ".some((r) => r.textContent.includes('Undone by #'))")
    # A note, retracted from the Event page, stays on record struck through; History lists the mark, the undo, the note,
    # and its retraction.
    page.evaluate("(uid) => window.__app.select(uid, false)", rdp["uid"])
    page.wait_for_selector("#details[data-page='event'] .ev-history", state="attached")   # History is a fold, closed at first
    page.locator("#details").get_by_placeholder("Add a note to this event").fill("first look")
    page.locator("#details").get_by_role("button", name="Add note").click()
    page.wait_for_selector("#details .notes li >> text=first look")
    page.locator("#details .notes").get_by_role("button", name="Retract").click()
    page.wait_for_selector("#details .notes li.gone")
    page.wait_for_function("() => document.querySelectorAll('#details .ev-history li').length === 4")
    assert page.locator("#details .history-fold summary").text_content() == "History (4)"   # the CSS capitalizes it


def test_import_page_adds_new_evidence_and_imports_a_firewall_log(page, synthetic_case):
    """Add new evidence, choose the zone the Windows Firewall log asks for, and import."""
    import re

    from glessner.intake import intake

    intake(synthetic_case)
    (synthetic_case.evidence / "DC01" / "pfirewall.log").write_bytes(
        b"#Version: 1.5\r\n#Software: Microsoft Windows Firewall\r\n#Time Format: Local\r\n"
        b"#Fields: date time action protocol src-ip dst-ip src-port dst-port size tcpflags tcpsyn tcpack tcpwin "
        b"icmptype icmpcode info path pid\r\n"
        b"2020-09-19 03:21:50 ALLOW TCP 194.61.24.102 10.42.85.10 51544 3389 0 - 0 0 0 - - - RECEIVE 1234\r\n")
    details = page.locator("#details")
    case_menu(page, "importButton")
    page.wait_for_selector("#details[data-page='import']")
    assert "No logs to import yet" in details.inner_text()
    details.get_by_role("button", name="Add new evidence").click()
    page.wait_for_selector("#details .imp-problem >> text=carry no zone")
    assert "Windows Firewall" in details.locator(".imp-file").inner_text()
    go = details.get_by_role("button", name=re.compile(r"^Import \d+ lines$"))
    assert go.is_disabled()
    details.get_by_label("Times without a zone are in").select_option("UTC")
    page.wait_for_selector("#details .imp-events li")
    assert "ALLOW TCP 194.61.24.102:51544 -> 10.42.85.10:3389" in details.locator(".imp-events").inner_text()
    with page.expect_navigation():
        go.click()
    page.wait_for_function("() => window.__ready === true && window.__app.S.data !== null")
    assert page.evaluate("() => window.__app.S.data.events.some((e) => e.code === 'ALLOW')")


def test_import_page_reads_syslog_by_its_layout_and_suggests_the_year(page, synthetic_case):
    """Log lines in a known layout: the page names the layout, takes the year syslog leaves out from the case's own
    events, and imports once the zone is chosen."""
    import re

    from glessner.intake import intake

    intake(synthetic_case)
    (synthetic_case.evidence / "DC01" / "auth.log").write_text(
        "Sep 19 03:21:50 citadel sshd[812]: Accepted password for rick from 194.61.24.102 port 50122 ssh2\n"
        "Sep 19 03:22:10 citadel sshd[813]: Failed password for invalid user admin from 194.61.24.102 port 50123 ssh2\n",
        newline="\n")
    details = page.locator("#details")
    case_menu(page, "importButton")
    page.wait_for_selector("#details[data-page='import']")
    details.get_by_role("button", name="Add new evidence").click()
    page.wait_for_selector("#details .imp-problem >> text=carry no zone")
    assert details.get_by_label("Layout").input_value() == "syslog"
    assert details.get_by_label("Year of the first record").input_value() == "2020"
    details.get_by_label("Times without a zone are in").select_option("UTC")
    page.wait_for_selector("#details .imp-events li")
    assert "sshd: Accepted password for rick from 194.61.24.102" in details.locator(".imp-events").inner_text()
    with page.expect_navigation():
        details.get_by_role("button", name=re.compile(r"^Import \d+ lines$")).click()
    page.wait_for_function("() => window.__ready === true && window.__app.S.data !== null")
    assert page.evaluate("() => window.__app.S.data.events.some((e) => e.code === 'Accepted')")


def test_search_shows_where_matches_are_and_helps_with_the_syntax(page):
    """The match strip and busiest stretch, highlighted terms on the list and the Event page,
    Add to search from a field, and the Search help page's examples."""
    page.locator("#search").fill("C137.local")
    page.locator("#search").press("Enter")
    page.wait_for_selector("#details[data-page='search'] .match-strip .bar")
    details = page.locator("#details")
    assert details.locator(".related li .found mark").first.inner_text().lower() == "c137.local"
    assert "in Computer:" in details.locator(".related li .found").first.inner_text()
    marked = page.evaluate("() => window.__app.S.related.size")
    assert marked == int(details.locator(".related .actions strong").inner_text().split()[0])
    before = view(page)
    details.get_by_role("button", name="Zoom to the busiest stretch").click()
    page.wait_for_function("(b) => { const v = window.__app.S.view; return v.end - v.start < b.end - b.start; }", arg=before)
    # The Event page opened from a result highlights the term; Add to search puts a field in the box.
    details.locator(".related li.rel-row span").first.click()
    page.wait_for_selector("#details[data-page='event'] .ev-facts dd mark")
    code = details.locator(".ev-facts dd", has_text="4624").first
    code.hover()
    code.get_by_role("button", name="Add to search").click()
    assert page.locator("#search").input_value() == "C137.local code:4624"
    # Another page clears the highlight; Search help runs an example with a click.
    page.locator("#searchHelp").click()
    page.wait_for_selector("#details[data-page='searchHelp']")
    assert page.evaluate("() => window.__app.S.highlight") is None
    details.get_by_role("button", name="code:4624 logon_type:10").click()
    page.wait_for_selector("#details[data-page='search'] .related li.rel-row")
    assert page.locator("#search").input_value() == "code:4624 logon_type:10"


def test_a_wildcard_search_highlights_its_match_without_freezing_the_page(browser, synthetic_case):
    """A wildcard search must not freeze the page: with each * a lazy .*? in one regular expression for the highlights,
    which backtracks, a*a*a*a*a*b over a message of 160 a's takes over 5 s in V8. The search lists its match, found in
    its event data, and opens its Event page with the value highlighted, each in a few seconds; Playwright's wait
    times out from outside a frozen page."""
    odd = Event(T0 + 5 * SEC, "Event Recorded", "evtx", "DC01/odd.evtx", "1", "a" * 160, extra={"hit": "aaaaab"})
    load(synthetic_case.db_path, [odd], host="DC01", tool="evtxecmd", tool_version="t", run_id="r9",
         replaces_sources=["DC01/odd.evtx"], staging_dir=synthetic_case.folder)
    for page in served_page(browser, synthetic_case):
        page.locator("#search").fill("a*a*a*a*a*b")
        page.locator("#search").press("Enter")
        found = page.locator("#details[data-page='search'] .related li .found mark")
        found.wait_for(timeout=10_000)
        assert found.first.inner_text() == "aaaaab"
        page.locator("#details .related li.rel-row", has_text="in data.hit").locator("span").first.click()
        page.wait_for_selector("#details[data-page='event'] .ev-facts mark", timeout=10_000)
        assert page.locator("#details .ev-facts mark").first.inner_text() == "aaaaab"


def test_a_tab_whose_case_another_tab_replaced_says_so_and_writes_nothing(browser, synthetic_case, tmp_path):
    """The server holds one open case, so a request would run against whichever case was open when it came. A tab
    still showing case A, after a second tab opened a copy of it on the same server, could mark the copy's event, which
    has the same ID, and the copy's journal would keep the mark. The page sends the open's ID with every request, the
    server refuses one that names another open, and the page says another case is open, offers a reload, and sends
    nothing more."""
    import shutil

    from glessner.case import copy_case
    from glessner.journal import replay

    copy = copy_case(synthetic_case, tmp_path / "copy", "Copy", "cody")
    shutil.copy2(synthetic_case.db_path, copy.db_path)   # the same events and IDs, as a copy's rebuild gives
    for page in served_page(browser, synthetic_case):
        sent = []
        page.on("request", lambda req: sent.append((req.url, req.headers.get("x-glessner-case")))   # noqa: B023
                if "/api/" in req.url else None)
        rdp = event_point(page, "4624", hit=True)
        page.mouse.click(rdp["x"], rdp["y"])
        page.wait_for_selector("#details[data-page='event'] .ev-verdict")
        opened = page.evaluate("window.__app.S.meta.case_id")
        assert sent and {header for _, header in sent} == {opened}, sent   # every request names the open
        page.hub.open(copy)   # as a second tab's Cases page does
        page.locator("#details .ev-verdict").get_by_role("button", name="Malicious", exact=True).click()
        band = page.locator("#caseChanged")
        band.wait_for()
        assert band.inner_text().startswith("Another case is open now: Copy. Reload the page to work on it")
        page.wait_for_function("() => document.getElementById('status').textContent.startsWith('Mark failed: "
                               "Another case is open now')")
        assert replay(copy.folder / "journal.jsonl").marks == {} == replay(synthetic_case.folder / "journal.jsonl").marks
        before = len(sent)
        refused = page.evaluate("() => import('/js/core.js').then((m) => m.api('/api/marks')).catch((e) => e.message)")
        assert refused.startswith("Another case is open now") and len(sent) == before   # sent nothing
        band.get_by_role("button", name="Reload").click()
        page.wait_for_function("() => window.__ready === true && document.getElementById('caseName').textContent "
                               "=== 'Copy'")
        page.errors[:] = [e for e in page.errors if not e.startswith("HTTP 409: ")]   # the refusals were the point


def test_suggested_tags_accept_and_dismiss_at_opposite_ends(browser, synthetic_case):
    """Each suggested tag has accept at its left end and dismiss at its right, and both work."""
    from test_tags import ATTACK_HIT

    from glessner.events import load

    load(synthetic_case.db_path, [ATTACK_HIT], host="DC01", tool="hayabusa", tool_version="t", run_id="r6",
         replaces_sources=[ATTACK_HIT.source_file], staging_dir=synthetic_case.folder)
    for page in served_page(browser, synthetic_case):
        rdp = event_point(page, "4624", hit=True)
        page.evaluate("(uid) => window.__app.select(uid, false)", rdp["uid"])
        page.locator("#details button.tw").click()   # the suggestions fold, closed at first
        chip = page.locator("#details .tagchip.split", has_text="Lateral Movement")
        chip.wait_for()
        ends = chip.locator("button.end")
        assert [ends.nth(0).inner_text(), ends.nth(1).inner_text()] == ["✓", "×"]
        assert ends.nth(0).bounding_box()["x"] < chip.locator(".label").bounding_box()["x"] < ends.nth(1).bounding_box()["x"]
        page.locator("#details").get_by_role("button", name="Accept the tag Lateral Movement").click()
        page.wait_for_function("() => [...document.querySelectorAll('#details .tagchip:not(.suggested)')]"
                               ".some((c) => c.textContent.startsWith('Lateral Movement'))")
        page.locator("#details").get_by_role("button", name="Dismiss the tag Credential Access").click()
        page.wait_for_function("() => ![...document.querySelectorAll('#details .tagchip.suggested')]"
                               ".some((c) => c.textContent.includes('Credential Access'))")


def test_view_filter_can_include_suggested_tags(browser, synthetic_case):
    """Include suggested tags is off by default. On, a tactic only Hayabusa suggests can be checked and shows
    its event; off again, the View matches the analyst's tags only, and the checked tactic can still be taken out."""
    from test_tags import ATTACK_HIT

    from glessner.events import load

    load(synthetic_case.db_path, [ATTACK_HIT], host="DC01", tool="hayabusa", tool_version="t", run_id="r6",
         replaces_sources=[ATTACK_HIT.source_file], staging_dir=synthetic_case.folder)
    for page in served_page(browser, synthetic_case):
        everything = page.evaluate("() => window.__app.S.data.events.length")
        rdp = event_point(page, "4624", hit=True)
        page.locator("#viewButton").click()
        panel = page.locator("#viewPanel")
        panel.get_by_role("button", name="Tactics and tags").click()   # folded while none of its values is on
        include = panel.get_by_role("checkbox", name="Include suggested tags")
        lateral = panel.get_by_role("checkbox", name="Show events tagged Lateral Movement")
        include.wait_for()
        assert not include.is_checked() and lateral.is_disabled()
        assert "Include suggested tags (Hayabusa's, not yet accepted)" in panel.locator("label.include").inner_text()
        row = panel.locator("label.vrow", has=page.get_by_role("checkbox", name="Show events tagged Lateral Movement"))
        assert "0 · 1 suggested" in row.inner_text()
        # The disabled box says why, and how to show the tag
        why = "1 event suggested by Hayabusa, none tagged yet. Turn on Include suggested tags to show them."
        assert lateral.get_attribute("title") == why and row.get_attribute("title") == why
        include.check()
        assert row.get_attribute("title") == "1 more suggested by Hayabusa"
        lateral.check()
        page.wait_for_function("(uid) => window.__app.S.data.events.length === 1 && window.__app.S.data.events[0].uid === uid",
                               arg=rdp["uid"])
        assert "View: Tag Lateral Movement, suggested tags included" in page.locator("#status").inner_text()
        # Off again: the analyst hasn't accepted the tag, so nothing shows, and the tactic can still be unchecked.
        panel.get_by_role("checkbox", name="Include suggested tags").uncheck()
        page.wait_for_function("() => window.__app.S.data.events.length === 0")
        lateral = panel.get_by_role("checkbox", name="Show events tagged Lateral Movement")
        assert lateral.is_checked() and lateral.is_enabled()
        lateral.uncheck()
        page.wait_for_function("(n) => window.__app.S.data.events.length === n", arg=everything)


def test_tools_page_runs_a_tool_and_shows_it_ran(browser, synthetic_case, tmp_path):
    """The Tools page lists a tool ready to run, runs it in the background, and shows that it ran."""
    from test_server import fake_tool_case

    cache = fake_tool_case(synthetic_case, tmp_path)
    for page in served_page(browser, synthetic_case, setup=lambda app: setattr(app, "tool_cache", cache)):
        case_menu(page, "toolsButton")
        page.wait_for_selector("#details[data-page='tools'] .tools-table")
        details = page.locator("#details")
        assert "1 event log, on 1 host" in details.locator(".tools-table").inner_text()
        details.get_by_role("button", name="Run Fake").click()
        # The table's result, which shows whether the page followed the job or the job had finished when the page
        # first asked about it
        page.wait_for_function("() => document.querySelector('#details .tools-table .ok') !== null")
        assert "Ran " in details.locator(".tools-table").inner_text()
        # A job counts its runs, not hosts
        assert details.locator(".tools-job").inner_text().startswith("Fake finished 1 of 1 run.\nDC01: ok")


def test_tools_page_loads_tool_output_found_in_the_evidence(browser, synthetic_case):
    """An EvtxECmd CSV from a KAPE run shows under Tool output already in the evidence, and loads."""
    from test_tool_outputs import EVTX_COLUMNS, evtx_rows, write_rows

    from glessner.intake import intake
    from glessner.tools import load_registry

    write_rows(synthetic_case.evidence / "WS02" / "Modules" / "EventLogs" / "20240514_EvtxECmd_Output.csv", EVTX_COLUMNS,
               evtx_rows("WS02.corp.local"))
    intake(synthetic_case)
    for page in served_page(browser, synthetic_case, setup=lambda app: setattr(app, "tool_cache", (load_registry(), {}))):
        case_menu(page, "toolsButton")
        page.wait_for_selector("#details[data-page='tools'] .tools-outputs")
        outputs = page.locator("#details .tools-outputs")
        assert "1 file, on WS02" in outputs.inner_text() and "Ready, not loaded" in outputs.inner_text()
        everything = page.locator("#details").get_by_role("button", name="Run and load everything ready")
        assert everything.is_enabled()
        assert "Will load 1 group of found output." in page.locator("#details").inner_text()
        with page.expect_navigation():   # the timeline reloads once events have loaded
            outputs.get_by_role("button", name="Load EvtxECmd CSV on WS02").click()
        page.wait_for_function("() => window.__ready === true")
        case_menu(page, "toolsButton")
        page.wait_for_selector("#details .tools-outputs .ok")
        assert "Loaded " in page.locator("#details .tools-outputs").inner_text()


# Asks the server about the background job, through the page's own request function, which sends the session, until it
# reports the job finished, for up to `timeout` milliseconds; true when it did
JOB_FINISHED = """async (timeout) => {
    const deadline = Date.now() + timeout;
    while (Date.now() < deadline) {
        if ((await (await import('/js/core.js')).api('/api/run_status')).job?.finished) return true;
        await new Promise((resolve) => setTimeout(resolve, 50));
    }
    return false;
}"""


def test_tools_page_follows_a_load_that_finishes_before_the_page_answers(browser, synthetic_case):
    """A load started from the Tools page is followed from the click, so the timeline reloads once it has finished even
    when the Tools page's own request is still unanswered. That request is held here until the job has finished, as a
    short job's would be, and its answer then shows the job finished, not running."""
    from test_tool_outputs import EVTX_COLUMNS, evtx_rows, write_rows

    from glessner.intake import intake
    from glessner.tools import load_registry

    write_rows(synthetic_case.evidence / "WS02" / "Modules" / "EventLogs" / "20240514_EvtxECmd_Output.csv", EVTX_COLUMNS,
               evtx_rows("WS02.corp.local"))
    intake(synthetic_case)
    held = []
    for page in served_page(browser, synthetic_case, setup=lambda app: setattr(app, "tool_cache", (load_registry(), {}))):
        case_menu(page, "toolsButton")
        page.wait_for_selector("#details[data-page='tools'] .tools-outputs")
        page.route("**/api/tools", lambda route: held.append(route))
        with page.expect_request("**/api/tools"):
            page.locator("#details .tools-outputs").get_by_role("button", name="Load EvtxECmd CSV on WS02").click()
        wait_held(page, held)
        # The timeline reloads once events have loaded; a page change isn't a load. The wait covers the job's, then the
        # reload's.
        with page.expect_event("load", timeout=PAGE_TIMEOUT_MS + LOAD_TIMEOUT_MS):
            assert page.evaluate(JOB_FINISHED, PAGE_TIMEOUT_MS)
            held[0].continue_()


def test_a_tool_run_leaves_a_page_opened_while_it_starts_and_runs(browser, synthetic_case, tmp_path):
    """A run started from the Tools page draws that page again when the server answers, and again when the job finishes,
    but only while the Tools page shows: a page the analyst opened meanwhile, here Rules, keeps the panel. The run's
    request is held here until Rules shows; the stand-in tool loads nothing, so the timeline doesn't reload."""
    from test_server import fake_tool_case

    cache = fake_tool_case(synthetic_case, tmp_path)
    held = []
    for page in served_page(browser, synthetic_case, setup=lambda app: setattr(app, "tool_cache", cache)):
        case_menu(page, "toolsButton")
        page.wait_for_selector("#details[data-page='tools'] .tools-table")
        page.route("**/api/run_tool", lambda route: held.append(route))
        page.locator("#details").get_by_role("button", name="Run Fake").click()
        wait_held(page, held)
        case_menu(page, "rulesButton")
        page.wait_for_selector("#details[data-page='rules']")
        page.evaluate(RECORD_REQUESTS)
        with page.expect_response("**/api/run_tool"):
            held[0].continue_()
        page.unroute("**/api/run_tool")
        # The status line says the job finished in the task that would draw the Tools page again
        page.wait_for_function("() => document.getElementById('status').textContent === 'Fake finished.'")
        assert asked(page, "/api/tools") == []
        assert page.locator("#details").get_attribute("data-page") == "rules"


def test_tools_page_loads_autoruns_and_the_event_page_shows_the_entry(browser, synthetic_case):
    """An Autoruns CSV loads from the Tools page, which counts the entry without a time, since nothing else shows it;
    an entry's Event page says what its time is and lists Autoruns' own fields."""
    from test_autoruns import AUTORUNS_CSV, autoruns_bytes, pacific

    from glessner.events import event_uid
    from glessner.intake import intake
    from glessner.parsers.autoruns import BUILT
    from glessner.tools import load_registry

    (synthetic_case.evidence / AUTORUNS_CSV).parent.mkdir(parents=True)
    (synthetic_case.evidence / AUTORUNS_CSV).write_bytes(autoruns_bytes())
    intake(synthetic_case)
    pacific(synthetic_case)
    service = event_uid("DC01", "autoruns", AUTORUNS_CSV, "5", BUILT)   # line 5: the coreupdater service
    for page in served_page(browser, synthetic_case, setup=lambda app: setattr(app, "tool_cache", (load_registry(), {}))):
        case_menu(page, "toolsButton")
        outputs = page.locator("#details .tools-outputs")
        outputs.wait_for()
        assert "Autoruns CSV" in outputs.inner_text() and "Ready, not loaded" in outputs.inner_text()
        assert "1 Autoruns CSV: open the Import page" in page.locator("#details").inner_text()
        with page.expect_navigation():
            outputs.get_by_role("button", name="Load Autoruns CSV on DC01").click()
        page.wait_for_function("() => window.__ready === true")
        case_menu(page, "toolsButton")
        page.wait_for_selector("#details .tools-outputs .ok")
        status = page.locator("#details .tools-outputs").inner_text()
        assert ": 5 events, 1 without a time, so off the timeline" in status
        # Loaded, the CSV isn't counted for the Import page, which lists it apart, unpicked
        assert "open the Import page" not in page.locator("#details").inner_text()
        case_menu(page, "importButton")
        files = page.locator("#details[data-page='import'] .imp-files")
        files.wait_for()
        assert files.locator("h3").all_text_contents() == ["Files to import", "Loaded as found output"]
        assert f"{AUTORUNS_CSV}\nAutoruns CSV; loaded from the Tools page, 5 events" in files.inner_text()
        assert files.get_by_role("button", name=AUTORUNS_CSV).count() == 0
        page.locator("#details .back-bar button").click()
        page.evaluate("(uid) => window.__app.select(uid, false)", service)
        facts = page.locator("#details .ev-facts")
        group = facts.locator("xpath=.//div[h3='Autoruns entry']/dl/dt")
        group.first.wait_for()
        names = group.all_inner_texts()
        assert names[:3] == ["Category", "Entry", "Entry Location"] and {"SHA-256", "LocationLastWritten"} <= set(names)
        assert "Autoruns, Image built (PE link time)" in page.locator("#details").inner_text()


def test_start_page_makes_a_case_and_opens_its_tools_page(browser, tmp_path):
    """The case GUI. A new case from the start page is checked, taken in, and opened on its Tools page; the Cases
    button leads back, where it's the open case at the top of the recent list. The analyst field starts as the Windows
    account, and the name typed there goes into case.yaml, for the new case and for a copy."""
    ev = tmp_path / "evidence"
    logs = ev / "DC01" / "Windows" / "System32" / "winevt" / "Logs"
    logs.mkdir(parents=True)
    (logs / "Security.evtx").write_bytes(b"ElfFile\x00" + b"\x01" * 64)
    for page in served_page(browser, None, ready="() => window.__start && window.__start.info !== null"):
        start = page.locator("#start")
        # The case name's box is wide enough to show its whole example name
        assert start.get_by_label("Case name").evaluate(
            "(i) => { i.value = i.placeholder; const fits = i.scrollWidth <= i.clientWidth; i.value = ''; return fits; }")
        start.get_by_label("Case name").fill("Browser case")
        assert start.get_by_label("Analyst", exact=True).input_value() == getpass.getuser()
        start.get_by_label("Analyst", exact=True).fill("Ana Lyst")
        start.get_by_label("Evidence folder").fill(str(ev))
        start.get_by_label("Case folder", exact=True).fill(str(tmp_path / "cases" / "browser"))
        page.wait_for_selector("#start [data-check='evidence'].ok")
        assert "Found 1 file, " in start.locator("[data-check='evidence']").inner_text()
        assert "in 1 folder: DC01" in start.locator("[data-check='evidence']").inner_text()
        with page.expect_navigation():
            start.get_by_role("button", name="Create case and take in evidence").click()
        page.wait_for_function("() => window.__ready === true")
        page.wait_for_selector("#details[data-page='tools']")
        assert "No events yet" in page.locator("#status").inner_text()
        assert not page.evaluate(AXIS_DRAWN)   # no time axis without events
        assert page.locator("#caseName").inner_text() == "Browser case"
        with page.expect_navigation():
            case_menu(page, "casesButton")
        page.wait_for_selector("#start .start-case.current")
        assert "Browser case" in page.locator("#start .start-case.current").inner_text()
        assert open_case(tmp_path / "cases" / "browser").settings.analyst == "Ana Lyst"
        start.get_by_role("button", name="Copy Browser case").click()
        assert start.get_by_label("Analyst for the copy").input_value() == getpass.getuser()
        start.get_by_label("Analyst for the copy").fill("Tester")
        start.get_by_role("button", name="Make the copy").click()
        page.wait_for_function("() => window.__startJob && window.__startJob.kind === 'copy'")
        assert not page.evaluate("window.__startJob.error")
        assert open_case(tmp_path / "cases" / "browser-copy").settings.analyst == "Tester"


def test_start_page_names_the_runs_a_copy_left_out(browser, tmp_path):
    """A copy's rebuild leaves out a tool run whose output changed since it ran. The start page's Copy box names each
    run left out and why, not only that the copy is ready."""
    from test_runner import pecmd_run, write_pecmd

    from glessner.case import create_case
    from glessner.intake import intake
    from glessner.start import remember

    ev = tmp_path / "evidence"
    (ev / "DC01").mkdir(parents=True)
    (ev / "DC01" / "notes.txt").write_text("evidence")
    case = create_case(tmp_path / "cases" / "source", "Source case", ev, "cody")
    intake(case)
    record, output = pecmd_run(case)
    write_pecmd(output / "pecmd.csv", case, "DIFFERENT.EXE", "2024-02-01 00:00:00.0000000")
    remember(case, 1)
    for page in served_page(browser, None, ready="() => window.__start && window.__start.info !== null"):
        start = page.locator("#start")
        start.get_by_role("button", name="Copy Source case").click()
        start.get_by_role("button", name="Make the copy").click()
        page.wait_for_function("() => window.__startJob && window.__startJob.kind === 'copy'")
        assert not page.evaluate("window.__startJob.error")
        box = start.locator(".start-job")
        box.locator(".start-left-out li").first.wait_for()
        assert "is ready in " in box.inner_text()
        assert box.locator(".warn").inner_text() == ("Its rebuild left out 1 run, whose output or evidence changed since "
                                                     "it ran, so their events are not in the copy:")
        (note,) = box.locator(".start-left-out li").all_inner_texts()
        assert note.startswith(f"{record.run_id}: Rebuild at ") and note.endswith(" left it out: pecmd.csv: SHA-256 changed")


def test_start_page_names_the_build_and_refuses_a_newer_case_format(browser, synthetic_case, monkeypatch):
    """A quiet line at the start page's foot names the build, and opening a case of a newer format than
    this build reads says so with both numbers instead of opening it."""
    from glessner import version
    from glessner.case import CASE_FILE, CASE_FORMAT

    monkeypatch.setattr(version, "BAKED_BUILD", "9.9.9+test")
    version.build_id.cache_clear()
    settings = synthetic_case.folder / CASE_FILE
    text = settings.read_text(encoding="utf-8")
    settings.write_text(text.replace(f"case_format: {CASE_FORMAT}", f"case_format: {CASE_FORMAT + 1}"), encoding="utf-8")
    try:
        for page in served_page(browser, None, ready="() => window.__start && window.__start.info !== null"):
            assert page.locator("#start .start-build").inner_text() == "glessner 9.9.9+test"
            page.get_by_label("Case folder to open").fill(str(synthetic_case.folder))
            page.locator("#start").get_by_role("button", name="Open", exact=True).click()
            page.wait_for_function("() => document.querySelector('#status').textContent.startsWith(\"It didn't open\")")
            assert page.locator("#status").inner_text() == (
                f"It didn't open: {synthetic_case.folder} is a case of format {CASE_FORMAT + 1}, and this build of "
                f"glessner (9.9.9+test) reads formats up to {CASE_FORMAT}. Open it with a build that reads format "
                f"{CASE_FORMAT + 1}.")
            page.errors[:] = [e for e in page.errors if "/api/start/open" not in e]   # that refusal was the point
    finally:
        version.build_id.cache_clear()


def test_start_page_shows_each_tool_s_file_and_the_links_it_skipped(browser, tmp_path):
    """The tools check refuses a tools folder that holds the evidence, and otherwise names the file each tool would
    run, one per line. The evidence check says which links it skipped rather than followed."""
    ev = tmp_path / "evidence"
    (ev / "DC01").mkdir(parents=True)
    (ev / "DC01" / "Security.evtx").write_bytes(b"ElfFile\x00" + b"\x01" * 64)
    exe = tmp_path / "tools" / "EZ" / "EvtxECmd" / "EvtxECmd.exe"
    exe.parent.mkdir(parents=True)
    exe.write_bytes(b"")   # a placeholder: nothing runs
    junction(ev / "LINKED", tmp_path / "tools")
    for page in served_page(browser, None, ready="() => window.__start && window.__start.info !== null"):
        start = page.locator("#start")
        tools = start.locator("[data-check='tools']")
        start.get_by_label("Evidence folder").fill(str(ev))
        start.get_by_label("Tools folder").fill(str(tmp_path))
        page.wait_for_selector("#start [data-check='tools'].warn")
        assert "The tools folder and the evidence folder must not contain each other" in tools.inner_text()
        assert (f"in 1 folder: DC01. Skipped 1 link, not followed: LINKED -> {tmp_path / 'tools'}."
                in start.locator("[data-check='evidence']").inner_text())
        start.get_by_label("Tools folder").fill(str(tmp_path / "tools"))
        page.wait_for_selector("#start [data-check='tools'].ok")
        assert tools.inner_text().splitlines()[1:] == [f"EvtxECmd: {exe}"]


def test_start_page_warns_of_several_copies_of_one_collection(browser, tmp_path):
    """A folder whose top-level folders each hold the same host's folder, as ashemery-case1-run01's does, gets a
    warning under the evidence check, worded from the folders' names. One copy clears it, and the case can still be
    created with the warning showing."""
    ev = tmp_path / "dataset"
    for top in ("collection", "triage", "triage_more"):
        logs = ev / top / "WIN-7Q2K4M" / "Windows" / "System32" / "winevt" / "Logs"
        logs.mkdir(parents=True)
        (logs / "Security.evtx").write_bytes(b"ElfFile\x00" + top.encode() * 8)
    for page in served_page(browser, None, ready="() => window.__start && window.__start.info !== null"):
        start = page.locator("#start")
        copies = start.locator("[data-check='evidence-copies']")
        start.get_by_label("Case name").fill("Copies")
        start.get_by_label("Case folder", exact=True).fill(str(tmp_path / "cases" / "copies"))
        start.get_by_label("Evidence folder").fill(str(ev / "triage"))
        page.wait_for_selector("#start [data-check='evidence'].ok")
        assert copies.is_hidden()
        start.get_by_label("Evidence folder").fill(str(ev))
        copies.wait_for()
        assert copies.inner_text() == ("collection, triage, and triage_more each hold a host folder of their own, such as "
                                       "WIN-7Q2K4M. Choose the folder that holds one copy of each host.")
        assert "in 3 folders: collection, triage, triage_more" in start.locator("[data-check='evidence']").inner_text()
        create = start.get_by_role("button", name="Create case and take in evidence")
        assert create.is_enabled()
        with page.expect_navigation():
            create.click()
        page.wait_for_selector("#details[data-page='tools']")


def test_start_page_removes_recent_cases_whose_folder_is_gone(browser, tmp_path, monkeypatch):
    """A recent case whose folder is gone reads "folder not found" with Open and Copy off, and has Remove from list;
    with two or more such cases, one line above the list removes them all. Only recent.json changes: a folder that is
    there without its case.yaml keeps its file, and a case whose folder came back after the page drew stays on the
    list. A case whose folder is there keeps Open and Copy alone."""
    from types import SimpleNamespace

    from glessner.case import create_case
    from glessner.start import load_recent, remember

    monkeypatch.setenv("GLESSNER_CONFIG_DIR", str(tmp_path / "config"))   # a list of this test's own
    ev = tmp_path / "evidence"
    (ev / "DC01").mkdir(parents=True)
    (ev / "DC01" / "notes.txt").write_text("evidence")
    here = create_case(tmp_path / "cases" / "here", "Here", ev, "cody")
    for name in ("Gone 1", "Gone 2", "Gone 3", "No yaml"):
        remember(SimpleNamespace(folder=tmp_path / "cases" / name, settings=SimpleNamespace(
            name=name, evidence_path=str(ev), tools_folder="")), 5)
    remember(here, 0)
    kept = tmp_path / "cases" / "No yaml" / "kept.txt"   # a folder with no case.yaml reads as not found too
    kept.parent.mkdir()
    kept.write_text("not a case")
    for page in served_page(browser, None, ready="() => window.__start && window.__start.info !== null"):
        start = page.locator("#start")
        row = lambda name: start.locator(".start-case").filter(   # noqa: B023  (by the name alone: a path holds words too)
            has=page.locator(".name", has_text=re.compile(f"^{re.escape(name)}$")))   # noqa: B023
        assert row("Here").get_by_role("button").all_inner_texts() == ["Open", "Copy"]
        assert row("Here").get_by_role("button", name="Open Here").is_enabled()
        for name in ("Gone 1", "Gone 2", "Gone 3", "No yaml"):
            assert "folder not found" in row(name).inner_text()
            assert row(name).get_by_role("button").all_inner_texts() == ["Open", "Copy", "Remove from list"]
            assert row(name).get_by_role("button", name=f"Open {name}").is_disabled()
            assert row(name).get_by_role("button", name=f"Remove from list: {name}").is_enabled()
        line = start.locator(".start-missing")
        assert line.text_content() == "Folder not found for 4 cases.Remove the 4 from the list"
        assert line.get_by_role("button").get_attribute("title") == "Changes only this list. No case folder is touched."
        # One row
        row("Gone 1").get_by_role("button", name="Remove from list: Gone 1").click()
        page.wait_for_function("() => document.getElementById('status').textContent === 'Removed Gone 1 from Recent cases.'")
        assert row("Gone 1").count() == 0 and line.text_content() == "Folder not found for 3 cases.Remove the 3 from the list"
        # A case whose folder came back after the page drew stays, and its row opens again
        create_case(tmp_path / "cases" / "Gone 2", "Gone 2", ev, "cody")
        row("Gone 2").get_by_role("button", name="Remove from list: Gone 2").click()
        page.wait_for_function("() => document.getElementById('status').textContent === "
                               "'The folder of Gone 2 is there again, so it stays on the list.'")
        assert row("Gone 2").get_by_role("button").all_inner_texts() == ["Open", "Copy"]
        assert row("Gone 2").get_by_role("button", name="Open Gone 2").is_enabled()
        # The line takes the rest. A double click sends one request: the buttons are off until the answer, where a
        # second request had come back with nothing removed
        sent = []
        page.on("request", lambda req: sent.append(req.url) if req.url.endswith("/api/start/forget") else None)  # noqa: B023
        line.get_by_role("button", name="Remove the 2 from the list").dblclick()
        page.wait_for_function("() => document.getElementById('status').textContent === 'Removed 2 cases from Recent cases.'")
        page.wait_for_load_state("networkidle")
        assert len(sent) == 1 and page.locator("#status").text_content() == "Removed 2 cases from Recent cases."
        assert line.count() == 0
        assert [r["name"] for r in load_recent()] == ["Here", "Gone 2"]
        assert start.locator(".start-case .name").all_inner_texts() == ["Here", "Gone 2"]
        assert kept.read_text() == "not a case" and (here.folder / "case.yaml").is_file()


def test_clock_switch_aligns_the_hosts_and_sets_them_back(clock_page):
    """Times stay as recorded until the Case panel's switch aligns them, and the hosts' lane flags say which.
    DESKTOP's says its clock was changed twice, and its hover text names the changes and the span the offset fits."""
    p = clock_page
    assert p.locator("#clockSwitch").is_visible()
    assert [p.locator(f"#{b}").get_attribute("aria-pressed") for b in ("clockRecorded", "clockAligned")] == ["true", "false"]
    flag = p.locator("#labels .clock-flag").first
    assert flag.inner_text() == "clock +1 h"   # short, so the default label width shows it; the exact skew is in the hover
    assert "from 10 RDP connections; 10 of 10 pairs within 2 s" in flag.get_attribute("title")
    desktop = p.locator("#labels .row", has_text="DESKTOP").locator(".clock-flag")
    assert desktop.inner_text() == "clock +1 h*"   # the asterisk: its clock was changed, which the hover explains first
    assert desktop.get_attribute("title").startswith("* DESKTOP's clock was changed twice;")
    assert "ran 59 m 59.5 s ahead of the capture" in desktop.get_attribute("title")
    assert ("Its clock was changed by -3,599.6 s at 2020-09-19 00:21:48 and by +3,599.2 s at 2020-09-19 02:51:47 host "
            "time.\nThe pairs cover 2020-09-19 03:25:07 to 2020-09-19 03:28:07 host time, so one offset fits only its "
            "events before the clock change at 2020-09-19 00:21:48 and after the clock change at 2020-09-19 02:51:47.") \
        in desktop.get_attribute("title")
    assert p.locator("#labels .row", has_text="WS02").locator(".clock-flag").count() == 0   # its pairs disagree
    flags = "() => [...document.querySelectorAll('#labels .clock-flag')].map((f) => f.textContent.replace('*', ''))"
    recorded = ["clock +1 h"]
    # With a 131's Event page open, the 131 keeps its place on screen and the window moves an hour instead.
    p.evaluate("(uid) => window.__app.select(uid, false)", event_point(p, "131")["uid"])
    p.locator("#details .ev-clock").wait_for()
    before = view(p)
    p.locator("#clockAligned").click()
    p.wait_for_selector("#clockAligned[aria-pressed='true']")
    p.wait_for_function(f"() => ({flags})().every((t) => t === 'aligned to the capture')")
    assert p.locator("#clockRecorded").get_attribute("aria-pressed") == "false"
    assert p.evaluate("window.__app.S.meta.hosts.find((h) => h.host === 'DC01').offset_seconds") == -3599.5
    assert round(view(p)["start"] - before["start"]) == -3_599_500
    p.locator("#details .ev-clock", has_text="Times here are aligned to the capture.").wait_for()
    p.locator("#clockRecorded").click()
    p.wait_for_selector("#clockRecorded[aria-pressed='true']")
    p.wait_for_function(f"(want) => ({flags})().every((t) => want.includes(t))", arg=recorded)
    assert sorted(set(p.evaluate(flags))) == recorded
    assert p.evaluate("window.__app.S.meta.hosts.find((h) => h.host === 'DC01').offset_seconds") == 0
    assert round(view(p)["start"]) == round(before["start"])


def test_a_double_click_on_the_switch_aligns_once(clock_page, synthetic_case):
    """A second click before the first one's answer is ignored, so each host gets one journal entry
    and no request fails (served_page checks every response)."""
    p = clock_page
    posts = []
    p.on("request", lambda r: posts.append(r.url) if r.method == "POST" and r.url.endswith("/api/host") else None)
    for half in ("clockAligned", "clockRecorded"):
        p.locator(f"#{half}").dblclick()
        p.wait_for_selector(f"#{half}[aria-pressed='true']")
        p.wait_for_selector("#clockSwitch button[aria-disabled]", state="detached")
    assert len(posts) == 2
    entries = read_entries(synthetic_case.folder / JOURNAL_FILE)
    assert [(e["host"], e["seconds"]) for e in entries if e["action"] == "host_offset"] == [
        ("DC01", -3599.5), ("DESKTOP", -3599.5), ("DC01", 0.0), ("DESKTOP", 0.0)]


def test_an_offset_typed_by_hand_aligns_nothing(clock_page):
    """An offset that isn't the suggestion aligns no host, so neither half is pressed and nothing is
    "partly aligned". As recorded sets back only the switch's offsets, so it says why it changes nothing."""
    p = clock_page
    case_menu(p, "hostsButton")
    offset = p.locator("#hostsTable tr[data-host='DC01'] input[type=number]")
    offset.fill("10")
    offset.dispatch_event("change")
    p.wait_for_selector("#clockSwitch[data-state='neither']")
    assert [p.locator(f"#{b}").get_attribute("aria-pressed") for b in ("clockRecorded", "clockAligned")] == ["false", "false"]
    assert p.locator("#clockPartly").is_hidden()
    p.evaluate("""() => { window.__statuses = []; new MutationObserver(() => window.__statuses.push(
        document.getElementById('status').textContent)).observe(document.getElementById('status'), { childList: true }); }""")
    p.locator("#clockRecorded").click()
    p.wait_for_function("(m) => window.__statuses.includes(m)", arg="There are no offsets from this switch to set back. "
                                                                   "Offsets typed in the Hosts panel stay: DC01.")
    assert p.evaluate("window.__app.S.meta.hosts.find((h) => h.host === 'DC01').offset_seconds") == 10


def test_the_page_names_tools_and_artifacts_as_the_server_does(clock_page):
    """The page takes tool and artifact names from /api/meta, which sends the registry's tool names and the parsers'
    artifact names, not from lists of its own. The Sources panel shows the capture's flows as "suricata (Suricata t)"
    and their Event page as "Suricata"."""
    from test_clock import CAPTURE

    from glessner.events import event_uid

    p = clock_page
    p.locator("#filtersButton").click()
    p.wait_for_selector("#fpTypes .frow")
    assert "suricata (Suricata t)" in p.locator("#fpTypes").inner_text()
    ts = T0 - 3480 * SEC
    uid = event_uid("network", "suricata", CAPTURE, f"flow|{ts}|194.61.24.102:51000|10.42.85.10:3389",
                    "Suricata flow started")
    p.evaluate("(uid) => window.__app.select(uid, false)", uid)
    p.wait_for_selector("#details .ev-ident .kind:text-is('Suricata, Suricata flow started')")


def test_hosts_panel_aligns_one_host_to_the_capture(clock_page):
    """The Clock offset cell says what the check found, and Align to the capture sets the suggested offset.
    With DESKTOP still as recorded, the switch says the hosts are partly aligned. The focus goes to the offset set."""
    p = clock_page
    case_menu(p, "hostsButton")
    check = p.locator("#hostsTable tr[data-host='DC01'] .clock-check")
    assert check.locator(".clock-head").inner_text() == "Clock looks 59 m 59.5 s ahead of the capture"
    assert "Measured against network, from 10 RDP connections; 10 of 10 pairs within 2 s." in check.inner_text()
    assert "Consistent with a clock set to the wrong hour or zone." in check.inner_text()
    assert p.locator("#hostsTable tr[data-host='network'] .clock-check").inner_text() == \
        "This lane is the capture the other hosts' clocks are checked against."
    desktop = p.locator("#hostsTable tr[data-host='DESKTOP'] .clock-check").inner_text()
    assert "Its clock was changed by -3,599.6 s at 2020-09-19 00:21:48 and by +3,599.2 s" in desktop
    assert "so one offset fits only its events before the clock change at 2020-09-19 00:21:48" in desktop
    split = p.locator("#hostsTable tr[data-host='WS02'] .clock-check[data-clock='disagree']")
    assert split.locator(".clock-head").inner_text() == "Pairs with the capture disagree"
    assert re.search(r"Groups of pairs suggest (-1,800 s \(5 pairs\), -3,599\.5 s|-3,599\.5 s \(5 pairs\), -1,800 s) "
                     r"\(5 pairs\)\.", split.inner_text())
    assert ("Its events pair with the capture's (network), but a second group of 5 pairs competes with the 5 that agree, "
            "so no offset is suggested.") in split.inner_text()
    check.get_by_role("button", name="Align to the capture: DC01").click()
    p.wait_for_selector("#hostsTable tr[data-host='DC01'] .clock-check[data-clock='agrees']")
    assert check.inner_text() == "Aligned to the capture"
    assert p.locator("#hostsTable tr[data-host='DC01'] input[type=number]").input_value() == "-3599.5"
    p.wait_for_selector("#clockSwitch[data-state='partly']")
    assert p.locator("#clockPartly").is_visible()
    assert [p.locator(f"#{b}").get_attribute("aria-pressed") for b in ("clockRecorded", "clockAligned")] == ["false", "false"]
    p.wait_for_selector("#clockSwitch button[aria-disabled]", state="detached")
    assert p.evaluate("[document.activeElement.type, document.activeElement.closest('tr').dataset.host]") == ["number", "DC01"]


def test_event_page_names_the_pair_and_show_the_pair_draws_the_link(clock_page):
    """A paired 131's Event page gives both clocks and its flow in the capture. The dashed link runs from the
    131's lane to the capture's, also when zoomed out to density bars, and to the window's edge when the pair is outside
    it. Show the pair selects the flow and fits both; aligning DC01 from the flow's page brings the 131 to it."""
    p = clock_page
    rdp = event_point(p, "131")
    p.evaluate("(uid) => window.__app.select(uid, false)", rdp["uid"])
    note = p.locator("#details .ev-clock")
    note.wait_for()
    assert note.inner_text().startswith("DC01's clock ran 59 m 59.5 s ahead of the capture (10 of 10 pairs agree). "
                                        "Times here are as recorded.")
    assert re.search(r"This event's pair: Flow 194\.61\.24\.102:510\d\d -> 10\.42\.85\.10:3389, seen in the capture at "
                     r"02:2\d:\d\d\.000 UTC", note.inner_text())
    drawn = "([from, edge]) => { const d = window.__app.S.pairDrawn; return d && d.from === from && d.edge === edge; }"
    rows = "() => window.__app.S.pairDrawn.rows.map((r) => window.__app.S.rows[r].label)"
    p.wait_for_function(drawn, arg=[rdp["uid"], None])
    flow_uid = p.evaluate("window.__app.S.pairDrawn.to")
    assert p.evaluate("window.__app.S.pairDrawn.label") == "same RDP connection, host clock +59 m 59.5 s"
    assert p.evaluate(rows) == ["DC01", "network"]
    # Zoomed out to density bars, neither end is a tick, so both are looked up by ID in the timeline's lanes.
    threshold = p.evaluate("window.__app.S.meta.event_threshold")
    p.evaluate("() => { window.__app.S.meta.event_threshold = 5; return window.__app.fetchView(); }")
    p.wait_for_function("(uid) => { const d = window.__app.S.pairDrawn; "
                        "return window.__app.S.data.mode === 'density' && d && d.from === uid && !d.edge; }", arg=rdp["uid"])
    assert p.evaluate(rows) == ["DC01", "network"]
    p.evaluate("(n) => { window.__app.S.meta.event_threshold = n; return window.__app.fetchView(); }", threshold)
    # Zoomed in on the 131, the flow an hour earlier is off to the left: the link runs to the edge and says where.
    at = p.evaluate("window.__app.S.pairLink.ts") / 1000
    p.evaluate("([s, e]) => window.__app.setView(s, e)", [at - 60_000, at + 60_000])
    p.wait_for_function(drawn, arg=[rdp["uid"], "left"])
    assert re.search(r"; pair at 02:2\d:\d\d\.000 UTC, before this window$", p.evaluate("window.__app.S.pairDrawn.label"))
    assert p.evaluate(rows) == ["DC01", "network"]
    # From the keyboard, Show the pair leaves the focus on the flow's own Show the pair, which leads back.
    p.locator("#details").get_by_role("button", name="Show the pair").focus()
    p.keyboard.press("Enter")
    p.wait_for_function(drawn, arg=[flow_uid, None])
    p.wait_for_function("() => window.__app.S.anim === null")   # the zoom to fit both has ended
    assert p.evaluate("[...window.__app.S.selected]") == [flow_uid]
    assert p.evaluate(rows) == ["network", "DC01"]
    v = view(p)
    assert v["start"] < at - 3_599_500 and v["end"] > at
    note = p.locator("#details .ev-clock")
    assert "DC01's times on the timeline are as recorded." in note.inner_text()
    assert re.search(r"This record's pair on DC01: 131 connection accepted, recorded at 03:2\d:\d\d\.500 on DC01's clock",
                     note.inner_text())
    p.wait_for_function("() => document.activeElement.textContent === 'Show the pair' "
                        "&& document.activeElement.closest('.ev-clock') !== null")
    # Zoomed in on the flow, the 131 an hour later is off to the right.
    p.evaluate("([s, e]) => window.__app.setView(s, e)", [at - 3_599_500 - 60_000, at - 3_599_500 + 60_000])
    p.wait_for_function(drawn, arg=[flow_uid, "right"])
    assert re.search(r"; pair at 03:2\d:\d\d\.500 UTC, after this window$", p.evaluate("window.__app.S.pairDrawn.label"))
    v = view(p)
    note.get_by_role("button", name="Align DC01 to the capture").click()
    p.wait_for_selector("#clockSwitch[data-state='partly']")   # DESKTOP is still as recorded
    p.wait_for_function("() => { const d = window.__app.S.pairDrawn; return d && !d.edge && d.label.endsWith(', aligned'); }")
    assert view(p) == v   # the flow didn't move, so neither did the window, and the 131 came into it
    assert "DC01's times on the timeline are aligned to the capture." in p.locator("#details .ev-clock").inner_text()
    assert p.locator("#details .ev-clock").get_by_role("button", name="Align DC01 to the capture").count() == 0
    p.wait_for_selector("#clockSwitch button[aria-disabled]", state="detached")
    assert p.evaluate("document.activeElement.textContent") == "Show the pair"   # the button it had is gone


def test_hosts_panel_splits_a_mixed_host_keeps_and_undoes(browser, tmp_path):
    """LAB's event logs record three computers, so the Hosts panel says so with the numbers from the case. The
    preview lists a new host per computer; the split gives each a lane, drops a View value naming LAB, and the Event
    page says where a moved event was loaded from. Undo split puts LAB back, and Keep as one host journals the choice
    and takes the notice away, leaving the split on offer. The preview's buttons are in view, and the keyboard focus
    goes to the control that replaces each one clicked."""
    from test_splits import lab_case

    case, _ = lab_case(tmp_path)
    focused = "() => document.activeElement.getAttribute('aria-label') || document.activeElement.textContent"
    for p in served_page(browser, case):
        # A short window, where a preview in a panel 40% of its height would hide the buttons
        p.set_viewport_size({"width": 1400, "height": 700})
        case_menu(p, "hostsButton")
        notice = p.locator("#hostSplits .split-notice")
        assert notice.locator("p").inner_text() == (
            "LAB's event logs were recorded by 3 computers. They read as one machine: one lane, one role guess "
            "(Domain controllers), 3 names, and logon-session and time-window pivots that join events across machines.")
        opener = notice.get_by_role("button", name="Split LAB by recorded computer…")
        opener.click()
        preview = notice.locator(".split-preview")
        preview.locator("h3").wait_for()
        assert opener.get_attribute("aria-expanded") == "true" and p.evaluate(focused) == "Split LAB into 4 hosts"
        assert preview.locator("h3").inner_text() == "Split LAB into 4 hosts"   # LAB keeps a hit with no computer
        assert preview.locator("p").first.inner_text() == (
            "Each event goes to the computer it records, and each Hayabusa row with it.")
        assert [r.split("\t") for r in preview.locator("tbody tr").all_inner_texts()] == [
            ["PC01", "PC01.example.corp", "3", "1", "2"], ["MSEDGEWIN10", "MSEDGEWIN10", "2", "1", "1"],
            ["DC1", "DC1.insecurebank.local", "1", "0", "1"]]
        happens = preview.locator("li").all_inner_texts()
        assert "Event logs alone give neither" in happens[0]
        assert happens[1] == ("The logon-session and time-window pivots stay within one machine. Same account, Same "
                              "source IP, Same source IP and port, Same file, and Same IP at either end search the "
                              "whole case, as they always do.")
        assert happens[3].endswith("1 Hayabusa row that records no computer stays on LAB.")
        go = preview.get_by_role("button", name="Split into 4 hosts")
        in_view = """(b) => { const r = b.getBoundingClientRect(), panel = document.getElementById('hostsPanel')
                                                                                  .getBoundingClientRect();
                              return r.top >= panel.top && r.bottom <= panel.bottom && r.bottom <= innerHeight; }"""
        assert go.evaluate(in_view)
        preview.get_by_role("button", name="Cancel").click()
        assert preview.is_hidden() and opener.get_attribute("aria-expanded") == "false"
        assert p.evaluate(focused) == "Split LAB by recorded computer…"
        opener.click()
        go.click()
        p.wait_for_selector("#hostSplits .split-done")
        p.wait_for_function("() => document.getElementById('status').textContent === 'Split LAB into 3 new hosts'")
        assert notice.count() == 0
        p.wait_for_function(f"() => ({focused})() === 'Undo split of LAB'")
        p.wait_for_function("() => window.__app.S.lanes.some((l) => l.keys.includes('PC01'))")
        assert "PC01" in "\n".join(labels(p)) and "MSEDGEWIN10" in "\n".join(labels(p))
        rows = p.locator("#hostsTable tbody tr").all_inner_texts()
        assert sorted(r.split("\t")[0] for r in rows) == ["DC1", "LAB", "MSEDGEWIN10", "PC01"]
        p.evaluate("(uid) => window.__app.select(uid, false)", event_point(p, "4688")["uid"])   # PC01's, both of them
        p.locator("#details .split-from").wait_for()
        split_seq = read_entries(case.folder / JOURNAL_FILE)[-1]["seq"]
        assert p.locator("#details .split-from").inner_text() == f"Loaded from LAB, shown on PC01 (split #{split_seq})"
        # A View value naming PC01 matches nothing once the undo takes PC01 away, so it comes off.
        p.evaluate("async () => (await import('/js/view.js')).addViewValue({ host: 'PC01' })")
        p.wait_for_selector("#viewCount:not([hidden])")
        done = p.locator("#hostSplits .split-done")
        done.get_by_role("button", name="Undo split of LAB", exact=True).click()
        assert p.evaluate(focused) == "Confirm undo split of LAB"
        done.get_by_role("button", name="Confirm undo split of LAB").click()
        p.wait_for_selector("#hostSplits .split-notice")
        p.wait_for_function("() => document.getElementById('status').textContent.startsWith('Undid')")
        assert p.locator("#status").inner_text() == (
            "Undid the split of LAB; 1 filter value naming a host that's gone came off")
        assert p.locator("#viewCount").is_hidden() and p.locator("#hostSplits .split-done").count() == 0
        p.wait_for_function(f"() => ({focused})() === 'Split LAB by recorded computer…'")
        p.wait_for_function("() => !window.__app.S.lanes.some((l) => l.keys.includes('PC01'))")
        p.locator("#hostSplits").get_by_role("button", name="Keep LAB as one host").click()
        p.wait_for_selector("#hostSplits .split-notice", state="detached")
        # Kept, with the split still on offer from the host's line, which takes the focus
        kept = p.locator("#hostSplits .split-kept")
        assert kept.locator("p").inner_text().startswith(
            "LAB is kept as one host, though its event logs record 3 computers (#")
        p.wait_for_function(f"() => ({focused})() === 'Split LAB by recorded computer…'")
        kept.get_by_role("button", name="Split LAB by recorded computer…").click()
        kept.locator(".split-preview h3").wait_for()
        entries = read_entries(case.folder / JOURNAL_FILE)
        assert [e["op"] for e in entries if e["action"] == "host_split"] == ["split", "undo", "keep"]


def window_text(start_ms, end_ms):
    """The window as the export controls on the Findings page name it (core.js windowText)."""
    def fmt(ms):
        return datetime.fromtimestamp(ms // 1000, UTC).strftime("%Y-%m-%d %H:%M:%S") + f".{ms % 1000:03d}"
    return f"{fmt(start_ms)} to {fmt(end_ms)} UTC"


def test_export_covers_the_window_the_page_names_as_the_view_moves(page):
    """The Export page (the Findings page's export controls) names the window on screen as the view moves, exports
    that one, and names it again in the result. DC01's first minute holds its five logons; the whole case holds them,
    DESKTOP's three, and six registry values, two of them the page fixture's zone."""
    whole = view(page)
    case_menu(page, "exportButton")
    page.wait_for_selector("#details[data-page='findings'] #exportWindow")
    named, result = page.locator("#exportWindow"), page.locator("#details .export-result")
    window_csv = page.locator("#details .export-card", has_text="Events in the window").get_by_role("button", name="CSV")
    assert named.inner_text() == window_text(int(whole["start"]), int(whole["end"]))
    minute = [T0 // 1000 - 1000, T0 // 1000 + 64_000]
    page.evaluate("([a, b]) => window.__app.setView(a, b)", minute)   # zoomed in after the page opened
    assert named.inner_text() == window_text(*minute)
    window_csv.click()
    page.wait_for_function("() => document.querySelector('#details .export-result')?.textContent.startsWith('Wrote')")
    assert result.inner_text().startswith("Wrote 5 events to ")
    # The window sentence, then the head after the file's entry
    assert f". Window: {window_text(*minute)}. Journal head after recording this file: " in result.inner_text()
    page.evaluate("([a, b]) => window.__app.setView(a, b)", [whole["start"], whole["end"]])
    assert named.inner_text() == window_text(int(whole["start"]), int(whole["end"]))
    first = result.inner_text()
    window_csv.click()
    page.wait_for_function("(first) => document.querySelector('#details .export-result').textContent !== first", arg=first)
    assert result.inner_text().startswith("Wrote 14 events to ")
    assert f". Window: {window_text(int(whole['start']), int(whole['end']))}. Journal head " in result.inner_text()


def test_event_page_keeps_its_body_in_view_under_a_tall_header(browser, synthetic_case):
    """An event with a pending suggestion and rows of Hayabusa's hits and suggested tags has a tall header. In a panel
    dragged to its shortest, where the header takes more than half of it, the body keeps a height of its own, at least
    160 px, and the panel scrolls to it, so the fields, pivots, and notes below the header stay in reach."""
    tactics = " ¦ ".join(["InitAccess", "Exec", "Persis", "PrivEsc", "Evas", "CredAccess", "Disc", "LatMov", "Collect",
                          "C2", "Exfil", "Impact"])
    hits = [Event(ts_us=T0, ts_desc="Event Recorded", artifact="hayabusa", source_file=DC_LOG, source_record=f"101:r{i}",
                  record_id=101, message=f"Rule {i} [high]", log_channel="Security",
                  rule_title=f"A long Hayabusa rule title that takes up a good part of a line, number {i}",
                  rule_level="high", extra={"MitreTactics": tactics,
                                            "MitreTags": " ¦ ".join(f"T10{j:02d}.001" for j in range(8))})
            for i in range(3)]
    load(synthetic_case.db_path, hits, host="DC01", tool="hayabusa", tool_version="t", run_id="r6",
         replaces_sources=[], staging_dir=synthetic_case.folder)
    for page in served_page(browser, synthetic_case):
        rdp = event_point(page, "4624", hit=True)
        page.evaluate("(uid) => window.__app.select(uid, false)", rdp["uid"])
        page.locator("#details .ev-sum button.more").click()   # the other hits, in the header's third row
        page.locator("#details .ev-head-more .chips").first.wait_for()
        page.locator("#details button.tw").click()
        page.locator("#details .tagchip.suggested").first.wait_for()
        page.locator("#divider").focus()
        for _ in range(40):
            page.keyboard.press("ArrowDown")   # the panel to its shortest
        sizes = page.evaluate("""() => ({ panel: document.getElementById('details').clientHeight,
            head: document.querySelector('#details .ev-head').offsetHeight,
            body: document.querySelector('#details .ev-body').offsetHeight,
            scroller: [document.getElementById('detailsBody').clientHeight,
                       document.getElementById('detailsBody').scrollHeight] })""")
        assert sizes["head"] > sizes["panel"] / 2 and sizes["body"] >= 160, sizes
        assert sizes["scroller"][1] > sizes["scroller"][0], sizes   # the panel scrolls to the body
        page.locator("#details").get_by_text("Raw fields", exact=False).click(timeout=5_000)
        assert page.locator("#details details.raw").evaluate("(d) => d.open")


def test_accept_keeps_the_note_typed_before_it(page, synthetic_case):
    """A note typed in the verdict zone before Accept as Suspicious goes with the mark."""
    rdp = event_point(page, "4624", hit=True)
    page.evaluate("(uid) => window.__app.select(uid, false)", rdp["uid"])
    page.locator("#details .mark-note").fill("RDP from the internet as Administrator")
    accept = page.locator("#details button.primary", has_text="Accept as")
    assert accept.inner_text() == "Accept as Suspicious"   # the mark's word
    page.locator("#details").get_by_role("button", name="Accept as Suspicious").click()
    page.wait_for_selector("#details .mark-note-text")
    assert page.locator("#details .mark-note-text").inner_text() == (
        "Note: Accepted suggestion from hayabusa: RDP from the internet as Administrator")
    assert read_entries(synthetic_case.folder / JOURNAL_FILE)[-1]["note"] == (
        "Accepted suggestion from hayabusa: RDP from the internet as Administrator")


def latest_lone_point(p, code):
    """The page coordinates of the latest drawn event with this event code that no other event shares 3 px with, so a
    click on it selects it rather than listing a pile."""
    point = p.evaluate(f"""(code) => {{
        let found = null;
        for (const [row, items] of window.__app.S.index.entries()) {{
            const events = (items || []).filter((it) => it.kind === 'event');
            for (const it of events) {{
                if (it.e.code === code && events.filter((o) => Math.abs(o.x - it.x) <= 3).length === 1
                    && (!found || it.x > found.it.x)) found = {{ row, it }};
            }}
        }}
        return found && ({POINT})(found.row, found.it, found.it.e.uid);
    }}""", code)
    assert point, f"no lone drawn event with code {code}"
    return point


def shift_click(p, point):
    p.keyboard.down("Shift")
    p.mouse.click(point["x"], point["y"])
    p.keyboard.up("Shift")


def selected(p):
    return p.evaluate("[...window.__app.S.selected].sort()")


def test_a_group_mark_lists_its_events_and_marks_and_a_pile_starts_a_new_selection(page):
    """A plain click on stacked events opens their list and starts a new selection, so the next shift-click can't mark
    an event the analyst no longer has in view. The verdict for several events lists each selected event with its
    mark, and the status line says what a mark did. At Fit case DC01's last three logons share a pixel."""
    rdp = event_point(page, "4624", hit=True)
    page.mouse.click(rdp["x"], rdp["y"])
    page.locator("#details .ev-verdict").get_by_role("button", name="Malicious", exact=True).click()
    page.wait_for_function("(text) => document.getElementById('status').textContent.startsWith(text)",
                           arg="Marked one event Malicious · ")
    pile = event_point(page, "4672")
    page.mouse.click(pile["x"], pile["y"])
    page.wait_for_selector("#details[data-page='pile']")
    assert selected(page) == []
    explicit = latest_lone_point(page, "4624")   # DESKTOP's 4624 at 03:36:22
    shift_click(page, explicit)
    page.wait_for_selector("#details[data-page='event'] .ev-verdict")
    assert selected(page) == [explicit["uid"]]
    shift_click(page, event_point(page, "4624", hit=True))
    zone = page.locator("#details .ev-verdict")
    listing = page.locator("#details .ev-head-more .selection-list")   # the header's third row
    listing.wait_for()
    assert zone.locator("h3").first.inner_text().lower() == "verdict for 2 selected events"
    assert listing.locator(".sel-text").all_text_contents() == [   # in time order
        "2020-09-19 03:21:48.000000  DC01  4624 logon", "2020-09-19 03:36:22.000000  DESKTOP  4624 logon"]
    assert listing.locator(".badge").all_text_contents() == ["M", "U"]   # the badge leads each row
    zone.get_by_role("button", name="Suspicious (2)").click()
    page.wait_for_function("(text) => document.getElementById('status').textContent.startsWith(text)",
                           arg="Marked 2 events Suspicious · ")
    page.wait_for_function("() => [...document.querySelectorAll('#details .selection-list .badge')]"
                           ".every((s) => s.textContent === 'S')")


def test_a_shift_click_on_stacked_events_lists_them_and_a_pick_joins_the_selection(page):
    """A shift-click on stacked events lists them with the selection kept, instead of adding whichever one the hit
    test finds first, and a shift-click on one in the list adds it without replacing the selection."""
    explicit = latest_lone_point(page, "4624")   # DESKTOP's 4624 at 03:36:22
    page.mouse.click(explicit["x"], explicit["y"])
    page.wait_for_selector("#details[data-page='event'] .ev-verdict")
    shift_click(page, event_point(page, "4672"))
    pile = page.locator("#details[data-page='pile']")
    pile.wait_for()
    assert page.locator("#detailsBand .title").inner_text() == "3 events under the cursor"
    assert selected(page) == [explicit["uid"]]
    pile.locator("li", has_text="4672 logon").click(modifiers=["Shift"])
    page.locator("#details .ev-head-more .selection-list").wait_for()
    assert len(selected(page)) == 2 and explicit["uid"] in selected(page)
    texts = page.locator("#details .selection-list .sel-text").all_text_contents()
    assert [t.split("  ")[1:3] for t in texts] == [["DC01", "4672 logon"], ["DESKTOP", "4624 logon"]], texts


def test_a_pile_list_stays_when_the_focused_event_answers_after_it(page):
    """A shift-click on stacked events keeps the focus, and the focused event's page, still loading, doesn't replace
    their list when it answers. The selection list's request is held here until the pile list is
    shown, as a slow one on a large case would be."""
    explicit = latest_lone_point(page, "4624")   # DESKTOP's 4624 at 03:36:22
    page.mouse.click(explicit["x"], explicit["y"])
    page.wait_for_selector("#details[data-page='event'] .ev-verdict")
    held = []
    page.route("**/api/selected?*", lambda route: held.append(route))
    with page.expect_request("**/api/selected?*"):
        shift_click(page, event_point(page, "4624", hit=True))
    shift_click(page, event_point(page, "4672"))
    page.wait_for_selector("#details[data-page='pile']")
    while not held:
        page.wait_for_timeout(20)
    with page.expect_response("**/api/selected?*"):
        held[0].continue_()
    page.wait_for_timeout(300)   # time for the event page to draw, had it still meant to
    assert page.locator("#details").get_attribute("data-page") == "pile"
    assert len(selected(page)) == 2 and explicit["uid"] in selected(page)


def test_a_search_that_answers_late_leaves_the_event_page_opened_after_it(page):
    """A search that answers after the analyst has opened an event from the earlier results doesn't replace that
    event's page. The second search's request is held here until the event's page shows."""
    page.locator("#search").fill("code:4624")
    page.locator("#search").press("Enter")
    page.wait_for_selector("#details[data-page='search'] .related li.rel-row")
    held = []
    page.route("**/api/search?*", lambda route: held.append(route))
    page.locator("#search").fill("code:4672")
    with page.expect_request("**/api/search?*"):
        page.locator("#search").press("Enter")
    page.locator("#details .related li.rel-row .rel-text").first.click()
    page.wait_for_selector("#details[data-page='event'] .ev-ident")
    while not held:
        page.wait_for_timeout(20)
    with page.expect_response("**/api/search?*"):
        held[0].continue_()
    page.wait_for_timeout(300)   # time for the search to draw, had it still meant to
    assert page.locator("#details").get_attribute("data-page") == "event"


def test_a_page_that_answers_late_leaves_any_page_asked_for_after_it(page, synthetic_case):
    """A search that answers late doesn't replace To investigate, Rules, or the audit trail opened after it, and those
    pages, answering late, don't replace a search made after them. A page that waits for its request claims the Details
    panel when asked, and any other, such as Export, as it draws. The Import page waits for its list and then for its
    first file's preview."""
    from glessner.intake import intake

    (synthetic_case.evidence / "DC01" / "pfirewall.log").write_bytes(
        b"#Version: 1.5\r\n#Software: Microsoft Windows Firewall\r\n#Time Format: Local\r\n#Fields: date time action\r\n"
        b"2020-09-19 03:21:50 ALLOW\r\n")
    intake(synthetic_case)

    def held_until_shown(pattern, ask, later, shown):
        """Ask for a page whose request is held, then for another page, and answer the first once the other shows."""
        held = []
        page.route(pattern, lambda route: held.append(route))
        ask()
        while not held:
            page.wait_for_timeout(20)
        later()
        page.wait_for_selector(f"#details[data-page='{shown}']")
        with page.expect_response(pattern):
            held[0].continue_()
        page.wait_for_timeout(300)   # time for the first page to draw, had it still meant to
        page.unroute(pattern)
        assert page.locator("#details").get_attribute("data-page") == shown

    def search():
        page.locator("#search").fill("code:4624")
        page.locator("#search").press("Enter")

    def suggestions():
        page.locator("#investigateButton").click()
        page.wait_for_selector("#details[data-page='investigate']")
        page.locator("#details").get_by_role("button", name="hayabusa", exact=True).click()

    pages = {"investigate": ["**/api/investigate"], "rules": ["**/api/rules"], "audit": ["**/api/audit?*"],
             "import": ["**/api/imports*", "**/api/import_preview"], "suggestions": ["**/api/pending?*"], "export": []}
    for name, patterns in pages.items():
        # To investigate is on the path; the others are in the Case menu
        if name == "suggestions":
            show = suggestions
        elif name == "investigate":
            show = lambda: page.locator("#investigateButton").click()
        else:
            show = lambda name=name: case_menu(page, f"{name}Button")
        shown = "findings" if name == "export" else name   # the Case menu's Export opens the Findings page
        held_until_shown("**/api/search?*", search, show, shown)   # the search first
        for pattern in patterns:
            held_until_shown(pattern, show, search, "search")       # the page first


def test_local_time_on_the_host_stays_its_own_clock_after_an_offset(page, synthetic_case):
    """With a clock offset on the host, "Local time on DC01" gives the time as recorded, on DC01's own clock, not the
    adjusted time, which DC01's clock never showed: Pacific daylight time in September 2020.

    Enter commits the offset once. A change event dispatched after fill() would send it, and the field's own change on
    blur would send it again; the event's page could then be read while the second edit rebuilds the hosts table,
    which shows no offset (2 failures in 27 runs)."""
    rdp = event_point(page, "4624", hit=True)   # recorded at 2020-09-19 03:21:48 UTC
    case_menu(page, "hostsButton")
    offset = page.locator("#hostsTable tr[data-host='DC01'] input[type=number]")
    offset.fill("3600")
    offset.press("Enter")
    page.wait_for_function("() => window.__app.S.meta.hosts.find((h) => h.host === 'DC01').offset_seconds === 3600")
    page.evaluate("(uid) => window.__app.select(uid, false)", rdp["uid"])
    # The timeline's time, moved by the offset, once the event's page has drawn with it
    page.wait_for_function("() => (document.querySelector('#details .ev-ident') || {}).textContent"
                           "?.includes('2020-09-19 04:21:48.000000 UTC')")
    # The time's hover has the recorded time and DC01's own clock
    title = page.locator("#details .ev-ident .time").get_attribute("title")
    assert "Recorded 2020-09-19 03:21:48.000000 UTC" in title
    assert "Local time on DC01: 2020-09-18 20:21:48.000000 PDT" in title
    offsets = [e for e in read_entries(synthetic_case.folder / JOURNAL_FILE) if e["action"] == "host_offset"]
    assert len(offsets) == 1


def test_tools_page_says_what_it_is_doing_while_the_tools_report(browser, synthetic_case):
    """The Tools page's first open after the server starts runs every tool's version check, about 4 s, and the page
    says what it is doing meanwhile, so a new case doesn't look hung. The answer is held here as a slow one would be."""
    from glessner.tools import load_registry

    for page in served_page(browser, synthetic_case, setup=lambda app: setattr(app, "tool_cache", (load_registry(), {}))):
        held = []
        page.route("**/api/tools*", lambda route: held.append(route))   # noqa: B023
        case_menu(page, "toolsButton")
        checking = page.locator("#details[data-page='tools'] .tools-checking")
        checking.wait_for(timeout=5_000)
        assert checking.inner_text().startswith("Checking the tools folder: each tool reports its version")
        while not held:
            page.wait_for_timeout(20)
        held[0].continue_()
        page.wait_for_selector("#details[data-page='tools'] .tools-table")
        assert checking.count() == 0


def test_right_click_menu_offers_same_ip_at_either_end_for_each_address(page):
    """The right-click menu has a Same IP at either end item per address the event holds, and a disabled one, saying
    why, for an event with none. Customize lists the item too."""
    rdp = event_point(page, "4624", hit=True)
    page.mouse.click(rdp["x"], rdp["y"], button="right")
    menu = page.locator("#quickMenu")
    menu.get_by_role("menuitem", name="Same IP at either end: 194.61.24.102").click()
    page.wait_for_function("() => (document.querySelector('#relatedList .actions strong') || {}).textContent"
                           " === '194.61.24.102 at either end: 1 event'")
    explicit = event_point(page, "4648")   # DESKTOP's 4648 names no address
    page.mouse.click(explicit["x"], explicit["y"], button="right")
    none = menu.get_by_role("menuitem", name="Same IP at either end", exact=True)
    assert none.is_disabled() and none.get_attribute("title") == "This event has no source or destination IP"
    menu.get_by_role("menuitem", name="Customize this menu…").click()
    assert menu.get_by_label("Same IP at either end").is_checked()


def test_the_wheel_zooms_by_how_far_it_moved(page):
    """The zoom follows the distance a wheel event moves: the window's span halves or doubles every 200 px, so 100 px,
    a mouse wheel's notch in Edge, zooms by √2, and one event moves at most 300 px. A fixed 1.25 or 0.8 per event would
    zoom ten touchpad steps of 4 px in ninefold and a 1,000 px spin by only 0.8."""
    def zoom(deltas, mode=0):
        return page.evaluate("""([deltas, mode]) => {
            const canvas = document.getElementById('lanes'), rect = canvas.getBoundingClientRect();
            const span = () => window.__app.S.view.end - window.__app.S.view.start;
            const before = span();
            for (const deltaY of deltas) {
                canvas.dispatchEvent(new WheelEvent('wheel', { deltaY, deltaMode: mode, clientX: rect.left + 300,
                                                               clientY: rect.top + 10, cancelable: true }));
            }
            return span() / before;
        }""", [deltas, mode])

    assert zoom([-4] * 10) == pytest.approx(2 ** -0.2)   # a touchpad's 40 px
    assert zoom([-100]) == pytest.approx(2 ** -0.5)      # one notch
    assert zoom([-1000]) == pytest.approx(2 ** -1.5)     # a fast spin, limited to 300 px
    assert zoom([3], mode=1) == pytest.approx(2 ** 0.5)  # three lines out, a notch in Firefox's units


def test_a_note_typed_beside_a_list_s_mark_buttons_goes_with_the_mark(page, synthetic_case):
    """The search and pivot lists' mark buttons take a note, as the Event page's verdict for several events does. The
    note stays while events are ticked, and is journaled with the mark."""
    page.locator("#search").fill("code:4624")
    page.locator("#search").press("Enter")
    page.wait_for_selector("#details[data-page='search'] .related li.rel-row")
    page.locator("#details .related .mark-note").fill("Logons from the attacker's foothold")
    page.locator("#details").get_by_role("button", name="Select all").click()
    note = page.locator("#details .related .mark-note")
    assert note.input_value() == "Logons from the attacker's foothold"
    count = page.locator("#details .related li.rel-row").count()
    assert note.get_attribute("placeholder") == f"Note for marking {count} events (optional)"
    # A mark that fails keeps the ticks and the note for another try
    page.route("**/api/mark", lambda route: route.abort("aborted"))
    page.locator("#details").get_by_role("button", name=f"Mark {count} Suspicious").click()
    page.wait_for_function("() => document.getElementById('status').textContent.startsWith('Mark failed')")
    assert note.input_value() == "Logons from the attacker's foothold"
    page.unroute("**/api/mark")
    page.locator("#details").get_by_role("button", name=f"Mark {count} Suspicious").click()
    page.wait_for_function("(n) => document.querySelectorAll('#details .related li.rel-row .badge.s').length === n",
                           arg=count)   # searched again
    assert note.input_value() == ""   # the next mark starts without it
    last = read_entries(synthetic_case.folder / JOURNAL_FILE)[-1]
    assert (last["action"], len(last["targets"]), last["note"]) == ("mark", count, "Logons from the attacker's foothold")


def test_user_lanes_show_one_lane_per_account_in_its_usual_spelling(browser, synthetic_case):
    """An account written in two letter cases is one user lane, labeled with the case's most common spelling: six
    events as C137\\Administrator, two as c137\\ADMINISTRATOR."""
    shouted = [logon(T0 + (70 + i) * SEC, 120 + i, DC_LOG, user="ADMINISTRATOR", domain="c137") for i in range(2)]
    load(synthetic_case.db_path, shouted, host="DC01", tool="evtxecmd", tool_version="t", run_id="r9",
         replaces_sources=[], staging_dir=synthetic_case.folder)
    for page in served_page(browser, synthetic_case):
        page.locator("#groupby").select_option(label="User > Host")
        page.wait_for_function("() => [...document.querySelectorAll('#labels .row')].some((r) => "
                               "r.textContent.includes('C137\\\\Administrator'))")
        # The label and the count; a preset's first-level groups open folded
        assert [t for t in labels(page) if "administrator" in t.lower()] == ["▸C137\\Administrator8"]


def test_same_file_says_when_the_event_s_file_has_no_full_path(browser, synthetic_case):
    """A 7045 whose service binary has no folder reads its File as cmd.exe, so Same file says why it is unavailable,
    "Its file, cmd.exe, has no full path to match on", not "This event has no file path". Same file matches full
    paths, and the Event page's button and the right-click menu say this file has none; the Event page's next pivots
    put the reason on their not-offered line. Matching a bare name isn't built. An imported event's path has a folder
    but no file key, since imports set none, and it isn't called a bare name."""
    from glessner.events import event_uid

    system = "DC01/Windows/System32/winevt/Logs/System.evtx"
    service = Event(T0 + 30 * SEC, "Event Recorded", "evtx", system, "7", "7045 A service was installed in the system",
                    event_code="7045", log_channel="System", file_path="cmd.exe")
    load(synthetic_case.db_path, [service], host="DC01", tool="evtxecmd", tool_version="t", run_id="r9",
         replaces_sources=[system], staging_dir=synthetic_case.folder)
    export = "DC01/edr_export.csv"
    imported = Event(T0 + 40 * SEC, "Timestamp", "edr", export, "2", "Process started",
                     file_path="C:\\Users\\x\\evil.exe")
    load(synthetic_case.db_path, [imported], host="DC01", tool="csv_import", tool_version="t", run_id="r10",
         replaces_sources=[export], staging_dir=synthetic_case.folder)
    uid = event_uid("DC01", "evtx", system, "7", "Event Recorded")
    why = "Its file, cmd.exe, has no full path to match on"   # the page's reason, which the menu's disabled item shows too
    for page in served_page(browser, synthetic_case):
        page.evaluate("(uid) => window.__app.select(uid, false)", event_uid("DC01", "edr", export, "2", "Timestamp"))
        page.wait_for_selector("#details[data-page='event'] .ev-ident")
        not_offered = page.locator("#details .pv-not")
        assert "Same file: Its file, C:\\Users\\x\\evil.exe, can't be matched on its path." in not_offered.inner_text()
        page.evaluate("(uid) => window.__app.select(uid, false)", uid)
        page.wait_for_function("() => document.querySelector('#details .pv-not')?.textContent.includes('cmd.exe')")
        assert "Same file: Its file, cmd.exe, has no full path to match on." in not_offered.inner_text()
        assert page.locator("#details").get_by_role("button", name="Same file", exact=True).count() == 0
        point = event_point(page, "7045")
        page.mouse.click(point["x"], point["y"], button="right")
        item = page.locator("#quickMenu").get_by_role("menuitem", name="Same file", exact=True)
        assert item.is_disabled() and item.get_attribute("title") == why
        page.keyboard.press("Escape")
        rdp = event_point(page, "4624", hit=True)   # an event with no file at all keeps its own reason
        page.mouse.click(rdp["x"], rdp["y"], button="right")
        item = page.locator("#quickMenu").get_by_role("menuitem", name="Same file", exact=True)
        assert item.get_attribute("title") == "This event has no file path"


def test_tools_page_lists_each_unidentified_file_with_why(browser, synthetic_case):
    """The Tools page lists each unidentified file with why intake could not identify it, such as a prefetch name
    without its signature, and says "1 unidentified file" for one."""
    from glessner.intake import intake
    from glessner.tools import load_registry

    prefetch = synthetic_case.evidence / "DESKTOP" / "Windows" / "Prefetch" / "VSSVC.EXE-6C8F0C66.pf"
    prefetch.parent.mkdir(parents=True)
    prefetch.write_bytes(bytes(512))
    intake(synthetic_case)
    for page in served_page(browser, synthetic_case, setup=lambda app: setattr(app, "tool_cache", (load_registry(), {}))):
        case_menu(page, "toolsButton")
        unread = page.locator("#details .tools-unread")
        unread.wait_for()
        assert "1 unidentified file List" in unread.inner_text()
        unread.get_by_role("button", name="List").click()
        assert page.locator("#details .tools-unidentified li").all_inner_texts() == [
            "DESKTOP/Windows/Prefetch/VSSVC.EXE-6C8F0C66.pf (named like prefetch, but no prefetch signature; "
            "header is all zero bytes)"]


def test_the_status_line_counts_what_lies_outside_the_window_drawn_and_filtered(browser, synthetic_case):
    """The status line counts what lies outside the window drawn, under the Sources and View filter, not Fit case's own
    strays, 1 earlier and 2 later here: the link time 40 s after the last logon is drawn inside the view's margin, and
    the note goes when the View shows none of them."""
    from test_analysis_relations import load_link_time_strays

    load_link_time_strays(synthetic_case)
    for page in served_page(browser, synthetic_case):
        status = page.locator("#status")
        assert status.inner_text().endswith(
            " | Outside this view: 1 earlier, from 1937-10-23; 1 later, to 2037-10-21. Zoom out to see them.")
        page.locator("#viewButton").click()
        # The View's name shows at the click, and the note follows the view drawn under it, which answers later
        page.locator("#viewPanel").get_by_role("button", name="Chain", exact=True).click()
        page.wait_for_function("() => { const text = document.getElementById('status').textContent;"
                               " return text.includes('View: Malicious, Suspicious') && !text.includes('Outside this view'); }")


def test_sources_panel_shows_and_hides_a_capture_s_record_types(browser, synthetic_case):
    """The Sources panel goes below a capture's file to Suricata's record types, stored as the channel, so each can be
    shown or hidden apart. The file opens to them, and unticking one hides its records."""
    from test_filters import load_capture_records

    load_capture_records(synthetic_case)
    for page in served_page(browser, synthetic_case):
        suricata = "() => window.__app.S.data.events.filter((e) => e.tool === 'suricata').length"
        assert page.evaluate(suricata) == 6
        page.locator("#filtersButton").click()
        tree = page.locator("#fpTree")
        for node in ("network", "suricata, 1 file", "case001.pcap"):
            tree.get_by_role("button", name=f"Show or hide what is in {node}", exact=True).click()
        assert tree.locator(".frow.d3 .name").all_text_contents() == ["flow", "dns", "alert"]
        tree.get_by_role("checkbox", name="Show flow in case001.pcap on network").uncheck()
        page.wait_for_function(f"() => ({suricata})() === 3")
        page.wait_for_function("() => document.querySelector('#fpTree .frow.d3 .n').textContent === '0 of 3'")
        assert tree.locator(".frow.d2", has_text="case001.pcap").locator(".n").inner_text() == "3 of 6"
        assert page.locator("#fpChips").inner_text().startswith("Hiding flow in case001.pcap on network")


def test_sources_panel_counts_a_file_read_by_two_tools_under_each(browser, synthetic_case):
    """RECmd's registry events and SBECmd's shellbags events come from the same hive file, and the shown counts are
    keyed by evidence type as well as host and file, so hiding shellbags unchecks its rows without the registry's
    count. Each evidence type's rows count only its own events from the file."""
    from glessner.events import Event

    hive = "DESKTOP/Users/morty/NTUSER.DAT"
    bags = [Event(T0 + i * SEC, "Last interacted", "shellbags", hive, f"bag|{i}", f"Folder {i}") for i in range(3)]
    load(synthetic_case.db_path, bags, host="DESKTOP", tool="sbecmd", tool_version="t", run_id="r8",
         replaces_sources=[hive], staging_dir=synthetic_case.folder)
    load(synthetic_case.db_path, [registry(hive, "ROOT\\Software\\Run", f"v{i}", "x.exe") for i in range(2)],
         host="DESKTOP", tool="recmd", tool_version="t", run_id="r9", replaces_sources=[hive],
         staging_dir=synthetic_case.folder)
    for page in served_page(browser, synthetic_case):
        page.locator("#filtersButton").click()
        types, tree = page.locator("#fpTypes"), page.locator("#fpTree")
        types.locator(".frow", has_text="shellbags").locator("input").uncheck()
        page.wait_for_function("() => window.__app.S.shown !== null")
        for node in ("DESKTOP", "registry, 2 files", "shellbags, 1 file"):
            tree.get_by_role("button", name=f"Show or hide what is in {node}", exact=True).click()
        assert types.locator(".frow", has_text="shellbags").locator(".n").inner_text() == "0 of 3"
        assert not types.locator(".frow", has_text="shellbags").locator("input").is_checked()
        assert types.locator(".frow", has_text="registry").locator(".n").inner_text() == "6"
        files = tree.locator(".frow.d2", has_text="NTUSER.DAT")
        assert [files.nth(i).locator(".n").inner_text() for i in range(2)] == ["2", "0 of 3"]


def test_import_page_counts_a_json_array_by_its_records(page, synthetic_case):
    """A JSON array of three records on one line counts its records, not its lines: "JSON array, 3 records", and the
    button "Import 3 records"."""
    from glessner.intake import intake

    intake(synthetic_case)
    records = [{"@timestamp": f"2020-09-19T03:2{i}:50Z", "user": f"u{i}", "action": "login"} for i in range(3)]
    (synthetic_case.evidence / "DC01" / "export.json").write_text(json.dumps(records), newline="\n")
    details = page.locator("#details")
    case_menu(page, "importButton")
    page.wait_for_selector("#details[data-page='import']")
    details.get_by_role("button", name="Add new evidence").click()
    details.get_by_role("button", name="Import 3 records", exact=True).wait_for()
    assert details.locator(".imp-map .actions .muted").first.inner_text() == "JSON array, 3 records"


def test_a_click_anywhere_on_a_listed_event_but_its_tick_box_opens_it(page):
    """The whole row of a search result opens its event, except the tick box, which ticks. The text is only 581 px of
    a 1,324 px row on the samples case, so a click near the row's right end must open it too. The row writes an event
    log event's code once, "4624 logon", not "4624  4624 logon"."""
    page.locator("#search").fill("code:4624")
    page.locator("#search").press("Enter")
    page.wait_for_selector("#details[data-page='search'] .related li.rel-row")
    row = page.locator("#details .related li.rel-row").first
    assert [row.locator(sel).text_content() for sel in (".rel-time", ".rel-host", ".rel-text")] == [
        "2020-09-19 03:21:48.000000", "DC01", "4624 logon"]   # one cell each
    row.locator("input").click()
    assert row.locator("input").is_checked()
    assert page.locator("#details").get_attribute("data-page") == "search"
    box, text = row.bounding_box(), row.locator(".rel-text").bounding_box()
    assert box["x"] + box["width"] - 5 > text["x"] + text["width"]   # the click lands past the text
    page.mouse.click(box["x"] + box["width"] - 5, box["y"] + box["height"] / 2)
    page.wait_for_selector("#details[data-page='event'] .ev-ident")
    assert "DC01" in page.locator("#details .ev-ident").inner_text()


def test_counts_of_one_read_in_the_singular(page):
    """A count of one reads in the singular: "1 of these hosts has a guessed role" on a role's lane flag, the state
    line's "In this window: 1", with the link count in its hover, "1 event pending, would be Suspicious" on To
    investigate, and "Wrote 1 event" on the Export page (the Findings page's export controls)."""
    flags = page.locator("#labels .guess").evaluate_all("(els) => els.map((e) => e.title)")
    assert "1 of these hosts has a guessed role. Right-click to confirm." in flags
    one = [T0 // 1000 + 895_000, T0 // 1000 + 905_000]   # DESKTOP's 4648 alone
    page.evaluate("([a, b]) => window.__app.setView(a, b)", one)
    page.wait_for_function("() => document.getElementById('stInWindow').textContent === 'In this window: 1'")
    # The 4648's own link has both ends on DESKTOP, the host that recorded it, so it isn't drawn, and the hover counts the
    # links drawn, not the window's links: this link is never on the canvas, so the hover says 0
    assert page.evaluate("window.__app.S.data.links.items.length") == 1
    assert page.locator("#stInWindow").get_attribute("title").endswith("0 logon links drawn.")
    page.locator("#investigateButton").click()
    page.wait_for_selector("#details[data-page='investigate'] .rule")
    assert "1 event pending, would be Suspicious" in page.locator("#details .rule", has_text="hayabusa").inner_text()
    case_menu(page, "exportButton")
    page.locator("#details .export-card", has_text="Events in the window").get_by_role("button", name="CSV").click()
    page.wait_for_function("() => document.querySelector('#details .export-result')?.textContent.startsWith('Wrote')")
    assert page.locator("#details .export-result").inner_text().startswith("Wrote 1 event to ")
    # A host whose pairs disagree can have a group of one pair, which reads "(1 pair)".
    groups = page.evaluate("""async () => (await import('/js/clock.js')).clockCell({ host: 'WS02', clock: {
        state: 'disagree', reason: '', clusters: [{ seconds: -3599.5, pairs: 9 }, { seconds: 12, pairs: 1 }] } })
        .map((e) => e.textContent).join(' | ')""")
    assert "Groups of pairs suggest -3,599.5 s (9 pairs), +12 s (1 pair)." in groups


def test_import_page_counts_of_one_read_in_the_singular(page, synthetic_case):
    """A count of one reads in the singular on the Import page: "1 listed file is gone", "The first event", and
    "Imported 1 event from 1 file"."""
    from glessner.intake import intake

    gone = synthetic_case.evidence / "DC01" / "old.bin"
    gone.write_bytes(bytes(16))
    intake(synthetic_case)
    gone.unlink()
    details, status = page.locator("#details"), page.locator("#status")
    case_menu(page, "importButton")
    page.wait_for_selector("#details[data-page='import']")
    details.get_by_role("button", name="Add new evidence").click()
    page.wait_for_function("() => document.getElementById('status').textContent.startsWith('No new files')")
    assert status.inner_text() == "No new files in the evidence folder. 1 listed file is gone from it; run verify."
    record = [{"@timestamp": "2020-09-19T03:21:50Z", "user": "u1", "action": "login"}]
    (synthetic_case.evidence / "DC01" / "export.json").write_text(json.dumps(record), newline="\n")
    details.get_by_role("button", name="Add new evidence").click()
    go = details.get_by_role("button", name="Import 1 record", exact=True)
    go.wait_for()
    assert details.locator("h3", has_text="The first").text_content() == "The first event"
    with page.expect_navigation():
        go.click()
        # The status shows until the page reloads, 0.8 s later
        done = page.wait_for_function(
            "() => { const t = document.getElementById('status').textContent; return t.startsWith('Imported') && t; }")
        assert done.json_value() == "Imported 1 event from 1 file. Reloading the timeline."
    page.wait_for_function("() => window.__ready === true && window.__app.S.data !== null")


def test_a_mark_whose_event_is_gone_is_counted_in_the_singular(browser, synthetic_case):
    """A case with one mark whose event no longer exists warns "1 mark refers to an event that no longer exists". The
    warning is set after the view's first counts, ahead of the view's line, so they don't replace it before it can be
    read, and it stays until the view changes."""
    from glessner.events import event_uid
    from glessner.journal import Journal

    Journal(synthetic_case).append("mark", targets=[event_uid("DC01", "evtx", "DC01/gone.evtx", "1", "Event Recorded")],
                                   value="malicious")
    record ="""document.addEventListener('DOMContentLoaded', () => {
        window.__statuses = [];
        const keep = (changes) => changes.forEach((c) => c.addedNodes.forEach((n) => window.__statuses.push(n.textContent)));
        new MutationObserver(keep).observe(document.getElementById('status'), { childList: true });
    })"""
    for page in served_page(browser, synthetic_case):
        page.add_init_script(record)
        page.reload()
        page.wait_for_function("() => window.__ready === true && window.__app.S.data !== null")
        warning = "Warning: 1 mark refers to an event that no longer exists."
        page.wait_for_function("(text) => document.getElementById('status').textContent.startsWith(text)", arg=warning)
        page.wait_for_timeout(500)   # time for any redraw still to come
        assert page.locator("#status").inner_text().startswith(warning)
        assert not any("1 marks" in s for s in page.evaluate("() => window.__statuses"))


def test_the_missing_marks_warning_stays_on_a_case_with_no_events(browser, tmp_path):
    """The missing-marks warning and "No events yet" are one status line, so a case with marks and no events shows the
    warning."""
    from glessner.case import create_case
    from glessner.events import event_uid
    from glessner.journal import Journal

    ev = tmp_path / "evidence"
    ev.mkdir()
    case = create_case(tmp_path / "case", "Empty", ev, "cody")
    Journal(case).append("mark", targets=[event_uid("DC01", "evtx", "DC01/gone.evtx", "1", "Event Recorded")],
                         value="malicious")
    for page in served_page(browser, case):
        line = "Warning: 1 mark refers to an event that no longer exists. | No events yet."
        page.wait_for_function("(text) => document.getElementById('status').textContent.startsWith(text)", arg=line)
        page.wait_for_timeout(500)   # time for any redraw still to come
        assert page.locator("#status").inner_text().startswith(line)


def test_what_a_decision_and_a_tag_say_stays_on_the_status_line_until_the_view_changes(browser, synthetic_case):
    """A decision and a tag set the status line after the view's redraw, ahead of the view's own line, so the redraw
    doesn't replace it with its counts before it can be read, as it doesn't a mark's text. The line stays until the
    view next changes."""
    from test_tags import ATTACK_HIT

    from glessner.events import load

    load(synthetic_case.db_path, [ATTACK_HIT], host="DC01", tool="hayabusa", tool_version="t", run_id="r6",
         replaces_sources=[ATTACK_HIT.source_file], staging_dir=synthetic_case.folder)
    status = "document.getElementById('status').textContent"
    def run(page):
        def said(line):
            page.wait_for_function(f"() => {status}.startsWith({line!r})")
            page.wait_for_timeout(400)   # time for any redraw still to come
            assert page.evaluate(f"() => {status}").startswith(line)

        rdp = event_point(page, "4624", hit=True)
        page.evaluate("(uid) => window.__app.select(uid, false)", rdp["uid"])
        page.wait_for_selector("#details[data-page='event'] .ev-verdict")
        page.locator("#details").get_by_role("button", name="+ Tag").click()
        page.locator("#quickMenu").get_by_role("menuitem", name="Lateral Movement", exact=True).click()
        said("Tagged one event: Lateral Movement · ")
        page.locator("#details button.tw").click()   # the suggestions fold, closed at first
        page.locator("#details").get_by_role("button", name="Dismiss the tag Credential Access").click()
        said("Dismissed: Credential Access · ")
        page.locator("#details").get_by_role("button", name="Accept as Suspicious").click()
        said("accept: 1 event (hayabusa) · ")
        # The next redraw is the view's own: a pan replaces the line
        page.evaluate("() => { const v = window.__app.S.view; return window.__app.setView(v.start + 1000, v.end + 1000); }")
        page.wait_for_function(f"() => {status}.startsWith('Window moved · ')")

    for page in served_page(browser, synthetic_case):
        run(page)


def test_a_shift_click_that_deselects_the_event_on_the_event_page_shows_the_next_selected_or_the_hint(page):
    """A shift-click on a selected event takes it out of the selection and moves the Event page off it, so a mark made
    there can't act on an event the analyst has taken out. The page goes to the event selected last of those left, and
    with none left to the opening hint."""
    first = event_point(page, "4624", hit=True)
    second = latest_lone_point(page, "4624")
    page.mouse.click(first["x"], first["y"])
    page.wait_for_selector(f"#details[data-key='event:{first['uid']}'] .ev-verdict")
    shift_click(page, second)
    page.wait_for_selector(f"#details[data-key='event:{second['uid']}'] .ev-verdict")
    assert selected(page) == sorted([first["uid"], second["uid"]])
    shift_click(page, second)   # out of the selection: the page was on it
    page.wait_for_selector(f"#details[data-key='event:{first['uid']}'] .ev-verdict")
    assert selected(page) == [first["uid"]] and page.evaluate("window.__app.S.focus") == first["uid"]
    assert page.locator("#details .ev-verdict h3").inner_text().lower() == "verdict"   # one event again, not a list of two
    shift_click(page, first)   # the last one out: nothing is in focus, and the panel is the opening hint
    page.wait_for_selector("#details[data-page='hint']")
    assert selected(page) == [] and page.evaluate("window.__app.S.focus") is None
    assert page.locator("#details .hint").count() == 1
    # An event's page still loading when the selection empties doesn't replace the hint, which is already the page
    held = []
    page.route("**/api/event?*", lambda route: held.append(route))
    page.mouse.click(first["x"], first["y"])
    while not held:
        page.wait_for_timeout(20)
    shift_click(page, first)
    page.wait_for_function("() => window.__app.S.selected.size === 0")
    with page.expect_response("**/api/event?*"):
        held[0].continue_()
    page.wait_for_timeout(300)   # time for the event's page to draw, had it still meant to
    page.unroute("**/api/event?*")
    assert page.locator("#details").get_attribute("data-page") == "hint"


def test_a_pivot_that_answers_late_leaves_the_event_opened_after_it(page):
    """A pivot that answers late doesn't draw its list, its highlights, or its trail step over whatever the panel shows
    by then. Its request is held here until another event's page shows."""
    rdp = event_point(page, "4624", hit=True)
    other = latest_lone_point(page, "4624")
    page.evaluate("(uid) => window.__app.select(uid, false)", rdp["uid"])
    page.wait_for_selector(f"#details[data-key='event:{rdp['uid']}'] .pv[data-pivot='account']")
    held = []
    page.route("**/api/related?*", lambda route: held.append(route))
    page.locator('#details .pv[data-pivot="account"] button.pv-go').click()
    while not held:
        page.wait_for_timeout(20)
    page.evaluate("(uid) => window.__app.select(uid, false)", other["uid"])
    page.wait_for_selector(f"#details[data-key='event:{other['uid']}'] .ev-verdict")
    with page.expect_response("**/api/related?*"):
        held[0].continue_()
    page.wait_for_timeout(300)   # time for the pivot to draw, had it still meant to
    page.unroute("**/api/related?*")
    assert page.evaluate("[window.__app.S.pivotResult, window.__app.S.related.size, window.__app.S.trail.length]") == [None, 0, 1]
    assert page.locator("#relatedList li.rel-row").count() == 0


def test_an_action_that_answers_late_leaves_the_page_asked_for_after_it(browser, synthetic_case):
    """Accept all on the Suggestions page or To investigate, Add rule on the Rules page, Undo on the audit trail, and
    Add new evidence on the Import page each leave alone the page the analyst has asked for since, when the server
    answers late. Each request is held here until another page shows."""
    from glessner.intake import intake
    from glessner.server import api_mark, api_note, api_rule

    record = [{"@timestamp": "2020-09-19T03:21:50Z", "user": "u1", "action": "login"}]
    (synthetic_case.evidence / "DC01" / "export.json").write_text(json.dumps(record), newline="\n")
    intake(synthetic_case)   # the Import page lists the manifest's files

    def setup(app):
        api_rule(app, {"op": "add", "text": "id: second\nsuggest: suspicious\nwhen: {field: tool, equals: evtxecmd}\n"})
        uid = app.con.execute("SELECT event_uid FROM events WHERE tool = 'evtxecmd' AND ts_us = ?",
                              [T0 + 874 * SEC]).fetchone()[0]   # DESKTOP's, with no Hayabusa suggestion to decide
        api_mark(app, {"uids": [uid], "value": "malicious"})
        api_note(app, {"uid": uid, "text": "a note to retract"})

    def run(page):
        details = page.locator("#details")

        def held_until_shown(pattern, act, shown, show, answer=lambda route: route.continue_()):
            """Do `act`, which sends a request that is held, then show another page, and answer the request once it shows."""
            held = []
            page.route(pattern, lambda route: held.append(route))
            act()
            while not held:
                page.wait_for_timeout(20)
            show()
            page.wait_for_selector(f"#details[data-page='{shown}']")
            with page.expect_response(pattern):
                answer(held[0])
            page.wait_for_timeout(300)   # time for the first page to draw, had it still meant to
            page.unroute(pattern)
            assert details.get_attribute("data-page") == shown, pattern

        def rules():
            case_menu(page, "rulesButton")

        def audit():
            case_menu(page, "auditButton")

        def investigate():
            page.locator("#investigateButton").click()
            page.wait_for_selector("#details[data-page='investigate']")

        # Accept all and Reject all ask first: the request goes when the confirm button is pressed
        def confirmed(opener, label):
            opener.click()
            details.locator(".confirm-block").get_by_role("button", name=label, exact=True).click()

        investigate()
        details.get_by_role("button", name="hayabusa", exact=True).click()
        page.wait_for_selector("#details[data-page='suggestions']")
        accept_all = details.get_by_role("button", name="Accept all", exact=True)
        held_until_shown("**/api/suggestion", lambda: confirmed(accept_all, "Accept 1"), "rules", rules)
        investigate()
        row = details.locator(".rule", has_text="second")
        held_until_shown("**/api/suggestion",
                         lambda row=row: confirmed(row.get_by_role("button", name="Reject all"), re.compile(r"^Reject \d+$")),
                         "audit", audit)
        rules()
        details.locator("textarea").fill("id: third\nsuggest: suspicious\nwhen: {field: tool, equals: sbecmd}\n")
        held_until_shown("**/api/rule", lambda: details.get_by_role("button", name="Add rule", exact=True).click(),
                         "audit", audit)
        rules()
        row = details.locator("table tr", has_text="third")
        held_until_shown("**/api/rule", lambda row=row: row.get_by_role("button", name="Remove").click(), "audit", audit)
        audit()
        note = details.locator(".audit-row", has_text="a note to retract").first
        note.get_by_role("button", name="Retract").click()
        confirm = note.locator(".audit-confirm").get_by_role("button", name="Retract")
        confirm.wait_for()
        held_until_shown("**/api/note_retract", confirm.click, "rules", rules)
        audit()
        mark = details.locator(".audit-row", has_text="Malicious").first
        mark.get_by_role("button", name="Undo").click()
        confirm = mark.locator(".audit-confirm").get_by_role("button", name="Undo 1 event")
        confirm.wait_for()
        held_until_shown("**/api/undo", confirm.click, "rules", rules)
        case_menu(page, "importButton")
        page.wait_for_selector("#details[data-page='import']")
        held_until_shown("**/api/evidence_add", lambda: details.get_by_role("button", name="Add new evidence").click(),
                         "rules", rules)
        # An import that fails, answered once another page shows, redraws nothing either
        case_menu(page, "importButton")
        page.locator("#details button.primary:not([disabled])").wait_for()
        refuse = lambda route: route.fulfill(status=500, content_type="application/json", body='{"error": "refused"}')
        held_until_shown("**/api/import", lambda: page.locator("#details button.primary").click(), "rules", rules, refuse)
        page.errors[:] = [e for e in page.errors if "/api/import" not in e]   # that refusal was the point
        # And an import whose runs all failed
        case_menu(page, "importButton")
        page.locator("#details button.primary:not([disabled])").wait_for()
        failed = json.dumps({"runs": [{"path": "DC01/export.json", "status": "failed", "reason": "no"}], "errors": []})
        fail = lambda route: route.fulfill(status=200, content_type="application/json", body=failed)
        held_until_shown("**/api/import", lambda: page.locator("#details button.primary").click(), "rules", rules, fail)

    for page in served_page(browser, synthetic_case, setup=setup):
        run(page)


def mark_and_note_an_event(app):
    """Mark an event Malicious and put a note on it, so that the audit trail lists a mark to undo and a note to retract."""
    from glessner.server import api_mark, api_note

    uid = app.con.execute("SELECT event_uid FROM events WHERE tool = 'evtxecmd' AND ts_us = ?",
                          [T0 + 874 * SEC]).fetchone()[0]
    api_mark(app, {"uids": [uid], "value": "malicious"})
    api_note(app, {"uid": uid, "text": "a note to retract"})


def test_a_late_retract_leaves_the_audit_trail_opened_again_alone(browser, synthetic_case):
    """A retract redraws the audit trail once the timeline has reloaded. When the analyst has left the trail and opened it
    again by then, the page is theirs: the redraw would close the Undo confirm they opened on it. The retract's reload of
    the lanes is held here until that confirm shows."""
    held = []

    def hold_first(route):   # the retract's reload; any later one goes through
        if held:
            route.continue_()
        else:
            held.append(route)

    for page in served_page(browser, synthetic_case, setup=mark_and_note_an_event):
        details = page.locator("#details")
        case_menu(page, "auditButton")
        note = details.locator(".audit-row", has_text="a note to retract").first
        note.get_by_role("button", name="Retract").click()
        page.route("**/api/lanes?*", hold_first)
        with page.expect_request("**/api/lanes?*"), page.expect_response("**/api/note_retract"):
            note.locator(".audit-confirm").get_by_role("button", name="Retract").click()
        wait_held(page, held)
        case_menu(page, "rulesButton")
        page.wait_for_selector("#details[data-page='rules']")
        case_menu(page, "auditButton")
        mark = details.locator(".audit-row", has_text="Malicious").first
        mark.get_by_role("button", name="Undo").click()
        confirm = mark.locator(".audit-confirm").get_by_role("button", name="Undo 1 event")
        confirm.wait_for()
        page.evaluate(RECORD_REQUESTS)
        with page.expect_request("**/api/counts"):   # the reload is done, and the trail would ask for its redraw with it
            held[0].continue_()
        page.unroute("**/api/lanes?*")
        assert asked(page, "/api/audit?") == []
        assert confirm.is_visible()


@pytest.mark.parametrize(("row", "ask", "confirm", "endpoint", "done"), [
    ("Malicious", "Undo", "Undo 1 event", "undo", lambda details: details.locator(".correction-tag")),
    ("a note to retract", "Retract", "Retract", "note_retract", lambda details: details.get_by_text("Retracted by #")),
], ids=["undo", "retract"])
def test_an_undo_or_a_retract_that_answers_late_draws_the_audit_trail_opened_again(
        browser, synthetic_case, row, ask, confirm, endpoint, done):
    """The audit trail the analyst opened again while an undo or a retract was in flight was read before the change was
    journaled, so it draws again when the change is done and shows it. The request is held here until the trail has
    been opened again."""
    held = []
    for page in served_page(browser, synthetic_case, setup=mark_and_note_an_event):
        details = page.locator("#details")
        case_menu(page, "auditButton")
        entry = details.locator(".audit-row", has_text=row).first
        entry.get_by_role("button", name=ask).click()
        page.route(f"**/api/{endpoint}", lambda route: held.append(route))
        with page.expect_request(f"**/api/{endpoint}"):
            entry.locator(".audit-confirm").get_by_role("button", name=confirm).click()
        wait_held(page, held)
        case_menu(page, "rulesButton")
        page.wait_for_selector("#details[data-page='rules']")
        case_menu(page, "auditButton")
        page.wait_for_selector("#details[data-page='audit']")
        assert done(details).count() == 0
        held[0].continue_()
        done(details).first.wait_for()


def test_an_undo_draws_the_audit_trail_again_with_the_filters_it_shows_by_then(browser, synthetic_case):
    """An undo draws the audit trail again when it's done, with the filters the trail shows by then, so a trail the
    analyst narrowed while the undo was in flight stays narrowed. The undo is held here until the trail lists marks only."""
    held = []
    for page in served_page(browser, synthetic_case, setup=mark_and_note_an_event):
        details = page.locator("#details")
        case_menu(page, "auditButton")
        mark = details.locator(".audit-row", has_text="Malicious").first
        mark.get_by_role("button", name="Undo").click()
        page.route("**/api/undo", lambda route: held.append(route))
        with page.expect_request("**/api/undo"):
            mark.locator(".audit-confirm").get_by_role("button", name="Undo 1 event").click()
        wait_held(page, held)
        with page.expect_response(lambda res: "/api/audit?" in res.url):
            details.get_by_role("combobox", name="Action").select_option("Marks")
        with page.expect_request(lambda req: "/api/audit?" in req.url) as redraw:
            held[0].continue_()
        assert "kind=Marks" in redraw.value.url
        details.get_by_text("Undone by #").wait_for()
        assert details.get_by_role("combobox", name="Action").input_value() == "Marks"


def test_a_retract_leaves_a_confirm_open_on_the_trail_and_draws_the_trail_once_it_closes(browser, synthetic_case):
    """A retract done while the analyst has an Undo confirm open on another row of the same trail says so on the status
    line and leaves that confirm open, since drawing the trail again would close it. The trail draws again once the
    confirm closes, and shows the note retracted. The retract's reload of the lanes is held here until the confirm
    shows."""
    held = []

    def hold_first(route):   # the retract's reload; any later one goes through
        if held:
            route.continue_()
        else:
            held.append(route)

    for page in served_page(browser, synthetic_case, setup=mark_and_note_an_event):
        details = page.locator("#details")
        case_menu(page, "auditButton")
        note = details.locator(".audit-row", has_text="a note to retract").first
        note.get_by_role("button", name="Retract").click()
        page.route("**/api/lanes?*", hold_first)
        with page.expect_request("**/api/lanes?*"), page.expect_response("**/api/note_retract"):
            note.locator(".audit-confirm").get_by_role("button", name="Retract").click()
        wait_held(page, held)
        page.wait_for_function("() => document.getElementById('status').textContent.startsWith('Retracted note #')")
        mark = details.locator(".audit-row", has_text="Malicious").first
        mark.get_by_role("button", name="Undo").click()
        confirm = mark.locator(".audit-confirm")
        confirm.get_by_role("button", name="Undo 1 event").wait_for()
        page.evaluate(RECORD_REQUESTS)
        with page.expect_request("**/api/counts"):   # the reload is done, and the trail would ask for its redraw with it
            held[0].continue_()
        page.unroute("**/api/lanes?*")
        assert asked(page, "/api/audit?") == []
        assert confirm.get_by_role("button", name="Undo 1 event").is_visible()
        assert details.get_by_text("Retracted by #").count() == 0
        confirm.get_by_role("button", name="Cancel").click()
        details.get_by_text("Retracted by #").wait_for()


def first_held(held):
    """A route handler that holds the route's first request in `held` and lets every later one through."""
    def handle(route):
        if held:
            route.continue_()
        else:
            held.append(route)
    return handle


def start_held_undo(page, reload):
    """Open the audit trail, undo its mark, and return the mark's row once the server has answered the undo and holds
    the undo's reload of the lanes in `reload`."""
    details = page.locator("#details")
    case_menu(page, "auditButton")
    mark = details.locator(".audit-row", has_text="Malicious").first
    mark.get_by_role("button", name="Undo").click()
    page.route("**/api/lanes?*", first_held(reload))
    with page.expect_response("**/api/undo"):
        mark.locator(".audit-confirm").get_by_role("button", name="Undo 1 event").click()
    wait_held(page, reload)
    return mark


def test_an_event_opened_from_the_audit_trail_during_an_undos_reload_takes_the_panel(browser, synthetic_case):
    """An Event page asked for from the audit trail while an undo's timeline reloads draws when it answers, even after
    the reload is done: the undo's redraw of the trail leaves alone a page asked for since that is still loading. The
    reload is held here until the event is asked for, and the event until the reload is done."""
    reload, event = [], []
    for page in served_page(browser, synthetic_case, setup=mark_and_note_an_event):
        mark = start_held_undo(page, reload)
        page.route("**/api/event?*", first_held(event))
        mark.locator(".ev-name").click()
        wait_held(page, event)
        with page.expect_request("**/api/counts"):   # the reload is done, and the trail would have drawn again by now
            reload[0].continue_()
        event[0].continue_()
        page.wait_for_selector("#details[data-page='event']")


def test_a_trail_narrowed_during_an_undos_reload_keeps_its_filters(browser, synthetic_case):
    """The audit trail narrowed while an undo's timeline reloads draws with its own filters when its read answers after
    the reload. That read follows the undo, so the trail doesn't draw again. The reload is held here until the trail is
    narrowed, and the narrowed read until the reload is done."""
    reload, read = [], []
    for page in served_page(browser, synthetic_case, setup=mark_and_note_an_event):
        details = page.locator("#details")
        start_held_undo(page, reload)
        page.route("**/api/audit?*", first_held(read))
        page.evaluate(RECORD_REQUESTS)
        details.get_by_role("combobox", name="Action").select_option("Marks")
        wait_held(page, read)
        with page.expect_request("**/api/counts"):   # the reload is done, and the trail would have drawn again by now
            reload[0].continue_()
        read[0].continue_()
        details.get_by_text("Undone by #").wait_for()
        reads = asked(page, "/api/audit?")   # a redraw would be asked for in the task that drew the trail
        assert len(reads) == 1 and "kind=Marks" in reads[0]
        assert details.get_by_role("combobox", name="Action").input_value() == "Marks"


def test_a_trail_read_before_an_undo_draws_again_when_its_read_answers_after_the_undo(browser, synthetic_case):
    """The audit trail opened again while an undo is in flight, whose read answers only once the undo and its timeline
    reload are done, was read before the undo, so it draws again once it has drawn, and shows the undo. The undo is
    held here until the server has answered that read, and the read's answer until the undo is done."""
    undo, read = [], []
    for page in served_page(browser, synthetic_case, setup=mark_and_note_an_event):
        details = page.locator("#details")
        case_menu(page, "auditButton")
        mark = details.locator(".audit-row", has_text="Malicious").first
        mark.get_by_role("button", name="Undo").click()
        page.route("**/api/undo", lambda route: undo.append(route))
        with page.expect_request("**/api/undo"):
            mark.locator(".audit-confirm").get_by_role("button", name="Undo 1 event").click()
        wait_held(page, undo)
        case_menu(page, "rulesButton")
        page.wait_for_selector("#details[data-page='rules']")
        page.route("**/api/audit?*", first_held(read))
        case_menu(page, "auditButton")
        wait_held(page, read)
        before = read[0].fetch()   # the trail as the server reads it before the undo
        with page.expect_request("**/api/counts"):
            undo[0].continue_()
        read[0].fulfill(response=before)
        details.locator(".correction-tag").first.wait_for()


def mark_two_and_note_one(app):
    """Mark two events Malicious in one entry and put a note on one of them, so that the audit trail lists a mark with
    its event list and an undo, and a note to retract."""
    from glessner.server import api_mark, api_note

    rows = app.con.execute("SELECT event_uid FROM events WHERE tool = 'evtxecmd' ORDER BY ts_us LIMIT 2").fetchall()
    uids = [uid for (uid,) in rows]
    api_mark(app, {"uids": uids, "value": "malicious"})
    api_note(app, {"uid": uids[0], "text": "a note to retract"})


@pytest.mark.parametrize("box", ["events", "plan error"])
def test_a_trail_a_retract_left_unchanged_draws_once_the_box_on_another_row_closes(browser, synthetic_case, box):
    """A retract done while another row's box holds a confirm leaves the trail as it is, and the trail draws again once
    that box closes, showing the note retracted. The box closes as the row's event list, opened in place of its Undo
    confirm, or as the error of an undo plan that failed, which has a Close button. The retract's reload of the lanes
    is held here until the box shows."""
    held = []
    for page in served_page(browser, synthetic_case, setup=mark_two_and_note_one):
        details = page.locator("#details")
        case_menu(page, "auditButton")
        note = details.locator(".audit-row", has_text="a note to retract").first
        note.get_by_role("button", name="Retract").click()
        page.route("**/api/lanes?*", first_held(held))
        with page.expect_request("**/api/lanes?*"), page.expect_response("**/api/note_retract"):
            note.locator(".audit-confirm").get_by_role("button", name="Retract").click()
        wait_held(page, held)
        mark = details.locator(".audit-row", has_text="Malicious").first
        shown = mark.locator(".audit-confirm")
        if box == "plan error":
            page.route("**/api/undo_plan?*", lambda route: route.fulfill(
                status=500, content_type="application/json", body=json.dumps({"error": "the plan failed"})))
        mark.get_by_role("button", name="Undo").click()
        shown.get_by_text("the plan failed" if box == "plan error" else "Undo 2 events").wait_for()
        if box == "plan error":
            page.unroute("**/api/undo_plan?*")
            page.errors[:] = [e for e in page.errors if "/api/undo_plan" not in e]   # that refusal was the point
        page.evaluate(RECORD_REQUESTS)
        with page.expect_request("**/api/counts"):   # the reload is done, and the trail would ask for its redraw with it
            held[0].continue_()
        page.unroute("**/api/lanes?*")
        assert asked(page, "/api/audit?") == []
        if box == "events":
            events = mark.get_by_role("button", name="2 events", exact=True)
            events.click()
            shown.locator("li").first.wait_for()
            assert details.get_by_text("Retracted by #").count() == 0
            events.click()
        else:
            assert details.get_by_text("Retracted by #").count() == 0
            shown.get_by_role("button", name="Close").click()
        details.get_by_text("Retracted by #").wait_for()


def test_a_trail_whose_redraw_failed_settles_when_a_confirm_on_it_closes(browser, synthetic_case):
    """The audit trail draws again after an undo, to show it. When that read fails, the trail on screen stays as it was,
    and it settles again once a confirm on it closes, here a Retract confirm canceled. The redraw's read is refused
    here."""
    for page in served_page(browser, synthetic_case, setup=mark_and_note_an_event):
        details = page.locator("#details")
        case_menu(page, "auditButton")
        mark = details.locator(".audit-row", has_text="Malicious").first
        mark.get_by_role("button", name="Undo").click()
        page.route("**/api/audit?*", refused_with("the trail failed"))
        with page.expect_response("**/api/audit?*"):
            mark.locator(".audit-confirm").get_by_role("button", name="Undo 1 event").click()
        page.unroute("**/api/audit?*")
        page.errors[:] = [e for e in page.errors if "/api/audit?" not in e]   # that refusal was the point
        page.wait_for_function("() => document.getElementById('status').textContent.startsWith('Audit trail failed')")
        note = details.locator(".audit-row", has_text="a note to retract").first
        note.get_by_role("button", name="Retract").click()
        page.evaluate(RECORD_REQUESTS)
        note.locator(".audit-confirm").get_by_role("button", name="Cancel").click()
        assert len(asked(page, "/api/audit?")) == 1
        details.locator(".correction-tag").first.wait_for()


def test_a_retract_on_the_trail_draws_it_again_after_a_page_asked_for_failed(browser, synthetic_case):
    """A page asked for while an undo's timeline reloads holds the audit trail's redraw, since that page takes the panel
    when it draws. When the page fails instead, here Rules, the trail stays as it was, and the next change confirmed on
    it, here a retract, draws it again with both changes. The undo's reload is held here until Rules has failed."""
    reload = []
    for page in served_page(browser, synthetic_case, setup=mark_and_note_an_event):
        details = page.locator("#details")
        start_held_undo(page, reload)
        page.route("**/api/rules", refused_with("the rules failed"))
        with page.expect_response("**/api/rules"):
            case_menu(page, "rulesButton")
        page.unroute("**/api/rules")
        page.errors[:] = [e for e in page.errors if "/api/rules" not in e]   # that refusal was the point
        with page.expect_request("**/api/counts"):   # the reload is done, and Rules' claim holds the trail's redraw
            reload[0].continue_()
        page.unroute("**/api/lanes?*")
        assert details.get_attribute("data-page") == "audit"
        note = details.locator(".audit-row", has_text="a note to retract").first
        note.get_by_role("button", name="Retract").click()
        page.evaluate(RECORD_REQUESTS)
        with page.expect_request("**/api/counts"):   # the retract's reload is done, and the trail settles with it
            note.locator(".audit-confirm").get_by_role("button", name="Retract").click()
        assert len(asked(page, "/api/audit?")) == 1
        details.get_by_text("Retracted by #").wait_for()
        assert details.locator(".correction-tag").count() == 1


def test_an_undo_on_the_trail_draws_it_again_after_a_page_asked_for_failed(browser, synthetic_case):
    """A page asked for while a retract's timeline reloads holds the audit trail's redraw, since that page takes the
    panel when it draws. When the page fails instead, here Rules, the trail stays as it was, and the next change
    confirmed on it, here an undo, draws it again with both changes. The retract's reload is held here until Rules has
    failed."""
    reload = []
    for page in served_page(browser, synthetic_case, setup=mark_and_note_an_event):
        details = page.locator("#details")
        case_menu(page, "auditButton")
        note = details.locator(".audit-row", has_text="a note to retract").first
        note.get_by_role("button", name="Retract").click()
        page.route("**/api/lanes?*", first_held(reload))
        with page.expect_response("**/api/note_retract"):
            note.locator(".audit-confirm").get_by_role("button", name="Retract").click()
        wait_held(page, reload)
        page.route("**/api/rules", refused_with("the rules failed"))
        with page.expect_response("**/api/rules"):
            case_menu(page, "rulesButton")
        page.unroute("**/api/rules")
        page.errors[:] = [e for e in page.errors if "/api/rules" not in e]   # that refusal was the point
        with page.expect_request("**/api/counts"):   # the reload is done, and Rules' claim holds the trail's redraw
            reload[0].continue_()
        page.unroute("**/api/lanes?*")
        assert details.get_attribute("data-page") == "audit"
        assert details.get_by_text("Retracted by #").count() == 0
        mark = details.locator(".audit-row", has_text="Malicious").first
        mark.get_by_role("button", name="Undo").click()
        page.evaluate(RECORD_REQUESTS)
        with page.expect_request("**/api/counts"):   # the undo's reload is done, and the trail settles with it
            mark.locator(".audit-confirm").get_by_role("button", name="Undo 1 event").click()
        assert len(asked(page, "/api/audit?")) == 1
        details.locator(".correction-tag").first.wait_for()
        details.get_by_text("Retracted by #").wait_for()


def test_a_confirm_opened_while_the_trail_redraws_stays_open_until_it_closes(browser, synthetic_case):
    """The audit trail draws again after a retract, to show it. A confirm the analyst opens on the trail while that
    read is out stays open when the read answers, since the redraw would close it, and the trail draws once the confirm
    closes. The redraw's read is held here until the confirm shows."""
    read = []
    for page in served_page(browser, synthetic_case, setup=mark_and_note_an_event):
        details = page.locator("#details")
        case_menu(page, "auditButton")
        note = details.locator(".audit-row", has_text="a note to retract").first
        note.get_by_role("button", name="Retract").click()
        page.route("**/api/audit?*", first_held(read))
        page.evaluate(RECORD_REQUESTS)
        note.locator(".audit-confirm").get_by_role("button", name="Retract").click()
        wait_held(page, read)
        mark = details.locator(".audit-row", has_text="Malicious").first
        mark.get_by_role("button", name="Undo").click()
        confirm = mark.locator(".audit-confirm")
        confirm.get_by_role("button", name="Undo 1 event").wait_for()
        read[0].continue_()
        page.unroute("**/api/audit?*")
        page.wait_for_function("() => window.__taken.some((path) => path.startsWith('/api/audit?'))")
        assert confirm.get_by_role("button", name="Undo 1 event").is_visible()
        assert details.get_by_text("Retracted by #").count() == 0
        confirm.get_by_role("button", name="Cancel").click()
        details.get_by_text("Retracted by #").wait_for()


def test_an_undo_whose_timeline_reload_fails_says_so_and_draws_the_trail(browser, synthetic_case):
    """The timeline reloads after an undo, and the audit trail then draws again to show it. When the reload fails, the
    status line says the timeline didn't reload and why, in place of the undo's own line, and the trail still draws. The
    reload of the lanes is refused here."""
    for page in served_page(browser, synthetic_case, setup=mark_and_note_an_event):
        details = page.locator("#details")
        case_menu(page, "auditButton")
        mark = details.locator(".audit-row", has_text="Malicious").first
        mark.get_by_role("button", name="Undo").click()
        page.route("**/api/lanes?*", refused_with("the lanes failed"))
        with page.expect_response("**/api/lanes?*"):
            mark.locator(".audit-confirm").get_by_role("button", name="Undo 1 event").click()
        page.unroute("**/api/lanes?*")
        page.errors[:] = [e for e in page.errors if "/api/lanes" not in e]   # that refusal was the point
        details.locator(".correction-tag").first.wait_for()
        assert page.locator("#status").inner_text() == "The timeline didn't reload: the lanes failed"
