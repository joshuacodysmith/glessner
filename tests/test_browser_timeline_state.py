"""The timeline's state after each change, in a real browser: the lanes, the Sources panel's boxes, the window's data,
Fit case's range, the logon links' counts, and the Hosts panel's edits. An answer that comes back after a later change
must not draw over it. They drive the installed Microsoft Edge through Playwright, as test_browser_smoke does, and are
skipped without it."""

import re

import pytest
from conftest import DC_LOG, SEC, T0, logon
from test_browser_page_guards import settled
from test_browser_smoke import (  # noqa: F401
    HOST_BOX_CHECKED,
    POINT,
    RECORD_REQUESTS,
    asked,
    browser,
    case_menu,
    clock_page,
    event_point,
    labels,
    page,
    served_page,
    wait_held,
)
from test_parsers import EVTX_COLUMNS
from test_splits import EDGE_SEC, PC01_SEC, make_run, security

from glessner.case import create_case
from glessner.events import load

pytestmark = pytest.mark.browser

# Whether the page's code has finished with answers to paths starting with each prefix, in this order, since
# RECORD_REQUESTS ran
TAKEN_IN_ORDER = """(prefixes) => {
    let at = 0;
    for (const prefix of prefixes) {
        const i = window.__taken.slice(at).findIndex((path) => path.startsWith(prefix));
        if (i < 0) return false;
        at += i + 1;
    }
    return true;
}"""
TAKEN = "([prefix, n]) => window.__taken.filter((path) => path.startsWith(prefix)).length >= n"


def hold_first(held, n=1):
    """A route handler that keeps the first `n` requests it sees in `held` and lets the rest through."""
    def handle(route):
        if len(held) < n:
            held.append(route)
        else:
            route.continue_()
    return handle


def later_reload_wins(p, first, second):
    """Make the change `first` with its lanes request held, then the change `second`, whose lanes answer, then let the
    first's answer through. Returns the second's answer, once the page's code has finished with both."""
    p.evaluate(RECORD_REQUESTS)
    held = []
    p.route("**/api/lanes?*", hold_first(held))
    first()
    wait_held(p, held)
    with p.expect_response("**/api/lanes?*") as later:
        second()
    p.wait_for_function(TAKEN, arg=["/api/lanes?", 1])
    held[0].continue_()
    p.unroute("**/api/lanes?*")
    p.wait_for_function(TAKEN, arg=["/api/lanes?", 2])
    return later.value.json()


@pytest.mark.parametrize("change", ["filter", "preset"])
def test_a_lanes_answer_for_an_earlier_change_is_dropped(page, change):  # noqa: F811
    """The lanes and the state line's count are the latest change's, though an earlier change's lanes answer last:
    under a filter, Show only DC01 and then Show all; for the lane keys, Host > Mark and then Role > Host > User,
    whose lanes key on other fields."""
    if change == "filter":
        def apply(call):
            return lambda: page.evaluate(f"() => import('/js/filters.js').then((m) => {{ m.{call}; }})")
        second = later_reload_wins(page, apply("showOnly({ host: 'DC01' })"), apply("clearFilters()"))
    else:
        def preset(index):
            return lambda: page.locator("#groupby").select_option(index)
        second = later_reload_wins(page, preset("1"), preset("2"))
    assert page.evaluate("window.__app.S.lanes") == second["lanes"]
    assert page.evaluate("window.__app.S.lanesShown") == second["shown"]
    assert page.locator("#stShown").inner_text().startswith(f"Showing {second['shown']:,} of ")
    if change == "filter":
        assert "DESKTOP" in "\n".join(labels(page))
    else:
        # The first-level rows, past the group of sources outside the case, are the roles the later answer's lanes start with
        first = "[...new Set(window.__app.S.rows.filter((r) => r.depth === 0 && r.keys).map((r) => r.keys[0]))]"
        assert sorted(page.evaluate(first)) == sorted({lane["keys"][0] for lane in second["lanes"]})


def lab_case_split_whole(tmp_path):
    """A one-folder collection, LAB, of event logs that PC01 and MSEDGEWIN10 recorded, and nothing else: split by
    recorded computer, LAB keeps no event and goes."""
    (tmp_path / "evidence" / "LM").mkdir(parents=True)
    case = create_case(tmp_path / "case", "Samples", tmp_path / "evidence", "cody", single_host="LAB")
    rows = [
        security(case, 1, 4624, "PC01.example.corp", PC01_SEC, 1, TargetUserName="alice", TargetDomainName="CORP",
                 LogonType="3", TargetLogonId="0x3E7", IpAddress="10.0.2.15"),
        security(case, 2, 4688, "PC01.example.corp", PC01_SEC, 2, NewProcessName="C:\\Windows\\System32\\cmd.exe"),
        security(case, 1, 4624, "MSEDGEWIN10", EDGE_SEC, 4, TargetUserName="bob", LogonType="3",
                 TargetLogonId="0x3E7", IpAddress="10.0.2.15"),
    ]
    make_run(case, "evtxecmd", "evtxecmd_csv", "evtxecmd.csv", EVTX_COLUMNS, rows, [PC01_SEC, EDGE_SEC], 1)
    return case


def test_a_split_that_takes_every_rule_away_leaves_no_filter(browser, tmp_path):  # noqa: F811
    """Show only LAB, then split LAB by recorded computer. LAB goes, so its rule comes off, and with no rule left the
    timeline has no filter: the lanes show the new hosts, not a filter that names a host that's gone."""
    case = lab_case_split_whole(tmp_path)
    for p in served_page(browser, case):
        p.evaluate("() => import('/js/filters.js').then((m) => { m.showOnly({ host: 'LAB' })"
                   ".then((r) => { window.__only = r; }); })")
        p.wait_for_function("() => window.__only !== undefined")
        assert p.evaluate("window.__app.S.filterId") is not None
        case_menu(p, "hostsButton")
        notice = p.locator("#hostSplits .split-notice")
        notice.get_by_role("button", name="Split LAB by recorded computer…").click()
        notice.get_by_role("button", name=re.compile(r"^Split into \d+ hosts$")).click()
        p.wait_for_function("() => document.getElementById('status').textContent.startsWith('Split LAB into')")
        assert p.evaluate("window.__app.S.meta.hosts.map((h) => h.host).sort()") == ["MSEDGEWIN10", "PC01"]
        assert p.evaluate("window.__app.S.filter.only") == []
        assert p.evaluate("window.__app.S.filterId") is None
        shown = "\n".join(labels(p))
        assert "PC01" in shown and "MSEDGEWIN10" in shown


def host_row(host):
    return f"#fpTree .frow[data-pred='{{\"host\":\"{host}\"}}']"


# Whether a host's row in the Sources panel reads this count
HOST_COUNT = """([host, text]) => document.querySelector(`#fpTree .frow[data-pred='{"host":"${host}"}'] .n`)
                                     ?.textContent === text"""


@pytest.mark.parametrize("panel", ["open", "reopened"])
def test_the_sources_boxes_wait_for_the_counts_of_the_filter_in_force(page, panel):  # noqa: F811
    """The Sources panel's boxes come from the counts the filter in force shows. Until they answer, no box can say
    what shows: each is disabled and its count reads "…", so DESKTOP, hidden by the latest change, doesn't read checked,
    and a click on DC01's box, hidden by the change before, changes no rule. A panel closed for the change and opened
    while its counts are out waits too. Once they answer, the boxes read the latest change's counts."""
    tree = page.locator("#fpTree")
    dc01 = tree.get_by_role("checkbox", name="Show DC01", exact=True)
    desktop = tree.get_by_role("checkbox", name="Show DESKTOP", exact=True)
    page.locator("#filtersButton").click()
    with page.expect_response("**/api/shown?*"):
        dc01.uncheck()   # hides DC01
    full = page.evaluate("window.__app.S.sources.hosts.find((h) => h.host === 'DC01').count.toLocaleString()")
    page.wait_for_function(HOST_COUNT, arg=["DC01", f"0 of {full}"])
    held = []
    page.route("**/api/shown?*", lambda route: held.append(route))
    if panel == "open":
        with page.expect_request("**/api/filter"):
            desktop.click()   # hides DESKTOP too
    else:
        page.locator("#filtersButton").click()   # closes the panel, which asks for no counts while closed
        page.evaluate("() => import('/js/filters.js').then((m) => m.setShown({ host: 'DESKTOP' }, false))")
        page.locator("#filtersButton").click()
    wait_held(page, held)
    rules = page.evaluate("JSON.stringify(window.__app.S.filter)")
    for host, box in (("DC01", dc01), ("DESKTOP", desktop)):
        assert not box.is_checked() and box.is_disabled(), host
        assert page.locator(f"{host_row(host)} .n").inner_text() == "…", host
    page.evaluate(RECORD_REQUESTS)
    dc01.click(force=True)
    # A click that acts registers its filter at once, so a quarter of a second covers it
    page.wait_for_timeout(250)
    assert page.evaluate("JSON.stringify(window.__app.S.filter)") == rules
    assert asked(page, "/api/filter") == []
    held[0].continue_()
    page.unroute("**/api/shown?*")
    page.wait_for_function(HOST_COUNT, arg=["DC01", f"0 of {full}"])
    assert page.evaluate(HOST_BOX_CHECKED, ["DESKTOP", False]) and page.evaluate(HOST_BOX_CHECKED, ["DC01", False])
    assert dc01.is_enabled() and desktop.is_enabled()


# Click the Logon links box on the first of the page's turns that runs while the window moves
TOGGLE_LINKS_DURING_THE_MOTION = """() => {
    const until = performance.now() + 10000;
    const tick = () => {
        if (window.__app.S.anim) { document.getElementById('showLinks').click(); window.__toggled = true; }
        else if (performance.now() < until) setTimeout(tick, 5);
    };
    setTimeout(tick, 5);
}"""

# The page coordinates of the first density bar drawn away from the logon links, whose arrows take a click first
DENSITY_BAR = f"""() => {{
    const nearLink = (x) => window.__app.S.linkSegs.some((seg) => Math.abs(seg.x - x) < 8);
    for (const [row, items] of window.__app.S.index.entries()) {{
        for (const it of items || []) {{
            const x = (it.x0 + it.x1) / 2;
            if (it.kind === 'cell' && !nearLink(x)) return ({POINT})(row, {{ x }}, null);
        }}
    }}
    return null;
}}"""


SHOWN_IS_VIEW = ("() => { const { S } = window.__app; return S.shownWindow.start === S.view.start "
                 "&& S.shownWindow.end === S.view.end; }")


def test_a_redraw_asked_for_while_the_window_moves_draws_the_new_window(page):  # noqa: F811
    """A click on a density bar moves the window to the bar, and its data loads during the motion. Logon links toggled
    meanwhile asks for the window the motion goes to. The motion's own answer, for that window, draws while the
    toggle's request is out, and once both answer, the window's data and its "In this window" count are the new
    window's, not a window the motion passed through."""
    page.evaluate("() => { window.__app.S.meta.event_threshold = 1; return window.__app.fetchView(); }")
    page.wait_for_function("() => window.__app.S.data.mode === 'density' && !window.__app.S.windowPending")
    bar = page.evaluate(DENSITY_BAR)
    assert bar, "no density bar drawn"
    page.evaluate(RECORD_REQUESTS)
    held = []
    page.route("**/api/view?*", hold_first(held, 2))
    page.evaluate(TOGGLE_LINKS_DURING_THE_MOTION)
    page.mouse.click(bar["x"], bar["y"])
    wait_held(page, held)
    page.wait_for_function("() => window.__toggled === true")
    page.wait_for_function("() => window.__app.S.anim === null")
    held[0].continue_()
    page.wait_for_function(TAKEN, arg=["/api/view?", 1])
    assert page.evaluate(SHOWN_IS_VIEW), "the motion's answer wasn't drawn while the toggle's request was out"
    wait_held(page, held, 2)
    held[1].continue_()
    page.unroute("**/api/view?*")
    page.wait_for_function(TAKEN, arg=["/api/view?", 2])
    assert page.evaluate(SHOWN_IS_VIEW)
    assert page.evaluate("() => { const { S } = window.__app; return S.data.start === Math.floor(S.view.start * 1000) "
                         "&& S.data.end === Math.ceil(S.view.end * 1000); }")
    count = page.evaluate("window.__app.S.data.count")
    assert page.locator("#stInWindow").inner_text() == f"In this window: {count:,}"


def test_an_offset_moves_fit_case_s_range(page):  # noqa: F811
    """A clock offset moves its host's times, and with them Fit case's range and its hover. DESKTOP has the case's
    latest events, so a day's offset on it moves the range's end by a day."""
    end = T0 + 910 * SEC   # DESKTOP's last logon
    assert page.evaluate("window.__app.S.meta.fit.end") == end
    case_menu(page, "hostsButton")
    page.evaluate(RECORD_REQUESTS)
    offset = page.locator("#hostsTable tr[data-host='DESKTOP'] input[type=number]")
    offset.fill("86400")
    offset.press("Enter")
    page.wait_for_function(TAKEN_IN_ORDER, arg=["/api/host", "/api/lanes?", "/api/view?"])
    assert page.evaluate("window.__app.S.meta.fit.end") == end + 86_400 * SEC
    assert "From 2020-09-19 to 2020-09-20" in page.locator("#fit").get_attribute("title")


def test_a_range_read_that_answers_after_a_later_offset_s_is_dropped(page):  # noqa: F811
    """Each offset reads the case's range again. A day's offset on DESKTOP and then none: the first read answers
    last, and Fit case keeps the range the second read gave, the one the offsets in force make."""
    end = T0 + 910 * SEC   # DESKTOP's last logon
    case_menu(page, "hostsButton")
    page.evaluate(RECORD_REQUESTS)
    held = []

    def answered_now_delivered_late(route):
        if held:
            route.continue_()
        else:
            held.append((route, route.fetch()))

    page.route("**/api/meta", answered_now_delivered_late)

    def offset():
        return page.locator("#hostsTable tr[data-host='DESKTOP'] input[type=number]")

    offset().fill("86400")
    offset().press("Enter")
    wait_held(page, held)
    page.wait_for_function("() => window.__app.S.meta.hosts.find((h) => h.host === 'DESKTOP').offset_seconds === 86400")
    offset().fill("0")
    offset().press("Enter")
    page.wait_for_function(TAKEN, arg=["/api/meta", 1])
    assert page.evaluate("window.__app.S.meta.fit.end") == end
    route, answer = held[0]
    route.fulfill(response=answer)
    page.unroute("**/api/meta")
    page.wait_for_function(TAKEN, arg=["/api/meta", 2])
    assert page.evaluate("window.__app.S.meta.hosts.find((h) => h.host === 'DESKTOP').offset_seconds") == 0
    assert page.evaluate("window.__app.S.meta.fit.end") == end


def test_a_split_moves_fit_case_s_range_back_to_the_times_recorded(browser, tmp_path):  # noqa: F811
    """A day's offset on LAB moves its times, and Fit case's range with them. Split by recorded computer, LAB's events
    go to new hosts, which don't take its offset, so the range is again the one the times as recorded make."""
    case = lab_case_split_whole(tmp_path)
    for p in served_page(browser, case):
        recorded = p.evaluate("window.__app.S.meta.fit")
        case_menu(p, "hostsButton")
        offset = p.locator("#hostsTable tr[data-host='LAB'] input[type=number]")
        offset.fill("86400")
        offset.press("Enter")
        p.wait_for_function("(end) => window.__app.S.meta.fit.end === end", arg=recorded["end"] + 86_400 * SEC)
        notice = p.locator("#hostSplits .split-notice")
        notice.get_by_role("button", name="Split LAB by recorded computer…").click()
        notice.get_by_role("button", name=re.compile(r"^Split into \d+ hosts$")).click()
        p.wait_for_function("() => document.getElementById('status').textContent.startsWith('Split LAB into')")
        assert p.evaluate("window.__app.S.meta.fit") == recorded


def test_aligning_the_clocks_moves_fit_case_s_range(clock_page):  # noqa: F811
    """Aligning every measured host to the capture moves their times, and Fit case's range with them: once the timeline
    has redrawn, the range is the one the server gives for the offsets now in force."""
    p = clock_page
    before = p.evaluate("window.__app.S.meta.fit")
    p.evaluate(RECORD_REQUESTS)
    p.locator("#clockAligned").click()
    p.wait_for_function(TAKEN_IN_ORDER, arg=["/api/host", "/api/lanes?", "/api/view?"])
    after = p.evaluate("() => import('/js/core.js').then((m) => m.api('/api/meta')).then((meta) => meta.fit)")
    assert after["end"] != before["end"]
    assert p.evaluate("window.__app.S.meta.fit") == after


def test_a_user_lane_named_constructor_reads_its_name_and_show_only_applies(browser, synthetic_case):  # noqa: F811
    """A lane's label is its key, or the spelling the server gives for it. A user named constructor, from a failed
    logon that records no domain, is a key like any other: its lane reads constructor, and Show only on it shows it
    alone."""
    failed = logon(T0 + 30 * SEC, 106, DC_LOG, user="constructor", domain="", ltype="3", code="4625")
    load(synthetic_case.db_path, [failed], host="DC01", tool="evtxecmd", tool_version="t", run_id="r7",
         replaces_sources=[], staging_dir=synthetic_case.folder)
    for p in served_page(browser, synthetic_case):
        p.locator("#groupby").select_option("3")   # User > Host
        p.wait_for_function("() => window.__app.S.rows.some((r) => r.depth === 0 && r.key === 'user')")
        at = p.evaluate("() => window.__app.S.rows.findIndex((r) => r.depth === 0 && r.keys?.[0] === 'constructor')")
        row = p.locator(f"#labels .row[data-row='{at}']")
        assert row.evaluate("(r) => r.childNodes[1].textContent") == "constructor"
        row.click(button="right")
        p.locator("#quickMenu").get_by_role("menuitem", name="Show only constructor").click()
        p.wait_for_function("() => window.__app.S.filterId !== null && window.__app.S.lanes.length === 1")
        assert p.evaluate("window.__app.S.filter.only") == [{"user": "constructor"}]
        assert p.evaluate("window.__app.S.lanes") == [{"keys": ["constructor", "DC01"], "count": 1}]


def test_a_logon_link_from_a_host_with_no_lane_is_counted_and_named(page):  # noqa: F811
    """With DESKTOP hidden in the Sources, DC01's logons from DESKTOP have no source lane to draw from. The window
    count's hover counts them, and the status line's note names the host and says why."""
    page.locator("#filtersButton").click()
    page.evaluate(RECORD_REQUESTS)
    page.locator("#fpTree").get_by_role("checkbox", name="Show DESKTOP", exact=True).uncheck()
    # The view under the filter, drawn
    page.wait_for_function("() => window.__taken.some((path) => path.startsWith('/api/view?') && path.includes('&filter='))")
    from_desktop = page.evaluate("window.__app.S.data.links.items"
                                 ".filter((l) => l.source === 'DESKTOP' && !l.outside && l.target_keys).length")
    assert from_desktop >= 1
    assert page.evaluate("window.__app.S.linksSkipped") == from_desktop
    hover = page.locator("#stInWindow").get_attribute("title")
    assert hover.endswith(f"; {from_desktop:,} from a host with no lane not drawn.")
    note = page.evaluate("window.__app.S.linkNote")
    assert "DESKTOP" in note and note in page.locator("#status").inner_text()


def test_the_hosts_panel_adds_a_dotted_name_as_a_name_and_an_address_as_an_ip(page):  # noqa: F811
    """A value typed beside a host is an IP address when it is four dotted numbers or holds a colon, and a name
    otherwise: dc1.ad is a name, though every character in it could be part of an IPv6 address."""
    case_menu(page, "hostsButton")
    add = "#hostsTable tr[data-host='DC01'] input[type=text]"
    # The Hosts panel is drawn again with each answer, so the next value goes in the new row's box
    listed = "([field, value]) => window.__app.S.meta.hosts.find((h) => h.host === 'DC01')[field].includes(value)"
    for value, op, field, stored in (("dc1.ad", "add_name", "names", "DC1"), ("10.0.0.9", "add_ip", "ips", "10.0.0.9"),
                                     ("fe80::5", "add_ip", "ips", "fe80::5")):
        page.locator(add).fill(value)
        with page.expect_response("**/api/host") as answer:
            page.locator(add).press("Enter")
        assert answer.value.request.post_data_json["op"] == op
        assert answer.value.ok, answer.value.json()
        page.wait_for_function(listed, arg=[field, stored])


def test_a_page_opened_while_a_host_change_applies_keeps_the_panel(page):  # noqa: F811
    """A host change redraws the timeline, then the Event page on screen, whose time and clock note follow an offset.
    A page asked for while the change was out keeps the panel: here Findings, opened while an offset applied, whose
    read answers after the timeline has redrawn."""
    uid = event_point(page, "4624", hit=True)["uid"]
    page.evaluate("(uid) => window.__app.select(uid, false)", uid)
    page.wait_for_selector(f"#details[data-key='event:{uid}'] .ev-ident")
    case_menu(page, "hostsButton")
    page.evaluate(RECORD_REQUESTS)
    host, findings = [], []
    page.route("**/api/host", lambda route: host.append(route))
    page.route("**/api/findings_page", lambda route: findings.append(route))
    offset = page.locator("#hostsTable tr[data-host='DC01'] input[type=number]")
    offset.fill("60")
    offset.press("Enter")
    wait_held(page, host)
    page.locator("#tabFindings").click()
    wait_held(page, findings)
    host[0].continue_()
    page.unroute("**/api/host")
    page.wait_for_function(TAKEN_IN_ORDER, arg=["/api/host", "/api/lanes?", "/api/view?"])
    findings[0].continue_()
    page.unroute("**/api/findings_page")
    page.wait_for_function(TAKEN, arg=["/api/findings_page", 1])
    # The page takes an answer as soon as it arrives, so half a second covers the redraw that taking it would make
    page.wait_for_timeout(500)
    assert page.locator("#details").get_attribute("data-page") == "findings"
    assert asked_events(page) == []


def test_an_event_page_asked_for_before_an_offset_and_drawn_while_it_applies_follows_it(page):  # noqa: F811
    """An Event page asked for before a host change, and drawn while the change is out, read the time from before it.
    It is no page asked for since, so once the timeline has redrawn, it reloads and shows its time with the offset."""
    uid = event_point(page, "4624", hit=True)["uid"]
    case_menu(page, "hostsButton")
    page.evaluate(RECORD_REQUESTS)
    event, host = [], []
    page.route("**/api/event?*", hold_first(event))
    page.route("**/api/host", lambda route: host.append(route))
    page.evaluate("(uid) => window.__app.select(uid, false)", uid)
    wait_held(page, event)
    offset = page.locator("#hostsTable tr[data-host='DC01'] input[type=number]")
    offset.fill("60")
    offset.press("Enter")
    wait_held(page, host)
    event[0].continue_()   # the event is read before the offset applies
    page.unroute("**/api/event?*")
    page.wait_for_selector(f"#details[data-key='event:{uid}'] .ev-ident")
    drawn = page.evaluate("window.__app.S.focusEvent")
    assert drawn["host"] == "DC01"
    host[0].continue_()
    page.unroute("**/api/host")
    page.wait_for_function(TAKEN, arg=["/api/event?", 2])
    assert page.evaluate("window.__app.S.focusEvent.adjusted") == drawn["adjusted"] + 60 * SEC


def test_an_event_page_left_and_opened_again_while_a_host_change_applies_follows_it(page):  # noqa: F811
    """An Event page left for Findings and opened again with Back while an offset is out reads its time from before
    the offset. The page on screen is the one the analyst asked for last, so once the timeline has redrawn, it reloads
    and shows its time with the offset."""
    uid = event_point(page, "4624", hit=True)["uid"]
    page.evaluate("(uid) => window.__app.select(uid, false)", uid)
    page.wait_for_selector(f"#details[data-key='event:{uid}'] .ev-ident")
    drawn = page.evaluate("window.__app.S.focusEvent")
    assert drawn["host"] == "DC01"
    case_menu(page, "hostsButton")
    page.evaluate(RECORD_REQUESTS)
    host = offset_dc01_held(page)
    page.locator("#tabFindings").click()
    page.wait_for_selector("#details[data-page='findings'] .findings-col")
    page.locator("#detailsBand button.back").click()
    page.wait_for_selector(f"#details[data-key='event:{uid}'] .ev-ident")
    assert page.evaluate("window.__app.S.focusEvent.adjusted") == drawn["adjusted"]
    release_and_settle(page, host)
    assert len(asked_events(page)) == 2
    assert page.locator("#details").get_attribute("data-key") == f"event:{uid}"
    assert page.evaluate("window.__app.S.focusEvent.adjusted") == drawn["adjusted"] + 60 * SEC


def test_another_event_s_page_opened_while_a_host_change_applies_follows_it(page):  # noqa: F811
    """The Event page of another event on the same host, opened while an offset is out, read its time from before the
    offset. It is the page the analyst asked for last, so once the timeline has redrawn, it reloads and shows its time
    with the offset."""
    first = event_point(page, "4624", hit=True)["uid"]
    other = another_dc01_event(page, first)
    page.evaluate("(uid) => window.__app.select(uid, false)", first)
    page.wait_for_selector(f"#details[data-key='event:{first}'] .ev-ident")
    case_menu(page, "hostsButton")
    page.evaluate(RECORD_REQUESTS)
    host = offset_dc01_held(page)
    page.evaluate("(uid) => window.__app.select(uid, false)", other)
    page.wait_for_selector(f"#details[data-key='event:{other}'] .ev-ident")
    drawn = page.evaluate("window.__app.S.focusEvent")
    assert drawn["host"] == "DC01"
    release_and_settle(page, host)
    assert len(asked_events(page)) == 2
    assert page.locator("#details").get_attribute("data-key") == f"event:{other}"
    assert page.evaluate("window.__app.S.focusEvent.adjusted") == drawn["adjusted"] + 60 * SEC


def test_another_event_s_page_still_loading_when_a_host_change_applies_follows_it(page):  # noqa: F811
    """The Event page of another event on the same host, asked for while an offset is out, can read its time from
    before the offset and draw only after the timeline has redrawn. Once it draws, it reloads and shows its time with
    the offset."""
    first = event_point(page, "4624", hit=True)["uid"]
    other = another_dc01_event(page, first)
    page.evaluate("(uid) => window.__app.select(uid, false)", first)
    page.wait_for_selector(f"#details[data-key='event:{first}'] .ev-ident")
    case_menu(page, "hostsButton")
    page.evaluate(RECORD_REQUESTS)
    host = offset_dc01_held(page)
    held = []

    def answered_now_delivered_late(route):
        if held:
            route.continue_()
        else:
            held.append((route, route.fetch()))

    page.route("**/api/event?*", answered_now_delivered_late)
    page.evaluate("(uid) => window.__app.select(uid, false)", other)
    wait_held(page, held)
    route, answer = held[0]
    before = answer.json()["event"]   # the event as the server reads it before the offset applies
    assert before["host"] == "DC01"
    host[0].continue_()
    page.unroute("**/api/host")
    page.wait_for_function(TAKEN_IN_ORDER, arg=["/api/host", "/api/lanes?", "/api/view?"])
    assert page.locator("#details").get_attribute("data-key") != f"event:{other}"
    route.fulfill(response=answer)
    page.unroute("**/api/event?*")
    page.wait_for_selector(f"#details[data-key='event:{other}'] .ev-ident")
    settled(page)   # a reload the page asked for as it drew has answered
    assert len(asked_events(page)) == 2
    assert page.locator("#details").get_attribute("data-key") == f"event:{other}"
    assert page.evaluate("window.__app.S.focusEvent.adjusted") == before["adjusted_ts_us"] + 60 * SEC


def another_dc01_event(p, first):
    """An event drawn in the window on DC01, other than `first`."""
    return p.evaluate("""(first) => {
        const { S } = window.__app, at = S.groupby.indexOf('host');
        return S.data.events.find((e) => e.uid !== first && e.keys[at] === 'DC01').uid;
    }""", first)


def offset_dc01_held(p):
    """Set DC01's offset to 60 s in the open Hosts panel, and return the list that holds the change's request."""
    host = []
    p.route("**/api/host", lambda route: host.append(route))
    offset = p.locator("#hostsTable tr[data-host='DC01'] input[type=number]")
    offset.fill("60")
    offset.press("Enter")
    wait_held(p, host)
    return host


def release_and_settle(p, host):
    """Let the held host change through, and wait until the timeline has redrawn and every request since has answered,
    the Event page's pivot counts aside, which its redraw cancels."""
    host[0].continue_()
    p.unroute("**/api/host")
    p.wait_for_function(TAKEN_IN_ORDER, arg=["/api/host", "/api/lanes?", "/api/view?"])
    settled(p)


def asked_events(p):
    return p.evaluate("() => window.__asked.filter((path) => path.startsWith('/api/event?'))")
