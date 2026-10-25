"""Browser tests for the app's frame: the Case panel grouped by job with its path and Case menu, the Case overview and
its actions, the Timeline's toolbar, its state line, and the legend, in light and dark.
They run as test_browser_smoke.py's do, on the installed Edge, and are skipped without it."""

import json

import pytest
from conftest import DC_LOG
from test_browser_smoke import browser, case_menu, clock_page, filtered_view, served_page, to_timeline, view  # noqa: F401
from test_manifest_record import copy_naming_reasons
from test_overview import FILES, app_with_work, evidence_log, held_open, overview_case, rewrite_record, run_record  # noqa: F401

from glessner import intake as intake_module
from glessner.events import connect
from glessner.intake import add_new, intake, verify
from glessner.journal import unvouched_words
from glessner.tools import load_registry

pytestmark = pytest.mark.browser
BACKGROUND = {"light": "rgb(243, 243, 240)", "dark": "rgb(21, 21, 23)"}
# The tokens draw.js reads for its colors, in each scheme, as app.css defines them and the legend's swatches must
# compute them
TOKENS = {"light": {"--unreviewed": "#5b7aa6", "--authorized": "#2f8a4c", "--suspicious": "#bd8000", "--malicious": "#c0262d",
                    "--hit": "#c0262d", "--select": "#111111", "--related": "#e0a400", "--muted": "#5c5c66",
                    "--d1": "#dbe6f3", "--d5": "#1f4f99", "--link": "#c2410c", "--line": "#d6d6d1",
                    "--suspicious-text": "#8a5c00"},
          "dark": {"--unreviewed": "#8aa6cf", "--authorized": "#5cc27c", "--suspicious": "#e8b23a", "--malicious": "#f05a5f",
                   "--hit": "#f05a5f", "--select": "#ffffff", "--related": "#ffd257", "--muted": "#a3a3ad",
                   "--d1": "#24364f", "--d5": "#8fb6ec", "--link": "#f08a4b", "--line": "#3a3a41",
                   "--suspicious-text": "#e5b84a"}}
# Each swatch's paint and the token draw.js draws that mark with: ticks by mark, a hollow suggestion in its mark's
# color, the hit box, the selection box, the related fill, a faded pivot result, the density shades (draw.js mixes d1
# and d5 in sRGB, so the middle shade is their mean), the hit line, logon links, window links, and the clock pair link
SWATCHES = [("lg-unreviewed", "fill", "--unreviewed"), ("lg-authorized", "fill", "--authorized"),
            ("lg-suspicious", "fill", "--suspicious"), ("lg-malicious", "fill", "--malicious"),
            ("lg-hollow", "stroke", "--suspicious"), ("lg-hit", "stroke", "--hit"), ("lg-select", "stroke", "--select"),
            ("lg-related", "fill", "--related"), ("lg-faded", "fill", "--muted"), ("lg-d1", "fill", "--d1"),
            ("lg-d3", "fill", ("--d1", "--d5")), ("lg-d5", "fill", "--d5"), ("lg-hitline", "fill", "--hit"),
            ("lg-link", "stroke", "--link"), ("lg-link-head", "fill", "--link"), ("lg-link-count", "fill", "--link"),
            ("lg-window", "stroke", "--related"), ("lg-window-gap", "fill", "--related"), ("lg-pair", "stroke", "--suspicious")]
# Lane label flags, in the lane labels' colors
FLAGS = [(".lg-flag.clock-flag:not(.aligned)", "--suspicious-text"), (".lg-flag.clock-flag.aligned", "--muted"),
         (".lg-flag.guess", "--suspicious-text")]


def rgb(hex_color):
    return tuple(int(hex_color[i:i + 2], 16) for i in (1, 3, 5))


def paint(text):
    """A computed color as numbers: rgb(...) as Edge gives a plain color, color(srgb ...) as it gives color-mix's."""
    if text.startswith("color(srgb"):
        return tuple(round(float(v) * 255) for v in text[len("color(srgb "):-1].split()[:3])
    return tuple(int(v) for v in text[text.index("(") + 1:-1].split(",")[:3])


def no_tool_scan(app):
    """The Tools page without detection's version checks, which take seconds."""
    app.tool_cache = (load_registry(), {})


def current(p):
    return p.locator("#path button[aria-current='page']").inner_text()


def focused(p):
    return p.evaluate("document.activeElement.id")


@pytest.mark.parametrize("scheme", ["light", "dark"])
def test_the_path_leads_from_the_overview_to_the_timeline_to_investigate_and_findings(browser, synthetic_case, scheme):  # noqa: F811
    """A case opens on its overview, with the timeline loaded behind it, and the path's steps show their pages: To
    investigate its page, and Findings the Findings page, with the exports beside the findings. The Timeline step takes
    the Details panel off their pages, so the path and the panel agree. A page opened over the overview, such as a
    search, brings the timeline forward. The line under the case's name gives its state; the overview's empty sections
    say what they cover."""
    for p in served_page(browser, synthetic_case, tab="overview", color_scheme=scheme, setup=no_tool_scan):
        assert p.evaluate("getComputedStyle(document.body).backgroundColor") == BACKGROUND[scheme]
        p.wait_for_selector("#ovStart")
        assert p.locator("#overview").is_visible() and current(p) == "Overview"
        assert p.locator("#work").evaluate("(n) => n.inert") and p.evaluate("window.__app.S.data !== null")
        assert p.locator("#caseState").inner_text() == "Open · no intake manifest yet · analyst cody"
        assert p.locator("#ovGaps p").inner_text() == (
            "None recorded: no tool's latest run failed or loaded nothing, intake identified and read every file and "
            "listed every folder, no log clear is recorded, and every host but a network sensor lane has event logs.")
        p.locator("#tabTimeline").click()
        assert p.locator("#overview").is_hidden() and current(p) == "Timeline"
        assert not p.locator("#work").evaluate("(n) => n.inert") and p.locator("#lanes").is_visible()
        p.locator("#investigateButton").click()
        p.wait_for_selector("#details[data-page='investigate']")
        assert current(p).startswith("To investigate")
        p.locator("#tabTimeline").click()   # no event in focus: back to the opening hint
        p.wait_for_selector("#details[data-page='hint'] .hint")
        assert current(p) == "Timeline"
        p.locator("#tabFindings").click()
        p.wait_for_selector("#details[data-page='findings'] .exports-col")
        assert current(p) == "Findings"
        p.locator("#tabOverview").click()
        assert p.locator("#overview").is_visible() and current(p) == "Overview"
        p.locator("#search").fill("code:4624")
        p.locator("#search").press("Enter")
        p.wait_for_selector("#details[data-page='search']")
        assert p.locator("#overview").is_hidden() and current(p) == "Timeline"
        # With no leads, Start here says what it would have listed
        p.route("**/api/overview", lambda route: route.fulfill(
            json={**route.fetch().json(), "leads": []}))
        p.locator("#tabOverview").click()
        p.wait_for_function("() => document.getElementById('ovLeads').textContent.startsWith('No leads')")
        assert p.locator("#ovLeads").inner_text() == (
            "No leads: no alert with a time at medium level or above, no rule that suggests an event, and no host clock "
            "the check measured off the capture.")


def test_the_case_menu_opens_moves_and_closes_by_mouse_and_keyboard(browser, synthetic_case):  # noqa: F811
    """Case is a menu button. A click or Enter or Space opens it at its first item, and the arrow down or up key at
    its first or last; the arrow keys move and wrap, Home and End jump; Escape closes it and gives the focus back;
    Tab, a click elsewhere, or the focus leaving it by the / key closes it; Enter on an item does what it says."""
    for p in served_page(browser, synthetic_case, setup=no_tool_scan):
        button, menu = p.locator("#caseMenuButton"), p.locator("#caseMenu")
        assert menu.is_hidden() and button.get_attribute("aria-expanded") == "false"
        assert menu.locator("[role=menuitem]").evaluate_all("(items) => items.map((i) => i.firstChild.textContent)") == [
            "Hosts", "Tools", "Import", "Rules", "Export", "Audit trail", "Cases"]
        button.click()
        assert menu.is_visible() and button.get_attribute("aria-expanded") == "true" and focused(p) == "hostsButton"
        p.locator("#details").click()
        assert menu.is_hidden() and button.get_attribute("aria-expanded") == "false"
        button.focus()
        p.keyboard.press("Enter")
        assert menu.is_visible() and focused(p) == "hostsButton"
        p.keyboard.press("ArrowDown")
        assert focused(p) == "toolsButton"
        p.keyboard.press("ArrowUp")
        p.keyboard.press("ArrowUp")
        assert focused(p) == "casesButton"   # wraps
        p.keyboard.press("Home")
        assert focused(p) == "hostsButton"
        p.keyboard.press("End")
        assert focused(p) == "casesButton"
        p.keyboard.press("Escape")
        assert menu.is_hidden() and focused(p) == "caseMenuButton"
        p.keyboard.press(" ")
        assert menu.is_visible() and focused(p) == "hostsButton"
        p.keyboard.press("Escape")
        p.keyboard.press("ArrowUp")
        assert menu.is_visible() and focused(p) == "casesButton"
        p.keyboard.press("Tab")
        assert menu.is_hidden()
        button.click()
        p.keyboard.press("/")   # search's own key takes the focus out of the menu
        assert menu.is_hidden() and focused(p) == "search" and button.get_attribute("aria-expanded") == "false"
        button.focus()
        p.keyboard.press("ArrowDown")
        p.keyboard.press("ArrowDown")
        p.keyboard.press("Enter")
        p.wait_for_selector("#details[data-page='tools']")
        assert menu.is_hidden() and focused(p) == "caseMenuButton"


def test_every_control_that_left_the_header_still_works(browser, synthetic_case):  # noqa: F811
    """Every control works: the Timeline's controls from its toolbar, each with its hover hint, and the setup and
    record work from the Case menu."""
    intake(synthetic_case)   # the Import page lists the manifest's files
    for p in served_page(browser, synthetic_case, setup=no_tool_scan):
        # The case buttons' hover hints carry the case's counts, so they are set when the counts answer, which can be
        # after the page is ready
        p.wait_for_function("() => document.getElementById('investigateButton').title !== ''")
        for control in ("lanesLabel", "fit", "filtersButton", "viewButton", "linksLabel", "machineLabel", "addZone",
                        "legendButton", "tabOverview", "tabTimeline", "investigateButton", "tabFindings", "caseMenuButton",
                        "hostsButton", "toolsButton", "importButton", "rulesButton", "exportButton", "auditButton",
                        "casesButton", "searchHelp", "clockRecorded", "clockAligned"):
            assert p.locator(f"#{control}").get_attribute("title"), control
        assert p.locator("#filtersButton").get_attribute("title").startswith("Sources: show or hide hosts, evidence types")
        assert p.locator("#legendButton").get_attribute("title") == ("Legend: what each mark on the timeline means. "
                                                                      "Press L to show or hide it.")
        p.locator("#groupby").select_option(label="Host > Mark")
        p.wait_for_function("() => window.__app.S.groupby.join() === 'host,mark'")
        start = view(p)["start"]
        p.evaluate("(t) => window.__app.setView(t, t + 60000)", start + 600_000)
        p.locator("#fit").click()
        p.wait_for_function("(t) => Math.abs(window.__app.S.view.start - t) < 1", arg=start)
        for button, panel in (("filtersButton", "filterPanel"), ("viewButton", "viewPanel")):
            p.locator(f"#{button}").click()
            p.wait_for_selector(f"#{panel}:not([hidden])")
            p.locator(f"#{button}").click()
            p.wait_for_selector(f"#{panel}", state="hidden")
        # The links drawn are the window's before Fit until the fitted window's data answers
        p.wait_for_function("() => window.__app.S.data.links.items.length > 0")
        p.locator("#showLinks").uncheck()
        p.wait_for_function("() => window.__app.S.data.links.items.length === 0")
        with p.expect_request(lambda r: "/api/view" in r.url and "hide_machine=0" in r.url):
            p.locator("#hideMachine").uncheck()
        p.locator("#addZone").click()
        p.wait_for_selector("#quickMenu:not([hidden])")
        p.keyboard.press("Escape")
        case_menu(p, "hostsButton")
        assert p.locator("#hostsPanel").is_visible()
        case_menu(p, "hostsButton")
        assert p.locator("#hostsPanel").is_hidden()
        for item, page_name in (("toolsButton", "tools"), ("importButton", "import"), ("rulesButton", "rules"),
                                ("exportButton", "findings"), ("auditButton", "audit")):   # Export opens the Findings page
            case_menu(p, item)
            p.wait_for_selector(f"#details[data-page='{page_name}']")
        with p.expect_navigation():
            case_menu(p, "casesButton")
        p.wait_for_function("() => window.__start && window.__start.info !== null")


def test_the_overview_shows_each_section_and_its_actions_open_the_events(browser, overview_case):  # noqa: F811
    """Start here's leads in their stated order, with Worked on a worked one; progress, by host, what the case holds,
    its gaps, and its integrity; and each action and number leads to the events or page behind it."""
    app, uid = app_with_work(overview_case)
    app.con.close()
    for p in served_page(browser, overview_case, tab="overview", setup=no_tool_scan):
        p.wait_for_selector("#ovLeads .ov-lead")
        leads = p.locator("#ovLeads .ov-lead")
        titles = leads.locator(".t").all_inner_texts()
        assert len(titles) == 7
        assert titles[0] == "Hayabusa, critical and high: 3 events on DC01, 2020-09-19 03:21:48 to 03:52:50 UTC"
        assert titles[3] == "Hayabusa, medium: 1 event on DESKTOP, 2020-09-19 03:36:22 UTCWorked"
        assert [leads.nth(i).locator(".ov-badge").count() for i in range(7)] == [0, 0, 0, 1, 1, 0, 0]
        assert titles[6] == "DESKTOP's clock ran 59 m 59.5 s ahead of the capture"
        assert leads.nth(0).locator(".counts").inner_text() == "3 events; 1 without a mark or a decision"
        assert p.locator("#ovStart .ov-note").inner_text().startswith("Ranked by severity: critical alerts, then high")
        stats = p.locator("#ovStats").inner_text()
        # The line names its three relations: To investigate counts each event's own top pivots, so it can differ
        for text in ("Leads worked\n2 of 7", "3 decided, 6 pending", "2 of 2 marked Malicious or Suspicious", "Notes\n1",
                     "Marked events sharing a logon session, file, or source IP with unreviewed events\n2 of 2",
                     "Your last action\n"):
            assert text in stats, text
        assert p.locator("#ovByHost tr[data-host='DC01']").inner_text().split("\t") == ["DC01", "1", "3", "1 of 4 worked"]
        assert "59 m 59.5 s ahead of the capture, not aligned" in p.locator("#ovHosts tr[data-host='DESKTOP']").inner_text()
        assert "Event log, Registry; Hayabusa: 5 events with a hit" in p.locator("#ovHosts tr[data-host='DC01']").inner_text()
        gaps = p.locator("#ovGaps").inner_text()
        for text in ("SrumECmd on DESKTOP: failed: exit code 1.", "RBCmd on DC01: ran and loaded nothing.",
                     "1 file intake could not identify, kept in the manifest and hashed.",
                     "DC01: 1102 in Security at 2020-09-19 03:26:48 UTC", "WS03: no event logs loaded."):
            assert text in gaps, text
        integrity = p.locator("#ovIntegrity").inner_text()
        closed = json.loads(overview_case.verification_path.read_text().splitlines()[-1])["at"][:10]
        for text in ("1 evidence file hashed at intake (SHA-256)",
                     f"Last full re-hash: {closed}, at the case's close: every readable file matched",
                     "Times shown: UTC, as each host's clock recorded them", "Build: "):
            assert text in integrity, text

        # Open on timeline: the lead's events selected, its window in view, the earliest on the Event page
        leads.nth(0).get_by_role("button", name="Open on timeline").click()
        p.wait_for_function("(want) => [...window.__app.S.selected].sort().join() === want.sort().join()",
                            arg=[uid[101], uid[104], uid[106]])
        p.wait_for_selector("#details[data-page='event'] .selection-list")
        assert p.locator("#overview").is_hidden() and current(p) == "Timeline"
        assert p.locator("#details .ev-verdict h3").text_content() == "Verdict for 3 selected events"
        p.wait_for_function("(a) => window.__app.S.view.start < a.start && window.__app.S.view.end > a.end",
                            arg={"start": 1600485708000, "end": 1600487570000})
        assert "Hidden from the timeline" not in p.locator("#status").inner_text()
        # Review suggestions and Show in Hosts
        p.locator("#tabOverview").click()
        leads.nth(5).get_by_role("button", name="Review suggestions").click()
        p.wait_for_selector("#details[data-page='suggestions']")
        assert "machine-accounts-authorized suggests authorized" in p.locator("#details h2").inner_text()
        p.locator("#tabOverview").click()
        leads.nth(6).get_by_role("button", name="Show in Hosts").click()
        p.wait_for_selector("#hostsTable tr[data-host='DESKTOP']")
        assert p.locator("#hostsPanel").is_visible() and current(p) == "Timeline"
        # A number that stands for events opens them: Malicious 1 sets the View to that mark and lists its event in the
        # Details panel. The list draws last, after the state line's count, and setPage's followPage takes the timeline
        # forward over the overview when a page draws: drawn after the click on Overview below, it hides the gaps,
        # and the click on See the run waits 30 s (1 full suite run in 11, 3 runs of this test in 40, when measured)
        p.locator("#tabOverview").click()
        p.locator("#ovProgress .ov-legend button").first.click()
        p.wait_for_function("() => window.__app.S.viewSpec && window.__app.S.viewSpec.marks.join() === 'Malicious'")
        p.wait_for_function("() => document.getElementById('stShown').textContent.startsWith('Showing 1 of ')")
        p.wait_for_selector("#details[data-page='opened'] h2:text-is('Events marked Malicious')")
        assert p.locator("#details li.rel-row").count() == 1
        # The gaps' links: the run on the Tools page, the unidentified files there, and a log clear's event
        p.locator("#tabOverview").click()
        p.locator("#ovGaps li[data-run]").first.get_by_role("button", name="See the run").click()
        p.wait_for_selector("#details li[data-run='20261016T010100Z_srumecmd_DESKTOP']")
        p.locator("#tabOverview").click()
        p.locator("#ovGaps").get_by_role("button", name="See in Tools").click()
        p.wait_for_selector("#toolsUnidentified:not([hidden])")
        p.locator("#tabOverview").click()
        p.locator(f"#ovGaps li[data-clear='{uid[108]}']").get_by_role("button", name="Open the event").click()
        p.wait_for_function("(u) => window.__app.S.focus === u", arg=uid[108])


def test_a_lead_s_rule_titles_open_the_events_the_rule_hit_on_its_host(browser, overview_case):  # noqa: F811
    """A Hayabusa lead's why line lists its rules with their event counts, each rule's title a link that opens the
    Timeline and searches the events that rule hit on the lead's host, at any time; another tool's lead has no links."""
    app, _ = app_with_work(overview_case)
    app.con.close()
    for p in served_page(browser, overview_case, tab="overview", setup=no_tool_scan):
        p.wait_for_selector("#ovLeads .ov-lead")
        leads = p.locator("#ovLeads .ov-lead")
        why = leads.nth(0).locator(".why")
        assert why.inner_text() == "Rules: Critical rule (1 event), RDP from internet (1 event), Service installed (1 event)."
        assert why.locator("button").all_inner_texts() == ["Critical rule", "RDP from internet", "Service installed"]
        link = why.get_by_role("button", name="Critical rule")
        assert link.get_attribute("title") == "Search the events this rule hit on DC01, at any time"
        assert leads.nth(1).locator(".why button").count() == 0   # Suricata's signatures are not Hayabusa rules
        link.click()
        p.wait_for_selector("#details[data-page='search'] li.rel-row")
        assert current(p) == "Timeline" and p.locator("#search").input_value() == 'rule:"Critical rule" host:DC01'
        assert p.locator("#detailsBand .title").inner_text() == 'Search: rule:"Critical rule" host:DC01'
        assert p.locator("#details li.rel-row").count() == 1
        assert "Hayabusa rule" in p.locator("#details .reach").first.inner_text()


def test_a_lead_or_a_number_says_how_many_of_its_events_the_sources_hide(browser, overview_case):  # noqa: F811
    """A lead's events, or the events a number opens, can fall under hidden Sources, which the timeline
    doesn't draw. The status says how many, and where to show them, rather than only that they were selected."""
    app, _ = app_with_work(overview_case)
    app.con.close()
    for p in served_page(browser, overview_case, setup=no_tool_scan):
        p.locator("#filtersButton").click()
        # The lead's line is the status line's until the next redraw of it, and the Sources change's own view redraws
        # it when it answers, so the lead opens after the page has drawn that view
        with filtered_view(p) as drawn:
            p.locator("#fpTree").get_by_role("checkbox", name="Show DC01", exact=True).uncheck()
        p.wait_for_function("(n) => window.__app.S.data.count === n", arg=drawn.value.json()["count"])
        p.wait_for_selector("#stHiddenSources")
        p.locator("#tabOverview").click()
        p.locator("#ovLeads .ov-lead").nth(0).get_by_role("button", name="Open on timeline").click()
        p.wait_for_function("(n) => window.__app.S.selected.size === n", arg=3)
        p.wait_for_function("() => document.getElementById('status').textContent.includes('Hidden from the timeline')")
        assert p.locator("#status").inner_text().endswith(
            ". Hidden from the timeline: 3 by the Sources; the state line's Show buttons show them.")
        # DC01's one mark, from By host, under the same Sources
        p.locator("#tabOverview").click()
        p.locator("#ovByHost tr[data-host='DC01'] td.num button").first.click()
        p.wait_for_function("() => document.getElementById('status').textContent.startsWith('The Sources hide')")
        assert p.locator("#status").inner_text() == (
            'The Sources hide 1 event this View shows; the Show beside "Hidden by Sources" on the state line shows them.')
        assert p.locator("#stShown").inner_text().startswith("Showing 0 of ")


def test_the_overview_names_each_hayabusa_lead_s_rule_set_and_the_rows_each_host_skipped(browser, overview_case):  # noqa: F811
    """A Hayabusa lead's chips give the rule set of the Hayabusa run that made its hits, not the maps of the EvtxECmd
    run that parsed the events they matched, and say so when a run made before the case recorded its rules has no label.
    A Suricata lead keeps its rule set's chip. A host's events cell says how many rows its latest runs skipped."""
    run_record(overview_case, "r7", "evtxecmd", "DC01", "ok", 11, rules="Maps, 456 maps",
               tool_files={"EvtxECmd.exe": "12" * 32, "Maps/": "34" * 32})
    run_record(overview_case, "r8", "hayabusa", "DC01", "ok", 4, rules="Hayabusa rules fffbdd1", tool_files=FILES)
    run_record(overview_case, "r9", "hayabusa", "DESKTOP", "ok", 1)
    run_record(overview_case, "20261016T020000Z_mftecmd_DC01", "mftecmd", "DC01", "ok", 5, inputs=("DC01/C/$MFT",),
               rows_skipped=4)
    rewrite_record(overview_case, "20261016T010000Z_suricata_network", rows_skipped=1)
    app, _ = app_with_work(overview_case)
    app.con.close()
    for p in served_page(browser, overview_case, tab="overview", setup=no_tool_scan):
        p.wait_for_selector("#ovLeads .ov-lead")
        leads = p.locator("#ovLeads .ov-lead")
        assert [leads.nth(i).locator(".ov-chip").all_inner_texts() for i in range(4)] == [
            ["Hayabusa 3.6.0, t", "Hayabusa rules fffbdd1"], ["Suricata 8.0.7", "ET Open 11310"],
            ["Hayabusa 3.6.0", "Hayabusa rules fffbdd1"], ["Hayabusa 3.6.0", "Hayabusa rules not recorded"]]
        skipped = lambda host: p.locator(f"#ovHosts tr[data-host='{host}'] td.num div.muted").all_inner_texts()  # noqa: B023
        assert (skipped("DC01"), skipped("network"), skipped("DESKTOP")) == (["and 4 skipped"], ["and 1 skipped"], [])


def test_a_gap_s_reason_ends_in_one_period_on_the_overview_and_the_tools_page(browser, overview_case):  # noqa: F811
    """A reason that already ends in a period, as a failed run's can and a found load's note does, takes no second one
    where the Overview's Gaps and the Tools page's list of runs end it, and a reason without one takes one on both."""
    note = ("1 row naming x.evtx was not loaded: a run of this tool on the host read the file itself, and that run's "
            "events stand for it.")
    rewrite_record(overview_case, "20261016T010100Z_srumecmd_DESKTOP", reason="exit code 1.")
    rewrite_record(overview_case, "20261016T010200Z_rbcmd_DC01", notes=[note])
    run_record(overview_case, "20261016T010500Z_jlecmd_DESKTOP", "jlecmd", "DESKTOP", "failed", None, reason="exit code 3")
    app, _ = app_with_work(overview_case)
    app.con.close()
    squeeze = lambda texts: [" ".join(t.split()) for t in texts]
    for p in served_page(browser, overview_case, tab="overview", setup=no_tool_scan):
        p.wait_for_selector("#ovGaps li[data-run]")
        assert squeeze(p.locator("#ovGaps li[data-run]").all_inner_texts()) == [
            "SrumECmd on DESKTOP: failed: exit code 1. See the run", f"RBCmd on DC01: ran and loaded nothing. {note} See the run",
            "JLECmd on DESKTOP: failed: exit code 3. See the run"]
        case_menu(p, "toolsButton")
        p.wait_for_selector("#details[data-page='tools'] .tools-gaps li")
        assert squeeze(p.locator("#details .tools-gaps li").all_inner_texts()) == [
            "SrumECmd on DESKTOP: failed. exit code 1. Run 20261016T010100Z_srumecmd_DESKTOP, 2026-10-16 01:00 UTC",
            f"RBCmd on DC01: ran and loaded nothing. {note} Run 20261016T010200Z_rbcmd_DC01, 2026-10-16 01:00 UTC",
            "JLECmd on DESKTOP: failed. exit code 3. Run 20261016T010500Z_jlecmd_DESKTOP, 2026-10-16 01:00 UTC"]


def test_the_report_outline_says_its_method_covers_the_rule_sets(browser, synthetic_case):  # noqa: F811
    """The Method line of the report's outline names the tools, their versions, their rule sets, the runs, and the build."""
    for p in served_page(browser, synthetic_case):
        p.locator("#tabFindings").click()
        p.wait_for_selector("#details .report-outline li")
        p.wait_for_function("() => [...document.querySelectorAll('#details .exports-col .ex-count')]"
                            ".every((n) => n.textContent !== '…')")
        method = p.locator("#details .report-outline li").nth(6).inner_text()
        assert method.startswith("Method, tools, versions, rule sets, ") and method.endswith(", and the build")


def test_the_header_line_reads_every_evidence_check_and_follows_a_findings_summary(browser, overview_case):  # noqa: F811
    """The case was closed with its evidence matching; a later full re-hash found a file changed, and a
    run's check of another file matched after it. The line says closed and changed, since a close outranks no later
    check and a run's matching check clears nothing. Restored, the report's re-hash matches, and the line
    follows it."""
    app, _ = app_with_work(overview_case)
    app.con.close()
    unknown = overview_case.evidence / "DC01" / "unknown.bin"
    unknown.write_bytes(b"changed")
    assert verify(overview_case, reason="manual full verification") == ["DC01/unknown.bin: SHA-256 changed"]
    (overview_case.evidence / "DESKTOP" / "later.txt").write_text("added later")
    add_new(overview_case)
    assert verify(overview_case, ["DESKTOP/later.txt"], reason="after run r13") == []
    for p in served_page(browser, overview_case, setup=no_tool_scan):
        line = p.locator("#caseState")
        assert line.inner_text() == "Closed on 2026-10-16 · evidence changed since intake: 1 file · analyst cody"
        assert "DC01/unknown.bin: SHA-256 changed" in line.get_attribute("title")
        assert "1 evidence file hashed at intake (SHA-256), and 1 added later." in line.get_attribute("title")
        unknown.write_bytes(b"\x01\x02 nothing known")
        p.locator("#tabFindings").click()
        p.locator("#details").get_by_role("button", name="Write report (Markdown)").click()
        p.wait_for_function("() => document.getElementById('caseState').textContent.includes('full re-hash matched')")
        rehashed = json.loads(overview_case.verification_path.read_text().splitlines()[-1])
        assert rehashed["reason"] == "full check when writing the report"
        assert line.inner_text() == f"Closed on 2026-10-16 · full re-hash matched on {rehashed['at'][:10]} · analyst cody"


def test_the_header_line_and_integrity_name_files_no_re_hash_could_check(browser, synthetic_case, monkeypatch):  # noqa: F811
    """A file intake couldn't read has no hash, so no re-hash checks it. After a full re-hash matched, the header's
    line names the unverified files, and the overview says the files with an intake hash matched, not every readable
    file: a file that can be read later still has no hash to check."""
    import glessner.intake as intake_module

    (synthetic_case.evidence / "DC01" / "locked.bin").write_bytes(b"locked")
    (synthetic_case.evidence / "DC01" / "open.bin").write_bytes(b"open")
    real = intake_module.sha256_file

    def sha256_file(path):   # as when another program holds the file open with no sharing
        if path.name == "locked.bin":
            raise PermissionError(13, "The process cannot access the file")
        return real(path)

    with monkeypatch.context() as m:
        m.setattr(intake_module, "sha256_file", sha256_file)
        intake(synthetic_case)
    assert verify(synthetic_case, reason="manual full verification") == []   # readable, and still unverified
    day = json.loads(synthetic_case.verification_path.read_text().splitlines()[-1])["at"][:10]
    for p in served_page(browser, synthetic_case, tab="overview", setup=no_tool_scan):
        line = p.locator("#caseState")
        assert line.inner_text() == f"Open · full re-hash matched on {day}; 1 file unverified · analyst cody"
        assert line.locator(".warn").inner_text() == "1 file unverified"
        p.wait_for_selector("#ovRehash")
        assert p.locator("#ovRehash").inner_text() == (
            f"Last full re-hash: {day}, by the verify command: every file with an intake hash matched")


MANIFEST_CHANGES = {
    "differs": ("manifest.jsonl differs from its record", "differed from its record"),
    "grew": ("manifest.jsonl grew past its record", "grew past its record"),
}


@pytest.mark.parametrize("state", list(MANIFEST_CHANGES))
def test_the_header_line_and_integrity_warn_when_only_the_manifest_changed(browser, synthetic_case, state):  # noqa: F811
    """A full re-hash whose only problem is manifest.jsonl against its record in the journal has no problem file, so the
    header's line and Integrity's re-hash warn of the manifest and never say the re-hash matched, and Integrity's
    manifest line says what the re-hash found."""
    from glessner.cli import main

    (synthetic_case.evidence / "DC01" / "a.txt").write_text("first", encoding="utf-8")
    assert main(["intake", str(synthetic_case.folder)]) == 0
    seq = json.loads((synthetic_case.folder / "journal.jsonl").read_bytes().splitlines()[-1])["seq"]
    if state == "differs":   # every entry still reads alike
        path = synthetic_case.manifest_path
        path.write_bytes(path.read_bytes().replace(b'"method": ', b'"method":  '))
    else:   # a stop between Add new evidence's replace and its record
        (synthetic_case.evidence / "DC01" / "b.txt").write_text("second", encoding="utf-8")
        add_new(synthetic_case)
    assert main(["verify", str(synthetic_case.folder)]) == 1
    last = json.loads(synthetic_case.verification_path.read_text().splitlines()[-1])
    day, checked = last["at"][:10], last["files_checked"]
    warning, found = MANIFEST_CHANGES[state]
    for p in served_page(browser, synthetic_case, tab="overview", setup=no_tool_scan):
        line = p.locator("#caseState")
        title = line.get_attribute("title")
        assert line.inner_text() == f"Open · {warning} · analyst cody"
        assert line.locator(".warn").inner_text() == warning and "matched" not in title
        # The newest check's sentence names what it found, which is no problem file
        assert f"(manual full verification), listed {checked} file{'s' if checked > 1 else ''}: {warning}." in title
        p.wait_for_selector("#ovRehash")
        assert p.locator("#ovRehash").inner_text() == f"Last full re-hash: {day}, by the verify command: {warning}"
        assert p.locator("#ovIntegrity #ovManifest.warn").inner_text() == (
            f"manifest.jsonl: {found}, entry #{seq}, at the last full re-hash")


def test_the_header_line_names_a_changed_evidence_file_and_the_manifest_together(browser, synthetic_case):  # noqa: F811
    """A full re-hash that found a changed evidence file and manifest.jsonl differing from its record warns of both, in
    the header's line and in the newest check's sentence of its hover."""
    from glessner.cli import main

    evidence = synthetic_case.evidence / "DC01" / "a.txt"
    evidence.write_text("first", encoding="utf-8")
    assert main(["intake", str(synthetic_case.folder)]) == 0
    path = synthetic_case.manifest_path
    path.write_bytes(path.read_bytes().replace(b'"method": ', b'"method":  '))
    evidence.write_text("changed", encoding="utf-8")
    assert main(["verify", str(synthetic_case.folder)]) == 1
    warning = "manifest.jsonl differs from its record"
    for p in served_page(browser, synthetic_case, tab="overview", setup=no_tool_scan):
        line = p.locator("#caseState")
        assert line.inner_text() == f"Open · evidence changed since intake: 1 file; {warning} · analyst cody"
        assert line.locator(".warn").inner_text() == f"evidence changed since intake: 1 file; {warning}"
        assert f"(manual full verification), listed 1 file: 1 problem; {warning}." in line.get_attribute("title")


def test_the_header_line_and_integrity_warn_of_a_missing_manifest_the_journal_records(browser,  # noqa: F811
                                                                                       synthetic_case):
    """A missing manifest.jsonl that the journal records is a warning in the header's line, with the words to restore it
    in its hover, and in Integrity's manifest line, never a case still waiting for intake, whatever the last full
    re-hash found."""
    from glessner.cli import main

    (synthetic_case.evidence / "DC01" / "a.txt").write_text("first", encoding="utf-8")
    assert main(["intake", str(synthetic_case.folder)]) == 0
    seq = json.loads((synthetic_case.folder / "journal.jsonl").read_bytes().splitlines()[-1])["seq"]
    assert main(["verify", str(synthetic_case.folder)]) == 0
    synthetic_case.manifest_path.unlink()
    for p in served_page(browser, synthetic_case, tab="overview", setup=no_tool_scan):
        line = p.locator("#caseState")
        assert line.inner_text() == "Open · manifest.jsonl is missing · analyst cody"
        assert line.locator(".warn").inner_text() == "manifest.jsonl is missing"
        assert (f"manifest.jsonl is missing, but the journal records it, entry #{seq}. Restore it from a copy of the "
                "case.") in line.get_attribute("title")
        p.wait_for_selector("#ovManifest")
        assert p.locator("#ovIntegrity #ovManifest.warn").inner_text() == (
            f"manifest.jsonl: missing, but the journal records it, entry #{seq}; restore it from a copy of the case")


@pytest.mark.parametrize(("name", "warns"), [("no head recorded here", True), ("a break", True),
                                             ("a first record from Add new evidence", False)])
def test_the_header_line_warns_when_a_copy_s_record_is_one_its_source_could_not_vouch_for(browser, synthetic_case,  # noqa: F811
                                                                                         tmp_path, name, warns):
    """A copy whose full re-hash matched has a warning in the header's line from its first open, before it has made a
    full re-hash of its own, and after it, when its manifest record is one its source couldn't vouch for: the source's
    journal had a break, or no head of it was recorded on this computer. The hover gives the reasons' words. A source
    whose first record came with Add new evidence is a note, in the hover only."""
    from glessner.cli import main

    copy, record = copy_naming_reasons(synthetic_case, tmp_path, name, verified=True)
    for rehash in (None, "the copy's own"):
        if rehash:
            assert main(["verify", str(copy.folder)]) == 0
        day = json.loads(copy.verification_path.read_text(encoding="utf-8").splitlines()[-1])["at"][:10]
        matched = f"full re-hash matched on {day}"
        for p in served_page(browser, copy, tab="overview", setup=no_tool_scan):
            line = p.locator("#caseState")
            assert unvouched_words(record) in line.get_attribute("title")
            if warns:
                warning = "manifest record: its source could not vouch for it"
                assert line.inner_text() == f"Open · {matched}; {warning} · analyst {copy.settings.analyst}"
                assert line.locator(".warn").inner_text() == warning
            else:
                assert line.inner_text() == f"Open · {matched} · analyst {copy.settings.analyst}"
                assert line.locator(".warn").count() == 0


def dc_log_event(case):
    """The ID of one event read from the case's DC01 Security log."""
    con = connect(case.db_path, read_only=True)
    try:
        return con.execute("SELECT event_uid FROM events WHERE source_file = ? LIMIT 1", [DC_LOG]).fetchone()[0]
    finally:
        con.close()


def provenance_check(p, uid):
    """The Event page's hash check against intake, for the event `uid`."""
    p.evaluate("(uid) => window.__app.select(uid, false)", uid)
    p.wait_for_selector("#details[data-page='event'] .prov .prov-check")
    return p.locator("#details .prov .prov-check")


def test_a_file_a_check_could_not_re_read_is_not_called_changed(browser, synthetic_case, monkeypatch):  # noqa: F811
    """A check that can't read a file, as when another program holds it open, compares no hash. The header's line,
    Integrity, and the Event page say the file could not be re-read, never that the evidence changed."""
    evidence_log(synthetic_case)
    intake(synthetic_case)
    with monkeypatch.context() as m:
        m.setattr(intake_module, "sha256_file", held_open("Security.evtx"))
        assert verify(synthetic_case, [DC_LOG], reason="after run r1") == [f"{DC_LOG}: unreadable (Permission denied)"]
    day = json.loads(synthetic_case.verification_path.read_text().splitlines()[-1])["at"][:10]
    uid = dc_log_event(synthetic_case)
    for p in served_page(browser, synthetic_case, tab="overview", setup=no_tool_scan):
        line = p.locator("#caseState")
        assert line.inner_text() == "Open · 1 evidence file could not be re-read · analyst cody"
        assert line.locator(".warn").inner_text() == "1 evidence file could not be re-read"
        assert "compared no hash" in line.get_attribute("title")
        p.wait_for_selector("#ovRehash")
        assert p.locator("#ovChanged").count() == 0
        assert p.locator("#ovIntegrity #ovNotReread.warn").inner_text() == (
            f"Could not be re-read, so not compared with intake: 1 file, found by the check of {day}")
        check = provenance_check(p, uid)
        assert check.inner_text() == "could not be re-read (Permission denied), so not compared with intake"
        assert "unreadable" in check.get_attribute("class")


def test_the_header_line_and_the_event_page_warn_of_check_log_lines_they_cannot_read(browser, synthetic_case):  # noqa: F811
    """A line of verification.jsonl that can't be read may have held a problem, so after a full re-hash that matched,
    the header's line warns of it, and the Event page says no readable check found the file changed rather than that it
    matches intake."""
    evidence_log(synthetic_case)
    intake(synthetic_case)
    assert verify(synthetic_case, reason="manual full verification") == []
    day = json.loads(synthetic_case.verification_path.read_text().splitlines()[-1])["at"][:10]
    with synthetic_case.verification_path.open("ab") as f:
        f.write(b"\0" * 64)
    assert verify(synthetic_case, [DC_LOG], reason="after a run") == []
    uid = dc_log_event(synthetic_case)
    for p in served_page(browser, synthetic_case, tab="overview", setup=no_tool_scan):
        line = p.locator("#caseState")
        assert line.inner_text() == f"Open · full re-hash matched on {day}; 1 check-log line unreadable · analyst cody"
        assert line.locator(".warn").inner_text() == "1 check-log line unreadable"
        assert ("1 line of verification.jsonl could not be read, so any problem it holds is not counted here."
                in line.get_attribute("title"))
        check = provenance_check(p, uid)
        assert check.inner_text() == "no readable check found it changed; 1 check-log line unreadable"
        assert "uncounted" in check.get_attribute("class")
        assert check.get_attribute("title").startswith("1 line of verification.jsonl could not be read")


def test_integrity_says_how_many_lines_of_the_check_log_could_not_be_read(browser, synthetic_case):  # noqa: F811
    """Two runs of 0x00 that crashes left in verification.jsonl, each made a whole line by the next check, are
    unreadable lines that may have held a problem. Integrity counts them in a warning; a case without one shows none."""
    intake(synthetic_case)
    assert verify(synthetic_case, reason="manual full verification") == []
    for p in served_page(browser, synthetic_case, tab="overview", setup=no_tool_scan):
        p.wait_for_selector("#ovRehash")
        assert p.locator("#ovCheckLines").count() == 0
    for _ in range(2):
        with synthetic_case.verification_path.open("ab") as f:
            f.write(b"\0" * 64)
        assert verify(synthetic_case, reason="after a run") == []
    for p in served_page(browser, synthetic_case, tab="overview", setup=no_tool_scan):
        p.wait_for_selector("#ovRehash")
        lines = p.locator("#ovIntegrity #ovCheckLines.warn")
        assert lines.inner_text() == (
            "2 lines of verification.jsonl could not be read, so any problem they hold is not counted here")


def test_the_overview_shows_before_the_timeline_behind_it_has_loaded(browser, synthetic_case):  # noqa: F811
    """The case opens on its overview, which is read first. The timeline loads behind it once the overview has
    answered: with the overview's answer held, the timeline asks for no lanes, and once it's let go, the overview is
    filled in and the timeline then loads."""
    for p in served_page(browser, synthetic_case, tab="overview"):
        held, lanes = [], []
        p.route("**/api/overview", lambda route: held.append(route))   # noqa: B023
        p.on("request", lambda r: lanes.append(r.url) if "/api/lanes" in r.url else None)   # noqa: B023
        p.reload()
        for _ in range(200):
            if held:
                break
            p.wait_for_timeout(50)
        p.wait_for_timeout(500)
        # The overview shows while it reads the case, and the timeline hasn't asked for its lanes
        assert held and not lanes and p.locator("#overview").inner_text() == "Reading the case..."
        held[0].continue_()
        p.unroute("**/api/overview")
        p.wait_for_selector("#ovStart #ovLeads .ov-lead")
        p.wait_for_function("() => window.__ready === true && window.__app.S.data !== null")
        assert lanes and p.locator("#overview").is_visible() and current(p) == "Overview"


def test_the_state_line_counts_what_is_hidden_and_each_show_clears_it_alone(browser, synthetic_case):  # noqa: F811
    """Showing X of Y events, X being what the Sources and View show over the whole case; a pill per
    hidden category, each naming what it hides and counting its own events, with Show clearing that one alone; and the
    window. A show pred alone hides nothing, so it makes no Sources pill."""
    for p in served_page(browser, synthetic_case):
        total = p.evaluate("window.__app.S.meta.rows")
        lanes = p.evaluate("import('/js/core.js').then((m) => m.api('/api/lanes?groupby=host'))")
        desktop = next(lane["count"] for lane in lanes["lanes"] if lane["keys"] == ["DESKTOP"])
        shown = p.locator("#stShown")
        assert shown.inner_text() == f"Showing {total:,} of {total:,} events on the timeline"
        machine = lanes["machine_links"]
        assert p.locator("#stHiddenMachine").inner_text() == f"Hidden: machine-account logon links ({machine:,})\nShow"
        p.locator("#stHiddenMachine").get_by_role("button", name="Show").click()
        assert not p.locator("#hideMachine").is_checked() and p.locator("#stHiddenMachine").count() == 0
        p.locator("#filtersButton").click()
        p.locator("#fpTree").get_by_role("checkbox", name="Show DESKTOP", exact=True).uncheck()
        p.wait_for_function("(t) => document.getElementById('stShown').textContent === t",
                            arg=f"Showing {total - desktop:,} of {total:,} events on the timeline")
        assert p.locator("#stHiddenSources").inner_text().startswith(f"Hidden by Sources (DESKTOP): {desktop:,} events")
        # The View on top: pending suggestions only, two on DC01 (Hayabusa's on 101, the machine-account rule's on 103)
        p.locator("#viewButton").click()
        p.locator("#viewPanel").get_by_role("button", name="Review", exact=True).click()
        p.wait_for_function("() => document.getElementById('stShown').textContent.startsWith('Showing 2 of ')")
        p.wait_for_function("() => !document.getElementById('stHidden').textContent.includes('...')")
        assert p.locator("#stHiddenSources").inner_text().startswith(f"Hidden by Sources (DESKTOP): {desktop:,} events")
        assert p.locator("#stHiddenView").inner_text().startswith(
            f"Hidden by the View (only Suggested): {total - desktop - 2:,} events")
        p.locator("#stHiddenView").get_by_role("button", name="Show").click()
        p.wait_for_function("(t) => document.getElementById('stShown').textContent === t",
                            arg=f"Showing {total - desktop:,} of {total:,} events on the timeline")
        assert p.locator("#stHiddenView").count() == 0 and p.locator("#stHiddenSources").count() == 1
        p.locator("#stHiddenSources").get_by_role("button", name="Show").click()
        p.wait_for_function("(t) => document.getElementById('stShown').textContent === t",
                            arg=f"Showing {total:,} of {total:,} events on the timeline")
        assert p.locator("#stHidden").inner_text() == ""
        assert p.locator("#stClockPill").inner_text() == "Times: UTC, as recorded"
        p.evaluate("window.__app.setView(Date.UTC(2020, 8, 19, 3), Date.UTC(2020, 8, 19, 3, 30))")
        assert p.locator("#stWindow").inner_text() == "Window 2020-09-19 03:00:00.000 to 03:30:00.000 UTC, 30 min"
        # A show pred with no hide to make an exception to, as a hand-made filter could hold, with the View on
        p.evaluate("window.__app.S.filter = { only: [], hide: [], show: [{ host: 'DC01' }] }")
        p.locator("#viewPanel").get_by_role("button", name="Review", exact=True).click()
        p.wait_for_function("() => document.getElementById('stShown').textContent.startsWith('Showing 2 of ')")
        p.wait_for_function("() => !document.getElementById('stHidden').textContent.includes('...')")
        assert p.locator("#stHiddenSources").count() == 0
        assert p.locator("#stHiddenView").inner_text().startswith(f"Hidden by the View (only Suggested): {total - 2:,} events")


def test_the_state_line_names_the_clock_and_aligns_from_it(clock_page):  # noqa: F811
    """The state line says which clock the times are on, with Align while hosts show recorded times and
    Show recorded once the switch aligned them. The pill is short and its hover says it in full; with the legend open,
    the toolbar wraps beside it, but Legend stays in its first row and the window on one line."""
    p = clock_page
    pill = p.locator("#stClockPill")
    assert pill.inner_text() == "Recorded times: DC01 +59 m 59.5 s, DESKTOP +59 m 59.5 s vs capture\nAlign"
    assert pill.get_attribute("title") == ("Times as each host's clock recorded them. Measured against the capture: "
                                           "DC01 +59 m 59.5 s, DESKTOP +59 m 59.5 s.")
    p.set_viewport_size({"width": 1280, "height": 800})
    p.locator("#legendButton").click()
    p.wait_for_selector("#legendPanel:not([hidden])")
    top = p.evaluate("""() => ['legendButton', 'lanesLabel', 'clockSwitch'].map((id) =>
        Math.round(document.getElementById(id).getBoundingClientRect().top))""")
    assert top[0] == top[1] < top[2], top   # the toolbar wrapped, and Legend kept its row
    lines = p.locator("#stWindow").evaluate("""(n) => { const r = document.createRange(); r.selectNodeContents(n);
        return new Set([...r.getClientRects()].map((c) => Math.round(c.bottom))).size; }""")
    assert lines == 1
    p.locator("#legendButton").click()
    p.locator("#stAlign").click()
    p.wait_for_selector("#clockAligned[aria-pressed='true']")
    p.wait_for_function("() => document.getElementById('stClockPill').textContent.startsWith('Aligned')")
    assert pill.inner_text() == "Aligned to capture: DC01 -3,599.5 s, DESKTOP -3,599.5 s\nShow recorded"
    # The switch reads Aligned before the alignment has reloaded the timeline, and a click before then is dropped; the
    # switch's halves say they're busy until it has
    p.wait_for_selector("#clockAligned:not([aria-disabled])")
    p.locator("#stRecorded").click()
    p.wait_for_selector("#clockRecorded[aria-pressed='true']")
    p.wait_for_function("() => document.getElementById('stClockPill').textContent.startsWith('Recorded times')")


@pytest.mark.parametrize("scheme", ["light", "dark"])
def test_the_legend_shows_by_button_and_by_l_in_the_page_colors(browser, synthetic_case, scheme):  # noqa: F811
    """The legend lists every mark the timeline draws, each swatch in the token draw.js draws that mark
    with, so each scheme gets its own colors; the button and L show or hide it, but L typed in a field doesn't; this
    browser remembers it, and the page works when storage is blocked."""
    for p in served_page(browser, synthetic_case, color_scheme=scheme):
        panel, button = p.locator("#legendPanel"), p.locator("#legendButton")
        assert panel.is_hidden() and button.get_attribute("aria-pressed") == "false"
        width = p.evaluate("window.__app.S.width")
        button.click()
        assert panel.is_visible() and button.get_attribute("aria-pressed") == "true"
        p.wait_for_function("(w) => window.__app.S.width < w", arg=width)   # the timeline makes room
        assert panel.locator("h3").all_text_contents() == ["Event ticks, by your mark", "Boxes and fills", "Zoomed out",
                                                           "Lines", "Lane labels"]
        assert panel.locator(".lg-item").count() == 19
        tokens = TOKENS[scheme]
        painted = p.evaluate("""(swatches) => swatches.map(([cls, prop]) =>
            getComputedStyle(document.querySelector(`#legendPanel .${cls}`))[prop])""", [s[:2] for s in SWATCHES])
        for (cls, _, token), got in zip(SWATCHES, painted, strict=True):
            want = (tuple(round((a + b) / 2) for a, b in zip(rgb(tokens[token[0]]), rgb(tokens[token[1]]), strict=True))
                    if isinstance(token, tuple) else rgb(tokens[token]))
            assert all(abs(a - b) <= 1 for a, b in zip(paint(got), want, strict=True)), (cls, got, want)
        flags = p.evaluate("(sel) => sel.map((s) => getComputedStyle(document.querySelector(`#legendPanel ${s}`)).color)",
                           [f[0] for f in FLAGS])
        assert [paint(c) for c in flags] == [rgb(tokens[f[1]]) for f in FLAGS]
        p.locator("#details").click()
        p.keyboard.press("l")
        assert panel.is_hidden() and button.get_attribute("aria-pressed") == "false"
        p.locator("#search").click()
        p.keyboard.press("l")
        assert panel.is_hidden() and p.locator("#search").input_value() == "l"
        p.locator("#details").click()
        p.keyboard.press("L")
        assert panel.is_visible()
        p.reload()
        p.wait_for_function("() => window.__ready === true && window.__app.S.data !== null")
        to_timeline(p)
        assert panel.is_visible() and button.get_attribute("aria-pressed") == "true"
        # Storage blocked, as in a private window or with site data blocked: closed, and the button still works
        p.add_init_script("Storage.prototype.getItem = () => { throw new Error('blocked'); };"
                          "Storage.prototype.setItem = () => { throw new Error('blocked'); };")
        p.goto(p.new_link())   # a reload would find no session in storage
        p.wait_for_function("() => window.__ready === true && window.__app.S.data !== null")
        to_timeline(p)
        assert panel.is_hidden()
        button.click()
        assert panel.is_visible()
