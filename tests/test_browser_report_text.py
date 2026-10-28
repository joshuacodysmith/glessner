"""The Overview's note on a host's events outside its span, and bidi controls on the pages that carry the report's and the
case's text, in a real browser. A host's span leaves out a time no run could have read; the note beside it counts those
events with their dates. The header's line and its hover, the Overview (host names, Integrity's hover of changed files),
the Tools page's found output, and the Export preview show each bidi control as a visible [U+XXXX], as the pages
test_browser_bidi covers do. They drive the installed Microsoft Edge through Playwright, as test_browser_smoke does, and
are skipped without it."""

import pytest
from test_browser_bidi import MIXED, NAME, RLO, USER, mixed_case, raw_controls, shown
from test_browser_frame import no_tool_scan
from test_browser_report import open_findings
from test_browser_smoke import browser, case_menu, served_page  # noqa: F401
from test_overview import RUN, STRAY, run_record, timed
from test_tool_outputs import EVTX_COLUMNS, evtx_rows, write_rows

from glessner.events import connect, to_us
from glessner.intake import intake, verify
from glessner.server import api_mark, api_setting
from glessner.tools import load_registry

pytestmark = pytest.mark.browser
EARLY = to_us("1980-01-01T00:00:00Z")

# renderCaseState, given a state of the shape /api/case_state answers and an analyst's name
RENDER = """async ([state, analyst]) => {
    const core = await import('/js/core.js');
    core.S.meta.analyst = analyst;
    (await import('/js/frame.js')).renderCaseState(state);
}"""


def changed_file(case, host, name):
    """An evidence file named `name` under the host's folder, hashed at intake and changed after it, and the problem a
    full re-hash found."""
    path = case.evidence / host / name
    path.write_text("first", encoding="utf-8")
    intake(case)
    path.write_text("changed", encoding="utf-8")
    problems = verify(case, reason="manual full verification")
    assert problems == [f"{host}/{name}: SHA-256 changed"]
    return problems[0]


def test_the_overview_draws_a_note_beside_the_span_of_a_host_with_events_outside_it(browser, synthetic_case):  # noqa: F811
    """A host with one event in 3320 reads its span from its other events, with the one outside counted by its date. A
    host with two outside, a 1980 file time and a time in 3320, says how many and between which dates."""
    timed(synthetic_case, "DC01", [STRAY])
    timed(synthetic_case, "DESKTOP", [EARLY, STRAY], run="r21")
    run_record(synthetic_case, RUN, "evtxecmd", "DC01", "ok", 6)
    for p in served_page(browser, synthetic_case, tab="overview", setup=no_tool_scan):
        p.wait_for_selector("#ovHosts")
        span = lambda host: p.locator(f"#ovHosts tr[data-host='{host}'] td").nth(4)   # noqa: B023
        assert span("DC01").inner_text() == ("2020-09-19 02:21:48 to 2020-09-19 03:22:51\n"
                                             "1 event dated 3320-11-16, outside the rest")
        assert span("DESKTOP").inner_text() == ("2020-09-19 02:21:48 to 2020-09-19 03:36:58\n"
                                                "2 events outside the rest, dated 1980-01-01 to 3320-11-16")
        assert "before 1990 or more than a day after the newest tool run" in span("DC01").locator(".muted").get_attribute("title")
        assert p.locator("#ovHosts tr[data-host='DC01'] td").nth(3).inner_text() == "8"   # the events counted still hold it
        assert raw_controls(p) == []


def test_the_overview_shows_a_host_name_and_the_integrity_hover_with_bidi_controls_as_code_points(browser, tmp_path):  # noqa: F811
    """A host whose name holds a left-to-right isolate, and an evidence file with a right-to-left override in its name
    that a re-hash found changed. The Hosts table, By host, and Integrity's hover of the changed files write the
    controls as [U+XXXX]."""
    case = mixed_case(tmp_path)
    problem = changed_file(case, "LM", f"report{RLO}fdp.scr")
    for p in served_page(browser, case, tab="overview", setup=no_tool_scan):
        p.wait_for_selector("#ovChanged")
        assert p.locator("#ovChanged").get_attribute("title") == shown(problem)
        assert p.locator("#ovHosts tbody tr td").first.inner_text() == shown(MIXED)
        assert p.locator("#ovByHost tbody tr td").first.inner_text() == shown(MIXED)
        assert raw_controls(p) == []


def test_the_tools_page_shows_found_output_s_host_and_file_names_with_bidi_controls_as_code_points(browser, synthetic_case):  # noqa: F811
    """Tool output found in an evidence folder whose name holds a right-to-left override: the row's host and the hover
    that lists its files write the override as [U+202E]."""
    host = f"WS{RLO}02"
    path = "Modules/EventLogs/20240514_EvtxECmd_Output.csv"
    write_rows(synthetic_case.evidence / host / path, EVTX_COLUMNS, evtx_rows("WS02.corp.local"))
    intake(synthetic_case)
    for p in served_page(browser, synthetic_case, setup=lambda app: setattr(app, "tool_cache", (load_registry(), {}))):
        case_menu(p, "toolsButton")
        p.wait_for_selector("#details[data-page='tools'] .tools-outputs")
        row = p.locator("#details .tools-outputs tbody tr").first
        assert row.locator("td").nth(2).inner_text() == f"1 file, on {shown(host)}"
        assert row.locator("td").first.get_attribute("title") == f"{shown(host)}/{path}"
        assert raw_controls(p) == []


def test_the_header_line_and_its_hover_name_a_changed_file_with_its_bidi_control_as_a_code_point(browser, synthetic_case):  # noqa: F811
    """A full re-hash found an evidence file changed whose name holds a right-to-left override. The header's hover,
    which lists the files the checks found, writes it as [U+202E], and nothing in the header holds the character."""
    problem = changed_file(synthetic_case, "DC01", f"report{RLO}fdp.scr")
    for p in served_page(browser, synthetic_case, tab="overview", setup=no_tool_scan):
        line = p.locator("#caseState")
        assert line.inner_text() == "Open · evidence changed since intake: 1 file · analyst cody"
        assert shown(problem) in line.get_attribute("title")
        assert raw_controls(p) == []


def test_the_header_line_shows_each_text_a_state_gives_with_its_bidi_controls_as_code_points(browser, synthetic_case):  # noqa: F811
    """renderCaseState writes the analyst's name, the problems the checks found, the newest check's reason, the reasons
    a copy's manifest record names, and the journal's words, in the line and its hover, with each bidi control as
    [U+XXXX]."""
    words = f"after {NAME}"
    state = {"closed": None, "intake": True, "manifest_missing": "", "evidence_files": 3, "added_files": 0, "unreadable": 1,
             "unlisted": 1,
             "manifest_record": {"unvouched": ["break"], "warn": True, "text": f"Its source's journal had a break {words}"},
             "checks": {"checks": 2, "files": 1, "changed_files": 1, "not_reread": 0, "unreadable_lines": 1,
                        "problems": [f"DC01/{NAME}: SHA-256 changed"], "found_at": "2026-10-16T01:00:00Z",
                        "last_full": {"at": "2026-10-16T01:00:00Z", "reason": "manual full verification", "files_checked": 3,
                                      "result": "mismatch", "problems": 1},
                        "newest": {"at": "2026-10-16T01:00:00Z", "reason": words, "files_checked": 3, "result": "mismatch",
                                   "problems": 1}},
             "journal": {"broken": True, "read_only": f"The journal was changed {words}"}}
    for p in served_page(browser, synthetic_case, tab="overview", setup=no_tool_scan):
        p.evaluate(RENDER, [state, USER])
        line = p.locator("#caseState")
        assert line.inner_text().endswith(f"analyst {shown(USER)}")
        title = line.get_attribute("title")
        for text in (f"DC01/{NAME}: SHA-256 changed", f"({words})", f"Its source's journal had a break {words}",
                     f"The journal was changed {words}"):
            assert shown(text) in title, text
        assert raw_controls(p) == []


def test_the_export_preview_shows_a_marked_event_s_bidi_controls_as_the_report_writes_them(browser, synthetic_case):  # noqa: F811
    """A marked event whose message and source file hold a right-to-left override, a Summary that names the file, and a
    note on the mark: the Markdown the preview shows has no raw control, and writes the override as [U+202E] in the
    escaped text and inside the code span."""
    with connect(synthetic_case.db_path) as con:
        uid = con.execute("SELECT event_uid FROM events WHERE tool = 'evtxecmd' AND event_code = '4624' "
                          "ORDER BY ts_us LIMIT 1").fetchone()[0]
        con.execute("UPDATE events SET message = ?, source_file = ? WHERE event_uid = ?",
                    [f"Ran {NAME}", f"DC01/{NAME}.evtx", uid])

    def marks(app):
        api_mark(app, {"uids": [uid], "value": "malicious", "note": f"see {NAME}"})
        api_setting(app, {"name": "report_summary", "value": f"A dropper called {NAME} ran."})

    for p in served_page(browser, synthetic_case, setup=marks):
        open_findings(p)
        p.locator("#details .exports-col").get_by_role("button", name="Preview").click()
        preview = p.locator("#details .report-preview")
        preview.wait_for(state="visible")
        text = preview.inner_text()
        assert r"A dropper called report\[U+202E\]fdp.scr ran." in text
        assert r"Ran report\[U+202E\]fdp.scr" in text and "evtx `DC01/report[U+202E]fdp.scr.evtx`" in text
        assert raw_controls(p) == []
