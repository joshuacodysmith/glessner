"""The report, the scoped exports, and Written from this case, in a real browser: the Summary written and saved,
Preview with nothing written, Write report as the page's one lead button, each export card's scope and its file, the
table of files written with the whole hash on hover, and the audit trail's cut of a long event name with the whole in
its hover and the click through. They drive the installed Microsoft Edge through Playwright, as test_browser_smoke
does, and are skipped without it."""

import json
from pathlib import Path

import pytest
from conftest import SEC, T0
from test_browser_smoke import browser, case_menu, served_page, view, window_text  # noqa: F401
from test_report import LONG

from glessner.journal import JOURNAL_FILE
from glessner.server import api_mark

pytestmark = pytest.mark.browser
FINDINGS = "#details[data-page='findings']"
RESULT = "#details .export-result"
WROTE = f"() => document.querySelector('{RESULT}')?.textContent.startsWith('Wrote')"
WRITTEN_NOTE = ("Each file is hashed when written and recorded in the journal, so a copy handed on can be checked against "
                "the case.")


def entries(case):
    return [json.loads(line) for line in (case.folder / JOURNAL_FILE).read_text(encoding="utf-8").splitlines()]


def uid_at(app, ts, tool="evtxecmd"):
    return app.con.execute("SELECT event_uid FROM events WHERE tool = ? AND ts_us = ?", [tool, ts]).fetchone()[0]


def open_findings(p):
    p.locator("#tabFindings").click()
    p.wait_for_selector(f"{FINDINGS} .export-card")
    # The column's counts arrive from /api/exports_page after the page draws
    p.wait_for_function("() => [...document.querySelectorAll('#details .exports-col .ex-count')]"
                        ".every((n) => n.textContent !== '…')")


def wrote(p, start):
    p.wait_for_function(f"(start) => document.querySelector('{RESULT}')?.textContent.startsWith(start)", arg=start)
    return p.locator(RESULT).inner_text()


def test_report_and_exports_open_with_the_details_band(browser, synthetic_case):  # noqa: F811
    """The right column's Report and Exports read as two sections. Each heading is the Details band,
    its tint and its name in --t-11 caps, with the panel's 3 px edge, and Exports stands 24 px below the report's
    buttons."""
    for p in served_page(browser, synthetic_case):
        open_findings(p)
        heads = p.evaluate("""() => {
            const band = getComputedStyle(document.getElementById('detailsBand'));
            const edge = getComputedStyle(document.getElementById('details')).borderTopColor;
            return [...document.querySelectorAll('#details .exports-col h2')].map((h) => {
              const s = getComputedStyle(h), name = getComputedStyle(h.querySelector('.name') || h);
              return [h.textContent, s.backgroundColor === band.backgroundColor, s.borderTopWidth, s.borderTopColor === edge,
                      name.textTransform, name.fontSize];
            });
        }""")
        assert heads == [["Report", True, "3px", True, "uppercase", "11px"],
                         ["Exports", True, "3px", True, "uppercase", "11px"]]
        # One rule under the Exports band: the band's own, not the first card's beside it
        first = "getComputedStyle(document.querySelector('#details .exports-col .export-card')).borderTopWidth"
        assert p.evaluate(first) == "0px"
        gap = p.evaluate("""() => {
            const buttons = document.querySelector('#details .exports-col button.primary').closest('.actions');
            const exports = document.querySelectorAll('#details .exports-col h2')[1];
            return exports.getBoundingClientRect().top - buttons.getBoundingClientRect().bottom;
        }""")
        assert gap >= 24


def test_the_summary_is_saved_previewed_and_the_report_written(browser, synthetic_case):  # noqa: F811
    """The right column: the report's seven sections with what each holds; the Summary saved as the case_setting
    report_summary and worded on the status line; Preview showing the text with no file and no entry; Write report, the
    page's one lead button, writing the file with its entry and the head after it; and Written from this case listing the
    file with its rows and its SHA-256 short, the whole in the hover."""
    found = {}

    def marks(app):
        found["rdp"] = uid_at(app, T0)
        api_mark(app, {"uids": [found["rdp"]], "value": "malicious"})

    for p in served_page(browser, synthetic_case, setup=marks):
        open_findings(p)
        col = p.locator("#details .exports-col")
        assert col.locator("h2").all_text_contents() == ["Report", "Exports"]   # shown in caps
        outline = col.locator(".report-outline li")
        assert outline.count() == 7 and outline.all_inner_texts()[0] == "Summary, empty: the report says so"
        assert outline.all_inner_texts()[2].startswith("Timeline of marked events, 1 event marked Malicious or Suspicious")
        assert outline.all_inner_texts()[3] == "Indicators, 2 values from 1 Malicious mark"
        write = col.get_by_role("button", name="Write report (Markdown)")
        assert "primary" in write.get_attribute("class") and p.locator("#details button.primary").count() == 1
        col.get_by_label("Summary").fill("The attacker came in over RDP from the internet.")
        col.get_by_role("button", name="Save summary").click()
        p.wait_for_function("() => document.getElementById('status').textContent.startsWith('Saved the report summary')")
        entry = entries(synthetic_case)[-1]
        assert (entry["action"], entry["name"], entry["value"]) == ("case_setting", "report_summary",
                                                                     "The attacker came in over RDP from the internet.")
        assert outline.all_inner_texts()[0] == "Summary, written: 9 words"
        # Preview: the text in the page, nothing written or journaled
        before, files = len(entries(synthetic_case)), sorted((synthetic_case.folder / "exports").glob("*"))
        col.get_by_role("button", name="Preview").click()
        preview = col.locator(".report-preview")
        preview.wait_for(state="visible")
        text = preview.inner_text()
        assert text.startswith("# Report: Synthetic")
        assert "## 1. Summary\n\nThe attacker came in over RDP from the internet." in text
        assert "## 7. Method" in text and "not for a preview" in text
        assert len(entries(synthetic_case)) == before and sorted((synthetic_case.folder / "exports").glob("*")) == files
        # Write report: the file, its entry, the head after it, and the Written from this case row
        write.click()
        result = wrote(p, "Wrote the report (1 marked event) to ")
        assert "Journal head after recording this file: " in result
        assert "Record it with the file to check the file later." in result
        entry = entries(synthetic_case)[-1]
        assert (entry["action"], entry["kind"], entry["rows"]) == ("file_written", "report", 1)
        assert "The attacker came in over RDP" in (synthetic_case.folder / entry["path"]).read_text(encoding="utf-8")
        row = col.locator(".files-table tbody tr").first
        row.wait_for()
        cells = row.locator("td").all_inner_texts()
        short = f"{entry['sha256'][:8]}...{entry['sha256'][-4:]}"
        assert cells == [str(entry["at"])[11:19], Path(entry["path"]).name, "1", short]
        assert row.locator(".file-hash").get_attribute("title") == entry["sha256"]
        assert row.locator("td").nth(1).get_attribute("title") == f"{entry['path']}: report, whole case, 1 event"
        assert col.locator(".written-note").inner_text() == WRITTEN_NOTE
        assert p.locator("#caseState").inner_text().startswith("Open · ")   # the header's line was read again after the re-hash


def test_the_exports_state_their_scope_and_write_their_files(browser, synthetic_case):  # noqa: F811
    """Each card names its scope and contents before the click: Marked events the whole case, Events in the window
    the window shown with the events in it, Indicators the Malicious marks, Audit trail the whole journal. Each click
    writes the file and its entry, says what it wrote, and the files table lists them newest first."""
    def marks(app):
        api_mark(app, {"uids": [uid_at(app, T0)], "value": "malicious"})
        api_mark(app, {"uids": [uid_at(app, T0 + 60 * SEC)], "value": "suspicious"})

    for p in served_page(browser, synthetic_case, setup=marks):
        whole = view(p)
        open_findings(p)
        col = p.locator("#details .exports-col")
        cards = col.locator(".export-card")
        assert cards.locator("b").all_inner_texts() == ["Marked events", "Events in the window", "Indicators", "Audit trail"]
        assert cards.locator(".chip.scope").all_inner_texts()[::2] == ["whole case", "Malicious marks"]
        assert cards.locator(".chip.scope").all_inner_texts()[3] == "whole journal"
        marked, window, indicators, audit = (cards.nth(i) for i in range(4))
        assert marked.locator(".ex-count").inner_text() == "2 marked events, 2 of them Malicious or Suspicious"
        # Each CSV card says a spreadsheet gets a tab in front of a formula, and the timeline cards what JSONL keeps
        cells = "a tab goes in front of any text a spreadsheet would run as a formula"
        for timeline in (marked, window):
            assert timeline.locator(".export-what").inner_text().endswith(
                f" · in CSV, {cells}; JSONL keeps values as written")
        assert ("a network record's signature, community ID, URL, DNS and TLS names, and a DHCP client's MAC address · "
                "each event's mark") in marked.inner_text()
        assert indicators.locator(".export-what").inner_text().endswith(f" · read from parsed fields only · {cells}")
        assert "formula" not in audit.inner_text()
        marked.get_by_role("button", name="CSV").click()
        result = wrote(p, "Wrote 2 events to ")
        assert ". Whole case. Journal head after recording this file: " in result
        entry = entries(synthetic_case)[-1]
        assert entry["scope"] == {"marks": "marked"} and Path(entry["path"]).name.startswith("marked_events_")
        # The window card names the window shown and counts its events, as the state line does
        assert window.locator("#exportWindow").inner_text() == window_text(int(whole["start"]), int(whole["end"]))
        p.wait_for_function("() => /^\\d/.test(document.getElementById('exportWindowCount').textContent)")
        assert window.locator("#exportWindowCount").inner_text().endswith(" under the current Sources and View")
        window.get_by_role("button", name="JSONL").click()
        result = wrote(p, "Wrote 12 events to ")   # the whole case on the timeline: the 8 logons and 4 registry values
        assert f". Window: {window_text(int(whole['start']), int(whole['end']))}. Journal head " in result
        entry = entries(synthetic_case)[-1]
        assert entry["scope"]["marks"] == "all" and "start" in entry["scope"] and entry["format"] == "jsonl"
        assert indicators.locator(".ex-count").inner_text().startswith("2 values from 1 Malicious mark")
        indicators.get_by_role("button", name="CSV").click()
        wrote(p, "Wrote 2 indicator values from 1 Malicious event to ")
        assert entries(synthetic_case)[-1]["kind"] == "indicators"
        assert audit.locator(".ex-count").inner_text().endswith(" entries in plain words")
        audit.get_by_role("button", name="Markdown").click()
        n = len(entries(synthetic_case))
        wrote(p, f"Wrote {n} entries to ")
        assert entries(synthetic_case)[-1]["kind"] == "audit_trail"
        rows = col.locator(".files-table tbody tr")
        p.wait_for_function("() => document.querySelectorAll('#details .files-table tbody tr').length === 4")
        names = [r.split("_")[0] for r in rows.locator("td:nth-child(2)").all_inner_texts()]
        assert names == ["audit", "indicators", "timeline", "marked"]   # newest first


def test_the_audit_trail_cuts_a_long_name_at_a_boundary_with_the_whole_in_the_hover(browser, synthetic_case):  # noqa: F811
    """The trail quotes the event an entry names, cut at a word or address boundary with "…", never inside the address,
    with the whole message and the time in its hover, the mark word apart from it, and a click that opens the event; a
    short name is whole."""
    found = {}

    def marks(app):
        found["rdp"], found["morty"] = uid_at(app, T0), uid_at(app, T0 + 60 * SEC)
        app.con.execute("UPDATE events SET message = ? WHERE event_uid = ?", [LONG, found["rdp"]])
        api_mark(app, {"uids": [found["rdp"]], "value": "malicious"})
        api_mark(app, {"uids": [found["morty"]], "value": "suspicious"})

    for p in served_page(browser, synthetic_case, setup=marks):
        case_menu(p, "auditButton")
        p.wait_for_selector("#details .audit-row .ev-name")
        rows = p.locator("#details .audit-row")
        long_row, short_row = rows.filter(has_text="Malicious").first, rows.filter(has_text="Suspicious").first
        name = long_row.locator(".ev-name")
        text = name.inner_text()
        assert text.startswith("“DC01 4624: Alert: ET EXPLOIT_KIT") and text.endswith(" …”") and len(text) <= 105
        assert "192.185.21.183:80" in text or "192.185.21" not in text
        assert long_row.inner_text().split("”")[1].strip().startswith("Malicious")   # the mark word apart from the name
        title = name.get_attribute("title")
        assert LONG in title and title.startswith("2020-09-19 03:21:48.000000 UTC\n")
        assert short_row.locator(".ev-name").inner_text() == "“DC01 4624: 4624 logon”"
        name.click()
        p.wait_for_selector("#details[data-page='event'] .ev-ident")
        assert "DC01" in p.locator("#details .ev-ident").inner_text()
        assert p.evaluate("window.__app.S.focus") == found["rdp"]


def test_each_export_card_states_the_scope_of_the_file_it_writes(browser, synthetic_case):  # noqa: F811
    """With a filter on, the window card says so and counts its events under it, and its file holds exactly that many,
    whether or not the report's Apply tick is on; the Marked events card says whole case and writes the whole case, filtered
    or not. The tick is the report's alone, and its label says so: the window file doesn't wait on a tick in another
    section, and the whole-case export doesn't take the filter the tick sends."""
    def marks(app):
        api_mark(app, {"uids": [uid_at(app, T0)], "value": "malicious"})
        api_mark(app, {"uids": [uid_at(app, T0 + 60 * SEC)], "value": "suspicious"})

    for p in served_page(browser, synthetic_case, setup=marks):
        p.locator("#filtersButton").click()
        p.locator("#fpTree").get_by_role("checkbox", name="Show DESKTOP", exact=True).uncheck()
        p.wait_for_function(
            "() => ![...document.querySelectorAll('#labels .row')].some((r) => r.textContent.includes('DESKTOP'))")
        p.locator("#filtersButton").click()
        open_findings(p)
        col = p.locator("#details .exports-col")
        assert col.locator("label[for=exportFiltered]").inner_text() == "Apply the current Sources and View (1) to the report"
        window, marked = col.locator(".export-card").nth(1), col.locator(".export-card").nth(0)
        assert window.locator(".chip.scope").inner_text().endswith(", 1 filter on")
        p.wait_for_function("() => /^\\d/.test(document.getElementById('exportWindowCount').textContent)")
        stated = int(window.locator("#exportWindowCount").inner_text().split()[0].replace(",", ""))
        assert not col.locator("#exportFiltered").is_checked()
        window.get_by_role("button", name="CSV").click()
        assert wrote(p, "Wrote ").startswith(f"Wrote {stated} events to ")
        entry = entries(synthetic_case)[-1]
        assert entry["rows"] == stated and entry["filters"] and "Hidden" in entry["filters"]["text"]
        assert Path(entry["path"]).name.startswith("timeline_all_filtered_")
        # The tick changes the report's scope and leaves both cards' as they were
        col.locator("#exportFiltered").check()
        marked.get_by_role("button", name="CSV").click()
        p.wait_for_function("() => document.querySelector('#details .export-result')?.textContent.includes('Whole case.')")
        entry = entries(synthetic_case)[-1]
        assert entry["rows"] == 2 and entry["filters"] is None and entry["scope"] == {"marks": "marked"}
        assert Path(entry["path"]).name.startswith("marked_events_") and "_filtered" not in Path(entry["path"]).name


def test_the_files_table_gives_a_seven_digit_row_count_room(browser, synthetic_case):  # noqa: F811
    """The Rows column is wide enough for "1,242,846", so a big file's count never runs into the SHA-256 beside it (at 44 px
    a six-digit count ended 2 px inside the hash)."""
    def marks(app):
        api_mark(app, {"uids": [uid_at(app, T0)], "value": "malicious"})

    for p in served_page(browser, synthetic_case, setup=marks):
        open_findings(p)
        col = p.locator("#details .exports-col")
        col.locator(".export-card").nth(2).get_by_role("button", name="CSV").click()   # Indicators: one row in the table
        p.wait_for_selector("#details .files-table tbody tr")
        fits = p.evaluate("""() => {
            const cell = document.querySelector('#details .files-table tbody td.num');
            cell.textContent = '1,242,846';
            return cell.scrollWidth <= cell.clientWidth;
        }""")
        assert fits


def test_the_window_card_names_the_filters_turned_on_while_the_page_shows(browser, synthetic_case):  # noqa: F811
    """The window export applies the filters on at the click, so the card names them as they change, as it follows the
    window: a Sources change made with the Findings page open is named on the card before the click, and the file holds
    the count the card states. The report's tick follows too, offered only while a filter is on. The card names the
    filters at the click, not those of the moment the page opened, which would name none while its file was filtered."""
    def hide_desktop(p, hide):
        p.locator("#filtersButton").click()
        box = p.locator("#fpTree").get_by_role("checkbox", name="Show DESKTOP", exact=True)
        box.uncheck() if hide else box.check()
        p.wait_for_function("(hide) => [...document.querySelectorAll('#labels .row')]"
                            ".some((r) => r.textContent.includes('DESKTOP')) !== hide", arg=hide)
        p.locator("#filtersButton").click()

    for p in served_page(browser, synthetic_case):
        open_findings(p)
        col = p.locator("#details .exports-col")
        window, tick = col.locator(".export-card").nth(1), col.locator("#exportFiltered")
        assert not window.locator(".chip.scope").inner_text().endswith(" on") and tick.is_disabled()
        hide_desktop(p, True)
        assert p.locator(FINDINGS).count() == 1   # the page stayed
        p.wait_for_function("() => /^\\d/.test(document.getElementById('exportWindowCount').textContent)")
        assert window.locator(".chip.scope").inner_text().endswith(", 1 filter on")
        assert tick.is_enabled() and col.locator("label[for=exportFiltered]").inner_text() == (
            "Apply the current Sources and View (1) to the report")
        stated = int(window.locator("#exportWindowCount").inner_text().split()[0].replace(",", ""))
        window.get_by_role("button", name="CSV").click()
        assert wrote(p, "Wrote ").startswith(f"Wrote {stated} events to ")
        assert entries(synthetic_case)[-1]["filters"]
        # And back off: the card names none, and the tick is no longer offered
        hide_desktop(p, False)
        assert not window.locator(".chip.scope").inner_text().endswith(" on") and tick.is_disabled()
        assert col.locator("label[for=exportFiltered]").inner_text() == (
            "Apply the current Sources and View to the report (none are on)")
