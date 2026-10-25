"""Layout and Start page checks in a real browser: the Start page's line after Remove from list names the folder when
two listed cases share a name, the tag picker's menu stays off the window's edge and keeps its width as its hint
changes, and the overview's stats stay inside their section, with the last action across its width. They drive the
installed Microsoft Edge through Playwright, as test_browser_smoke does, and are skipped without it."""

from types import SimpleNamespace

import pytest
from conftest import T0
from test_browser_findings import uid_at
from test_browser_frame import no_tool_scan
from test_browser_smoke import VIEWPORT, browser, page, served_page, wait_held  # noqa: F401

from glessner.case import create_case
from glessner.server import api_mark
from glessner.start import remember

pytestmark = pytest.mark.browser
START_READY = "() => window.__start && window.__start.info !== null"
EDGE_GAP = 4   # the least the menu keeps between its right edge and the window's
# The overview's stats cells, by text, that have no width or reach past either side of the stats box
CELLS_OUTSIDE = """() => { const box = document.getElementById('ovStats').getBoundingClientRect();
  return [...document.querySelectorAll('#ovStats > *')].filter((cell) => { const r = cell.getBoundingClientRect();
    return r.width < 1 || r.left < box.left - 0.5 || r.right > box.right + 0.5; }).map((cell) => cell.textContent); }"""


def listed(case_folder, name, evidence):
    """A recent-case entry for a folder that doesn't exist, which the Start page lists as not found."""
    remember(SimpleNamespace(folder=case_folder, settings=SimpleNamespace(name=name, evidence_path=str(evidence),
                                                                          tools_folder="")), 5)


def remove_from_list(p, folder, name):
    """Click Remove from list on the row whose folder ends in `folder`, wait for the status line to change, and return it."""
    before = p.locator("#status").text_content()
    row = p.locator("#start .start-case").filter(has_text=folder)
    row.get_by_role("button", name=f"Remove from list: {name}").click()
    p.wait_for_function("(before) => document.getElementById('status').textContent !== before", arg=before)
    return p.locator("#status").text_content()


def test_removing_one_of_two_cases_with_the_same_name_says_which_folder_went(browser, tmp_path, monkeypatch):  # noqa: F811
    """With gone cases of one name listed, the line after Remove from list adds the removed case's folder, so it says
    which row went. The line for a case whose folder came back names the folder too. A case whose name no other listed
    case has is named alone."""
    monkeypatch.setenv("GLESSNER_CONFIG_DIR", str(tmp_path / "config"))
    evidence = tmp_path / "evidence"
    (evidence / "DC01").mkdir(parents=True)
    (evidence / "DC01" / "notes.txt").write_text("evidence")
    for folder in ("acme-first", "acme-second", "acme-third"):
        listed(tmp_path / "cases" / folder, "Acme", evidence)
    listed(tmp_path / "cases" / "other", "Other", evidence)
    for p in served_page(browser, None, ready=START_READY):
        assert remove_from_list(p, "acme-first", "Acme") == "Removed Acme (folder acme-first) from Recent cases."
        create_case(tmp_path / "cases" / "acme-second", "Acme", evidence, "cody")   # its folder is back, so it stays listed
        assert remove_from_list(p, "acme-second", "Acme") == (
            "The folder of Acme (folder acme-second) is there again, so it stays on the list.")
        assert remove_from_list(p, "acme-third", "Acme") == "Removed Acme (folder acme-third) from Recent cases."
        assert remove_from_list(p, "other", "Other") == "Removed Other from Recent cases."


def test_removing_a_case_whose_twin_s_folder_ends_alike_names_its_whole_folder(browser, tmp_path, monkeypatch):  # noqa: F811
    """When another listed case of the same name has a folder with the same last part, as a copy on another drive does,
    the line after Remove from list names the removed case's whole folder, since its last part says nothing."""
    monkeypatch.setenv("GLESSNER_CONFIG_DIR", str(tmp_path / "config"))
    evidence = tmp_path / "evidence"
    (evidence / "DC01").mkdir(parents=True)
    first, second = tmp_path / "drive-d" / "acme", tmp_path / "drive-e" / "Acme"
    for folder in (first, second):
        listed(folder, "Acme", evidence)
    for p in served_page(browser, None, ready=START_READY):
        assert remove_from_list(p, "drive-d", "Acme") == f"Removed Acme (folder {first}) from Recent cases."


def hint_wording_changes(p):
    """Open the tag picker at a pointer 8 px from the window's right edge while the ATT&CK list is still out, and return
    the menu's box at each hint: the first wording, the one after the list comes, an ID the list revoked ("1086"), and an
    ID with matches ("T1543"), which opens the list. The list is held until the menu has been placed, so the menu is
    placed at the first hint's width. Last, the box of the menu closed and opened again at that pointer, with the list
    in from the start."""
    held = []
    p.route("**/api/attack", lambda route: held.append(route))
    uid = p.evaluate("() => window.__app.S.data.events[0].uid")
    p.evaluate("([uid, x]) => import('/js/tags.js').then((m) => m.openTagPicker([uid], x, 300))", [uid, VIEWPORT["width"] - 8])
    p.wait_for_selector("#quickMenu:not([hidden])")
    wait_held(p, held)
    seen = {"placed": p.locator("#quickMenu").bounding_box()}
    held[0].continue_()
    p.wait_for_function("() => document.querySelector('#quickMenu .attack-hint').textContent.includes('Enterprise ATT&CK')")
    seen["listed"] = p.locator("#quickMenu").bounding_box()
    box = p.locator("#quickMenu").get_by_role("combobox", name="ATT&CK technique")
    box.fill("1086")
    p.wait_for_function("() => document.querySelector('#quickMenu .attack-hint').textContent.includes('revoked')")
    seen["revoked"] = p.locator("#quickMenu").bounding_box()
    box.fill("T1543")
    p.locator("#quickMenu .attack-list [role=option]").first.wait_for()
    seen["matches"] = p.locator("#quickMenu").bounding_box()
    p.evaluate("() => import('/js/quick_menu.js').then((m) => m.closeQuickMenu())")
    p.wait_for_selector("#quickMenu", state="hidden")
    p.evaluate("([uid, x]) => import('/js/tags.js').then((m) => m.openTagPicker([uid], x, 300))", [uid, VIEWPORT["width"] - 8])
    p.wait_for_selector("#quickMenu:not([hidden])")
    p.wait_for_function("() => document.querySelector('#quickMenu .attack-hint').textContent.includes('Enterprise ATT&CK')")
    seen["reopened"] = p.locator("#quickMenu").bounding_box()
    return seen


def test_the_tag_menu_keeps_off_the_window_edge_and_its_width_as_the_hint_changes(page):  # noqa: F811
    """The tag picker opened near the right edge stays at least 4 px inside the window after the ATT&CK list comes and
    as the hint changes, and its width holds at the one it was placed with. Opened again once the list is in, it takes
    that same width."""
    seen = hint_wording_changes(page)
    width = page.evaluate("() => window.innerWidth")
    assert {k: round(b["x"] + b["width"], 1) for k, b in seen.items() if b["x"] + b["width"] > width - EDGE_GAP} == {}
    assert {round(b["width"], 1) for b in seen.values()} == {round(seen["placed"]["width"], 1)}


def test_the_finding_form_s_hint_keeps_the_width_of_its_field(page):  # noqa: F811
    """Only the tag picker's hint has a fixed width: the Findings form's hint fills its field."""
    page.locator("#tabFindings").click()
    page.wait_for_selector("#details[data-page='findings'] .findings-col")
    page.get_by_role("button", name="New finding", exact=True).click()
    form = page.locator("#details .finding-new .finding-form")
    page.wait_for_function("() => document.querySelector('#details .attack-hint').textContent.includes('Enterprise ATT&CK')")
    hint, field = form.locator(".attack-hint").bounding_box(), form.locator(".attack-field").bounding_box()
    assert hint["width"] == field["width"]


def one_mark(app):
    """The Tools page without its version checks, and one event marked Malicious, so the overview has a last action."""
    no_tool_scan(app)
    api_mark(app, {"uids": [uid_at(app, T0)], "value": "malicious"})


def test_the_overview_s_last_action_takes_the_width_of_its_section(browser, synthetic_case):  # noqa: F811
    """The overview's Your last action puts its value under the label, across the section's width, rather than in the
    value column beside the labels."""
    for p in served_page(browser, synthetic_case, tab="overview", setup=one_mark):
        value = p.locator("#ovStats > div:last-child")
        label = p.locator("#ovStats > div:nth-last-child(2)")
        assert label.inner_text() == "Your last action" and "UTC" in value.inner_text()
        v, lab, stats = value.bounding_box(), label.bounding_box(), p.locator("#ovStats").bounding_box()
        assert v["width"] > 400
        assert v["x"] == stats["x"] and v["width"] == stats["width"]
        assert v["y"] > lab["y"]   # under its label


def test_the_overview_s_stats_stay_inside_their_section_at_each_window_width(browser, synthetic_case):  # noqa: F811
    """Every label and value of the overview's stats lies inside its section, with a width, from 1400 px down to 961 px,
    the narrowest window that keeps the sections side by side, and at 800 px, where they stack. The longest label wraps
    rather than pushing the values past the section's edge."""
    for p in served_page(browser, synthetic_case, tab="overview", setup=one_mark):
        outside = {}
        for width in (1400, 1280, 1024, 961, 800):
            p.set_viewport_size({"width": width, "height": 768})
            outside[width] = p.evaluate(CELLS_OUTSIDE)
        assert {width: cells for width, cells in outside.items() if cells} == {}
