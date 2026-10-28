"""Browser tests for the Case overview's Tool check line in Integrity: shown when a run's tool files differed from the pin,
with a tool name drawn through the page's own text, so a bidi control in it shows as a visible [U+XXXX]. They run as
test_browser_smoke.py's do, on the installed Edge, and are skipped without it."""

import pytest
from test_browser_frame import no_tool_scan
from test_browser_smoke import browser, served_page  # noqa: F401
from test_overview import CHECK_WHERE, ODD_TOOL, recorded_checks, run_record

pytestmark = pytest.mark.browser


def test_integrity_shows_the_tool_check_line_with_a_tool_name_s_bidi_control_made_visible(browser, synthetic_case, tmp_path):  # noqa: F811
    checks = recorded_checks(tmp_path / "fake_tools")
    run_record(synthetic_case, "r1", ODD_TOOL, "DC01", "ok", 5, tool_check=checks["differs"])
    run_record(synthetic_case, "r2", "evtxecmd", "DC01", "ok", 5, tool_check=checks["differs"])
    run_record(synthetic_case, "r3", "evtxecmd", "DESKTOP", "ok", 5, tool_check=checks["matches"])
    for p in served_page(browser, synthetic_case, tab="overview", setup=no_tool_scan):
        p.wait_for_selector("#ovRehash")
        line = p.locator("#ovIntegrity #ovToolCheck")
        assert line.inner_text() == ("Tool check: 2 runs used tool files that differed from the pin: "
                                     f"evil|*_[U+202E]tool and EvtxECmd. {CHECK_WHERE}")
        assert "\u202e" not in line.text_content()
        assert "warn" in line.get_attribute("class").split()


def test_integrity_has_no_tool_check_line_when_every_run_matched_or_none_was_checked(browser, synthetic_case, tmp_path):  # noqa: F811
    checks = recorded_checks(tmp_path / "fake_tools")
    run_record(synthetic_case, "r1", "evtxecmd", "DC01", "ok", 5, tool_check=checks["matches"])
    run_record(synthetic_case, "r2", "evtxecmd", "DESKTOP", "ok", 5, tool_check=checks["not pinned"])
    run_record(synthetic_case, "r3", "recmd", "DC01", "ok", 1)
    for p in served_page(browser, synthetic_case, tab="overview", setup=no_tool_scan):
        p.wait_for_selector("#ovRehash")
        assert p.locator("#ovToolCheck").count() == 0
        assert "differed from the pin" not in p.locator("#ovIntegrity").inner_text()
