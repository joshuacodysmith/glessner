"""Browser tests for what the page says of evidence no check could compare: a folder intake couldn't list in the
header's line, a folder Add new evidence can't open in its status line, and the Event page's state for a file whose
checks follow a line of the check log that can't be read. They run as test_browser_smoke.py's do, on the installed
Edge, and are skipped without it."""

import json

import pytest
from conftest import DC_LOG
from test_browser_frame import dc_log_event, no_tool_scan, paint, provenance_check
from test_browser_smoke import browser, case_menu, served_page  # noqa: F401
from test_evidence_paths import shut
from test_overview import evidence_log

from glessner.intake import intake, verify

pytestmark = pytest.mark.browser


def test_the_header_line_names_a_folder_intake_could_not_list_as_a_folder(browser, synthetic_case, monkeypatch):  # noqa: F811
    """How many files a folder intake couldn't list holds is unknown, so after a full re-hash matched, the header's
    line counts it as a folder, not as a file."""
    (synthetic_case.evidence / "DC01" / "open.bin").write_bytes(b"open")
    (synthetic_case.evidence / "DC01" / "shut").mkdir()
    (synthetic_case.evidence / "DC01" / "shut" / "inner.txt").write_bytes(b"inner")
    with monkeypatch.context() as m:
        shut(m, "shut")
        intake(synthetic_case)
    assert verify(synthetic_case, reason="manual full verification") == []
    day = json.loads(synthetic_case.verification_path.read_text().splitlines()[-1])["at"][:10]
    for p in served_page(browser, synthetic_case, tab="overview", setup=no_tool_scan):
        line = p.locator("#caseState")
        assert line.inner_text() == f"Open · full re-hash matched on {day}; 1 folder unverified · analyst cody"
        assert line.locator(".warn").inner_text() == "1 folder unverified"
        assert "1 evidence file hashed at intake (SHA-256); 1 folder intake could not list." in line.get_attribute("title")


def test_the_overview_names_a_folder_intake_could_not_list_as_a_folder(browser, synthetic_case, monkeypatch):  # noqa: F811
    """The overview's Gaps list a folder intake couldn't list apart from the files it couldn't read, with the error
    that kept it from being listed, and Integrity counts it as a folder, so a full re-hash that matched is of the files
    with an intake hash."""
    (synthetic_case.evidence / "DC01" / "open.bin").write_bytes(b"open")
    (synthetic_case.evidence / "DC01" / "shut").mkdir()
    (synthetic_case.evidence / "DC01" / "shut" / "inner.txt").write_bytes(b"inner")
    with monkeypatch.context() as m:
        shut(m, "shut")
        intake(synthetic_case)
    assert verify(synthetic_case, reason="manual full verification") == []
    for p in served_page(browser, synthetic_case, tab="overview", setup=no_tool_scan):
        p.wait_for_selector("#ovRehash")
        assert p.locator("#ovUnreadable").count() == 0
        folder = p.locator("#ovGaps #ovUnlisted")
        assert folder.locator(".warn").inner_text() == "1 folder intake could not list,"
        assert folder.locator("li").all_inner_texts() == ["DC01/shut: PermissionError: [Errno 13] Access is denied"]
        assert p.locator("#ovIntegrity > .ov-integrity > span").first.inner_text() == (
            "1 evidence file hashed at intake (SHA-256); 1 folder could not be listed")
        assert p.locator("#ovRehash").inner_text().endswith(": every file with an intake hash matched")


def test_add_new_evidence_says_what_it_could_not_read(browser, synthetic_case, monkeypatch):  # noqa: F811
    """Add new evidence shows the summary's errors, as the command line prints them, so a listed folder it can't open
    isn't shown only as no new files."""
    (synthetic_case.evidence / "DC01" / "shut").mkdir()
    (synthetic_case.evidence / "DC01" / "shut" / "inner.txt").write_bytes(b"inner")
    intake(synthetic_case)
    for p in served_page(browser, synthetic_case, setup=no_tool_scan):
        case_menu(p, "importButton")
        p.wait_for_selector("#details[data-page='import']")
        shut(monkeypatch, "shut")
        p.locator("#details").get_by_role("button", name="Add new evidence").click()
        p.wait_for_function("() => document.getElementById('status').textContent.startsWith('No new files')")
        assert p.locator("#status").inner_text() == (
            "No new files in the evidence folder. Unreadable: DC01/shut: folder can't be opened, so its 1 file in the "
            "manifest can't be looked for: PermissionError: [Errno 13] Access is denied.")


def test_the_event_page_s_uncounted_state_has_the_warning_color(browser, synthetic_case):  # noqa: F811
    """The Event page's state for a file a line of the check log that can't be read may have named takes the color
    and weight of the other states that warn, such as changed."""
    evidence_log(synthetic_case)
    intake(synthetic_case)
    assert verify(synthetic_case, reason="manual full verification") == []
    with synthetic_case.verification_path.open("ab") as f:
        f.write(b"\0" * 64)
    assert verify(synthetic_case, [DC_LOG], reason="after a run") == []
    uid = dc_log_event(synthetic_case)
    for p in served_page(browser, synthetic_case, tab="overview", setup=no_tool_scan):
        check = provenance_check(p, uid)
        assert "uncounted" in check.get_attribute("class")
        uncounted, changed = check.evaluate("""(e) => {
            const twin = e.cloneNode(true);
            twin.className = 'prov-check changed';
            e.after(twin);
            const styles = [e, twin].map((n) => [getComputedStyle(n).color, getComputedStyle(n).fontWeight]);
            twin.remove();
            return styles;
        }""")
        assert (paint(uncounted[0]), uncounted[1]) == (paint(changed[0]), changed[1])
        assert paint(uncounted[0]) != paint(p.evaluate("() => getComputedStyle(document.querySelector('.prov')).color"))
