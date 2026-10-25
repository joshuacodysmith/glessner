"""A list's note box beside its mark buttons, in a real browser. Its placeholder is its only visible label, so it stays
short with any number of rows ticked, and the box's hover and name say how many events the note goes with. They drive
the installed Microsoft Edge through Playwright, as test_browser_smoke does, and are skipped without it."""

import re

import pytest
from conftest import SEC, T0, logon
from test_browser_details import NARROWEST_FITS, PLACEHOLDER_FITS
from test_browser_smoke import browser, served_page  # noqa: F401

from glessner.events import load

pytestmark = pytest.mark.browser
EXTRA_LOG = "DC01/Windows/System32/winevt/Logs/Extra.evtx"


@pytest.fixture
def more_logons(synthetic_case):
    """Ten more logons on DC01, so a search for code:4624 lists fourteen there."""
    events = [logon(T0 + (120 + i) * SEC, 300 + i, EXTRA_LOG, user=f"user{i}", ltype="3", ip="10.42.85.115")
              for i in range(10)]
    load(synthetic_case.db_path, events, host="DC01", tool="evtxecmd", tool_version="t", run_id="more",
         replaces_sources=[EXTRA_LOG], staging_dir=synthetic_case.folder)
    return synthetic_case


def test_a_list_note_box_with_rows_ticked_shows_its_whole_placeholder(browser, more_logons):  # noqa: F811
    """On a search's list at 1400 by 900, with matches the View hides and a find on, the row of buttons is crowded and the
    note box shrinks. With fourteen rows ticked, the box still shows its whole placeholder, as drawn and at the narrowest
    the page lets it shrink to, and its hover and name count the events the note goes with."""
    for p in served_page(browser, more_logons):
        p.evaluate("() => import('/js/view.js').then((m) => m.addViewValue({ host: 'DC01' }))")
        p.wait_for_function("() => window.__app.S.filterId !== null && !window.__app.S.windowPending")
        p.locator("#search").fill("code:4624")
        p.locator("#search").press("Enter")
        p.locator("#searchShowHidden").wait_for()
        head = p.locator("#details[data-page='search'] .sticky-head")
        head.locator(".find input").fill("DC01")
        select = head.locator("button", has_text=re.compile(r"^Select the \d+ shown$"))
        shown = int(re.search(r"\d+", select.inner_text())[0])
        assert shown >= 12
        select.click()
        head.get_by_role("button", name=f"Mark {shown} Malicious").wait_for()
        note = head.locator(".mark-note")
        assert note.evaluate(PLACEHOLDER_FITS)
        assert note.evaluate(NARROWEST_FITS)
        assert note.get_attribute("placeholder") == "Note (optional)"
        assert note.get_attribute("title") == note.get_attribute("aria-label") == f"Note for marking {shown} events (optional)"
