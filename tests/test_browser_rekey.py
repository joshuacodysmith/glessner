"""The page's side of a case format upgrade that changed event IDs, in a real browser as test_browser_smoke drives it:
the overview counts the IDs it left unplaced, an earlier ID opens the event it names after the upgrade, the trail marks
the entries read through the upgrade, and each event an unplaced ID may have meant says so."""

import pytest
from test_browser_smoke import browser, served_page, to_timeline  # noqa: F401
from test_rekey_journal import evtx_uids, new_id, rekey

from glessner.events import connect
from glessner.journal import Journal

pytestmark = pytest.mark.browser
FOCUSED = "(uid) => window.__app.S.focusEvent && window.__app.S.focusEvent.uid === uid"


def test_the_page_says_where_an_upgrade_changed_an_id_or_left_one_unplaced(browser, synthetic_case):  # noqa: F811
    x, u, v = evtx_uids(synthetic_case)
    y = new_id("y")
    journal = Journal(synthetic_case)
    journal.append("mark", targets=[x], value="malicious", note="")
    seq = rekey(synthetic_case, journal, {x: y}, unplaced={u: [u, v]})["seq"]
    for page in served_page(browser, synthetic_case, tab="overview"):
        page.wait_for_selector("#ovUnplaced")
        assert page.locator("#ovUnplaced").inner_text().startswith(
            "1 event ID the journal named before a case format upgrade could each mean more than one event")
        to_timeline(page)
        page.evaluate("(uid) => window.__app.select(uid, false)", x)   # an ID from an export made before the upgrade
        page.wait_for_function(FOCUSED, arg=y)
        assert page.evaluate("() => [window.__app.S.focus, ...window.__app.S.selected]") == [y, y]
        assert page.locator("#details .id-changed").inner_text() == (
            f"This event's ID changed at #{seq}, when the case format was upgraded; it was opened by its earlier ID, {x}.")
        page.locator("#details .history-fold summary").click()   # History is a fold, closed at first
        page.wait_for_selector("#details .ev-history .history li")
        assert f"(IDs as changed at #{seq})" in page.locator("#details .ev-history").inner_text()
        page.evaluate("(uid) => window.__app.select(uid, false)", v)
        page.wait_for_function(FOCUSED, arg=v)
        assert page.locator("#details .id-unplaced").inner_text() == (
            f"Before #{seq}, the ID {u} may have meant this event or 1 other event; the entries made under it stay on "
            "that ID. Mark this event again if they meant it.")
        assert page.locator("#details .id-changed").count() == 0


def test_the_page_says_when_an_id_is_also_an_earlier_id_of_another_event(browser, synthetic_case):  # noqa: F811
    """The event an ID names is shown, with a notice that an upgrade also moved the ID to another event, and a link
    that opens that one, whose page has no such notice. Raw fields leave the notice out. The trail by the ID says the
    same, and its link lists the other event's entries."""
    x, u, _ = evtx_uids(synthetic_case)
    y = new_id("y")
    journal = Journal(synthetic_case)
    journal.append("mark", targets=[x], value="malicious", note="")
    seq = rekey(synthetic_case, journal, {x: y})["seq"]
    con = connect(synthetic_case.db_path)
    try:
        con.execute("UPDATE events SET event_uid = ? WHERE event_uid = ?", [x, u])   # the ID x belongs to another event
    finally:
        con.close()
    for page in served_page(browser, synthetic_case, tab="overview"):
        to_timeline(page)
        page.evaluate("(uid) => window.__app.select(uid, false)", x)
        page.wait_for_function(FOCUSED, arg=x)
        notice = page.locator("#details .id-also-named")
        assert notice.inner_text().startswith(
            f"Before the case format upgrade at #{seq}, this ID named another event, which has the ID {y} now.")
        assert page.locator("#details .id-changed").count() == 0
        raw = page.locator("#details details", has=page.locator("summary", has_text="Raw fields"))
        if raw.get_attribute("open") is None:
            raw.locator("summary").click()
        assert "[object Object]" not in raw.inner_text() and "id_also_named" not in raw.inner_text()   # NOT_RAW
        notice.get_by_role("button", name="Open that event").click()
        page.wait_for_function(FOCUSED, arg=y)
        assert page.evaluate("() => [window.__app.S.focus, ...window.__app.S.selected]") == [y, y]
        assert page.locator("#details .id-also-named").count() == 0
        # The trail by the ID keeps its own entries (none) and says the same, with a way to the other event's
        page.evaluate("(uid) => window.__app.select(uid, false)", x)
        page.wait_for_function(FOCUSED, arg=x)
        page.locator("#details .history-fold summary").click()   # the button is in History, a fold
        page.locator("#details").get_by_role("button", name="Open in the audit trail").click()
        page.wait_for_function("() => document.getElementById('details').dataset.key === 'audit'")
        notice = page.locator("#details .id-also-named")
        assert notice.inner_text().startswith(
            f"Before the case format upgrade at #{seq}, this ID named another event, which has the ID {y} now; the "
            "entries made under this ID before then are listed under that one.")
        assert page.locator("#details .audit-row").count() == 0
        notice.get_by_role("button", name="Show that event's entries").click()
        page.wait_for_function("() => document.querySelectorAll('#details .audit-row').length === 1")
        assert page.locator("#details .id-also-named").count() == 0
