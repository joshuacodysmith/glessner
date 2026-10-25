"""A write the server has answered, when the timeline then fails to reload, in a real browser. The write counts as done:
the status line says what was written and that the timeline didn't reload, a list clears its ticks and note, and a retry
has nothing left to write. A write the server refuses still reads as failed. They drive the installed Microsoft Edge
through Playwright, as test_browser_smoke does, and are skipped without it."""

from urllib.parse import urlsplit

import pytest
from conftest import SEC, T0
from test_browser_investigate import uid_at
from test_browser_smoke import RECORD_REQUESTS, browser, case_menu, clock_page, refused_with, served_page  # noqa: F401

from glessner.audit import read_entries
from glessner.journal import JOURNAL_FILE
from glessner.server import api_rule

pytestmark = pytest.mark.browser
LANES_FAILED = "the lanes failed"
RELOAD_FAILED = f"the timeline didn't reload: {LANES_FAILED}"
HOSTS_CHANGED = f"The hosts changed, but {RELOAD_FAILED}"
LOGONS = "id: logons\nsuggest: suspicious\nwhen: {field: event_code, equals: '4624'}\n"


def refuse(p, path, message):
    """Answer each request for `path` from now on with HTTP 500 and `message`. Returns what unrefuse takes."""
    match = lambda url: urlsplit(url).path == path
    p.route(match, refused_with(message))
    return match


def unrefuse(p, match, *paths):
    """Let requests through again. The refusals were the point of the test, so they leave p.errors."""
    p.unroute(match)
    p.errors[:] = [e for e in p.errors if not any(path in e for path in paths)]


def status_naming(p, text):
    """The status line, once it holds `text`."""
    p.wait_for_function("(text) => document.getElementById('status').textContent.includes(text)", arg=text)
    return p.locator("#status").inner_text()


def journal(case, action):
    return [e for e in read_entries(case.folder / JOURNAL_FILE) if e["action"] == action]


def counted(p, button, text):
    """Wait until the count on a case button reads `text`: the counts follow a write whether or not the lanes reload."""
    p.wait_for_selector(f"#{button}:not([hidden])")
    p.wait_for_function("([id, text]) => document.getElementById(id).textContent.startsWith(text)", arg=[button, text])


def search_logons(p):
    """Search for the six 4624 events and tick them all. Returns the Details panel."""
    p.locator("#search").fill("code:4624")
    p.locator("#search").press("Enter")
    details = p.locator("#details[data-page='search']")
    details.get_by_role("button", name="Select all").click()
    return details


def test_a_mark_is_written_when_the_timeline_does_not_reload_after_it(browser, synthetic_case):  # noqa: F811
    """A mark from a list whose answer comes, and whose lanes then fail to load, says it was written and that the
    timeline didn't reload. The list clears its ticks and note and shows the new marks, and the journal holds the one
    mark. A mark the server refuses first reads as failed and keeps the ticks and note for another try."""
    for p in served_page(browser, synthetic_case):
        details = search_logons(p)
        note = details.locator(".mark-note")
        note.fill("seen twice")
        marked = refuse(p, "/api/mark", "the mark was refused")
        details.get_by_role("button", name="Mark 6 Suspicious").click()
        assert status_naming(p, "refused") == "Mark failed: the mark was refused"
        unrefuse(p, marked, "/api/mark")
        assert details.locator("li.rel-row input:checked").count() == 6 and note.input_value() == "seen twice"
        assert journal(synthetic_case, "mark") == []
        refuse(p, "/api/lanes", LANES_FAILED)
        p.evaluate(RECORD_REQUESTS)
        details.get_by_role("button", name="Mark 6 Suspicious").click()
        assert status_naming(p, LANES_FAILED) == f"Marked 6 events Suspicious; {RELOAD_FAILED}"
        counted(p, "flaggedCount", "6")
        assert p.evaluate("() => window.__asked.some((path) => path.startsWith('/api/view'))")   # the window's data followed too
        p.wait_for_function("() => document.querySelectorAll('#details li.rel-row .badge.s').length === 6")
        assert p.locator("#status").inner_text() == f"Marked 6 events Suspicious; {RELOAD_FAILED}"
        assert details.locator("li.rel-row input:checked").count() == 0 and note.input_value() == ""
        assert details.get_by_role("button", name="Mark Suspicious", exact=True).count() == 1
        (entry,) = journal(synthetic_case, "mark")
        assert len(entry["targets"]) == 6 and entry["note"] == "seen twice"
        p.errors[:] = [e for e in p.errors if "/api/lanes" not in e]


def test_an_accepted_suggestion_is_written_when_the_timeline_does_not_reload_after_it(browser, synthetic_case):  # noqa: F811
    """Accept on the Event page says what was decided and that the timeline didn't reload, and the page shows the mark.
    A decision the server refuses first reads as failed."""
    uids = {}

    def rule(app):
        api_rule(app, {"op": "add", "text": LOGONS})
        uids["logon"] = uid_at(app, T0 + 60 * SEC)

    for p in served_page(browser, synthetic_case, setup=rule):
        p.evaluate("(uid) => window.__app.select(uid, false)", uids["logon"])
        accept = p.locator("#details").get_by_role("button", name="Accept as Suspicious")
        decided = refuse(p, "/api/suggestion", "the decision was refused")
        accept.click()
        assert status_naming(p, "refused") == "Suggestion change failed: the decision was refused"
        unrefuse(p, decided, "/api/suggestion")
        refuse(p, "/api/lanes", LANES_FAILED)
        accept.click()
        assert status_naming(p, LANES_FAILED) == f"accept: 1 event (logons); {RELOAD_FAILED}"
        p.locator("#details .ev-verdict .status.suspicious").wait_for()
        counted(p, "flaggedCount", "1")
        assert p.locator("#status").inner_text() == f"accept: 1 event (logons); {RELOAD_FAILED}"
        assert len(journal(synthetic_case, "mark")) == 1
        p.errors[:] = [e for e in p.errors if "/api/lanes" not in e]


@pytest.mark.parametrize("edit", ["offset", "role"])
def test_a_host_change_is_written_when_the_timeline_does_not_reload_after_it(browser, synthetic_case, edit):  # noqa: F811
    """An offset typed in the Hosts panel, or a role confirmed there, says the hosts changed and that the timeline didn't
    reload, and the panel shows the change. A change the server refuses first reads as failed."""
    for p in served_page(browser, synthetic_case):
        case_menu(p, "hostsButton")
        row = p.locator("#hostsTable tr[data-host='DC01']")

        def change(row, offset):
            if edit == "offset":
                row.locator("input[type=number]").fill(str(offset))   # a value the box does not hold, or Enter changes nothing
                row.locator("input[type=number]").press("Enter")
            else:
                row.get_by_role("button", name="Confirm").click()

        refused = refuse(p, "/api/host", "the host change was refused")
        change(row, 1800)
        assert status_naming(p, "refused") == ("Host change failed: the host change was refused" if edit == "offset"
                                               else "Confirm failed: the host change was refused")
        unrefuse(p, refused, "/api/host")
        refuse(p, "/api/lanes", LANES_FAILED)
        change(row, 3600)
        assert status_naming(p, LANES_FAILED) == HOSTS_CHANGED
        if edit == "offset":
            assert p.evaluate("window.__app.S.meta.hosts.find((h) => h.host === 'DC01').offset_seconds") == 3600
            assert len(journal(synthetic_case, "host_offset")) == 1
        else:
            row.get_by_role("button", name="Confirm").wait_for(state="detached")
            assert len(journal(synthetic_case, "host_role")) == 1
        assert p.locator("#status").inner_text() == HOSTS_CHANGED
        p.errors[:] = [e for e in p.errors if "/api/lanes" not in e]


@pytest.mark.parametrize("view", [False, True], ids=["no View", "a View on"])
def test_a_split_kept_as_one_host_is_written_when_the_timeline_does_not_reload_after_it(browser, tmp_path, view):  # noqa: F811
    """Keep as one host, the Hosts panel's control for a host whose logs record several computers, says what was
    written and that the timeline didn't reload, and the panel shows the host as kept. A View in force registers its
    filter and reads the lanes again after the change, and that read fails too."""
    from test_splits import lab_case

    case, _ = lab_case(tmp_path)
    for p in served_page(browser, case):
        if view:
            p.evaluate("() => import('/js/view.js').then((m) => m.addViewValue({ host: 'LAB' }))")
            p.wait_for_function("() => window.__app.S.filterId !== null && !window.__app.S.windowPending")
        case_menu(p, "hostsButton")
        refuse(p, "/api/lanes", LANES_FAILED)
        p.locator("#hostSplits").get_by_role("button", name="Keep LAB as one host").click()
        assert status_naming(p, "Kept LAB") == f"Kept LAB as one host. {HOSTS_CHANGED}"
        p.locator("#hostSplits .split-kept").wait_for()
        assert [e["op"] for e in journal(case, "host_split")] == ["keep"]
        p.errors[:] = [e for e in p.errors if "/api/lanes" not in e]


def test_a_clock_alignment_is_written_when_the_timeline_does_not_reload_after_it(clock_page):  # noqa: F811
    """The Case panel's switch says the hosts changed and that the timeline didn't reload, the switch shows the
    alignment, and its halves answer clicks again. An alignment the server refuses first reads as failed."""
    p = clock_page
    refused = refuse(p, "/api/host", "the alignment was refused")
    p.locator("#clockAligned").click()
    assert status_naming(p, "refused") == "Clock alignment failed: the alignment was refused"
    unrefuse(p, refused, "/api/host")
    refuse(p, "/api/lanes", LANES_FAILED)
    p.locator("#clockAligned").click()
    assert status_naming(p, LANES_FAILED) == HOSTS_CHANGED
    p.wait_for_selector("#clockAligned[aria-pressed='true']")
    p.wait_for_selector("#clockSwitch button[aria-disabled]", state="detached")
    assert p.evaluate("window.__app.S.meta.hosts.find((h) => h.host === 'DC01').offset_seconds") == -3599.5
    assert p.locator("#status").inner_text() == HOSTS_CHANGED
    p.errors[:] = [e for e in p.errors if "/api/lanes" not in e]


def test_a_rule_is_written_when_the_timeline_does_not_reload_after_it(browser, synthetic_case):  # noqa: F811
    """Add rule on the Rules page says the rule was added and that the timeline didn't reload, and the page lists the
    rule. A rule the server refuses reads as failed, in the page."""
    for p in served_page(browser, synthetic_case):
        case_menu(p, "rulesButton")
        page = p.locator("#details[data-page='rules']")
        page.locator("textarea").fill("id: broken\nsuggest: suspicious\n")
        page.get_by_role("button", name="Add rule").click()
        page.get_by_text("rule not saved").wait_for()
        p.errors[:] = [e for e in p.errors if "/api/rule" not in e]   # that refusal was the point
        page.locator("textarea").fill(LOGONS)
        refuse(p, "/api/lanes", LANES_FAILED)
        page.get_by_role("button", name="Add rule").click()
        p.wait_for_function(f"() => document.getElementById('status').textContent.includes('{LANES_FAILED}')"
                            f" || document.getElementById('details').textContent.includes('{LANES_FAILED}')")
        assert p.locator("#status").inner_text() == f"Added the rule; {RELOAD_FAILED}"
        counted(p, "pendingCount", "6 pending")
        page.locator("table td", has_text="logons").first.wait_for()
        assert [e["id"] for e in journal(synthetic_case, "rule_add") if e["id"] == "logons"] == ["logons"]
        assert p.locator("#status").inner_text() == f"Added the rule; {RELOAD_FAILED}"
        p.errors[:] = [e for e in p.errors if "/api/lanes" not in e]
