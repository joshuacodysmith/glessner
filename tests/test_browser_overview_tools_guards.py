"""The list a Case overview number opens, and the Tools page, after an action on them, in a real browser. A mark from the list,
a run started from the Tools page, and the job that finishes while the page shows draw their page again, but not over a page
the analyst asked for meanwhile, even one still loading as the action answers. They drive the installed Microsoft Edge through
Playwright, as test_browser_smoke does, and are skipped without it."""

import time

import pytest
from conftest import SEC, T0
from test_browser_findings import uid_at
from test_browser_page_guards import SHOWN, TAKEN, Held, ask_rules, asked_meanwhile, settled
from test_browser_smoke import (  # noqa: F401
    PAGE_TIMEOUT_MS,
    RECORD_REQUESTS,
    browser,
    case_menu,
    served_page,
    wait_held,
)
from test_server import fake_tool_case

from glessner.server import api_mark

pytestmark = pytest.mark.browser


def with_fake_tool(case, tmp_path):
    """The `setup` for served_page that gives the Tools page its one tool, a stand-in that runs at once and loads nothing, so
    the timeline doesn't reload when its job ends."""
    cache = fake_tool_case(case, tmp_path)
    return lambda app: setattr(app, "tool_cache", cache)


def wait_job_finished(p):
    """Wait until the server's background job has finished, whatever the page has asked of it."""
    deadline = time.monotonic() + PAGE_TIMEOUT_MS / 1000
    while not p.hub.app.job.state()["finished"]:
        if time.monotonic() > deadline:
            pytest.fail(f"The job hadn't finished after {PAGE_TIMEOUT_MS / 1000:g} s")
        p.wait_for_timeout(20)


def test_rules_asked_for_while_the_overview_list_marks_keeps_the_panel(browser, synthetic_case):  # noqa: F811
    """A mark from the list a Case overview number opens draws that list again once it is written, but not over Rules, asked
    for while the mark was out and still loading then."""
    def marked(app):
        api_mark(app, {"uids": [uid_at(app, T0), uid_at(app, T0 + 62 * SEC)], "value": "malicious"})

    for p in served_page(browser, synthetic_case, setup=marked, tab="overview"):
        p.locator("#ovProgress .ov-legend button").first.click()
        p.wait_for_selector("#details[data-page='opened'] li.rel-row")
        p.locator("#details li.rel-row input").first.check()
        mark = p.locator("#details").get_by_role("button", name="Mark 1 Suspicious")
        asked_meanwhile(p, "/api/mark", mark.click, "/api/rules", ask_rules(p), "rules")


def test_rules_asked_for_while_a_tool_run_starts_keeps_the_panel(browser, synthetic_case, tmp_path):  # noqa: F811
    """A run started from the Tools page draws that page again once the server has answered, but not over Rules, asked for
    while the request was out and still loading then."""
    for p in served_page(browser, synthetic_case, setup=with_fake_tool(synthetic_case, tmp_path)):
        case_menu(p, "toolsButton")
        p.wait_for_selector("#details[data-page='tools'] .tools-table")
        run = p.locator("#details").get_by_role("button", name="Run Fake")
        asked_meanwhile(p, "/api/run_tool", run.click, "/api/rules", ask_rules(p), "rules")


def test_rules_asked_for_while_a_tool_job_finishes_keeps_the_panel(browser, synthetic_case, tmp_path):  # noqa: F811
    """A job that finishes with nothing loaded draws the Tools page again, but not over Rules, asked for while the page's poll
    of the job was out and still loading when the poll said it had finished. The poll's request is held until Rules is asked
    for, and released once the stand-in tool has finished."""
    for p in served_page(browser, synthetic_case, setup=with_fake_tool(synthetic_case, tmp_path)):
        case_menu(p, "toolsButton")
        p.wait_for_selector("#details[data-page='tools'] .tools-table")
        p.evaluate(RECORD_REQUESTS)
        polling = Held(p, "/api/run_status")
        p.locator("#details").get_by_role("button", name="Run Fake").click()
        wait_held(p, polling.routes)
        p.wait_for_function(TAKEN, arg="/api/tools")   # the page drew again as the run started
        reading = Held(p, "/api/rules")
        ask_rules(p)()
        wait_held(p, reading.routes)
        wait_job_finished(p)
        polling.release()
        p.wait_for_function(TAKEN, arg="/api/run_status")
        settled(p, "/api/rules")
        reading.release()
        p.wait_for_function(TAKEN, arg="/api/rules")
        settled(p)
        assert p.evaluate(SHOWN) == "rules"
