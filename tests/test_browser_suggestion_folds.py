"""The Suggestions page's group folds, in a real browser: each group stays as the analyst saw it, open or folded, through
the redraw each decision makes, wherever the new order puts it, and starts over on a new page; Show all first opens the
group it lists; its arrow tells a screen reader whether the group is open and names the list it shows. They drive the
installed Microsoft Edge through Playwright, as test_browser_smoke does, and are skipped without it."""

import pytest
from conftest import SEC, T0, logon
from test_browser_investigate import INVESTIGATE, open_worklist
from test_browser_smoke import browser, served_page  # noqa: F401

from glessner.events import load
from glessner.queries import PENDING_LIMIT
from glessner.server import api_rule

pytestmark = pytest.mark.browser
EXTRA_LOG = "DC01/Windows/System32/winevt/Logs/Extra.evtx"
ZED, ANN = "C137\\zed", "C137\\ann"
# Whether the group with this key reads this count in its head
COUNT_IS = """([key, text]) => [...document.querySelectorAll('#details .sg-group')].some((g) =>
    g.querySelector('.sg-head strong').textContent === key && g.querySelector('.sg-head .muted').textContent === text)"""
# Whether the group with this key lists this many rows
LISTED_IS = """([key, n]) => [...document.querySelectorAll('#details .sg-group')].some((g) =>
    g.querySelector('.sg-head strong').textContent === key && g.querySelectorAll('.sg-events li').length === n)"""


def add_logons(case, users):
    """A network logon on DC01 by each of `users`, a second apart."""
    events = [logon(T0 + (120 + i) * SEC, 300 + i, EXTRA_LOG, user=user, ltype="3", ip="10.42.85.115")
              for i, user in enumerate(users)]
    load(case.db_path, events, host="DC01", tool="evtxecmd", tool_version="t", run_id="more",
         replaces_sources=[EXTRA_LOG], staging_dir=case.folder)
    return case


@pytest.fixture
def two_big_groups(synthetic_case):
    """28 logons by zed and 27 by ann on DC01. A rule that suggests every 4624 groups them by account as the two largest
    groups, zed's first, and with the synthetic case's own six logons more than 50 are pending, so only the first group
    opens at first."""
    return add_logons(synthetic_case, ["zed"] * 28 + ["ann"] * 27)


@pytest.fixture
def cut_group(synthetic_case):
    """Ten more logons by zed than a group lists at first, so zed's group comes first and is cut at the limit."""
    return add_logons(synthetic_case, ["zed"] * (PENDING_LIMIT + 10))


def suggest_logons(app):
    api_rule(app, {"op": "add", "text": "id: logons\nsuggest: suspicious\nwhen: {field: event_code, equals: '4624'}\n"})


def open_logons(p):
    open_worklist(p)
    p.locator(f"{INVESTIGATE} .rule[data-source='logons'] button.rule-name").click()
    p.wait_for_selector("#details[data-page='suggestions'] .sg-group")


def group(p, key):
    return p.locator("#details .sg-group").filter(has=p.locator(".sg-head strong", has_text=key))


def order(p):
    return p.locator("#details .sg-head strong").all_inner_texts()


def is_open(p, key):
    """Whether the group's list shows, checked against what its arrow says."""
    shown = group(p, key).locator(".sg-body").is_visible()
    arrow = group(p, key).locator(".sg-head .twisty")
    assert arrow.get_attribute("aria-expanded") == str(shown).lower()
    assert arrow.inner_text() == ("▾" if shown else "▸")
    return shown


def reject_first(p, key, left):
    """Reject the first pending event of the group, and wait until the page has drawn again with `left` pending in it."""
    with p.expect_response("**/api/suggestion"):
        group(p, key).locator(".sg-events li:not(.sg-decided)").first.get_by_role("button", name="Reject").click()
    p.wait_for_function(COUNT_IS, arg=[key, f"{left} pending"])


def test_each_group_keeps_its_fold_through_decisions_and_a_new_order(browser, two_big_groups):  # noqa: F811
    """The second group, opened with its arrow, stays open through two Rejects in a row, with no reopen between them.
    Rejects that drop the first group to the second's count put the second first, and both stay open. The arrow names the
    list it shows. Opened again after another page, the page draws its groups as it does at first."""
    for p in served_page(browser, two_big_groups, setup=suggest_logons):
        open_logons(p)
        assert order(p)[:2] == [ZED, ANN]
        assert is_open(p, ZED) and not is_open(p, ANN)
        arrow = group(p, ANN).locator(".sg-head .twisty")
        assert group(p, ANN).locator(f".sg-body#{arrow.get_attribute('aria-controls')}").count() == 1
        arrow.click()
        assert is_open(p, ANN)
        reject_first(p, ANN, 26)
        assert is_open(p, ANN) and is_open(p, ZED)
        reject_first(p, ANN, 25)
        assert is_open(p, ANN)
        for left in (27, 26, 25):
            reject_first(p, ZED, left)
        assert order(p)[:2] == [ANN, ZED]   # tied at 25, ann's key sorts first
        assert is_open(p, ANN) and is_open(p, ZED)
        group(p, ZED).locator(".sg-events li .sg-text").first.click()
        p.wait_for_selector("#details[data-page='event'] .ev-ident")
        p.locator("#detailsBand button.back").click()
        p.wait_for_selector("#details[data-page='suggestions'] .sg-group")
        assert is_open(p, ANN) and not is_open(p, ZED)


def test_show_all_first_opens_a_group_the_analyst_folded(browser, cut_group):  # noqa: F811
    """The first group, folded with its arrow, opens again when its Reject N confirm's Show all N first lists all of it."""
    n = PENDING_LIMIT + 10
    for p in served_page(browser, cut_group, setup=suggest_logons):
        open_logons(p)
        assert order(p)[0] == ZED and is_open(p, ZED)
        assert group(p, ZED).locator(".sg-more").count() == 1
        group(p, ZED).locator(".sg-head .twisty").click()
        assert not is_open(p, ZED)
        group(p, ZED).get_by_role("button", name=f"Reject {n}", exact=True).click()
        group(p, ZED).get_by_role("button", name=f"Show all {n} first").click()
        p.wait_for_function(LISTED_IS, arg=[ZED, n])
        assert is_open(p, ZED)
        assert group(p, ZED).locator(".sg-more").count() == 0
