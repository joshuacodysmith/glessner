"""Every fold arrow in a real browser, in each place the app draws one: the same 16 px glyph at weight 400, so an arrow
in a bold label draws as wide as the rest; a target at least 24 by 24 px, except a lane label, whose row keeps the
lanes' 20 px and takes no keyboard focus; one underline on hover, under an arrow that is its own button or under the
label of a control with one, never reaching that label's arrow, with the arrow's color unchanged; and a fold state that
follows each click, in aria-expanded or in the open attribute of the details a summary heads, with the arrow pointing
right while folded and down while open. A lane label states its fold by its arrow alone. They drive the installed
Microsoft Edge through Playwright, as test_browser_smoke does, and are skipped without it."""

from collections.abc import Callable
from dataclasses import dataclass

import pytest
from conftest import T0
from test_browser_findings import finding_of_two, open_findings
from test_browser_pivots import INSTALL, select, uid
from test_browser_smoke import browser, served_page  # noqa: F401
from test_browser_suggestion_folds import ANN, group, open_logons, suggest_logons, two_big_groups  # noqa: F401
from test_browser_tags import OLD_RULE
from test_browser_tool_pins import many_changes, open_tools, pins
from test_pivots import pcase, pcase_events  # noqa: F401

from glessner.events import load

pytestmark = pytest.mark.browser
FOLDED, OPEN = "▸", "▾"
# The arrow's font and the glyph it draws: the text of the arrow's element, or the content of the pseudo-element it is
# drawn as
ARROW = """(target, [arrow, pseudo]) => {
  const node = arrow ? target.querySelector(arrow) : target;
  const style = getComputedStyle(node, pseudo);
  const text = pseudo ? style.content : node.textContent;
  return { size: style.fontSize, weight: style.fontWeight, glyph: (text.match(/[▸▾]/) || [null])[0] };
}"""
# Whether the control says its fold is open: a summary by its details' open attribute, a button by aria-expanded,
# and null for a control that says neither
EXPANDED = """(target) => target.localName === 'summary' ? target.parentElement.open
    : target.hasAttribute('aria-expanded') ? target.getAttribute('aria-expanded') === 'true' : null"""
# Whether the control's label is underlined, whether an underline reaches its arrow, and the arrow's color. An
# underline reaches the arrow from the arrow's own style or from an ancestor's, through each box between them, and
# stops at an inline-block or other atomic inline and at a box out of the flow, which a decoration does not pass into.
UNDERLINES = """(target, [arrow, pseudo, label]) => {
  const node = arrow ? target.querySelector(arrow) : target;
  const underlined = (style) => style.textDecorationLine.includes('underline');
  const closed = (style) => style.display.startsWith('inline-') || ['absolute', 'fixed'].includes(style.position)
    || style.cssFloat !== 'none';
  const styles = pseudo ? [getComputedStyle(node, pseudo)] : [];
  for (let n = node; n; n = n.parentElement) styles.push(getComputedStyle(n));
  let reached = false;
  for (const style of styles) {
    if (underlined(style)) { reached = true; break; }
    if (closed(style)) break;
  }
  return { label: underlined(getComputedStyle(label ? target.querySelector(label) : target)), arrow: reached,
           color: getComputedStyle(node, pseudo).color };
}"""


@dataclass(frozen=True)
class Place:
    """A place the app draws a fold arrow. `case` names the fixture that makes its case, and `setup(case, tmp_path,
    found)`, when given, prepares the case before it is served and returns served_page's setup or None.
    `find(p, found)` opens the page and returns the control a click folds or opens, with its arrow folded.
    `arrow` is the arrow's element inside that control, when it is not the control itself, and `pseudo` the
    pseudo-element the arrow is drawn as. An arrow with neither is its own button. `label` is the element inside the
    control that hover underlines, when it is not the control itself. `lane` marks the lane labels: served folded to
    their first level, with the lanes' row height and no stated fold."""
    case: str
    find: Callable
    arrow: str | None = None
    pseudo: str | None = None
    label: str | None = None
    setup: Callable | None = None
    lane: bool = False


def first_evtxecmd_event(case, tmp_path, found):
    """The setup that keeps the ID of the case's EvtxECmd event at T0 in found["uid"]."""
    def setup(app):
        found["uid"] = app.con.execute("SELECT event_uid FROM events WHERE tool = 'evtxecmd' AND ts_us = ?",
                                       [T0]).fetchone()[0]
    return setup


def with_old_rule(case, tmp_path, found):
    """A Hayabusa hit with ATT&CK tags on the EvtxECmd event at T0, so its page offers suggested tags."""
    load(case.db_path, [OLD_RULE], host="DC01", tool="hayabusa", tool_version="t", run_id="r6",
         replaces_sources=[], staging_dir=case.folder)
    return first_evtxecmd_event(case, tmp_path, found)


def open_event(p, found):
    p.evaluate("(uid) => window.__app.select(uid, false)", found["uid"])
    p.wait_for_selector("#details[data-page='event'] .ev-facts")


def suggestions(p, found):
    open_logons(p)
    return group(p, ANN).locator(".sg-head button.twisty")


def sources(p, found):
    p.locator("#filtersButton").click()
    row = p.locator("#fpTree .frow:has(> button.tw)").first
    return p.locator(f"#fpTree .frow[data-node='{row.get_attribute('data-node')}'] > button.tw")


def service_install(case, tmp_path, found):
    """Keeps the ID of the case's service install in found["uid"], read before the server opens the database, and
    returns no setup."""
    found["uid"] = uid(case, INSTALL)


def pivots(p, found):
    select(p, found["uid"])
    p.locator("#details .pv-h input[type=checkbox]").uncheck()
    return p.locator("#details .pv").first.locator("button.pv-tw")


def view(p, found):
    p.locator("#viewButton").click()
    return p.locator("#viewPanel h3 button.fold", has_text="Tactics and tags")


def lanes(p, found):
    folded = p.locator("#labels .row.group").filter(has=p.locator(".twisty", has_text=FOLDED)).first
    return p.locator(f"#labels .row.group[data-row='{folded.get_attribute('data-row')}']")


def suggested_tags(p, found):
    open_event(p, found)
    return p.locator("#details .ev-verdict button.tw")


def pinned_files(p, found):
    open_tools(p)
    return p.locator("#details tr[data-tool='evtxecmd'] .pin-line button.linklike")


def event_fold(p, found):
    open_event(p, found)
    return p.locator("#details .ev-facts details.fold > summary").first


def retired_findings(p, found):
    open_findings(p)
    return p.locator("#details .retired-fold > summary")


PLACES = {
    "suggestions": Place("two_big_groups", suggestions, setup=lambda case, tmp_path, found: suggest_logons),
    "sources": Place("synthetic_case", sources),
    "pivots": Place("pcase", pivots, setup=service_install),
    "view": Place("synthetic_case", view, arrow=".fold-arrow", label=".fold-title"),
    "lanes": Place("synthetic_case", lanes, arrow=".twisty", lane=True),
    "suggested_tags": Place("synthetic_case", suggested_tags, arrow="span[aria-hidden]", setup=with_old_rule),
    "pinned_files": Place("synthetic_case", pinned_files, pseudo="::after",
                          setup=lambda case, tmp_path, found: pins(case, tmp_path, edit=many_changes)),
    "event_folds": Place("synthetic_case", event_fold, pseudo="::before", setup=first_evtxecmd_event),
    "retired_findings": Place("synthetic_case", retired_findings, pseudo="::before",
                              setup=lambda case, tmp_path, found: finding_of_two("restore", found)),
}


def state(target, place):
    """What the control says about its fold, and the glyph its arrow draws."""
    return target.evaluate(EXPANDED), target.evaluate(ARROW, [place.arrow, place.pseudo])["glyph"]


def underlines(target, place):
    """Whether the control's label is underlined, whether an underline reaches its arrow, and the arrow's color."""
    return target.evaluate(UNDERLINES, [place.arrow, place.pseudo, place.label])


def settled(p, read, want, *args):
    """What read(*args) returns once it is want, or what it returns after two seconds."""
    for _ in range(40):
        if (got := read(*args)) == want:
            break
        p.wait_for_timeout(50)
    return got


@pytest.mark.parametrize("name", PLACES)
def test_every_fold_arrow_is_one_size_in_a_full_target_with_one_hover_and_says_whether_it_is_open(
        browser, request, tmp_path, name):  # noqa: F811
    place = PLACES[name]
    case = request.getfixturevalue(place.case)
    found = {}
    setup = place.setup(case, tmp_path, found) if place.setup else None
    for p in served_page(browser, case, setup=setup, folds=place.lane):
        target = place.find(p, found)
        arrow = target.evaluate(ARROW, [place.arrow, place.pseudo])
        assert (arrow["size"], arrow["weight"]) == ("16px", "400"), name
        if place.lane:
            assert target.evaluate("(row) => row.tabIndex") == -1, name
        else:
            box = target.bounding_box()
            assert box["width"] >= 24 and box["height"] >= 24, (name, box)
        assert state(target, place) == (None if place.lane else False, FOLDED), name
        p.mouse.move(0, 0)
        rest = underlines(target, place)
        assert (rest["label"], rest["arrow"]) == (False, False), (name, rest)
        target.hover()
        want = {"label": True, "arrow": place.arrow is None and place.pseudo is None, "color": rest["color"]}
        assert settled(p, underlines, want, target, place) == want, name
        for opened in (True, False):
            target.click()
            want = (None if place.lane else opened, OPEN if opened else FOLDED)
            assert settled(p, state, want, target, place) == want, (name, opened)
