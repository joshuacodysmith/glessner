"""The lanes folded to their first level on open, in a real browser: the folds on
open, a group opened or folded by the analyst and remembered by case and preset across a reload, Open all and Fold all, a
group that appears after the first mark, the 20 cases the key keeps, and a browser that blocks storage. They drive the
installed Microsoft Edge through Playwright, as test_browser_smoke does, and are skipped without it."""

import json

import pytest
from test_browser_smoke import browser, event_point, served_page, to_timeline  # noqa: F401

pytestmark = pytest.mark.browser
KEY = "glessner.laneFolds"
READY = "() => window.__ready === true && window.__app.S.data !== null"
MARK_ROLE_HOST = "mark,role,host"


def node_id(keys):
    """A lane node's ID as lanes.js writes it: the keys as JSON with no spaces."""
    return json.dumps(keys, separators=(",", ":"))


UNREVIEWED = node_id(["Unreviewed"])
DCS = node_id(["Unreviewed", "Domain controllers"])


def rows(p):
    """Each lane row as [twisty, label]: the twisty is ▸ folded, ▾ open, and '' for a lane."""
    return p.evaluate("() => [...document.querySelectorAll('#labels .row')]"
                      ".map((r) => [r.querySelector('.twisty').textContent, r.childNodes[1].textContent])")


def stored(p):
    return p.evaluate("(k) => JSON.parse(localStorage.getItem(k) || 'null')", KEY)


def group(p, label):
    return p.locator("#labels .row.group", has_text=label)


def shown(p, keys):
    """Whether the lane node with these keys has a row: a label other nodes share, such as a role under each mark, can't say."""
    return p.evaluate("(id) => window.__app.S.rowIndex.has(id)", node_id(keys))


def node(p, keys):
    """The row of the lane node with these keys."""
    row = p.evaluate("(id) => window.__app.S.rowIndex.get(id)", node_id(keys))
    assert row is not None, keys
    return p.locator(f"#labels .row[data-row='{row}']")


def reload(p, url=None):
    """The page again: reloaded, or opened at `url` when it can't keep its session across a reload."""
    if url is None:
        p.reload()
    else:
        p.goto(url)
    p.wait_for_function(READY)
    to_timeline(p)


def test_the_lanes_open_folded_and_the_folds_are_kept_by_case_and_preset(browser, synthetic_case):  # noqa: F811
    """On open every row is a first-level group, folded, and the button reads Open all. Opening Unreviewed shows every
    role and host under it. A deeper group folded stays folded. Both choices survive a reload, under
    glessner.laneFolds by the case's key and the preset; another preset opens folded, with its own choices."""
    for p in served_page(browser, synthetic_case, folds=True):
        first = rows(p)
        assert first and all(twisty == "▸" for twisty, _ in first), first
        assert [label for _, label in first if label == "Unreviewed"] == ["Unreviewed"]
        assert p.locator("#foldAll").inner_text() == "Open all"
        assert p.locator("#foldAll").get_attribute("title").startswith("Open all: open every lane group.")
        # The button sits in the lane labels' corner, right of UTC, and not in the toolbar, which keeps one row
        assert p.locator("#axisSpacer > span").inner_text() == "UTC" and p.locator("#axisSpacer > button#foldAll").count() == 1
        assert p.locator("#tlToolbar #foldAll").count() == 0
        corner, button = p.locator("#axisSpacer").bounding_box(), p.locator("#foldAll").bounding_box()
        assert button["x"] > corner["x"] + corner["width"] / 2 and button["height"] <= corner["height"]
        assert p.locator("#details .hint").inner_text().endswith("Click a group label to open or fold it.")
        assert stored(p) is None
        key = p.evaluate("() => window.__app.S.meta.case_key")
        group(p, "Unreviewed").click()
        opened = rows(p)
        assert ["▾", "Unreviewed"] in opened and ["▾", "Domain controllers"] in opened and ["", "DC01"] in opened
        assert p.locator("#foldAll").inner_text() == "Fold all"
        store = stored(p)
        assert store["cases"][0]["key"] == key
        assert store["cases"][0]["presets"] == {MARK_ROLE_HOST: {UNREVIEWED: True}}
        group(p, "Domain controllers").click()
        folded = rows(p)
        assert ["▸", "Domain controllers"] in folded and ["", "DC01"] not in folded and ["▾", "Unreviewed"] in folded
        assert stored(p)["cases"][0]["presets"][MARK_ROLE_HOST] == {UNREVIEWED: True, DCS: False}
        reload(p)
        assert rows(p) == folded
        # Another preset starts folded, with choices of its own; back on this one, the choices are as left
        p.locator("#groupby").select_option(label="Host > Mark")
        p.wait_for_function("() => [...document.querySelectorAll('#labels .row')]"
                            ".some((r) => r.textContent.startsWith('▸DC01'))")
        by_host = rows(p)
        assert all(twisty == "▸" for twisty, _ in by_host), by_host
        group(p, "DC01").click()
        assert ["▾", "DC01"] in rows(p)
        assert set(stored(p)["cases"][0]["presets"]) == {MARK_ROLE_HOST, "host,mark"}
        p.locator("#groupby").select_option(label="Mark > Role > Host")
        p.wait_for_function("() => [...document.querySelectorAll('#labels .row')]"
                            ".some((r) => r.textContent.startsWith('▾Unreviewed'))")
        assert rows(p) == folded


def test_open_all_and_fold_all(browser, synthetic_case):  # noqa: F811
    """Open all opens every group, a deeper one the analyst folded included, and the button then reads Fold all; Fold all
    is the default again, every first-level group folded, and clears the preset's choices."""
    for p in served_page(browser, synthetic_case, folds=True):
        button = p.locator("#foldAll")
        button.click()   # Open all
        opened = rows(p)
        assert all(twisty != "▸" for twisty, _ in opened) and ["", "DC01"] in opened, opened
        assert button.inner_text() == "Fold all"
        choices = stored(p)["cases"][0]["presets"][MARK_ROLE_HOST]
        assert set(choices.values()) == {True} and UNREVIEWED in choices and DCS not in choices
        dc01 = ["Unreviewed", "Domain controllers", "DC01"]
        node(p, dc01[:2]).click()   # a deeper fold, which Open all opens again
        assert not shown(p, dc01) and button.inner_text() == "Fold all"
        button.click()   # Fold all
        folded = rows(p)
        assert all(twisty == "▸" for twisty, _ in folded) and len(folded) == 4, folded
        assert button.inner_text() == "Open all"
        assert stored(p)["cases"][0]["presets"][MARK_ROLE_HOST] == {}
        group(p, "Unreviewed").click()
        node(p, dc01[:2]).click()
        assert not shown(p, dc01) and button.inner_text() == "Fold all"
        button.click()   # Fold all, from one group open
        assert all(twisty == "▸" for twisty, _ in rows(p))
        button.click()   # Open all again: the deeper fold is gone
        assert shown(p, dc01) and stored(p)["cases"][0]["presets"][MARK_ROLE_HOST].get(DCS) is None


def test_a_group_that_appears_after_the_first_mark_opens_folded(browser, synthetic_case):  # noqa: F811
    """Malicious has no lane until the first mark. It then appears folded, while the groups opened before stay open."""
    for p in served_page(browser, synthetic_case, folds=True):
        group(p, "Unreviewed").click()
        assert ["Malicious"] not in [[label] for _, label in rows(p)]
        rdp = event_point(p, "4624", hit=True)
        p.mouse.click(rdp["x"], rdp["y"], button="right")
        p.locator("#quickMenu").get_by_role("menuitem", name="Mark Malicious").click()
        p.wait_for_function("() => [...document.querySelectorAll('#labels .row')]"
                            ".some((r) => r.textContent.startsWith('▸Malicious'))")
        after = rows(p)
        assert ["▾", "Unreviewed"] in after and ["", "DC01"] in after
        assert stored(p)["cases"][0]["presets"][MARK_ROLE_HOST] == {UNREVIEWED: True}


def test_the_key_keeps_the_20_cases_used_last_and_works_without_storage(browser, synthetic_case):  # noqa: F811
    """Opening a case the key holds moves it to the front, a read being a use, so a case only looked at isn't the first to
    go; a choice puts a new case first and drops the 21st; a value that isn't the page's is ignored. With storage blocked,
    the folds still work in the page."""
    for p in served_page(browser, synthetic_case, folds=True):
        key = p.evaluate("() => window.__app.S.meta.case_key")
        others = [{"key": f"case-{i:02}", "presets": {MARK_ROLE_HOST: {}}} for i in range(19)]
        mine = {"key": key, "presets": {MARK_ROLE_HOST: {UNREVIEWED: True}}}
        p.evaluate("([k, v]) => localStorage.setItem(k, v)", [KEY, json.dumps({"cases": [*others, mine]})])
        reload(p)
        assert ["▾", "Unreviewed"] in rows(p)   # its choices were read
        assert [c["key"] for c in stored(p)["cases"]] == [key, *(f"case-{i:02}" for i in range(19))]   # and it moved to the front
        others = [{"key": f"case-{i:02}", "presets": {MARK_ROLE_HOST: {}}} for i in range(20)]
        p.evaluate("([k, v]) => localStorage.setItem(k, v)", [KEY, json.dumps({"cases": others})])
        reload(p)
        assert [c["key"] for c in stored(p)["cases"]] == [f"case-{i:02}" for i in range(20)]   # not held: a read adds nothing
        group(p, "Unreviewed").click()
        store = stored(p)
        assert [c["key"] for c in store["cases"]] == [key, *(f"case-{i:02}" for i in range(19))]
        p.evaluate("([k, v]) => localStorage.setItem(k, v)", [KEY, "not the page's"])
        reload(p)
        assert all(twisty == "▸" for twisty, _ in rows(p))
        group(p, "Unreviewed").click()
        assert stored(p)["cases"][0]["key"] == key
        # Storage blocked: every read and write is in try and catch
        p.add_init_script("Object.defineProperty(window, 'localStorage', { get() { throw new Error('storage blocked'); } });")
        reload(p, p.new_link())
        assert all(twisty == "▸" for twisty, _ in rows(p))
        group(p, "Unreviewed").click()
        assert ["", "DC01"] in rows(p) and p.locator("#foldAll").inner_text() == "Fold all"
        p.locator("#foldAll").click()
        assert all(twisty == "▸" for twisty, _ in rows(p))


def test_logon_links_inside_a_folded_group_are_counted_and_the_status_line_says_so(browser, synthetic_case):  # noqa: F811
    """A link whose two hosts fall in one folded group has nowhere to go and isn't drawn: with Mark > Role > Host folded,
    the links between the case's hosts vanish while Logon links stays ticked. The window count's hover counts the links
    drawn and those inside a folded group, the status line's note says to open the group, and Open all draws them and
    drops the note. The shared fixture opens every group, so this runs in the default folded state."""
    for p in served_page(browser, synthetic_case, folds=True):
        assert p.locator("#showLinks").is_checked()
        folded = p.evaluate("() => [window.__app.S.linksDrawn, window.__app.S.linksFolded]")
        assert folded[0] >= 1 and folded[1] >= 1, folded   # the outside source's link reaches another row; the hosts' don't
        note = "Logon links inside a folded group aren't drawn; open the group to see them."
        assert p.evaluate("() => window.__app.S.linkNote") == note
        assert note in p.locator("#status").inner_text()
        hover = p.locator("#stInWindow").get_attribute("title")
        assert f"{folded[0]} logon link{'s' if folded[0] > 1 else ''} drawn; " in hover
        assert hover.endswith(f"{folded[1]} logon link{'s' if folded[1] > 1 else ''} inside a folded group not drawn.")
        p.locator("#foldAll").click()
        opened = p.evaluate("() => [window.__app.S.linksDrawn, window.__app.S.linksFolded]")
        assert opened == [folded[0] + folded[1], 0], opened
        assert p.evaluate("() => window.__app.S.linkNote") == "" and note not in p.locator("#status").inner_text()
        assert p.locator("#stInWindow").get_attribute("title").endswith(f"{opened[0]} logon links drawn.")
        p.locator("#foldAll").click()   # folded again, the note is back
        assert note in p.locator("#status").inner_text()
