"""The design language in a real browser: the controls and the focus ring in both schemes, the
dividers' grip, the Timeline's band and edges, links against buttons, the pressed and lead buttons, the broad flag, text in
the -text tokens, and tabular numerals. They drive the installed Microsoft Edge through Playwright, as test_browser_smoke
does, and are skipped without it."""

import pytest
from test_browser_frame import no_tool_scan, paint
from test_browser_pivots import COUNTED, INSTALL, pv, select, uid
from test_browser_smoke import browser, case_menu, event_point, served_page, to_timeline  # noqa: F401
from test_overview import app_with_work, overview_case  # noqa: F401
from test_pivots import RDP, pcase, pcase_events  # noqa: F401

from glessner import pivots, queries

pytestmark = pytest.mark.browser
SCHEMES = ["light", "dark"]
# A color token as the page computes it: any surface or text, color-mix included
TOKEN = """(name) => { const probe = document.createElement('i'); probe.style.color = `var(${name})`;
    document.body.append(probe); const c = getComputedStyle(probe).color; probe.remove(); return c; }"""


def token(p, name):
    return paint(p.evaluate(TOKEN, name))


def computed(p, selector, prop, pseudo=None):
    """A computed property of the first element matching the selector, as numbers when it is a color."""
    value = p.locator(selector).first.evaluate(
        "(n, [prop, pseudo]) => getComputedStyle(n, pseudo)[prop]", [prop, pseudo])
    return paint(value) if value.startswith(("rgb", "color(")) else value


def near(got, want):
    return all(abs(a - b) <= 1 for a, b in zip(got, want, strict=True))


def keyboard_focus(p, selector):
    """Focus an element as the keyboard would, so :focus-visible matches."""
    p.keyboard.press("Shift")
    p.locator(selector).focus()
    assert p.evaluate("document.activeElement.matches(':focus-visible')")


def open_event(p, code="4624", hit=True):
    uid_ = event_point(p, code, hit=hit)["uid"]
    p.evaluate("(uid) => window.__app.select(uid, false)", uid_)
    p.wait_for_selector("#details[data-page='event'] .ev-ident")
    return uid_


@pytest.mark.parametrize("scheme", SCHEMES)
def test_controls_follow_the_scheme(browser, pcase, scheme):  # noqa: F811
    """Fields take --panel and --fg and their placeholders --muted in both schemes, so Edge's own white field and gray
    placeholder (rgb 117) don't show in dark mode."""
    install = uid(pcase, INSTALL)
    for p in served_page(browser, pcase, color_scheme=scheme):
        select(p, install)
        assert p.evaluate("matchMedia('(prefers-color-scheme: dark)').matches") == (scheme == "dark")
        for selector in ("#search", "#details input.pv-seconds", "#details .mark-note"):
            assert near(computed(p, selector, "backgroundColor"), token(p, "--panel")), selector
            assert near(computed(p, selector, "color"), token(p, "--fg")), selector
            assert near(computed(p, selector, "borderTopColor"), token(p, "--line-strong")), selector
        for selector in ("#search", "#details .mark-note"):
            assert near(computed(p, selector, "color", "::placeholder"), token(p, "--muted")), selector


@pytest.mark.parametrize("scheme", SCHEMES)
def test_a_link_is_drawn_in_the_accent(browser, synthetic_case, scheme):  # noqa: F811
    """A link is --accent, visited or not: the browser's own blue, and its purple once visited, is unreadable on the dark
    panel, as on the Tools page's Download page link and the start page's links."""
    for p in served_page(browser, synthetic_case, color_scheme=scheme):
        p.evaluate("""() => { for (const v of ['link', 'visited']) {
            const a = document.createElement('a'); a.href = v === 'link' ? '/never-seen' : '/'; a.id = `probe-${v}`;
            a.textContent = v; document.getElementById('details').append(a); } }""")
        for probe in ("#probe-link", "#probe-visited"):
            assert near(computed(p, probe, "color"), token(p, "--accent")), (scheme, probe)


@pytest.mark.parametrize("scheme", SCHEMES)
def test_the_focus_ring_is_one_rule(browser, synthetic_case, scheme):  # noqa: F811
    """Both dividers, whose outline the page removes, and a Case menu item draw the one ring: solid, 2 px, --focus.
    The dividers and the menu draw it inside."""
    for p in served_page(browser, synthetic_case, color_scheme=scheme, setup=no_tool_scan):
        focus = token(p, "--focus")
        for selector in ("#divider", "#labelDivider"):
            p.locator(selector).focus()
            p.keyboard.press("Tab")
            p.keyboard.press("Shift+Tab")
            assert p.evaluate("document.activeElement.id") == selector[1:], selector
            assert p.evaluate("document.activeElement.matches(':focus-visible')")
            assert computed(p, selector, "outlineStyle") == "solid", selector
            assert computed(p, selector, "outlineWidth") == "2px", selector
            assert near(computed(p, selector, "outlineColor"), focus), selector
            assert computed(p, selector, "outlineOffset") == "-2px", selector
        p.locator("#caseMenuButton").focus()
        p.keyboard.press("ArrowDown")
        assert p.evaluate("document.activeElement.id") == "hostsButton"
        assert computed(p, "#hostsButton", "outlineStyle") == "solid"
        assert computed(p, "#hostsButton", "outlineWidth") == "2px"
        assert near(computed(p, "#hostsButton", "outlineColor"), focus)
        p.keyboard.press("Escape")
        assert computed(p, "#caseMenuButton", "outlineWidth") == "2px"
        assert computed(p, "#caseMenuButton", "outlineOffset") == "1px"


@pytest.mark.parametrize("scheme", SCHEMES)
def test_the_dividers_have_a_grip(browser, synthetic_case, scheme):  # noqa: F811
    """The Details divider carries a 44 by 6 px grip in --line-strong, --accent once it has the keyboard's focus. The
    lane labels' divider keeps its grip out of sight until it is focused, and then shows it upright, 6 by 44 px."""
    for p in served_page(browser, synthetic_case, color_scheme=scheme):
        grip = p.locator("#divider .grip")
        box = grip.bounding_box()
        assert (round(box["width"]), round(box["height"])) == (44, 6)
        assert near(computed(p, "#divider .grip", "backgroundColor"), token(p, "--line-strong"))
        assert p.locator("#labelDivider .grip").is_hidden()
        keyboard_focus(p, "#divider")
        assert near(computed(p, "#divider .grip", "backgroundColor"), token(p, "--accent"))
        keyboard_focus(p, "#labelDivider")
        upright = p.locator("#labelDivider .grip")
        assert upright.is_visible()
        box = upright.bounding_box()
        assert (round(box["width"]), round(box["height"])) == (6, 44)
        assert near(computed(p, "#labelDivider .grip", "backgroundColor"), token(p, "--accent"))


@pytest.mark.parametrize("scheme", SCHEMES)
def test_the_timeline_band_and_edges(browser, synthetic_case, scheme):  # noqa: F811
    """The toolbar is the Timeline band, named Timeline, and the Timeline panel and the Sources panel carry its 3 px
    edge. The Sources panel opens with a band that stays at its top while the panel scrolls."""
    for p in served_page(browser, synthetic_case, color_scheme=scheme):
        assert near(computed(p, "#tlToolbar", "backgroundColor"), token(p, "--band-timeline"))
        assert p.locator("#tlToolbar > :first-child").text_content() == "Timeline"
        assert near(computed(p, "#stateLine", "backgroundColor"), token(p, "--state-bg"))
        assert computed(p, "#timeline", "borderTopWidth") == "3px"
        assert near(computed(p, "#timeline", "borderTopColor"), token(p, "--band-timeline-edge"))
        p.set_viewport_size({"width": 1400, "height": 520})
        p.locator("#filtersButton").click()
        p.wait_for_selector("#filterPanel:not([hidden])")
        assert computed(p, "#filterPanel", "borderTopWidth") == "3px"
        assert near(computed(p, "#filterPanel", "borderTopColor"), token(p, "--band-timeline-edge"))
        band = p.locator("#filterPanel .band")
        assert band.locator(".name").text_content() == "Sources"
        assert band.get_by_role("button", name="Clear all").is_visible()
        assert near(computed(p, "#filterPanel .band", "backgroundColor"), token(p, "--band-timeline"))
        panel = p.locator("#filterPanel")
        assert panel.evaluate("(n) => n.scrollHeight > n.clientHeight")
        before = band.bounding_box()["y"]
        panel.evaluate("(n) => { n.scrollTop = 120; }")
        assert panel.evaluate("(n) => n.scrollTop") > 0
        assert band.bounding_box()["y"] == before
        p.locator("#filtersButton").click()
        for button, panel_id, name in (("viewButton", "viewPanel", "View filter"), ("legendButton", "legendPanel", "Legend")):
            p.locator(f"#{button}").click()
            p.wait_for_selector(f"#{panel_id}:not([hidden])")
            assert computed(p, f"#{panel_id}", "borderTopWidth") == "3px"
            assert near(computed(p, f"#{panel_id}", "borderTopColor"), token(p, "--band-timeline-edge"))
            assert p.locator(f"#{panel_id} .band .name").text_content() == name
            assert near(computed(p, f"#{panel_id} .band", "backgroundColor"), token(p, "--band-timeline"))
            p.locator(f"#{button}").click()


@pytest.mark.parametrize("scheme", SCHEMES)
def test_links_and_buttons_follow_the_rule(browser, pcase, monkeypatch, scheme):  # noqa: F811
    """Links are --accent and borderless, actions are bordered, and every row's breakdown entry is a link, not
    only the window row's. Clear all, which acts, has a --line-strong border."""
    monkeypatch.setattr(queries, "RELATED_LIMIT", 2)
    monkeypatch.setattr(pivots, "RELATED_LIMIT", 2)
    install = uid(pcase, INSTALL)
    for p in served_page(browser, pcase, color_scheme=scheme):
        select(p, install)
        p.wait_for_function("() => document.querySelector("
                            "'#details .pv[data-pivot=\"service_name\"] .pv-sources').textContent.includes('7036')")
        p.wait_for_function(COUNTED)
        links = p.locator("#details button.linklike")
        assert links.count() >= 5
        for button in links.all():
            if button.is_visible():
                assert near(paint(button.evaluate("(n) => getComputedStyle(n).color")), token(p, "--accent"))
                assert button.evaluate("(n) => getComputedStyle(n).borderTopWidth") == "0px"
        assert near(computed(p, "#details button.pv-go", "color"), token(p, "--accent"))
        window = pv(p, "window")
        window.locator("button.pv-source").first.wait_for()
        for button in window.locator("button.pv-source").all():
            assert near(paint(button.evaluate("(n) => getComputedStyle(n).color")), token(p, "--accent"))
        # Every row's breakdown entries are links: a count in blue opens a list
        service = pv(p, "service_name")
        service.locator("button.pv-source").first.wait_for()
        for button in service.locator("button.pv-source").all():
            assert near(paint(button.evaluate("(n) => getComputedStyle(n).color")), token(p, "--accent"))
        p.locator("#filtersButton").click()
        clear = p.locator("#filterPanel").get_by_role("button", name="Clear all")
        assert clear.evaluate("(n) => getComputedStyle(n).borderTopWidth") == "1px"
        assert near(paint(clear.evaluate("(n) => getComputedStyle(n).borderTopColor")), token(p, "--line-strong"))
        assert "linklike" not in (clear.get_attribute("class") or "")


@pytest.mark.parametrize("scheme", SCHEMES)
def test_pressed_and_lead_buttons(browser, synthetic_case, scheme):  # noqa: F811
    """A pressed toggle takes the --accent border and --fg text. The lead button of a pending Suspicious suggestion is
    the mark's amber fill with --on-amber text, since white on amber lacks the contrast."""
    for p in served_page(browser, synthetic_case, color_scheme=scheme):
        legend = p.locator("#legendButton")
        assert near(computed(p, "#legendButton", "borderTopColor"), token(p, "--line-strong"))
        legend.click()
        assert legend.get_attribute("aria-pressed") == "true"
        assert near(computed(p, "#legendButton", "color"), token(p, "--fg"))
        assert near(computed(p, "#legendButton", "borderTopColor"), token(p, "--accent"))
        assert near(computed(p, "#legendButton", "backgroundColor"), token(p, "--pressed-bg"))
        open_event(p)
        accept = p.locator("#details").get_by_role("button", name="Accept as Suspicious")
        assert near(paint(accept.evaluate("(n) => getComputedStyle(n).backgroundColor")), token(p, "--fill-suspicious"))
        assert near(paint(accept.evaluate("(n) => getComputedStyle(n).color")), token(p, "--on-amber"))
        reject = p.locator("#details .decision").get_by_role("button", name="Reject")
        assert near(paint(reject.evaluate("(n) => getComputedStyle(n).backgroundColor")), token(p, "--panel"))


@pytest.mark.parametrize("scheme", SCHEMES)
def test_the_broad_flag_is_readable(browser, pcase, monkeypatch, scheme):  # noqa: F811
    """The broad flag takes --suspicious-text, on either column, because amber is 3.0:1 on white."""
    monkeypatch.setattr(queries, "RELATED_LIMIT", 2)
    monkeypatch.setattr(pivots, "RELATED_LIMIT", 2)
    rdp = uid(pcase, RDP)
    for p in served_page(browser, pcase, color_scheme=scheme):
        select(p, rdp)
        flag = pv(p, "account").locator(".pv-broad")
        flag.wait_for()
        assert near(paint(flag.evaluate("(n) => getComputedStyle(n).color")), token(p, "--suspicious-text"))
        assert flag.locator("strong").inner_text() == "Broad:"
        assert flag.locator("strong").evaluate("(n) => getComputedStyle(n).fontWeight") in ("700", "bold")


# Every visible text node's color, by the element it sits in
TEXT_COLORS = """() => { const seen = new Map();
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    for (let node = walker.nextNode(); node; node = walker.nextNode()) {
        const parent = node.parentElement;
        if (!node.textContent.trim() || !parent || ['SCRIPT', 'STYLE', 'OPTION'].includes(parent.tagName)) continue;
        if (!parent.getClientRects().length || getComputedStyle(parent).visibility === 'hidden') continue;
        const color = getComputedStyle(parent).color;
        if (!seen.has(color)) seen.set(color, parent.className || parent.tagName);
    }
    return [...seen.entries()]; }"""


def no_bare_mark_text(p, where):
    bare = {name: token(p, name) for name in ("--unreviewed", "--authorized", "--suspicious", "--malicious")}
    for color, holder in p.evaluate(TEXT_COLORS):
        for name, want in bare.items():
            assert not near(paint(color), want), f"{where}: text in {name} ({holder})"
    for button in p.locator("button.linklike").all():
        if button.is_visible():
            assert near(paint(button.evaluate("(n) => getComputedStyle(n).color")), token(p, "--accent")), where


def test_no_text_in_a_bare_mark_color(browser, overview_case, tmp_path):  # noqa: F811
    """In dark mode, the pages that hold the most colored text read in the -text tokens: no visible text takes a mark
    token's color, and every link is --accent. The Tools page's warnings, the overview's badge and flags, and the rest
    take the -text tokens, not the bare ones."""
    app, _ = app_with_work(overview_case)
    app.con.close()
    for p in served_page(browser, overview_case, tab="overview", color_scheme="dark", setup=no_tool_scan):
        # No tool is installed here, so the Tools page holds only muted notes; two rows say what is missing
        def missing(route):
            body = route.fetch().json()
            body["tools"][0].update(status="missing", license="")
            body["tools"][1].update(status="blocked", missing="a runtime")
            route.fulfill(json=body)
        p.route("**/api/tools*", missing)
        p.wait_for_selector("#ovLeads .ov-lead .ov-badge")
        assert p.locator("#ovLeads .ov-badge").count() >= 1 and p.locator(".ov-table .flag").count() >= 1
        no_bare_mark_text(p, "the Case overview")
        p.locator("#tabTimeline").click()
        for item, page_name in (("toolsButton", "tools"), ("importButton", "import"), ("rulesButton", "rules"),
                                ("auditButton", "audit")):
            case_menu(p, item)
            p.wait_for_selector(f"#details[data-page='{page_name}']")
            if page_name == "tools":
                p.wait_for_selector(".tools-table .warn")
            no_bare_mark_text(p, page_name)
        p.locator("#investigateButton").click()
        p.wait_for_selector("#details[data-page='investigate']")
        p.locator("#details").get_by_role("button", name="hayabusa", exact=True).first.click()
        p.wait_for_selector("#details[data-page='suggestions']")
        no_bare_mark_text(p, "the Suggestions page")
        case_menu(p, "hostsButton")
        p.wait_for_selector("#hostsTable tbody tr")
        no_bare_mark_text(p, "the Hosts panel")
    for p in served_page(browser, None, color_scheme="dark", ready="() => window.__start && window.__start.info !== null"):
        p.wait_for_selector("#start")
        no_bare_mark_text(p, "the start page")


def test_counts_and_times_use_tabular_numerals(browser, synthetic_case):  # noqa: F811
    """Counts, offsets, and times line up in columns: list rows, the state line, and the Event page's time take tabular
    numerals."""
    for p in served_page(browser, synthetic_case):
        p.locator("#search").fill("code:4624")
        p.locator("#search").press("Enter")
        p.wait_for_selector("#details[data-page='search'] li.rel-row")
        assert computed(p, "#details .related li.rel-row", "fontVariantNumeric") == "tabular-nums"
        assert computed(p, "#stateLine", "fontVariantNumeric") == "tabular-nums"
        open_event(p)
        assert computed(p, "#details .ev-ident .time", "fontVariantNumeric") == "tabular-nums"


# ---------- The Sources, View, and Legend panels ----------

PANELS = (("filtersButton", "filterPanel"), ("viewButton", "viewPanel"), ("legendButton", "legendPanel"))
LATERAL = "tactic:TA0008"   # the tag "Lateral Movement"


def tag_one(app):
    from glessner.server import api_search, api_tag

    uid_ = api_search(app, {"q": ["code:4624"]})["events"][0]["uid"]
    api_tag(app, {"uids": [uid_], "add": [LATERAL]})


@pytest.mark.parametrize("scheme", SCHEMES)
def test_a_panel_button_shows_its_panel_is_open(browser, synthetic_case, scheme):  # noqa: F811
    """The Sources, View, and Legend buttons take the pressed look (--accent border, --pressed-bg, --fg text) and
    aria-pressed and aria-expanded while their panel is open, and lose it when it closes. Sources and View share one slot, so
    opening one releases the other. The View panel's Close button shuts it, and from the keyboard it gives the focus back to
    the View button, since the focus is otherwise lost to the page once the panel hides."""
    for p in served_page(browser, synthetic_case, color_scheme=scheme):
        for button, panel in PANELS:
            b = p.locator(f"#{button}")
            assert (b.get_attribute("aria-pressed"), b.get_attribute("aria-expanded")) == ("false", "false"), button
            assert near(computed(p, f"#{button}", "borderTopColor"), token(p, "--line-strong")), button
            b.click()
            p.wait_for_selector(f"#{panel}:not([hidden])")
            assert (b.get_attribute("aria-pressed"), b.get_attribute("aria-expanded")) == ("true", "true"), button
            assert near(computed(p, f"#{button}", "borderTopColor"), token(p, "--accent")), button
            assert near(computed(p, f"#{button}", "backgroundColor"), token(p, "--pressed-bg")), button
            assert near(computed(p, f"#{button}", "color"), token(p, "--fg")), button
            b.click()
            p.wait_for_selector(f"#{panel}", state="hidden")
            assert (b.get_attribute("aria-pressed"), b.get_attribute("aria-expanded")) == ("false", "false"), button
        # One flyout at a time: View takes the slot from Sources, and each button follows its own panel
        p.locator("#filtersButton").click()
        p.locator("#viewButton").click()
        p.wait_for_selector("#filterPanel", state="hidden")
        assert p.locator("#filtersButton").get_attribute("aria-pressed") == "false"
        assert p.locator("#viewButton").get_attribute("aria-pressed") == "true"
        # The panel's band has a Close button, beside Show all, and it closes the panel and releases the button
        band = p.locator("#viewPanel .band")
        close = band.get_by_role("button", name="Close the View filter panel")
        assert close.inner_text() == "Close" and band.get_by_role("button", name="Show all").is_visible()
        close.focus()
        p.keyboard.press("Enter")
        p.wait_for_selector("#viewPanel", state="hidden")
        assert p.locator("#viewButton").get_attribute("aria-pressed") == "false"
        assert p.locator("#viewButton").get_attribute("aria-expanded") == "false"
        assert p.evaluate("() => document.activeElement.id") == "viewButton"


def fold_state(p):
    """Each section of the View panel: its heading button's expanded state, whether its body shows, and its folded count."""
    return p.evaluate("""() => [...document.querySelectorAll('#viewPanel h3 button.fold')].map((b) => ({
        title: b.querySelector('.fold-title').textContent, expanded: b.getAttribute('aria-expanded'),
        body: !document.getElementById(b.getAttribute('aria-controls')).hidden,
        count: b.querySelector('.fold-count').hidden ? null : b.querySelector('.fold-count').textContent }))""")


def test_the_view_panels_sections_fold_and_the_folds_are_remembered(browser, synthetic_case):  # noqa: F811
    """Each section of the View panel folds from its heading and a folded one says how many of its values are on.
    Tactics and tags starts folded while none of its values is on. The folds are remembered by the browser, and a browser that
    blocks storage still keeps them from one redraw of the panel to the next."""
    for p in served_page(browser, synthetic_case, setup=tag_one):
        p.locator("#viewButton").click()
        panel = p.locator("#viewPanel")
        panel.locator("h3 button.fold").first.wait_for()
        assert fold_state(p) == [{"title": "Marks", "expanded": "true", "body": True, "count": None},
                                 {"title": "Tactics and tags", "expanded": "false", "body": False, "count": "none on"},
                                 {"title": "Values", "expanded": "true", "body": True, "count": None}]
        tag = panel.get_by_role("checkbox", name="Show events tagged Lateral Movement")
        assert not tag.is_visible()
        panel.get_by_role("button", name="Tactics and tags").click()   # open it, and tick the tag
        assert tag.is_visible()
        tag.check()
        p.wait_for_function("() => window.__app.S.data.events.length === 1")
        panel.get_by_role("button", name="Tactics and tags").click()   # fold it with a value on
        assert fold_state(p)[1] == {"title": "Tactics and tags", "expanded": "false", "body": False, "count": "1 on"}
        panel.get_by_role("button", name="Marks").click()
        assert fold_state(p)[0] == {"title": "Marks", "expanded": "false", "body": False, "count": "0 of 5 on"}
        # A redraw of the panel, by a preset, keeps the folds
        panel.get_by_role("button", name="Review", exact=True).click()
        p.wait_for_function("() => document.querySelector('#viewPanel .fold-count')?.textContent === '1 of 5 on'")
        assert [s["expanded"] for s in fold_state(p)] == ["false", "false", "true"]
        assert fold_state(p)[0]["count"] == "1 of 5 on"
        # The browser remembers them: a page of the same profile reads the saved folds, and the tag's tick (a value kept in the
        # page) is off again, so the section says none on
        p.reload()
        p.wait_for_function("() => window.__ready === true && window.__app.S.data !== null")
        to_timeline(p)
        p.locator("#viewButton").click()
        p.locator("#viewPanel h3 button.fold").first.wait_for()
        assert [(s["title"], s["expanded"]) for s in fold_state(p)] == [("Marks", "false"), ("Tactics and tags", "false"),
                                                                        ("Values", "true")]
        assert fold_state(p)[0]["count"] == "5 of 5 on" and fold_state(p)[1]["count"] == "none on"
    # Never chosen: a value on keeps Tactics and tags open; and storage that throws does not lose a fold between redraws
    for p in served_page(browser, synthetic_case, setup=tag_one):
        p.evaluate("""async () => { const { addViewValue } = await import('/js/view.js');
            await addViewValue({ tag: 'tactic:TA0008' }); }""")
        p.locator("#viewButton").click()
        p.locator("#viewPanel h3 button.fold").first.wait_for()
        assert fold_state(p)[1] == {"title": "Tactics and tags", "expanded": "true", "body": True, "count": None}
        p.evaluate("""() => { const fail = () => { throw new Error('storage blocked'); };
            Storage.prototype.getItem = fail; Storage.prototype.setItem = fail; }""")
        p.locator("#viewPanel").get_by_role("button", name="Values").click()
        assert fold_state(p)[2]["expanded"] == "false"
        p.locator("#viewPanel").get_by_role("button", name="Chain", exact=True).click()
        p.wait_for_function("() => document.querySelector('#viewPanel .fold-count')?.textContent === '2 of 5 on'")
        assert fold_state(p)[2]["expanded"] == "false"
