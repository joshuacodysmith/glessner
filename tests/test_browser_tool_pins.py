"""The Tools page's pins in a real browser: each tool's badge, the manifest's line, the fold of pinned files, the confirm that
comes before a pin, and what a run's job says of its tool's files. They drive the installed Microsoft Edge through
Playwright, as test_browser_smoke does, and are skipped without it."""

import re

import pytest
from test_browser_smoke import (  # noqa: F401
    PAGE_TIMEOUT_MS,
    RECORD_REQUESTS,
    asked,
    browser,
    case_menu,
    refused_with,
    served_page,
    wait_held,
)
from test_server import pinning
from test_tools_manifest import pinned

from glessner.tools_manifest import manifest_file

pytestmark = pytest.mark.browser

MANIFEST_LINE = ".tools-manifest"


def pins(case, tmp_path, *, pin_both=True, edit=None):
    """The `setup` for served_page that gives the Tools page the stand-in tool and EvtxECmd in a tools folder under
    tmp_path, as test_server.pinning does. Both are pinned, or the stand-in alone with `pin_both` false, and `edit(other)`
    changes EvtxECmd's files after its pin, as the page's first hashing will find them."""
    def setup(app):
        fake, other = pinning(app, case, tmp_path)
        pinned(tmp_path, *((fake, other) if pin_both else (fake,)))
        if edit:
            edit(other)
    return setup


def many_changes(other):
    """A changed map, a missing one, and 25 added: 27 files that differ from the pin, in the folder Maps."""
    maps = other.executable.parent / "Maps"
    (maps / "a.map").write_bytes(b"a, edited\n")
    (maps / "b.map").unlink()
    for n in range(25):
        (maps / f"m{n:02d}.map").write_bytes(b"m\n")


def open_tools(p):
    case_menu(p, "toolsButton")
    p.wait_for_selector("#details[data-page='tools'] .tools-table")


def badge(p, tool_id):
    return p.locator(f"#details tr[data-tool='{tool_id}'] .pin-badge")


def test_the_tools_page_shows_each_tool_s_badge_with_its_hover_and_the_manifest_s_line(browser, synthetic_case, tmp_path):  # noqa: F811
    path = manifest_file(tmp_path / "tools")
    for p in served_page(browser, synthetic_case, setup=pins(synthetic_case, tmp_path, edit=many_changes)):
        open_tools(p)
        assert badge(p, "fake").inner_text() == "Matches pin" and "ok" in badge(p, "fake").get_attribute("class")
        assert "match your pin of" in badge(p, "fake").get_attribute("title")
        assert badge(p, "evtxecmd").inner_text() == "Differs from pin"
        assert "warn" in badge(p, "evtxecmd").get_attribute("class")
        assert "pin it again" in badge(p, "evtxecmd").get_attribute("title")
        assert badge(p, "pecmd").inner_text() == "Outside the tools folder"
        assert "Move the tool into it" in badge(p, "pecmd").get_attribute("title")
        assert p.locator("#details tr[data-tool='event_xml'] .pin-badge").count() == 0   # built in
        line = p.locator(f"#details {MANIFEST_LINE}").inner_text()
        assert line.startswith(f"Tools manifest {path}: 1 of 2 tools match their pins, 1 differs.")
        assert re.search(r"Checked at \d\d:\d\d UTC\.", line)
        assert p.get_by_role("button", name="Pin unpinned tools").count() == 0   # every tool has a pin


def test_the_fold_lists_each_pinned_file_with_its_state_and_caps_a_folder_s_files_at_20(browser, synthetic_case, tmp_path):  # noqa: F811
    for p in served_page(browser, synthetic_case, setup=pins(synthetic_case, tmp_path, edit=many_changes)):
        open_tools(p)
        fold = p.locator("#details tr.pin-fold[data-tool='evtxecmd']")
        assert fold.get_attribute("hidden") is not None
        toggle = p.locator("#details tr[data-tool='evtxecmd']").get_by_role("button", name="Pinned files")
        assert toggle.get_attribute("aria-expanded") == "false"
        toggle.click()
        assert fold.get_attribute("hidden") is None and toggle.get_attribute("aria-expanded") == "true"
        text = fold.inner_text()
        assert re.search(r"Pinned \d{4}-\d\d-\d\d \d\d:\d\d UTC by build \S+, at version 1\.5\.2\.0", text)
        top = {row.locator(".pin-path").inner_text(): row for row in fold.locator(".pin-row:not(.nested)").all()}
        assert sorted(top) == ["EvtxECmd.dll", "EvtxECmd.exe", "Maps/"]
        assert top["EvtxECmd.exe"].locator(".pin-now").inner_text() == "Matches"
        assert top["Maps/"].locator(".pin-now").inner_text().startswith("Differs: ")
        sha = top["EvtxECmd.exe"].locator(".pin-sha")
        assert re.fullmatch(r"[0-9a-f]{12}\.\.\.", sha.inner_text()) and re.fullmatch(r"[0-9a-f]{64}", sha.get_attribute("title"))
        nested = fold.locator(".pin-row.nested")
        assert nested.count() == 20
        assert nested.first.locator(".pin-path").inner_text() == "Maps/a.map"
        assert nested.first.locator(".pin-now").inner_text().startswith("Changed, now ")
        assert "Missing, possibly removed by antivirus" in fold.locator(".pin-row.nested", has_text="Maps/b.map").inner_text()
        assert fold.locator(".pin-more").inner_text() == "and 7 more"
        assert "Links: none pinned, none now." in text and "Tools manifest " in text
        assert "No run of this tool in this case." in text
        toggle.click()
        assert fold.get_attribute("hidden") is not None


def test_pin_again_asks_first_naming_the_manifest_and_what_changed_and_cancel_leaves_it(browser, synthetic_case, tmp_path):  # noqa: F811
    path = manifest_file(tmp_path / "tools")
    for p in served_page(browser, synthetic_case, setup=pins(synthetic_case, tmp_path, edit=many_changes)):
        open_tools(p)
        before = path.read_bytes()
        p.get_by_role("button", name="Pin EvtxECmd again").click()
        confirm = p.locator("#details .confirm-block[role='group']")
        text = confirm.inner_text()
        assert f"Pin EvtxECmd as it is now, in {path}? Every case that uses this tools folder compares with its pins." in text
        assert re.search(r"Since its pin of \d{4}-\d\d-\d\d: 1 changed, 1 missing, and 25 added in Maps/\.", text)
        assert "A pin records what is in the folder; it doesn't check where the files came from." in text
        assert path.read_bytes() == before   # nothing is written until the confirm
        confirm.get_by_role("button", name="Cancel").click()
        assert confirm.count() == 0 and path.read_bytes() == before
        assert badge(p, "evtxecmd").inner_text() == "Differs from pin"
        p.get_by_role("button", name="Pin EvtxECmd again").click()
        confirm.get_by_role("button", name="Pin EvtxECmd").click()
        p.wait_for_function("() => document.querySelector(\"#details tr[data-tool='evtxecmd'] .pin-badge\")"
                            ".textContent === 'Matches pin'", timeout=PAGE_TIMEOUT_MS)
        assert path.read_bytes() != before
        assert "evtxecmd" in path.read_text(encoding="utf-8")
        assert p.locator(f"#details {MANIFEST_LINE}").inner_text().startswith(f"Tools manifest {path}: 2 of 2 tools match")
        assert p.get_by_role("button", name="Pin EvtxECmd again").count() == 0


def test_a_file_changed_after_the_page_drew_makes_the_confirmed_pin_refuse_and_say_to_scan(browser, synthetic_case, tmp_path):  # noqa: F811
    path = manifest_file(tmp_path / "tools")
    holder = {}

    def edit(other):
        many_changes(other)
        holder["maps"] = other.executable.parent / "Maps"

    for p in served_page(browser, synthetic_case, setup=pins(synthetic_case, tmp_path, edit=edit)):
        open_tools(p)
        before = path.read_bytes()
        p.get_by_role("button", name="Pin EvtxECmd again").click()
        confirm = p.locator("#details .confirm-block[role='group']")
        (holder["maps"] / "a.map").write_bytes(b"changed after the page drew\n")
        confirm.get_by_role("button", name="Pin EvtxECmd").click()
        p.wait_for_function("() => document.querySelector('#status').textContent.includes('Scan again')",
                            timeout=PAGE_TIMEOUT_MS)
        assert "EvtxECmd's files changed since the page showed them. Scan again, then pin." in p.locator("#status").inner_text()
        assert path.read_bytes() == before
        assert badge(p, "evtxecmd").inner_text() == "Differs from pin"
        p.errors[:] = [e for e in p.errors if not e.endswith("/api/pin_tools")]   # that refusal was the point


def test_pin_unpinned_tools_asks_first_and_pins_each_tool_with_no_pin(browser, synthetic_case, tmp_path):  # noqa: F811
    path = manifest_file(tmp_path / "tools")
    for p in served_page(browser, synthetic_case, setup=pins(synthetic_case, tmp_path, pin_both=False)):
        open_tools(p)
        assert badge(p, "evtxecmd").inner_text() == "Not pinned"
        assert "Pin a tool after you install it" in badge(p, "evtxecmd").get_attribute("title")
        assert p.locator(f"#details {MANIFEST_LINE}").inner_text().startswith(
            f"Tools manifest {path}: 1 of 2 tools match their pins, 1 is not pinned.")
        before = path.read_bytes()
        p.get_by_role("button", name="Pin unpinned tools").click()
        confirm = p.locator("#details .confirm-block[role='group']")
        assert f"Pin EvtxECmd as it is now, in {path}?" in confirm.inner_text()
        confirm.get_by_role("button", name="Cancel").click()
        assert path.read_bytes() == before
        p.get_by_role("button", name="Pin unpinned tools").click()
        confirm.get_by_role("button", name="Pin EvtxECmd").click()
        p.wait_for_function("() => document.querySelector(\"#details tr[data-tool='evtxecmd'] .pin-badge\")"
                            ".textContent === 'Matches pin'", timeout=PAGE_TIMEOUT_MS)
        assert '"evtxecmd"' in path.read_text(encoding="utf-8")
        assert p.get_by_role("button", name="Pin unpinned tools").count() == 0


PIN_WRITE = "**/api/pin_tools"
BUTTONS = [(False, "Pin unpinned tools"), (True, "Pin EvtxECmd again")]


def pin_posts(p):
    """How many pins the page has sent since RECORD_REQUESTS ran, counted as it makes each request."""
    return asked(p, "/api/pin_tools").count("/api/pin_tools")


def pin_setup(case, tmp_path, pin_both):
    """The pins() setup with the button to test: Pin again on a tool whose maps changed, or Pin unpinned tools."""
    return pins(case, tmp_path, pin_both=pin_both, edit=many_changes if pin_both else None)


@pytest.mark.parametrize(("pin_both", "name"), BUTTONS)
def test_a_second_click_on_a_pin_button_while_its_pin_is_out_sends_nothing(browser, synthetic_case, tmp_path, pin_both, name):  # noqa: F811
    """With /api/pin_tools held, the pin button is disabled from the confirm on, and a click on it opens no second confirm
    and sends no second pin. Once the pin answers, the manifest holds the tool and the page says it matches."""
    path = manifest_file(tmp_path / "tools")
    for p in served_page(browser, synthetic_case, setup=pin_setup(synthetic_case, tmp_path, pin_both)):
        open_tools(p)
        p.evaluate(RECORD_REQUESTS)
        button = p.get_by_role("button", name=name)
        confirm = p.locator("#details .confirm-block[role='group']")
        held = []
        p.route(PIN_WRITE, lambda route: held.append(route))   # noqa: B023
        button.click()
        confirm.get_by_role("button", name="Pin EvtxECmd").click()
        wait_held(p, held)
        assert button.is_disabled()
        button.click(force=True)
        assert confirm.count() == 0 and pin_posts(p) == 1
        held[0].continue_()
        p.wait_for_function("() => document.querySelector(\"#details tr[data-tool='evtxecmd'] .pin-badge\")"
                            ".textContent === 'Matches pin'", timeout=PAGE_TIMEOUT_MS)
        p.unroute(PIN_WRITE)
        assert pin_posts(p) == 1 and '"evtxecmd"' in path.read_text(encoding="utf-8")


@pytest.mark.parametrize(("pin_both", "name"), BUTTONS)
def test_a_refused_pin_enables_its_button_again_for_another_try(browser, synthetic_case, tmp_path, pin_both, name):  # noqa: F811
    path = manifest_file(tmp_path / "tools")
    for p in served_page(browser, synthetic_case, setup=pin_setup(synthetic_case, tmp_path, pin_both)):
        open_tools(p)
        before = path.read_bytes()
        button = p.get_by_role("button", name=name)
        confirm = p.locator("#details .confirm-block[role='group']")
        p.route(PIN_WRITE, refused_with("The tools folder is read-only."))
        button.click()
        confirm.get_by_role("button", name="Pin EvtxECmd").click()
        p.wait_for_function("() => { const s = document.getElementById('status'); "
                            "return (s.title || s.textContent) === \"Didn't pin: The tools folder is read-only.\"; }")
        assert button.is_enabled() and path.read_bytes() == before
        p.unroute(PIN_WRITE)
        p.errors[:] = [e for e in p.errors if not e.endswith("/api/pin_tools")]   # that refusal was the point
        button.click()
        confirm.get_by_role("button", name="Pin EvtxECmd").click()
        p.wait_for_function("() => document.querySelector(\"#details tr[data-tool='evtxecmd'] .pin-badge\")"
                            ".textContent === 'Matches pin'", timeout=PAGE_TIMEOUT_MS)
        assert path.read_bytes() != before


@pytest.mark.parametrize(("pin_both", "name"), BUTTONS)
def test_a_scan_during_a_pin_holds_the_new_pin_button_until_the_server_answers(browser, synthetic_case, tmp_path, pin_both, name):  # noqa: F811
    """Scan again draws the page's buttons anew. With /api/pin_tools held, the button drawn by the scan is disabled, a click
    on it opens no second confirm and sends no second pin, and once the server refuses the pin it is enabled again. After a
    pin that succeeds, a button drawn by the next scan is enabled."""
    path = manifest_file(tmp_path / "tools")
    maps = []

    def edit(other):
        maps.append(other.executable.parent / "Maps")
        if pin_both:
            many_changes(other)

    for p in served_page(browser, synthetic_case, setup=pins(synthetic_case, tmp_path, pin_both=pin_both, edit=edit)):
        open_tools(p)
        before = path.read_bytes()
        p.evaluate(RECORD_REQUESTS)
        button = p.get_by_role("button", name=name)
        confirm = p.locator("#details .confirm-block[role='group']")
        held = []
        p.route(PIN_WRITE, lambda route: held.append(route))   # noqa: B023
        button.click()
        confirm.get_by_role("button", name="Pin EvtxECmd").click()
        wait_held(p, held)
        p.get_by_role("button", name="Scan again").click()
        p.wait_for_function("() => document.querySelector('#status').textContent.startsWith('Found ')", timeout=PAGE_TIMEOUT_MS)
        assert button.is_disabled()
        button.click(force=True)
        assert confirm.count() == 0 and pin_posts(p) == 1
        refused_with("The tools folder is read-only.")(held[0])
        p.wait_for_function("() => { const s = document.getElementById('status'); "
                            "return (s.title || s.textContent) === \"Didn't pin: The tools folder is read-only.\"; }")
        assert button.is_enabled() and path.read_bytes() == before
        p.unroute(PIN_WRITE)
        p.errors[:] = [e for e in p.errors if not e.endswith("/api/pin_tools")]   # that refusal was the point
        button.click()
        confirm.get_by_role("button", name="Pin EvtxECmd").click()
        p.wait_for_function("() => document.querySelector(\"#details tr[data-tool='evtxecmd'] .pin-badge\")"
                            ".textContent === 'Matches pin'", timeout=PAGE_TIMEOUT_MS)
        assert path.read_bytes() != before
        (maps[0] / "a.map").write_bytes(b"edited after the pin\n")
        p.get_by_role("button", name="Scan again").click()
        p.wait_for_function("() => document.querySelector('#status').textContent.startsWith('Found ')", timeout=PAGE_TIMEOUT_MS)
        assert p.get_by_role("button", name="Pin EvtxECmd again").is_enabled()


def test_pin_again_sits_before_the_run_button_and_the_fold_s_toggle_shows_an_arrow(browser, synthetic_case, tmp_path):  # noqa: F811
    for p in served_page(browser, synthetic_case, setup=pins(synthetic_case, tmp_path, edit=many_changes)):
        open_tools(p)
        row = p.locator("#details tr[data-tool='evtxecmd']")
        labels = [b.get_attribute("aria-label") for b in row.locator("td:last-child button").all()]
        assert labels == ["Pin EvtxECmd again", "Run EvtxECmd"]
        toggle = row.get_by_role("button", name="Pinned files")
        arrow = lambda: toggle.evaluate("(b) => getComputedStyle(b, '::after').content")   # noqa: B023
        assert "▸" in arrow()
        toggle.click()
        assert "▾" in arrow()
        toggle.click()
        assert "▸" in arrow()


@pytest.mark.parametrize(("pin_both", "name"), BUTTONS)
def test_the_pin_buttons_are_disabled_while_a_job_runs(browser, synthetic_case, tmp_path, pin_both, name):  # noqa: F811
    from glessner.toolbox import ToolJob

    def setup(app):
        pins(synthetic_case, tmp_path, pin_both=pin_both, edit=many_changes if pin_both else None)(app)
        app.job = ToolJob("Fake", 1)   # a job that hasn't finished

    for p in served_page(browser, synthetic_case, setup=setup):
        open_tools(p)
        assert p.locator("#details .tools-job").count() == 1
        assert p.get_by_role("button", name=name).is_disabled()
        assert p.get_by_role("button", name="Run Fake").is_disabled()   # as Run is


def test_a_job_whose_tool_differs_from_the_pin_says_so_in_its_step_line_and_the_ran_line(browser, synthetic_case, tmp_path):  # noqa: F811
    def setup(app):
        pins(synthetic_case, tmp_path)(app)
        fake = app.tool_cache[1]["fake"]
        (fake.executable.parent / "Maps" / "a.map").write_bytes(b"a, edited\n")

    for p in served_page(browser, synthetic_case, setup=setup):
        open_tools(p)
        assert badge(p, "fake").inner_text() == "Differs from pin"
        p.get_by_role("button", name="Run Fake").click()
        p.wait_for_selector("#details .tools-job li", timeout=PAGE_TIMEOUT_MS)
        p.wait_for_function("() => document.querySelector('#details .tools-job').textContent.includes('finished')",
                            timeout=PAGE_TIMEOUT_MS)
        assert "tools differ from the pin" in p.locator("#details .tools-job li").first.inner_text()
        p.wait_for_function("() => document.querySelector(\"#details tr[data-tool='fake']\").textContent"
                            ".includes('its tools differed from the pin')", timeout=PAGE_TIMEOUT_MS)
        assert badge(p, "fake").inner_text() == "Differs from pin"
