"""The tag picker's technique box on the ATT&CK list, in a real browser: it picks only listed techniques, a revoked ID
typed names its replacement, Hayabusa's revoked ID is suggested as its replacement, and an older tag off the list is
flagged and can be removed. They drive the installed Microsoft Edge through Playwright, as test_browser_smoke does,
and are skipped without it."""

import pytest
from conftest import DC_LOG, T0
from test_browser_smoke import browser, served_page  # noqa: F401

from glessner.events import Event, load

pytestmark = pytest.mark.browser
EVENT = "#details[data-page='event']"
OLD_RULE = Event(ts_us=T0, ts_desc="Event Recorded", artifact="hayabusa", source_file=DC_LOG, source_record="101:old",
                 record_id=101, message="Old rule [high]", log_channel="Security", rule_title="Old rule",
                 rule_level="high", extra={"MitreTactics": "LatMov", "MitreTags": "T1086 ¦ T9999"})


def test_the_tag_picker_picks_only_listed_techniques_and_an_old_tag_is_flagged(browser, synthetic_case):  # noqa: F811
    """The picker's technique box is the ATT&CK pick list, one technique at a time: typing an ID or words of a name
    lists the matches, the arrow keys move in the list (not the menu), Enter or a click tags the event, Escape closes
    the list and leaves the menu, and the event's own techniques leave the list. A revoked ID typed names its
    replacement. Hayabusa's rule tagging the revoked T1086 suggests T1059.001, its hover naming T1086, and its T9999
    suggests nothing. A tag on T9999 journaled before the list shows dashed with its flag, in the View panel too, and
    × removes it."""
    load(synthetic_case.db_path, [OLD_RULE], host="DC01", tool="hayabusa", tool_version="t", run_id="r6",
         replaces_sources=[], staging_dir=synthetic_case.folder)
    found = {}

    def setup(app):
        found["uid"] = app.con.execute("SELECT event_uid FROM events WHERE tool = 'evtxecmd' AND ts_us = ?",
                                       [T0]).fetchone()[0]
        with app.lock:   # as an old case holds it: the journal checks only the ID's form
            app.journal.append("tag", targets=[found["uid"]], add=["technique:T9999"])
            app.rewrite(tags=[found["uid"]])

    for p in served_page(browser, synthetic_case, setup=setup):
        p.evaluate("(uid) => window.__app.select(uid, false)", found["uid"])
        p.wait_for_selector(f"{EVENT} .ev-verdict")
        details = p.locator("#details")
        old = details.locator(".tagchip.off-list")
        assert old.text_content().startswith("T9999 (not in ATT&CK v20.0)")
        details.locator("button.tw").click()   # the suggestions fold, closed at first
        label = details.locator(".tagchip.suggested .label", has_text="T1059.001")
        assert label.get_attribute("title") == "Hayabusa's rule tags T1086 (revoked; now T1059.001)"
        assert [t for t in details.locator(".tagchip.suggested .label").all_text_contents()
                if t.startswith("T")] == ["T1059.001"]

        menu = p.locator("#quickMenu")
        box = menu.get_by_role("combobox", name="ATT&CK technique")
        hint = menu.locator(".attack-hint")
        options = menu.locator(".attack-list [role=option]")
        details.get_by_role("button", name="+ Tag").click()
        p.wait_for_function("() => document.querySelector('#quickMenu .attack-hint')?.textContent.includes('v20.0')")
        assert hint.text_content() == "Type an ID or a name, then pick from the list (Enterprise ATT&CK v20.0)."
        box.fill("1086")
        assert hint.text_content() == "T1086 is revoked in ATT&CK v20.0; it's now T1059.001."
        assert menu.locator(".attack-pop").is_hidden()
        box.fill("powershell")
        options.first.wait_for()
        assert [o.get_attribute("data-technique") for o in options.all()] == ["T1059.001", "T1546.013"]
        box.press("ArrowDown")   # the list's key, not the menu's: the focus stays in the box
        assert p.evaluate("() => document.activeElement.getAttribute('role')") == "combobox"
        assert options.nth(1).get_attribute("aria-selected") == "true"
        box.press("Escape")   # closes the list, and the menu stays
        assert menu.locator(".attack-pop").is_hidden() and menu.is_visible()
        box.fill("")
        box.press("ArrowDown")   # an empty box leaves the arrow keys to the menu
        assert p.evaluate("() => document.activeElement.getAttribute('aria-label')") == "Your own tag"
        box.fill("powershell")
        options.first.wait_for()
        box.press("ArrowDown")
        box.press("Enter")
        menu.wait_for(state="hidden")
        chip = details.locator(".tagchip.technique", has_text="T1546.013")
        chip.wait_for()
        assert chip.get_attribute("title").startswith("Event Triggered Execution: PowerShell Profile, tagged by ")

        details.get_by_role("button", name="+ Tag").click()   # a click picks too; the event's own leave the list
        box.fill("t1546.013")
        assert hint.text_content() == "T1546.013 is on this event already."
        box.press("End")   # in the text, not the menu's last item
        assert p.evaluate("() => document.activeElement.getAttribute('role')") == "combobox"
        box.fill("T1546.01")
        options.first.wait_for()
        assert "T1546.013" not in [o.get_attribute("data-technique") for o in options.all()]
        menu.locator(".attack-list [data-technique='T1546.011']").click()
        details.locator(".tagchip.technique", has_text="T1546.011").wait_for()

        p.locator("#viewButton").click()
        p.locator("#viewPanel").get_by_role("button", name="Tactics and tags").click()
        row = p.locator("#viewPanel .vrow", has_text="T9999")
        assert row.locator(".flag").text_content() == " (not in ATT&CK v20.0)"
        old.get_by_role("button", name="Remove the tag T9999").click()
        p.wait_for_function("() => !document.querySelector('#details .tagchip.off-list')")

        # Near the window's foot the list opens above the box, so all of it shows
        p.set_viewport_size({"width": 1400, "height": 520})
        details.get_by_role("button", name="+ Tag").click()
        box.fill("T1546")
        options.first.wait_for()
        pop = menu.locator(".attack-pop")
        assert "up" in pop.get_attribute("class") and pop.bounding_box()["y"] >= 0
        assert pop.bounding_box()["y"] + pop.bounding_box()["height"] <= box.bounding_box()["y"]
