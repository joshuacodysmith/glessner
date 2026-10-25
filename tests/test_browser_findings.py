"""The Findings page with its caveats, in a real browser: a finding made from a selection, edited, linked
from the Event page, unlinked, retired, and restored; the event chips opening their events; the caveat beside the record
and on the card; a link of more than 25 events asking first; and Show them. They drive the installed Microsoft Edge
through Playwright, as test_browser_smoke does, and are skipped without it."""

import json
from urllib.parse import urlsplit

import pytest
from conftest import DC_LOG, SEC, T0, logon
from test_browser_smoke import RECORD_REQUESTS, asked, browser, refused_with, served_page, wait_held  # noqa: F401

from glessner.events import load
from glessner.journal import JOURNAL_FILE
from glessner.server import api_finding, api_mark

pytestmark = pytest.mark.browser
FINDINGS = "#details[data-page='findings']"
EVENT = "#details[data-page='event']"
IN_FINDING = "() => document.querySelector('#details .finding-in')?.textContent.startsWith('In the finding: ')"


def entries(case):
    return [json.loads(line) for line in (case.folder / JOURNAL_FILE).read_text(encoding="utf-8").splitlines()]


def uid_at(app, ts, tool="evtxecmd"):
    return app.con.execute("SELECT event_uid FROM events WHERE tool = ? AND ts_us = ?", [tool, ts]).fetchone()[0]


def select(p, uids):
    """Select these events on the timeline, as clicks and shift-clicks would, which opens the last one's page."""
    p.evaluate("(uids) => uids.forEach((u, i) => window.__app.select(u, i > 0))", uids)
    p.wait_for_selector(f"{EVENT} .ev-verdict")


def open_findings(p):
    p.locator("#tabFindings").click()
    p.wait_for_selector(f"{FINDINGS} .findings-col")


def card(p, number):
    return p.locator(f"{FINDINGS} .finding", has_text=f"{number}. ")


def pick_technique(scope, typed, technique):
    """Type into the ATT&CK box and pick the technique with Enter, which takes the first match, the one highlighted."""
    box = scope.get_by_role("combobox", name="ATT&CK techniques")
    box.fill(typed)
    first = scope.locator(".attack-list [role=option]").first
    first.wait_for()
    assert first.get_attribute("data-technique") == technique and first.get_attribute("aria-selected") == "true"
    box.press("Enter")
    scope.locator(f".attack-chip[data-technique='{technique}']").wait_for()


def test_a_finding_is_made_from_a_selection_edited_linked_unlinked_retired_and_restored(browser, synthetic_case):  # noqa: F811
    """New finding from the selected events names its target and opens the form; the card shows the worded severity
    chip, the number and title, the narrative, the ATT&CK line, each event as a chip with its current mark, and the
    caveat of the events' type; Edit changes the fields through /api/finding; Add to a finding on the Event page links
    the event and the page says which finding it is in; Unlink takes one out; Retire asks its reason and the card folds
    away under Retired findings, from where Restore brings it back. Every change is one journal entry."""
    found = {}

    def marks(app):
        found["rdp"], found["morty"], found["dc"] = uid_at(app, T0), uid_at(app, T0 + 60 * SEC), uid_at(app, T0 + 62 * SEC)
        api_mark(app, {"uids": [found["rdp"]], "value": "malicious"})
        api_mark(app, {"uids": [found["morty"], found["dc"]], "value": "suspicious"})

    for p in served_page(browser, synthetic_case, setup=marks):
        details = p.locator("#details")
        select(p, [found["rdp"], found["morty"]])
        open_findings(p)
        assert details.locator(".findings-col h2").inner_text() == "Findings you wrote"
        assert details.locator(".exports-col h2").all_text_contents() == ["Report", "Exports"]   # shown in caps
        assert details.locator("#exportWindow").count() == 1
        assert details.locator(".unassigned b").inner_text() == "3 marked events are in no finding yet."
        assert p.evaluate("getComputedStyle(document.querySelector('.findings-page')).gridTemplateColumns").count(" ") == 1
        details.get_by_role("button", name="New finding from the 2 selected events").click()
        form = details.locator(".finding-form")
        form.get_by_label("Title").fill("RDP from the internet, then a network logon")
        form.get_by_label("Severity").select_option("High")
        pick_technique(form, "1021.001", "T1021.001")
        pick_technique(form, "valid accounts", "T1078")
        form.get_by_label("Narrative").fill("Administrator logged on over RDP from 194.61.24.102 at 03:21:48.")
        before = len(entries(synthetic_case))
        form.get_by_role("button", name="Add the finding with 2 events").click()
        one = card(p, 1)
        one.wait_for()
        assert one.locator(".chip").inner_text() == "High" and "level-high" in one.locator(".chip").get_attribute("class")
        assert one.locator(".finding-title").inner_text() == "1. RDP from the internet, then a network logon"
        assert one.locator(".finding-narr").inner_text() == "Administrator logged on over RDP from 194.61.24.102 at 03:21:48."
        line = one.locator(".finding-line").first
        assert line.inner_text().startswith("ATT&CK: T1021.001, T1078 · 2 supporting events · added ")
        chips = one.locator(".ev-chip")
        assert chips.count() == 2 and chips.locator(".badge").all_inner_texts() == ["M", "S"]
        assert chips.locator(".linklike").all_inner_texts() == ["4624 DC01 03:21:48", "4624 DC01 03:22:48"]
        assert one.locator(".finding-caveat p").get_attribute("data-caveat") == "logon"
        assert details.locator(".unassigned b").inner_text() == "1 marked event is in no finding yet."
        entry = entries(synthetic_case)[-1]
        assert len(entries(synthetic_case)) == before + 1
        assert (entry["action"], entry["op"], entry["severity"], entry["techniques"], entry["targets"]) == (
            "finding", "add", "High", ["T1021.001", "T1078"], [found["rdp"], found["morty"]])
        assert "confirmed" not in entry
        fid = entry["seq"]
        # Edit: only the fields that changed go in the entry
        one.get_by_role("button", name="Edit").click()
        one.get_by_label("Severity").select_option("Critical")
        one.get_by_label("Title").fill("RDP from the internet")
        one.get_by_role("button", name="Save changes").click()
        p.wait_for_function("() => document.querySelector('#details .finding .finding-title')?.textContent"
                            " === '1. RDP from the internet'")
        assert one.locator(".chip").inner_text() == "Critical"
        assert line.inner_text().startswith("ATT&CK: T1021.001, T1078 · 2 supporting events · edited ")
        entry = entries(synthetic_case)[-1]
        assert (entry["op"], entry["finding"], entry["title"], entry["severity"]) == (
            "edit", fid, "RDP from the internet", "Critical")
        assert "narrative" not in entry and "techniques" not in entry
        # Add to a finding, from the Event page, naming the event as Save trail does
        select(p, [found["dc"]])
        row = details.locator(".finding-add")
        assert details.locator(".finding-in").count() == 0 and row.is_hidden()   # nothing to say: the header keeps two rows
        assert details.locator(".ev-head-more").is_hidden()
        details.get_by_role("button", name="+ Finding").click()   # beside + Tag, with the target in its hover
        assert details.get_by_role("button", name="+ Finding").get_attribute("title") == "Add the 4624 on DC01 to a finding"
        pick = row.get_by_label("Finding to add to")
        p.wait_for_function("() => document.querySelector('#details .finding-add select option[value=\"new\"]') !== null")
        assert [o.inner_text() for o in pick.locator("option").all()] == [
            "Choose a finding", "1. RDP from the internet", "New finding…"]
        pick.select_option(str(fid))
        row.get_by_role("button", name="Add the 4624 on DC01").click()
        p.wait_for_function(IN_FINDING)
        assert details.locator(".finding-in button").inner_text() == "1. RDP from the internet"
        entry = entries(synthetic_case)[-1]
        assert (entry["op"], entry["finding"], entry["targets"]) == ("link", fid, [found["dc"]]) and "confirmed" not in entry
        # Unlink, in edit mode
        open_findings(p)
        one = card(p, 1)
        assert one.locator(".ev-chip").count() == 3
        assert details.locator(".unassigned b").inner_text() == "Every marked event is in a finding."
        one.get_by_role("button", name="Edit").click()
        unlinks = one.locator(".ev-chip-edit").get_by_role("button", name="Unlink")
        assert unlinks.count() == 3
        unlinks.last.click()
        p.wait_for_function("() => document.querySelectorAll('#details .finding .ev-chip').length === 2")
        entry = entries(synthetic_case)[-1]
        assert (entry["op"], entry["finding"], entry["targets"]) == ("unlink", fid, [found["dc"]])
        assert one.locator(".finding-form").count() == 1   # the edit form stays open after an Unlink
        one.get_by_role("button", name="Cancel").click()
        # Retire with its reason; the card folds away, keeps its number, and Restore brings it back
        one = card(p, 1)
        one.get_by_role("button", name="Retire").click()
        one.get_by_label("Reason").fill("Explained by the backup job.")
        one.get_by_role("button", name="Retire the finding").click()
        fold = details.locator(".retired-fold")
        fold.wait_for()
        assert fold.locator("summary").text_content() == "Retired findings (1)"
        assert details.locator(".findings-col > .finding").count() == 0
        assert details.locator(".unassigned b").inner_text() == "3 marked events are in no finding yet."
        fold.locator("summary").click()
        gone = fold.locator(".finding.retired")
        assert gone.locator(".finding-title").inner_text() == "1. RDP from the internet"
        assert gone.locator(".finding-line").first.inner_text().endswith(" by cody. Reason: Explained by the backup job.")
        assert gone.locator(".ev-chip").count() == 2 and gone.get_by_role("button", name="Edit").count() == 0
        entry = entries(synthetic_case)[-1]
        assert (entry["op"], entry["finding"], entry["reason"]) == ("retire", fid, "Explained by the backup job.")
        gone.get_by_role("button", name="Restore").click()
        p.wait_for_function("() => document.querySelectorAll('#details .findings-col > .finding').length === 1")
        assert details.locator(".retired-fold").count() == 0 and card(p, 1).locator(".chip").inner_text() == "Critical"
        assert entries(synthetic_case)[-1]["op"] == "restore"
        assert [e["action"] for e in entries(synthetic_case)[before:]] == ["finding"] * 6


def finding_write(url):
    """Whether a request is a write to /api/finding. The page's reads of the findings go to /api/findings_page."""
    return urlsplit(url).path == "/api/finding"


def two_events(found):
    """A setup that keeps the IDs of the case's first two events in found["uids"]."""
    return lambda app: found.update(uids=[uid_at(app, T0), uid_at(app, T0 + 60 * SEC)])


def finding_posts(p):
    """How many changes the page has sent to /api/finding since RECORD_REQUESTS ran, counted as it makes each request."""
    return asked(p, "/api/finding").count("/api/finding")


def adds(case):
    return [e for e in entries(case) if e["action"] == "finding" and e["op"] == "add"]


def new_finding_form(p, uids):
    """Select these events, open New finding's form over them on the Findings page, and fill its title and severity.
    Returns the form and starts recording the page's requests."""
    select(p, uids)
    open_findings(p)
    p.locator("#details").get_by_role("button", name=f"New finding from the {len(uids)} selected events").click()
    form = p.locator(f"{FINDINGS} .finding-new .finding-form")
    form.get_by_label("Title").fill("Same finding")
    form.get_by_label("Severity").select_option("High")
    p.evaluate(RECORD_REQUESTS)
    return form


def test_a_second_click_on_add_the_finding_while_its_write_is_out_adds_nothing(browser, synthetic_case):  # noqa: F811
    """With /api/finding held, Add the finding and Cancel are disabled from the click on, and a click on the disabled Add
    sends no second request. Once the write answers, the journal holds one add and the page lists one finding."""
    found = {}
    for p in served_page(browser, synthetic_case, setup=two_events(found)):
        form = new_finding_form(p, found["uids"])
        add, cancel = form.get_by_role("button", name="Add the finding with 2 events"), form.get_by_role("button", name="Cancel")
        held = []
        p.route(finding_write, lambda route: held.append(route))   # noqa: B023
        add.click()
        wait_held(p, held)
        assert add.is_disabled() and cancel.is_disabled()
        add.click(force=True)
        assert finding_posts(p) == 1
        held[0].continue_()
        card(p, 1).wait_for()
        p.unroute(finding_write)
        assert len(adds(synthetic_case)) == 1
        assert p.locator(f"{FINDINGS} .findings-col > .finding").count() == 1


def test_a_double_click_on_add_the_finding_adds_one_finding(browser, synthetic_case):  # noqa: F811
    """A double click on Add the finding, with nothing held, sends one request and journals one add."""
    found = {}
    for p in served_page(browser, synthetic_case, setup=two_events(found)):
        form = new_finding_form(p, found["uids"])
        form.get_by_role("button", name="Add the finding with 2 events").dblclick()
        card(p, 1).wait_for()
        assert finding_posts(p) == 1
        assert len(adds(synthetic_case)) == 1
        assert p.locator(f"{FINDINGS} .findings-col > .finding").count() == 1


def test_a_refused_add_leaves_the_form_open_with_add_and_cancel_enabled_for_another_try(browser, synthetic_case):  # noqa: F811
    """When /api/finding refuses the add, the status line says so, the form stays with its words, Add the finding and
    Cancel are enabled again, and the next click adds the finding once."""
    found = {}
    for p in served_page(browser, synthetic_case, setup=two_events(found)):
        form = new_finding_form(p, found["uids"])
        add, cancel = form.get_by_role("button", name="Add the finding with 2 events"), form.get_by_role("button", name="Cancel")
        p.route(finding_write, refused_with("The journal is busy."))
        add.click()
        p.wait_for_function("() => { const s = document.getElementById('status'); "
                            "return (s.title || s.textContent) === 'Finding change failed: The journal is busy.'; }")
        assert add.is_enabled() and cancel.is_enabled()
        assert form.get_by_label("Title").input_value() == "Same finding" and adds(synthetic_case) == []
        p.unroute(finding_write)
        p.errors[:] = [e for e in p.errors if "/api/finding" not in e]   # that refusal was the point
        add.click()
        card(p, 1).wait_for()
        assert len(adds(synthetic_case)) == 1 and finding_posts(p) == 2


def test_a_second_click_on_save_changes_while_its_write_is_out_edits_once(browser, synthetic_case):  # noqa: F811
    """The Edit form's Save changes and Cancel wait for the write as the new finding's form does: a second click while
    /api/finding is held sends nothing, and the journal holds one edit."""
    found = {}

    def setup(app):
        found["fid"] = api_finding(app, {"op": "add", "title": "A logon", "severity": "Low",
                                         "targets": [uid_at(app, T0)]})["finding"]

    for p in served_page(browser, synthetic_case, setup=setup):
        open_findings(p)
        one = card(p, 1)
        one.get_by_role("button", name="Edit").click()
        one.get_by_label("Narrative").fill("Administrator logged on over RDP.")
        p.evaluate(RECORD_REQUESTS)
        save, cancel = one.get_by_role("button", name="Save changes"), one.get_by_role("button", name="Cancel")
        held = []
        p.route(finding_write, lambda route: held.append(route))   # noqa: B023
        save.click()
        wait_held(p, held)
        assert save.is_disabled() and cancel.is_disabled()
        save.click(force=True)
        assert finding_posts(p) == 1
        held[0].continue_()
        p.wait_for_function("() => document.querySelectorAll('#details .finding-form').length === 0")
        p.unroute(finding_write)
        edits = [e for e in entries(synthetic_case) if e["action"] == "finding" and e["op"] == "edit"]
        assert [(e["finding"], e["narrative"]) for e in edits] == [(found["fid"], "Administrator logged on over RDP.")]


def test_the_chips_open_their_events_and_the_caveat_shows_beside_the_record_and_on_the_card(browser, synthetic_case):  # noqa: F811
    """On the Event page, a 4624 shows "What this does not prove" beside its record, with the caveat text and its
    sources as links, and Show less folds it to its title, remembered in this browser; a registry value with no row in the
    table shows none. On a card: the caveats of its events' types, each once; a finding of events with none shows no box.
    A chip is a link that opens its event."""
    found = {}

    def findings(app):
        found["rdp"], found["morty"] = uid_at(app, T0), uid_at(app, T0 + 60 * SEC)
        found["reg"] = app.con.execute("SELECT event_uid FROM events WHERE tool = 'recmd' AND host = 'DC01' "
                                       "ORDER BY event_uid").fetchone()[0]
        api_mark(app, {"uids": [found["rdp"]], "value": "malicious"})
        api_finding(app, {"op": "add", "title": "Logons and a registry value", "severity": "Medium",
                          "targets": [found["rdp"], found["morty"], found["reg"]]})
        api_finding(app, {"op": "add", "title": "The computer name", "severity": "Informational", "targets": [found["reg"]]})

    for p in served_page(browser, synthetic_case, setup=findings):
        details = p.locator("#details")
        open_findings(p)
        one, two = card(p, 1), card(p, 2)
        assert one.locator(".finding-caveat p").count() == 1
        assert one.locator(".finding-caveat p").get_attribute("data-caveat") == "logon"
        assert one.locator(".finding-caveat .caveat-title").inner_text() == "What this does not prove"
        text = one.locator(".finding-caveat p").inner_text()
        assert text.startswith("Logon events 4624 and 4625. A logon event shows an account authenticated, or failed to, "
                               "from a source.")
        assert text.endswith("Sources: Microsoft, event 4624 · Microsoft, event 4625 · Microsoft, MS-NLMP AUTHENTICATE_MESSAGE")
        assert two.locator(".chip").inner_text() == "Informational" and two.locator(".finding-caveat").count() == 0
        # A chip opens its event
        chip = one.locator(".ev-chip", has_text="03:21:48")
        assert chip.locator(".badge").get_attribute("title").startswith("Malicious, marked by cody")
        chip.locator(".linklike").click()
        p.wait_for_selector(f"{EVENT} .ev-ident")
        assert "DC01" in details.locator(".ev-ident").inner_text()
        assert p.evaluate("[...window.__app.S.selected]") == [found["rdp"]]
        # The caveat beside the record, above the fields
        box = details.locator(".ev-caveat")
        assert box.get_attribute("data-caveat") == "logon"
        assert p.evaluate("() => document.querySelector('#details .ev-message').nextElementSibling"
                          ".classList.contains('ev-caveat')")
        assert box.locator(".caveat-title").inner_text() == "What this does not prove"
        assert box.locator(".caveat-text").inner_text() == (
            "A logon event shows an account authenticated, or failed to, from a source. It does not show who used the account. "
            "On an NTLM logon, the workstation name is the one the client sent. The address and workstation "
            "fields depend on the authentication protocol.")
        assert box.locator(".caveat-src").inner_text() == (
            "Sources: Microsoft, event 4624 · Microsoft, event 4625 · Microsoft, MS-NLMP AUTHENTICATE_MESSAGE · Show less")
        links = box.locator(".caveat-src a")
        assert links.count() == 3 and links.first.get_attribute("href").endswith("/auditing/event-4624")
        assert links.last.get_attribute("href").endswith("/ms-nlmp/033d32cc-88f9-4483-9bf2-b273055038ce")
        assert box.locator(".caveat-src span[title]").count() == 0   # each source a link, none a file name
        box.get_by_role("button", name="Show less").click()
        assert "collapsed" in box.get_attribute("class") and box.locator(".caveat-text").is_hidden()
        assert box.get_by_role("button", name="Show more").is_visible() and box.locator(".caveat-title").is_visible()
        # Folded, the line is its title and Show more: no "Sources:" label or separators left behind
        assert box.locator(".caveat-src").inner_text().strip() == "Show more"
        # Remembered: another 4624's page opens it folded; a registry value has no caveat at all
        select(p, [found["morty"]])
        p.wait_for_function("(uid) => document.querySelector('#details').dataset.key === `event:${uid}`", arg=found["morty"])
        assert "collapsed" in details.locator(".ev-caveat").get_attribute("class")
        details.locator(".ev-caveat").get_by_role("button", name="Show more").click()
        assert details.locator(".ev-caveat .caveat-text").is_visible()
        select(p, [found["reg"]])
        p.wait_for_function("(uid) => document.querySelector('#details').dataset.key === `event:${uid}`", arg=found["reg"])
        assert details.locator(".ev-caveat").count() == 0
        assert details.locator(".finding-in").text_content() == (
            "In the finding: 1. Logons and a registry value, 2. The computer name")


def test_linking_more_than_25_events_asks_first_and_show_them_lists_the_marked_events_in_no_finding(browser, synthetic_case):  # noqa: F811
    """On the Findings page, Add to a finding with 30 selected events asks first, Cancel changes nothing, and the confirmed
    link records the count; a new finding from the same 30 asks too and is written as its add and a link with the consent.
    Show them lists the Malicious and Suspicious events in no finding, with their badges and ticks, and a tick offers a new
    finding from the ticked events."""
    found = {}
    many = [logon(T0 + (1000 + n) * SEC, 9900 + n, DC_LOG, user="bulk", ltype="3", ip="10.42.85.50") for n in range(30)]
    load(synthetic_case.db_path, many, host="DC01", tool="evtxecmd", tool_version="t", run_id="bulk", replaces_sources=[],
         staging_dir=synthetic_case.folder)

    def setup(app):
        found["rdp"], found["morty"], found["dc"] = uid_at(app, T0), uid_at(app, T0 + 60 * SEC), uid_at(app, T0 + 62 * SEC)
        found["bulk"] = [r[0] for r in app.con.execute("SELECT event_uid FROM events WHERE run_id = 'bulk' "
                                                       "ORDER BY ts_us").fetchall()]
        api_mark(app, {"uids": [found["rdp"], found["morty"]], "value": "malicious"})
        api_mark(app, {"uids": [found["dc"]], "value": "suspicious"})
        found["fid"] = api_finding(app, {"op": "add", "title": "Bulk logons", "severity": "Low"})["finding"]

    for p in served_page(browser, synthetic_case, setup=setup):
        details = p.locator("#details")
        select(p, found["bulk"])
        assert details.locator(".ev-verdict h3").text_content() == "Verdict for 30 selected events"
        row = details.locator(".finding-add")
        details.get_by_role("button", name="+ Finding").click()
        p.wait_for_function("() => document.querySelector('#details .finding-add select option[value=\"new\"]') !== null")
        row.get_by_label("Finding to add to").select_option(str(found["fid"]))
        before = len(entries(synthetic_case))
        row.get_by_role("button", name="Add the 30 selected events").click()
        block = details.locator(".confirm-block")
        block.wait_for()
        assert block.locator(".confirm-title").inner_text() == 'Link 30 events to the finding "Bulk logons"?'
        assert block.locator(".confirm-line").inner_text() == "A selection of 30 events you picked by hand."
        assert block.locator(".actions button").all_inner_texts() == ["Link 30", "Cancel"]
        # A link changes no event, so the block says that and not "All 30 change"
        assert block.locator(".confirm-points li").first.inner_text() == (
            "All 30 are linked to the finding. Their marks and tags don't change.")
        block.get_by_role("button", name="Cancel").click()
        p.wait_for_selector("#details .confirm-block", state="detached")
        assert len(entries(synthetic_case)) == before
        row.get_by_role("button", name="Add the 30 selected events").click()
        block.wait_for()
        with p.expect_response("**/api/finding") as got:
            block.get_by_role("button", name="Link 30", exact=True).click()
        assert json.loads(got.value.request.post_data)["confirmed"] == {"count": 30}
        p.wait_for_function(IN_FINDING)
        entry = entries(synthetic_case)[-1]
        assert (entry["op"], entry["finding"], len(entry["targets"]), entry["confirmed"]) == (
            "link", found["fid"], 30, {"count": 30, "skipped": 0})
        # A new finding from the same selection asks too
        open_findings(p)
        details.get_by_role("button", name="New finding from the 30 selected events").click()
        form = details.locator(".finding-form")
        form.get_by_label("Title").fill("Thirty network logons as bulk")
        form.get_by_label("Severity").select_option("Medium")
        form.get_by_role("button", name="Add the finding with 30 events").click()
        block.wait_for()
        assert block.locator(".confirm-title").inner_text() == "Link 30 events to a new finding?"
        assert block.locator(".confirm-points li").first.inner_text() == (
            "All 30 are linked to the new finding. Their marks and tags don't change.")
        p.keyboard.press("Escape")
        p.wait_for_selector("#details .confirm-block", state="detached")
        assert entries(synthetic_case)[-1]["op"] == "link" and details.locator(".finding-form").count() == 1   # the form stays
        # A confirm that was canceled wrote nothing, so the form's buttons work again
        assert form.get_by_role("button", name="Add the finding with 30 events").is_enabled()
        assert form.get_by_role("button", name="Cancel").is_enabled()
        form.get_by_role("button", name="Add the finding with 30 events").click()
        block.wait_for()
        block.get_by_role("button", name="Link 30", exact=True).click()
        two = card(p, 2)
        two.wait_for()
        assert two.locator(".finding-line").first.inner_text().startswith("ATT&CK: none given · 30 supporting events · added ")
        assert two.locator(".ev-chip:visible").count() == 8 and two.get_by_role("button", name="+22 more").count() == 1
        two.get_by_role("button", name="+22 more").click()
        assert two.locator(".ev-chip:visible").count() == 30 and two.get_by_role("button", name="Fewer").count() == 1
        add, link = entries(synthetic_case)[-2:]
        assert (add["op"], add["title"], add["targets"]) == ("add", "Thirty network logons as bulk", [])
        assert (link["op"], link["finding"], len(link["targets"]), link["confirmed"]) == (
            "link", add["seq"], 30, {"count": 30, "skipped": 0})
        # Show them: the three marked events are in no finding
        line = details.locator(".unassigned")
        assert line.locator("b").inner_text() == "3 marked events are in no finding yet."
        line.get_by_role("button", name="Show them").click()
        rows = details.locator(".unassigned-list li.rel-row")
        p.wait_for_function("() => document.querySelectorAll('#details .unassigned-list li.rel-row').length === 3")
        assert rows.locator(".badge").all_inner_texts() == ["M", "M", "S"]
        assert details.locator(".unassigned-list .actions strong").inner_text() == "3 marked events in no finding"
        rows.first.locator("input").check()
        assert details.locator(".unassigned-list").get_by_role("button", name="New finding from the 1 ticked").count() == 1
        assert line.get_by_role("button", name="Hide them").count() == 1
        rows.nth(1).locator(".rel-text").click()
        p.wait_for_selector(f"{EVENT} .ev-ident")
        assert p.evaluate("[...window.__app.S.selected]") == [found["morty"]]


def test_show_them_says_when_it_lists_only_the_first_of_the_marked_events_in_no_finding(browser, synthetic_case, monkeypatch):  # noqa: F811
    """The server lists at most LISTED_EVENTS events, so when more are in no finding the list's heading says it is the first
    of them, as a finding's card says "Listing the first N of M", rather than naming the count it lists."""
    from glessner import server

    monkeypatch.setattr(server, "LISTED_EVENTS", 2)

    def setup(app):
        api_mark(app, {"uids": [uid_at(app, T0), uid_at(app, T0 + 60 * SEC), uid_at(app, T0 + 62 * SEC)], "value": "malicious"})

    for p in served_page(browser, synthetic_case, setup=setup):
        open_findings(p)
        details = p.locator("#details")
        assert details.locator(".unassigned b").inner_text() == "3 marked events are in no finding yet."
        details.get_by_role("button", name="Show them").click()
        p.wait_for_function("() => document.querySelectorAll('#details .unassigned-list li.rel-row').length === 2")
        assert details.locator(".unassigned-list .actions strong").inner_text() == "The first 2 of 3 marked events in no finding"


def test_the_attack_field_picks_only_listed_techniques_and_flags_an_old_id(browser, synthetic_case):  # noqa: F811
    """The ATT&CK box lists Enterprise ATT&CK v20.0's techniques as the analyst types an ID, with or
    without its T, or words of a name; the first match is highlighted, the arrow keys move, Enter or a click picks, Escape
    closes, and a picked technique leaves the list. Text that matches nothing can't be picked, and Save says so. Past 50
    matches the guidance asks for more. A finding saved with IDs the list lacks keeps them: the card writes the server's
    flag beside each unlisted one, the edit form shows it as a flagged chip, an edit of other fields keeps it, and an edit
    of the techniques must remove it first."""
    found = {}

    def setup(app):
        found["uid"] = uid_at(app, T0 + 60 * SEC)
        with app.lock:
            found["old"] = app.journal.append("finding", op="add", title="From before the list", severity="High",
                                              techniques=["T1059.001", "T1086", "T9999"], targets=[found["uid"]])["seq"]

    for p in served_page(browser, synthetic_case, setup=setup):
        details = p.locator("#details")
        open_findings(p)
        old = details.locator(f".finding[data-finding='{found['old']}']")
        assert old.locator(".finding-line").first.inner_text().startswith(
            "ATT&CK: T1059.001, T1086 (revoked; now T1059.001), T9999 (not in ATT&CK v20.0) · 1 supporting event · added ")
        details.get_by_role("button", name="New finding", exact=True).click()
        form = details.locator(".finding-new .finding-form")
        form.get_by_label("Title").fill("Made with the pick list")
        form.get_by_label("Severity").select_option("Medium")
        box = form.get_by_role("combobox", name="ATT&CK techniques")
        hint = form.locator(".attack-hint")
        p.wait_for_function("() => document.querySelector('#details .attack-hint').textContent.includes('v20.0')")
        assert hint.inner_text() == "Type an ID or a name, then pick from the list (Enterprise ATT&CK v20.0)."
        assert box.get_attribute("placeholder") == "ATT&CK technique (optional)"
        # Words of a name: both PowerShell techniques, in ID order, the first highlighted, with their tactics
        box.fill("powershell")
        options = form.locator(".attack-list [role=option]")
        p.wait_for_function("() => document.querySelectorAll('#details .attack-list [role=option]').length === 2")
        assert [o.get_attribute("data-technique") for o in options.all()] == ["T1059.001", "T1546.013"]
        assert options.first.inner_text() == "T1059.001 Command and Scripting Interpreter: PowerShell · Execution"
        assert box.get_attribute("aria-expanded") == "true"
        assert box.get_attribute("aria-activedescendant") == options.first.get_attribute("id")
        box.press("Enter")
        chips = form.locator(".attack-chip")
        assert chips.locator(".label").all_inner_texts() == ["T1059.001 Command and Scripting Interpreter: PowerShell"]
        assert box.input_value() == "" and form.locator(".attack-list").is_hidden()
        # An ID without its T; the arrow moves to the second match, and Enter picks it
        box.fill("1078")
        p.wait_for_function("() => document.querySelector('#details .attack-list [role=option]')?.dataset.technique === 'T1078'")
        box.press("ArrowDown")
        assert options.nth(1).get_attribute("aria-selected") == "true" and options.first.get_attribute("aria-selected") == "false"
        box.press("Enter")
        form.locator(".attack-chip[data-technique='T1078.001']").wait_for()
        # A picked technique leaves the list; Escape closes it and keeps the form
        box.fill("t1078")
        p.wait_for_function("() => document.querySelectorAll('#details .attack-list [role=option]').length === 4")
        assert "T1078.001" not in [o.get_attribute("data-technique") for o in options.all()]
        box.press("Escape")
        assert form.locator(".attack-list").is_hidden() and box.get_attribute("aria-expanded") == "false"
        assert form.is_visible()
        # Text that matches nothing can't be picked, and Save says so
        box.fill("no such thing")
        p.wait_for_function("() => document.querySelector('#details .attack-hint').textContent.startsWith('No ')")
        assert hint.inner_text() == 'No Enterprise ATT&CK v20.0 technique matches "no such thing".'
        box.press("Enter")
        assert chips.count() == 2
        before = len(entries(synthetic_case))
        form.get_by_role("button", name="Add the finding").click()
        assert form.locator("p.warn").inner_text() == ('"no such thing" isn\'t picked. Pick a technique from the list, '
                                                       "or clear the ATT&CK box.")
        assert len(entries(synthetic_case)) == before
        # Past 50 matches the guidance asks for more of the ID or name
        box.fill("t1")
        p.wait_for_function("() => document.querySelectorAll('#details .attack-list [role=option]').length === 50")
        assert hint.inner_text() == "Showing 50 of 704. Type more of the ID or name to narrow the list."
        assert form.locator(".attack-more").inner_text() == hint.inner_text()   # the open list covers the hint
        box.fill("t1003")
        assert form.locator(".attack-more").is_hidden()   # T1003 and its sub-techniques fit: the foot goes with the overflow
        # A click picks; × removes
        box.fill("1021.001")
        form.locator(".attack-list [data-technique='T1021.001']").click()
        form.get_by_role("button", name="Remove T1078.001").click()
        assert [c.get_attribute("data-technique") for c in chips.all()] == ["T1059.001", "T1021.001"]
        assert hint.inner_text() == "Type an ID or a name, then pick from the list (Enterprise ATT&CK v20.0)."
        form.get_by_role("button", name="Add the finding").click()
        made = card(p, 2)
        made.wait_for()
        assert made.locator(".finding-line").first.inner_text().startswith(
            "ATT&CK: T1059.001, T1021.001 · 0 supporting events · added ")
        entry = entries(synthetic_case)[-1]
        assert (entry["op"], entry["title"], entry["techniques"]) == (
            "add", "Made with the pick list", ["T1059.001", "T1021.001"])
        # The old finding: flagged chips; an edit of the title alone keeps its IDs
        old.get_by_role("button", name="Edit").click()
        flagged = old.locator(".attack-chip.off-list")
        assert flagged.locator(".label").all_inner_texts() == ["T1086 revoked; now T1059.001", "T9999 not in ATT&CK v20.0"]
        assert old.locator(".attack-chip[data-technique='T1059.001'] .label").inner_text().startswith("T1059.001 Command and")
        old.get_by_label("Title").fill("Kept as it was")
        old.get_by_role("button", name="Save changes").click()
        p.wait_for_function("() => document.querySelector('#details .finding .finding-title')?.textContent"
                            " === '1. Kept as it was'")
        entry = entries(synthetic_case)[-1]
        assert (entry["op"], entry["finding"], entry["title"]) == ("edit", found["old"], "Kept as it was")
        assert "techniques" not in entry
        # An edit of the techniques must remove the flagged IDs first
        old.get_by_role("button", name="Edit").click()
        pick_technique(old, "valid accounts", "T1078")
        before = len(entries(synthetic_case))
        old.get_by_role("button", name="Save changes").click()
        assert old.locator("p.warn").inner_text() == "T1086, T9999 aren't in ATT&CK v20.0. Remove them to save the ATT&CK field."
        assert len(entries(synthetic_case)) == before
        old.get_by_role("button", name="Remove T1086").click()
        old.get_by_role("button", name="Remove T9999").click()
        old.get_by_role("button", name="Save changes").click()
        p.wait_for_function("() => document.querySelector('#details .finding .finding-line')?.textContent"
                            ".startsWith('ATT&CK: T1059.001, T1078 · ')")
        assert entries(synthetic_case)[-1]["techniques"] == ["T1059.001", "T1078"]
