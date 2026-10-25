"""The Details panel after an action on one of its pages, in a real browser. An action such as Accept all, Add rule, a
note, a mark, or a tag draws its page again when it answers, and a page the analyst asked for meanwhile keeps the panel,
even when it is still loading as the action answers. A page left and opened again before the answer draws again to show
it, and so does a list left and opened again before its tag answers. A confirm open on the page holds the redraw until it
closes. The Findings page drawn again after a write keeps its other open forms and the Summary's unsaved text, a form
whose write fails after such a redraw opens again unless another form of its kind has taken its place, and a change to
the Import page's mapping keeps the change before it. Going back to a step of the trail marks that step in the band at
once. They drive the installed Microsoft Edge through Playwright, as test_browser_smoke does, and are skipped without
it."""

import json
import re
from functools import partial
from urllib.parse import urlsplit

import pytest
from conftest import SEC, T0
from test_browser_findings import FINDINGS, entries, open_findings, uid_at
from test_browser_investigate import INVESTIGATE, open_worklist, page_post
from test_browser_pivots import FIRST, pv, select, uid, walk
from test_browser_reload import click_and_redraw, finding_card, holding_the_first, report_summary
from test_browser_search import search, words
from test_browser_smoke import RECORD_REQUESTS, asked, browser, case_menu, refused_with, served_page, wait_held  # noqa: F401
from test_pivots import RDP, pcase, pcase_events  # noqa: F401

from glessner import server
from glessner.imports import save_mapping
from glessner.intake import intake
from glessner.server import api_finding, api_import_preview, api_mark, api_note, api_rule

pytestmark = pytest.mark.browser
# Whether the page's code has finished with an answer to this path, query aside, since RECORD_REQUESTS ran
TAKEN = "(path) => window.__taken.some((p) => p.split('?')[0] === path)"
# Whether every request the page's code made since RECORD_REQUESTS ran has answered and the code that reads its answer has
# run, leaving out the paths that start with one of `held`: a read the test holds, and To investigate's counts, which a
# redraw of that page cancels.
SETTLED = """(held) => {
    const taken = [...window.__taken];
    return window.__asked.filter((path) => !held.some((prefix) => path.startsWith(prefix))).every((path) => {
        const at = taken.indexOf(path);
        if (at < 0) return false;
        taken.splice(at, 1);
        return true;
    });
}"""
COUNTS = "/api/pivot_count"
LOGONS = ("id: logons\nsuggest: suspicious\nwhen:\n  all:\n"
          "    - {field: event_code, equals: '4624'}\n    - {field: host, equals: DC01}\n")
SHOWN = "() => document.getElementById('details').dataset.page"


class Held:
    """Each request to `path` (its query aside) is held in `routes` until the test releases them."""

    def __init__(self, p, path):
        self.p, self.routes = p, []
        self.match = lambda url: urlsplit(url).path == path
        p.route(self.match, lambda route: self.routes.append(route))

    def release(self):
        for route in self.routes:
            route.continue_()
        self.p.unroute(self.match)


class HeldAnswer:
    """Each request to `path` (its query aside) reaches the server at once, and its answer is held in `routes`, with the
    route, until the test passes it on. The page then reads what the server held when the request was made."""

    def __init__(self, p, path):
        self.p, self.routes, self.answered = p, [], 0
        self.match = lambda url: urlsplit(url).path == path
        p.route(self.match, lambda route: self.routes.append((route, route.fetch())))

    def answer(self):
        """Pass on the answers held so far. Later requests are held too."""
        for route, response in self.routes[self.answered:]:
            route.fulfill(response=response)
        self.answered = len(self.routes)

    def release(self):
        self.answer()
        self.p.unroute(self.match)


def settled(p, *held):
    p.wait_for_function(SETTLED, arg=[*held, COUNTS])


def asked_meanwhile(p, action, act, read, ask, shown):
    """Start an action with `act`, whose request to `action` is held, then ask for another page with `ask`, whose read
    from `read` is held too. Release the action and wait until it has done with its own requests, such as its timeline
    reload; then release the read. The page asked for draws, which the test reads as `shown`, and keeps the panel."""
    p.evaluate(RECORD_REQUESTS)
    acting = Held(p, action)
    act()
    wait_held(p, acting.routes)
    reading = Held(p, read)
    ask()
    wait_held(p, reading.routes)
    acting.release()
    p.wait_for_function(TAKEN, arg=action)
    settled(p, read)
    reading.release()
    p.wait_for_function(TAKEN, arg=read)
    settled(p)
    assert p.evaluate(SHOWN) == shown


def ask_rules(p):
    return lambda: case_menu(p, "rulesButton")


def ask_findings(p):
    return lambda: p.locator("#tabFindings").click()


def open_event(p, event):
    p.evaluate("(u) => window.__app.select(u, false)", event)
    p.wait_for_selector(f"#details[data-key='event:{event}'] .ev-verdict")


def open_suggestions(p, source="hayabusa"):
    open_worklist(p)
    p.locator("#details").get_by_role("button", name=source, exact=True).click()
    p.wait_for_selector(f"#details[data-key='suggestions:{source}'] .sg-group")


def confirm(scope, label=re.compile(r"^Accept \d+$")):
    scope.locator(".confirm-block").get_by_role("button", name=label).click()


@pytest.mark.parametrize("change", ["add", "remove"])
def test_findings_asked_for_while_a_rule_changes_keeps_the_panel(browser, synthetic_case, change):  # noqa: F811
    """Add rule and Remove draw the Rules page again once the timeline has reloaded, but not over Findings, asked for
    while the rule changed and still loading then."""
    def run(p):
        case_menu(p, "rulesButton")
        details = p.locator("#details[data-page='rules']")
        details.locator("table").wait_for()
        if change == "add":
            details.locator("textarea").fill("id: added\nsuggest: suspicious\nwhen: {field: tool, equals: sbecmd}\n")
            act = details.get_by_role("button", name="Add rule", exact=True).click
        else:
            act = details.locator("tr", has_text="logons").get_by_role("button", name="Remove").click
        asked_meanwhile(p, "/api/rule", act, "/api/findings_page", ask_findings(p), "findings")

    for p in served_page(browser, synthetic_case, setup=lambda app: api_rule(app, {"op": "add", "text": LOGONS})):
        run(p)


def test_the_rules_page_draws_again_after_add_rule_and_remove(browser, synthetic_case):  # noqa: F811
    """With no page asked for meanwhile, Add rule draws the Rules page again with the new rule's row, and Remove draws it
    again without it."""
    for p in served_page(browser, synthetic_case):
        case_menu(p, "rulesButton")
        details = p.locator("#details[data-page='rules']")
        details.locator("table").wait_for()
        details.locator("textarea").fill("id: added\nsuggest: suspicious\nwhen: {field: tool, equals: sbecmd}\n")
        details.get_by_role("button", name="Add rule", exact=True).click()
        row = details.locator("tr", has=p.locator("td", has_text=re.compile(r"^added$")))
        row.wait_for()
        row.get_by_role("button", name="Remove").click()
        row.wait_for(state="detached")
        assert p.evaluate(SHOWN) == "rules"


def test_rules_asked_for_while_an_event_is_followed_up_keeps_the_panel(browser, synthetic_case):  # noqa: F811
    """The Followed up tick on To investigate draws the worklist again when it answers, but not over Rules, asked for
    meanwhile and still loading then."""
    found = {}

    def setup(app):
        found["uid"] = uid_at(app, T0 + 874 * SEC)
        api_mark(app, {"uids": [found["uid"]], "value": "suspicious"})

    for p in served_page(browser, synthetic_case, setup=setup):
        open_worklist(p)
        tick = p.locator(f"{INVESTIGATE} li.rel-row[data-uid='{found['uid']}'] input.inv-tick")
        asked_meanwhile(p, "/api/followup", tick.check, "/api/rules", ask_rules(p), "rules")


def test_rules_asked_for_while_the_worklists_next_page_is_read_keeps_the_panel(browser, synthetic_case, monkeypatch):  # noqa: F811
    """Show the next lists the marked events again when a mark changed since the first page was read, but not over Rules,
    asked for while the next page was read and still loading then."""
    monkeypatch.setattr(server, "WORKLIST_PAGE", 2)
    uids = {}

    def setup(app):
        uids.update((seconds, uid_at(app, T0 + seconds * SEC)) for seconds in (0, 60, 874))
        api_mark(app, {"uids": list(uids.values()), "value": "suspicious"})

    for p in served_page(browser, synthetic_case, setup=setup):
        open_worklist(p)
        page_post(p, "/api/mark", {"uids": [uids[0]], "value": "unreviewed", "note": ""})
        more = p.locator(INVESTIGATE).get_by_role("button", name="Show the next 1")
        asked_meanwhile(p, "/api/investigate", more.click, "/api/rules", ask_rules(p), "rules")


def test_rules_asked_for_while_to_investigate_accepts_all_keeps_the_panel(browser, synthetic_case):  # noqa: F811
    """Accept all on To investigate draws the worklist again once the decision is done, but not over Rules, asked for
    meanwhile and still loading then."""
    def run(p):
        open_worklist(p)
        row = p.locator(f"{INVESTIGATE} .rule[data-source='logons']")

        def act():
            row.get_by_role("button", name="Accept all").click()
            confirm(row)

        asked_meanwhile(p, "/api/suggestion", act, "/api/rules", ask_rules(p), "rules")

    for p in served_page(browser, synthetic_case, setup=lambda app: api_rule(app, {"op": "add", "text": LOGONS})):
        run(p)


def test_rules_asked_for_while_the_suggestions_page_accepts_keeps_the_panel(browser, synthetic_case):  # noqa: F811
    """An event's Accept on a source's Suggestions page draws that page again once the decision is done, but not over
    Rules, asked for meanwhile and still loading then."""
    for p in served_page(browser, synthetic_case):
        open_suggestions(p)
        accept = p.locator("#details .sg-events li").first.get_by_role("button", name="Accept", exact=True)
        asked_meanwhile(p, "/api/suggestion", accept.click, "/api/rules", ask_rules(p), "rules")


def test_rules_asked_for_while_new_evidence_is_added_keeps_the_panel(browser, synthetic_case):  # noqa: F811
    """Add new evidence draws the Import page again when the files are hashed, but not over Rules, asked for meanwhile
    and still loading then."""
    record = [{"@timestamp": "2020-09-19T03:21:50Z", "user": "u1", "action": "login"}]
    (synthetic_case.evidence / "DC01" / "export.json").write_text(json.dumps(record), newline="\n")
    intake(synthetic_case)   # the Import page lists the manifest's files
    for p in served_page(browser, synthetic_case):
        case_menu(p, "importButton")
        add = p.locator("#details[data-page='import']").get_by_role("button", name="Add new evidence")
        add.wait_for()
        asked_meanwhile(p, "/api/evidence_add", add.click, "/api/rules", ask_rules(p), "rules")


@pytest.mark.parametrize("first", ["preview", "files"])
def test_files_added_while_another_is_previewed_are_listed(browser, synthetic_case, first):  # noqa: F811
    """A click on a listed file's name while Add new evidence hashes the files draws that file's preview in place. Once
    both have answered, whichever answers first, the Import page lists the new file."""
    record = [{"@timestamp": "2020-09-19T03:21:50Z", "user": "u1", "action": "login"}]
    (synthetic_case.evidence / "DC01" / "a.json").write_text(json.dumps(record), newline="\n")
    intake(synthetic_case)
    for p in served_page(browser, synthetic_case):
        case_menu(p, "importButton")
        details = p.locator("#details[data-page='import']")
        add = details.get_by_role("button", name="Add new evidence")
        add.wait_for()
        (synthetic_case.evidence / "DC01" / "b.json").write_text(json.dumps(record), newline="\n")
        listed = details.get_by_role("button", name=re.compile(r"b\.json$"))
        assert listed.count() == 0
        p.evaluate(RECORD_REQUESTS)
        adding = Held(p, "/api/evidence_add")
        add.click()
        wait_held(p, adding.routes)
        previewing = Held(p, "/api/import_preview")
        details.get_by_role("button", name=re.compile(r"a\.json$")).click()
        wait_held(p, previewing.routes)
        holds = [(previewing, "/api/import_preview"), (adding, "/api/evidence_add")]
        if first == "files":
            holds.reverse()
        (one, one_path), (two, two_path) = holds
        one.release()
        p.wait_for_function(TAKEN, arg=one_path)
        settled(p, two_path)
        two.release()
        p.wait_for_function(TAKEN, arg=two_path)
        settled(p)
        assert p.evaluate(SHOWN) == "import"
        assert listed.count() == 1


# The values of the Import page's selects with these labels, null for one not drawn, read at once
MAPPED = "(labels) => labels.map((label) => document.querySelector(`#details select[aria-label='${label}']`)?.value ?? null)"
# Whether every preview asked for since RECORD_REQUESTS ran has answered but one
PREVIEWS_BUT_ONE = """() => {
    const previews = (paths) => paths.filter((path) => path === '/api/import_preview').length;
    return previews(window.__taken) === previews(window.__asked) - 1;
}"""


def ignore_user(p, user):
    """Set the Import page's user field to Ignore with its select, `user`, and wait until the preview has drawn it."""
    with p.expect_response("**/api/import_preview"):
        user.select_option("ignore")
    p.wait_for_function("() => document.querySelector(\"#details select[aria-label='What user holds']\")?.value === 'ignore'")


@pytest.mark.parametrize("when", ["before", "during"])
def test_add_new_evidence_keeps_the_mapping_the_analyst_chose(browser, synthetic_case, when):  # noqa: F811
    """The Import page draws again once Add new evidence has hashed the files, and keeps the mapping the analyst chose
    for the file on screen, before the files were hashed or while they were: here its user field set to Ignore, which
    the guess maps to an event field."""
    record = [{"@timestamp": "2020-09-19T03:21:50Z", "user": "u1", "action": "login"}]
    (synthetic_case.evidence / "DC01" / "export.json").write_text(json.dumps(record), newline="\n")
    intake(synthetic_case)
    for p in served_page(browser, synthetic_case):
        case_menu(p, "importButton")
        details = p.locator("#details[data-page='import']")
        user = details.get_by_label("What user holds")
        user.wait_for()
        assert user.input_value() != "ignore"
        if when == "before":
            ignore_user(p, user)
        p.evaluate(RECORD_REQUESTS)
        adding = Held(p, "/api/evidence_add")
        details.get_by_role("button", name="Add new evidence").click()
        wait_held(p, adding.routes)
        if when == "during":
            ignore_user(p, user)
        adding.release()
        p.wait_for_function(TAKEN, arg="/api/evidence_add")
        settled(p)
        assert len(asked(p, "/api/imports")) == 1   # the page was drawn again with the files read anew
        assert p.evaluate(SHOWN) == "import"
        assert user.input_value() == "ignore"


def test_a_file_a_redraw_puts_on_screen_starts_from_its_guess(browser, synthetic_case):  # noqa: F811
    """The mapping chosen for a file stays with it. With the other unidentified files shown, one picked, and its user
    field set to Ignore, hiding them again puts the listed file back on screen with the guess for it."""
    record = [{"@timestamp": "2020-09-19T03:21:50Z", "user": "u1", "action": "login"}]
    (synthetic_case.evidence / "DC01" / "export.json").write_text(json.dumps(record), newline="\n")
    (synthetic_case.evidence / "DC01" / "notes.dat").write_text("time,user,action\n2020-09-19T03:21:50Z,u1,login\n",
                                                                 newline="\n")
    intake(synthetic_case)
    for p in served_page(browser, synthetic_case):
        case_menu(p, "importButton")
        details = p.locator("#details[data-page='import']")
        user = details.get_by_label("What user holds")
        user.wait_for()
        guess = p.evaluate(MAPPED, ["Format", "What user holds"])
        assert guess[1] != "ignore"
        others = details.get_by_label("Show other unidentified files")
        others.check()
        notes = details.get_by_role("button", name=re.compile(r"notes\.dat$"))
        notes.click()   # listed once the page has drawn again with every file
        details.locator(".imp-file.sel", has_text="notes.dat").wait_for()
        assert p.evaluate(MAPPED, ["Format"]) != guess[:1]   # notes.dat is read as CSV
        ignore_user(p, user)
        p.evaluate(RECORD_REQUESTS)
        others.uncheck()
        p.wait_for_function(TAKEN, arg="/api/import_preview")
        settled(p)
        assert details.locator(".imp-file.sel").inner_text().startswith("DC01/export.json")
        assert p.evaluate(MAPPED, ["Format", "What user holds"]) == guess


def test_the_import_page_opened_again_keeps_the_mapping_the_analyst_chose(browser, synthetic_case):  # noqa: F811
    """The Import page opened again, with Back from another page or with the Case menu's Import, shows the file it
    showed with the mapping the analyst chose for it: here its user field set to Ignore."""
    record = [{"@timestamp": "2020-09-19T03:21:50Z", "user": "u1", "action": "login"}]
    (synthetic_case.evidence / "DC01" / "export.json").write_text(json.dumps(record), newline="\n")
    intake(synthetic_case)
    for p in served_page(browser, synthetic_case):
        case_menu(p, "importButton")
        details = p.locator("#details[data-page='import']")
        user = details.get_by_label("What user holds")
        user.wait_for()
        ignore_user(p, user)
        for reopen in (p.locator("#detailsBand button.back").click, partial(case_menu, p, "importButton")):
            ask_findings(p)()
            p.wait_for_selector("#details[data-page='findings'] .findings-col")
            reopen()
            user.wait_for()
            assert user.input_value() == "ignore"


def refused_and_kept(sent, message):
    """A route handler that keeps each request's JSON body in `sent` and answers it with HTTP 500 and `message`."""
    refuse = refused_with(message)

    def handle(route):
        sent.append(route.request.post_data_json)
        refuse(route)
    return handle


def test_a_preview_that_answers_after_a_later_one_leaves_the_mapping_on_screen(browser, synthetic_case):  # noqa: F811
    """Add new evidence draws the Import page again, and that preview, asked under the guess, is held while the analyst
    sets the user field to Ignore and that preview draws. The held one answers last and draws nothing, so the page
    still shows Ignore, and Import sends the mapping on screen."""
    record = [{"@timestamp": "2020-09-19T03:21:50Z", "user": "u1", "action": "login"}]
    (synthetic_case.evidence / "DC01" / "export.json").write_text(json.dumps(record), newline="\n")
    intake(synthetic_case)
    for p in served_page(browser, synthetic_case):
        case_menu(p, "importButton")
        details = p.locator("#details[data-page='import']")
        user = details.get_by_label("What user holds")
        user.wait_for()
        p.evaluate(RECORD_REQUESTS)
        held, sent = [], []
        p.route(lambda url: urlsplit(url).path == "/api/import_preview", holding_the_first(held))
        details.get_by_role("button", name="Add new evidence").click()
        wait_held(p, held)
        ignore_user(p, user)
        settled(p, "/api/import_preview")   # the redraw Add new evidence still owes the page reads the files again
        p.wait_for_function(PREVIEWS_BUT_ONE)
        held[0].continue_()
        settled(p)
        assert user.input_value() == "ignore"
        p.route(lambda url: urlsplit(url).path == "/api/import", refused_and_kept(sent, "Not imported here."))
        details.get_by_role("button", name="Import 1 record", exact=True).click()
        p.wait_for_function("() => document.getElementById('status').textContent.startsWith('Import failed')")
        assert sent[0]["mapping"]["ignore"] == ["user"]
        p.errors[:] = [e for e in p.errors if not e.endswith("/api/import")]   # that refusal was the point


def test_a_mapping_change_made_before_the_last_one_s_preview_answers_keeps_both(browser, synthetic_case):  # noqa: F811
    """Each change to the Import page's mapping asks for a preview. With the preview of the first change, the user field
    set to Ignore, held, the analyst sets the action field to Ignore too. Once both previews have answered, the page
    shows both fields ignored, and Import sends both."""
    record = [{"@timestamp": "2020-09-19T03:21:50Z", "user": "u1", "action": "login"}]
    (synthetic_case.evidence / "DC01" / "export.json").write_text(json.dumps(record), newline="\n")
    intake(synthetic_case)
    for p in served_page(browser, synthetic_case):
        case_menu(p, "importButton")
        details = p.locator("#details[data-page='import']")
        user, action = details.get_by_label("What user holds"), details.get_by_label("What action holds")
        user.wait_for()
        assert "ignore" not in p.evaluate(MAPPED, ["What user holds", "What action holds"])
        p.evaluate(RECORD_REQUESTS)
        held, sent = [], []
        p.route(lambda url: urlsplit(url).path == "/api/import_preview", holding_the_first(held))
        user.select_option("ignore")
        wait_held(p, held)
        action.select_option("ignore")
        p.wait_for_function(PREVIEWS_BUT_ONE)
        held[0].continue_()
        settled(p)
        assert p.evaluate(MAPPED, ["What user holds", "What action holds"]) == ["ignore", "ignore"]
        p.route(lambda url: urlsplit(url).path == "/api/import", refused_and_kept(sent, "Not imported here."))
        details.get_by_role("button", name="Import 1 record", exact=True).click()
        p.wait_for_function("() => document.getElementById('status').textContent.startsWith('Import failed')")
        assert sorted(sent[0]["mapping"]["ignore"]) == ["action", "user"]
        p.errors[:] = [e for e in p.errors if not e.endswith("/api/import")]   # that refusal was the point


# Whether the page's code has finished with `n` answers to a preview since RECORD_REQUESTS ran
PREVIEWS_TAKEN = "(n) => window.__taken.filter((path) => path === '/api/import_preview').length === n"


@pytest.mark.parametrize("redraw", ["others", "evidence"])
def test_the_import_page_drawn_again_while_a_change_s_preview_is_out_keeps_the_change(browser, synthetic_case, redraw):  # noqa: F811
    """The Import page draws again, with its own preview, when Show other unidentified files is ticked and after Add new
    evidence. With the preview of a change, the user field set to Ignore, held, the page drawn again starts from that
    change: once both previews have answered, the page shows the field ignored, and Import sends it so."""
    record = [{"@timestamp": "2020-09-19T03:21:50Z", "user": "u1", "action": "login"}]
    (synthetic_case.evidence / "DC01" / "export.json").write_text(json.dumps(record), newline="\n")
    intake(synthetic_case)
    for p in served_page(browser, synthetic_case):
        case_menu(p, "importButton")
        details = p.locator("#details[data-page='import']")
        user = details.get_by_label("What user holds")
        user.wait_for()
        assert user.input_value() != "ignore"
        p.evaluate(RECORD_REQUESTS)
        held, sent = [], []
        p.route(lambda url: urlsplit(url).path == "/api/import_preview", holding_the_first(held))
        user.select_option("ignore")
        wait_held(p, held)
        if redraw == "others":
            details.get_by_label("Show other unidentified files").check()
        else:
            details.get_by_role("button", name="Add new evidence").click()
        p.wait_for_function(PREVIEWS_TAKEN, arg=1)
        held[0].continue_()
        settled(p)
        assert p.evaluate(MAPPED, ["What user holds"]) == ["ignore"]
        p.route(lambda url: urlsplit(url).path == "/api/import", refused_and_kept(sent, "Not imported here."))
        details.get_by_role("button", name="Import 1 record", exact=True).click()
        p.wait_for_function("() => document.getElementById('status').textContent.startsWith('Import failed')")
        assert "user" in sent[0]["mapping"]["ignore"]
        p.errors[:] = [e for e in p.errors if not e.endswith("/api/import")]   # that refusal was the point


def test_a_mapping_change_made_as_another_file_is_picked_is_dropped(browser, synthetic_case):  # noqa: F811
    """A change to the mapping starts from the mapping last asked for, once its preview answers. With a saved mapping
    chosen for export.json and its preview held, the analyst sets the user field to Ignore and then picks notes.dat
    before that preview answers. The change was made on export.json's controls, so it is dropped: notes.dat shows its own
    guess, and Import sends that."""
    record = [{"@timestamp": "2020-09-19T03:21:50Z", "user": "u1", "action": "login"}]
    (synthetic_case.evidence / "DC01" / "export.json").write_text(json.dumps(record), newline="\n")
    (synthetic_case.evidence / "DC01" / "notes.dat").write_text("time,user,action\n2020-09-19T03:21:50Z,u1,login\n",
                                                                 newline="\n")
    intake(synthetic_case)

    def setup(app):
        save_mapping(app.case, "kept", api_import_preview(app, {"path": "DC01/export.json"})["mapping"])

    for p in served_page(browser, synthetic_case, setup=setup):
        case_menu(p, "importButton")
        details = p.locator("#details[data-page='import']")
        user = details.get_by_label("What user holds")
        user.wait_for()
        details.get_by_label("Show other unidentified files").check()
        notes = details.get_by_role("button", name=re.compile(r"notes\.dat$"))
        notes.wait_for()
        p.evaluate(RECORD_REQUESTS)
        held, sent = [], []
        p.route(lambda url: urlsplit(url).path == "/api/import_preview", holding_the_first(held))
        details.get_by_label("Mapping", exact=True).select_option("saved:kept")
        wait_held(p, held)
        user.select_option("ignore")
        notes.click()
        details.locator(".imp-file.sel", has_text="notes.dat").wait_for()
        settled(p, "/api/import_preview")
        guess = p.evaluate(MAPPED, ["Format", "What user holds"])
        assert guess[1] not in (None, "ignore")
        held[0].continue_()
        settled(p)
        assert details.locator(".imp-file.sel").inner_text().startswith("DC01/notes.dat")
        assert p.evaluate(MAPPED, ["Format", "What user holds"]) == guess
        p.route(lambda url: urlsplit(url).path == "/api/import", refused_and_kept(sent, "Not imported here."))
        details.get_by_role("button", name=re.compile(r"^Import \d")).click()
        p.wait_for_function("() => document.getElementById('status').textContent.startsWith('Import failed')")
        assert sent[0]["paths"] == ["DC01/notes.dat"]
        assert "user" not in sent[0]["mapping"].get("ignore", [])
        p.errors[:] = [e for e in p.errors if not e.endswith("/api/import")]   # that refusal was the point


def test_rules_asked_for_while_a_finding_is_retired_keeps_the_panel(browser, synthetic_case):  # noqa: F811
    """Retiring a finding draws the Findings page again when it answers, but not over Rules, asked for meanwhile and
    still loading then."""
    def run(p):
        p.locator("#tabFindings").click()
        card = p.locator("#details[data-page='findings'] .finding", has_text="1. Lateral movement")
        card.get_by_role("button", name="Retire").click()
        asked_meanwhile(p, "/api/finding", card.get_by_role("button", name="Retire the finding").click, "/api/rules",
                        ask_rules(p), "rules")

    setup = lambda app: api_finding(app, {"op": "add", "title": "Lateral movement", "severity": "High"})
    for p in served_page(browser, synthetic_case, setup=setup):
        run(p)


def test_a_finding_retired_keeps_the_open_new_finding_form_and_the_summary_s_unsaved_text(browser, synthetic_case):  # noqa: F811
    """Retiring a finding draws the Findings page again. The new finding's form open on it, with a title typed, and the
    words typed in the report's Summary and not saved are still there after the redraw."""
    setup = lambda app: api_finding(app, {"op": "add", "title": "Lateral movement", "severity": "High"})
    for p in served_page(browser, synthetic_case, setup=setup):
        open_findings(p)
        p.locator("#details .inv-head").get_by_role("button", name="New finding").click()
        form = p.locator(f"{FINDINGS} .finding-new .finding-form")
        form.get_by_label("Title").fill("Unsaved")
        report_summary(p).fill("Typed summary.")
        card = p.locator(f"{FINDINGS} .finding", has_text="1. Lateral movement")
        card.get_by_role("button", name="Retire").click()
        click_and_redraw(p, card.get_by_role("button", name="Retire the finding"))
        assert p.locator(f"{FINDINGS} .finding.retired", has_text="1. Lateral movement").count() == 1
        assert form.count() == 1
        assert form.get_by_label("Title").input_value() == "Unsaved"
        assert report_summary(p).input_value() == "Typed summary."


def test_a_finding_s_write_closes_only_the_form_it_saved(browser, synthetic_case):  # noqa: F811
    """With an edit form open on one finding and the new finding's form open too, Unlink in the edit form draws the
    Findings page again: the edit form stays open with its typed title, less the unlinked event, and the new finding's
    form stays. Save changes then closes the edit form, and the new finding's form still stays."""
    ids = {}

    def setup(app):
        ids["uids"] = [uid_at(app, T0), uid_at(app, T0 + 60 * SEC)]
        ids["fid"] = api_finding(app, {"op": "add", "title": "A logon", "severity": "Low", "targets": ids["uids"]})[
            "finding"]

    for p in served_page(browser, synthetic_case, setup=setup):
        open_findings(p)
        p.locator("#details .inv-head").get_by_role("button", name="New finding").click()
        added = p.locator(f"{FINDINGS} .finding-new .finding-form")
        added.get_by_label("Title").fill("Second, unsaved")
        card = finding_card(p, ids["fid"])
        card.get_by_role("button", name="Edit").click()
        edit = card.locator(".finding-form")
        edit.get_by_label("Title").fill("RDP from the internet")
        click_and_redraw(p, card.get_by_role("button", name="Unlink").first)
        assert edit.count() == 1
        assert edit.get_by_label("Title").input_value() == "RDP from the internet"
        assert card.locator(".ev-chip").count() == 1
        assert added.get_by_label("Title").input_value() == "Second, unsaved"
        click_and_redraw(p, edit.get_by_role("button", name="Save changes"))
        assert card.locator(".finding-form").count() == 0
        assert card.locator(".finding-title").inner_text() == "1. RDP from the internet"
        assert added.get_by_label("Title").input_value() == "Second, unsaved"
        assert (entries(synthetic_case)[-1]["op"], entries(synthetic_case)[-1]["title"]) == ("edit", "RDP from the internet")


def test_a_finding_form_whose_save_is_out_when_another_write_redraws_closes_once_saved(browser, synthetic_case):  # noqa: F811
    """Save changes on one finding's edit form is out when another finding is retired, and the retire's redraw of the
    Findings page answers first. The form being saved isn't drawn again, and once its save answers the card shows the
    saved title with no form open."""
    ids = {}

    def setup(app):
        ids["kept"] = api_finding(app, {"op": "add", "title": "A logon", "severity": "Low"})["finding"]
        ids["gone"] = api_finding(app, {"op": "add", "title": "Lateral movement", "severity": "High"})["finding"]

    for p in served_page(browser, synthetic_case, setup=setup):
        open_findings(p)
        card = finding_card(p, ids["kept"])
        card.get_by_role("button", name="Edit").click()
        card.get_by_label("Title").fill("RDP from the internet")
        p.evaluate(RECORD_REQUESTS)
        saving = []
        p.route(lambda url: urlsplit(url).path == "/api/finding", holding_the_first(saving))
        card.get_by_role("button", name="Save changes").click()
        wait_held(p, saving)
        gone = finding_card(p, ids["gone"])
        gone.get_by_role("button", name="Retire").click()
        click_and_redraw(p, gone.get_by_role("button", name="Retire the finding"))
        settled(p, "/api/finding")
        assert card.locator(".finding-form").count() == 0
        saving[0].continue_()
        p.wait_for_function("(title) => document.querySelector(`#details .finding-title`)?.textContent === title",
                            arg="1. RDP from the internet")
        settled(p)
        assert card.locator(".finding-form").count() == 0
        assert card.locator(".finding-title").inner_text() == "1. RDP from the internet"


def test_a_finding_write_whose_redraw_cannot_read_keeps_the_forms_for_the_next_draw(browser, synthetic_case):  # noqa: F811
    """Retiring a finding while the findings can't be read: the page says the open forms and the Summary's unsaved text
    are kept, and the Findings step, with the read working, brings back the new finding's form and the Summary's words."""
    setup = lambda app: api_finding(app, {"op": "add", "title": "Lateral movement", "severity": "High"})
    for p in served_page(browser, synthetic_case, setup=setup):
        open_findings(p)
        p.locator("#details .inv-head").get_by_role("button", name="New finding").click()
        form = p.locator(f"{FINDINGS} .finding-new .finding-form")
        form.get_by_label("Title").fill("Unsaved")
        report_summary(p).fill("Typed summary.")
        card = p.locator(f"{FINDINGS} .finding", has_text="1. Lateral movement")
        card.get_by_role("button", name="Retire").click()
        failing = lambda url: urlsplit(url).path == "/api/findings_page"
        p.route(failing, refused_with("The findings are busy."))
        card.get_by_role("button", name="Retire the finding").click()
        p.wait_for_selector(f"{FINDINGS} >> text=Could not load the findings: The findings are busy.")
        assert p.locator(FINDINGS).get_by_text("are kept until the page loads").count() == 1
        p.unroute(failing)
        p.errors[:] = [e for e in p.errors if "/api/findings_page" not in e]   # that refusal was the point
        open_findings(p)
        assert p.locator(f"{FINDINGS} .finding.retired", has_text="1. Lateral movement").count() == 1
        assert form.count() == 1
        assert form.get_by_label("Title").input_value() == "Unsaved"
        assert report_summary(p).input_value() == "Typed summary."


def two_findings(ids):
    """A setup that adds two findings, whose IDs it keeps in `ids` as "first" and "second"."""
    def setup(app):
        ids["first"] = api_finding(app, {"op": "add", "title": "A logon", "severity": "Low"})["finding"]
        ids["second"] = api_finding(app, {"op": "add", "title": "Lateral movement", "severity": "High"})["finding"]
    return setup


def test_a_finding_s_write_keeps_another_card_s_retire_reason(browser, synthetic_case):  # noqa: F811
    """Retire's reason row, open on one finding with a reason typed, stays open with it when Save changes on another
    finding's edit form draws the Findings page again."""
    ids = {}
    for p in served_page(browser, synthetic_case, setup=two_findings(ids)):
        open_findings(p)
        first, second = finding_card(p, ids["first"]), finding_card(p, ids["second"])
        first.get_by_role("button", name="Retire").click()
        first.get_by_label("Reason").fill("Duplicate of 2")
        second.get_by_role("button", name="Edit").click()
        second.get_by_label("Title").fill("RDP from the internet")
        click_and_redraw(p, second.get_by_role("button", name="Save changes"))
        assert second.locator(".finding-title").inner_text() == "2. RDP from the internet"
        assert first.get_by_label("Reason").input_value() == "Duplicate of 2"


def two_unfiled_events(ids):
    """A setup that marks two events, which no finding holds, and adds a finding. Keeps the events' IDs in `ids` as
    "uids" and the finding's as "fid"."""
    def setup(app):
        ids["uids"] = [uid_at(app, T0), uid_at(app, T0 + 60 * SEC)]
        api_mark(app, {"uids": ids["uids"], "value": "suspicious"})
        ids["fid"] = api_finding(app, {"op": "add", "title": "Lateral movement", "severity": "High"})["finding"]
    return setup


def test_a_finding_s_write_keeps_the_unfiled_list_open_with_its_tick_and_note(browser, synthetic_case):  # noqa: F811
    """With two marked events in no finding, Show them lists them. The list stays open, with a row ticked and a note typed
    for the mark, when retiring a finding draws the Findings page again."""
    ids = {}
    for p in served_page(browser, synthetic_case, setup=two_unfiled_events(ids)):
        open_findings(p)
        p.locator(FINDINGS).get_by_role("button", name="Show them").click()
        unfiled = p.locator(f"{FINDINGS} .unassigned-list")
        row = unfiled.locator(f"li.rel-row[data-uid='{ids['uids'][0]}']")
        row.locator("input").check()
        unfiled.locator(".mark-note").fill("Seen in the proxy log")
        card = finding_card(p, ids["fid"])
        card.get_by_role("button", name="Retire").click()
        click_and_redraw(p, card.get_by_role("button", name="Retire the finding"))
        row.wait_for()
        assert p.locator(FINDINGS).get_by_role("button", name="Hide them").count() == 1
        assert row.locator("input").is_checked()
        assert unfiled.locator("li.rel-row input:checked").count() == 1
        assert unfiled.locator(".mark-note").input_value() == "Seen in the proxy log"


def test_new_finding_from_the_unfiled_ticks_opens_in_place(browser, synthetic_case):  # noqa: F811
    """New finding from the ticked rows of the unfiled list opens the new finding's form over them in place. An edit form
    open on a finding and the Summary's unsaved text stay, and the new finding's form already open keeps its typed title,
    now for the ticked event, which the status line says."""
    ids = {}
    for p in served_page(browser, synthetic_case, setup=two_unfiled_events(ids)):
        open_findings(p)
        page = p.locator(FINDINGS)
        page.locator(".inv-head").get_by_role("button", name="New finding").click()
        added = page.locator(".finding-new .finding-form")
        added.get_by_label("Title").fill("Typed first")
        card = finding_card(p, ids["fid"])
        card.get_by_role("button", name="Edit").click()
        card.get_by_label("Title").fill("Edited, unsaved")
        report_summary(p).fill("Typed summary.")
        page.get_by_role("button", name="Show them").click()
        page.locator(f".unassigned-list li.rel-row[data-uid='{ids['uids'][0]}'] input").check()
        page.get_by_role("button", name="New finding from the 1 ticked").click()
        added.get_by_role("button", name="Add the finding with 1 event").wait_for()
        assert added.get_by_label("Title").input_value() == "Typed first"
        assert card.get_by_label("Title").input_value() == "Edited, unsaved"
        assert report_summary(p).input_value() == "Typed summary."
        assert p.locator("#status").inner_text().startswith(
            "The new finding's form keeps what was typed in it, now for 1 ticked event.")


@pytest.mark.parametrize("field", ["Summary", "Title"])
def test_a_finding_s_write_keeps_the_focus_and_caret_in_the_field_being_typed_in(browser, synthetic_case, field):  # noqa: F811
    """Retiring a finding draws the Findings page again while the analyst types in the Summary, or in another finding's
    edit form, with the caret inside the words. The words typed stay, and so do the focus and the caret, so the typing
    goes on where it was."""
    ids = {}
    for p in served_page(browser, synthetic_case, setup=two_findings(ids)):
        open_findings(p)
        first, second = finding_card(p, ids["first"]), finding_card(p, ids["second"])
        if field == "Summary":
            box = report_summary(p)
        else:
            first.get_by_role("button", name="Edit").click()
            box = first.get_by_label("Title")
        box.fill("Typed end")
        second.get_by_role("button", name="Retire").click()
        p.evaluate(RECORD_REQUESTS)
        retiring = Held(p, "/api/finding")
        second.get_by_role("button", name="Retire the finding").click()
        wait_held(p, retiring.routes)
        box.focus()
        box.evaluate("(node) => node.setSelectionRange(5, 5)")   # the caret after "Typed"
        p.keyboard.type(" before")
        p.evaluate("() => { window.__drawnBefore = document.querySelector('#details .findings-page'); }")
        retiring.release()
        p.wait_for_function("() => { const page = document.querySelector('#details .findings-page'); "
                            "return page !== null && page !== window.__drawnBefore; }")
        settled(p)
        report_summary(p)
        p.keyboard.type(" after")
        assert box.input_value() == "Typed before after end"
        assert box.evaluate("(node) => node === document.activeElement")


def test_a_finding_form_whose_save_fails_after_another_write_redrew_opens_again(browser, synthetic_case):  # noqa: F811
    """Save changes on one finding's edit form is out when another finding is retired, and the retire's redraw of the
    Findings page leaves that form out. The save then fails: the form opens again with its typed title, and the status
    line says so."""
    ids = {}
    for p in served_page(browser, synthetic_case, setup=two_findings(ids)):
        open_findings(p)
        first, second = finding_card(p, ids["first"]), finding_card(p, ids["second"])
        first.get_by_role("button", name="Edit").click()
        first.get_by_label("Title").fill("Typed and then refused")
        p.evaluate(RECORD_REQUESTS)
        saving = []
        p.route(lambda url: urlsplit(url).path == "/api/finding", holding_the_first(saving))
        first.get_by_role("button", name="Save changes").click()
        wait_held(p, saving)
        second.get_by_role("button", name="Retire").click()
        click_and_redraw(p, second.get_by_role("button", name="Retire the finding"))
        settled(p, "/api/finding")
        assert first.locator(".finding-form").count() == 0
        refused_with("The journal is busy.")(saving[0])
        first.locator(".finding-form").wait_for()
        settled(p)
        assert first.get_by_label("Title").input_value() == "Typed and then refused"
        assert p.locator("#status").inner_text() == (
            "Finding change failed: The journal is busy. Its form is open again with what was typed in it.")
        assert entries(synthetic_case)[-1]["op"] == "retire"
        p.errors[:] = [e for e in p.errors if "/api/finding" not in e]   # that refusal was the point


def save_held_then_retire_the_second(p, ids, form, label):
    """Click `label` in `form`, a finding form, with its write held, and retire the second finding, whose redraw of the
    Findings page leaves that form out. Returns the held write."""
    p.evaluate(RECORD_REQUESTS)
    saving = []
    p.route(lambda url: urlsplit(url).path == "/api/finding", holding_the_first(saving))
    form.get_by_role("button", name=label).click()
    wait_held(p, saving)
    second = finding_card(p, ids["second"])
    second.get_by_role("button", name="Retire").click()
    click_and_redraw(p, second.get_by_role("button", name="Retire the finding"))
    settled(p, "/api/finding")
    assert form.count() == 0
    return saving


def refused_and_settled(p, saving):
    """Answer the held finding write with a refusal, and wait until the page has finished with what follows it."""
    refused_with("The journal is busy.")(saving[0])
    p.wait_for_function(TAKEN, arg="/api/finding")
    settled(p)
    p.errors[:] = [e for e in p.errors if "/api/finding" not in e]   # that refusal was the point


@pytest.mark.parametrize("typed", ["Second", ""], ids=["typed", "empty"])
def test_a_new_finding_whose_add_fails_while_another_new_form_is_open_says_its_words_are_not_kept(browser, synthetic_case, typed):  # noqa: F811
    """Add the finding is out when another finding is retired, and the retire's redraw leaves the form out. The analyst
    opens New finding again, typing in it or not, and the add then fails. The page has one new finding's form, so the
    open one stays as it is, and the status line says the words typed in the form that failed aren't kept."""
    ids = {}
    for p in served_page(browser, synthetic_case, setup=two_findings(ids)):
        open_findings(p)
        new = p.locator("#details .inv-head").get_by_role("button", name="New finding")
        new.click()
        added = p.locator(f"{FINDINGS} .finding-new .finding-form")
        added.get_by_label("Title").fill("First add, refused")
        added.get_by_label("Severity").select_option("Low")
        saving = save_held_then_retire_the_second(p, ids, added, re.compile(r"^Add the finding"))
        new.click()
        added.get_by_label("Title").fill(typed)
        refused_and_settled(p, saving)
        assert [box.input_value() for box in added.get_by_label("Title").all()] == [typed]
        assert p.locator("#status").inner_text() == (
            "Finding change failed: The journal is busy. What was typed in its form isn't kept: another new finding's form "
            "takes its place.")
        assert entries(synthetic_case)[-1]["op"] == "retire"


def test_an_edit_whose_save_fails_while_the_finding_has_another_edit_form_says_its_words_are_not_kept(browser, synthetic_case):  # noqa: F811
    """Save changes on one finding's edit form is out when another finding is retired, and the retire's redraw leaves
    the form out. The analyst opens Edit on that finding again and types in it, and the save then fails. The open edit
    form stays as it is, and the status line says the words typed in the form that failed aren't kept."""
    ids = {}
    for p in served_page(browser, synthetic_case, setup=two_findings(ids)):
        open_findings(p)
        first = finding_card(p, ids["first"])
        first.get_by_role("button", name="Edit").click()
        edit = first.locator(".finding-form")
        edit.get_by_label("Title").fill("Typed and then refused")
        saving = save_held_then_retire_the_second(p, ids, edit, "Save changes")
        first.get_by_role("button", name="Edit").click()
        edit.get_by_label("Title").fill("Typed again")
        refused_and_settled(p, saving)
        assert [box.input_value() for box in edit.get_by_label("Title").all()] == ["Typed again"]
        assert p.locator("#status").inner_text() == (
            "Finding change failed: The journal is busy. What was typed in its form isn't kept: another edit form of the "
            "finding takes its place.")
        assert entries(synthetic_case)[-1]["op"] == "retire"


def test_rules_asked_for_while_an_event_is_linked_to_a_finding_keeps_the_panel(browser, synthetic_case):  # noqa: F811
    """Linking an event to a finding from its Event page draws that page again when it answers, but not over Rules,
    asked for meanwhile and still loading then."""
    found = {}

    def setup(app):
        found["uid"] = uid_at(app, T0 + 874 * SEC)
        found["fid"] = api_finding(app, {"op": "add", "title": "Lateral movement", "severity": "High"})["finding"]

    def run(p):
        open_event(p, found["uid"])
        details = p.locator("#details")
        details.get_by_role("button", name="+ Finding").click()
        p.wait_for_function("() => document.querySelector('#details .finding-add select option[value=\"new\"]') !== null")
        row = details.locator(".finding-add")
        row.get_by_label("Finding to add to").select_option(str(found["fid"]))
        asked_meanwhile(p, "/api/finding", row.get_by_role("button", name=re.compile("^Add ")).click, "/api/rules",
                        ask_rules(p), "rules")

    for p in served_page(browser, synthetic_case, setup=setup):
        run(p)


def test_rules_asked_for_while_a_search_adds_its_hidden_matches_keeps_the_panel(browser, synthetic_case):  # noqa: F811
    """Show the hidden matches on the timeline draws the search again once the View has changed, but not over Rules,
    asked for meanwhile and still loading then."""
    for p in served_page(browser, synthetic_case):
        p.evaluate("() => import('/js/view.js').then((m) => m.addViewValue({ host: 'DC01' }))")
        p.wait_for_function("() => window.__app.S.filterId !== null && !window.__app.S.windowPending")
        p.locator("#search").fill("code:4624")
        p.locator("#search").press("Enter")
        show = p.locator("#searchShowHidden")
        show.wait_for()
        asked_meanwhile(p, "/api/filter", show.click, "/api/rules", ask_rules(p), "rules")


def test_rules_asked_for_while_a_trail_is_saved_keeps_the_panel(browser, pcase):  # noqa: F811
    """Save trail as a note draws the start event's page again when it answers, but not over Rules, asked for meanwhile
    and still loading then."""
    rdp = uid(pcase, RDP)
    for p in served_page(browser, pcase):
        select(p, rdp)
        pv(p, "session").locator("button.pv-go").click()
        p.locator("#relatedList strong", has_text="with the same host and logon ID").wait_for()
        save = p.locator("#details nav.trail button.trail-save")
        asked_meanwhile(p, "/api/note", save.click, "/api/rules", ask_rules(p), "rules")


def test_rules_asked_for_while_a_note_is_added_keeps_the_panel(browser, synthetic_case):  # noqa: F811
    """Add note draws the Event page again when it answers, but not over Rules, asked for meanwhile and still loading
    then."""
    found = {}
    for p in served_page(browser, synthetic_case, setup=lambda app: found.update(uid=uid_at(app, T0 + 874 * SEC))):
        open_event(p, found["uid"])
        p.locator("#details").get_by_placeholder("Add a note to this event").fill("seen before")
        add = p.locator("#details").get_by_role("button", name="Add note")
        asked_meanwhile(p, "/api/note", add.click, "/api/rules", ask_rules(p), "rules")


def test_rules_asked_for_while_a_note_is_retracted_keeps_the_panel(browser, synthetic_case):  # noqa: F811
    """Retract on the Event page's note draws the page again when it answers, but not over Rules, asked for meanwhile
    and still loading then."""
    found = {}

    def setup(app):
        found["uid"] = uid_at(app, T0 + 874 * SEC)
        api_note(app, {"uid": found["uid"], "text": "a note to retract"})

    for p in served_page(browser, synthetic_case, setup=setup):
        open_event(p, found["uid"])
        retract = p.locator("#details .notes").get_by_role("button", name="Retract")
        asked_meanwhile(p, "/api/note_retract", retract.click, "/api/rules", ask_rules(p), "rules")


@pytest.mark.parametrize("decision", ["mark", "accept"])
def test_rules_asked_for_while_the_event_page_decides_keeps_the_panel(browser, synthetic_case, decision):  # noqa: F811
    """A mark and an Accept on the Event page draw the page again once the timeline has reloaded, but not over Rules,
    asked for meanwhile and still loading then."""
    found = {}
    for p in served_page(browser, synthetic_case, setup=lambda app: found.update(uid=uid_at(app, T0))):
        open_event(p, found["uid"])
        verdict = p.locator("#details .ev-verdict")
        if decision == "mark":
            asked_meanwhile(p, "/api/mark", verdict.get_by_role("button", name="Malicious", exact=True).click,
                            "/api/rules", ask_rules(p), "rules")
        else:
            asked_meanwhile(p, "/api/suggestion", verdict.locator(".decision button.primary").click, "/api/rules",
                            ask_rules(p), "rules")


def test_rules_asked_for_during_a_review_decision_keeps_the_panel_and_the_review_stays(browser, synthetic_case):  # noqa: F811
    """Accept in Review one by one moves to the next event once the decision is done, unless the analyst has asked for
    another page meanwhile: Rules, still loading then, keeps the panel, and the review stays on the decided event."""
    def run(p):
        open_worklist(p)
        p.locator(f"{INVESTIGATE} .rule[data-source='logons']").get_by_role("button", name="Review one by one").click()
        bar = p.locator("#details[data-page='event'] .review-bar")
        bar.wait_for()
        decided = p.evaluate("window.__app.S.focus")
        asked_meanwhile(p, "/api/suggestion", bar.get_by_role("button", name="Accept as Suspicious").click, "/api/rules",
                        ask_rules(p), "rules")
        assert p.evaluate("window.__app.S.focus") == decided

    for p in served_page(browser, synthetic_case, setup=lambda app: api_rule(app, {"op": "add", "text": LOGONS})):
        run(p)


def test_an_event_page_asked_for_during_a_group_decisions_reload_keeps_the_panel(browser, synthetic_case):  # noqa: F811
    """A group's Accept on the Suggestions page draws the page again once the timeline has reloaded, but not over an
    Event page asked for while the timeline reloaded and still loading then."""
    found = {}

    def run(p):
        open_suggestions(p)
        group = p.locator("#details .sg-group").first

        def act():
            group.get_by_role("button", name=re.compile(r"^Accept \d+$")).click()
            confirm(group)

        asked_meanwhile(p, "/api/lanes", act, "/api/event",
                        lambda: p.evaluate("(u) => window.__app.select(u, false)", found["uid"]), "event")

    for p in served_page(browser, synthetic_case, setup=lambda app: found.update(uid=uid_at(app, T0 + 874 * SEC))):
        run(p)


def test_a_suggestions_page_opened_again_before_its_group_decision_answers_shows_it(browser, synthetic_case):  # noqa: F811
    """The Suggestions page left and opened again while a group's Accept was out was read before the decision, so it
    draws again when the decision is done, and no longer lists the group."""
    def run(p):
        open_suggestions(p)
        details = p.locator("#details")
        group = details.locator(".sg-group").first
        key = group.locator(".sg-head strong").inner_text()
        p.evaluate(RECORD_REQUESTS)
        accepting = Held(p, "/api/suggestion")
        group.get_by_role("button", name=re.compile(r"^Accept \d+$")).click()
        confirm(group)
        wait_held(p, accepting.routes)
        case_menu(p, "rulesButton")
        p.wait_for_selector("#details[data-page='rules']")
        p.locator("#detailsBand button.back").click()
        p.wait_for_selector("#details[data-key='suggestions:hayabusa'] .sg-group")
        assert details.locator(".sg-head strong", has_text=key).count() == 1
        accepting.release()
        p.wait_for_function(TAKEN, arg="/api/suggestion")
        settled(p)
        assert p.evaluate(SHOWN) == "suggestions"
        assert details.locator(".sg-head strong", has_text=key).count() == 0

    for p in served_page(browser, synthetic_case):
        run(p)


def add_logons(app):
    api_rule(app, {"op": "add", "text": LOGONS})


def test_a_confirm_opened_while_a_decision_is_out_stays_until_it_closes(browser, synthetic_case):  # noqa: F811
    """An event's Accept on the logons rule's Suggestions page is out when the analyst opens Accept all's confirm. The
    Accept's answer doesn't draw the page over the confirm, so the question stays. Cancel closes it, and the page then
    draws once, without the accepted event."""
    def run(p):
        open_suggestions(p, "logons")
        details = p.locator("#details")
        rows = details.locator(".sg-events li")
        listed = rows.count()
        p.evaluate(RECORD_REQUESTS)
        accepting = Held(p, "/api/suggestion")
        rows.first.get_by_role("button", name="Accept", exact=True).click()
        wait_held(p, accepting.routes)
        details.get_by_role("button", name="Accept all").click()
        block = details.locator(".confirm-block")
        block.wait_for()
        accepting.release()
        p.wait_for_function(TAKEN, arg="/api/suggestion")
        settled(p)
        assert block.count() == 1 and rows.count() == listed
        assert asked(p, "/api/pending?") == []
        block.get_by_role("button", name="Cancel").click()
        p.wait_for_function(TAKEN, arg="/api/pending")
        settled(p)
        assert block.count() == 0 and rows.count() == listed - 1
        assert len(asked(p, "/api/pending?")) == 1

    for p in served_page(browser, synthetic_case, setup=add_logons):
        run(p)


def test_a_confirm_opened_while_the_page_reads_itself_again_stays_until_it_closes(browser, synthetic_case):  # noqa: F811
    """After an event's Accept on the logons rule's Suggestions page, the page reads its suggestions again to draw the
    change. Accept all's confirm, opened while that read is out, stays when the read answers. Cancel closes it, and the
    page then draws, without the accepted event."""
    def run(p):
        open_suggestions(p, "logons")
        details = p.locator("#details")
        rows = details.locator(".sg-events li")
        listed = rows.count()
        p.evaluate(RECORD_REQUESTS)
        reading = Held(p, "/api/pending")
        rows.first.get_by_role("button", name="Accept", exact=True).click()
        wait_held(p, reading.routes)
        details.get_by_role("button", name="Accept all").click()
        block = details.locator(".confirm-block")
        block.wait_for()
        reading.release()
        p.wait_for_function(TAKEN, arg="/api/pending")
        settled(p)
        assert block.count() == 1 and rows.count() == listed
        block.get_by_role("button", name="Cancel").click()
        p.wait_for_function("(n) => document.querySelectorAll('#details .sg-events li').length === n", arg=listed - 1)
        settled(p)
        assert block.count() == 0
        assert len(asked(p, "/api/pending?")) == 2

    for p in served_page(browser, synthetic_case, setup=add_logons):
        run(p)


def test_a_search_opened_again_while_its_forgiving_count_is_out_shows_the_count(browser, synthetic_case):  # noqa: F811
    """The search left and opened again while its forgiving count was out shows the count when it answers."""
    words(synthetic_case)
    for p in served_page(browser, synthetic_case):
        search(p, '"nmap"', 2)
        counting = Held(p, "/api/search_adds")
        p.locator("#searchAddsGo").click()
        wait_held(p, counting.routes)
        case_menu(p, "rulesButton")
        p.wait_for_selector("#details[data-page='rules']")
        p.locator("#detailsBand button.back").click()
        p.wait_for_selector("#details[data-page='search'] #searchAddsBusy")
        counting.release()
        p.wait_for_selector("#details[data-page='search'] #searchAdds")


def test_findings_keeps_the_panel_when_its_list_marks_events_other_than_the_focused_one(browser, synthetic_case):  # noqa: F811
    """On Findings, Show them lists the marked events in no finding. Marking four of them that aren't the event in focus
    leaves Findings on screen while the list reads them again, and after, when the page has drawn again."""
    found = {}

    def setup(app):
        found["uids"] = [uid_at(app, T0 + s * SEC) for s in (60, 61, 62, 874, 910)]
        api_mark(app, {"uids": found["uids"], "value": "suspicious"})

    def run(p):
        focus = found["uids"][3]
        open_event(p, focus)
        p.locator("#tabFindings").click()
        details = p.locator("#details[data-page='findings']")
        details.get_by_role("button", name="Show them").click()
        rows = details.locator(".unassigned-list li.rel-row")
        p.wait_for_function("() => document.querySelectorAll('#details .unassigned-list li.rel-row').length === 5")
        for other in (u for u in found["uids"] if u != focus):
            details.locator(f".unassigned-list li.rel-row[data-uid='{other}'] input").check()
        assert rows.locator("input:checked").count() == 4
        details.locator(".findings-page").evaluate("(n) => { n.dataset.drawn = 'before'; }")
        p.evaluate(RECORD_REQUESTS)
        listing = Held(p, "/api/findings_page")
        details.get_by_role("button", name="Mark 4 Malicious").click()
        wait_held(p, listing.routes)
        p.wait_for_function(TAKEN, arg="/api/mark")
        settled(p, "/api/findings_page")
        assert p.evaluate(SHOWN) == "findings"
        listing.release()
        p.wait_for_function(TAKEN, arg="/api/findings_page")
        settled(p)
        assert p.evaluate(SHOWN) == "findings"
        assert p.evaluate("window.__app.S.focus") == focus
        assert details.locator(".findings-page[data-drawn='before']").count() == 0   # the page drew again

    for p in served_page(browser, synthetic_case, setup=setup):
        run(p)


def test_a_tag_from_a_search_with_the_focused_event_ticked_keeps_the_search(browser, synthetic_case):  # noqa: F811
    """A tag given from a search's list to the ticked events, the event in focus among them, leaves the search on
    screen."""
    found = {}
    for p in served_page(browser, synthetic_case, setup=lambda app: found.update(uid=uid_at(app, T0 + 874 * SEC))):
        open_event(p, found["uid"])
        p.locator("#search").fill("code:4624")
        p.locator("#search").press("Enter")
        row = p.locator(f"#details[data-page='search'] li.rel-row[data-uid='{found['uid']}']")
        row.locator("input").check()
        p.evaluate(RECORD_REQUESTS)
        p.locator("#details").get_by_role("button", name="Tag 1 as...").click()
        p.locator("#quickMenu").get_by_role("menuitem", name="Lateral Movement", exact=True).click()
        p.wait_for_function(TAKEN, arg="/api/tag")
        settled(p)
        assert p.evaluate(SHOWN) == "search"


def search_4624(p):
    p.locator("#search").fill("code:4624")
    p.locator("#search").press("Enter")
    return p.locator("#details[data-page='search']")


def tag_lateral_movement(p, scope):
    scope.get_by_role("button", name="Tag 1 as...").click()
    p.locator("#quickMenu").get_by_role("menuitem", name="Lateral Movement", exact=True).click()


def test_rules_asked_for_while_a_search_list_marks_keeps_the_panel(browser, synthetic_case):  # noqa: F811
    """A mark from a search's list draws the search again once it is written, but not over Rules, asked for meanwhile
    and still loading then."""
    for p in served_page(browser, synthetic_case):
        details = search_4624(p)
        details.locator("li.rel-row input").first.check()
        mark = details.get_by_role("button", name="Mark 1 Malicious")
        asked_meanwhile(p, "/api/mark", mark.click, "/api/rules", ask_rules(p), "rules")


def test_rules_asked_for_while_a_search_list_tags_keeps_the_panel(browser, synthetic_case):  # noqa: F811
    """A tag from a search's list draws the search again once it is written, but not over Rules, asked for meanwhile
    and still loading then."""
    for p in served_page(browser, synthetic_case):
        details = search_4624(p)
        details.locator("li.rel-row input").first.check()
        asked_meanwhile(p, "/api/tag", partial(tag_lateral_movement, p, details), "/api/rules", ask_rules(p),
                        "rules")


LATERAL_MOVEMENT = {"tag": "tactic:TA0008"}   # a View value: events tagged Lateral Movement
VIEW_ON = "() => window.__app.S.filterId !== null && !window.__app.S.windowPending"


def tagged_row_shows(p, row, scope):
    """With the View on Lateral Movement, `row` is hidden by the View. Tag it from its list, `scope`, and wait until the
    tag and what follows it have answered."""
    assert row.locator(".tag").inner_text().startswith("hidden")
    row.locator("input").check()
    p.evaluate(RECORD_REQUESTS)
    tag_lateral_movement(p, scope)
    p.wait_for_function(TAKEN, arg="/api/tag")
    settled(p)


def test_a_tag_from_a_search_list_draws_the_list_again(browser, synthetic_case):  # noqa: F811
    """With the View on Lateral Movement, a search's row of an untagged event is hidden by the View. Tagging it from the
    list draws the list again, and the row is no longer hidden."""
    found = {}
    for p in served_page(browser, synthetic_case, setup=lambda app: found.update(uid=uid_at(app, T0 + 874 * SEC))):
        p.evaluate("(v) => import('/js/view.js').then((m) => m.addViewValue(v))", LATERAL_MOVEMENT)
        p.wait_for_function(VIEW_ON)
        details = search_4624(p)
        row = details.locator(f"li.rel-row[data-uid='{found['uid']}']")
        tagged_row_shows(p, row, details)
        assert p.evaluate(SHOWN) == "search"
        assert not any(t.startswith("hidden") for t in row.locator(".tag").all_inner_texts())


def test_a_tag_from_a_pivots_list_draws_the_list_again(browser, pcase):  # noqa: F811
    """With the View on Lateral Movement, a pivot's row of an untagged event is hidden. Tagging it from the list draws the
    list again, and the row is no longer hidden."""
    rdp = uid(pcase, RDP)
    for p in served_page(browser, pcase):
        p.evaluate("(v) => import('/js/view.js').then((m) => m.addViewValue(v))", LATERAL_MOVEMENT)
        p.wait_for_function(VIEW_ON)
        select(p, rdp)
        pv(p, "session").locator("button.pv-go").click()
        listed = p.locator("#relatedList")
        row = listed.locator("li.rel-row", has_text="4672")
        row.wait_for()
        tagged_row_shows(p, row, listed)
        assert p.evaluate(SHOWN) == "event"
        assert not any(t.startswith("hidden") for t in row.locator(".tag").all_inner_texts())


def test_a_tag_from_a_pivots_list_with_the_focused_event_ticked_draws_the_list_again(browser, pcase):  # noqa: F811
    """With the View on Lateral Movement, the RDP logon's Same logon session list holds the logon itself, and both it
    and the session's 4672 are hidden. Tagging the two from the list draws the logon's Event page again, since it is
    among them, and reads the list again too, so the 4672's row is no longer hidden."""
    rdp = uid(pcase, RDP)
    for p in served_page(browser, pcase):
        p.evaluate("(v) => import('/js/view.js').then((m) => m.addViewValue(v))", LATERAL_MOVEMENT)
        p.wait_for_function(VIEW_ON)
        select(p, rdp)
        pv(p, "session").locator("button.pv-go").click()
        listed = p.locator("#relatedList")
        row = listed.locator("li.rel-row", has_text="4672")
        row.wait_for()
        assert row.locator(".tag").inner_text().startswith("hidden")
        listed.locator(f"li.rel-row[data-uid='{rdp}'] input").check()
        row.locator("input").check()
        p.evaluate(RECORD_REQUESTS)
        listed.get_by_role("button", name="Tag 2 as...").click()
        p.locator("#quickMenu").get_by_role("menuitem", name="Lateral Movement", exact=True).click()
        p.wait_for_function(TAKEN, arg="/api/tag")
        settled(p)
        assert len(asked(p, "/api/event?")) == 1 and len(asked(p, "/api/related?")) == 1
        assert p.evaluate(SHOWN) == "event"
        assert not any(t.startswith("hidden") for t in row.locator(".tag").all_inner_texts())


def tag_then_leave_for_rules(p, found):
    """With the View on Lateral Movement, tick the search's row of `found`'s event, which the View hides, and tag it
    Lateral Movement from the list. The tag is held, and the Rules page is opened while it is out. Returns the tag's
    hold and the row's locator."""
    p.evaluate("(v) => import('/js/view.js').then((m) => m.addViewValue(v))", LATERAL_MOVEMENT)
    p.wait_for_function(VIEW_ON)
    details = search_4624(p)
    row = details.locator(f"li.rel-row[data-uid='{found['uid']}']")
    assert row.locator(".tag").inner_text().startswith("hidden")
    row.locator("input").check()
    p.evaluate(RECORD_REQUESTS)
    tagging = Held(p, "/api/tag")
    tag_lateral_movement(p, details)
    wait_held(p, tagging.routes)
    case_menu(p, "rulesButton")
    p.wait_for_selector("#details[data-page='rules']")
    return tagging, row


def test_a_search_opened_again_while_its_tag_is_out_draws_the_list_again(browser, synthetic_case):  # noqa: F811
    """A search's row hidden by the View is tagged from the list, and while the tag is out the analyst opens Rules and
    goes back to the search, which reads its rows before the tag answers. When the tag answers, the list draws again,
    and the row is no longer hidden."""
    found = {}
    for p in served_page(browser, synthetic_case, setup=lambda app: found.update(uid=uid_at(app, T0 + 874 * SEC))):
        tagging, row = tag_then_leave_for_rules(p, found)
        p.locator("#detailsBand button.back").click()
        row.wait_for()
        settled(p, "/api/tag")
        assert row.locator(".tag").inner_text().startswith("hidden")
        tagging.release()
        p.wait_for_function(TAKEN, arg="/api/tag")
        settled(p)
        assert p.evaluate(SHOWN) == "search"
        assert not any(t.startswith("hidden") for t in row.locator(".tag").all_inner_texts())


def test_a_search_still_loading_when_its_tag_answers_draws_again(browser, synthetic_case):  # noqa: F811
    """A search's row hidden by the View is tagged from the list, and while the tag is out the analyst opens Rules and
    goes back to the search, which reads its rows before the tag is written. Its answer is held until the tag has
    answered. The search draws as it read, with the row hidden, then reads its rows once more, and the row is no longer
    hidden."""
    found = {}
    for p in served_page(browser, synthetic_case, setup=lambda app: found.update(uid=uid_at(app, T0 + 874 * SEC))):
        tagging, row = tag_then_leave_for_rules(p, found)
        reading = HeldAnswer(p, "/api/search")
        p.locator("#detailsBand button.back").click()
        wait_held(p, reading.routes)
        tagging.release()
        p.wait_for_function(TAKEN, arg="/api/tag")
        settled(p, "/api/search")
        reading.answer()
        wait_held(p, reading.routes, 2)
        assert p.evaluate(SHOWN) == "search"
        assert row.locator(".tag").inner_text().startswith("hidden")
        reading.release()
        p.wait_for_function("() => window.__taken.filter((path) => path.startsWith('/api/search?')).length === 2")
        settled(p)
        assert p.evaluate(SHOWN) == "search"
        assert not any(t.startswith("hidden") for t in row.locator(".tag").all_inner_texts())
        assert len(asked(p, "/api/search?")) == 2


def test_going_back_to_a_step_marks_it_in_the_band_at_once(browser, pcase):  # noqa: F811
    """A click on an earlier step of the trail marks that step as the one on screen at once, before its event's page
    has loaded."""
    rdp = uid(pcase, RDP)
    for p in served_page(browser, pcase):
        walk(p, rdp)
        loading = Held(p, "/api/event")
        p.locator("#details nav.trail").get_by_role("button", name=FIRST, exact=True).click()
        assert p.locator("#details nav.trail .here").inner_text() == FIRST
        wait_held(p, loading.routes)
        loading.release()
        p.wait_for_selector(f"#details[data-key='event:{rdp}']")
        assert p.locator("#details nav.trail .here").inner_text() == FIRST
