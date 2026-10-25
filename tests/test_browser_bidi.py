"""Bidi controls in evidence text, in a real browser. Each one a page puts in for a reader, as text or in a title,
aria-label, or placeholder, shows as a visible [U+XXXX], so a right-to-left override can't draw a file name backward.
Values the page sends back, copies, or keeps in an input or a data attribute keep the character as recorded. They drive
the installed Microsoft Edge through Playwright, as test_browser_smoke does, and are skipped without it."""

import json
import re

import pivot_key_fixtures as fx
import pytest
from conftest import SEC, T0
from test_browser_badges import tooltip_for
from test_browser_pivots import COUNTED, pv, select
from test_browser_smoke import browser, filtered_view, page, point_of, served_page, wait_drawn  # noqa: F401
from test_parsers import EVTX_COLUMNS, write_csv
from test_pivots import INSTALLER, load_events, system_event, uid_of
from test_splits import DC1_SEC, EDGE_SEC, PC01_SEC, security

from glessner.case import create_case
from glessner.events import connect
from glessner.imports import run_import
from glessner.intake import intake
from glessner.parsers.common import file_key
from glessner.runner import RunRecord, _write_record, load_output

pytestmark = pytest.mark.browser
START_READY = "() => window.__start && window.__start.info !== null"

RLO = "\u202e"   # right-to-left override
LRI = "\u2066"   # left-to-right isolate
NAME = f"report{RLO}fdp.scr"   # drawn as written, it reads reportrcs.pdf
FILE = f"C:\\Users\\Public\\{NAME}"
SHORT = "C:\\Users\\Public\\REPORT~1.SCR"   # NAME's 8.3 form
USER = f"evil{RLO}resu"
ADDRESS = f"fe80::1%{RLO}1"   # an IPv6 address keeps its scope ID as written
MESSAGE = f"Wrote {NAME}"
SOURCE = f"bidi{RLO}.csv"
MIXED = f"LAB{LRI}"
# Every bidi control, then the zero-width characters, which ordinary text uses (U+200D joins emoji) and which stay
CONTROLS = "\u061c\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"
ZERO_WIDTH = "\u200b\u200c\u200d\ufeff"

# Each bidi control the page shows a reader: in a text node, or in a title, aria-label, or placeholder, listed with the
# element it is in and its text, with each control written <U+XXXX> so the report reads as the page holds it.
RAW_CONTROLS = r"""() => {
    const CONTROL = /[\u061C\u200E\u200F\u202A-\u202E\u2066-\u2069]/;
    const written = (s) => s.replace(new RegExp(CONTROL.source, 'g'),
                                     (c) => `<U+${c.codePointAt(0).toString(16).toUpperCase().padStart(4, '0')}>`).slice(0, 160);
    const where = (node) => (node ? node.tagName.toLowerCase() + (node.id ? `#${node.id}` : '')
        + (typeof node.className === 'string' && node.className.trim() ? `.${node.className.trim().split(/\s+/).join('.')}` : '')
        : 'document');
    const found = [];
    const walker = document.createTreeWalker(document.documentElement, NodeFilter.SHOW_TEXT);
    for (let n = walker.nextNode(); n; n = walker.nextNode()) {
        if (CONTROL.test(n.nodeValue)) found.push(`${where(n.parentElement)} text: ${written(n.nodeValue)}`);
    }
    for (const node of document.querySelectorAll('[title], [aria-label], [placeholder]')) {
        for (const name of ['title', 'aria-label', 'placeholder']) {
            const value = node.getAttribute(name);
            if (value && CONTROL.test(value)) found.push(`${where(node)} ${name}: ${written(value)}`);
        }
    }
    return found;
}"""

# The helper on every control and zero-width character, and el's text and attributes for one value holding all of them
HELPER = """async ([text]) => {
    const core = await import('/js/core.js');
    const node = core.el('span', { title: text, 'aria-label': text, placeholder: text, 'data-value': text, value: text }, text);
    const attrs = Object.fromEntries(['title', 'aria-label', 'placeholder', 'data-value', 'value']
                                     .map((name) => [name, node.getAttribute(name)]));
    return { shown: core.showControls(text), text: node.textContent, attrs };
}"""

# A logon link's hover, from the function the tooltip is built with, since the case here draws no link with a bidi control
LINK_TIP = """async (l) => (await import('/js/interaction.js')).describe({ kind: 'link', l })"""

# Record what the page copies, in place of the clipboard, which a headless browser may refuse
RECORD_COPIES = "() => { window.__copied = []; navigator.clipboard.writeText = async (t) => { window.__copied.push(t); }; }"


def raw_controls(p):
    return p.evaluate(RAW_CONTROLS)


def shown(text):
    """Text as the pages show it: each bidi control as [U+XXXX]."""
    return re.sub(f"[{CONTROLS}]", lambda m: f"[U+{ord(m.group()):04X}]", text)


def imported(case, name="bidi.csv"):
    """Import one CSV record into DC01, from the file `name`, whose file name, message, account, and source address's
    scope ID each hold a right-to-left override, through the Import module, and return its event ID."""
    (case.evidence / "DC01" / name).write_text(
        f"Time,User,SourceIP,File,Message\n2020-09-19T03:25:00Z,{USER},{ADDRESS},{FILE},{MESSAGE}\n",
        encoding="utf-8", newline="")
    intake(case)
    mapping = {"format": "csv", "delimiter": ",", "header": True, "artifact": "csv",
               "time": {"columns": ["Time"], "format": "ymd", "zone": "UTC"},
               "fields": {"user": "User", "source_ip": "SourceIP", "path": "File", "message": "Message"},
               "host": {"from": "folder"}, "message": "{Message}", "ignore": []}
    record = run_import(case, f"DC01/{name}", mapping, zones={})
    assert record.status == "ok", record.reason
    with connect(case.db_path, read_only=True) as con:
        row = con.execute("SELECT event_uid, user_name, source_ip, file_path, message FROM events WHERE source_file = ?",
                          [f"DC01/{name}"]).fetchone()
    assert row[1:] == (USER, ADDRESS, FILE, MESSAGE)   # stored as recorded
    return row[0]


def mixed_case(tmp_path):
    """A one-folder collection whose host's name holds a left-to-right isolate, of event logs from three computers, as
    test_splits.lab_case builds LAB, so the host is flagged as recorded by several computers."""
    (tmp_path / "evidence" / "LM").mkdir(parents=True)
    case = create_case(tmp_path / "case", "Samples", tmp_path / "evidence", "cody", single_host=MIXED)
    rows = [security(case, 1, 4624, "PC01.example.corp", PC01_SEC, 1, TargetUserName="alice", LogonType="3"),
            security(case, 1, 4624, "MSEDGEWIN10", EDGE_SEC, 4, TargetUserName="bob", LogonType="3"),
            security(case, 1, 4768, "DC1.insecurebank.local", DC1_SEC, 6, TargetUserName="carol")]
    run_id = "20261015T010000Z_evtxecmd_LAB"
    folder = case.runs_folder / run_id
    (folder / "output").mkdir(parents=True)
    write_csv(folder / "output" / "evtxecmd.csv", EVTX_COLUMNS, rows)
    record = RunRecord(run_id=run_id, tool="evtxecmd", tool_version="t", executable="", host=MIXED, argv=[], cwd="",
                       inputs=[PC01_SEC, EDGE_SEC, DC1_SEC], started_utc="2026-10-15T00:00:00Z", status="ok",
                       parser="evtxecmd_csv")
    _write_record(folder, record)
    load_output(case, record, folder)
    return case


def field_value(p, label):
    """The value cell of the Event page's field with this label."""
    return (p.locator("#details .ev-facts dt").filter(has_text=re.compile(f"^{re.escape(label)}$")).first
            .locator("xpath=following-sibling::dd[1]"))


def test_each_bidi_control_shows_as_its_code_point_and_values_kept_for_the_page_stay(page):  # noqa: F811
    """The helper writes each bidi control as [U+XXXX] and leaves zero-width characters as they are. el writes a text
    child, a title, an aria-label, and a placeholder that way, and keeps a data attribute and a value as given, since
    the page reads those back or sends them."""
    text = f"a{CONTROLS}b{ZERO_WIDTH}c"
    escaped = f"a{shown(CONTROLS)}b{ZERO_WIDTH}c"
    assert escaped.count("[U+") == len(CONTROLS)
    assert page.evaluate(HELPER, [text]) == {
        "shown": escaped, "text": escaped,
        "attrs": {"title": escaped, "aria-label": escaped, "placeholder": escaped, "data-value": text, "value": text}}


def test_an_event_s_bidi_controls_show_as_escapes_on_the_timeline_its_hover_and_its_page(browser, synthetic_case):  # noqa: F811
    """An event whose file name, message, account, and source address hold a right-to-left override. The lanes by user,
    the hover on its tick, a logon link's hover, its Event page, the address menu, and the status line after Add to view
    filter each show the override as [U+202E]. The address menu's Search item and the account's Add to search put the
    values in the search box as recorded. The view filter holds the account as recorded, so the event still shows and
    the button reads Remove. A click on the File value, and Copy as JSON, copy the values as recorded."""
    uid = imported(synthetic_case)
    seen = {}
    for p in served_page(browser, synthetic_case):
        p.locator("#groupby").select_option("3")   # User > Host
        p.wait_for_function("(user) => window.__app.S.rows.some((r) => r.depth === 0 && r.keys?.[0] === user)", arg=USER)
        at = p.evaluate("(user) => window.__app.S.rows.findIndex((r) => r.depth === 0 && r.keys?.[0] === user)", USER)
        label = p.locator(f"#labels .row[data-row='{at}']")
        assert label.evaluate("(r) => r.childNodes[1].textContent") == shown(USER)
        assert label.get_attribute("title") == f"User: {shown(USER)}"
        seen["lanes by user"] = raw_controls(p)

        wait_drawn(p, uid)   # the lanes answer before the view that draws the event under them
        tick = point_of(p, uid)
        tip = tooltip_for(p, tick["x"], tick["y"])
        assert tip.inner_text().splitlines()[-1].endswith(f"UTC · {shown(MESSAGE)}")
        seen["hover"] = raw_controls(p)
        p.mouse.move(0, 0)
        link = {"source": f"WS{RLO}1", "target": "DC01", "accounts": [USER], "count": 2, "ts": 1600485900000000,
                "kinds": ["4624 type 3"], "uid": None}
        assert p.evaluate(LINK_TIP, link) == [f"WS[U+202E]1 -> DC01 (2 logons)\n{shown(USER)}\n4624 type 3\n"
                                              "2020-09-19 03:25:00.000000 UTC, the middle one\nClick to zoom in"]

        select(p, uid)
        assert field_value(p, "File").evaluate("(dd) => dd.firstChild.textContent") == shown(FILE)
        assert p.locator("#details .ev-message").inner_text() == shown(MESSAGE)
        seen["Event page"] = raw_controls(p)

        field_value(p, "Source IP").locator("button[aria-haspopup='menu']").click()
        menu = p.locator("#quickMenu")
        menu.wait_for()
        assert menu.get_attribute("aria-label") == f"View {shown(ADDRESS)}"
        seen["address menu"] = raw_controls(p)
        menu.get_by_role("menuitem").filter(has_text="Search addr:").click()
        field_value(p, "Account").locator("button.addsearch").click()
        assert p.locator("#search").input_value() == f"addr:{ADDRESS} user:{USER}"

        toggle = field_value(p, "Account").locator("button.viewtoggle")
        with filtered_view(p):
            toggle.click()
        assert p.evaluate("window.__app.S.viewSpec.values") == [{"user": USER}]
        p.wait_for_function("(uid) => window.__app.S.data.events.some((e) => e.uid === uid)", arg=uid)
        assert field_value(p, "Account").locator("button.viewtoggle").inner_text() == "Remove from view filter"
        status = p.locator("#status")
        assert status.inner_text().startswith(f"Added to the view filter: Account {shown(USER)}")
        assert status.get_attribute("title") == status.inner_text()
        seen["status line"] = raw_controls(p)

        p.evaluate(RECORD_COPIES)
        field_value(p, "File").click(position={"x": 3, "y": 6})
        p.wait_for_function("() => window.__copied.length === 1")
        assert p.evaluate("window.__copied") == [FILE]
        p.locator("#details details.raw").evaluate("(d) => { d.open = true; }")
        p.get_by_role("button", name="Copy as JSON").click()
        p.wait_for_function("() => window.__copied.length === 2")
        copied = json.loads(p.evaluate("window.__copied[1]"))
        assert [copied[k] for k in ("file_path", "message", "user_name", "source_ip")] == [FILE, MESSAGE, USER, ADDRESS]
    assert seen == {stop: [] for stop in seen}


def test_a_search_its_list_s_find_and_an_account_pivot_show_bidi_controls_as_escapes(browser, synthetic_case):  # noqa: F811
    """A search whose highlight spans a right-to-left override marks it shown as [U+202E], on its list and on the Event
    page opened from it. A word the list's find box marks is shown the same way, and so are the account pivot's heading
    and its Add to view filter button."""
    uid = imported(synthetic_case)
    seen = {}
    for p in served_page(browser, synthetic_case):
        p.locator("#search").fill("report*fdp")
        p.locator("#search").press("Enter")
        hit = p.locator("#details[data-page='search'] .related li.rel-row .rel-event mark")
        hit.first.wait_for()
        assert hit.first.inner_text() == shown(f"report{RLO}fdp")
        seen["search list"] = raw_controls(p)

        p.locator("#details .related .find input").fill("fdp")
        p.locator("#details .related mark.find-hit").first.wait_for()
        seen["list find"] = raw_controls(p)

        p.locator("#details .related li.rel-row .rel-event").first.click()
        p.wait_for_selector(f"#details[data-key='event:{uid}'] .ev-message mark")
        assert p.locator("#details .ev-message mark").inner_text() == shown(f"report{RLO}fdp")
        p.wait_for_function(COUNTED)
        seen["Event page from the search"] = raw_controls(p)

        pv(p, "account").locator("button.pv-go").click()
        heading = p.locator("#relatedList .sticky-head")
        heading.locator("button.viewtoggle").wait_for()
        assert heading.locator("button.viewtoggle").inner_text() == f"Add Account {shown(USER)} to view filter"
        seen["account pivot"] = raw_controls(p)
    assert seen == {stop: [] for stop in seen}


def test_the_pivot_caveat_names_the_long_path_of_an_83_path_with_its_bidi_control_shown(browser, synthetic_case, tmp_path):  # noqa: F811
    """A service installed from an 8.3 path whose long name, by DC01's MFT, holds a right-to-left override. The Same
    file row's caveat names the long path as the MFT wrote it, and the row's list notes it, each with the override shown
    as [U+202E]."""
    mft = fx.mft_events(tmp_path, "DC01", [(".\\Users", "Public/"), (".\\Users\\Public", NAME)])
    load_events(synthetic_case, mft, "DC01", tool="mftecmd", run="bidi_mft")
    load_events(synthetic_case, [system_event(T0 + 90 * SEC, 9990, "7045", {"ServiceName": "Updater", "ImagePath": SHORT},
                                              file_path=SHORT, file_key=file_key(SHORT), **INSTALLER)], "DC01", run="bidi_svc")
    with connect(synthetic_case.db_path, read_only=True) as con:
        install = uid_of(con, "event_code = '7045' AND record_id = 9990")
    written = f"\\Users\\Public\\{NAME}"   # the path as the MFT writes it
    note = f"This 8.3 path stands for {shown(written)}, by DC01's MFT."
    seen = {}
    for p in served_page(browser, synthetic_case):
        select(p, install)
        assert pv(p, "file").locator(".pv-caveat").text_content() == f"Caveat: {note}"
        seen["Event page"] = raw_controls(p)

        pv(p, "file").locator("button.pv-go").click()
        p.locator("#relatedList p.muted").filter(has_text=note).wait_for()
        seen["Same file list"] = raw_controls(p)
    assert seen == {stop: [] for stop in seen}


def test_the_hosts_button_names_a_mixed_host_with_its_bidi_control_shown(browser, tmp_path):  # noqa: F811
    """A host whose name holds a left-to-right isolate and whose event logs record three computers: the Hosts button's
    hover names it as LAB[U+2066], as its lane does."""
    case = mixed_case(tmp_path)
    for p in served_page(browser, case):
        button = p.locator("#hostsButton")
        p.wait_for_function("() => document.getElementById('hostsButton').title.includes('split by recorded computer')")
        assert f". {shown(MIXED)} can be split by recorded computer: open Hosts." in button.get_attribute("title")
        assert shown(MIXED) in p.locator("#labels").inner_text()
        assert raw_controls(p) == []


def test_the_sources_panel_shows_a_file_name_s_bidi_control_and_its_find_takes_the_shown_text_or_the_character(
        browser, synthetic_case):  # noqa: F811
    """An imported file whose name holds a right-to-left override. The Sources panel's row, its hover, and its box's
    label show the override as [U+202E], and the panel's find box finds the file by the text the row shows or by the
    character itself."""
    imported(synthetic_case, SOURCE)
    seen = {}
    for p in served_page(browser, synthetic_case):
        p.locator("#filtersButton").click()
        p.locator("#fpTree .frow").first.wait_for()
        files = p.locator("#fpTree .frow.d2")
        for stop, query in (("find by the shown text", shown(SOURCE)[:12]), ("find by the character", SOURCE[:5])):
            p.locator("#fpFind").fill(query)
            assert files.locator(".name").all_inner_texts() == [shown(SOURCE)], stop
            assert files.locator("input[type='checkbox']").get_attribute("aria-label") == f"Show {shown(SOURCE)} on DC01"
            seen[stop] = raw_controls(p)
    assert seen == {stop: [] for stop in seen}


def test_the_start_page_s_folder_checks_show_bidi_controls_as_escapes(browser, tmp_path):  # noqa: F811
    """An evidence folder whose name, and one of whose top-level folders' names, hold a right-to-left override. The
    check's note, its copies warning, and the folder browser show the override as [U+202E]. The path in the box, which
    the check reads, the folder a click in the browser opens, and the path Use this folder puts in the box keep it as
    written."""
    evidence = tmp_path / f"ev{RLO}idence"
    for top in (f"copy{RLO}A", "triage"):
        (evidence / top / "WIN1" / "Windows").mkdir(parents=True)
        (evidence / top / "WIN1" / "Windows" / "notes.txt").write_text("x", encoding="utf-8")
    seen = {}
    for p in served_page(browser, None, ready=START_READY):
        field = p.locator(".start-field", has=p.get_by_label("Evidence folder", exact=True))
        field.get_by_label("Evidence folder", exact=True).fill(str(evidence))
        p.wait_for_function("() => document.querySelector('[data-check=\"evidence\"]').textContent.startsWith('Found')")
        assert p.locator('[data-check="evidence"]').inner_text() == "Found 2 files, 0 KB, in 2 folders: copy[U+202E]A, triage."
        copies = p.locator('[data-check="evidence-copies"]')
        assert copies.inner_text().startswith("copy[U+202E]A and triage each hold a host folder of their own")
        seen["the check"] = raw_controls(p)

        field.get_by_role("button", name="Browse").click()
        folders = p.locator(".start-browser li button")
        folders.first.wait_for()
        assert folders.all_inner_texts() == ["copy[U+202E]A", "triage"]
        assert p.locator(".start-browser .mono").first.inner_text() == shown(str(evidence))
        assert field.get_by_label("Evidence folder", exact=True).input_value() == str(evidence)
        seen["the folder browser"] = raw_controls(p)

        folders.first.click()
        p.wait_for_function("(path) => window.__start.browsing?.listing?.path === path", arg=str(evidence / f"copy{RLO}A"))
        assert folders.all_inner_texts() == ["WIN1"]
        seen["a folder opened from the browser"] = raw_controls(p)

        p.get_by_role("button", name="Use this folder").click()
        assert field.get_by_label("Evidence folder", exact=True).input_value() == str(evidence / f"copy{RLO}A")
    assert seen == {stop: [] for stop in seen}
