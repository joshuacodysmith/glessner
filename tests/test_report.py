"""The report, the scoped exports, the indicators, and the audit trail's cut of long event names, on the server side: the
report's seven sections and head lines, the report_summary setting's replay and audit wording, each export's scope, the
indicators drawn only from Malicious marks and parsed fields, the columns for network sources, the exports page's
endpoint, a View's search worded through Term.describe, and the cut in the trail and its export."""

import csv
import json
import re
from pathlib import Path

import pytest
from chain_fixtures import AT, chained, note, unchained
from conftest import NETWORK_CAPTURE, SEC, T0
from pivot_key_fixtures import AUTORUNS_COLUMNS, autoruns_row, csv_file, folder_of, run
from test_server import login, request

from glessner import server
from glessner.audit import cut_name, describe, file_words, read_entries
from glessner.caveats import table
from glessner.events import Event, load
from glessner.export import NO_SUMMARY, SECTIONS, _local, _md, indicators
from glessner.filters import describe as describe_filter
from glessner.filters import normalize, view_terms
from glessner.heads import forget
from glessner.journal import JOURNAL_FILE, replay
from glessner.parsers import PARSERS, ParseContext
from glessner.server import (
    App,
    api_audit,
    api_audit_export,
    api_export,
    api_exports_page,
    api_filter,
    api_finding,
    api_indicators,
    api_mark,
    api_report,
    api_report_preview,
    api_setting,
)

LONG = ("Alert: ET EXPLOIT_KIT Neutrino EK Landing Page (A Network Trojan was detected, severity 1) http "
        "192.185.21.183:80 -> 192.168.122.52:49200 HTTP GET st.domandvilma.com/fvviewforumqn.php")
# A capture's records with the fields the network columns and the indicators read: an alert with a community ID, a DNS query
# in EVE's v2 layout, an HTTP request to a host written as an address, a TLS server name, a DHCP lease, and a file's hash
EVE = [
    {"timestamp": "2020-09-19T03:50:00.000000+0000", "flow_id": 11, "community_id": "1:abc=", "event_type": "alert",
     "src_ip": "203.0.113.80", "src_port": 80, "dest_ip": "10.0.0.5", "dest_port": 49200, "proto": "TCP",
     "alert": {"signature_id": 2100498, "signature": "GPL ATTACK_RESPONSE id check returned root", "category": "Bad",
               "severity": 2}},
    {"timestamp": "2020-09-19T03:50:01.000000+0000", "flow_id": 12, "event_type": "dns", "src_ip": "10.0.0.5",
     "src_port": 53000, "dest_ip": "10.0.0.1", "dest_port": 53, "proto": "UDP",
     "dns": {"type": "request", "queries": [{"rrname": "update.evil.example", "rrtype": "A"}]}},
    {"timestamp": "2020-09-19T03:50:02.000000+0000", "flow_id": 11, "event_type": "http", "src_ip": "10.0.0.5",
     "src_port": 49200, "dest_ip": "203.0.113.80", "dest_port": 80, "proto": "TCP",
     "http": {"hostname": "203.0.113.80", "url": "/payload.exe", "http_method": "GET", "status": 200}},
    {"timestamp": "2020-09-19T03:50:03.000000+0000", "flow_id": 13, "event_type": "tls", "src_ip": "10.0.0.5",
     "src_port": 49300, "dest_ip": "198.51.100.9", "dest_port": 443, "proto": "TCP",
     "tls": {"sni": "c2.example", "version": "TLS 1.2"}},
    {"timestamp": "2020-09-19T03:50:04.000000+0000", "flow_id": 14, "event_type": "dhcp", "src_ip": "0.0.0.0",
     "src_port": 68, "dest_ip": "255.255.255.255", "dest_port": 67, "proto": "UDP",
     "dhcp": {"type": "request", "client_mac": "00:26:55:32:a9:17", "dhcp_type": "ack"}},
    {"timestamp": "2020-09-19T03:50:05.000000+0000", "flow_id": 11, "event_type": "fileinfo", "src_ip": "203.0.113.80",
     "src_port": 80, "dest_ip": "10.0.0.5", "dest_port": 49200, "proto": "TCP",
     "fileinfo": {"filename": "/payload.exe", "size": 126, "sha256": "a" * 64}},
]


def entries(case):
    return read_entries(case.folder / JOURNAL_FILE)


def uid_at(app, ts, tool="evtxecmd"):
    return app.con.execute("SELECT event_uid FROM events WHERE tool = ? AND ts_us = ?", [tool, ts]).fetchone()[0]


def load_eve(case):
    """EVE's records as Suricata's run on the capture, in a network lane of their own."""
    out = case.folder.parent / "eve_run"
    out.mkdir()
    (out / "eve.json").write_text("".join(json.dumps(r) + "\n" for r in EVE), encoding="utf-8")
    events = PARSERS["suricata_eve"](ParseContext(out, case.evidence, (NETWORK_CAPTURE,)))
    load(case.db_path, events, host="network", tool="suricata", tool_version="8.0.7", run_id="r6",
         replaces_sources=[NETWORK_CAPTURE], staging_dir=out)


def section(text, number):
    """One numbered section of the report, from its heading to the next."""
    start = text.index(f"\n## {number}. ")
    rest = text[start + 1:]
    end = rest.find(f"\n## {number + 1}. ")
    return rest if end < 0 else rest[:end]


def test_the_report_has_its_seven_sections_with_the_analysts_words_and_the_head(synthetic_case):
    """The report in seven sections, in order: the Summary as written; each finding with its severity,
    techniques, supporting events as entries of the timeline or not, its caveats, and a retired one named and left out;
    the timeline's events each with its finding; the caveats of the marked evidence after it; the indicators from the
    one Malicious mark, with the case's own address left out; the hosts; the evidence check and the head lines; and the
    runs. Its file entry is of kind report with the printed head. The preview is the same text with no file, no entry,
    and no re-hash, and says so. With the summary cleared, the report says no summary has been written."""
    app = App(synthetic_case, for_work=True)
    try:
        rdp, morty, dc = uid_at(app, T0), uid_at(app, T0 + 60 * SEC), uid_at(app, T0 + 62 * SEC)
        api_mark(app, {"uids": [rdp], "value": "malicious", "note": "RDP from the internet"})
        api_mark(app, {"uids": [morty], "value": "suspicious"})
        api_finding(app, {"op": "add", "title": "RDP from the internet", "severity": "High", "techniques": ["T1021.001"],
                          "narrative": "Administrator came in over RDP.", "targets": [rdp, dc]})
        scratch = api_finding(app, {"op": "add", "title": "Scratch", "severity": "Low", "targets": []})["finding"]
        api_finding(app, {"op": "retire", "finding": scratch, "reason": "a test"})
        api_setting(app, {"name": "report_summary", "value": "An attacker logged on over RDP.\r\n\r\nThen moved on.\n"})
        res = api_report(app, {})
        text = Path(res["path"]).read_text(encoding="utf-8")
        assert text.startswith("# Report: Synthetic\n\nGenerated ")
        assert " for cody. The summary and the findings are the analyst's words." in text
        heads = [line for line in text.splitlines() if line.startswith("## ")]
        assert heads == [f"## {n}. {s}" for n, s in enumerate(SECTIONS, 1)]
        assert section(text, 1) == "## 1. Summary\n\nAn attacker logged on over RDP.\n\nThen moved on.\n"
        findings = section(text, 2)
        assert "### 1. RDP from the internet\n\nHigh. ATT&CK: T1021.001. 2 supporting events; added " in findings
        assert "\n\nAdministrator came in over RDP.\n\n- Entry 1: 2020-09-19 03:21:48.000000 UTC, DC01, 4624 logon\n" in findings
        assert "- Not in the timeline (Unreviewed): 2020-09-19 03:22:50.000000 UTC, DC01, 4624 logon\n" in findings
        logon = next(c for c in table() if c["id"] == "logon")
        assert (f"Does not prove:\n\n- **Logon events 4624 and 4625.** {_md(logon['text'])} Sources: "
                "[Microsoft, event 4624](") in findings
        assert "### 2." not in findings and 'Retired finding, left out: 2. Scratch (retired ' in findings
        assert 'reason: "a test").' in findings
        timeline = section(text, 3)
        assert ("1. **2020-09-19 03:21:48.000000 UTC, DC01, Malicious.** 4624 logon\n   - Finding: 1. RDP from the internet\n"
                "   - Mark note: RDP from the internet\n") in timeline
        assert ("2. **2020-09-19 03:22:48.000000 UTC, DC01, Suspicious.** 4624 logon\n   - Source: evtxecmd t, run `r1`"
                in timeline)
        assert "\n### What the marked evidence does not prove\n" in timeline
        assert f"- **Logon events 4624 and 4625** (2 marked): {_md(logon['text'])} Sources: " in timeline
        found = section(text, 4)
        assert "Taken only from the 1 event marked Malicious, from fields the tools parsed" in found
        assert "| IP address | `194.61.24.102` | 1 | 2020-09-19 03:21:48.000000 UTC | 2020-09-19 03:21:48.000000 UTC |" in found
        assert "| Account | `C137\\Administrator` | 1 |" in found and "10.42.85" not in found and "mortysmith" not in found
        assert "| DC01 | Domain controllers (guessed) | Not recorded | CITADEL-DC01 | 10.42.85.10 | none |" in section(text, 5)
        integrity = section(text, 6)
        assert "No intake manifest exists, so evidence hashes were not checked." in integrity
        assert "Journal: " in integrity and "consistent: each names the one before it." in integrity
        assert "| `r1` | evtxecmd | t | DC01 | 5 |  |" in section(text, 7) and "Written by glessner " in section(text, 7)
        written = entries(synthetic_case)[-1]
        assert (written["kind"], written["rows"], written["scope"]) == ("report", 2, {"marks": "flagged"})
        assert f"Journal head when written: `{written['journal_head']}` (entry #{written['head_seq']})" in integrity
        assert describe(written).startswith(f"Wrote {Path(res['path']).name}: report, whole case, 2 events, SHA-256 ")
        # The preview: the same sections, no file, no entry, and no re-hash
        before, files = len(entries(synthetic_case)), sorted((synthetic_case.folder / "exports").iterdir())
        preview = api_report_preview(app, {})
        assert preview["events"] == 2 and "## 1. Summary\n\nAn attacker logged on over RDP." in preview["text"]
        assert "The evidence is re-hashed when the report is written, not for a preview." in preview["text"]
        assert len(entries(synthetic_case)) == before and sorted((synthetic_case.folder / "exports").iterdir()) == files
        # An empty summary says so
        api_setting(app, {"name": "report_summary", "value": "   "})
        assert section(api_report_preview(app, {})["text"], 1) == f"## 1. Summary\n\n{NO_SUMMARY}\n"
    finally:
        app.con.close()


def test_the_report_summary_is_a_case_setting_that_replays_and_reads_in_the_trail(running):
    """The Summary is journaled as the case_setting report_summary, over HTTP: replay gives it back, the trail words it
    with the text cut at a boundary (cut_name) and quoted, an empty value clears it and reads so, and a value that is not
    text, or is too long, is refused with 400."""
    app, port, _ = running
    session = login(port, app)
    post = lambda body: request(port, "POST", "/api/setting", session=session, body={"name": "report_summary", **body})
    text = ("The attacker logged on to DC01 over RDP from 194.61.24.102 at 03:21:48 UTC, " * 3).strip()
    res, body = post({"value": f"  {text}\r\n"})
    assert res.status == 200 and json.loads(body)["value"] == text
    assert app.journal.state.settings["report_summary"] == text
    assert replay(app.journal.path).settings["report_summary"] == text
    entry = entries(app.case)[-1]
    assert (entry["action"], entry["name"], entry["value"]) == ("case_setting", "report_summary", text)
    words = describe(entry)
    assert words.startswith('Wrote the report summary: "The attacker logged on to DC01 over RDP from 194.61.24.102 at ')
    cut = words[len('Wrote the report summary: "'):-1]
    assert cut.endswith(" …") and len(cut) <= 103 and text.startswith(cut[:-2]) and text[len(cut) - 2] == " "   # at a word
    assert api_audit(app, {"kind": ["Settings"]})["rows"][0]["text"] == words
    res, body = post({"value": ""})
    assert res.status == 200 and app.journal.state.settings["report_summary"] == ""
    assert describe(entries(app.case)[-1]) == "Cleared the report summary"
    for bad in (5, None, ["a"], "x" * 20_001):
        res, body = post({"value": bad})
        assert res.status == 400 and "report_summary is text" in json.loads(body)["error"], bad


def test_marked_exports_cover_the_whole_case_and_the_window_export_keeps_its_window(synthetic_case):
    """Marked events and Malicious-and-Suspicious-only exports cover the whole case whatever the window, an event with
    no time last, and their file entries carry no start or end; All events keeps the window. Each file is named by its
    scope, and the trail words it. The indicators file is of kind indicators and counts values."""
    bag = "DESKTOP/Users/rick/NTUSER.DAT"
    load(synthetic_case.db_path, [Event(None, "ShellBag", "shellbags", bag, "bag1", "ShellBag loot")],
         host="DESKTOP", tool="sbecmd", tool_version="t", run_id="r9", replaces_sources=[bag],
         staging_dir=synthetic_case.folder)
    app = App(synthetic_case, for_work=True)
    try:
        rdp, morty = uid_at(app, T0), uid_at(app, T0 + 60 * SEC)
        untimed = app.con.execute("SELECT event_uid FROM events WHERE tool = 'sbecmd'").fetchone()[0]
        api_mark(app, {"uids": [rdp, untimed], "value": "malicious"})
        api_mark(app, {"uids": [morty], "value": "authorized"})
        minute = {"start": T0, "end": T0 + 1}
        marked = api_export(app, {"format": "csv", "marks": "marked", **minute})
        with Path(marked["path"]).open(encoding="utf-8", newline="") as f:
            rows = list(csv.DictReader(f))
        assert marked["rows"] == 3 and marked["scope"] == {"marks": "marked"}
        assert Path(marked["path"]).name.startswith("marked_events_")
        assert [r["event_uid"] for r in rows] == [rdp, morty, untimed] and rows[-1]["datetime"] == ""   # whole case, untimed last
        flagged = api_export(app, {"format": "jsonl", "marks": "flagged"})   # no window given
        assert flagged["rows"] == 2 and flagged["scope"] == {"marks": "flagged"}
        assert Path(flagged["path"]).name.startswith("flagged_events_")
        window = api_export(app, {"format": "csv", "marks": "all", **minute})
        assert window["rows"] == 1 and window["scope"] == {"marks": "all", **minute}
        assert Path(window["path"]).name.startswith("timeline_all_")
        made = {e["seq"]: e for e in entries(synthetic_case) if e["action"] == "file_written"}
        assert made[marked["head_seq"]]["scope"] == {"marks": "marked"}
        assert made[window["head_seq"]]["scope"] == {"marks": "all", **minute}
        assert describe(made[marked["head_seq"]]).startswith(
            f"Wrote {Path(marked['path']).name}: timeline, marked events, whole case, 3 events, ")
        assert describe(made[window["head_seq"]]).startswith(
            f"Wrote {Path(window['path']).name}: timeline, all events from 2020-09-19 03:21:48")
        found = api_indicators(app, {})
        entry = entries(synthetic_case)[-1]
        assert (entry["kind"], entry["format"], entry["rows"], found["values"], found["events"]) == ("indicators", "csv", 2, 2, 2)
        assert describe(entry).startswith(f"Wrote {Path(found['path']).name}: indicators, from the Malicious marks, 2 values, ")
        assert Path(found["path"]).name.startswith("indicators_")
    finally:
        app.con.close()


def test_indicators_come_only_from_malicious_marks_and_parsed_fields(synthetic_case):
    """The indicators are the values among the events marked Malicious, from parsed fields alone: an address in a
    message is not read, a Suspicious event's values are not taken, and the case's own hosts' addresses are left out. A
    network record gives its DNS name, HTTP host (an address, typed so), TLS server name, and file hash."""
    load_eve(synthetic_case)
    app = App(synthetic_case, for_work=True)
    try:
        rdp, morty, dc = uid_at(app, T0), uid_at(app, T0 + 60 * SEC), uid_at(app, T0 + 62 * SEC)   # dc: DC01 to itself
        app.con.execute("UPDATE events SET message = '4624 logon from 203.0.113.9 as evil\\bob' WHERE event_uid = ?", [rdp])
        api_mark(app, {"uids": [rdp, dc], "value": "malicious"})
        api_mark(app, {"uids": [morty], "value": "suspicious"})   # mortysmith from 10.42.85.115: not taken
        found = indicators(app.con, [rdp, dc], app.identity)
        assert [(g["type"], g["value"], g["events"], g["first"], g["last"]) for g in found] == [
            ("IP address", "194.61.24.102", 1, T0, T0), ("Account", "C137\\Administrator", 2, T0, T0 + 62 * SEC)]
        assert indicators(app.con, [], app.identity) == []
        # A logon's process is the logon process, an ordinary Windows binary: the Security 4624 gives no File indicator, and a
        # 4688 (process creation, where the process is the subject) does
        winlogon, evil = "C:\\Windows\\System32\\winlogon.exe", "C:\\Temp\\evil.exe"
        app.con.execute("UPDATE events SET process_executable = ? WHERE event_uid = ?", [winlogon, rdp])
        app.con.execute("UPDATE events SET event_code = '4688', process_executable = ? WHERE event_uid = ?", [evil, dc])
        files = {v for t, v in ((g["type"], g["value"]) for g in indicators(app.con, [rdp, dc], app.identity)) if t == "File"}
        assert files == {evil}
        # A 4648's process is the one that used the explicit credentials, such as PsExec run with -u: the subject, not the
        # logon process, so it stays
        psexec = "C:\\Users\\Public\\PsExec.exe"
        app.con.execute("UPDATE events SET event_code = '4648', process_executable = ? WHERE event_uid = ?", [psexec, dc])
        files = {v for t, v in ((g["type"], g["value"]) for g in indicators(app.con, [rdp, dc], app.identity)) if t == "File"}
        assert files == {psexec}
        app.con.execute("UPDATE events SET event_code = '4624' WHERE event_uid = ?", [dc])
        net = [r[0] for r in app.con.execute("SELECT event_uid FROM events WHERE tool = 'suricata' ORDER BY ts_us").fetchall()]
        api_mark(app, {"uids": net, "value": "malicious"})
        found = {(g["type"], g["value"]): g["events"] for g in indicators(app.con, [rdp, dc, *net], app.identity)}
        assert found[("Domain", "update.evil.example")] == 1 and found[("Domain", "c2.example")] == 1
        assert found[("IP address", "203.0.113.80")] == 3 and found[("SHA-256", "a" * 64)] == 1   # the HTTP host is an address
        assert ("IP address", "10.42.85.10") not in found and ("IP address", "0.0.0.0") not in found
        assert ("IP address", "255.255.255.255") not in found   # the DHCP request's broadcast destination
        assert ("Domain", "203.0.113.80") not in found
        assert not any(v == "203.0.113.9" or "bob" in v for _, v in found)
        with Path(api_indicators(app, {})["path"]).open(encoding="utf-8", newline="") as f:
            rows = list(csv.DictReader(f))
        assert rows[0] == {"type": "IP address", "value": "194.61.24.102", "marked_events": "1",
                           "first_seen": "2020-09-19T03:21:48.000000Z", "last_seen": "2020-09-19T03:21:48.000000Z", "note": ""}
        assert {(r["type"], r["value"]) for r in rows} == set(found)
    finally:
        app.con.close()


SYSTEM_TOOL_NOTE = "In the Windows folder: may be a system tool the attacker used. Check before you block it."
POWERSHELL = "c:\\windows\\system32\\windowspowershell\\v1.0\\powershell.exe"


def test_a_windows_system_tool_stays_among_the_indicators_with_a_note_on_its_row(synthetic_case, tmp_path):
    """An Autoruns Run-key entry marked Malicious whose target is powershell.exe lists the path as a File value, in the
    table, indicators.csv, and the report, with a note that it may be a system tool the attacker used. A file outside the
    Windows folders, marked the same way, has no note."""
    out = folder_of(tmp_path, "autoruns")
    csv_file(out / "autoruns.csv", AUTORUNS_COLUMNS, [
        autoruns_row("Updater", POWERSHELL, f"{POWERSHELL} -nop -w hidden -c iex"),
        autoruns_row("Dropped", "c:\\users\\public\\updater.exe", "c:\\users\\public\\updater.exe -q")])
    load(synthetic_case.db_path, run("autoruns_csv", out, root=tmp_path), host="DC01", tool="autoruns", tool_version="t",
         run_id="r20", replaces_sources=[], staging_dir=out)
    app = App(synthetic_case, for_work=True)
    try:
        uids = [r[0] for r in app.con.execute("SELECT event_uid FROM events WHERE artifact = 'autoruns'").fetchall()]
        assert len(uids) == 2
        api_mark(app, {"uids": uids, "value": "malicious"})
        files = {g["value"]: g["note"] for g in indicators(app.con, uids, app.identity) if g["type"] == "File"}
        assert files == {POWERSHELL: SYSTEM_TOOL_NOTE, "c:\\users\\public\\updater.exe": ""}
        with Path(api_indicators(app, {})["path"]).open(encoding="utf-8", newline="") as f:
            rows = {(r["type"], r["value"]): r["note"] for r in csv.DictReader(f)}
        assert rows[("File", POWERSHELL)] == SYSTEM_TOOL_NOTE and rows[("File", "c:\\users\\public\\updater.exe")] == ""
        text = Path(api_report(app, {})["path"]).read_text(encoding="utf-8")
        listed = section(text, SECTIONS.index("Indicators") + 1).splitlines()
        assert "| Type | Value | Marked events | First seen | Last seen | Note |" in listed
        row = lambda value: next(line for line in listed if line.startswith(f"| File | `{value}` | 1 | "))
        assert row(POWERSHELL).endswith(f" | {SYSTEM_TOOL_NOTE} |")
        assert row("c:\\users\\public\\updater.exe").endswith(" |  |")
    finally:
        app.con.close()


def test_the_note_marks_a_file_in_the_windows_system_folders_whatever_its_case_slashes_or_drive(synthetic_case):
    """The Windows folder's own files and everything below its System32, SysWOW64, and Sysnative folders count, on any
    drive, with either slash after a drive or SYSVOL, in any case, and as an MFT, a prefetch file, or a variable writes
    them. The Windows folder's other folders, which a dropped file can sit in, and look-alike names do not, and neither
    does a name with no folder, a path with no root, or one that starts with a single forward slash."""
    noted = [
        "C:\\Windows\\System32\\cmd.exe", "c:\\WINDOWS\\system32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "c:/windows/system32/cmd.exe", "C:/Windows\\SysWOW64/cmd.exe", "D:\\Windows\\Sysnative\\cmd.exe",
        "C:\\Windows\\explorer.exe", ".\\Windows\\System32\\cmd.exe", "\\Windows\\System32\\cmd.exe",
        "%SystemRoot%\\System32\\cmd.exe", "\\\\?\\C:\\Windows\\System32\\cmd.exe",
        "\\VOLUME{01d6a1b2c3d4e5f6-12345678}\\WINDOWS\\SYSTEM32\\CMD.EXE",
        # The forms the registry, SRUM, and Security log parsers write: a device path, a domain controller's system volume,
        # NT's \??\ and \SystemRoot, a variable, a shell path, and a doubled backslash
        "\\Device\\HarddiskVolume3\\Windows\\System32\\cmd.exe", "\\device\\harddiskvolume2\\windows\\system32\\svchost.exe",
        "SYSVOL\\Windows\\System32\\services.exe", "sysvol\\windows\\explorer.exe", "SYSVOL/Windows/System32/services.exe",
        "sysvol/windows\\explorer.exe", "\\??\\C:\\Windows\\System32\\cmd.exe",
        "\\SystemRoot\\System32\\drivers\\evil.sys", "%windir%\\system32\\cmd.exe", "This PC\\C:\\Windows\\System32\\cmd.exe",
        "C:\\Windows\\\\System32\\cmd.exe"]
    plain = [
        "C:\\Windows\\Temp\\evil.exe", "C:\\Windows\\Tasks\\evil.exe", "C:\\Users\\Public\\Windows\\System32\\cmd.exe",
        "C:\\Temp\\cmd.exe", "C:\\Windows\\System32x\\cmd.exe", "C:\\Windowsold\\System32\\cmd.exe", "cmd.exe",
        "C:\\Program Files\\Windows\\cmd.exe", "SYSVOL\\Temp\\Windows\\cmd.exe", "SYSVOLX\\Windows\\System32\\cmd.exe",
        "\\Device\\HarddiskVolume3\\Temp\\cmd.exe", "\\??\\C:\\Users\\Public\\cmd.exe",
        # A path that starts with one forward slash is a URL or Unix path, as in Suricata's file names, and one with no root
        # names no volume: neither says which folder it is in
        "/Windows/System32/cmd.exe", "Windows\\System32\\cmd.exe", "SYSVOL/Temp/Windows/cmd.exe"]
    app = App(synthetic_case, for_work=True)
    try:
        rdp = uid_at(app, T0)
        for path in (*noted, *plain):
            app.con.execute("UPDATE events SET file_path = ? WHERE event_uid = ?", [path, rdp])
            files = {g["value"]: g["note"] for g in indicators(app.con, [rdp], app.identity) if g["type"] == "File"}
            assert files == {path: SYSTEM_TOOL_NOTE if path in noted else ""}, path
    finally:
        app.con.close()


def test_the_report_names_a_who_that_is_not_a_string_as_the_audit_trail_does(synthetic_case):
    """Format 2's reader gives a line as written, so a line under the seal can hold a who that is a list, an object, a
    number, or null. The report names it by the JSON text the audit trail lists, in a note, in who added or edited a
    finding, and in who retired one, and the report is written."""
    app = App(synthetic_case, for_work=True)
    try:
        rdp = uid_at(app, T0)
    finally:
        app.con.close()
    finding = {"action": "finding", "at": AT}
    (synthetic_case.folder / JOURNAL_FILE).write_bytes(chained([], before=unchained(
        {"seq": 1, "at": AT, "who": "cody", "action": "mark", "targets": [rdp], "value": "malicious"},
        note(2, uid=rdp, text="seen on the wire", who=["cody", "ann"]),
        {**finding, "seq": 3, "who": {"by": "cody"}, "op": "add", "title": "Added by an object", "severity": "High",
         "targets": [rdp]},
        {**finding, "seq": 4, "who": 5, "op": "add", "title": "Edited by null", "severity": "High", "targets": []},
        {**finding, "seq": 5, "who": None, "op": "edit", "finding": 4, "narrative": "Changed."},
        {**finding, "seq": 6, "who": None, "op": "add", "title": "Retired by a list", "severity": "Low", "targets": []},
        {**finding, "seq": 7, "who": ["bob"], "op": "retire", "finding": 6})))
    forget(synthetic_case.folder)
    app = App(synthetic_case, for_work=True)
    try:
        text = Path(api_report(app, {})["path"]).read_text(encoding="utf-8")
    finally:
        app.con.close()
    who = lambda value: _md(json.dumps(value))
    assert f"   - Note ({AT}, {who(['cody', 'ann'])}): seen on the wire" in text
    assert f"; added 2026-10-17 02:14 UTC by {who({'by': 'cody'})}." in text
    assert "; edited 2026-10-17 02:14 UTC by null." in text   # not the empty name that str() of None would give
    assert f"Retired by a list (retired 2026-10-17 02:14 UTC by {who(['bob'])})" in text


def test_network_rows_carry_their_own_columns_and_windows_rows_keep_theirs(synthetic_case):
    """A network record's row names its signature as rule.name with rule.id and event.severity, its type as
    event.dataset in place of winlog.channel, its connection as network.community_id (a community ID and nothing else),
    network.flow_id (Suricata's flow ID), or zeek.uid (Zeek's uid), and url.full, dns.question.name, tls.server.name, and
    client.mac from its data; a Windows event keeps winlog.channel and Hayabusa's title in rule.name, with the network
    columns empty."""
    load_eve(synthetic_case)
    fast = Event(ts_us=T0 + 70 * SEC, ts_desc="Alert", artifact="ids_alert", source_file="fast.log", source_record="1",
                 message="[1:2001:1] ET TEST Leak", log_channel="Attempted Information Leak",
                 extra={"signature": "ET TEST Leak", "sid": "2001", "priority": "2"})
    zeek = Event(ts_us=T0 + 71 * SEC, ts_desc="http", artifact="zeek", source_file="http.log", source_record="1",
                 message="GET evil.example/a.exe", log_channel="http",
                 extra={"uid": "CabC1", "host": "evil.example", "uri": "/a.exe"})
    load(synthetic_case.db_path, [fast, zeek], host="network", tool="import", tool_version="t", run_id="r7",
         replaces_sources=["fast.log", "http.log"], staging_dir=synthetic_case.folder)
    app = App(synthetic_case)
    try:
        res = api_export(app, {"format": "csv", "marks": "all", "start": 0, "end": 2**53})
        with Path(res["path"]).open(encoding="utf-8", newline="") as f:
            rows = list(csv.DictReader(f))
        by = {r["event.dataset"]: r for r in rows if r["event.dataset"]}
        net = ("network.community_id", "network.flow_id", "zeek.uid", "url.full", "dns.question.name", "tls.server.name",
               "client.mac", "rule.id", "event.severity")
        assert set(by) == {f"suricata.{k}" for k in ("alert", "dns", "http", "tls", "dhcp", "fileinfo")} | {
            "ids_alert.alert", "zeek.http"}
        assert all(r["winlog.channel"] == "" for r in by.values())
        alert, dns, http = by["suricata.alert"], by["suricata.dns"], by["suricata.http"]
        # The community ID stays in its column when the sensor wrote one, with the flow ID beside it; a record with only a flow ID
        # leaves the community ID empty
        assert (alert["rule.name"], alert["rule.id"], alert["event.severity"], alert["network.community_id"],
                alert["network.flow_id"]) == ("GPL ATTACK_RESPONSE id check returned root", "2100498", "2", "1:abc=", "11")
        assert (dns["dns.question.name"], dns["network.community_id"], dns["network.flow_id"]) == (
            "update.evil.example", "", "12")
        assert (http["url.full"], http["network.community_id"], http["network.flow_id"]) == (
            "http://203.0.113.80/payload.exe", "", "11")
        # An imported fast alert's channel is its classification, so its dataset is the alert; Zeek's http.log gives its uid,
        # host and URI
        fast, zeek = by["ids_alert.alert"], by["zeek.http"]
        assert (fast["rule.name"], fast["rule.id"], fast["event.severity"], fast["winlog.channel"]) == (
            "ET TEST Leak", "2001", "2", "")
        assert (zeek["network.community_id"], zeek["network.flow_id"], zeek["zeek.uid"], zeek["url.full"]) == (
            "", "", "CabC1", "http://evil.example/a.exe")
        assert by["suricata.tls"]["tls.server.name"] == "c2.example"
        assert by["suricata.dhcp"]["client.mac"] == "00:26:55:32:a9:17"
        rdp = next(r for r in rows if r["event_uid"] == uid_at(app, T0))
        assert (rdp["winlog.channel"], rdp["event.dataset"], rdp["rule.name"]) == ("Security", "", "RDP from internet")
        assert [rdp[k] for k in net] == [""] * len(net)
    finally:
        app.con.close()


def test_the_exports_page_counts_and_lists_the_files_written_newest_first(synthetic_case, monkeypatch):
    """GET /api/exports_page: the counts the right column states before a click, the summary, and the files the case wrote
    (state.files) newest first, each with its SHA-256 short and in full and the trail's words, capped at FILES_SHOWN with
    the total beside."""
    from glessner import server

    app = App(synthetic_case, for_work=True)
    try:
        rdp, morty = uid_at(app, T0), uid_at(app, T0 + 60 * SEC)
        api_mark(app, {"uids": [rdp], "value": "malicious"})
        api_mark(app, {"uids": [morty], "value": "authorized"})
        api_setting(app, {"name": "report_summary", "value": "One line."})
        api_finding(app, {"op": "add", "title": "RDP", "severity": "High", "targets": [rdp]})
        scratch = api_finding(app, {"op": "add", "title": "Scratch", "severity": "Low", "targets": []})["finding"]
        api_finding(app, {"op": "retire", "finding": scratch})
        page = api_exports_page(app, {})
        assert {k: page[k] for k in ("summary", "findings", "retired", "marked", "flagged", "malicious", "indicators", "hosts",
                                     "evidence_files", "runs", "files", "files_total")} == {
            "summary": "One line.", "findings": 1, "retired": 1, "marked": 2, "flagged": 1, "malicious": 1, "indicators": 2,
            "hosts": 2, "evidence_files": 0, "runs": 5, "files": [], "files_total": 0}
        assert page["journal_entries"] == app.journal.chain.seq
        written = [api_report(app, {}), api_export(app, {"format": "csv", "marks": "marked"}), api_indicators(app, {}),
                   api_audit_export(app, {})]
        page = api_exports_page(app, {})
        files = page["files"]
        assert [f["kind"] for f in files] == ["audit_trail", "indicators", "timeline", "report"] and page["files_total"] == 4
        assert [f["seq"] for f in files] == [w["head_seq"] for w in reversed(written)]
        assert all(f["short"] == f"{f['sha256'][:8]}...{f['sha256'][-4:]}" and len(f["sha256"]) == 64 for f in files)
        assert files[3]["words"] == "report, whole case, 1 event" and files[2]["path"].startswith("exports/marked_events_")
        assert files[1]["words"] == "indicators, from the Malicious marks, 2 values"
        assert files[0]["rows"] == app.journal.chain.seq - 1
        monkeypatch.setattr(server, "FILES_SHOWN", 2)
        page = api_exports_page(app, {})
        assert [f["kind"] for f in page["files"]] == ["audit_trail", "indicators"] and page["files_total"] == 4
    finally:
        app.con.close()


def test_a_views_search_is_worded_through_its_terms():
    """filters.describe and view_terms word a View's search through each term's Term.describe, so a report that names a
    View's search says what it matched; the other fields keep their wording."""
    spec = normalize({"view": {"marks": ["Malicious"], "values": [
        {"search": 'nmap "evil tool" host:DC01 -rule:"RDP from internet"'}, {"addr": "10.0.2.17", "host": "DC01"}]}})
    search = ('a search for "nmap" anywhere and the words "evil tool" as whole words and host is "DC01" and events not hit '
              'by the Hayabusa rule "RDP from internet"')
    # normalize sorts the values, so the address pred comes before the search
    assert view_terms(spec) == ["marked Malicious", "with IP 10.0.2.17 at either end and host DC01", f"with {search}"]
    assert describe_filter(spec) == (f"View: events marked Malicious; or with IP 10.0.2.17 at either end and host DC01; "
                                     f"or with {search}.")
    # A search that doesn't parse reads as its text: a pred written past normalize, which refuses it when it is saved
    assert view_terms({"view": {"marks": [], "values": [{"search": "-host:DC01"}]}}) == ["with a search for -host:DC01"]
    only = normalize({"only": [{"search": '"nmap"'}]})
    assert describe_filter(only) == 'Only events with a search for the whole word "nmap".'


def test_the_trail_cuts_a_long_event_name_at_a_boundary_and_exports_it_whole(synthetic_case):
    """The trail's row carries the event it names with its whole name, its name cut at a word or address boundary
    with "…", its ID, and its time; the row's words hold the whole name, and so does the Markdown export. An entry of
    several events names none. cut_name's own cases: a short name whole, a cut before a separator and never inside an
    address, and a single run cut at the limit."""
    app = App(synthetic_case, for_work=True)
    try:
        rdp, morty, dc = uid_at(app, T0), uid_at(app, T0 + 60 * SEC), uid_at(app, T0 + 62 * SEC)
        app.con.execute("UPDATE events SET message = ? WHERE event_uid = ?", [LONG, rdp])
        api_mark(app, {"uids": [rdp], "value": "malicious"})
        api_mark(app, {"uids": [morty], "value": "suspicious"})
        api_mark(app, {"uids": [morty, dc], "value": "authorized"})
        both, short_row, long_row = api_audit(app, {})["rows"][:3]
        name = f"DC01 4624: {LONG}"
        assert long_row["text"] == f"Marked {name} Malicious" and long_row["event"]["name"] == name
        assert (long_row["event"]["uid"], long_row["event"]["ts"]) == (rdp, T0)
        cut = long_row["event"]["short"]
        assert cut.endswith(" …") and len(cut) <= 103 and name.startswith(cut[:-2]) and name[len(cut) - 2] in " |,;"
        assert "192.185.21.183:80" in cut or "192.185.21" not in cut   # never inside an address
        assert short_row["event"] == {"uid": morty, "name": "DC01 4624: 4624 logon", "short": "DC01 4624: 4624 logon",
                                      "ts": T0 + 60 * SEC}
        assert both["event"] is None and both["count"] == 2
        exported = Path(api_audit_export(app, {})["path"]).read_text(encoding="utf-8")
        assert f"Marked DC01 4624: {_md(LONG)} Malicious" in exported and "…" not in exported
    finally:
        app.con.close()
    assert cut_name("DC01 4624: 4624 logon") == "DC01 4624: 4624 logon"
    assert cut_name("x" * 100) == "x" * 100 and cut_name("x" * 101) == "x" * 100 + " …"
    assert cut_name("one two " * 20) == "one two " * 12 + "one …"   # cut at the last space before the 100th character
    # Before the separator, with the address whole
    assert cut_name("a |" + "192.0.2.1:443," * 20, 30) == "a |192.0.2.1:443,192.0.2.1:443 …"


def test_the_exports_pages_words_for_each_file_are_the_trails(synthetic_case):
    """The Findings page words a file as the audit trail does: a window export with the filters it applied, the flagged and
    the marked exports as the whole case, and the indicators and the report. state.files keeps each entry's scope and
    filters for it, so a filtered timeline file doesn't read "all events, whole case"."""
    app = App(synthetic_case, for_work=True)
    try:
        rdp = uid_at(app, T0)
        api_mark(app, {"uids": [rdp], "value": "malicious"})
        fid = api_filter(app, {"hide": [{"host": "DESKTOP"}]})["id"]
        api_export(app, {"format": "csv", "marks": "all", "start": T0, "end": T0 + 120 * SEC, "filter": fid})
        api_export(app, {"format": "jsonl", "marks": "flagged"})
        api_export(app, {"format": "csv", "marks": "marked"})
        api_indicators(app, {})
        api_report(app, {"filter": fid})
        written = [e for e in entries(synthetic_case) if e["action"] == "file_written"]
        words = [f["words"] for f in reversed(api_exports_page(app, {})["files"])]
        assert words == [file_words(e) for e in written] and len(words) == 5
        assert words[0].startswith("timeline, all events from 2020-09-19 03:21:48") and ", filtered: Hidden" in words[0]
        assert words[1] == "timeline, malicious and suspicious events, whole case, 1 event"
        assert words[2] == "timeline, marked events, whole case, 1 event"
        assert words[3] == "indicators, from the Malicious marks, 2 values"
        assert words[4].startswith("report, whole case, 1 event, filtered: ") and not words[4].endswith(".")
        assert not words[0].endswith(".") and ".," not in describe(written[0])   # the filter's period isn't followed by a comma
    finally:
        app.con.close()


def test_the_exports_pages_counts_leave_out_marks_on_events_no_longer_loaded(synthetic_case):
    """The marks table keeps a mark whose event is gone, as a re-run with new record keys leaves it. Every card's count is
    the file's: the marked and flagged counts, the Malicious marks, and the indicators read the events that are loaded, so
    the page never states more than the file it opens holds."""
    app = App(synthetic_case, for_work=True)
    try:
        rdp, dc, gone = uid_at(app, T0), uid_at(app, T0 + 62 * SEC), uid_at(app, T0 + 60 * SEC)
        api_mark(app, {"uids": [rdp, gone], "value": "malicious"})
        api_mark(app, {"uids": [dc], "value": "suspicious"})
        app.con.execute("DELETE FROM events WHERE event_uid = ?", [gone])
        page = api_exports_page(app, {})
        assert (page["marked"], page["flagged"], page["malicious"]) == (2, 2, 1)
        assert api_export(app, {"format": "csv", "marks": "marked"})["rows"] == page["marked"]
        assert api_export(app, {"format": "csv", "marks": "flagged"})["rows"] == page["flagged"]
        found = api_indicators(app, {})
        assert found["events"] == page["malicious"] and found["values"] == page["indicators"]
        text = Path(api_report(app, {})["path"]).read_text(encoding="utf-8")
        assert "Taken only from the 1 event marked Malicious" in text
    finally:
        app.con.close()


def test_a_retired_findings_events_and_a_gone_event_in_the_report(synthetic_case):
    """A retired finding supports no entry of the timeline, so its events carry no Finding line for it; an open finding
    that names an event no longer loaded says so in its list."""
    app = App(synthetic_case, for_work=True)
    try:
        rdp = uid_at(app, T0)
        api_mark(app, {"uids": [rdp], "value": "malicious"})
        gone = "f" * 32
        api_finding(app, {"op": "add", "title": "Open one", "severity": "High", "targets": [rdp, gone]})
        retired = api_finding(app, {"op": "add", "title": "Retired one", "severity": "Low", "targets": [rdp]})["finding"]
        api_finding(app, {"op": "retire", "finding": retired})
        text = Path(api_report(app, {})["path"]).read_text(encoding="utf-8")
        assert "   - Finding: 1. Open one\n" in section(text, 3) and "Retired one" not in section(text, 3)
        assert f"- An event no longer loaded: ID `{gone}`" in section(text, 2)
    finally:
        app.con.close()


def test_the_addresses_that_name_no_host_are_no_indicator():
    """Unspecified, loopback, broadcast, multicast, and link-local addresses (an IPv6 zone included) are left out; any other
    address, private ones too, and a name are not."""
    for left_out in ("0.0.0.0", "::", "127.0.0.1", "::1", "255.255.255.255", "224.0.0.251", "ff02::fb", "169.254.7.7",
                     "fe80::1%12"):
        assert _local(left_out), left_out
    for kept in ("203.0.113.80", "10.0.0.5", "2001:db8::1", "update.evil.example", "239.1"):
        assert not _local(kept), kept


MAPS = {"EvtxECmd.exe": "12" * 32, "Maps/": "34" * 32}   # what a format 4 run of EvtxECmd records
RECMD = {"ReCmd.exe": "56" * 32, "Plugins/": "78" * 32}


def method_part(text):
    """The Method section's table rows and what follows them."""
    return section(text, 7)


def test_the_method_table_gives_each_run_s_rule_set_and_lists_the_tool_files_of_each_distinct_set_once(synthetic_case):
    """The Rules column follows Events. A run's label is what its record holds; a tool run of a tool whose registry entry
    has a rules_label, with no tool_files, says "not recorded"; found output, a run with no record, and a tool with no
    rules_label and no label say nothing, and so does an import, which no registry entry names. Under the table each
    distinct set of tool files is listed once with the runs that recorded it, a folder by its path and a /."""
    from test_overview import run_record

    load_eve(synthetic_case)
    fast = Event(ts_us=T0 + 70 * SEC, ts_desc="Alert", artifact="ids_alert", source_file="fast.log", source_record="1",
                 message="[1:2001:1] ET TEST Leak", log_channel="Attempted Information Leak",
                 extra={"signature": "ET TEST Leak", "sid": "2001", "priority": "2"})
    load(synthetic_case.db_path, [fast], host="network", tool="import", tool_version="t", run_id="r7",
         replaces_sources=["fast.log"], staging_dir=synthetic_case.folder)
    run_record(synthetic_case, "r1", "evtxecmd", "DC01", "ok", 5, rules="Maps, 456 maps", tool_files=MAPS)
    run_record(synthetic_case, "r2", "evtxecmd", "DESKTOP", "ok", 5, rules="Maps, 456 maps", tool_files=MAPS)
    run_record(synthetic_case, "r3", "recmd", "DC01", "ok", 1)   # made before format 4
    run_record(synthetic_case, "r4", "recmd", "DESKTOP", "ok", 1, rules="DFIRBatch.reb 2.22", tool_files=RECMD)
    run_record(synthetic_case, "r5", "hayabusa", "DC01", "ok", 1, from_output=True)
    run_record(synthetic_case, "r6", "suricata", "network", "ok", 6, rules="ET Open 11310")
    run_record(synthetic_case, "r7", "import", "network", "ok", 1, parser="import")
    app = App(synthetic_case, for_work=True)
    try:
        for text in (Path(api_report(app, {})["path"]).read_text(encoding="utf-8"), api_report_preview(app, {})["text"]):
            method = method_part(text)
            assert "| Run | Tool | Version | Host | Events | Rules |\n|---|---|---|---|---|---|\n" in method
            rows = {line.split("|")[1].strip(" `"): line for line in method.splitlines() if line.startswith("| `r")}
            assert rows["r1"] == "| `r1` | evtxecmd | t | DC01 | 5 | Maps, 456 maps |"
            assert rows["r2"] == "| `r2` | evtxecmd | t | DESKTOP | 3 | Maps, 456 maps |"
            assert rows["r3"].endswith("| recmd | t | DC01 | 2 | rules not recorded |")
            assert rows["r4"].endswith("| recmd | t | DESKTOP | 2 | DFIRBatch.reb 2.22 |")
            assert rows["r5"].endswith("| hayabusa | t | DC01 | 1 |  |")
            assert rows["r6"] == "| `r6` | suricata | 8.0.7 | network | 6 | ET Open 11310 |"
            assert rows["r7"] == "| `r7` | import | t | network | 1 |  |"
            _, _, files_part = method.partition("Files each tool ran with")
            assert files_part.startswith(", as its runs recorded them, by SHA-256. A path that ends in / is a folder, hashed "
                                         "as the lines `sha256sum` prints for its files, by their paths in the folder with "
                                         "forward slashes, sorted in code point order, leaving out a .git folder and links.\n\n")
            first = "- Runs `r1`, `r2`:\n  - `EvtxECmd.exe`: `" + "12" * 32 + "`\n  - `Maps/`: `" + "34" * 32 + "`\n"
            second = "- Run `r4`:\n  - `Plugins/`: `" + "78" * 32 + "`\n  - `ReCmd.exe`: `" + "56" * 32 + "`\n"
            assert files_part.endswith(first + second) and not any(f"`{run}`" in files_part for run in ("r3", "r5", "r6", "r7"))
    finally:
        app.con.close()


def test_a_run_record_the_report_cannot_read_fails_it_naming_the_file(synthetic_case):
    """A run.json this build refuses fails the Method table as it fails the Case overview: by the file's name, before
    the evidence is re-hashed, anything is written, or anything is journaled. A case with an intake manifest, whose report
    would otherwise re-hash its evidence, gains no line in verification.jsonl for a report that is never written."""
    from test_overview import rewrite_record, run_record

    from glessner.case import CaseError
    from glessner.intake import intake

    for name in ("Security.evtx", "System.evtx"):
        (synthetic_case.evidence / "DC01" / name).write_bytes(b"ElfFile\x00" + name.encode())
    intake(synthetic_case)
    run_record(synthetic_case, "r1", "evtxecmd", "DC01", "ok", 5, tool_files=MAPS)
    rewrite_record(synthetic_case, "r1", tool_files=["EvtxECmd.exe"])
    app = App(synthetic_case, for_work=True)

    def recorded():
        file = synthetic_case.verification_path
        return file.read_bytes() if file.exists() else b""

    try:
        before, verified = len(entries(synthetic_case)), recorded()
        for call in (api_report, api_report_preview):
            with pytest.raises(CaseError, match=r"r1[\\/]run\.json has a tool_files that isn't a JSON object"):
                call(app, {})
        with pytest.raises(CaseError, match=r"run\.json has a tool_files"):
            server.api_overview(app, {})   # the Case overview fails the same way
        assert len(entries(synthetic_case)) == before
        assert recorded() == verified
        assert not (synthetic_case.folder / "exports").exists() or not list((synthetic_case.folder / "exports").glob("report_*"))
    finally:
        app.con.close()


def report_hashes(text):
    """Each marked event's evidence SHA-256 as the report's Source line gives it, or None for a line that gives no hash,
    by event ID, and that line."""
    found, source = {}, ""
    for line in text.splitlines():
        if line.startswith("   - Source: "):
            source = line
        elif line.startswith("   - Event ID: `"):
            match = re.search(r"evidence SHA-256 `([0-9a-f]{64})`", source)
            found[line.removeprefix("   - Event ID: `").removesuffix("`")] = (match.group(1) if match else None, source)
    return found


def test_the_report_cites_the_hash_the_event_page_does_for_an_event_of_found_output(tmp_path):
    """The Event page cites the intake hash of the output file a found-output load read, not of the file the event
    names, which the load never read, and cites none for a load of several files or one whose run record is gone. The
    report's hash for each such event is the page's, whether the file the event names is in the manifest or not, and its
    line names the output file, or says why it gives none. An event of a tool's run cites the file it names."""
    from test_found_output_sources import FOUND, KAPE, LOG, OTHER_HOST, OUTSIDE, SYSTEM_LOG, evtxecmd_run, found_case, load

    from glessner.runner import read_run

    case = found_case(tmp_path)
    direct = evtxecmd_run(case)
    names_a_listed_file = load(case, "WS02", OTHER_HOST[0])   # its rows name WS01's Security log, which the manifest lists
    names_an_outside_file = load(case, "WS02", OUTSIDE[0])    # its rows name a path on the collecting machine
    several = load(case, "WS01", FOUND, KAPE)
    app = App(case, for_work=True)
    try:
        uids = {}
        for name, record in (("tool", direct), ("listed", names_a_listed_file), ("outside", names_an_outside_file),
                             ("several", several)):
            uids[name] = app.con.execute("SELECT event_uid FROM events WHERE run_id = ? ORDER BY event_uid LIMIT 1",
                                         [record.run_id]).fetchone()[0]
        api_mark(app, {"uids": list(uids.values()), "value": "suspicious"})
        report = Path(api_report(app, {})["path"]).read_text(encoding="utf-8")
        cited = report_hashes(report)
        for text in (report, api_report_preview(app, {})["text"]):
            assert report_hashes(text) == cited
        page = {name: server.api_event(app, {"uid": [uid]})["event"]["provenance"] for name, uid in uids.items()}
        for name, uid in uids.items():
            assert cited[uid][0] == (page[name]["sha256"] or None), name   # the page's, event by event
        assert cited[uids["tool"]][0] == app.manifest[SYSTEM_LOG]
        output = read_run(case, names_a_listed_file.run_id).inputs[0]
        assert cited[uids["listed"]][0] == app.manifest[output] != app.manifest[LOG]
        assert f"evidence SHA-256 `{app.manifest[output]}` (of the output file `{output}`)" in cited[uids["listed"]][1]
        outside = read_run(case, names_an_outside_file.run_id).inputs[0]
        assert cited[uids["outside"]][0] == app.manifest[outside]
        assert cited[uids["several"]] == (None, cited[uids["several"]][1])
        assert "no evidence SHA-256: the load read 2 output files and doesn't record which one the event came from" in (
            cited[uids["several"]][1])
        assert "not in manifest" not in report
    finally:
        app.con.close()


def test_the_report_gives_no_hash_for_an_event_of_found_output_whose_run_record_is_gone(tmp_path):
    """Without its run's record nothing says which output file the load read, so the Event page cites none, and the
    report says that instead of giving the hash of the file the event names, or "not in manifest"."""
    import shutil

    from test_found_output_sources import FOUND, found_case, load

    case = found_case(tmp_path)
    record = load(case, "WS01", FOUND)
    shutil.rmtree(case.runs_folder / record.run_id)
    app = App(case, for_work=True)
    try:
        uid = app.con.execute("SELECT event_uid FROM events WHERE run_id = ? LIMIT 1", [record.run_id]).fetchone()[0]
        api_mark(app, {"uids": [uid], "value": "suspicious"})
        assert server.api_event(app, {"uid": [uid]})["event"]["provenance"]["sha256"] == ""
        text = Path(api_report(app, {})["path"]).read_text(encoding="utf-8")
        found, line = report_hashes(text)[uid]
        assert found is None and "no evidence SHA-256: the run's record is gone, so the output the event was read from " \
            "is unknown." in line
    finally:
        app.con.close()
