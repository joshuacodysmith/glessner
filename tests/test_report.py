"""The report, the scoped exports, the indicators, and the audit trail's cut of long event names, on the server side: the
report's seven sections and head lines, the report_summary setting's replay and audit wording, each export's scope, the
indicators drawn only from Malicious marks and parsed fields, the columns for network sources, the exports page's
endpoint, a View's search worded through Term.describe, and the cut in the trail and its export."""

import csv
import json
from pathlib import Path

from conftest import NETWORK_CAPTURE, SEC, T0
from test_server import login, request

from glessner.audit import cut_name, describe, file_words, read_entries
from glessner.caveats import table
from glessner.events import Event, load
from glessner.export import NO_SUMMARY, SECTIONS, _local, _md, indicators
from glessner.filters import describe as describe_filter
from glessner.filters import normalize, view_terms
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
        assert "| `r1` | evtxecmd | t | DC01 | 5 |" in section(text, 7) and "Written by glessner " in section(text, 7)
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
                           "first_seen": "2020-09-19T03:21:48.000000Z", "last_seen": "2020-09-19T03:21:48.000000Z"}
        assert {(r["type"], r["value"]) for r in rows} == set(found)
    finally:
        app.con.close()


def test_network_rows_carry_d45s_columns_and_windows_rows_keep_theirs(synthetic_case):
    """A network record's row names its signature as rule.name with rule.id and event.severity, its type as
    event.dataset in place of winlog.channel, the connection as network.community_id (the community ID, else the flow
    ID), and url.full, dns.question.name, tls.server.name, and client.mac from its data; a Windows event keeps
    winlog.channel and Hayabusa's title in rule.name, with the network columns empty."""
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
        net = ("network.community_id", "url.full", "dns.question.name", "tls.server.name", "client.mac", "rule.id",
               "event.severity")
        assert set(by) == {f"suricata.{k}" for k in ("alert", "dns", "http", "tls", "dhcp", "fileinfo")} | {
            "ids_alert.alert", "zeek.http"}
        assert all(r["winlog.channel"] == "" for r in by.values())
        alert, dns, http = by["suricata.alert"], by["suricata.dns"], by["suricata.http"]
        assert (alert["rule.name"], alert["rule.id"], alert["event.severity"], alert["network.community_id"]) == (
            "GPL ATTACK_RESPONSE id check returned root", "2100498", "2", "1:abc=")
        assert (dns["dns.question.name"], dns["network.community_id"]) == ("update.evil.example", "12")
        assert (http["url.full"], http["network.community_id"]) == ("http://203.0.113.80/payload.exe", "11")
        # An imported fast alert's channel is its classification, so its dataset is the alert; Zeek's http.log gives its uid,
        # host and URI
        fast, zeek = by["ids_alert.alert"], by["zeek.http"]
        assert (fast["rule.name"], fast["rule.id"], fast["event.severity"], fast["winlog.channel"]) == (
            "ET TEST Leak", "2001", "2", "")
        assert (zeek["network.community_id"], zeek["url.full"]) == ("CabC1", "http://evil.example/a.exe")
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
