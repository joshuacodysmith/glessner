"""The Findings page with its caveats, on the server side: the page's endpoint with each finding's events
and their current marks, the retired ones, and the marked events in no finding; the caveat table, each type to its fixed
text and sources and a type with none to none; and the refusals the page relies on, over HTTP."""

import json
from pathlib import Path
from urllib.parse import urlparse

from conftest import DC_LOG, SEC, T0, logon
from test_server import login, request

from glessner.caveats import caveat_for, caveats_for, table
from glessner.events import Event, load
from glessner.export import _md
from glessner.journal import JOURNAL_FILE
from glessner.parsers.recmd import PLUGINS
from glessner.server import App, api_event, api_finding, api_findings_page, api_mark, api_report_preview

FOUR = {"artifact": "evtx", "event_code": "4624", "log_channel": "Security", "registry_path": ""}
APPCOMPAT = "ROOT\\ControlSet001\\Control\\Session Manager\\AppCompatCache"


def entries(case):
    return [json.loads(line) for line in (case.folder / JOURNAL_FILE).read_text(encoding="utf-8").splitlines()]


def uid_at(app, ts, tool="evtxecmd"):
    return app.con.execute("SELECT event_uid FROM events WHERE tool = ? AND ts_us = ?", [tool, ts]).fetchone()[0]


def test_the_page_lists_each_finding_with_its_events_their_current_marks_and_the_marked_events_in_no_finding(synthetic_case):
    """Each finding in the order of its add, numbered so, with its events through _listed_events and _mark_info, so a mark
    changed after the link shows as it is; a retired finding keeps its number, carries its reason, and holds no event,
    so its events count as "in no finding" with the other Malicious and Suspicious events outside an open finding; an
    Authorized event is not among them; `unassigned=1` lists them; and a finding's caveats come from its events' types."""
    app = App(synthetic_case, for_work=True)
    try:
        rdp, morty, machine, dc = (uid_at(app, T0), uid_at(app, T0 + 60 * SEC), uid_at(app, T0 + 61 * SEC),
                                   uid_at(app, T0 + 62 * SEC))
        api_mark(app, {"uids": [rdp, morty], "value": "malicious"})
        api_mark(app, {"uids": [dc], "value": "suspicious"})
        api_mark(app, {"uids": [machine], "value": "authorized"})
        first = api_finding(app, {"op": "add", "title": "RDP from the internet", "severity": "High",
                                  "narrative": "Seen at 03:21.", "techniques": ["T1021.001"], "targets": [rdp, morty]})["finding"]
        second = api_finding(app, {"op": "add", "title": "A test finding", "severity": "Low", "targets": [dc]})["finding"]
        api_finding(app, {"op": "retire", "finding": second, "reason": "Made to test the page."})
        page = api_findings_page(app, {})
        assert [(f["id"], f["number"], f["title"]) for f in page["findings"]] == [(first, 1, "RDP from the internet"),
                                                                                   (second, 2, "A test finding")]
        one, two = page["findings"]
        assert (one["severity"], one["narrative"], one["techniques"], one["total"], one["retired"]) == (
            "High", "Seen at 03:21.", ["T1021.001"], 2, None)
        assert [(e["uid"], e["mark"], e["mark_who"], e["host"], e["code"]) for e in one["events"]] == [
            (rdp, "Malicious", "cody", "DC01", "4624"), (morty, "Malicious", "cody", "DC01", "4624")]
        assert one["added"]["who"] == "cody" and one["edited"] is None
        assert [c["id"] for c in one["caveats"]] == ["logon"] and one["caveats"][0]["name"] == "Logon events 4624 and 4625"
        assert two["retired"]["reason"] == "Made to test the page." and two["events"][0]["uid"] == dc
        # The retired finding's event and nothing else: the Authorized event is not a marked event here
        assert page["unassigned"] == 1 and "unassigned_events" not in page
        listed = api_findings_page(app, {"unassigned": ["1"]})["unassigned_events"]
        assert [(e["uid"], e["mark"]) for e in listed] == [(dc, "Suspicious")]
        # The mark changes after the link, and the listed event shows the mark it has now
        api_mark(app, {"uids": [morty], "value": "suspicious"})
        api_finding(app, {"op": "unlink", "finding": first, "targets": [rdp]})
        page = api_findings_page(app, {})
        assert [(e["uid"], e["mark"]) for e in page["findings"][0]["events"]] == [(morty, "Suspicious")]
        assert page["unassigned"] == 2 and page["findings"][0]["total"] == 1
        # The Event page says which open findings the event is in, and none for the retired one's event
        assert api_event(app, {"uid": [morty]})["event"]["findings"] == [{"id": first, "number": 1,
                                                                            "title": "RDP from the internet"}]
        assert api_event(app, {"uid": [dc]})["event"]["findings"] == []
    finally:
        app.con.close()


def test_the_caveat_table_maps_each_type_to_its_text_and_sources_and_a_type_with_none_to_none(synthetic_case):
    """The fixed texts, keyed by artifact, event type, and what a registry entry's time means, each with its sources;
    the same record always gets the same text; a kind the table doesn't name gets none. The Event page carries the
    record's caveat."""
    cases = [
        ({"artifact": "prefetch"}, "prefetch", "A Prefetch file shows the program ran", "Forensics Wiki, Prefetch"),
        ({"artifact": "amcache"}, "amcache", "An Amcache file entry shows the file was present and inventoried, with its SHA-1.",
         "Cyber Triage, Shimcache and Amcache (Ray, 2026)"),
        ({"artifact": "registry", "registry_path": APPCOMPAT},
         "appcompatcache", "An AppCompatCache entry shows Windows saw the file. On Vista and later",
         "Mandiant, Shimcache (Parisi, 2015)"),
        ({"artifact": "registry", "registry_path": APPCOMPAT, "ts_desc": "Registry Key LastWrite"}, "appcompatcache",
         "An AppCompatCache entry shows Windows saw the file.", "Valhuntir, Shimcache"),
        ({"artifact": "registry", "registry_path": APPCOMPAT, "ts_desc": "AppCompatCache file modified"},
         "appcompatcache_modified", "This time is the file's last modified time as the AppCompatCache entry recorded it",
         "Mandiant, Shimcache (Parisi, 2015)"),
        ({"artifact": "registry", "ts_desc": "UserAssist last executed"}, "program_last_run",
         "This is the last run time the entry records for the program",
         "Cyber Triage, UserAssist (Ray, 2026)"),
        ({"artifact": "registry", "ts_desc": "BAM last executed"}, "program_last_run", "This is the last run time",
         "parsers/recmd.py, the entry times"),
        ({"artifact": "registry", "ts_desc": "SAM account name key last write"}, "sam_account",
         "These times come from this host's SAM hive, which holds the host's local accounts only",
         "Windows Incident Response, User Account Analysis (Carvey, 2009)"),
        ({"artifact": "registry", "ts_desc": "USB device last connected"}, "device_times",
         "These times come from the device's entry in the SYSTEM hive.",
         "Yogesh Khatri's forensic blog, Windows 8 device timestamps (Khatri, 2013)"),
        ({"artifact": "registry", "ts_desc": "Service key last write"}, "entry_key_write",
         "This time is when the entry's own registry key last changed.", "parsers/recmd.py, the entry times"),
        ({"artifact": "registry", "ts_desc": "Device class key last write"}, "entry_key_write",
         "This time is when the entry's own registry key last changed.", "The Data Leakage Case (NIST CFReDS): in a "
         "Glessner case built from it, a USB drive's Device Classes keys were last written when it was connected again "
         "on 2015-03-24, not at its first connection the day before"),
        ({"artifact": "registry", "ts_desc": "Profile last logoff"}, "profile_logon_times",
         "These times come from the account's key under ProfileList in the SOFTWARE hive.",
         "Microsoft, Scripts to retrieve profile age: LocalProfileLoadTime and LocalProfileUnloadTime"),
        ({"artifact": "registry", "ts_desc": "Office file last closed"}, "office_file_times",
         "The last opened time comes from the file's entry", "ThinkDFIR, Microsoft Office Reading Locations, part 1 "
         "(Moore, 2019)"),
        ({"artifact": "registry", "ts_desc": "URL last typed"}, "typed_url",
         "This time comes from the URL's value in the TypedURLsTime key",
         "Crucial Security Forensics Blog, TypedURLs part 1 (Nichols, 2011)"),
        ({"artifact": "registry", "ts_desc": "RecentDocs entry opened"}, "mru_list_time",
         "This time is the last write of the MRU list's registry key.",
         "Forensic 4:cast, Updates to the RecentDocs key in Windows 10 (Whitfield, 2019)"),
        ({"artifact": "registry", "ts_desc": "Scheduled task last stopped"}, "scheduled_task_times",
         "These times come from the DynamicInfo value", "cyber.wtf, Windows registry analysis: tasks (Ebach, 2022)"),
        ({"artifact": "registry", "ts_desc": "JumplistData last executed"}, "jumplistdata_time",
         "This time is the data of the program's value under Search\\JumplistData", "RECmd, Kroll batch file: JumplistData"),
        ({"artifact": "registry", "ts_desc": "Remote Desktop server entry last modified"}, "remote_desktop_server",
         "This time is the last write of the server's key under Terminal Server Client\\Servers",
         "JPCERT/CC, Tool Analysis Result Sheet: mstsc (RDP)"),
        ({"artifact": "registry", "ts_desc": "RADAR last detected"}, "radar_detection",
         "This time is the LastDetectionTime value", "Harel Segev, The mystery of the HeapLeakDetection registry key (2022)"),
        ({"artifact": "lnk"}, "lnk", "A shortcut or jump list entry shows the shell recorded a reference",
         "Valhuntir, LNK files"),
        ({"artifact": "jumplist"}, "lnk", "A shortcut or jump list entry", "Valhuntir, jump lists"),
        ({"artifact": "evtx", "event_code": "4624"}, "logon",
         "A logon event shows an account authenticated, or failed to, from a source.", "Microsoft, event 4624"),
        ({"artifact": "evtx", "event_code": "4625"}, "logon", "A logon event", "Microsoft, event 4625"),
        ({"artifact": "autoruns"}, "autoruns", "An Autoruns entry shows a persistence location and its target.",
         "Microsoft Sysinternals, Autoruns"),
        ({"artifact": "suricata", "log_channel": "alert", "event_code": "2025644"}, "suricata_alert",
         "An alert shows that traffic matched a signature. It does not show that the attack succeeded. "
         "The alert's source address is not necessarily the attacker.", "Suricata, EVE JSON format"),
        ({"artifact": "evtx", "event_code": "7045", "log_channel": "System"}, "service_installed",
         "A 7045 shows a service was registered with its image path. It does not show the binary ran.", "Valhuntir, services"),
    ]
    for ev, cid, start, source in cases:
        found = caveat_for(ev)
        assert found and found["id"] == cid and found["text"].startswith(start), ev
        assert source in [s["title"] for s in found["sources"]], ev
        assert all(s.get("url") or s.get("path") for s in found["sources"]), ev
        assert caveat_for(dict(ev)) == found   # the same record, the same text
    assert [row["id"] for row in table()] == ["prefetch", "amcache", "appcompatcache_modified", "appcompatcache",
                                              "program_last_run", "sam_account", "device_times", "entry_key_write",
                                              "profile_logon_times", "office_file_times", "typed_url", "mru_list_time",
                                              "scheduled_task_times", "jumplistdata_time",
                                              "remote_desktop_server", "radar_detection", "lnk", "logon", "autoruns",
                                              "suricata_alert", "service_installed"]
    root = Path(__file__).resolve().parent.parent
    for row in table():   # each source a public page or a file of the app
        assert all(s.get("url", "").startswith("https://") or (root / s.get("path", "")).is_file()
                   for s in row["sources"]), row["id"]
        for source in row["sources"]:   # a SANS poster's page needs an account
            url = urlparse(source.get("url", ""))
            on_sans = url.hostname == "sans.org" or (url.hostname or "").endswith(".sans.org")
            assert not (on_sans and "poster" in url.path.lower()), source["url"]
    run_key = "ROOT\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    for ev in ({"artifact": "evtx", "event_code": "4688"}, {"artifact": "registry", "registry_path": run_key},
               {"artifact": "registry", "registry_path": run_key, "ts_desc": "Registry Key LastWrite"},
               {"artifact": "registry", "ts_desc": "Windows app installed"},
               {"artifact": "mft", "ts_desc": "Service key last write"},
               {"artifact": "mft", "ts_desc": "RecentDocs entry opened"},
               {"artifact": "shellbags"}, {"artifact": "suricata", "log_channel": "flow"}, {"artifact": "srum"}, {}):
        assert caveat_for(ev) is None, ev
    # Several records: each type once, in the table's order, whatever the records' order
    found = caveats_for([{"artifact": "evtx", "event_code": "7045"}, {"artifact": "evtx", "event_code": "4624"},
                         {"artifact": "prefetch"}, {"artifact": "evtx", "event_code": "4624"}, {"artifact": "mft"}])
    assert [c["id"] for c in found] == ["prefetch", "logon", "service_installed"]
    assert caveats_for([{"artifact": "mft"}]) == []
    # The Event page: a 4624 carries the logon caveat beside its record; a registry value with no row in the table carries none
    app = App(synthetic_case, for_work=True)
    try:
        logon_event = api_event(app, {"uid": [uid_at(app, T0)]})["event"]
        assert logon_event["caveat"]["id"] == "logon" and logon_event["caveat"]["text"].startswith("A logon event shows")
        registry = app.con.execute("SELECT event_uid FROM events WHERE tool = 'recmd' LIMIT 1").fetchone()[0]
        assert api_event(app, {"uid": [registry]})["event"]["caveat"] is None
    finally:
        app.con.close()


def appcompat_events(path="C:\\Windows\\system32\\cmd.exe"):
    """An AppCompatCache row's LastWrite event and its entry's file modified time, as the RECmd parser gives them."""
    record = f"{APPCOMPAT}|AppCompatCache|AppCompatCache"
    common = {"artifact": "registry", "source_file": "Windows/System32/config/SYSTEM", "registry_path": APPCOMPAT,
              "registry_value": "AppCompatCache", "file_path": path}
    return [Event(T0, "Registry Key LastWrite", source_record=record, message=f"AppCompatCache: {path}", **common),
            Event(T0 - 3600 * SEC, "AppCompatCache file modified", source_record=f"{record}|0",
                  message=f"AppCompatCache: {path} (AppCompatCache file modified)", **common)]


def test_appcompat_entry_time_has_its_own_caveat():
    """An AppCompatCache entry's file modified time gets its own caveat, not the row's, which says its time is the
    cache key's last write. The row's LastWrite event keeps its caveat."""
    written, modified = ({"artifact": ev.artifact, "registry_path": ev.registry_path, "ts_desc": ev.ts_desc,
                          "event_code": "", "log_channel": ""} for ev in appcompat_events())
    assert caveat_for(written)["id"] == "appcompatcache"
    assert caveat_for(modified)["id"] == "appcompatcache_modified"
    assert "last write" not in caveat_for(modified)["text"]
    assert [c["id"] for c in caveats_for([modified, written])] == ["appcompatcache_modified", "appcompatcache"]


def test_each_registry_entry_time_but_a_windows_apps_install_time_has_a_caveat():
    """Every ts_desc the RECmd parser gives an entry event matches a caveat row by its ts_desc, except Windows apps'
    install time, which no public page explains yet."""
    entry_times = {desc for spec in PLUGINS.values() for desc in spec.times.values()}
    assert len(entry_times) == 45
    listed = [desc for row in table() for desc in row["match"].get("ts_desc", [])]
    assert len(listed) == len(set(listed))   # caveat_for takes the first row that fits, so a repeat hides one
    by_desc = {desc: (caveat_for({"artifact": "registry", "ts_desc": desc}) or {}).get("id") for desc in entry_times}
    assert [desc for desc, cid in by_desc.items() if cid is None] == ["Windows app installed"]
    assert all("ts_desc" in next(row for row in table() if row["id"] == cid)["match"] for cid in by_desc.values() if cid)


def test_ts_desc_caveat_shows_on_export_and_the_event_page(synthetic_case):
    """The caveat a record's time meaning picks shows on the Event page, on the Findings page, and in the report: an
    AppCompatCache entry's modified time with its own text, and the row's LastWrite time with the cache key's."""
    load(synthetic_case.db_path, appcompat_events(), host="DC01", tool="recmd", tool_version="t", run_id="entries",
         replaces_sources=[], staging_dir=synthetic_case.folder)
    app = App(synthetic_case, for_work=True)
    try:
        written, modified = (app.con.execute("SELECT event_uid FROM events WHERE run_id = 'entries' AND ts_desc = ?",
                                             [desc]).fetchone()[0]
                             for desc in ("Registry Key LastWrite", "AppCompatCache file modified"))
        assert api_event(app, {"uid": [modified]})["event"]["caveat"]["id"] == "appcompatcache_modified"
        assert api_event(app, {"uid": [written]})["event"]["caveat"]["id"] == "appcompatcache"
        api_mark(app, {"uids": [written, modified], "value": "suspicious"})
        api_finding(app, {"op": "add", "title": "Cached cmd.exe", "severity": "Low", "targets": [modified, written]})
        (finding,) = api_findings_page(app, {})["findings"]
        assert [c["id"] for c in finding["caveats"]] == ["appcompatcache_modified", "appcompatcache"]
        report = api_report_preview(app, {})["text"]
        own = next(c for c in table() if c["id"] == "appcompatcache_modified")
        assert f"- **{own['name']}.** {_md(own['text'])} Source" in report
        assert f"- **{own['name']}** (1 marked): {_md(own['text'])} Sources: " in report
        assert "- **AppCompatCache (Shimcache)** (1 marked): " in report
    finally:
        app.con.close()


def test_the_refusals_the_page_relies_on_and_the_consent_a_large_link_records(running):
    """Over HTTP: a bad severity, a technique that is no ATT&CK ID, a link to no finding, a target that is no event ID, a
    link or edit of a retired finding, a retire of one retired, and a restore of one open are each refused with a 400 and
    the message the page shows, and change nothing.
    A link of more than 25 events the analyst confirmed records `confirmed {count, skipped: 0}`; a new finding
    confirmed over its events is written as its add and a link carrying the consent, since format 3 carries `confirmed`
    on a link and not on an add; a confirmed request naming no events is refused."""
    app, port, _ = running
    session = login(port, app)
    many = [logon(T0 + (1000 + n) * SEC, 9900 + n, DC_LOG, user="bulk", ltype="3", ip="10.42.85.50") for n in range(30)]
    load(app.case.db_path, many, host="DC01", tool="evtxecmd", tool_version="t", run_id="bulk", replaces_sources=[],
         staging_dir=app.case.folder)
    uids = [r[0] for r in app.con.execute("SELECT event_uid FROM events WHERE run_id = 'bulk' ORDER BY ts_us").fetchall()]

    def finding(body):
        res, payload = request(port, "POST", "/api/finding", session=session, body=body)
        return res.status, json.loads(payload)

    status, made = finding({"op": "add", "title": "Bulk logons", "severity": "Medium", "targets": uids[:2]})
    assert status == 200
    fid = made["finding"]
    before = len(entries(app.case))
    refused = [({"op": "add", "title": "x", "severity": "Severe"},
                "severity is one of Critical, High, Medium, Low, Informational"),
               ({"op": "add", "title": "x", "severity": "Low", "techniques": ["T15"]},
                "T15 isn't in ATT&CK v20.0. Remove it to save the ATT&CK field."),
               ({"op": "add", "title": "x", "severity": "Low", "techniques": "T1078"}, "ATT&CK IDs such as T1543.003"),
               ({"op": "add", "title": "", "severity": "Low"}, "title is 1 to 200 characters"),
               ({"op": "link", "finding": 999, "targets": uids[:1]}, "There's no finding #999."),
               ({"op": "link", "finding": fid, "targets": []}, "non-empty list of event IDs"),
               # A target that is a list or an object is refused before the repeats are dropped, which needs hashable values
               ({"op": "add", "title": "x", "severity": "Low", "targets": [["x"]]}, "targets must be event IDs"),
               ({"op": "link", "finding": fid, "targets": [["x"]]}, "targets must be event IDs"),
               ({"op": "unlink", "finding": fid, "targets": [uids[0], {"uid": uids[1]}]}, "targets must be event IDs"),
               ({"op": "restore", "finding": fid}, 'The finding "Bulk logons" is not retired.'),
               ({"op": "link", "finding": fid, "targets": uids, "confirmed": {"count": "30"}}, "confirmed gives the count")]
    for body, message in refused:
        status, answer = finding(body)
        assert status == 400 and message in answer["error"], (body, answer)
    assert len(entries(app.case)) == before
    # Confirmed above 25: the link records the consent with skipped 0
    status, _ = finding({"op": "link", "finding": fid, "targets": uids, "confirmed": {"count": 30}})
    assert status == 200
    entry = entries(app.case)[-1]
    assert (entry["action"], entry["op"], entry["finding"], len(entry["targets"]), entry["confirmed"]) == (
        "finding", "link", fid, 30, {"count": 30, "skipped": 0})
    assert api_findings_page(app, {})["findings"][0]["total"] == 30
    # A new finding from a confirmed selection: its add, then the link with the consent
    status, made = finding({"op": "add", "title": "Thirty at once", "severity": "High", "narrative": "", "techniques": ["T1078"],
                            "targets": uids, "confirmed": {"count": 30}})
    assert status == 200
    add, link = entries(app.case)[-2:]
    assert (add["seq"], add["op"], add["targets"], add["techniques"]) == (made["finding"], "add", [], ["T1078"])
    assert (link["seq"], link["op"], link["finding"], len(link["targets"]), link["confirmed"]) == (
        made["seq"], "link", made["finding"], 30, {"count": 30, "skipped": 0})
    assert "confirmed" not in add
    status, answer = finding({"op": "add", "title": "No events", "severity": "High", "confirmed": {"count": 0}})
    assert status == 400 and "names the events it covers" in answer["error"]
    # A confirmed add whose link would be refused leaves no empty finding behind: the events are checked before the add
    before, held = len(entries(app.case)), len(app.journal.state.findings)
    for targets in ([], [5], [""]):
        status, answer = finding({"op": "add", "title": "Empty", "severity": "High", "targets": targets,
                                  "confirmed": {"count": len(targets)}})
        assert status == 400 and "non-empty list of event IDs" in answer["error"], targets
    assert len(entries(app.case)) == before and len(app.journal.state.findings) == held
    # Retired: edit, link, and unlink are refused until it is restored, and a second retire too
    status, _ = finding({"op": "retire", "finding": fid, "reason": "Not a finding."})
    assert status == 200
    for body in ({"op": "edit", "finding": fid, "title": "y"}, {"op": "link", "finding": fid, "targets": uids[:1]},
                 {"op": "unlink", "finding": fid, "targets": uids[:1]}):
        status, answer = finding(body)
        assert status == 400 and 'The finding "Bulk logons" was retired by #' in answer["error"]
        assert "Restore it first." in answer["error"]
    status, answer = finding({"op": "retire", "finding": fid})
    assert status == 400 and "is retired already" in answer["error"]
    page = api_findings_page(app, {})
    assert page["findings"][0]["retired"]["reason"] == "Not a finding." and page["findings"][0]["number"] == 1
    status, _ = finding({"op": "restore", "finding": fid})
    assert status == 200 and api_findings_page(app, {})["findings"][0]["retired"] is None
