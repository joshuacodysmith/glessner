"""The Findings page with its caveats, on the server side: the page's endpoint with each finding's events
and their current marks, the retired ones, and the marked events in no finding; the caveat table, each of the eight types
to its fixed text and sources and a type with none to none; and the refusals the page relies on, over HTTP."""

import json
from pathlib import Path

from conftest import DC_LOG, SEC, T0, logon
from test_server import login, request

from glessner.caveats import caveat_for, caveats_for, table
from glessner.events import load
from glessner.journal import JOURNAL_FILE
from glessner.server import App, api_event, api_finding, api_findings_page, api_mark

FOUR = {"artifact": "evtx", "event_code": "4624", "log_channel": "Security", "registry_path": ""}


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


def test_the_caveat_table_maps_each_of_the_eight_types_to_its_text_and_sources_and_a_type_with_none_to_none(synthetic_case):
    """The eight fixed texts, keyed by artifact and event type, each with its sources; the same record always gets
    the same text; a kind the table doesn't name gets none. The Event page carries the record's caveat."""
    cases = [
        ({"artifact": "prefetch"}, "prefetch", "A Prefetch file shows the program ran", "Forensics Wiki, Prefetch"),
        ({"artifact": "amcache"}, "amcache", "An Amcache file entry shows the file was present and inventoried, with its SHA-1.",
         "Cyber Triage, Shimcache and Amcache (Ray, 2026)"),
        ({"artifact": "registry", "registry_path": "ROOT\\ControlSet001\\Control\\Session Manager\\AppCompatCache"},
         "appcompatcache", "An AppCompatCache entry shows Windows saw the file. On Vista and later",
         "Mandiant, Shimcache (Parisi, 2015)"),
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
    assert [row["id"] for row in table()] == ["prefetch", "amcache", "appcompatcache", "lnk", "logon", "autoruns",
                                              "suricata_alert", "service_installed"]
    root = Path(__file__).resolve().parent.parent
    for row in table():   # each source a public page or a file of the app
        assert all(s.get("url", "").startswith("https://") or (root / s.get("path", "")).is_file()
                   for s in row["sources"]), row["id"]
    run_key = "ROOT\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    for ev in ({"artifact": "evtx", "event_code": "4688"}, {"artifact": "registry", "registry_path": run_key},
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


def test_the_refusals_the_page_relies_on_and_the_consent_a_large_link_records(running):
    """Over HTTP: a bad severity, a technique that is no ATT&CK ID, a link to no finding, a link or edit of a retired finding,
    a retire of one retired, and a restore of one open are each refused with the message the page shows, and change nothing.
    A link of more than 25 events the analyst confirmed records `confirmed {count, skipped: 0}`; a new finding
    confirmed over its events is written as its add and a link carrying the consent, since format 3 carries `confirmed`
    on a link and not on an add; a confirmed request naming no events is refused."""
    app, port, _ = running
    cookie = login(port, app)
    many = [logon(T0 + (1000 + n) * SEC, 9900 + n, DC_LOG, user="bulk", ltype="3", ip="10.42.85.50") for n in range(30)]
    load(app.case.db_path, many, host="DC01", tool="evtxecmd", tool_version="t", run_id="bulk", replaces_sources=[],
         staging_dir=app.case.folder)
    uids = [r[0] for r in app.con.execute("SELECT event_uid FROM events WHERE run_id = 'bulk' ORDER BY ts_us").fetchall()]

    def finding(body):
        res, payload = request(port, "POST", "/api/finding", cookie=cookie, body=body)
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
