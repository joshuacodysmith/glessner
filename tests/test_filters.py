"""View filters: they change what the timeline shows, never the case."""

import json
import urllib.parse

import pytest
from conftest import SEC, T0
from test_analysis_relations import open_case
from test_server import login, request

from glessner.filters import FilterError, describe, normalize, where_sql
from glessner.queries import lanes, view


def test_normalize_is_canonical_and_strict():
    a = normalize({"hide": [{"host": "DC01", "channel": "Security"}, {"channel": "Security", "host": "DC01"}]})
    assert a == {"only": [], "hide": [{"channel": "Security", "host": "DC01"}], "show": []}
    for bad in ({"hide": [{}]}, {"hide": [{"color": "red"}]}, {"only": [{"host": 1}]}, {"hide": "DC01"}):
        with pytest.raises(FilterError):
            normalize(bad)
    assert describe(a) == "Hidden: events with channel Security and host DC01."
    assert where_sql(normalize({})) == ""


def test_a_search_only_field_is_not_a_view_value():
    """rule: reads the hits table in search (search.SEARCH_ONLY) and is kept out of queries.FIELDS, so a View predicate
    with it is refused rather than reading a column that isn't there."""
    for pred in ({"rule": "RDP from internet"}, {"rule_title": "RDP from internet"}):
        with pytest.raises(FilterError):
            normalize({"hide": [pred]})


def test_hiding_is_scoped_and_null_safe(synthetic_case):
    con, _, _ = open_case(synthetic_case)
    counts = lambda spec: {lane["keys"][0]: lane["count"] for lane in lanes(con, ["host"], where_sql(normalize(spec)))}
    assert counts({}) == {"DC01": 7, "DESKTOP": 5}   # evtx and registry events
    # Security on DC01 only: DC01 keeps its registry events, which have no channel, and DESKTOP is untouched.
    assert counts({"hide": [{"host": "DC01", "channel": "Security"}]}) == {"DC01": 2, "DESKTOP": 5}
    assert counts({"hide": [{"channel": "Security"}]}) == {"DC01": 2, "DESKTOP": 2}
    assert counts({"only": [{"host": "DESKTOP"}]}) == {"DESKTOP": 5}
    assert counts({"only": [{"host": "DESKTOP"}], "hide": [{"artifact": "registry"}]}) == {"DESKTOP": 3}


def test_the_most_specific_rule_wins(synthetic_case):
    con, _, _ = open_case(synthetic_case)
    counts = lambda spec: {lane["keys"][0]: lane["count"] for lane in lanes(con, ["host"], where_sql(normalize(spec)))}
    dc_security = {"host": "DC01", "tool": "evtxecmd", "artifact": "evtx"}
    # Hide DC01, but show its event logs anyway: only the 2 registry events go.
    assert counts({"hide": [{"host": "DC01"}], "show": [dc_security]}) == {"DC01": 5, "DESKTOP": 5}
    # Hide event logs everywhere, but show them on DC01.
    assert counts({"hide": [{"tool": "evtxecmd", "artifact": "evtx"}], "show": [dc_security]}) == {"DC01": 7, "DESKTOP": 2}
    # Nested: hide DC01, show its event logs, hide its Security channel inside that.
    nested = {"hide": [{"host": "DC01"}, {**dc_security, "channel": "Security"}], "show": [dc_security]}
    assert counts(nested) == {"DESKTOP": 5}
    # A show rule with no broader hide around it changes nothing.
    assert counts({"show": [dc_security]}) == {"DC01": 7, "DESKTOP": 5}
    assert describe(normalize({"hide": [{"host": "DC01"}], "show": [{"host": "DC01", "channel": "Security"}]})) == (
        "Hidden: events with host DC01. Shown anyway: events with channel Security and host DC01.")


def test_hidden_logons_lose_their_arrows(synthetic_case):
    con, _, identity = open_case(synthetic_case)
    args = (con, identity, ["host"], T0 - 60 * SEC, T0 + 3600 * SEC, 100, 50_000, False)
    dc_security = {u for (u,) in con.execute("SELECT event_uid FROM events WHERE host = 'DC01' AND log_channel = 'Security'")
                   .fetchall()}
    before = {link["uid"] for link in view(*args)["links"]["items"]}
    hidden = view(*args, where_sql(normalize({"hide": [{"host": "DC01", "channel": "Security"}]})))
    after = {link["uid"] for link in hidden["links"]["items"]}
    # Arrows backed by DC01's Security logons go; DESKTOP's 4648 to DC01 is recorded on DESKTOP, so it stays.
    assert before & dc_security and not after & dc_security and after == before - dc_security
    assert all(e["keys"] != ["DC01"] or e["tool"] != "evtxecmd" for e in hidden["events"])


def test_filter_api_sources_categories_and_export(running):
    app, port, _ = running
    cookie = login(port, app)
    get = lambda path: json.loads(request(port, "GET", path, cookie=cookie)[1])
    res, body = request(port, "POST", "/api/filter", cookie=cookie, body={"hide": [{"host": "DC01", "channel": "Security"}]})
    assert res.status == 200
    fid = json.loads(body)["id"]
    hosts = {lane["keys"][0]: lane["count"] for lane in get(f"/api/lanes?groupby=host&filter={fid}")["lanes"]}
    assert hosts == {"DC01": 2, "DESKTOP": 5}
    assert request(port, "GET", "/api/lanes?groupby=host&filter=0000000000000000", cookie=cookie)[0].status == 400
    src = get("/api/sources")
    assert {(t["tool"], t["artifact"], t["count"]) for t in src["types"]} == {("evtxecmd", "evtx", 8), ("recmd", "registry", 4)}
    dc = next(h for h in src["hosts"] if h["host"] == "DC01")
    assert [(a["artifact"], len(a["files"]), a["count"]) for a in dc["artifacts"]] == [("evtx", 1, 5), ("registry", 1, 2)]
    assert src["hayabusa"]["count"] == 1
    pred = urllib.parse.quote(json.dumps({"host": "DC01"}))
    cats = get(f"/api/categories?pred={pred}")
    assert cats["types"][0] == {"tool": "evtxecmd", "artifact": "evtx", "count": 5, "shown": 5}
    assert cats["channels"] == [{"channel": "Security", "count": 5, "shown": 5}] and cats["channel_total"] == 1
    # With the filter, the menu and the Filter panel get what it shows, not only what exists.
    cats = get(f"/api/categories?pred={pred}&filter={fid}")
    assert cats["channels"] == [{"channel": "Security", "count": 5, "shown": 0}]
    shown = {(h, f): n for h, _, _, f, _, n in get(f"/api/shown?filter={fid}")["counts"]}
    assert shown[("DESKTOP", "DESKTOP/Windows/System32/winevt/Logs/Security.evtx")] == 3 and (
        "DC01", "DC01/Windows/System32/winevt/Logs/Security.evtx") not in shown
    # Exports ignore filters unless asked; asked, the file name and the response say so.
    full = json.loads(request(port, "POST", "/api/export", cookie=cookie,
                              body={"start": T0 - 7200 * SEC, "end": T0 + 7200 * SEC})[1])
    part = json.loads(request(port, "POST", "/api/export", cookie=cookie,
                              body={"start": T0 - 7200 * SEC, "end": T0 + 7200 * SEC, "filter": fid})[1])
    assert (full["rows"], part["rows"]) == (12, 7) and "_filtered" in part["path"] and "_filtered" not in full["path"]
    assert part["filter"] == "Hidden: events with channel Security and host DC01."


def load_capture_records(case):
    """One capture's Suricata records of three types, as the MTA case's EVE file holds eight: 3 flow, 2 dns, and 1 alert,
    20 minutes after T0, in the network lane."""
    from conftest import NETWORK_CAPTURE

    from glessner.events import Event, load

    kinds = ["flow"] * 3 + ["dns"] * 2 + ["alert"]
    load(case.db_path, [Event(T0 + (1200 + i) * SEC, "Record time", "suricata", NETWORK_CAPTURE, str(i), f"{kind} record",
                              log_channel=kind, event_provider="Suricata") for i, kind in enumerate(kinds)],
         host="network", tool="suricata", tool_version="8.0.7", run_id="r7", replaces_sources=[NETWORK_CAPTURE],
         staging_dir=case.folder)


def test_sources_list_the_record_types_in_a_capture_s_file_and_hide_one(synthetic_case):
    """The Sources panel lists Suricata's record types under a capture's file, so they can be shown or hidden apart. A
    file whose events have several channels lists them, and the shown counts come per channel. An event log file, one
    channel, lists none."""
    from conftest import NETWORK_CAPTURE, serving

    load_capture_records(synthetic_case)
    for app, port, _ in serving(synthetic_case):
        cookie = login(port, app)
        get = lambda path: json.loads(request(port, "GET", path, cookie=cookie)[1])   # noqa: B023
        hosts = {h["host"]: h for h in get("/api/sources")["hosts"]}
        assert hosts["network"]["artifacts"][0]["files"] == [{"file": NETWORK_CAPTURE, "count": 6, "channels": [
            {"channel": "flow", "count": 3}, {"channel": "dns", "count": 2}, {"channel": "alert", "count": 1}]}]
        assert all("channels" not in f for a in hosts["DC01"]["artifacts"] for f in a["files"])
        flow = {"host": "network", "tool": "suricata", "artifact": "suricata", "file": NETWORK_CAPTURE, "channel": "flow"}
        fid = json.loads(request(port, "POST", "/api/filter", cookie=cookie, body={"hide": [flow]})[1])["id"]
        shown = sorted(r[4:] for r in get(f"/api/shown?filter={fid}")["counts"] if r[0] == "network")
        assert shown == [["alert", 1], ["dns", 2]]
        lanes_now = {lane["keys"][0]: lane["count"] for lane in get(f"/api/lanes?groupby=host&filter={fid}")["lanes"]}
        assert lanes_now["network"] == 3


def test_view_shows_marks_and_values_and_fades_pivot_results(synthetic_case):
    """The View shows events by mark or pinned value; pivot results it hides come back faded."""
    from test_analysis_relations import build_tables

    from glessner.filters import FilterStore
    from glessner.queries import BASE_FROM, BASE_WHERE

    con, journal, identity = open_case(synthetic_case)
    rdp = con.execute("SELECT event_uid FROM events WHERE tool = 'evtxecmd' AND ts_us = ?", [T0]).fetchone()[0]
    journal.append("mark", targets=[rdp], value="malicious")
    build_tables(con, journal.state, identity)
    shown = lambda spec: {u for (u,) in con.execute(
        f"SELECT e.event_uid FROM {BASE_FROM} WHERE {BASE_WHERE}{where_sql(normalize(spec))}").fetchall()}
    chain = {"view": {"marks": ["Suspicious", "Malicious"]}}
    assert normalize(chain)["view"] == {"marks": ["Malicious", "Suspicious"], "values": []}   # canonical order
    assert shown(chain) == {rdp}
    # A pinned value adds its events: DC01's logon from DESKTOP's address.
    from_desktop = {u for (u,) in con.execute("SELECT event_uid FROM events WHERE source_ip = '10.42.85.115'").fetchall()}
    assert shown({"view": {"marks": ["Malicious"], "values": [{"ip": "10.42.85.115"}]}}) == {rdp} | from_desktop
    # Pivot results the view hides still show, flagged faded, until marked.
    other = sorted(from_desktop)[0]
    store = FilterStore()
    fid = store.add({"view": {"marks": ["Malicious"]}, "faded": [other, rdp]})
    events = view(con, identity, ["mark", "host"], T0 - 3600 * SEC, T0 + 3600 * SEC, 100, 50_000, False,
                  store.get(fid)[1], store.faded(fid))["events"]
    assert {e["uid"]: e.get("faded", False) for e in events} == {rdp: False, other: True}
    assert describe(store.get(fid)[0]) == "View: events marked Malicious. Plus 2 pivot results, shown faded."
    # A sources-only filter keeps its old form and ID; bad views are refused.
    assert "view" not in normalize({"hide": [{"host": "DC01"}]})
    for bad in ({"view": {"marks": ["Evil"]}}, {"view": "chain"}, {"view": {}, "faded": ["not-an-id"]}):
        with pytest.raises(FilterError):
            normalize(bad)


def test_view_can_include_suggested_tags(synthetic_case):
    """Include suggested tags. Off, the View's tag values match the analyst's tags only; on, Hayabusa's pending
    suggestions too, never a dismissed one. The Sources part and the Untagged lane don't change."""
    from test_tags import ATTACK_HIT, rdp_uid

    from glessner.analysis import refresh_tags
    from glessner.events import load
    from glessner.filters import filter_id
    from glessner.queries import BASE_FROM, BASE_WHERE, tag_counts

    load(synthetic_case.db_path, [ATTACK_HIT], host="DC01", tool="hayabusa", tool_version="t", run_id="r6",
         replaces_sources=[], staging_dir=synthetic_case.folder)
    con, journal, _ = open_case(synthetic_case)
    uid = rdp_uid(con)
    shown = lambda spec: {u for (u,) in con.execute(
        f"SELECT e.event_uid FROM {BASE_FROM} WHERE {BASE_WHERE}{where_sql(normalize(spec))}").fetchall()}
    view = lambda pred, on: {"view": {"values": [pred], "suggested_tags": on}}
    # Hayabusa suggests Lateral Movement, Credential Access, and T1021.001 for the RDP logon; nobody has accepted them.
    for pred in ({"tag": "tactic:TA0008"}, {"tag": "technique:T1021.001"}, {"tag": "*"}, {"tactic": "Lateral Movement"}):
        assert (shown(view(pred, False)), shown(view(pred, True))) == (set(), {uid}), pred
    assert shown(view({"tag": "tactic:TA0001"}, True)) == set()   # a tactic nothing suggested
    assert tag_counts(con)["any"] == 0 and tag_counts(con)["any_suggested"] == 1   # what Any tag would add
    # The Untagged lane keeps the lanes' meaning, read from accepted tags, and the Sources part ignores the setting.
    assert uid in shown(view({"tactic": "Untagged"}, True))
    # So with Untagged as the only tag value the setting changes nothing, and is dropped: the same ID and no note.
    assert normalize(view({"tactic": "Untagged"}, True)) == normalize(view({"tactic": "Untagged"}, False))
    assert shown({"only": [{"tag": "tactic:TA0008"}], **view({"tag": "*"}, True)}) == set()
    # A dismissed suggestion never matches; an accepted one matches either way.
    journal.append("tag_suggestion", targets=[uid], tags=["tactic:TA0006"], decision="dismissed")
    journal.append("tag", targets=[uid], add=["tactic:TA0008"], via="hayabusa")
    refresh_tags(con, journal.state, [uid])
    assert shown(view({"tag": "tactic:TA0006"}, True)) == set()
    assert shown(view({"tag": "tactic:TA0008"}, False)) == shown(view({"tag": "tactic:TA0008"}, True)) == {uid}
    assert tag_counts(con)["any"] == 1 and tag_counts(con)["any_suggested"] == 0
    # On is another filter, and its description says so, for the filtered export and the findings summary. Without a
    # tag value it changes nothing, so it's dropped and the filter keeps its ID.
    on, off = normalize(view({"tag": "tactic:TA0008"}, True)), normalize(view({"tag": "tactic:TA0008"}, False))
    assert on["view"]["suggested_tags"] is True and "suggested_tags" not in off["view"] and filter_id(on) != filter_id(off)
    assert describe(on) == ("View: events with tag tactic:TA0008. "
                            "Tag values also match Hayabusa's suggested tags, not yet accepted.")
    assert describe(off) == "View: events with tag tactic:TA0008."
    assert normalize({"view": {"marks": ["Malicious"], "suggested_tags": True}}) == normalize({"view": {"marks": ["Malicious"]}})
    with pytest.raises(FilterError):
        normalize({"view": {"values": [{"tag": "*"}], "suggested_tags": "yes"}})


def test_filtered_findings_say_when_suggested_tags_are_included(synthetic_case):
    """The filtered export and the findings summary take the event only Hayabusa's suggestion tags when the setting is
    on, and their note says so. The case has a suggestion, so the test checks the event as well as the note."""
    from conftest import serving
    from test_tags import ATTACK_HIT, rdp_uid

    from glessner.events import load

    load(synthetic_case.db_path, [ATTACK_HIT], host="DC01", tool="hayabusa", tool_version="t", run_id="r6",
         replaces_sources=[], staging_dir=synthetic_case.folder)
    for app, port, _ in serving(synthetic_case):
        cookie = login(port, app)
        post = lambda path, body: json.loads(request(port, "POST", path, cookie=cookie, body=body)[1])   # noqa: B023
        post("/api/mark", {"uids": [rdp_uid(app.con)], "value": "suspicious"})   # findings list marked events only
        span = {"start": T0 - 7200 * SEC, "end": T0 + 7200 * SEC}
        results = {}
        for on in (False, True):
            fid = post("/api/filter", {"view": {"values": [{"tag": "*"}], "suggested_tags": on}})["id"]
            results[on] = post("/api/export", {**span, "filter": fid}), post("/api/report", {"filter": fid})
        (export_off, findings_off), (export_on, findings_on) = results[False], results[True]
        assert (export_off["rows"], findings_off["events"], export_on["rows"], findings_on["events"]) == (0, 0, 1, 1)
        note = "View: events with tag *. Tag values also match Hayabusa's suggested tags, not yet accepted."
        assert export_on["filter"] == findings_on["filter"] == note
        assert export_off["filter"] == findings_off["filter"] == "View: events with tag *."
        with open(findings_on["path"], encoding="utf-8") as f:
            assert "suggested tags, not yet accepted" in f.read()


def test_view_values_match_pivots_and_event_data(synthetic_case):
    """Add to View picks the same events as the matching pivot, letter case aside, and any event-data field can be a
    View value."""
    from conftest import DC_LOG, logon

    from glessner.events import load
    from glessner.queries import BASE_FROM, BASE_WHERE, RELATED

    # The same account logged in another letter case, as Szechuan logs C137.LOCAL and C137.local.
    load(synthetic_case.db_path,
         [logon(T0 + 5 * SEC, 106, DC_LOG, user="ADMINISTRATOR", domain="c137", ltype="3", ip="10.42.85.115")],
         host="DC01", tool="evtxecmd", tool_version="t", run_id="r7", replaces_sources=[], staging_dir=synthetic_case.folder)
    con, _, _ = open_case(synthetic_case)
    shown = lambda pred: {u for (u,) in con.execute(
        f"SELECT e.event_uid FROM {BASE_FROM} WHERE {BASE_WHERE}{where_sql(normalize({'view': {'values': [pred]}}))}").fetchall()}
    pivot = lambda kind, *params: {u for (u,) in con.execute(
        f"SELECT e.event_uid FROM events e WHERE {BASE_WHERE} AND {RELATED[kind][1]}", list(params)).fetchall()}
    by_account = pivot("account", "C137", "Administrator")
    assert shown({"user": r"C137\Administrator"}) == by_account and len(by_account) >= 4
    assert shown({"ip": "10.42.85.115"}) == pivot("source_ip", "10.42.85.115")
    # An event-data field by name, any case; events without the field don't match. Its matches are saved before the
    # filter is used, as a search's are.
    from glessner.search import save_value

    explicit = {u for (u,) in con.execute("SELECT event_uid FROM events WHERE event_code = '4648'").fetchall()}
    save_value(con, "data.TargetServerName", "citadel-dc01.c137.LOCAL")
    assert shown({"data.TargetServerName": "citadel-dc01.c137.LOCAL"}) == explicit
    # Hiding the value takes out only its matches. Events without the field stay: the value's test is false for them,
    # not NULL, so hiding it doesn't hide them.
    hidden = normalize({"hide": [{"data.TargetServerName": "citadel-dc01.c137.LOCAL"}]})
    every, rest = ({u for (u,) in con.execute(f"SELECT e.event_uid FROM {BASE_FROM} WHERE {BASE_WHERE}{w}").fetchall()}
                   for w in ("", where_sql(hidden)))
    assert rest == every - explicit
    assert shown({"process": r"c:\windows\system32\NOTHERE.exe"}) == set()
    with pytest.raises(FilterError):
        normalize({"view": {"values": [{'data.a"b': "x"}]}})


def test_view_at_either_end(synthetic_case, tmp_path):
    """View at either end shows the events the IP pivot at either end finds, an inbound Sysmon 3 with the attacker as
    destination among them; viewing the address as source or as destination alone is unchanged. Its description reads
    "IP ... at either end", for the filtered export and the findings summary."""
    from test_analysis_relations import ATTACKER, load_inbound

    from glessner.queries import BASE_FROM, BASE_WHERE, related

    uids = load_inbound(synthetic_case, tmp_path)
    con, _, _ = open_case(synthetic_case)
    shown = lambda spec: {u for (u,) in con.execute(
        f"SELECT e.event_uid FROM {BASE_FROM} WHERE {BASE_WHERE}{where_sql(normalize(spec))}").fetchall()}
    view = lambda pred: {"view": {"values": [pred]}}
    pivot = {e["uid"] for e in related(con, uids["inbound"], "addr", ip=ATTACKER)["events"]}
    assert shown(view({"addr": ATTACKER})) == pivot == {uids["inbound"], uids["rdp"], uids["failed"]}
    assert shown(view({"ip": ATTACKER})) == {uids["rdp"], uids["failed"]}   # unchanged: the source IP alone
    assert shown(view({"dest_ip": ATTACKER})) == {uids["inbound"]}
    assert shown(view({"addr": "fe80::bad"})) == {uids["ipv6_in"], uids["ipv6_logon"]}
    # Hiding it takes those events out and leaves every event without the address, including those with no address.
    everything = shown({})
    assert shown({"hide": [{"addr": ATTACKER}]}) == everything - pivot
    assert describe(normalize(view({"addr": ATTACKER}))) == f"View: events with IP {ATTACKER} at either end."
    assert describe(normalize({"hide": [{"addr": ATTACKER, "host": "DC01"}]})) == (
        f"Hidden: events with IP {ATTACKER} at either end and host DC01.")
    with pytest.raises(FilterError, match="'addr'"):   # the error lists it among the fields
        normalize({"hide": [{"address": ATTACKER}]})


TARGET = "CITADEL-DC01.c137.local"   # the synthetic case's 4648 records it as TargetServerName


def test_a_views_data_value_is_saved_and_saved_again_after_a_load(synthetic_case):
    """A View's event data value is matched once and saved, as a search is, so a pan reads the saved
    matches rather than every event's data. A load drops them, and the next use matches again. Values that differ only
    in their spaces are kept apart."""
    from conftest import WS_LOG, logon

    from glessner.events import load
    from glessner.search import is_saved, normalize_query, value_key
    from glessner.server import App, api_filter, api_view

    app = App(synthetic_case)
    try:
        fid = api_filter(app, {"view": {"values": [{"data.TargetServerName": TARGET.lower()}]}})["id"]
        query = {"start": [str(T0 - 3600 * SEC)], "end": [str(T0 + 3600 * SEC)], "groupby": ["host"], "filter": [fid]}
        key = value_key("data.TargetServerName", TARGET.lower())
        assert api_view(app, query)["count"] == 1 and is_saved(app.con, key)
        again = logon(T0 + 950 * SEC, 204, WS_LOG, code="4648", extra={"TargetServerName": TARGET})
        load(synthetic_case.db_path, [again], host="DESKTOP", tool="evtxecmd", tool_version="t", run_id="r9",
             replaces_sources=[], staging_dir=synthetic_case.folder)
        app.refresh_identity(events_changed=True)   # as a job's after() and an import do
        assert not is_saved(app.con, key)
        assert api_view(app, query)["count"] == 2 and is_saved(app.con, key)
    finally:
        app.con.close()
    assert value_key("data.X", "a  b") != value_key("data.X", "a b")
    assert normalize_query(value_key("data.X", "a  b")) == value_key("data.X", "a  b")


def test_a_pivot_result_a_data_value_hides_is_drawn_faded(synthetic_case):
    """Read from the saved matches, a data value's test is false, not NULL, for an event without the field, so a pivot
    result the View hides comes back with its faded flag and is drawn faded, not as an ordinary tick."""
    from glessner.server import App, api_filter, api_view

    app = App(synthetic_case)
    try:
        rdp, explicit = (app.con.execute("SELECT event_uid FROM events WHERE ts_us = ? AND event_code = ?", params)
                         .fetchone()[0] for params in ([T0, "4624"], [T0 + 900 * SEC, "4648"]))
        fid = api_filter(app, {"view": {"values": [{"data.TargetServerName": TARGET}]}, "faded": [rdp]})["id"]
        events = api_view(app, {"start": [str(T0 - SEC)], "end": [str(T0 + 3600 * SEC)], "groupby": ["host"],
                                "filter": [fid]})["events"]
        assert {e["uid"]: e.get("faded", False) for e in events} == {rdp: True, explicit: False}
    finally:
        app.con.close()


def test_the_views_user_value_matches_the_bare_name_as_search_does(synthetic_case):
    """search's user: takes the bare name and a SID, and the View's value reads as search does, so the same text finds
    the same events in both. A DOMAIN\\name value stays exact. The bare-name match is for View values only: a user
    lane's menu makes {user: label} for its Hide and Show only, and a bare name there must stay that one lane."""
    from conftest import DC_LOG, WS_LOG

    from glessner.events import Event, load
    from glessner.queries import BASE_FROM, BASE_WHERE
    from glessner.search import results, save_hits
    sid = "S-1-5-21-1-2-3-500"

    def event(record, log, domain, extra=None, name="Administrator", code=""):
        return Event(ts_us=T0 + record * SEC, ts_desc="x", artifact="evtx", source_file=log, source_record=str(record),
                     message=f"account {record}", user_name=name, user_domain=domain, extra=extra, event_code=code)
    # Event 3 names its user by SID only; the host's 4624 (event 5) records the SID with a name, which the load looks up
    # (accounts.py) and records as AccountLookedUpSid
    naming = {"TargetUserSid": sid, "TargetUserName": "Administrator", "TargetDomainName": "C137"}
    load(synthetic_case.db_path, [event(1, WS_LOG, ""), event(2, WS_LOG, "DESKTOP-SDN1RPT"),
                                  event(3, DC_LOG, "", {"SecurityUserID": sid}, name=sid),
                                  event(4, DC_LOG, "C137", name="other"), event(5, DC_LOG, "C137", naming, code="4624")],
         host="DESKTOP", tool="evtxecmd", tool_version="t", run_id="r31", replaces_sources=[], staging_dir=synthetic_case.folder)
    con, _, _ = open_case(synthetic_case)
    uid = lambda record: con.execute("SELECT event_uid FROM events WHERE source_record = ? AND message LIKE 'account%'",
                                     [str(record)]).fetchone()[0]
    shown = lambda spec: {u for (u,) in con.execute(
        f"SELECT e.event_uid FROM {BASE_FROM} WHERE {BASE_WHERE}{where_sql(normalize(spec))}").fetchall()}
    view = lambda value: shown({"view": {"values": [{"user": value}]}})
    found = lambda q: {e["uid"] for e in results(con, save_hits(con, q)[0])["events"]}
    # The bare name: the View shows what search finds, in every domain, the account written without one included
    bare = view("administrator")
    assert bare == found("user:administrator") and {uid(1), uid(2), uid(3)} <= bare and uid(4) not in bare
    assert len(bare) > 3   # and C137\Administrator's logons on DC01
    # A DOMAIN\name value stays exact
    exact = view(r"C137\Administrator")
    assert exact == found(r"user:C137\Administrator") and uid(1) not in exact and uid(2) not in exact and uid(3) in exact
    # A SID matches the accounts looked up from it, as search's does
    assert view(sid) == found(f"user:{sid}") == {uid(3)}
    # A lane's menu makes {user: label}: Hide on the no-domain Administrator lane hides that lane only
    every = shown({})
    assert every - shown({"hide": [{"user": "Administrator"}]}) == {uid(1)}
    assert shown({"only": [{"user": "Administrator"}]}) == {uid(1)}
    assert every - shown({"hide": [{"user": r"C137\Administrator"}]}) == exact


def test_an_account_written_as_an_import_wrote_it_matches_in_search_and_the_view(synthetic_case):
    """An imported log's alice@C137.LOCAL or mortysmith/C137.LOCAL is stored as domain and name (imports.split_account), and
    the text as the log wrote it still finds it, in search's user: and the View's value."""
    from conftest import WS_LOG

    from glessner.events import Event, load
    from glessner.queries import BASE_FROM, BASE_WHERE
    from glessner.search import results, save_hits

    def event(record, name, domain):
        return Event(ts_us=T0 + record * SEC, ts_desc="x", artifact="csv_fixture", source_file=WS_LOG, source_record=str(record),
                     message=f"realm account {record}", user_name=name, user_domain=domain)
    load(synthetic_case.db_path, [event(1, "alice", "C137.LOCAL"), event(2, "mortysmith", "C137.LOCAL"), event(3, "alice", "")],
         host="DESKTOP", tool="import", tool_version="t", run_id="r32", replaces_sources=[], staging_dir=synthetic_case.folder)
    con, _, _ = open_case(synthetic_case)
    uid = lambda record: con.execute("SELECT event_uid FROM events WHERE source_record = ? AND message LIKE 'realm%'",
                                     [str(record)]).fetchone()[0]
    found = lambda q: {e["uid"] for e in results(con, save_hits(con, q)[0])["events"]}
    shown = lambda value: {u for (u,) in con.execute(
        f"SELECT e.event_uid FROM {BASE_FROM} WHERE {BASE_WHERE}"
        f"{where_sql(normalize({'view': {'values': [{'user': value}]}}))}").fetchall()}
    for text, want in (("alice@c137.local", {uid(1)}), ("mortysmith/C137.LOCAL", {uid(2)}),
                       (r"C137.LOCAL\alice", {uid(1)}), ("alice", {uid(1), uid(3)})):
        assert found(f"user:{text}") >= want and shown(text) >= want, text
    assert uid(2) not in found("user:alice@c137.local") | shown("alice@c137.local")
