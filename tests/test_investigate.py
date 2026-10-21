"""To investigate as a worklist with ask-first confirmation, on the server side: the unreviewed narrowing of a pivot's
count and its list, the worklist's items and their ranked rows, the Followed up tick across a mark change, and a
confirmed group action that covers the events the page counted and skips the ones decided meanwhile."""

import json

import pytest
from conftest import DC_LOG, SEC, T0, logon
from test_pivots import guide, load_events, more, papp, pcase, pcase_events, security_event, uid_of  # noqa: F401
from test_server import login, request

from glessner.events import Event
from glessner.journal import JOURNAL_FILE
from glessner.queries import QueryError, related
from glessner.server import (
    App,
    api_followup,
    api_investigate,
    api_mark,
    api_pending,
    api_pivot_count,
    api_related,
    api_rule,
    api_suggestion,
    api_tag,
)

RDP = "event_code = '4624' AND logon_type = '10' AND source_ip = '194.61.24.102'"


def last_entry(app):
    return json.loads((app.case.folder / JOURNAL_FILE).read_text(encoding="utf-8").splitlines()[-1])


def count(app, uid, kind, **more):
    return api_pivot_count(app, {"uid": [uid], "kind": [kind], **{k: [str(v)] for k, v in more.items()}})["count"]


def listed(app, uid, kind, **more):
    return api_related(app, {"uid": [uid], "kind": [kind], **{k: [str(v)] for k, v in more.items()}})


def test_an_unreviewed_count_equals_the_total_of_the_list_it_opens_on_several_pivot_kinds(papp):  # noqa: F811
    """A To investigate count is blue and opens the pivot's list kept to unreviewed events, so each count equals its
    list's total. Checked on a logon session, a source IP, an address at either end, the host's
    window, and an account, with one related event marked: the unreviewed count and list leave it out, the plain ones
    keep it, and no listed event carries a mark. A pending suggestion is not a mark, so such an event still counts."""
    rdp = uid_of(papp.con, RDP)
    same = [logon(T0 + (700 + n) * SEC, 9900 + n, DC_LOG, ip="194.61.24.102", logon_id="0x510986") for n in range(3)]
    more(papp, same)
    marked = uid_of(papp.con, "record_id = 9901")
    api_mark(papp, {"uids": [rdp], "value": "malicious"})
    api_mark(papp, {"uids": [marked], "value": "authorized"})
    kinds = [("session", {}), ("source_ip", {}), ("addr", {"ip": "194.61.24.102"}), ("window", {"seconds": 3600}),
             ("account", {})]
    for kind, args in kinds:
        every, unreviewed = count(papp, rdp, kind, **args), count(papp, rdp, kind, unreviewed=1, **args)
        plain, res = listed(papp, rdp, kind, **args), listed(papp, rdp, kind, unreviewed=1, **args)
        assert res["total"] == unreviewed == len(res["events"]), kind
        assert res["unreviewed"] is True and "unreviewed" not in plain, kind
        # The plain list holds the authorized event, and the anchor itself where the kind lists it; the unreviewed one neither
        with_mark = sum(1 for e in plain["events"] if e["mark"] in ("Malicious", "Suspicious", "Authorized"))
        assert unreviewed >= 1 and with_mark >= 1 and every == unreviewed + with_mark, (kind, every, unreviewed, with_mark)
        assert marked not in {e["uid"] for e in res["events"]}, kind
        assert all(e["mark"] == "Unreviewed" or e["mark"].startswith("Suggested: ") for e in res["events"]), kind
    # The query agrees without the server too
    direct = related(papp.con, rdp, "session", identity=papp.identity, unreviewed=True)
    assert direct["total"] == count(papp, rdp, "session", unreviewed=1)


def test_the_worklist_gives_each_event_its_top_countable_rows_and_leaves_out_search_and_system_sessions(papp):  # noqa: F811
    """Each marked event carries at most WORKLIST_ROWS rows from its kind's ranking, in rank order, each one a pivot the
    page can count as unreviewed events: never a search row, and never Same logon session on one of Windows' own sessions.
    The items carry who marked them and when, as every list does."""
    from glessner.pivots import WORKLIST_ROWS

    rdp = uid_of(papp.con, RDP)
    system = security_event(T0 + 400 * SEC, 9601, "4672", logon_id="0x3E7", user_name="SYSTEM", user_domain="NT AUTHORITY")
    more(papp, [system])
    api_mark(papp, {"uids": [rdp, uid_of(papp.con, "record_id = 9601")], "value": "suspicious"})
    res = api_investigate(papp, {})
    items = {i["uid"]: i for i in res["items"]}
    assert len(items) == 2 and all(i["mark_who"] == "cody" and i["mark_at"] for i in items.values())
    rows = items[rdp]["rows"]
    assert [r["pivot"] for r in rows] == ["session", "addr", "window"] and [r["n"] for r in rows] == [1, 2, 3]
    assert rows[1]["ip"] == "194.61.24.102" and rows[2]["seconds"] == 300 and all(r["reason"] for r in rows)
    assert len(rows) <= WORKLIST_ROWS
    privileges = items[uid_of(papp.con, "record_id = 9601")]["rows"]
    assert "session" not in [r["pivot"] for r in privileges]
    assert "search" not in [r["pivot"] for i in items.values() for r in i["rows"]]
    # A source with pending suggestions names the events it would act on and the first of them, for the confirm
    rule = next(r for r in res["rules"] if r["id"] == "machine-accounts-authorized")
    assert rule["pending"] == len(rule["uids"]) == 1 and rule["first"][0]["uid"] == rule["uids"][0]
    assert rule["description"].startswith("Machine-account network logons") and rule["builtin"]
    assert "uids" not in next(r for r in res["rules"] if r["id"] == "print-spooler-pipe")


def test_a_followed_up_tick_stays_across_a_mark_change_and_the_item_says_so(synthetic_case):
    """A later mark leaves the Followed up tick, and the worklist's row says the mark changed after it."""
    app = App(synthetic_case)
    try:
        rdp = app.con.execute("SELECT event_uid FROM events WHERE tool = 'evtxecmd' AND ts_us = ?", [T0]).fetchone()[0]
        api_mark(app, {"uids": [rdp], "value": "suspicious"})
        assert api_investigate(app, {})["items"][0]["followup"] is None
        ticked = api_followup(app, {"uids": [rdp], "done": True})["seq"]
        item = api_investigate(app, {})["items"][0]
        assert (item["followup"]["seq"], item["followup"]["who"], item["followup"]["after_mark"]) == (ticked, "cody", False)
        api_mark(app, {"uids": [rdp], "value": "malicious"})
        item = api_investigate(app, {})["items"][0]
        assert item["mark"] == "Malicious" and item["followup"]["seq"] == ticked and item["followup"]["after_mark"] is True
        api_followup(app, {"uids": [rdp], "done": False})
        assert api_investigate(app, {})["items"][0]["followup"] is None
    finally:
        app.con.close()


def test_a_confirmed_group_action_covers_the_counted_events_and_skips_those_decided_meanwhile(running):
    """The page sends the exact events it counted with the count its confirm stated. One event that became pending
    after the page counted is not touched; one decided elsewhere in between is skipped, and the answer and the entry's
    `confirmed` say so. /api/pending carries each group's uids, and /api/pending_uids what is pending now."""
    from glessner.server import api_pending_uids

    app, port, _ = running
    cookie = login(port, app)
    api_rule(app, {"op": "add", "text": "id: logons\nsuggest: suspicious\nwhen: {field: event_code, equals: '4624'}\n"})
    pending = json.loads(request(port, "GET", "/api/pending?source=logons&group_by=host", cookie=cookie)[1])
    counted = [u for g in pending["groups"] for u in g["uids"]]
    assert pending["total"] == len(counted) >= 5 and all(len(g["uids"]) == g["count"] for g in pending["groups"])
    # A group's uids are what /api/pending_uids gives for the group now
    group = pending["groups"][0]
    now_in_group = api_pending_uids(app, {"source": ["logons"], "group_by": ["host"], "group": [group["key"]]})["uids"]
    assert sorted(now_in_group) == sorted(group["uids"])
    late, elsewhere, *rest = counted
    # One of the counted is rejected first, so that its restore later makes it pending after the count
    api_suggestion(app, {"decision": "reject", "source": "logons", "uids": [late]})
    page_counted = [u for u in counted if u != late]
    api_suggestion(app, {"decision": "restore", "source": "logons", "uids": [late]})   # arrived after the page counted
    api_mark(app, {"uids": [elsewhere], "value": "authorized"})                        # decided elsewhere meanwhile
    now = api_pending_uids(app, {"source": ["logons"]})["uids"]
    assert late in now and elsewhere not in now and set(now) - set(page_counted) == {late}
    confirmed = {"decision": "accept", "source": "logons", "uids": page_counted, "confirmed": {"count": len(page_counted)}}
    res, body = request(port, "POST", "/api/suggestion", cookie=cookie, body=confirmed)
    assert res.status == 200
    answer = json.loads(body)
    assert (answer["changed"], answer["skipped"]) == (len(page_counted) - 1, 1)
    entry = last_entry(app)
    assert entry["action"] == "mark" and entry["confirmed"] == {"count": len(page_counted), "skipped": 1}
    assert sorted(entry["targets"]) == sorted(rest)
    assert api_pending_uids(app, {"source": ["logons"]})["uids"] == [late]   # the late one stays pending, untouched
    # A reject of a confirmed set records the same, and a refusal names what is wrong with the request
    res, body = request(port, "POST", "/api/suggestion", cookie=cookie,
                        body={"decision": "reject", "source": "logons", "uids": [late, elsewhere], "confirmed": {"count": 2}})
    assert json.loads(body)["skipped"] == 1 and last_entry(app)["confirmed"] == {"count": 2, "skipped": 1}
    for bad in ({"confirmed": {"count": -1}, "uids": [late]}, {"confirmed": 3, "uids": [late]}, {"confirmed": {"count": 1}}):
        with pytest.raises(QueryError):
            api_suggestion(app, {"decision": "reject", "source": "logons", **bad})
    # A mark or a tag confirmed records its count, and skips nothing
    api_mark(app, {"uids": [late], "value": "malicious", "confirmed": {"count": 1}})
    assert last_entry(app)["confirmed"] == {"count": 1, "skipped": 0}
    api_tag(app, {"uids": [late], "add": ["tag:checked"], "confirmed": {"count": 1}})
    assert last_entry(app)["confirmed"] == {"count": 1, "skipped": 0}


def test_show_all_first_lists_a_whole_group_up_to_the_servers_cap(running):
    """For Show all N first, /api/pending takes a limit above the usual 200, capped at the server's own."""
    from glessner import server

    app, port, _ = running
    cookie = login(port, app)
    api_rule(app, {"op": "add", "text": "id: logons\nsuggest: suspicious\nwhen: {field: event_code, equals: '4624'}\n"})
    def by_host(limit):
        return json.loads(request(port, "GET", f"/api/pending?source=logons&group_by=host&limit={limit}", cookie=cookie)[1])

    whole = by_host(50)
    assert [len(g["events"]) for g in by_host(1)["groups"]] == [1, 1]
    assert [len(g["events"]) for g in whole["groups"]] == [g["count"] for g in whole["groups"]] and whole["total"] > 2
    assert server.PENDING_LIMIT_MAX == 5_000 and by_host(10 ** 9)["total"] == whole["total"]
    assert api_pending(app, {"source": ["logons"], "group_by": ["host"], "limit": ["0"]})["groups"][0]["events"]


def test_the_worklist_leaves_out_a_search_row_that_ranks_in_the_top_three(papp):  # noqa: F811
    """A PowerShell script block's ranking puts a search for its block ID first, a field term the Event page counts. A
    search can't be kept to unreviewed events (`mark:` is the View's, not search's), so the worklist skips it and counts
    the rows after it."""
    script = Event(ts_us=T0 + 500 * SEC, ts_desc="Event Recorded", artifact="evtx", source_file=DC_LOG, source_record="9701",
                   record_id=9701, message="4104 script block", event_code="4104",
                   log_channel="Microsoft-Windows-PowerShell/Operational", extra={"ScriptBlockId": "b-1"})
    more(papp, [script])
    uid = uid_of(papp.con, "record_id = 9701")
    ranked = [r["pivot"] for r in guide(papp, uid)["rows"]]
    assert ranked[0] == "search" and ranked[1] == "window"   # the ranking holds a countable search first
    api_mark(papp, {"uids": [uid], "value": "suspicious"})
    item = next(i for i in api_investigate(papp, {})["items"] if i["uid"] == uid)
    assert [r["pivot"] for r in item["rows"]] == ["window"]   # the search is left out, and the event has no account


def test_a_rule_pivots_unreviewed_count_equals_its_list_and_drops_the_rules_whole_count(papp):  # noqa: F811
    """The rule pivot has a fast count of the whole rule's events; kept to unreviewed events it must count them as the list
    does, so one marked event of the rule lowers both."""
    hit = Event(ts_us=T0 + 63 * SEC, ts_desc="Event Recorded", artifact="hayabusa", source_file=DC_LOG,
                source_record="105:rule", record_id=105, message="RDP from internet [high]", log_channel="Security",
                rule_title="RDP from internet", rule_level="high")
    load_events(papp.case, [hit], "DC01", tool="hayabusa", run="r5b")
    papp.refresh_identity(events_changed=True)
    rdp, privileges = uid_of(papp.con, RDP), uid_of(papp.con, "event_code = '4672' AND record_id = 105")
    assert count(papp, rdp, "rule") == listed(papp, rdp, "rule")["total"] == 2   # the logon and the 4672 it hit
    api_mark(papp, {"uids": [privileges], "value": "authorized"})
    res = listed(papp, rdp, "rule", unreviewed=1)
    assert count(papp, rdp, "rule", unreviewed=1) == res["total"] == len(res["events"]) == 1
    assert count(papp, rdp, "rule") == 2


def test_the_worklist_ranks_an_event_by_its_hayabusa_hit(papp):  # noqa: F811
    """A kind the table doesn't name ranks the event's Hayabusa hit as a row of its own beside the host's window, so the
    worklist's rule row exists only when the hits reach the ranking: the flagged events' hits are read with them
    (queries.investigate)."""
    odd = Event(ts_us=T0 + 520 * SEC, ts_desc="Event Recorded", artifact="evtx", source_file=DC_LOG, source_record="9702",
                record_id=9702, message="9999 odd", event_code="9999", log_channel="Application")
    hit = Event(ts_us=T0 + 520 * SEC, ts_desc="Event Recorded", artifact="hayabusa", source_file=DC_LOG,
                source_record="9702:rule", record_id=9702, message="Odd thing [high]", log_channel="Application",
                rule_title="Odd thing", rule_level="high")
    more(papp, [odd])
    load_events(papp.case, [hit], "DC01", tool="hayabusa", run="r9")
    papp.refresh_identity(events_changed=True)
    uid = uid_of(papp.con, "record_id = 9702 AND tool = 'evtxecmd'")
    api_mark(papp, {"uids": [uid], "value": "malicious"})
    item = next(i for i in api_investigate(papp, {})["items"] if i["uid"] == uid)
    assert [r["pivot"] for r in item["rows"]] == ["window", "rule"] and item["rows"][1]["value"] == "Odd thing"
    assert [r["pivot"] for r in guide(papp, uid)["rows"]] == ["window", "rule"]


def test_a_confirmed_action_whose_counted_events_were_all_decided_meanwhile_acts_on_nothing(running):
    """The confirm names the events the page counted. When every one was decided elsewhere before the click, the
    request acts on none of them, not on every pending event: a suggestion that arrived after the page loaded stays
    pending, and no entry is written."""
    from glessner.server import api_pending_uids

    app, port, _ = running
    cookie = login(port, app)
    api_rule(app, {"op": "add", "text": "id: logons\nsuggest: suspicious\nwhen: {field: event_code, equals: '4624'}\n"})
    pending = json.loads(request(port, "GET", "/api/pending?source=logons", cookie=cookie)[1])
    counted = [u for g in pending["groups"] for u in g["uids"]]
    page_counted, arrived = counted[:2], counted[2:]
    assert len(arrived) >= 2
    api_mark(app, {"uids": page_counted, "value": "authorized"})   # decided elsewhere after the page counted them
    before = len(app.journal.path.read_text(encoding="utf-8").splitlines())
    for decision in ("accept", "reject"):
        body = {"decision": decision, "source": "logons", "uids": page_counted, "confirmed": {"count": 2}}
        res, answer = request(port, "POST", "/api/suggestion", cookie=cookie, body=body)
        assert res.status == 200 and (json.loads(answer)["changed"], json.loads(answer)["skipped"]) == (0, 2), decision
        assert len(app.journal.path.read_text(encoding="utf-8").splitlines()) == before, decision   # no entry
        assert sorted(api_pending_uids(app, {"source": ["logons"]})["uids"]) == sorted(arrived), decision


def test_show_all_first_is_cut_at_the_servers_cap(running, monkeypatch):
    """The limit "Show all N first" passes is clamped to PENDING_LIMIT_MAX: a limit above it lists no more than it."""
    from glessner import server

    app, port, _ = running
    cookie = login(port, app)
    api_rule(app, {"op": "add", "text": "id: logons\nsuggest: suspicious\nwhen: {field: event_code, equals: '4624'}\n"})
    monkeypatch.setattr(server, "PENDING_LIMIT_MAX", 2)
    res = json.loads(request(port, "GET", "/api/pending?source=logons&group_by=code&limit=1000000000", cookie=cookie)[1])
    group = res["groups"][0]
    assert group["count"] > 2 and len(group["events"]) == 2


def test_the_trail_says_when_an_action_was_confirmed_and_what_was_skipped(synthetic_case):
    """The journal records `confirmed {count, skipped}` on a mark, a tag, a suggestion's decision, and a link, and the
    trail's words end with it, so a reader can tell a confirmed action from one made at once, and see how many of the
    counted events were decided elsewhere. An entry with no consent reads as a plain entry."""
    from glessner.audit import describe, read_entries
    from glessner.server import api_finding

    app = App(synthetic_case)
    try:
        uids = [r[0] for r in app.con.execute("SELECT event_uid FROM events WHERE event_code = '4624' "
                                              "ORDER BY ts_us").fetchall()][:6]
        api_rule(app, {"op": "add", "text": "id: logons\nsuggest: suspicious\nwhen: {field: event_code, equals: '4624'}\n"})

        def last():
            return describe(read_entries(app.case.folder / JOURNAL_FILE)[-1])

        api_mark(app, {"uids": uids[:2], "value": "authorized", "note": ""})
        assert last() == "Marked 2 events Authorized"
        api_mark(app, {"uids": uids[:2], "value": "suspicious", "confirmed": {"count": 2}})
        assert last() == "Marked 2 events Suspicious (confirmed: 2 counted)"
        api_tag(app, {"uids": uids[:2], "add": ["tag:checked"], "confirmed": {"count": 2}})
        assert last().endswith(" (confirmed: 2 counted)") and last().startswith("Tagged 2 events")
        api_mark(app, {"uids": [uids[3]], "value": "authorized"})   # decided elsewhere after the page counted it
        api_suggestion(app, {"decision": "accept", "source": "logons", "uids": uids[2:4], "confirmed": {"count": 2}})
        assert last() == ("Marked 1 event Suspicious (accepted logons suggestions) "
                          "(confirmed: 2 counted, 1 skipped as decided meanwhile)")
        api_suggestion(app, {"decision": "reject", "source": "logons", "uids": [*uids[4:], uids[0]], "confirmed": {"count": 3}})
        assert last() == "Rejected the logons suggestion on 2 events (confirmed: 3 counted, 1 skipped as decided meanwhile)"
        made = api_finding(app, {"op": "add", "title": "Six logons", "severity": "Low", "targets": []})["finding"]
        api_finding(app, {"op": "link", "finding": made, "targets": uids, "confirmed": {"count": 6}})
        assert last().endswith(" (confirmed: 6 counted)") and last().startswith("Linked 6 events to the finding")
        api_followup(app, {"uids": uids[:1], "done": True, "confirmed": {"count": 1, "skipped": 0}})
        assert last().endswith(" (confirmed: 1 counted)")
    finally:
        app.con.close()
