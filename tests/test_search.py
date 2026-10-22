"""Search: words, phrases, field values, wildcards, and exclusions, across every field."""

import json
import urllib.parse

import pytest
from conftest import SEC, T0, WS_LOG
from test_analysis_relations import open_case
from test_server import login, request

from glessner.events import Event, load
from glessner.filters import normalize, where_sql
from glessner.queries import BASE_FROM, BASE_WHERE
from glessner.search import SearchError, Term, parse, results, save_hits


def test_parse_reads_words_phrases_fields_and_exclusions():
    assert parse('svchost "special privileges" ip:10.42.85.10 -code:4672 ProcessName:*\\cmd.exe') == [
        Term(False, "", "svchost", False), Term(False, "", "special privileges", True),
        Term(False, "ip", "10.42.85.10", False), Term(True, "code", "4672", False),
        Term(False, "data.ProcessName", "*\\cmd.exe", False)]
    # A drive letter or a time isn't a field name, and aliases name the app's fields.
    assert parse(r"C:\Windows 03:21") == [Term(False, "", r"C:\Windows", False), Term(False, "", "03:21", False)]
    assert parse('account:"C137\\Administrator" id:4624')[0].field == "user" and parse("id:4624")[0].field == "code"
    for bad in ("", "   ", "-svchost", "x" * 501, " ".join(["a"] * 21)):
        with pytest.raises(SearchError):
            parse(bad)


def test_search_matches_and_the_view_shows_them(synthetic_case):
    con, _, _ = open_case(synthetic_case)
    def hits(q):
        sid, _ = save_hits(con, q)
        return {e["uid"] for e in results(con, sid)["events"]}
    uids = lambda sql: {u for (u,) in con.execute(f"SELECT event_uid FROM events e WHERE {BASE_WHERE} AND {sql}").fetchall()}
    assert hits("194.61.24.102") == uids("e.source_ip = '194.61.24.102'")
    assert hits("ip:194.61.24.102") == hits("194.61.24.102")
    assert hits("user:administrator code:4624") == uids("lower(e.user_name) = 'administrator' AND e.event_code = '4624'")
    assert hits("code:4624 -ip:10.42.85.115") == uids("e.event_code = '4624' AND e.source_ip IS DISTINCT FROM '10.42.85.115'")
    assert hits("TargetServerName:citadel*") == uids("e.event_code = '4648'")   # event data, wildcard, any case
    assert hits("user:*sdn1rpt$") == uids("e.user_name = 'DESKTOP-SDN1RPT$'")
    assert hits('"4624 logon"') == uids("e.message = '4624 logon'")   # a phrase, as written
    assert hits("nothing_like_this") == set()
    # Saved once: the same search again reads the saved matches, and the View shows exactly them.
    assert con.execute("SELECT count(*) FROM search_runs").fetchone()[0] == 8
    hits("194.61.24.102")
    assert con.execute("SELECT count(*) FROM search_runs").fetchone()[0] == 8
    save_hits(con, "code:4624")   # as /api/filter does when a View holds a search
    shown = {u for (u,) in con.execute(f"SELECT e.event_uid FROM {BASE_FROM} WHERE {BASE_WHERE}"
                                       f"{where_sql(normalize({'view': {'values': [{'search': 'code:4624'}]}}))}").fetchall()}
    assert shown == uids("e.event_code = '4624'")


def test_search_api_and_errors(running):
    app, port, _ = running
    session = login(port, app)
    res, body = request(port, "GET", "/api/search?q=" + urllib.parse.quote("user:Administrator"), session=session)
    out = json.loads(body)
    assert res.status == 200 and out["total"] == len(out["events"]) >= 3 and out["terms"] == ['user is "Administrator"']
    assert out["first"] <= T0 <= out["last"]
    res, body = request(port, "GET", "/api/search?q=" + urllib.parse.quote("-only"), session=session)
    assert res.status == 400 and "isn't excluded" in json.loads(body)["error"]
    # A search in the View is saved when the filter registers, then shown like any value.
    res, body = request(port, "POST", "/api/filter", session=session, body={"view": {"values": [{"search": "code:4648"}]}})
    fid = json.loads(body)["id"]
    events = json.loads(request(port, "GET", f"/api/view?start={T0 - 3600 * 10**6}&end={T0 + 3600 * 10**6}"
                                             f"&groupby=mark,host&filter={fid}", session=session)[1])["events"]
    assert [e["code"] for e in events] == ["4648"]


def test_results_say_where_the_matches_are(synthetic_case):
    """A strip of counts over time, the busiest stretch, every match's ID, and where a word was found."""
    con, _, _ = open_case(synthetic_case)
    sid, terms = save_hits(con, "C137.local")
    res = results(con, sid, terms=terms)
    assert res["total"] > 2 and sum(res["strip"]["counts"]) == res["total"] and len(res["strip"]["counts"]) == 60
    assert res["strip"]["counts"][0] and res["strip"]["counts"][-1]   # the first and last matches open and close it
    core = res["core"]
    assert res["first"] <= core["start"] <= core["end"] <= res["last"] and core["count"] == -(-res["total"] // 2)
    assert len(res["uids"]) == res["total"] and not res["uids_limited"]
    assert {e["found"]["field"] for e in res["events"]} == {"Computer"}
    assert all("c137.local" in e["found"]["text"].lower() for e in res["events"])
    assert res["highlight"] == [{"value": "C137.local", "whole": False, "bounded": False}]
    # A word the shown message holds needs no "found in" line; a field term is highlighted as a whole value.
    sid, terms = save_hits(con, "logon code:4624")
    res = results(con, sid, terms=terms)
    assert all("found" not in e for e in res["events"])
    assert res["highlight"] == [{"value": "logon", "whole": False, "bounded": False},
                                {"value": "4624", "whole": True, "bounded": False}]


def test_every_field_term_compares_without_case_in_search_and_the_view(synthetic_case, tmp_path):
    """Every field term compares without case, in search and in the View, as the help says: host:desktop finds the
    host's events as host:DESKTOP does. An IPv6 address typed in upper case finds the lower-case form the parsers
    store."""
    from test_analysis_relations import load_inbound

    uids = load_inbound(synthetic_case, tmp_path)
    con, _, _ = open_case(synthetic_case)

    def hits(q):
        sid, _ = save_hits(con, q)
        return {e["uid"] for e in results(con, sid)["events"]}
    shown = lambda pred: {u for (u,) in con.execute(
        f"SELECT e.event_uid FROM {BASE_FROM} WHERE {BASE_WHERE}{where_sql(normalize({'view': {'values': [pred]}}))}").fetchall()}
    for field, value in (("host", "DC01"), ("tool", "evtxecmd"), ("artifact", "evtx"), ("channel", "Security"), ("run", "r1"),
                         ("file", "DC01/Windows/System32/winevt/Logs/Security.evtx"), ("code", "4624"), ("ip", "10.42.85.10")):
        found = hits(f"{field}:{value}")
        assert found, field
        assert hits(f'{field}:"{value.lower()}"') == hits(f'{field}:"{value.upper()}"') == found, field
        assert shown({field: value.swapcase()}) == shown({field: value}) and shown({field: value}), field
    assert hits("host:dc01") and hits("host:dc01") == hits("host:DC01") != hits("host:desktop")
    assert hits("-host:dc01 code:4624") == hits("-host:DC01 code:4624")
    assert uids["ipv6_in"] in hits("addr:FE80::BAD") and hits("addr:FE80::BAD") == hits("addr:fe80::bad")
    assert shown({"addr": "FE80::BAD"}) == shown({"addr": "fe80::bad"}) and shown({"addr": "fe80::bad"})


def test_parent_process_and_registry_data_are_fields(synthetic_case):
    """The parent process, its command line, and a registry value's data are search fields with short names, View
    values in any letter case, "found in" fields, and export columns."""
    import csv

    from conftest import SEC

    from glessner.events import Event, load
    from glessner.export import export_timeline

    w3wp = "C:\\Windows\\System32\\inetsrv\\w3wp.exe"
    sysmon = "DC01/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx"
    load(synthetic_case.db_path, [
        Event(T0 + 30 * SEC, "Event Recorded", "evtx", sysmon, "1", "1 Process creation | parent w3wp.exe", event_code="1",
              process_executable="C:\\Windows\\System32\\cmd.exe", process_parent_executable=w3wp,
              process_parent_command_line=f'{w3wp} -ap "DefaultAppPool"'),
        Event(T0 + 31 * SEC, "Event Recorded", "evtx", sysmon, "2", "13 Registry value set", event_code="13",
              registry_path="HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
              registry_data="C:\\Users\\Public\\u.dll")],
         host="DC01", tool="evtxecmd", tool_version="t", run_id="r8", replaces_sources=[sysmon],
         staging_dir=synthetic_case.folder)
    con, _, identity = open_case(synthetic_case)
    uid = lambda record: con.execute("SELECT event_uid FROM events WHERE source_file = ? AND source_record = ?",
                                     [sysmon, record]).fetchone()[0]
    shell, value = uid("1"), uid("2")

    def hits(q):
        sid, _ = save_hits(con, q)
        return {e["uid"] for e in results(con, sid)["events"]}
    assert hits("parent:*\\w3wp.exe") == hits("parent_process:*W3WP.EXE") == hits("parent_cmd:*defaultapppool*") == {shell}
    assert hits("registry_data:*.dll") == {value} and hits("parent_command_line:x") == set()
    shown = lambda pred: {u for (u,) in con.execute(
        f"SELECT e.event_uid FROM {BASE_FROM} WHERE {BASE_WHERE}{where_sql(normalize({'view': {'values': [pred]}}))}").fetchall()}
    assert shown({"parent": w3wp.upper()}) == {shell} and shown({"registry_data": "c:\\users\\public\\U.DLL"}) == {value}
    sid, terms = save_hits(con, "DefaultAppPool")
    assert [e["found"]["field"] for e in results(con, sid, terms=terms)["events"]] == ["Parent command line"]

    path, _ = export_timeline(con, synthetic_case, identity, T0 + 30 * SEC, T0 + 32 * SEC, "csv", "all")
    with path.open(encoding="utf-8", newline="") as f:
        rows = {r["event_uid"]: r for r in csv.DictReader(f)}
    assert rows[shell]["process.parent.executable"] == w3wp
    assert rows[shell]["process.parent.command_line"] == f'{w3wp} -ap "DefaultAppPool"'
    assert rows[value]["registry.data.strings"] == "C:\\Users\\Public\\u.dll"
    con.close()


def test_addr_matches_an_address_at_either_end(synthetic_case, tmp_path):
    """addr: finds what ip: or dst: would, so an inbound Sysmon 3 with the attacker as destination comes up with the
    attacker's logons. ip: and dst: work as they do alone, and an event data field named addr is searched as
    data.addr:."""
    from test_analysis_relations import ATTACKER, load_inbound

    from glessner.events import Event, load
    from glessner.queries import related

    uids = load_inbound(synthetic_case, tmp_path)
    audit = Event(T0 + 40, "Event Recorded", "evtx", "DC01/audit.log", "1", "USER_LOGIN", extra={"addr": ATTACKER})
    load(synthetic_case.db_path, [audit], host="DC01", tool="import", tool_version="t", run_id="r9", replaces_sources=[],
         staging_dir=synthetic_case.folder)
    con, _, _ = open_case(synthetic_case)
    audit_uid = con.execute("SELECT event_uid FROM events WHERE source_file = 'DC01/audit.log'").fetchone()[0]

    def hits(q):
        sid, _ = save_hits(con, q)
        return {e["uid"] for e in results(con, sid)["events"]}
    pivot = {e["uid"] for e in related(con, uids["inbound"], "addr", ip=ATTACKER)["events"]}
    assert hits(f"addr:{ATTACKER}") == hits(f"ip:{ATTACKER}") | hits(f"dst:{ATTACKER}") == pivot
    assert hits(f"ip:{ATTACKER}") == {uids["rdp"], uids["failed"]} and hits(f"dst:{ATTACKER}") == {uids["inbound"]}
    assert hits("ADDR:194.61.*") == pivot   # the field name in any case, and * as in ip:
    assert hits(f"code:3 -addr:{ATTACKER}") == {uids["loopback"], uids["ipv6_in"]}
    assert hits("addr:fe80::bad") == {uids["ipv6_in"], uids["ipv6_logon"]}
    assert hits(f"data.addr:{ATTACKER}") == {audit_uid} and audit_uid not in hits(f"addr:{ATTACKER}")
    (term,) = parse(f"addr:{ATTACKER}")
    assert term == Term(False, "addr", ATTACKER, False) and term.describe() == f'IP "{ATTACKER}" at either end'
    # A saved addr: search is a View value like any other.
    saved = where_sql(normalize({"view": {"values": [{"search": f"addr:{ATTACKER}"}]}}))
    shown = {u for (u,) in con.execute(f"SELECT e.event_uid FROM {BASE_FROM} WHERE {BASE_WHERE}{saved}").fetchall()}
    assert shown == pivot


def test_a_search_saved_before_addr_meant_either_end_runs_again(synthetic_case, tmp_path):
    """A case that ran addr:X when it meant the event data field addr has those matches saved under the ID the query
    had then. Opening the case drops them, and the same search runs again with the current meaning, an address at
    either end, rather than returning the old matches."""
    import hashlib

    from test_analysis_relations import ATTACKER, load_inbound

    from glessner.events import Event, load
    from glessner.queries import related
    from glessner.search import ensure_tables, normalize_query, search_id

    uids = load_inbound(synthetic_case, tmp_path)
    audit = Event(T0 + 40, "Event Recorded", "evtx", "DC01/audit.log", "1", "USER_LOGIN", extra={"addr": ATTACKER})
    load(synthetic_case.db_path, [audit], host="DC01", tool="import", tool_version="t", run_id="r9", replaces_sources=[],
         staging_dir=synthetic_case.folder)
    con, _, _ = open_case(synthetic_case)
    q = f"addr:{ATTACKER}"
    save_hits(con, "code:4624")   # saved under the current meaning, so it stays
    old = hashlib.sha256(normalize_query(q).encode()).hexdigest()[:16]   # the ID computed without search.MEANING
    con.execute("INSERT INTO search_hits SELECT ?, event_uid FROM events WHERE source_file = 'DC01/audit.log'", [old])
    con.execute("INSERT INTO search_runs VALUES (?, ?, 1, 2)", [old, q])
    ensure_tables(con)   # as the server does when it opens the case
    assert con.execute("SELECT sid FROM search_runs").fetchall() == [(search_id("code:4624"),)]
    assert con.execute("SELECT count(*) FROM search_hits WHERE sid = ?", [old]).fetchone()[0] == 0
    sid, terms = save_hits(con, q)
    pivot = {e["uid"] for e in related(con, uids["inbound"], "addr", ip=ATTACKER)["events"]}
    assert sid != old and {e["uid"] for e in results(con, sid, terms=terms)["events"]} == pivot


def test_marks_and_roles_are_left_to_the_view_filter():
    for q in ("mark:Malicious", "role:Servers", "x -mark:Authorized"):
        with pytest.raises(SearchError, match="View filter"):
            parse(q)


ARCHIVE = "DC01/Windows/System32/winevt/Logs/Archive-Security.evtx"


def load_archive(case, *records):
    """A run of the DC's archived Security log holding RDP logons from 194.61.24.102, as a job or the CLI loads one."""
    from conftest import SEC, logon

    from glessner.events import load

    load(case.db_path, [logon(T0 + r * SEC, r, ARCHIVE, ip="194.61.24.102") for r in records], host="DC01",
         tool="evtxecmd", tool_version="t", run_id=f"r{records[-1]}", replaces_sources=[ARCHIVE], staging_dir=case.folder)


def test_a_search_finds_events_loaded_after_it_was_saved(synthetic_case):
    """A load drops saved searches, so a search repeated after it, and a View holding one, find the
    events it added, and so does a search after the case reopens on events the CLI loaded while it was closed. A rerun
    that drops a marked event is counted as soon as it loads."""
    from conftest import serving

    window = f"start={T0 - 3600 * 10**6}&end={T0 + 3600 * 10**6}&groupby=host"
    for app, port, _ in serving(synthetic_case):
        session = login(port, app)
        get = lambda path: json.loads(request(port, "GET", path, session=session)[1])   # noqa: B023
        found = lambda: get("/api/search?q=194.61.24.102")["total"]   # noqa: B023
        assert found() == 1
        fid = json.loads(request(port, "POST", "/api/filter", session=session,
                                 body={"view": {"values": [{"search": "194.61.24.102"}]}})[1])["id"]
        assert len(get(f"/api/view?{window}&filter={fid}")["events"]) == 1
        load_archive(synthetic_case, 7)
        app.refresh_identity(events_changed=True)   # as a job's after() and an import do
        assert found() == 2 and len(get(f"/api/view?{window}&filter={fid}")["events"]) == 2
        marked = app.con.execute("SELECT event_uid FROM events WHERE source_file = ?", [ARCHIVE]).fetchone()[0]
        assert request(port, "POST", "/api/mark", session=session, body={"uids": [marked], "value": "malicious"})[0].status == 200
        load_archive(synthetic_case, 8)   # the rerun has no record 7
        app.refresh_identity(events_changed=True)
        assert get("/api/meta")["orphan_marks"] == 1 and found() == 2
    load_archive(synthetic_case, 8, 9)   # the CLI, with the server stopped
    for app, port, _ in serving(synthetic_case):
        session = login(port, app)
        assert json.loads(request(port, "GET", "/api/search?q=194.61.24.102", session=session)[1])["total"] == 3


def test_a_view_keeps_its_search_through_newer_searches(running):
    """search.KEEP newer searches push a View's search out of the saved ones, and the View saves it again rather than
    showing nothing under the filter ID the page keeps."""
    from glessner.search import KEEP

    app, port, _ = running
    session = login(port, app)
    window = f"start={T0 - 3600 * 10**6}&end={T0 + 3600 * 10**6}&groupby=host"
    fid = json.loads(request(port, "POST", "/api/filter", session=session,
                             body={"view": {"values": [{"search": "194.61.24.102"}]}})[1])["id"]
    shown = lambda: [e["code"] for e in json.loads(request(port, "GET", f"/api/view?{window}&filter={fid}",
                                                           session=session)[1])["events"]]
    assert shown() == ["4624"]
    for n in range(KEEP + 1):
        assert request(port, "GET", f"/api/search?q=word{n}", session=session)[0].status == 200
    assert app.con.execute("SELECT count(*) FROM search_runs").fetchone()[0] == KEEP
    assert shown() == ["4624"]


def test_a_view_s_searches_are_all_kept_when_one_is_saved_again(running):
    """Saving a View's dropped search again must not push out the least recently used saved search when that is the
    View's other one, or a pan or an export would miss that search's events."""
    from glessner.search import KEEP

    app, port, _ = running
    session = login(port, app)
    span = {"start": T0 - 3600 * 10**6, "end": T0 + 3600 * 10**6}
    fid = json.loads(request(port, "POST", "/api/filter", session=session, body={
        "view": {"values": [{"search": "194.61.24.102"}, {"search": "mortysmith"}]}})[1])["id"]
    shown = lambda: len(json.loads(request(port, "GET", f"/api/view?start={span['start']}&end={span['end']}"
                                           f"&groupby=host&filter={fid}", session=session)[1])["events"])

    def search_others(word):   # enough to drop the View's older search, but not its newer one
        for n in range(KEEP - 1):
            assert request(port, "GET", f"/api/search?q={word}{n}", session=session)[0].status == 200

    both = shown()
    assert both == 2
    search_others("word")
    assert shown() == both
    search_others("other")
    res, body = request(port, "POST", "/api/export", session=session, body={**span, "filter": fid})
    assert res.status == 200 and json.loads(body)["rows"] == both


def test_a_search_used_again_is_the_last_dropped(synthetic_case):
    """The saved searches are the KEEP most recently used, so a repeated search isn't the next one dropped."""
    from glessner.search import KEEP, is_saved

    con, _, _ = open_case(synthetic_case)
    save_hits(con, "194.61.24.102")
    for n in range(KEEP - 1):
        save_hits(con, f"word{n}")
    save_hits(con, "194.61.24.102")
    save_hits(con, "one more")
    assert is_saved(con, "194.61.24.102") and not is_saved(con, "word0")
    con.close()


def test_a_search_reads_outside_the_lock_and_again_after_a_load(synthetic_case, monkeypatch):
    """A search writes its matches on a reader, without the server's lock, so a mark sent meanwhile
    doesn't wait for it. Matches staged while a load's refresh ran are read again under the lock, so the saved search
    holds the events the load added, and no staged matches are left behind."""
    import threading

    from glessner import server

    app = server.App(synthetic_case)
    scanning, go, result = threading.Event(), threading.Event(), {}
    stage = server.stage_matches

    def held(con, condition):   # the matches as staged, handed back once the test lets it go
        staged = stage(con, condition)
        scanning.set()
        assert go.wait(10)
        return staged

    monkeypatch.setattr(server, "stage_matches", held)
    worker = threading.Thread(target=lambda: result.update(server.api_search(app, {"q": ["194.61.24.102"]})))
    worker.start()
    try:
        assert scanning.wait(10)
        rdp = app.con.execute("SELECT event_uid FROM events WHERE ts_us = ? AND event_code = '4624'", [T0]).fetchone()[0]
        mark = threading.Thread(target=lambda: server.api_mark(app, {"uids": [rdp], "value": "malicious"}))
        mark.start()
        mark.join(5)
        assert not mark.is_alive()   # it didn't wait for the search
        load_archive(synthetic_case, 7)
        app.refresh_identity(events_changed=True)
        go.set()
        worker.join(10)
        assert result["total"] == 2
        assert app.con.execute("SELECT count(*) FROM search_hits WHERE sid LIKE 'staged %'").fetchone()[0] == 0
    finally:
        go.set()
        worker.join(10)
        app.con.close()


def test_a_search_two_requests_save_at_once_is_saved_once(synthetic_case, monkeypatch):
    """Each request stages its matches under an ID of its own, so two requests that save one search at once, as the
    page's lanes and Sources requests can after a load, leave one copy of its matches and no staged ones."""
    import threading

    from glessner import server
    from glessner.search import search_id

    app = server.App(synthetic_case)
    stage, both, totals = server.stage_matches, threading.Barrier(2, timeout=10), []

    def together(con, condition):   # both requests have staged their matches before either saves them
        staged = stage(con, condition)
        both.wait()
        return staged

    monkeypatch.setattr(server, "stage_matches", together)
    workers = [threading.Thread(target=lambda: totals.append(server.api_search(app, {"q": ["4624"]})["total"]))
               for _ in range(2)]
    try:
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(10)
        rows, distinct, staged = app.con.execute(
            "SELECT count(*) FILTER (WHERE sid = ?), count(DISTINCT event_uid) FILTER (WHERE sid = ?), "
            "count(*) FILTER (WHERE sid LIKE 'staged %') FROM search_hits", [search_id("4624")] * 2).fetchone()
        assert totals[0] == totals[1] == rows == distinct > 0 and staged == 0
    finally:
        app.con.close()


ONE_SPACE, TWO_SPACES, A_TAB = r"C:\Program Files\app.exe", r"C:\Program  Files\app.exe", "C:\\Program\tFiles\\app.exe"


def load_paths(case, *paths):
    """MFT events whose paths differ only in the spaces inside them, by ID in path order."""
    from glessner.events import Event, connect, load
    from glessner.parsers.common import file_key

    # An MFT event carries the key of its path, which path: compares a full path by
    load(case.db_path, [Event(T0 + n, "$SI MA.B", "mft", "DC01/$MFT", f"{n}-1:app.exe", "app.exe", file_path=p,
                              file_key=file_key(p)) for n, p in enumerate(paths)], host="DC01", tool="mftecmd",
         tool_version="t", run_id="r9", replaces_sources=["DC01/$MFT"], staging_dir=case.folder)
    con = connect(case.db_path, read_only=True)
    uids = dict(con.execute("SELECT file_path, event_uid FROM events WHERE tool = 'mftecmd'").fetchall())
    con.close()
    return [uids[p] for p in paths]


def test_quoted_values_that_differ_only_in_their_spaces_are_different_searches(synthetic_case):
    """normalize_query keeps the spaces inside quotes, as the search compares a quoted value as written. Two paths that
    differ by a doubled space or a tab get search IDs of their own, so each search finds its own path. The query the
    search returns, which the page pins in the View, keeps them too, so after a load the View runs the same search and
    shows the same path's event."""
    from glessner.search import clear_saved, normalize_query
    from glessner.server import App, api_filter, api_search, api_view

    one, two, tab = load_paths(synthetic_case, ONE_SPACE, TWO_SPACES, A_TAB)
    con, _, _ = open_case(synthetic_case)
    try:
        for first, second in ((ONE_SPACE, TWO_SPACES), (TWO_SPACES, ONE_SPACE), (ONE_SPACE, A_TAB), (A_TAB, ONE_SPACE)):
            clear_saved(con)
            found = {}
            for path in (first, second):
                sid, terms = save_hits(con, f'path:"{path}"')
                found[path] = (sid, {e["uid"] for e in results(con, sid, terms=terms)["events"]})
            assert found[first][0] != found[second][0], (first, second)
            assert {p: uids for p, (_, uids) in found.items()} == {
                p: {{ONE_SPACE: one, TWO_SPACES: two, A_TAB: tab}[p]} for p in (first, second)}
    finally:
        con.close()
    # Spaces between terms don't count, and an unclosed quote is a word
    assert normalize_query('  code:4624 \t "a  b"   x ') == 'code:4624 "a  b" x'
    assert normalize_query('"a  b') == '"a b'
    # A search saved under its collapsed text and the ID that text had with MEANING 2, which the one-space search
    # would have too, is dropped by search.MEANING's rise when the case opens, so it can't answer the one-space search
    import hashlib

    from glessner.search import ensure_tables, search_id

    collapsed = f'path:"{ONE_SPACE}"'
    old = hashlib.sha256(f"2 {collapsed}".encode()).hexdigest()[:16]
    con, _, _ = open_case(synthetic_case)
    try:
        clear_saved(con)
        con.execute("INSERT INTO search_hits VALUES (?, ?)", [old, two])
        con.execute("INSERT INTO search_runs VALUES (?, ?, 1, 1)", [old, collapsed])
        ensure_tables(con)   # as the server does when it opens the case
        assert con.execute("SELECT count(*) FROM search_runs").fetchone()[0] == 0
        sid, terms = save_hits(con, collapsed)
        assert sid == search_id(collapsed) != old and [e["uid"] for e in results(con, sid)["events"]] == [one]
    finally:
        con.close()
    app = App(synthetic_case)
    try:
        res = api_search(app, {"q": [f'path:"{TWO_SPACES}"']})
        assert res["query"] == f'path:"{TWO_SPACES}"' and [e["uid"] for e in res["events"]] == [two]
        fid = api_filter(app, {"view": {"values": [{"search": res["query"]}]}})["id"]   # as the page pins it
        window = {"start": [str(T0 - 3600 * 10**6)], "end": [str(T0 + 3600 * 10**6)], "groupby": ["host"],
                  "filter": [fid]}
        assert [e["uid"] for e in api_view(app, window)["events"]] == [two]
        app.refresh_identity(events_changed=True)   # every load and case open drops the saved searches
        assert [e["uid"] for e in api_view(app, window)["events"]] == [two]
    finally:
        app.con.close()


def test_found_in_and_its_span_match_the_old_pattern_and_take_linear_time():
    """found_in searches for each piece of a wildcard value once, after the one before. Making each * a lazy .*? in one
    regular expression backtracks over every way to split a repeated text when a later piece is missing: a*a*a*a*a*b
    took 3.7 s on a message of 80 a's, and *invoke*download* past 5 s on an 8 KB script block, holding the GIL, so every
    request of the server waited. The spans are those the lazy pattern gives."""
    import random
    import re
    import time

    from glessner.search import bounded_pattern, found_in, wildcard_span

    def old(value, text):
        m = re.compile(".*?".join(re.escape(p) for p in value.split("*")), re.IGNORECASE | re.DOTALL).search(text)
        return (m.start(), m.end()) if m else None

    rng = random.Random(109)
    for _ in range(20_000):
        text = "".join(rng.choice("abAB*\n ") for _ in range(rng.randrange(0, 14)))
        value = "".join(rng.choice("abB**") for _ in range(rng.randrange(1, 7)))
        assert wildcard_span(value, text) == old(value, text), (value, text)
    for value in ("*a", "a*", "**", "*", "a**b", "*İ*", "ß*k"):
        for text in ("", "a", "xay", "aab", "İstanbul", "STRASSE kß"):
            assert wildcard_span(value, text) == old(value, text), (value, text)
    fields = {"message": "a" * 80, "extra": json.dumps({"hit": "aaaaab"})}
    t0 = time.thread_time()   # CPU time, as test_line_logs.seconds: waits for a CPU among parallel workers don't count
    found = found_in(fields, parse("a*a*a*a*a*b"))
    assert time.thread_time() - t0 < 0.5 and found == {"field": "data.hit", "text": "aaaaab", "before": False,
                                                        "after": False}
    # A quoted word is bounded: its spans are those of the pattern the server searches with, made lazy as above, on
    # text of ASCII letters, underscores, and the characters around them; and it takes as little time.
    for _ in range(20_000):
        text = "".join(rng.choice("abAB_.- \n") for _ in range(rng.randrange(0, 14)))
        value = "".join(rng.choice("abB.**") for _ in range(rng.randrange(1, 7)))
        m = re.compile(bounded_pattern(value).replace(".*", ".*?"), re.IGNORECASE | re.DOTALL).search(text)
        assert wildcard_span(value, text, True) == ((m.start(), m.end()) if m else None), (value, text)
    t0 = time.thread_time()
    found = found_in(fields, parse('"a*a*a*a*a*b"'))
    assert time.thread_time() - t0 < 0.5 and found["field"] == "data.hit"


SLOW_SEARCH = """
import json, sys, time
from glessner.search import found_in, parse
fields = {"message": "a" * 160, "process_command_line": "invoke-expression " * 2000,
          "extra": json.dumps({"hit": "aaaaab", "Payload": "Invoke-Expression (New-Object Net.WebClient).DownloadString"})}
t0 = time.thread_time()
answers = [found_in(fields, parse(q)) for q in ("a*a*a*a*a*b", "*invoke*download*", "invoke*command*output*download")]
print(json.dumps({"seconds": time.thread_time() - t0, "fields": [a and a["field"] for a in answers]}))
"""


def test_a_wildcard_search_s_excerpt_comes_back_within_a_bound():
    """Wildcard searches, each with a long field before the one that matches, run in a child process killed at 20 s, so
    a matcher that backtracks fails this test rather than holding up the suite. With a backtracking matcher the first
    two each take minutes."""
    import subprocess
    import sys

    done = subprocess.run([sys.executable, "-c", SLOW_SEARCH], capture_output=True, text=True, timeout=20, check=True)
    out = json.loads(done.stdout)
    assert out["seconds"] < 1 and out["fields"] == ["data.hit", "data.Payload", None], out


def test_path_compares_by_file_key(synthetic_case):
    """path: compares a full path by its file key, so it finds the file's MFT and Prefetch forms, which Same file reaches
    by the file key. A value with * or a bare name compares the path as written."""
    from conftest import DC_LOG

    from glessner.events import Event, load
    from glessner.parsers.common import file_key
    full = r"C:\Windows\System32\coreupdater.exe"

    def event(record, artifact, source, path="", process="", message=""):
        return Event(ts_us=T0 + record * 1_000_000, ts_desc="x", artifact=artifact, source_file=source, source_record=str(record),
                     message=message or f"record {record}", file_path=path, process_executable=process,
                     file_key=file_key(path or process))
    events = [event(1, "mft", "DC01/$MFT", r"\Windows\System32\coreupdater.exe"),
              event(2, "prefetch", "DC01/Windows/Prefetch/COREUPDATER.EXE-1.pf",
                    r"\VOLUME{01d6}\WINDOWS\SYSTEM32\COREUPDATER.EXE"),
              event(3, "evtx", DC_LOG, full),
              event(4, "evtx", DC_LOG, process=full),   # a 4688: the process is the event's file
              event(5, "evtx", DC_LOG, r"C:\Windows\System32\cmd.exe", message="cmd in system32")]
    load(synthetic_case.db_path, events, host="DC01", tool="evtxecmd", tool_version="t", run_id="r30", replaces_sources=[],
         staging_dir=synthetic_case.folder)
    con, _, _ = open_case(synthetic_case)

    def hits(q):
        sid, _ = save_hits(con, q)
        return {con.execute("SELECT source_record FROM events WHERE event_uid = ?", [e["uid"]]).fetchone()[0]
                for e in results(con, sid)["events"]}
    assert hits(f"path:{full}") == hits(r"path:C:\windows\SYSTEM32\CoreUpdater.exe") == {"1", "2", "3", "4"}
    assert hits(r"path:\Windows\System32\coreupdater.exe") == {"1", "2", "3", "4"}      # the MFT's own form
    assert hits(f"-path:{full} system32") == {"5"}                                      # excluded by the same key
    assert hits("path:*coreupdater*") == {"1", "2", "3"}      # as written: the process-only event names no path
    assert hits("path:coreupdater.exe") == set()              # a bare name is a name, compared as written
    assert hits(r"path:*\VOLUME{01d6}\*") == {"2"}
    assert hits("path:/var/tmp/x") == set()                   # not a Windows path: compared as written


def test_a_search_saved_before_the_path_change_runs_again(synthetic_case):
    """path: compares by file key, a different meaning from MEANING 3's, so a search saved under 3 is dropped when the
    case opens, to run again when it is next asked for."""
    import hashlib

    from glessner.search import MEANING, ensure_tables, normalize_query, search_id
    assert MEANING == 6
    con, _, _ = open_case(synthetic_case)
    ensure_tables(con)
    q = r"path:C:\Windows\System32\coreupdater.exe"
    old = hashlib.sha256(f"3 {normalize_query(q)}".encode()).hexdigest()[:16]   # the ID under MEANING 3
    con.execute("INSERT INTO search_hits SELECT ?, event_uid FROM events WHERE event_code = '4624'", [old])
    con.execute("INSERT INTO search_runs VALUES (?, ?, 1, 2)", [old, q])
    ensure_tables(con)   # as the server does when it opens the case
    assert con.execute("SELECT count(*) FROM search_runs WHERE sid = ?", [old]).fetchone()[0] == 0
    assert con.execute("SELECT count(*) FROM search_hits WHERE sid = ?", [old]).fetchone()[0] == 0
    assert search_id(q) != old


def test_a_search_saved_before_field_terms_ignored_case_runs_again(synthetic_case):
    """A search saved under MEANING 4, where host:dc01 found nothing, would keep returning that nothing. A later MEANING
    gives the same query another ID, and opening the case drops the old one."""
    import hashlib

    from glessner.search import MEANING, ensure_tables, normalize_query, search_id
    assert MEANING == 6
    con, _, _ = open_case(synthetic_case)
    ensure_tables(con)
    q = "host:dc01"
    old = hashlib.sha256(f"4 {normalize_query(q)}".encode()).hexdigest()[:16]   # the ID under MEANING 4
    con.execute("INSERT INTO search_runs VALUES (?, ?, 0, 2)", [old, q])
    ensure_tables(con)   # as the server does when it opens the case
    assert con.execute("SELECT count(*) FROM search_runs WHERE sid = ?", [old]).fetchone()[0] == 0
    sid, _ = save_hits(con, q)
    assert sid == search_id(q) != old and results(con, sid)["events"]


BOUNDED_SOURCE = "DC01/Windows/System32/winevt/Logs/Application.evtx"
BOUNDED_MESSAGES = {
    "plain": "nmap -sS 10.0.0.0/24", "winmaps": "loaded WinMaps.dll", "under": "x_nmap started", "digit": "nmap2 started",
    "path": "C:\\Tools\\nmap.exe -sV", "upper": "NMAP", "dllx": "dropped a.dllx", "blogged": "blogged on to the host",
    "logged": "user logged on to the host", "mimi": "mimikatz ran", "xmimi": "xmimikatz ran",
    "lines": "invoke-x\ndownload it", "apart": "invoke-x download-it",
}


def bounded_case(case):
    """The synthetic case with one event for each message of BOUNDED_MESSAGES, all of code 9000, and their IDs by label."""
    load(case.db_path, [Event(T0 + i * SEC, "Event Recorded", "evtx", BOUNDED_SOURCE, label, message, event_code="9000")
                        for i, (label, message) in enumerate(BOUNDED_MESSAGES.items())],
         host="DC01", tool="evtxecmd", tool_version="t", run_id="r9", replaces_sources=[BOUNDED_SOURCE],
         staging_dir=case.folder)
    con, _, identity = open_case(case)
    uids = dict(con.execute("SELECT source_record, event_uid FROM events WHERE source_file = ?", [BOUNDED_SOURCE]).fetchall())
    return con, identity, uids


def test_quotes_mean_a_bounded_word_or_phrase(synthetic_case):
    """A quoted "nmap" is the word alone, where bare nmap is the text anywhere.
    Letters, digits, and underscore on either side end a match; a side that ends in another character has no bound, so
    ".dll" works; * stands for any text; a phrase is whole words; and a minus excludes only the bounded matches."""
    con, _, uids = bounded_case(synthetic_case)

    def hits(q):
        sid, _ = save_hits(con, q)
        return {label for label, uid in uids.items() if uid in {e["uid"] for e in results(con, sid)["events"]}}
    assert hits('"nmap"') == {"plain", "path", "upper"}                    # not WinMaps, x_nmap, or nmap2
    assert hits("nmap") == {"plain", "winmaps", "under", "digit", "path", "upper"}
    assert hits('"nmap" -"nmap.exe"') == {"plain", "upper"}                # the minus leaves out a bounded match
    assert hits('code:9000 -"nmap"') == set(uids) - {"plain", "path", "upper"}   # and only the bounded ones
    assert hits('"NmAp"') == hits('"nmap"')
    assert hits('".dll"') == {"winmaps"}                                   # the dot has no bound; the l ends the word
    assert hits('"mimi*"') == {"mimi"}                                     # starts a word, ends anywhere
    assert hits('"*mimi*"') == {"mimi", "xmimi"}
    assert hits('"logged on"') == {"logged"}                               # "blogged on" is not the phrase
    assert hits("logged on") == {"blogged", "logged"}                      # bare words are found anywhere
    assert hits('"a.dllx"') == {"dllx"} and hits('"a.dll"') == set()       # a dot is a dot, not any character
    terms = parse('"nmap" "a b" nmap path:"a b"')
    assert [t.bounded for t in terms] == [True, True, False, False]
    assert [t.describe() for t in terms] == ['the whole word "nmap"', 'the words "a b" as whole words', '"nmap" anywhere',
                                             'path is "a b"']
    con.close()


def test_a_quoted_wildcard_spans_a_line_break(synthetic_case):
    """A * in a quoted phrase crosses a line break, as it does in a bare word (the regular expression's s option)."""
    con, _, uids = bounded_case(synthetic_case)
    sid, _ = save_hits(con, '"invoke*download"')
    assert {e["uid"] for e in results(con, sid)["events"]} == {uids["lines"], uids["apart"]}
    con.close()


def test_whole_word_rewrites_only_free_text():
    """The Whole word tick: `on` quotes every bare free-text word, `off` unquotes every quoted one without spaces, and fields,
    phrases with spaces, and words holding a quote stay as typed. None when no free-text term is left to change."""
    from glessner.search import whole_word

    q = 'nmap "logged on" code:4624 path:"C:\\Program Files"'
    assert whole_word(q) == {"state": "some", "on": '"nmap" "logged on" code:4624 path:"C:\\Program Files"',
                             "off": 'nmap "logged on" code:4624 path:"C:\\Program Files"'}
    assert whole_word('code:4624 path:"C:\\Program Files"') is None and whole_word("") is None
    assert whole_word("nmap svc") == {"state": "none", "on": '"nmap" "svc"', "off": "nmap svc"}
    assert whole_word('"nmap" -"svc"') == {"state": "all", "on": '"nmap" -"svc"', "off": "nmap -svc"}
    assert whole_word("-nmap code:1") == {"state": "none", "on": '-"nmap" code:1', "off": "-nmap code:1"}
    # A quoted value that would read as a field or an exclusion bare stays quoted, and a word with a quote in it is left
    assert whole_word('"ab:cd" "-x"')["off"] == '"ab:cd" "-x"'
    assert whole_word('say"hi nmap') == {"state": "none", "on": 'say"hi "nmap"', "off": 'say"hi nmap'}
    assert whole_word('say"hi') is None


def test_the_search_api_offers_the_whole_word_rewrite(running):
    app, port, _ = running
    session = login(port, app)
    res, body = request(port, "GET", "/api/search?q=" + urllib.parse.quote('logon "4624" code:4624'), session=session)
    out = json.loads(body)
    assert res.status == 200 and out["whole_word"] == {"state": "some", "on": '"logon" "4624" code:4624',
                                                       "off": 'logon 4624 code:4624'}
    assert out["terms"] == ['"logon" anywhere', 'the whole word "4624"', 'code is "4624"']
    res, body = request(port, "GET", "/api/search?q=" + urllib.parse.quote("code:4624"), session=session)
    assert json.loads(body)["whole_word"] is None


def test_found_in_skips_an_occurrence_inside_a_word():
    """A quoted word's excerpt and highlight follow its bound: in "winmaps ... nmap" the first occurrence is inside a word,
    so the excerpt is the second; a bare word still reports the first."""
    from glessner.search import found_in

    fields = {"process_command_line": "winmaps " + "." * 100 + " nmap -sS"}
    quoted = found_in(fields, parse('"nmap"'))
    assert quoted["field"] == "Command line" and quoted["before"] and "nmap -sS" in quoted["text"]
    bare = found_in(fields, parse("nmap"))
    assert not bare["before"] and bare["text"].startswith("winmaps")
    assert found_in({"process_command_line": "winmaps and x_nmap and nmap2"}, parse('"nmap"')) is None


def test_a_search_saved_before_quotes_meant_whole_words_runs_again(synthetic_case):
    """A quoted "nmap" is a bounded word, a different meaning from MEANING 5's, so a search saved under 5 is dropped when
    the case opens; the search then saves the bounded set, not the set saved under 5."""
    import hashlib

    from glessner.search import ensure_tables, normalize_query, search_id
    con, _, uids = bounded_case(synthetic_case)
    ensure_tables(con)
    q = '"nmap"'
    old = hashlib.sha256(f"5 {normalize_query(q)}".encode()).hexdigest()[:16]   # the ID under MEANING 5
    con.execute("INSERT INTO search_hits VALUES (?, ?)", [old, uids["winmaps"]])   # what "nmap" found under 5: inside a word
    con.execute("INSERT INTO search_runs VALUES (?, ?, 1, 2)", [old, q])
    ensure_tables(con)   # as the server does when it opens the case
    assert con.execute("SELECT count(*) FROM search_runs WHERE sid = ?", [old]).fetchone()[0] == 0
    assert con.execute("SELECT count(*) FROM search_hits WHERE sid = ?", [old]).fetchone()[0] == 0
    sid, _ = save_hits(con, q)
    assert sid == search_id(q) != old
    assert {e["uid"] for e in results(con, sid)["events"]} == {uids[label] for label in ("plain", "path", "upper")}
    con.close()


def test_rule_field_matches_the_events_a_rule_hit(synthetic_case):
    """rule: is a Hayabusa rule's title, in any letter case, with * for any text, not the event data field rule.
    data.rule: reaches an imported fast alert's own field. No highlight is made for it."""
    from glessner.queries import related

    load(synthetic_case.db_path, [Event(T0 + 5 * SEC, "Event Recorded", "ids_alert", "alerts/fast.log", "1", "ET SCAN probe",
                                        event_code="2002", extra={"rule": "1:2002:3"})],
         host="DC01", tool="evtxecmd", tool_version="t", run_id="r9", replaces_sources=["alerts/fast.log"],
         staging_dir=synthetic_case.folder)
    con, _, identity = open_case(synthetic_case)

    def hits(q):
        sid, _ = save_hits(con, q)
        return {e["uid"] for e in results(con, sid)["events"]}
    (rdp,) = hits("ip:194.61.24.102")
    same = {e["uid"] for e in related(con, rdp, "rule", identity=identity)["events"]}
    assert same == {rdp}
    assert hits('rule:"RDP from internet"') == hits('rule:"rdp FROM internet"') == hits('rule_title:"rdp from internet"') == same
    assert hits("rule:*rdp*") == hits("rule:rdp*") == hits('rule:"*FROM internet"') == same
    assert hits("rule:rdp") == set()                                       # the whole title, as any field
    assert rdp not in hits('-rule:"rdp from internet" code:4624') and hits('-rule:"rdp from internet" code:4624')
    assert hits("data.rule:1:2002:3") and hits("rule:1:2002:3") == set() and hits("rule:nothing") == set()
    terms = parse('rule:"rdp from internet" code:4624 "logon"')
    assert [t.field for t in terms] == ["rule", "code", ""]
    assert terms[0].describe() == 'events hit by the Hayabusa rule "rdp from internet"'   # after "Looking for" on the page
    assert parse('-rule:"x"  code:1')[0].describe() == 'events not hit by the Hayabusa rule "x"'
    sid, terms = save_hits(con, 'rule:"rdp from internet" logon')
    assert [h["value"] for h in results(con, sid, terms=terms)["highlight"]] == ["logon"]
    con.close()


SWEEP = "DC01/Windows/System32/winevt/Logs/Sweep.evtx"


def zorps(case):
    """Events holding "zorp" inside twelve other words (the first inside 12 events, the next 11, down to 1), and one holding
    the word alone: 78 events inside other words, 79 for the word anywhere."""
    load(case.db_path, [Event(T0 + (k * 20 + n) * SEC, "Event Recorded", "evtx", SWEEP, f"{k}-{n}", f"{chr(97 + k)}zorp started",
                              event_code="9100") for k in range(12) for n in range(12 - k)]
         + [Event(T0 + 999 * SEC, "Event Recorded", "evtx", SWEEP, "alone", "zorp ran", event_code="9100")],
         host="DC01", tool="evtxecmd", tool_version="t", run_id="r9", replaces_sources=[SWEEP], staging_dir=case.folder)
    return open_case(case)[0]


def test_search_adds_groups_the_words_a_term_sits_inside(synthetic_case):
    """The forgiving line counts what a quoted word's search finds without its quotes, how many of those hold the word
    only inside other words, and the ten largest of those words with the search for each, in one scan. Twelve words, so
    two are left out. Its total is what the forgiving search finds, and the other terms stay."""
    from glessner.search import search_adds

    con = zorps(synthetic_case)
    out = search_adds(con, '"zorp" code:9100')
    assert (out["total"], out["inside"], out["words"], out["more"]) == (79, 78, 12, 2)
    assert [(g["word"], g["count"]) for g in out["groups"]] == [(f"{chr(97 + k)}zorp", 12 - k) for k in range(10)]
    assert out["groups"][0]["query"] == '"azorp" code:9100' and out["forgiving_query"] == "zorp code:9100"
    sid, _ = save_hits(con, out["forgiving_query"])
    assert results(con, sid)["total"] == out["total"]
    sid, _ = save_hits(con, out["groups"][3]["query"])
    assert results(con, sid)["total"] == out["groups"][3]["count"]   # the quoted word finds what its group counted
    assert search_adds(con, '"alone"')["groups"] == [] and search_adds(con, '"zorp" -code:1')["total"] == 79
    none = search_adds(con, '"ran"')   # a word that sits inside no other
    assert (none["total"], none["inside"], none["words"], none["more"], none["groups"]) == (1, 0, 0, 0, [])
    con.close()


def test_search_adds_refuses_a_query_without_a_quoted_word(synthetic_case):
    """The line is offered for one quoted word with no space or *, which the same word typed bare reads as: a * would cross
    spaces in the grouping, and a quoted "ab:cd" bare would be a field."""
    from glessner.search import forgiving_term, search_adds

    con = zorps(synthetic_case)
    for q in ("zorp", '"a b"', '"zor*"', '-"zorp" code:9100', "code:9100", '"ab:cd"', '"-x"', 'path:"zorp"'):
        with pytest.raises(SearchError, match="word in quotes"):
            search_adds(con, q)
    assert forgiving_term(parse('"a b" -"x" "zorp" "ran"')) == 2 and forgiving_term(parse("zorp")) is None
    con.close()


def test_the_search_api_offers_the_forgiving_line_for_a_search_it_can_serve(running):
    """/api/search says whether the page may ask, so the page has no tokenizer of its own; /api/search_adds answers with the
    server's time, and a plain message with a 400 when the search has no quoted word."""
    app, port, _ = running
    session = login(port, app)
    res, body = request(port, "GET", "/api/search_adds?q=" + urllib.parse.quote("logon"), session=session)
    assert res.status == 400 and "word in quotes" in json.loads(body)["error"]
    res, body = request(port, "GET", "/api/search_adds?q=" + urllib.parse.quote('"logon" code:4624'), session=session)
    out = json.loads(body)
    assert res.status == 200 and out["total"] > 0 and out["forgiving_query"] == "logon code:4624" and out["server_ms"] >= 0
    assert (out["inside"], out["groups"]) == (0, [])   # "logon" is a word on its own in every message
    for q, offered in (('"logon"', True), ("logon", False), ('"a b" code:4624', False), ('"logon" -"x"', True)):
        res, body = request(port, "GET", "/api/search?q=" + urllib.parse.quote(q), session=session)
        assert json.loads(body)["forgiving"] is offered, q


def hayabusa_hit_on(case, record, title, level, source):
    load(case.db_path, [Event(ts_us=T0 + 500 * SEC, ts_desc="Event Recorded", artifact="hayabusa", source_file=source,
                              source_record=f"{record}:rule", record_id=record, message=f"{title} [{level}]",
                              log_channel="Security", rule_title=title, rule_level=level)],
         host="DC01", tool="hayabusa", tool_version="t", run_id="r10", replaces_sources=[source], staging_dir=case.folder)


PROBE = "DC01/Windows/System32/winevt/Logs/Probe.evtx"


def probe_case(case):
    """The synthetic case plus an event whose text holds "internet" and a medium Hayabusa rule hit on it, whose title does
    too: the RDP rule's title "RDP from internet" is held by no event's text."""
    load(case.db_path, [Event(T0 + 500 * SEC, "Event Recorded", "evtx", PROBE, "7001", "internet probe seen",
                              record_id=7001, log_channel="Security", event_code="9200")],
         host="DC01", tool="evtxecmd", tool_version="t", run_id="r9", replaces_sources=[PROBE], staging_dir=case.folder)
    hayabusa_hit_on(case, 7001, "Internet Probe Seen", "medium", PROBE)


def test_free_text_also_finds_rule_titles(synthetic_case):
    """A rule's title is not event text, so a word that only a title holds finds the rule by name: up to three titles,
    the most hits first, each with its level, its event count, the search for the rule in the word's place, the events
    of it that the results leave out, and how many it shares with the results."""
    from glessner.search import by_name

    probe_case(synthetic_case)
    con, _, _ = open_case(synthetic_case)
    (rdp,) = {u for (u,) in con.execute("SELECT event_uid FROM events WHERE source_record = '101'").fetchall()}
    sid, terms = save_hits(con, "internet")
    assert results(con, sid)["total"] == 1   # the one event whose text holds the word
    names = by_name(con, "internet", terms, sid)
    assert [(n["title"], n["level"], n["count"], n["query"], n["in_results"]) for n in names] == [
        ("Internet Probe Seen", "medium", 1, 'rule:"Internet Probe Seen"', 1),
        ("RDP from internet", "high", 1, 'rule:"RDP from internet"', 0)]
    assert names[0]["events"] == [] and [e["uid"] for e in names[1]["events"]] == [rdp]
    # The rule's own search finds exactly what the box counted, and the rest of the query stays beside it
    assert names[1]["count"] == results(con, save_hits(con, names[1]["query"])[0])["total"] == 1
    sid, terms = save_hits(con, "internet code:9200")
    assert [(n["title"], n["query"]) for n in by_name(con, "internet code:9200", terms, sid)] == [
        ("Internet Probe Seen", 'rule:"Internet Probe Seen" code:9200')]   # the RDP rule has no 9200 event
    sid, terms = save_hits(con, '"INTERNET" -rule:"nothing"')
    assert [n["title"] for n in by_name(con, '"INTERNET" -rule:"nothing"', terms, sid)] == [
        "Internet Probe Seen", "RDP from internet"]
    sid, terms = save_hits(con, "probe")   # a quoted word finds a title the same way; a word in no title finds none
    assert [n["title"] for n in by_name(con, '"probe"', parse('"probe"'), sid)] == ["Internet Probe Seen"]
    assert by_name(con, "seen", parse("seen"), sid)[0]["title"] == "Internet Probe Seen"
    assert by_name(con, '"intern"', parse('"intern"'), sid) == [] and by_name(con, "code:4624", parse("code:4624"), sid) == []
    con.close()


ZETA = "DC01/Windows/System32/winevt/Logs/Zeta.evtx"


def zeta_case(case):
    """The synthetic case plus five Zeta rules over events of code 9301 and 9302, and the one event whose text holds "zeta",
    code 9300, hit by Zeta D. Case-wide hits: E 4, C 3, A 2, B 2, D 1. Under code:9301 E drops to 1 and C leads with 3."""
    rules = [("Zeta A", "9301", 2), ("Zeta B", "9301", 2), ("Zeta C", "9301", 3), ("Zeta E", "9302", 3), ("Zeta E", "9301", 1),
             ("Zeta D", "9300", 1)]
    events, hits, record = [], [], 8000
    for title, code, n in rules:
        for _ in range(n):
            record += 1
            events.append(Event(T0 + (600 + record - 8000) * SEC, "Event Recorded", "evtx", ZETA, str(record),
                                "zeta marker" if code == "9300" else "plain event", record_id=record, log_channel="Security",
                                event_code=code))
            hits.append(Event(ts_us=T0 + 500 * SEC, ts_desc="Event Recorded", artifact="hayabusa", source_file=ZETA,
                              source_record=f"{record}:rule", record_id=record, message=f"{title} [medium]",
                              log_channel="Security", rule_title=title, rule_level="medium"))
    load(case.db_path, events, host="DC01", tool="evtxecmd", tool_version="t", run_id="r9", replaces_sources=[ZETA],
         staging_dir=case.folder)
    load(case.db_path, hits, host="DC01", tool="hayabusa", tool_version="t", run_id="r10", replaces_sources=[ZETA],
         staging_dir=case.folder)


class CountingReader:
    """A reader that counts the statements that scan the text of every event, which a rule's own events should not need
    more than once for all the rules."""

    def __init__(self, con):
        self.con, self.scans = con, 0

    def execute(self, sql, *args):
        self.scans += "concat_ws" in sql
        return self.con.execute(sql, *args)


def test_by_name_tries_the_rest_of_the_query_on_the_rules_own_events(synthetic_case):
    """The rest of the query runs once, over the events the candidate rules hit, and the three rules are picked and
    ranked by their events under the whole query, not by their hits case-wide. Running it over every event for each
    rule's count and again for its events took 15 s for "service svc" at 5.2 million events."""
    from glessner.search import by_name

    zeta_case(synthetic_case)
    con, _, _ = open_case(synthetic_case)

    def names(q):
        sid, terms = save_hits(con, q)
        return [(n["title"], n["count"]) for n in by_name(con, q, terms, sid)]
    assert names("zeta") == [("Zeta E", 4), ("Zeta C", 3), ("Zeta A", 2)]
    # Narrowed, the case-wide order doesn't hold: E has one event of code 9301, and B, which the case-wide cut drops, has two
    assert names("zeta code:9301") == [("Zeta C", 3), ("Zeta A", 2), ("Zeta B", 2)]
    # A rule that ranks last case-wide, and that the first three leave no event of, is the one the query finds
    assert names("zeta code:9300") == [("Zeta D", 1)]
    sid, terms = save_hits(con, "zeta plain")
    reader = CountingReader(con)
    assert [n["title"] for n in by_name(reader, "zeta plain", terms, sid)] == ["Zeta E", "Zeta C", "Zeta A"]
    assert reader.scans == 1
    con.close()


def test_by_name_leaves_out_a_rule_whose_search_would_be_too_long(synthetic_case):
    """The rule's search replaces the word, and a title is longer than the word, so a query near the limit can pass it. The
    page's request for the results must not fail for it: such a rule is left out."""
    from conftest import serving

    zeta_case(synthetic_case)
    q = "zeta -" + "q" * 489   # 495 characters, 504 with "Zeta C" for the word
    for app, port, _ in serving(synthetic_case):
        session = login(port, app)
        res, body = request(port, "GET", "/api/search?q=" + urllib.parse.quote(q), session=session)
        out = json.loads(body)
        assert res.status == 200 and out["total"] and "by_name" not in out


def test_the_search_api_lists_rules_found_by_name_with_their_events_marks(synthetic_case):
    """by_name comes with the results, its events carry the marks and who set them, and a search with a match has no hint."""
    from conftest import serving

    probe_case(synthetic_case)
    for app, port, _ in serving(synthetic_case):
        session = login(port, app)
        (rdp,) = [r[0] for r in app.con.execute("SELECT event_uid FROM events WHERE source_record = '101'").fetchall()]
        res, _ = request(port, "POST", "/api/mark", session=session, body={"uids": [rdp], "value": "suspicious", "note": ""})
        assert res.status == 200
        out = json.loads(request(port, "GET", "/api/search?q=" + urllib.parse.quote("internet"), session=session)[1])
        assert out["total"] == 1 and "hint" not in out
        assert [r["title"] for r in out["by_name"]] == ["Internet Probe Seen", "RDP from internet"]
        (event,) = out["by_name"][1]["events"]
        assert (event["uid"], event["mark"], event["mark_who"]) == (rdp, "Suspicious", app.journal.state.marks[rdp].who)
        out = json.loads(request(port, "GET", "/api/search?q=" + urllib.parse.quote("code:4624"), session=session)[1])
        assert out["total"] and "by_name" not in out   # no free-text word


def test_zero_result_hint_names_the_skipped_field_that_holds_the_text(synthetic_case):
    """A search with no match says what free text covers and skips, and names the values of the skipped fields that
    hold its words, each by the word's own meaning, with a search for it or, for a mark, a role, or a tag, the View
    value. A word found nowhere has the lists and no entries."""
    from glessner.queries import sources
    from glessner.search import zero_hint

    con, _, _ = open_case(synthetic_case)
    uid = con.execute("SELECT event_uid FROM events WHERE source_record = '101'").fetchone()[0]
    con.execute("INSERT INTO marks VALUES (?, 'Suspicious', '', 1)", [uid])
    con.execute("INSERT INTO tags VALUES (?, 'tactic:persistence', 'tactic', 'Persistence', 0, 1)", [uid])
    listing = sources(con)

    def found(q):
        return zero_hint(con, parse(q), listing)["found"]
    assert found("rdp from internet") == [{"field": "rule", "value": "RDP from internet", "count": 1, "level": "high",
                                           "query": 'rule:"RDP from internet"'}]
    assert found('"RDP"') == found("rdp*") and found("RDP") and found('"rdp fro"') == [] and found('"from internet"')
    evtx = con.execute("SELECT count(*) FROM events e WHERE e.tool = 'evtxecmd' AND e.ts_us IS NOT NULL").fetchone()[0]
    assert {"field": "tool", "value": "evtxecmd", "count": evtx, "query": "tool:evtxecmd"} in found("evtxecmd")
    assert [e for e in found("r2") if e["field"] == "run"] == [{"field": "run", "value": "r2", "count": 3, "query": "run:r2"}]
    assert {"field": "file", "value": WS_LOG, "count": 3, "query": f'file:"{WS_LOG}"'} in found('"Security.evtx"')
    assert {"field": "artifact", "value": "registry", "count": 4, "query": "artifact:registry"} in found("registry")
    assert found("suspicious") == [{"field": "mark", "value": "Suspicious", "count": 1, "view": {"mark": "Suspicious"}}]
    assert found("malicious") == [] and [e["value"] for e in found("review")] == ["Unreviewed"]   # no event marked Malicious
    assert [(e["value"], e["view"]) for e in found("controllers")] == [("Domain controllers", {"role": "Domain controllers"})]
    sql = "SELECT count(*) FROM events WHERE host = 'DC01' AND tool <> 'hayabusa' AND ts_us IS NOT NULL"
    on_dc = con.execute(sql).fetchone()[0]
    assert found("controllers")[0]["count"] == on_dc
    # A quoted word is whole words in the sources' values too: evtx is a word in the artifact evtx, and inside evtxecmd
    kinds = {(e["field"], e["value"]) for e in found("evtx") if e["field"] in ("tool", "artifact")}
    assert kinds == {("tool", "evtxecmd"), ("artifact", "evtx")}
    assert {(e["field"], e["value"]) for e in found('"evtx"') if e["field"] in ("tool", "artifact")} == {("artifact", "evtx")}
    assert found("persist") == [{"field": "tag", "value": "Persistence", "count": 1, "view": {"tag": "tactic:persistence"}}]
    nothing = zero_hint(con, parse("qqqqzzzz"), listing)
    assert nothing["found"] == [] and nothing["covers"][0] == "message" and "source IP" in nothing["covers"]
    assert nothing["covers"][-1] == "event data" and nothing["skips"][-1] == "Hayabusa rule titles"
    assert (nothing["text_only"], nothing["word"]) == (True, "qqqqzzzz")
    mixed = zero_hint(con, parse('qq host:DC01 "a b"'), listing)
    assert (mixed["text_only"], mixed["word"]) == (False, None)
    assert zero_hint(con, parse("code:1 -qq"), listing) is None   # no free-text word, so nothing free text skips
    # At most five of a field and twelve in all, tools first of the fields that hold many
    many = {"types": [{"tool": f"zz{n}", "artifact": f"zz{n}", "count": n + 1,
                       "runs": [{"run": f"zz{n}", "host": "x", "count": 1}]} for n in range(8)], "hosts": []}
    crowd = zero_hint(con, parse("zz"), many)["found"]
    assert [e["field"] for e in crowd] == ["tool"] * 5 + ["artifact"] * 5 + ["run"] * 2 and len(crowd) == 12
    assert [e["value"] for e in crowd[:5]] == ["zz7", "zz6", "zz5", "zz4", "zz3"]   # the most events first
    con.close()


def test_the_hints_unreviewed_count_is_the_views_and_leaves_out_pending_suggestions(synthetic_case):
    """The hint's Unreviewed entry opens the View's mark value Unreviewed, which a pending suggestion is not in, so its count
    is the View flyout's. A word of Suggested finds the suggested events the same way."""
    from glessner.queries import mark_counts, sources
    from glessner.search import zero_hint

    con, _, _ = open_case(synthetic_case)
    counts = mark_counts(con)
    assert counts["Suggested"] and counts["Unreviewed"]
    listing = sources(con)

    def found(q):
        return [e for e in zero_hint(con, parse(q), listing)["found"] if e["field"] == "mark"]
    assert found("unreviewed") == [{"field": "mark", "value": "Unreviewed", "count": counts["Unreviewed"],
                                    "view": {"mark": "Unreviewed"}}]
    assert found("suggested") == [{"field": "mark", "value": "Suggested", "count": counts["Suggested"],
                                   "view": {"mark": "Suggested"}}]
    con.close()


def test_the_search_api_gives_the_hint_for_a_search_with_no_match(running):
    app, port, _ = running
    session = login(port, app)
    out = json.loads(request(port, "GET", "/api/search?q=" + urllib.parse.quote("evtxecmd"), session=session)[1])
    assert out["total"] == 0 and out["events"] == [] and "by_name" not in out
    assert out["hint"]["found"][0]["query"] == "tool:evtxecmd" and out["hint"]["skips"][0] == "tool"
    out = json.loads(request(port, "GET", "/api/search?q=" + urllib.parse.quote("code:9999"), session=session)[1])
    assert out["total"] == 0 and "hint" not in out   # no free-text word, so no hint
    out = json.loads(request(port, "GET", "/api/search?q=" + urllib.parse.quote("4624"), session=session)[1])
    assert out["total"] and "hint" not in out


def test_tag_is_refused_like_mark():
    """A search saves its matches and tags change as you work, so tag: and tactic: say to use the View, as mark: does.
    Otherwise they would read the event data field tag, which almost no event has, and find nothing silently."""
    for q in ("tag:x", "tactic:Persistence", "x -tag:y", "TAG:x", 'tactic:"Lateral Movement"'):
        with pytest.raises(SearchError, match="View filter"):
            parse(q)
    assert parse("data.tag:x")[0].field == "data.tag"   # the event's own field of that name is reachable
