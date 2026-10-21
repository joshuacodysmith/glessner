"""Accounts known only by their SID take the name the same host's 4624s and 4672s record with it, whichever order the
runs load in."""

import csv
import json

from conftest import T0
from test_parsers import EVIDENCE, EVTX_COLUMNS, event_data, security_row, write_csv

from glessner.accounts import name_sids
from glessner.case import create_case
from glessner.events import Event, connect, load
from glessner.export import export_timeline
from glessner.filters import pred_sql
from glessner.intake import intake
from glessner.parsers import PARSERS, ParseContext
from glessner.queries import BASE_FROM, BASE_WHERE, account_names, lanes, related
from glessner.runner import load_found_output, rebuild
from glessner.search import results, save_hits
from glessner.server import App, api_rule

SID = "S-1-5-21-3623811015-3361044348-30300820-1013"
UNKNOWN = "S-1-5-21-3623811015-3361044348-30300820-1099"
LOOKED_UP = f"{SID} is CORP\\alice in 2 of this host's 4624 and 4672 events"


def script_block(record, sid, text="Get-ChildItem C:\\Users"):
    """PowerShell's script block event (4104), which names no account in its data: only the System element's UserID."""
    return {"EventRecordId": str(record), "TimeCreated": "2020-09-19 03:40:05.0000000", "EventId": "4104",
            "Provider": "Microsoft-Windows-PowerShell", "Channel": "Microsoft-Windows-PowerShell/Operational",
            "Computer": "LAB", "SourceFile": "D:\\Evidence\\case\\LAB\\PowerShell.evtx",
            "MapDescription": "Script block", "UserId": sid,
            "Payload": event_data(MessageNumber="1", MessageTotal="1", ScriptBlockText=text, ScriptBlockId="{1}")}


def app_readiness(record, sid):
    """AppReadiness's 240, whose own data gives the account as a SID (its User field); its System element's UserID is
    LocalSystem, so the parser keeps no SecurityUserID."""
    return {"EventRecordId": str(record), "TimeCreated": "2020-09-19 03:40:06.0000000", "EventId": "240",
            "Provider": "Microsoft-Windows-AppReadiness", "Channel": "Microsoft-Windows-AppReadiness/Admin",
            "Computer": "LAB", "SourceFile": "D:\\Evidence\\case\\LAB\\AppReadiness.evtx",
            "MapDescription": "", "UserId": "S-1-5-18",
            "Payload": event_data(User=sid, Package="Microsoft.Windows.Photos")}


def logons(sid=SID, name="alice", domain="CORP", first=100, second=1):
    """A 4624 and the 4672 Windows logs with it, each recording the SID with its name."""
    rows = [security_row(first, 4624, "Successful logon", {"TargetUserSid": sid, "TargetUserName": name,
                                                           "TargetDomainName": domain, "TargetLogonId": "0x5C1D2",
                                                           "LogonType": "2"}),
            security_row(first + 1, 4672, "Special privileges", {"SubjectUserSid": sid, "SubjectUserName": name,
                                                                  "SubjectDomainName": domain,
                                                                  "SubjectLogonId": "0x5C1D2"})]
    for row in rows:
        row["TimeCreated"] = f"2020-09-19 03:40:{second:02}.0000000"
    return rows


def parsed(folder, rows):
    folder.mkdir()
    write_csv(folder / "evtxecmd.csv", EVTX_COLUMNS, rows)
    return list(PARSERS["evtxecmd_csv"](ParseContext(folder, EVIDENCE)))


def load_run(db, events, host, run_id, staging, sources=()):
    load(db, events, host=host, tool="evtxecmd", tool_version="t", run_id=run_id,
         replaces_sources=sorted({e.source_file for e in events} | set(sources)), staging_dir=staging)


def accounts(db):
    """Each event's account and lookup marker, by host, event code, and record."""
    con = connect(db, read_only=True)
    rows = con.execute("SELECT host, event_code, source_record, user_name, user_domain, extra FROM events").fetchall()
    con.close()
    return {(h, code, rec): (name, domain, json.loads(extra or "{}").get("AccountLookedUp"))
            for h, code, rec, name, domain, extra in rows}


def snapshot(db):
    """Every event's ID, account, and extra data. A looked-up event's extra is rewritten as compact JSON, so the data
    compares parsed."""
    con = connect(db, read_only=True)
    rows = con.execute("SELECT event_uid, user_name, user_domain, extra FROM events ORDER BY event_uid").fetchall()
    con.close()
    return [(uid, name, domain, json.loads(extra) if extra else None) for uid, name, domain, extra in rows]


def test_a_sid_only_event_takes_the_name_once_the_hosts_logons_load(tmp_path):
    """The 4104s load in an earlier run than DC01's logons. Once the logons load, DC01's 4104 reads as CORP\\alice; a
    SID DC01 never names stays a SID, and so does the same SID on DESKTOP, which only DC01 names. Event IDs hold. When
    the Security log loads again without the logons, the account goes back to the SID."""
    db = tmp_path / "events.duckdb"
    load_run(db, parsed(tmp_path / "ps", [script_block(1, SID), script_block(2, UNKNOWN)]), "DC01", "r1", tmp_path)
    load_run(db, parsed(tmp_path / "ps2", [script_block(1, SID)]), "DESKTOP", "r2", tmp_path)
    before = snapshot(db)
    assert accounts(db)[("DC01", "4104", "1")] == (SID, "", None)

    security = parsed(tmp_path / "sec", logons())
    load_run(db, security, "DC01", "r3", tmp_path)
    found = accounts(db)
    assert found[("DC01", "4104", "1")] == ("alice", "CORP", LOOKED_UP)
    assert found[("DC01", "4104", "2")] == (UNKNOWN, "", None)        # a SID the case never names
    assert found[("DESKTOP", "4104", "1")] == (SID, "", None)         # named on another host only
    assert found[("DC01", "4624", "100")] == ("alice", "CORP", None)  # recorded, not looked up
    after = {uid: extra for uid, _, _, extra in snapshot(db)}
    block = next(uid for uid, name, _, _ in before if name == SID and after[uid].get("AccountLookedUp"))
    assert set(after) >= {uid for uid, *_ in before}                  # the same event IDs
    assert after[block]["SecurityUserID"] == SID and after[block]["ScriptBlockText"] == "Get-ChildItem C:\\Users"

    load_run(db, [], "DC01", "r4", tmp_path, sources=[security[0].source_file])   # its events replaced by none
    assert snapshot(db) == before


def test_a_sid_the_events_own_data_gives_is_named_too(tmp_path):
    """AppReadiness's User field gives the account as the SID, with no SecurityUserID. It takes the name like the 4104
    does, so the user is one account, and keeps the SID beside the marker; when the logons go, the event is as the
    parser wrote it."""
    db = tmp_path / "events.duckdb"
    load_run(db, parsed(tmp_path / "ar", [app_readiness(5, SID), app_readiness(6, UNKNOWN)]), "DC01", "r1", tmp_path)
    before = snapshot(db)
    assert accounts(db)[("DC01", "240", "5")] == (SID, "", None)
    security = parsed(tmp_path / "sec", logons())
    load_run(db, security, "DC01", "r2", tmp_path)
    found = accounts(db)
    assert found[("DC01", "240", "5")] == ("alice", "CORP", LOOKED_UP)
    assert found[("DC01", "240", "6")] == (UNKNOWN, "", None)
    extra = {e["User"]: e for _, _, _, e in snapshot(db) if e and "User" in e}
    assert (extra[SID]["AccountLookedUpSid"], extra[SID]["User"], "SecurityUserID" in extra[SID]) == (SID, SID, False)
    assert "AccountLookedUpSid" not in extra[UNKNOWN]
    load_run(db, [], "DC01", "r3", tmp_path, sources=[security[0].source_file])
    assert snapshot(db) == before


def test_the_lookup_changes_the_account_key_with_the_name(tmp_path):
    """A SID-only event's account key is the SID until the host's logons name it, then the named key, CORP\\alice, in
    the lookup's transaction, so Same account finds it with the logon. When the logons go, the key goes back to the
    SID."""
    db = tmp_path / "events.duckdb"

    def key():
        con = connect(db, read_only=True)
        try:
            return con.execute("SELECT account_key FROM events WHERE event_code = '4104'").fetchone()[0]
        finally:
            con.close()

    load_run(db, parsed(tmp_path / "ps", [script_block(1, SID)]), "DC01", "r1", tmp_path)
    assert key() == SID.lower()
    security = parsed(tmp_path / "sec", logons())
    load_run(db, security, "DC01", "r2", tmp_path)
    assert key() == "corp\\alice"
    load_run(db, [], "DC01", "r3", tmp_path, sources=[security[0].source_file])
    assert key() == SID.lower()


def test_only_loads_of_event_log_rows_or_logons_look_up(tmp_path, monkeypatch):
    """A lookup costs about 70 ms a host on the Szechuan case, and grows with the host's logons,
    so a load runs it only on the hosts where it adds or removes event log rows or 4624s and 4672s. MFT rows, an
    import's lane of other rows, and a tool's replaced rows of other kinds leave it out; an import's 4624s and replaced
    event log rows bring it in."""
    import glessner.accounts as accounts_module

    calls = []
    real = accounts_module.name_sids

    def recorded(con, hosts):
        calls.append(sorted(set(hosts)))
        return real(con, hosts)

    monkeypatch.setattr(accounts_module, "name_sids", recorded)
    db = tmp_path / "events.duckdb"
    mft = Event(T0, "File created", "mft", "C/$MFT", "1", "file", file_path="C:\\a.txt")
    load(db, [mft], host="DC01", tool="mftecmd", tool_version="t", run_id="r1", replaces_sources=["C/$MFT"],
         staging_dir=tmp_path)
    load(db, [], host="DC01", tool="mftecmd", tool_version="t", run_id="r2", replaces_sources=["C/$MFT"],
         staging_dir=tmp_path)
    script = parsed(tmp_path / "ps", [script_block(1, SID)])
    load_run(db, script, "DC01", "r3", tmp_path)
    logon = Event(T0, "Event Recorded", "windows_logon", "WS01/logons.csv", "7", "4624 logon", event_code="4624",
                  lane="WS01", extra={"TargetUserSid": SID, "TargetUserName": "alice"})
    firewall = Event(T0, "Connection allowed", "windows_firewall", "WS02/pfirewall.log", "1", "allow", lane="WS02")
    load(db, [logon, firewall], host=None, tool="import", tool_version="t", run_id="r4",
         replaces_sources=["WS01/logons.csv", "WS02/pfirewall.log"], staging_dir=tmp_path)
    load(db, [firewall], host=None, tool="import", tool_version="t", run_id="r5",
         replaces_sources=["WS01/logons.csv", "WS02/pfirewall.log"], staging_dir=tmp_path)
    load(db, [], host="DC01", tool="evtxecmd", tool_version="t", run_id="r6",
         replaces_sources=[script[0].source_file], staging_dir=tmp_path)
    assert calls == [[], [], ["DC01"], ["WS01"], ["WS01"], ["DC01"]]


def test_an_import_lane_and_the_rows_it_replaces_are_looked_up(tmp_path):
    """A load whose events name their own host, as an import's do (host None), looks up the hosts it adds rows to and
    the hosts whose rows it replaces."""
    db = tmp_path / "events.duckdb"
    load_run(db, parsed(tmp_path / "ps", [script_block(1, SID)]), "DC01", "r1", tmp_path)
    logon = Event(T0, "Event Recorded", "evtx", "DC01/exported.xml", "7", "4624 logon", event_code="4624",
                  user_name="alice", user_domain="CORP", lane="DC01",
                  extra={"TargetUserSid": SID, "TargetUserName": "alice", "TargetDomainName": "CORP"})
    load(db, [logon], host=None, tool="import", tool_version="t", run_id="r2", replaces_sources=["DC01/exported.xml"],
         staging_dir=tmp_path)
    assert accounts(db)[("DC01", "4104", "1")] == ("alice", "CORP", f"{SID} is CORP\\alice in 1 of this host's 4624 events")
    load(db, [], host=None, tool="import", tool_version="t", run_id="r3", replaces_sources=["DC01/exported.xml"],
         staging_dir=tmp_path)
    assert accounts(db)[("DC01", "4104", "1")] == (SID, "", None)


def test_a_renamed_account_takes_its_most_recorded_name_then_its_latest(tmp_path):
    """An account renamed from alice to alice2. DC01 records the SID as alice2 three times and as alice twice, later:
    the most recorded name wins over the latest and over sort order. DESKTOP records each once: the later name wins
    over sort order. The marker lists the other name with its count."""
    db = tmp_path / "events.duckdb"
    load_run(db, parsed(tmp_path / "ps", [script_block(1, SID)]), "DC01", "r1", tmp_path)
    load_run(db, parsed(tmp_path / "ps2", [script_block(1, SID)]), "DESKTOP", "r2", tmp_path)
    dc = (logons(name="alice2", first=100, second=1) + logons(name="alice2", first=200, second=2)[:1]
          + logons(name="alice", first=300, second=3))
    load_run(db, parsed(tmp_path / "dc", dc), "DC01", "r3", tmp_path)
    desktop = logons(name="alice", second=3)[:1] + logons(name="alice2", second=4)[1:]   # a 4624, then a 4672
    load_run(db, parsed(tmp_path / "ws", desktop), "DESKTOP", "r4", tmp_path)
    found = accounts(db)
    assert found[("DC01", "4104", "1")] == (
        "alice2", "CORP", f"{SID} is CORP\\alice2 in 3 of this host's 4624 and 4672 events, CORP\\alice in 2")
    assert found[("DESKTOP", "4104", "1")] == (
        "alice2", "CORP", f"{SID} is CORP\\alice2 in 1 of this host's 4672 events, CORP\\alice in 1")


def test_names_dont_depend_on_load_order_and_a_rebuild_gives_the_same(tmp_path):
    """The PowerShell and Security logs' EvtxECmd output, found in the evidence and loaded as runs: PowerShell's first,
    then Security's, then a rebuild, and the other order in another database, all give the same accounts and data."""
    evidence = tmp_path / "evidence"
    folder = evidence / "WS01" / "Modules" / "EventLogs"
    folder.mkdir(parents=True)
    write_csv(folder / "PowerShell_EvtxECmd_Output.csv", EVTX_COLUMNS, [script_block(1, SID), script_block(2, UNKNOWN)])
    write_csv(folder / "Security_EvtxECmd_Output.csv", EVTX_COLUMNS, logons())
    case = create_case(tmp_path / "case", "SIDs", evidence, "cody")
    intake(case)
    for name in ("PowerShell", "Security"):
        record = load_found_output(case, "evtxecmd", "evtxecmd_csv", "WS01",
                                   [f"WS01/Modules/EventLogs/{name}_EvtxECmd_Output.csv"])
        assert record.status == "ok"
        if name == "PowerShell":
            assert accounts(case.db_path)[("WS01", "4104", "1")] == (SID, "", None)
    loaded = snapshot(case.db_path)
    assert accounts(case.db_path)[("WS01", "4104", "1")] == ("alice", "CORP", LOOKED_UP)
    assert len(rebuild(case)) == 2
    assert snapshot(case.db_path) == loaded
    other = tmp_path / "other.duckdb"
    for name in ("Security", "PowerShell"):
        files = (folder / f"{name}_EvtxECmd_Output.csv",)
        load_run(other, list(PARSERS["evtxecmd_csv"](ParseContext(folder, evidence, (), files))), "WS01", name, tmp_path)
    assert snapshot(other) == loaded


def test_lanes_pivots_filters_search_rules_and_the_export_read_the_name(synthetic_case, tmp_path):
    """Everything that reads the account sees the name: lanes by account, the Same account pivot, the View filter,
    search, rule fields, and the export, which keeps the SID as user.id. The 4104's SID came from its System element,
    the AppReadiness 240's from its data. A search for the SID still finds both."""
    load_run(synthetic_case.db_path, parsed(tmp_path / "ps", [script_block(1, SID)]), "DC01", "r10", tmp_path)
    load_run(synthetic_case.db_path, parsed(tmp_path / "ar", [app_readiness(5, SID)]), "DC01", "r11", tmp_path)
    load_run(synthetic_case.db_path, parsed(tmp_path / "sec", logons()), "DC01", "r12", tmp_path)
    a = App(synthetic_case)
    try:
        block = a.con.execute("SELECT event_uid FROM events WHERE event_code = '4104'").fetchone()[0]
        mine = [(lane["keys"][0], lane["count"]) for lane in lanes(a.con, ["user"])
                if "alice" in lane["keys"][0] or lane["keys"][0].startswith("S-1-")]
        assert mine == [("corp\\alice", 4)]   # keyed in lower case, labeled as written
        assert account_names(a.con)["corp\\alice"] == "CORP\\alice"
        assert sorted(e["code"] for e in related(a.con, block, "account")["events"]) == ["240", "4104", "4624", "4672"]

        def view(pred):
            return a.con.execute(f"SELECT e.event_code FROM {BASE_FROM} WHERE {BASE_WHERE} AND {pred_sql(pred)} "
                                 "ORDER BY 1").fetchall()

        assert view({"user": "corp\\alice"}) == [("240",), ("4104",), ("4624",), ("4672",)]
        assert view({"user": SID}) == []   # the View, like the lanes, has the name; a search finds the SID
        search, _ = save_hits(a.con, "user:alice code:4104")
        assert [e["uid"] for e in results(a.con, search)["events"]] == [block]
        search, _ = save_hits(a.con, f"user:{SID}")
        assert sorted(e["code"] for e in results(a.con, search)["events"]) == ["240", "4104"]
        search, _ = save_hits(a.con, "user:S-1-5-21-*-1013")
        assert sorted(e["code"] for e in results(a.con, search)["events"]) == ["240", "4104"]
        rule = "id: alice-review\nsuggest: suspicious\nwhen: {field: account, equals: 'corp\\alice'}\n"
        assert {r["id"]: r for r in api_rule(a, {"op": "add", "text": rule})["rules"]}["alice-review"]["pending"] == 4
        path, _ = export_timeline(a.con, a.case, a.identity, 0, 2**62, "csv", "all")
        with path.open(encoding="utf-8", newline="") as f:
            rows = {r["event.code"]: r for r in csv.DictReader(f) if r["event.code"] in ("240", "4104", "4624")}
        for code in ("240", "4104"):
            assert (rows[code]["user.name"], rows[code]["user.domain"], rows[code]["user.id"]) == ("alice", "CORP", SID)
        assert (rows["4624"]["user.name"], rows["4624"]["user.id"]) == ("alice", "")   # recorded, no System SID
    finally:
        a.con.close()


def test_user_lanes_join_an_account_s_spellings_under_its_usual_one(synthetic_case):
    """The user lanes key accounts without their letter case, so one account written five ways is one lane, as Same
    account, like Windows, ignores the case. The lane is labeled with the case's most common spelling."""
    from conftest import DC_LOG, SEC, logon

    from glessner.server import api_lanes

    shouted = [logon(T0 + (70 + i) * SEC, 110 + i, DC_LOG, user="ADMINISTRATOR", domain="c137") for i in range(2)]
    load(synthetic_case.db_path, shouted, host="DC01", tool="evtxecmd", tool_version="t", run_id="r9",
         replaces_sources=[], staging_dir=synthetic_case.folder)
    a = App(synthetic_case)
    try:
        res = api_lanes(a, {"groupby": ["user"]})
        admins = [(lane["keys"][0], lane["count"]) for lane in res["lanes"] if "administrator" in lane["keys"][0].lower()]
        assert admins == [("c137\\administrator", 8)]   # six as C137\Administrator, two as c137\ADMINISTRATOR
        assert res["names"]["user"]["c137\\administrator"] == "C137\\Administrator"
        assert api_lanes(a, {"groupby": ["host"]})["names"] == {}
    finally:
        a.con.close()


def test_the_lookup_writes_nothing_when_nothing_changes(tmp_path):
    """Run again on the same rows, the lookup finds every account already right and writes nothing."""
    db = tmp_path / "events.duckdb"
    load_run(db, parsed(tmp_path / "ps", [script_block(1, SID)]), "DC01", "r1", tmp_path)
    load_run(db, parsed(tmp_path / "sec", logons()), "DC01", "r2", tmp_path)
    con = connect(db)
    try:
        assert name_sids(con, ["DC01", "DESKTOP"]) == 0 and name_sids(con, []) == 0
    finally:
        con.close()
