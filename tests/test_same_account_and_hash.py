"""The load side of Same account and Same hash, with case format 3: the account key every load computes, the fold of a
domain's spellings, Same account on the key, the hash list, and Same hash. The format 3 step's fill of older rows is
test_format3_step.py's."""

import duckdb
import hash_fixtures as hf
import pytest
from conftest import DC_LOG, SEC, T0, WS_LOG, logon

from glessner.accounts import key_sql
from glessner.case import create_case
from glessner.events import Event, load
from glessner.imports import run_import, split_account
from glessner.intake import intake
from glessner.pivots import count_pivot, guidance
from glessner.queries import event_details, related
from glessner.server import App

# ---------- the account key ----------

# Spellings as logs write them: a domain and name, a UPN, Zeek's name/REALM, and the forms that must stay names
SPELLINGS = ["C137\\Administrator", "Administrator@C137.LOCAL", "mortysmith/C137.LOCAL", "root/admin", "N/A",
             "a\\b\\c", "user@10.0.0.1", "@C137.LOCAL", "bob", "", "x@y@corp.example", "x/y/corp.example", "a\\b@c.d",
             "me@host", "svc@sub.corp-1.example", "Adm\nin@C137.LOCAL", "WIN-1$", "S-1-5-21-1-2-3-500"]


def key_of(con, name, domain=None) -> str:
    return con.execute(f"SELECT {key_sql('n', 'd')} FROM (SELECT ?::VARCHAR AS n, ?::VARCHAR AS d)",
                       [name, domain]).fetchone()[0]


def test_the_key_splits_a_name_as_split_account_does_and_the_event_s_domain_wins_over_a_realm():
    """With no domain, the key is split_account's domain and name in lower case, for every spelling in the table. A
    domain of "-" is none; the event's own domain wins over a UPN's realm; both are trimmed."""
    con = duckdb.connect()
    for text in SPELLINGS:
        domain, name = split_account(text)
        assert key_of(con, text) == (f"{domain}\\{name}" if domain else name).lower(), text
    assert key_of(con, "Administrator", "C137") == "c137\\administrator"
    assert key_of(con, "Administrator@C137.LOCAL", "C137") == "c137\\administrator"
    assert key_of(con, "Administrator@C137.LOCAL", "") == "c137.local\\administrator"
    assert key_of(con, " bob ", "-") == "bob" and key_of(con, "bob", " CORP ") == "corp\\bob"
    assert key_of(con, "SYSTEM", "NT AUTHORITY") == "nt authority\\system"
    assert key_of(con, None, None) == "" and key_of(con, "", "C137") == ""


# ---------- a case of logons, its folds, and Same account ----------

DOMAIN_SID = "S-1-5-21-2232410529-1445159330-2725690660"
LOCAL_SID = "S-1-5-21-1111111111-2222222222-3333333333"   # DESKTOP-SDN1RPT's own accounts
OTHER_SID = "S-1-5-21-4444444444-5555555555-6666666666"


def sid_logon(ts, record, source, user, domain, sid, code="4624", host_field="Target"):
    """A logon recording its account's SID with the domain, as 4624 (Target), 4672 (Subject), and 4768 do."""
    fields = ({"SubjectUserSid": sid, "SubjectDomainName": domain} if code == "4672"
              else {"TargetSid": sid, "TargetDomainName": domain} if code == "4768"
              else {"TargetUserSid": sid, "TargetDomainName": domain})
    return logon(ts, record, source, user=user, domain=domain, code=code, extra=fields)


@pytest.fixture
def acase(tmp_path):
    """Szechuan's Administrator in each spelling: C137 and C137.LOCAL with one domain SID, a 4769's UPN, DESKTOP's and
    MINWINPC's local Administrators, and a name with no domain. Then CORP and corp.example with no SID at all, and
    LAB.LOCAL whose SID is its own while a LAB spelling has none."""
    for host in ("DC01", "DESKTOP", "MINWINPC"):
        (tmp_path / "evidence" / host).mkdir(parents=True)
    case = create_case(tmp_path / "case", "Accounts", tmp_path / "evidence", "cody")
    dc = [sid_logon(T0, 1, DC_LOG, "Administrator", "C137", f"{DOMAIN_SID}-500"),
          sid_logon(T0 + SEC, 2, DC_LOG, "Administrator", "C137.LOCAL", f"{DOMAIN_SID}-500", code="4768"),
          sid_logon(T0 + 2 * SEC, 3, DC_LOG, "mortysmith", "C137", f"{DOMAIN_SID}-1106", code="4672"),
          logon(T0 + 3 * SEC, 4, DC_LOG, user="Administrator@C137.LOCAL", domain="", code="4769"),
          logon(T0 + 4 * SEC, 5, DC_LOG, user="bob", domain="CORP"),
          logon(T0 + 5 * SEC, 6, DC_LOG, user="bob@corp.example", domain="", code="4769"),
          sid_logon(T0 + 6 * SEC, 7, DC_LOG, "carol", "LAB.LOCAL", f"{OTHER_SID}-1001"),
          logon(T0 + 7 * SEC, 8, DC_LOG, user="carol", domain="LAB")]
    desktop = [sid_logon(T0 + 10 * SEC, 1, WS_LOG, "Administrator", "DESKTOP-SDN1RPT", f"{LOCAL_SID}-500",
                         code="4672")]
    minwin = [logon(T0 + 20 * SEC, 1, "MINWINPC/Security.evtx", user="Administrator", domain="MINWINPC")]
    srum = Event(ts_us=T0 + 30 * SEC, ts_desc="SRUM record", artifact="srum", source_file="DESKTOP/SRUDB.dat",
                 source_record="1", message="srum", user_name="Administrator", user_domain="")
    for host, events, run in (("DC01", dc, "r1"), ("DESKTOP", desktop, "r2"), ("MINWINPC", minwin, "r3"),
                              ("DESKTOP", [srum], "r4")):
        load(case.db_path, events, host=host, tool="evtxecmd", tool_version="t", run_id=run, replaces_sources=[],
             staging_dir=case.folder)
    return case


@pytest.fixture
def aapp(acase):
    app = App(acase)
    yield app
    app.con.close()


def uid_where(app, where, *params) -> str:
    return app.con.execute(f"SELECT event_uid FROM events WHERE {where}", list(params)).fetchone()[0]


def accounts_of(app, uids) -> set[tuple[str, str, str]]:
    marks = ",".join("?" * len(uids))
    return set(app.con.execute(f"SELECT host, user_domain, user_name FROM events WHERE event_uid IN ({marks})",
                               uids).fetchall())


def test_the_fold_joins_spellings_by_their_sids_keeps_a_machine_apart_and_infers_from_a_label_only_without_sids(aapp):
    """C137 and C137.LOCAL record one domain SID (4624, 4768), so they fold to C137; DESKTOP-SDN1RPT's Administrator
    has its machine's SID and stays out, as MINWINPC does. corp.example has no SID and folds to CORP by its first
    label. LAB.LOCAL has a SID of its own, so the label rule doesn't fold it into LAB."""
    rows = set(aapp.con.execute("SELECT spelling, domain, basis FROM account_domains").fetchall())
    assert rows == {("c137", "c137", "sid"), ("c137.local", "c137", "sid"), ("corp", "corp", "label"),
                    ("corp.example", "corp", "label")}


def test_same_account_on_the_key_from_a_domain_name_a_upn_and_a_bare_name(aapp):
    """From C137\\Administrator and from a 4769's Administrator@C137.LOCAL, the Administrator of C137 in both
    spellings, its UPN, and the name with no domain, never DESKTOP-SDN1RPT's or MINWINPC's. The note names the other
    spelling and why. From the bare name, every Administrator."""
    domain_seed = uid_where(aapp, "user_domain = 'C137' AND user_name = 'Administrator'")
    upn_seed = uid_where(aapp, "user_name = 'Administrator@C137.LOCAL'")
    expected = {("DC01", "C137", "Administrator"), ("DC01", "C137.LOCAL", "Administrator"),
                ("DC01", "", "Administrator@C137.LOCAL"), ("DESKTOP", "", "Administrator")}
    for seed in (domain_seed, upn_seed):
        res = related(aapp.con, seed, "account")
        assert res["label"] == "same account"
        assert accounts_of(aapp, [e["uid"] for e in res["events"]]) == expected
        assert "the same domain by the SIDs its logons record" in res["match_note"]
    assert related(aapp.con, domain_seed, "account")["match_note"] == (
        "Also events with this name and no domain. Also written as C137.LOCAL, the same domain by the SIDs its logons "
        "record.")
    bare = related(aapp.con, uid_where(aapp, "artifact = 'srum'"), "account")
    assert bare["label"] == "same account (name only, any domain)"
    assert accounts_of(aapp, [e["uid"] for e in bare["events"]]) == expected | {
        ("DESKTOP", "DESKTOP-SDN1RPT", "Administrator"), ("MINWINPC", "MINWINPC", "Administrator")}
    # A label fold says it is inferred
    corp = related(aapp.con, uid_where(aapp, "user_name = 'bob@corp.example'"), "account")
    assert accounts_of(aapp, [e["uid"] for e in corp["events"]]) == {("DC01", "CORP", "bob"),
                                                                    ("DC01", "", "bob@corp.example")}
    assert "Also written as CORP, taken as the same domain since its first DNS label" in corp["match_note"]


def test_a_row_s_count_equals_its_list_for_same_account(aapp):
    """The count the page shows for Same account is the list's total, through the same key and fold."""
    seed = uid_where(aapp, "user_name = 'Administrator@C137.LOCAL'")
    ev = event_details(aapp.con, seed, aapp.identity)
    g = guidance(ev, aapp.identity, {}, 60)
    assert [r for r in g["rows"] + g["plain"] if r["pivot"] == "account"]
    found = count_pivot(aapp.con, aapp.identity, seed, ev["adjusted_ts_us"], "account")
    assert found["count"] == related(aapp.con, seed, "account")["total"] == 4


# ---------- the hash list and Same hash ----------

@pytest.fixture
def hcase(tmp_path):
    """The five sources' records of coreupdater.exe, the Zeek files log imported with its preset."""
    evidence = tmp_path / "evidence"
    for host in ("DC01", "DESKTOP", "SENSOR"):
        (evidence / host).mkdir(parents=True)
    rel = hf.zeek_files(evidence)
    case = create_case(tmp_path / "case", "Hashes", evidence, "cody")
    intake(case)
    for i, (host, tool, events) in enumerate(hf.hash_events(tmp_path / "out").values()):
        load(case.db_path, events, host=host, tool=tool, tool_version="t", run_id=f"h{i}", replaces_sources=[],
             staging_dir=case.folder)
    started = logon(T0 + SEC, 2, DC_LOG, code="4688")
    load(case.db_path, [logon(T0, 1, DC_LOG), started], host="DC01", tool="evtxecmd", tool_version="t", run_id="h9",
         replaces_sources=[], staging_dir=case.folder)
    assert run_import(case, rel, {"preset": "zeek"}, zones={}).status == "ok"
    return case


@pytest.fixture
def happ(hcase):
    app = App(hcase)
    yield app
    app.con.close()


SOURCES = {"amcache": "artifact = 'amcache'", "autoruns": "artifact = 'autoruns'",
           "sysmon 1": "event_provider = 'Microsoft-Windows-Sysmon' AND event_code = '1'",
           "suricata": "artifact = 'suricata'", "zeek": "artifact = 'zeek' AND source_record = '1'"}


def test_each_source_s_hash_list_holds_its_hashes_in_lower_case_and_no_imphash_pesha_or_other_hash(happ):
    """Amcache's FileId form loses its 0000; Autoruns' upper-case hashes are lowered and its PESHA and IMP left out;
    Sysmon's IMPHASH is left out; Suricata's and Zeek's are kept as written. The 4624 has none."""
    lists = {name: happ.con.execute(f"SELECT hashes FROM events WHERE {where}").fetchone()[0]
             for name, where in SOURCES.items()}
    every = " ".join(sorted([hf.SHA256, hf.MD5, hf.SHA1]))
    assert lists == {"amcache": hf.SHA1, "autoruns": every, "sysmon 1": every, "suricata": every,
                     "zeek": " ".join(sorted([hf.MD5, hf.SHA1]))}
    assert happ.con.execute("SELECT hashes FROM events WHERE event_code = '4624'").fetchone()[0] == ""
    assert happ.con.execute("SELECT hashes FROM events WHERE event_code = '7'").fetchone()[0] == hf.OTHER256


def test_same_hash_from_each_source_finds_the_others_and_an_imphash_or_pesha_joins_nothing(happ):
    """From Amcache, Autoruns, Sysmon 1, Suricata's fileinfo, and the Zeek files import, the other four. The Sysmon 7
    shares only the import hash with them, and the second Zeek file's SHA-1 is the Autoruns entry's PESHA-1: neither
    joins."""
    seeds = {name: uid_where(happ, where) for name, where in SOURCES.items()}
    for name, seed in seeds.items():
        res = related(happ.con, seed, "hash")
        assert res["label"] == "same hash"
        assert {e["uid"] for e in res["events"]} == set(seeds.values()), name   # the list holds the seed too
    for where in ("event_code = '7'", "artifact = 'zeek' AND source_record = '2'"):
        seed = uid_where(happ, where)
        assert [e["uid"] for e in related(happ.con, seed, "hash")["events"]] == [seed]
    login = related(happ.con, uid_where(happ, "event_code = '4624'"), "hash")
    assert login == {"label": "same hash", "events": [], "note": "this event has no file hash"}


def rows_of(app, uid) -> dict:
    ev = event_details(app.con, uid, app.identity)
    return guidance(ev, app.identity, {}, 60)


def test_same_hash_ranks_just_above_same_file_name_shows_the_strongest_and_is_a_plain_link_elsewhere(happ):
    """Amcache's rows run file, hash, file name, window; a Sysmon 1's run session, file, window, account, hash, file
    name; a Suricata fileinfo's flow, hash, file name. The value is the strongest hash by its length, the row's title
    names the others, and its count is its list's. A Sysmon 7 has Same hash as a plain link; a 4624 has none, and no
    not-offered line names it, while a 4688's says it has no hash.
    coreupdater.exe isn't a Windows binary, so the row isn't broad."""
    order = {"amcache": ["file", "hash", "file_name", "window"],
             "sysmon 1": ["session", "file", "window", "account", "hash", "file_name"],
             "suricata": ["flow", "hash", "file_name"]}
    for name, pivots in order.items():
        seed = uid_where(happ, SOURCES[name])
        g = rows_of(happ, seed)
        assert [r["pivot"] for r in g["rows"] if r["pivot"] in pivots] == pivots, name
        (row,) = [r for r in g["rows"] if r["pivot"] == "hash"]
        ev = event_details(happ.con, seed, happ.identity)
        assert count_pivot(happ.con, happ.identity, seed, ev["adjusted_ts_us"], "hash")["count"] == 5
        assert not row.get("broad"), name
        if name == "amcache":
            assert row["value"] == f"SHA-1 {hf.SHA1[:8]}...{hf.SHA1[-4:]}" and "warn" not in row
        else:
            assert row["value"] == f"SHA-256 {hf.SHA256[:8]}...{hf.SHA256[-4:]}"
            assert row["warn"] == f"Also matches its SHA-1 {hf.SHA1} and MD5 {hf.MD5}."
    loaded = rows_of(happ, uid_where(happ, "event_code = '7'"))
    assert [p["value"] for p in loaded["plain"] if p["pivot"] == "hash"] == [
        f"SHA-256 {hf.OTHER256[:8]}...{hf.OTHER256[-4:]}"]
    logon_rows = rows_of(happ, uid_where(happ, "event_code = '4624'"))
    assert not [p for p in logon_rows["plain"] + logon_rows["rows"] + logon_rows["not_offered"] if p["pivot"] == "hash"]
    # A 4688's kind ranks Same hash, and a 4688 records none, so its line says so
    started = rows_of(happ, uid_where(happ, "event_code = '4688'"))
    assert [p["reason"] for p in started["not_offered"] if p["pivot"] == "hash"] == ["This event has no file hash"]


def test_same_hash_on_a_windows_binary_is_broad(happ, tmp_path):
    """The system_binary rule, tested on the event's own file name, as Same file name's is."""
    out = tmp_path / "svchost"
    out.mkdir()
    from rekey_fixtures import AMCACHE_FILE, write_rows

    from glessner.parsers import PARSERS, ParseContext

    write_rows(out / "2024_Amcache_UnassociatedFileEntries.csv", AMCACHE_FILE, [
        {"FileKeyLastWriteTimestamp": "2020-09-19 03:40:46", "FullPath": "c:\\windows\\system32\\svchost.exe",
         "SHA1": "0000" + "1" * 40}])
    events = list(PARSERS["amcache_csv"](ParseContext(out, tmp_path, ("DESKTOP/Amcache.hve",))))
    load(happ.case.db_path, events, host="DESKTOP", tool="amcacheparser", tool_version="t", run_id="s1",
         replaces_sources=[], staging_dir=happ.case.folder)
    happ.refresh_identity(events_changed=True)
    (row,) = [r for r in rows_of(happ, uid_where(happ, "file_path ILIKE '%svchost.exe'"))["rows"]
              if r["pivot"] == "hash"]
    assert row.get("broad")
