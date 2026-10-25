"""The case format 3 step's own work beside the seal: the evidence folder recorded on the tool runs whose record names
none (an empty evidence_root) and that format 2's step left, and the account key and the hash list filled in the
events loaded before. The seal itself is test_format3.py's; the load side of the account key and the hash list is
test_same_account_and_hash.py's."""

import hashlib
import json
import os
import shutil
from pathlib import Path

import hash_fixtures as hf
import pytest
from chain_fixtures import append_unchained, as_format, note, unchained
from conftest import DC_LOG, T0, logon
from parser_fix_fixtures import SECURITY, event_data, row, write_csv
from pivot_key_fixtures import mft_events, parsed, suricata_events
from rekey_cases import Format1, case_format, set_format, state_of
from rekey_fixtures import TOOL_HIVE, amcache_tables

from glessner import rekey
from glessner.case import CaseError, create_case, open_case
from glessner.events import COLUMNS, connect, load
from glessner.imports import run_import
from glessner.intake import intake
from glessner.queries import related
from glessner.rekey import PINNED_FILE, upgraded
from glessner.runner import read_runs, rebuild
from glessner.server import App

PINNING = "Upgrading the case format: recording where the runs read their files"
FILLING = "Upgrading the case format: filling the account key and the hashes"


class Crash(Exception):
    pass


def security_log(host: str) -> str:
    return f"{host}/Windows/System32/winevt/Logs/Security.evtx"


def evtx_output(source: str):
    """EvtxECmd's output for two logons, its SourceFile the absolute path the tool read."""
    def write(out):
        write_csv(out / "evtxecmd.csv", [
            {**row(n, "4624", SECURITY, event_data(TargetUserName="bob", TargetDomainName="C137", LogonType="3",
                                                   TargetLogonId=f"0x{n}")), "SourceFile": source} for n in (1, 2)])
    return write


def evtx_run(f: Format1, host: str, source: str | None = None, **kw):
    """An EvtxECmd run whose record names no evidence folder, on the host's Security log, its output naming the log
    under the evidence folder, or `source`."""
    return f.tool_run("evtxecmd", "evtxecmd_csv", host, [security_log(host)],
                      evtx_output(source or str(f.evidence / Path(security_log(host)))), no_folders=True, **kw)


def import_run(f: Format1):
    """An import of a CSV in the evidence, which reads the evidence where it is now and records no folder."""
    path = f.evidence / "WS01" / "logons.csv"
    path.write_text("Time,User,Message\n2024-07-01T10:00:00Z,alice,a\n", encoding="utf-8", newline="")
    f.take_in()
    mapping = {"format": "csv", "delimiter": ",", "header": True, "artifact": "csv_fixture",
               "time": {"columns": ["Time"], "format": "ymd", "zone": "UTC"}, "fields": {"user": "User", "message":
               "Message"}, "host": {"from": "folder"}, "message": "{Message}", "ignore": []}
    record = run_import(f.case, "WS01/logons.csv", mapping, zones={})
    assert record.status == "ok", record.reason
    return record


def run_json(f: Format1, record) -> bytes:
    return (f.case.runs_folder / record.run_id / "run.json").read_bytes()


def case_without_run_folders(tmp_path) -> tuple[Format1, dict]:
    """A format 2 case with runs whose record names no evidence folder and that format 2's step never parsed:
    EvtxECmd's on WS01, its output naming the log under the evidence; AmcacheParser's on a host with no found Amcache;
    EvtxECmd's on WS02, whose output names the evidence where it was before a move; and EvtxECmd's on WS03, whose output
    changed after its run. Beside them a found-output run and an import, which read the evidence where it is now."""
    f = Format1(tmp_path, hosts=("DESKTOP", "SENSOR", "WS01", "WS02", "WS03"))
    runs = {"evtx": evtx_run(f, "WS01"),
            "amcache": f.tool_run("amcacheparser", "amcache_csv", "DESKTOP", [TOOL_HIVE], amcache_tables, no_folders=True),
            "elsewhere": evtx_run(f, "WS02", "D:\\Evidence\\before-the-move\\" + security_log("WS02").replace("/", "\\")),
            "changed": evtx_run(f, "WS03")}
    output = f.case.runs_folder / runs["changed"].run_id / "output" / "evtxecmd.csv"
    output.write_bytes(output.read_bytes() + b"\r\n")
    f.eve_file("SENSOR/found/eve.json", 7)
    f.take_in()
    runs["found"] = f.found_run("suricata", "suricata_eve", "SENSOR", ["SENSOR/found/eve.json"])
    runs["import"] = import_run(f)
    set_format(f.case.folder, 2)   # format 2's step had nothing of these runs to remap
    f.reopen()
    return f, runs


def move_evidence(f: Format1, tmp_path) -> None:
    """The evidence folder moved, and case.yaml naming the new one."""
    moved = Path(shutil.move(f.evidence, tmp_path / "evidence_moved"))
    data = (f.case.folder / "case.yaml").read_text(encoding="utf-8").replace(str(f.evidence), str(moved))
    (f.case.folder / "case.yaml").write_text(data, encoding="utf-8")
    f.evidence = moved
    f.reopen()


def ids_of(f: Format1, runs) -> list[str]:
    return f.uids(where=f"run_id IN ({', '.join(repr(r.run_id) for r in runs)})")


# ---------- Pinning the evidence folder on older runs ----------

def test_pins(tmp_path, monkeypatch):
    """The WS01 EvtxECmd run and the AmcacheParser tool run are pinned; the run whose output
    names files elsewhere stays empty with the count; the run whose output changed stays empty and is named; the
    found-output run and the import are untouched. The step reports its progress, and the seal names the pins; the 3 to 4
    entry follows it. Then the evidence moves, case.yaml names the new folder, and a rebuild keeps the pinned runs' event
    IDs."""
    f, runs = case_without_run_folders(tmp_path)
    untouched = {name: run_json(f, runs[name]) for name in ("found", "import")}
    stages = []
    monkeypatch.setattr(rekey, "report_stage", lambda stage, done=0, total=0: stages.append((stage, done, total)))
    upgraded(f.case)
    assert case_format(f.case) == 4
    records = {r.run_id: r for r in read_runs(f.case)}
    for name in ("evtx", "amcache"):
        assert records[runs[name].run_id].evidence_root == str(f.evidence), name
    for name in ("elsewhere", "changed"):
        assert records[runs[name].run_id].evidence_root == "", name
    assert {name: run_json(f, runs[name]) for name in ("found", "import")} == untouched
    (seal,) = f.upgrades(3)
    (step,) = f.upgrades(4)
    assert step["from_format"] == 3 and step["seq"] > seal["seq"] and "pins" not in step
    pins = seal["pins"]
    assert pins["pinned"] == sorted([runs["evtx"].run_id, runs["amcache"].run_id])
    unpinned = pins["unpinned_runs"]
    assert set(unpinned) == {runs["elsewhere"].run_id, runs["changed"].run_id}
    assert unpinned[runs["elsewhere"].run_id] == (
        "2 of its events name a file outside the case's evidence folder and the run's own folder, so where it read its "
        "files can't be known")
    assert unpinned[runs["changed"].run_id].startswith("its output doesn't match its record: ")
    assert ("Recorded where 2 earlier tool runs read their files, so a later move of the evidence keeps their events' "
            "IDs; 2 runs were left as they were, each named with the reason.") in seal["text"]
    assert [s for s in stages if s[0] == PINNING] == [(PINNING, n, 4) for n in (1, 2, 3, 4)]
    assert not (f.case.folder / PINNED_FILE).exists()
    pinned = [runs["evtx"], runs["amcache"]]
    ids = ids_of(f, pinned)
    assert ids
    move_evidence(f, tmp_path)
    rebuild(f.case)
    assert ids_of(f, pinned) == ids


def test_a_run_the_parser_refuses_is_left_unpinned_and_named_and_the_step_goes_on(tmp_path, monkeypatch):
    """An exception from today's parser reading an older run's output is caught: otherwise one run it refuses would stop
    the step at every open and the case could never open. The run is left as it was and named with
    the reason, as a run naming files elsewhere is; the other pins, the seal, and the 3 to 4 step go on."""
    f, runs = case_without_run_folders(tmp_path)
    name = runs["evtx"].parser

    def refuses(ctx):
        raise ValueError("today's parser refuses this older output")
        yield   # a generator, as the parsers are

    monkeypatch.setitem(rekey.PARSERS, name, refuses)
    upgraded(f.case)
    assert case_format(f.case) == 4
    (seal,) = f.upgrades(3)
    (step,) = f.upgrades(4)
    assert step["from_format"] == 3 and step["seq"] > seal["seq"]
    assert seal["pins"]["unpinned_runs"][runs["evtx"].run_id] == (
        "its output can't be read by this build (ValueError: today's parser refuses this older output)")
    assert runs["amcache"].run_id in seal["pins"]["pinned"]
    assert not (f.case.folder / PINNED_FILE).exists()


def test_the_pins_are_counted_without_building_id_maps(tmp_path, monkeypatch):
    """The pins need only the count of events naming files outside the case, and _parse's two IDs per event and its
    maps would hold a large run's events in memory. The pins come out the same with no ID maps built."""
    f, runs = case_without_run_folders(tmp_path)

    def no_maps(*args, **kwargs):
        raise AssertionError("the pins build no ID maps")

    monkeypatch.setattr(rekey, "EventIds", no_maps)
    upgraded(f.case)
    (seal,) = f.upgrades(3)
    assert seal["pins"]["pinned"] == sorted([runs["evtx"].run_id, runs["amcache"].run_id])


def test_no_id_changes_at_the_pin(tmp_path):
    """The pinned runs' event IDs from a rebuild before the step and from
    one after it, on the same folders, are identical. The pin records the folder the run's output was read against."""
    f, runs = case_without_run_folders(tmp_path)
    pinned = [runs["evtx"], runs["amcache"]]
    before = ids_of(f, pinned)   # loaded as a format 1 build loaded them, with the folders empty
    upgraded(f.case)
    rebuild(f.reopen())
    assert ids_of(f, pinned) == before


def test_a_crash_among_the_pins(tmp_path, monkeypatch):
    """A fault right after the first of three records changes. The next
    open's seal names all three in pins.pinned, the first read from upgrade_pinned_runs.json, which is gone after."""
    f = Format1(tmp_path, hosts=("DESKTOP", "SENSOR", "WS01", "WS02"))
    runs = [evtx_run(f, "WS01"), evtx_run(f, "WS02"),
            f.tool_run("amcacheparser", "amcache_csv", "DESKTOP", [TOOL_HIVE], amcache_tables, no_folders=True)]
    set_format(f.case.folder, 2)
    real = rekey._write_record

    def first_then_crash(folder, record):
        real(folder, record)
        raise Crash("stopped after the first pin")

    monkeypatch.setattr(rekey, "_write_record", first_then_crash)
    with pytest.raises(Crash):
        upgraded(f.reopen())
    monkeypatch.setattr(rekey, "_write_record", real)
    assert case_format(f.case) == 2 and not f.upgrades(3)
    assert sum(bool(r.evidence_root) for r in read_runs(f.case)) == 1
    kept = json.loads((f.case.folder / PINNED_FILE).read_text(encoding="utf-8"))
    assert kept["runs"] == sorted(r.run_id for r in runs)
    upgraded(f.reopen())
    (seal,) = f.upgrades(3)
    assert seal["pins"] == {"pinned": sorted(r.run_id for r in runs), "unpinned_runs": {}}
    assert not (f.case.folder / PINNED_FILE).exists()


def test_an_unended_entry_the_reader_cant_apply_refuses_before_the_pins_change_a_run_record(tmp_path):
    """The pins rewrite case records, so the tail check comes before them: a refusal with "Nothing was changed" leaves
    the run.json files unwritten and upgrade_pinned_runs.json absent."""
    f, runs = case_without_run_folders(tmp_path)
    journal = f.case.folder / "journal.jsonl"
    journal.write_bytes(journal.read_bytes() + unchained(note("x"))[:-1])
    records = {name: run_json(f, record) for name, record in runs.items()}
    before = journal.read_bytes()
    with pytest.raises(CaseError, match="Nothing was changed"):
        upgraded(f.case)
    assert {name: run_json(f, record) for name, record in runs.items()} == records
    assert not (f.case.folder / PINNED_FILE).exists() and journal.read_bytes() == before
    assert case_format(f.case) == 2


def test_the_pinned_runs_file_reaches_the_disk_before_it_takes_its_name(tmp_path, monkeypatch):
    """upgrade_pinned_runs.json is written by temporary file, fsync, and replace, as each run record is
    (tests/test_rekey.py's run record check)."""
    f = Format1(tmp_path, hosts=("WS01",))
    evtx_run(f, "WS01")
    set_format(f.case.folder, 2)
    order = []
    real_fsync, real_replace = os.fsync, os.replace
    monkeypatch.setattr(os, "fsync", lambda fd: (order.append("fsync"), real_fsync(fd))[1])
    monkeypatch.setattr(os, "replace", lambda src, dst: (order.append(Path(dst).name), real_replace(src, dst))[1])
    upgraded(f.reopen())
    writes = [i for i, step in enumerate(order) if step == PINNED_FILE]
    assert len(writes) == 2   # the list, then the run's result
    assert all(order[i - 1] == "fsync" for i in writes)


# ---------- The account key and hash list fill ----------

def older_rows(case) -> None:
    """The events as a format 2 build left them: no account key or hash list. The next read-write connect adds both
    columns back, NULL in every row, as it does to a format 2 case's database."""
    con = connect(case.db_path)
    try:
        con.execute("ALTER TABLE events DROP COLUMN account_key")
        con.execute("ALTER TABLE events DROP COLUMN hashes")
        con.execute("CHECKPOINT")
    finally:
        con.close()


def the_rest(case) -> str:
    """Every other column of every row, IDs included, in a fixed order: what the fill must not change."""
    rest = [c for c in COLUMNS if c not in ("account_key", "hashes")]
    con = connect(case.db_path, read_only=True)
    try:
        rows = con.execute(f"SELECT {', '.join(rest)} FROM events ORDER BY event_uid").fetchall()
    finally:
        con.close()
    return hashlib.sha256(repr(rows).encode("utf-8", "surrogatepass")).hexdigest()


def columns_of(case) -> dict:
    con = connect(case.db_path, read_only=True)
    try:
        return {uid: (key, hashes) for uid, key, hashes in
                con.execute("SELECT event_uid, account_key, hashes FROM events").fetchall()}
    finally:
        con.close()


def every_source_case(tmp_path):
    """A case with the events of every parser fixture (tests/pivot_key_fixtures.py's EvtxECmd, RECmd, PECmd, WxTCmd, and
    Autoruns, its MFT and Suricata records), the five hash sources (tests/hash_fixtures.py), a logon in UPN form, and a
    Zeek files import; a mark and a note on two of them."""
    evidence = tmp_path / "evidence"
    for host in ("DC01", "DESKTOP", "SENSOR", "FIXTURE"):
        (evidence / host).mkdir(parents=True)
    rel = hf.zeek_files(evidence)
    case = create_case(tmp_path / "case", "Fill", evidence, "cody")
    intake(case)
    out = tmp_path / "out"
    out.mkdir()
    groups = {name: ("FIXTURE", name, list(events.values())) for name, events in parsed(out).items()}
    groups["mft"] = ("FIXTURE", "mftecmd", mft_events(out))
    groups["eve"] = ("SENSOR", "suricata", suricata_events(out))
    groups.update(hf.hash_events(out / "hashes"))
    groups["upn"] = ("DC01", "evtxecmd", [logon(T0, 1, DC_LOG, user="Administrator@C137.LOCAL", domain="",
                                                code="4769")])
    for i, (host, tool, events) in enumerate(groups.values()):
        load(case.db_path, events, host=host, tool=tool, tool_version="t", run_id=f"q{i:02d}", replaces_sources=[],
             staging_dir=case.folder)
    assert run_import(case, rel, {"preset": "zeek"}, zones={}).status == "ok"
    return case


def test_the_fill(tmp_path, monkeypatch):
    """In a format 2 case of every parser fixture and an import, the step gives each row the
    account key and hash list a fresh load gives; the IDs, marks, and journal references stay as they were; `columns`
    counts the rows, and the seal says so. A rerun after a fault halfway fills only the rows still NULL. Same hash then
    finds the older rows."""
    case = every_source_case(tmp_path)
    fresh = columns_of(case)
    assert any(h for _, h in fresh.values()) and any("\\" in k for k, _ in fresh.values())
    amcache_uid = next(u for u, (_, h) in fresh.items() if h == hf.SHA1)
    con = connect(case.db_path, read_only=True)
    try:
        hosts = [h for (h,) in con.execute("SELECT DISTINCT origin_host FROM events ORDER BY 1").fetchall()]
        per_host = dict(con.execute("SELECT origin_host, count(*) FROM events GROUP BY 1").fetchall())
    finally:
        con.close()
    assert len(hosts) >= 3
    as_format(case.folder, 2)
    append_unchained(case.folder, "mark", targets=[amcache_uid], value="malicious")
    append_unchained(case.folder, "note", target=next(iter(fresh)), text="seen")
    older_rows(case)
    base = tmp_path / "base"
    shutil.copytree(case.folder, base)
    rest = the_rest(case)

    # Whole: every row filled as a load fills it
    whole = open_case(case.folder)
    state = state_of(whole)
    upgraded(whole)
    assert columns_of(whole) == fresh and the_rest(whole) == rest and state_of(whole) == state
    entries = [json.loads(line) for line in (whole.folder / "journal.jsonl").read_text(encoding="utf-8").splitlines()]
    upgrades = [e for e in entries if e["action"] == "case_upgrade"]
    assert [(e["from_format"], e["to_format"]) for e in upgrades] == [(2, 3), (3, 4)]   # the seal, then the 3 to 4 step
    seal = upgrades[0]
    total = sum(per_host.values())   # rows: two of the fixtures' rows share an ID
    assert seal["columns"] == {"account_key": total, "hashes": total}
    assert f"Filled the account key and the hashes for {total:,} loaded events, for Same account and Same hash." in (
        seal["text"])
    assert "loaded before the account lookup keep the key those names give, and a rebuild can change it." in seal["text"]
    app = App(whole)
    try:
        found = related(app.con, amcache_uid, "hash")
        assert len(found["events"]) == 5   # Amcache, Autoruns, Sysmon 1, Suricata, and the Zeek file
    finally:
        app.con.close()

    # Halfway: a fault after the first host's fill; the rerun fills the rest, and counts only those
    half = open_case(Path(shutil.copytree(base, tmp_path / "half")))
    real = rekey._filled

    def crash(host):
        raise Crash(f"stopped after {host}")

    monkeypatch.setattr(rekey, "_filled", crash)
    with pytest.raises(Crash):
        upgraded(half)
    monkeypatch.setattr(rekey, "_filled", real)
    con = connect(half.db_path, read_only=True)
    try:
        still = con.execute("SELECT count(*) FROM events WHERE account_key IS NULL").fetchone()[0]
    finally:
        con.close()
    assert still == total - per_host[hosts[0]]
    half = open_case(half.folder)
    assert case_format(half) == 2
    stages = []
    monkeypatch.setattr(rekey, "report_stage", lambda stage, done=0, total=0: stages.append((stage, done, total)))
    upgraded(half)
    entries = [json.loads(line) for line in (half.folder / "journal.jsonl").read_text(encoding="utf-8").splitlines()]
    upgrades = [e for e in entries if e["action"] == "case_upgrade"]
    assert [(e["from_format"], e["to_format"]) for e in upgrades] == [(2, 3), (3, 4)]   # the seal, then the 3 to 4 step
    seal = upgrades[0]
    assert seal["columns"] == {"account_key": still, "hashes": still}
    assert [s for s in stages if s[0] == FILLING] == [(FILLING, n, len(hosts) - 1) for n in range(1, len(hosts))]
    assert columns_of(half) == fresh and the_rest(half) == rest and state_of(half) == state
