"""End-to-end check with the real EvtxECmd and Hayabusa on the Szechuan Sauce collection.

Skipped when the lab collection or tools are absent. Takes about three minutes on an idle machine: the tools run on the
whole collection, EvtxECmd on DC01 twice.
"""

import os
import shutil
import subprocess
import sys
import tempfile
import warnings
from pathlib import Path

import pytest
from conftest import links_in

from glessner.analysis import build_identity, build_tables
from glessner.case import create_case, open_case
from glessner.events import connect
from glessner.intake import intake
from glessner.journal import Journal
from glessner.relations import outside_sources
from glessner.runner import plan_runs, rebuild, run
from glessner.tools import detect, load_registry

TRIAGE = Path("D:/DFIR-Lab/datasets/szechuan-sauce/triage")
TOOLS = Path("D:/DFIR-Lab/tools")
CASES = Path("D:/DFIR-Lab/test-cases")
ALL_TOOLS = ("evtxecmd", "hayabusa", "recmd", "mftecmd", "pecmd", "lecmd")
RDP_FROM_INTERNET_US = 1600485708891087    # 2020-09-19 03:21:48.891087 UTC
DC01_TO_DESKTOP_US = (1600486582980909, 1600486584432948)   # 03:36:22.980909 and 03:36:24.432948

pytestmark = [
    pytest.mark.lab,
    pytest.mark.skipif(not (TRIAGE.is_dir() and TOOLS.is_dir()), reason="lab collection or tools not present"),
]


def remove_case_folder(folder: Path) -> None:
    """Delete a test case's folder under CASES, and warn when part of it is left, as a file held open leaves it."""
    shutil.rmtree(folder, ignore_errors=True)
    if folder.exists():
        warnings.warn(f"{folder} was not deleted completely; delete it by hand", stacklevel=2)


@pytest.fixture(scope="module")
def loaded_case():
    # The case lives under D:/DFIR-Lab, which has a Defender exclusion. In %TEMP%, Defender locked
    # Hayabusa's output (it quotes encoded PowerShell from the event logs) while it was being read.
    CASES.mkdir(exist_ok=True)
    folder = Path(tempfile.mkdtemp(prefix="lab_runs_", dir=CASES))
    case = create_case(folder / "case", "Szechuan", TRIAGE, "test", TOOLS)
    intake(case)
    specs = load_registry()
    detected = detect(specs.values(), TOOLS)
    records = [run(case, plan) for tool in ALL_TOOLS for plan in plan_runs(case, detected[tool])]
    yield case, detected, records
    remove_case_folder(folder)


def query(case, sql, *params):
    con = connect(case.db_path, read_only=True)
    try:
        return con.execute(sql, list(params)).fetchall()
    finally:
        con.close()


def test_all_runs_succeed_with_evidence_intact(loaded_case):
    _, _, records = loaded_case
    assert [(r.tool, r.host, r.status, r.evidence_check) for r in records] == [
        ("evtxecmd", "DC01", "ok", "ok"), ("evtxecmd", "DESKTOP", "ok", "ok"),
        ("hayabusa", "DC01", "ok", "ok"), ("hayabusa", "DESKTOP", "ok", "ok"),
        ("recmd", "DC01", "ok", "ok"), ("recmd", "DESKTOP", "ok", "ok"),
        ("mftecmd", "DC01", "ok", "ok"), ("mftecmd", "DESKTOP", "ok", "ok"),
        ("pecmd", "DESKTOP", "ok", "ok"),   # DC01 is a server: prefetch is off, so there is nothing to run
        ("lecmd", "DC01", "ok", "ok"), ("lecmd", "DESKTOP", "ok", "ok"),
    ]
    assert all(r.loaded_rows > 0 for r in records)


def test_golden_row_counts_match_the_tools_csv(loaded_case):
    """Parsers that emit one event per record load exactly as many rows as the tool wrote."""
    import csv
    import sys

    csv.field_size_limit(sys.maxsize // 4)
    case, _, records = loaded_case
    one_to_one = {"evtxecmd": "evtxecmd.csv", "hayabusa": "hayabusa.csv", "recmd": "recmd.csv"}
    checked = 0
    for r in records:
        if r.tool not in one_to_one:
            continue
        out = case.runs_folder / r.run_id / "output" / one_to_one[r.tool]
        with out.open(encoding="utf-8-sig", errors="replace", newline="") as f:
            tool_rows = sum(1 for _ in csv.DictReader(f))
        assert r.loaded_rows == tool_rows, (r.run_id, r.loaded_rows, tool_rows)
        checked += 1
    assert checked == 6


def test_case_facts_are_in_the_events(loaded_case):
    case, _, _ = loaded_case
    rdp = query(case, "SELECT user_domain, user_name, logon_type, source_ip FROM events WHERE host = 'DC01' "
                      "AND tool = 'evtxecmd' AND event_code = '4624' AND ts_us = ?", RDP_FROM_INTERNET_US)
    assert rdp == [("C137", "Administrator", "10", "194.61.24.102")]
    lateral = query(case, "SELECT ts_us, logon_type FROM events WHERE host = 'DESKTOP' AND tool = 'evtxecmd' "
                          "AND event_code = '4624' AND source_ip = '10.42.85.10' AND ts_us IN (?, ?) ORDER BY ts_us",
                    *DC01_TO_DESKTOP_US)
    assert lateral == [(DC01_TO_DESKTOP_US[0], "3"), (DC01_TO_DESKTOP_US[1], "10")]


def test_every_hayabusa_hit_joins_its_evtx_event(loaded_case):
    case, _, _ = loaded_case
    ((hits, joined),) = query(case, """
        SELECT count(*), count(e.event_uid) FROM events h
        LEFT JOIN events e ON e.tool = 'evtxecmd' AND e.host = h.host AND e.log_channel = h.log_channel
          AND e.record_id = h.record_id AND e.source_file = h.source_file
        WHERE h.tool = 'hayabusa'""")
    assert hits > 0 and joined == hits


def test_checkpoint_links_on_the_real_case(loaded_case):
    """The internet RDP and the DC01-to-DESKTOP lateral movement resolve as links."""
    case, _, _ = loaded_case
    con = connect(case.db_path)
    try:
        state = Journal(case).state
        identity = build_identity(con, state)
        assert identity.hosts["DC01"].ips == ["10.42.85.10"] and "CITADEL-DC01" in identity.hosts["DC01"].names
        assert identity.hosts["DESKTOP"].ips == ["10.42.85.115"] and identity.hosts["DC01"].role == "Domain controllers"
        # On real hives, the role and the time zone come from each SYSTEM hive.
        assert identity.hosts["DC01"].role_reason == "The SYSTEM hive records its product type as LanmanNT"
        assert identity.hosts["DESKTOP"].role_reason == "The SYSTEM hive records its product type as WinNT"
        for host in ("DC01", "DESKTOP"):
            zone = identity.hosts[host].timezone
            assert (zone["windows"], zone["iana"]) == ("Pacific Standard Time", "America/Los_Angeles")
        build_tables(con, state, identity)
        links = links_in(con, RDP_FROM_INTERNET_US - 10**6, DC01_TO_DESKTOP_US[1] + 10**6)
        got = {(link.ts, link.source, link.target, link.kind) for link in links}
        assert (RDP_FROM_INTERNET_US, "194.61.24.102", "DC01", "4624 type 10") in got
        assert (DC01_TO_DESKTOP_US[0], "DC01", "DESKTOP", "4624 type 3") in got
        assert (DC01_TO_DESKTOP_US[1], "DC01", "DESKTOP", "4624 type 10") in got
        assert outside_sources(con) == ["194.61.24.102"]
    finally:
        con.close()


def test_one_file_links_across_hosts_and_artifacts(loaded_case):
    """coreupdater.exe appears in both MFTs and DESKTOP's prefetch; LNK targets join their MFT records. Each host's
    service install (System 7045) joins them too, by the service's binary."""
    case, _, _ = loaded_case
    rows = query(case, "SELECT host, artifact, min(ts_us) FROM events WHERE file_key = ? AND artifact <> 'registry' "
                       "GROUP BY ALL ORDER BY 3", "\\windows\\system32\\coreupdater.exe")
    assert [(h, a) for h, a, _ in rows] == [("DC01", "mft"), ("DC01", "evtx"), ("DESKTOP", "mft"),
                                            ("DESKTOP", "prefetch"), ("DESKTOP", "evtx")]
    assert rows[3][2] == 1600486849410320   # executed 2020-09-19 03:40:49.410320 UTC
    # RECmd's rows name the file in their data: the Services plugin's, and UserAssist's {System}\ entry
    registry = query(case, "SELECT host, count(*) FROM events WHERE artifact = 'registry' AND file_key = ? GROUP BY ALL "
                           "ORDER BY 1", "\\windows\\system32\\coreupdater.exe")
    assert [h for h, _ in registry] == ["DC01", "DESKTOP"] and all(n >= 1 for _, n in registry)
    lnk_and_mft = query(case, "SELECT artifact FROM events WHERE host = 'DC01' AND file_key = ? GROUP BY ALL ORDER BY 1",
                        "\\fileshare\\secret\\beth_secret.txt")
    assert lnk_and_mft == [("lnk",), ("mft",)]


def test_suggestions_and_findings_summary_on_the_real_case(loaded_case):
    """The built-in rule and Hayabusa suggest marks; the findings summary re-hashes all evidence."""
    from glessner.export import write_report
    from glessner.server import App, api_mark, api_rules

    case, _, _ = loaded_case
    app = App(case)
    try:
        rules = {r["id"]: r for r in api_rules(app, {})["rules"]}
        assert rules["machine-accounts-authorized"]["matched"] == 96   # DESKTOP-SDN1RPT$ network logons to DC01
        assert rules["hayabusa"]["matched"] > 0
        rdp = app.con.execute("SELECT event_uid FROM events WHERE tool = 'evtxecmd' AND host = 'DC01' AND ts_us = ? "
                              "AND event_code = '4624'", [RDP_FROM_INTERNET_US]).fetchone()[0]
        api_mark(app, {"uids": [rdp], "value": "malicious", "note": "RDP from the internet"})
        path, count = write_report(app.con, case, app.identity, app.manifest, app.journal.state)
        text = path.read_text(encoding="utf-8")
        assert count == 1 and "Every evidence file (474) was re-hashed" in text and "all match" in text
        assert ("| DC01 | Domain controllers (guessed) | Windows Server 2012 R2 Standard Evaluation, build 9600 | "
                "CITADEL-DC01, ") in text
    finally:
        app.con.close()


def test_ids_survive_rerun_and_rebuild(loaded_case):
    case, detected, _ = loaded_case
    before = query(case, "SELECT event_uid, ts_us FROM events ORDER BY event_uid")
    (plan,) = plan_runs(case, detected["evtxecmd"], ["DC01"])
    again = run(case, plan)
    assert again.replaced_rows == again.loaded_rows
    assert query(case, "SELECT event_uid, ts_us FROM events ORDER BY event_uid") == before
    rebuild(case)
    assert query(case, "SELECT event_uid, ts_us FROM events ORDER BY event_uid") == before


def test_a_second_build_gives_the_same_events(loaded_case):
    """A second case built from the collection holds the same events as this one for the real Hayabusa's lane on DC01:
    the same IDs and the same value in every other column but run_id, since the two cases' runs have different IDs. The
    second case is built by the command line in a Python process of its own with another seed for string hashing, so
    neither the seed nor a cache the first build filled can make the two agree. Only Hayabusa's lane is compared, because
    its run on DC01 takes a fraction of EvtxECmd's. The raw output files are not compared."""
    case, _, _ = loaded_case
    folder = Path(tempfile.mkdtemp(prefix="lab_runs_again_", dir=CASES))
    try:
        again = folder / "case"
        for command in (["new-case", str(again), "--evidence", str(TRIAGE), "--name", "Szechuan again", "--analyst", "test",
                         "--tools", str(TOOLS)],
                        ["intake", str(again)],
                        ["run", str(again), "--tool", "hayabusa", "--host", "DC01"]):
            done = subprocess.run([sys.executable, "-m", "glessner", *command], env={**os.environ, "PYTHONHASHSEED": "2"},
                                  capture_output=True, text=True, timeout=900, check=False)
            assert done.returncode == 0, f"glessner {command[0]} failed:\n{done.stdout}\n{done.stderr}"
        lane = "host = 'DC01' AND tool = 'hayabusa'"
        con = connect(case.db_path, read_only=True)
        try:
            con.execute(f"ATTACH '{open_case(again).db_path}' AS again (READ_ONLY)")
            counts = [con.execute(f"SELECT count(*) FROM {db}.events WHERE {lane}").fetchone()[0] for db in ("main", "again")]
            assert counts[0] == counts[1] > 0
            for here, there in (("main", "again"), ("again", "main")):
                (differ,) = con.execute(f"SELECT count(*) FROM (SELECT * EXCLUDE (run_id) FROM {here}.events WHERE {lane} "
                                        f"EXCEPT ALL SELECT * EXCLUDE (run_id) FROM {there}.events WHERE {lane})").fetchone()
                assert differ == 0, f"{differ} events in the {here} case have no equal in the {there} case"
        finally:
            con.close()
    finally:
        remove_case_folder(folder)
