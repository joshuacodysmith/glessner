"""Autoruns CSVs found in the evidence load as an inventory of autostart entries, with the host's zone for Autoruns'
local times."""

import calendar
import csv
import io
import json
import shutil
import tempfile
import time
from pathlib import Path

import pytest
from conftest import SEC, T0, registry
from test_tool_outputs import write_rows

from glessner.case import create_case
from glessner.events import connect, load
from glessner.identify import identify_bytes, kind_of_file
from glessner.intake import intake
from glessner.parsers.autoruns import BUILT, NO_TIME, WRITTEN
from glessner.parsers.common import file_key
from glessner.runner import load_found_output, read_runs, rebuild
from glessner.toolbox import everything_ready, found_outputs, start_all_job
from glessner.tools import load_registry

# autorunsc -a * -c -h -s's columns, as its CSVs have them
COLUMNS = ["Time", "Entry Location", "Entry", "Enabled", "Category", "Profile", "Description", "Signer", "Company",
           "Image Path", "Version", "Launch String", "MD5", "SHA-1", "PESHA-1", "PESHA-256", "SHA-256", "IMP"]
RUN_KEY = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
SERVICES = "HKLM\\System\\CurrentControlSet\\Services"
HASHES = ["a" * 32, "b" * 40, "c" * 40, "d" * 64, "e" * 64, "f" * 32]
AUTORUNS_CSV = "DC01/autoruns/autorunsc-dc01.csv"


def location(when, where, category):
    """A location's own row: no entry, and one column short, as autorunsc writes it."""
    return [when, where, "", "", category, "System-wide"] + [""] * 11


def entry(when, where, name, category, image, launch, *, enabled="enabled", profile="System-wide", signer="",
          description="", company="", hashes=HASHES):
    return [when, where, name, enabled, category, profile, description, signer, company, image, "", launch, *hashes]


ROWS = [
    location("9/18/2020 8:30 PM", RUN_KEY, "Logon"),
    entry("8/22/2013 3:59 AM", RUN_KEY, "coreupdate", "Logon",
          "c:\\windows\\system32\\windowspowershell\\v1.0\\powershell.exe",
          "powershell.exe -WindowStyle Hidden -File C:\\Scripts\\update.ps1", signer="(Verified) Microsoft Windows",
          description="Windows PowerShell", company="Microsoft Corporation"),
    location("9/18/2020 10:31 PM", SERVICES, "Services"),
    entry("4/14/2010 3:06 PM", SERVICES, "coreupdater", "Services", "c:\\windows\\system32\\coreupdater.exe",
          "C:\\Windows\\System32\\coreupdater.exe"),
    entry("9/19/2020 2:15 AM", "Task Scheduler", "\\Backup", "Tasks", "c:\\scripts\\backup.vbs",
          "wscript.exe c:\\scripts\\backup.vbs", enabled="disabled"),
    entry("1/2/2020 1:00 PM", RUN_KEY.replace("HKLM", "HKCU"), "OneDrive", "Logon",
          "c:\\users\\ricksanchez\\appdata\\local\\microsoft\\onedrive\\onedrive.exe",
          "\"C:\\Users\\ricksanchez\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe\" /background",
          profile="C137\\ricksanchez", signer="(Verified) Microsoft Corporation"),
    # No time: Autoruns gives none when it can't read the image.
    entry("", "HKLM\\SOFTWARE\\Microsoft\\Active Setup\\Installed Components", "Microsoft Windows", "Logon",
          "File not found: C:\\Program Files\\Windows Mail\\WinMail.exe",
          "\"C:\\Program Files\\Windows Mail\\WinMail.exe\" OCInstallUserConfigOE", hashes=[""] * 6),
]


def autoruns_bytes(rows=ROWS, columns=COLUMNS):
    """UTF-16 with a byte order mark and CRLF lines, as autorunsc writes; the header unquoted, the rows quoted."""
    out = io.StringIO()
    out.write(",".join(columns) + "\r\n")
    csv.writer(out, quoting=csv.QUOTE_ALL, lineterminator="\r\n").writerows(rows)
    return out.getvalue().encode("utf-16")


def pacific(case, host="DC01", active=None):
    """The host's SYSTEM hive records Pacific time, as the Szechuan hosts' do; with active, its ActiveTimeBias too."""
    tz = "ROOT\\ControlSet001\\Control\\TimeZoneInformation"
    values = [("TimeZoneKeyName", "Pacific Standard Time"), ("Bias", "480"), ("DaylightBias", "-60")]
    values += [("ActiveTimeBias", active)] if active is not None else []
    load(case.db_path, [registry(f"{host}/Windows/System32/config/SYSTEM", tz, name, value) for name, value in values],
         host=host, tool="recmd", tool_version="t", run_id=f"tz-{host}", replaces_sources=[], staging_dir=case.folder)


def autoruns_case(tmp_path, data=None):
    ev = tmp_path / "evidence"
    (ev / "DC01" / "autoruns").mkdir(parents=True)
    (ev / AUTORUNS_CSV).write_bytes(data or autoruns_bytes())
    case = create_case(tmp_path / "case", "Autoruns", ev, "cody")
    intake(case)
    return case


def events(case):
    if not case.db_path.exists():   # nothing loaded yet
        return []
    con = connect(case.db_path, read_only=True)
    try:
        cur = con.execute("SELECT * FROM events WHERE tool = 'autoruns' ORDER BY CAST(source_record AS INTEGER)")
        names = [d[0] for d in cur.description]
        return [dict(zip(names, row)) for row in cur.fetchall()]
    finally:
        con.close()


def test_autoruns_csv_is_recognized_in_utf16_by_its_header(tmp_path):
    data = autoruns_bytes()
    ident = identify_bytes("autorunsc-dc01.csv", data[:65536])
    assert (ident.artifact, ident.detail) == ("tool_output", "autoruns")
    (tmp_path / "a.csv").write_bytes(data)
    assert kind_of_file(tmp_path / "a.csv").kind == "autoruns"   # the loader's own reading of the header
    (tmp_path / "u8.csv").write_text(",".join(COLUMNS) + "\n", encoding="utf-8-sig")   # a copy saved as UTF-8
    assert kind_of_file(tmp_path / "u8.csv").kind == "autoruns"
    assert identify_bytes("x.csv", "Time,Entry,Image Path\r\n".encode("utf-16")).artifact == "csv"


def test_entries_load_as_an_inventory_in_the_hosts_zone(tmp_path):
    case = autoruns_case(tmp_path)
    pacific(case)
    specs = load_registry()
    [group] = [g for g in found_outputs(case, specs, {}) if g["key"] == "autoruns_csv"]
    assert (group["host"], group["status"], group["tool_name"], group["label"]) == ("DC01", "ready", "Autoruns",
                                                                                     "Autoruns CSV")
    record = load_found_output(case, "autoruns", "autoruns_csv", "DC01", [AUTORUNS_CSV])
    assert (record.status, record.loaded_rows, record.rows_without_time, record.evidence_check) == ("ok", 5, 1, "ok")
    assert record.zone["label"] == "DC01's zone, Pacific Standard Time (America/Los_Angeles)"
    # Without ActiveTimeBias, the zone's offset when the newest location row was written: daylight time, -07:00.
    assert record.notes == ["Local times read in UTC-07:00, the offset of DC01's zone, Pacific Standard Time "
                            "(America/Los_Angeles), at the newest location row's time, 9/18/2020 10:31 PM.",
                            "1 event has no time: off the timeline, and out of search and exports."]
    run_key, service, script, onedrive, missing = events(case)   # one per entry; the location rows aren't events
    us = lambda iso: calendar.timegm(time.strptime(iso, "%Y-%m-%d %H:%M")) * 1_000_000   # a UTC time
    # The image's link time, read in Pacific daylight time: 15:06 PDT is 22:06 UTC.
    assert (service["ts_us"], service["ts_desc"]) == (us("2010-04-14 22:06"), BUILT)
    assert (service["file_path"], service["file_key"]) == ("c:\\windows\\system32\\coreupdater.exe",
                                                           file_key(".\\Windows\\System32\\coreupdater.exe"))   # MFT's
    assert (service["registry_path"], service["log_channel"], service["event_provider"], service["artifact"]) == (
        SERVICES, "Services", "Autoruns", "autoruns")
    # The launch string is the image path again, so "Runs:" is left out.
    assert service["message"] == "Services: coreupdater | c:\\windows\\system32\\coreupdater.exe | no signer"
    assert service["process_command_line"] == "C:\\Windows\\System32\\coreupdater.exe"
    extra = json.loads(service["extra"])
    assert extra["SHA-256"] == "e" * 64 and extra["MD5"] == "a" * 32 and extra["Time"] == "4/14/2010 3:06 PM"
    assert extra["LocationLastWritten"] == "2020-09-19 05:31 UTC (9/18/2020 10:31 PM as written)"
    assert run_key["ts_us"] == us("2013-08-22 10:59")
    assert run_key["process_command_line"].startswith("powershell.exe -WindowStyle Hidden")
    assert run_key["message"].startswith("Logon: coreupdate | c:\\windows\\system32\\windowspowershell\\v1.0\\"
                                         "powershell.exe | (Verified) Microsoft Windows | Runs: powershell.exe")
    assert json.loads(run_key["extra"])["LocationLastWritten"].startswith("2020-09-19 03:30 UTC")
    # A script's time is its last write; Task Scheduler is no registry key; a disabled entry says so.
    assert (script["ts_desc"], script["registry_path"], script["ts_us"]) == (WRITTEN, "", us("2020-09-19 09:15"))
    assert script["message"].startswith("Tasks: \\Backup | c:\\scripts\\backup.vbs | disabled | no signer")
    # January too is read at the one offset Autoruns wrote every time at, not Pacific standard time.
    assert (onedrive["user_domain"], onedrive["user_name"], onedrive["ts_us"]) == ("C137", "ricksanchez",
                                                                                  us("2020-01-02 20:00"))
    assert (missing["ts_us"], missing["ts_desc"], missing["file_path"]) == (
        None, NO_TIME, "C:\\Program Files\\Windows Mail\\WinMail.exe")
    assert missing["message"].startswith("Logon: Microsoft Windows | File not found: C:\\Program Files")
    loaded = next(g for g in found_outputs(case, specs, {}) if g["key"] == "autoruns_csv")
    assert (loaded["status"], loaded["loaded"]["rows"], loaded["loaded"]["without_time"]) == ("loaded", 5, 1)


def test_local_times_are_read_at_the_offset_autoruns_ran_at(tmp_path):
    """Autoruns writes every time at the one offset in force when it ran, so a December date on a host that ran it in
    September is an hour off Pacific standard time (as measured on the Szechuan DESKTOP). The SYSTEM hive's
    ActiveTimeBias, the offset when the hive was last written, comes first; here a collection made in winter."""
    case = autoruns_case(tmp_path)
    pacific(case, active="480")
    record = load_found_output(case, "autoruns", "autoruns_csv", "DC01", [AUTORUNS_CSV])
    assert record.status == "ok", record.reason
    assert record.zone == {"kind": "offset", "minutes": -480, "host": "DC01",
                           "label": "UTC-08:00, DC01's offset when its SYSTEM hive was last written (ActiveTimeBias)"}
    assert record.notes[0] == ("Local times read in UTC-08:00, DC01's offset when its SYSTEM hive was last written "
                               "(ActiveTimeBias).")
    run_key, service, script, onedrive, _ = events(case)
    us = lambda iso: calendar.timegm(time.strptime(iso, "%Y-%m-%d %H:%M")) * 1_000_000
    # April, August, and September dates take -08:00 as January's does.
    assert [e["ts_us"] for e in (service, run_key, script, onedrive)] == [
        us("2010-04-14 23:06"), us("2013-08-22 11:59"), us("2020-09-19 10:15"), us("2020-01-02 21:00")]
    assert json.loads(run_key["extra"])["LocationLastWritten"].startswith("2020-09-19 04:30 UTC")

    # Without ActiveTimeBias and without a location row to take the zone's offset at, the load says what to do.
    case = autoruns_case(tmp_path / "no_rows", autoruns_bytes([r for r in ROWS if r[2]]))
    pacific(case)
    record = load_found_output(case, "autoruns", "autoruns_csv", "DC01", [AUTORUNS_CSV])
    assert record.status == "failed" and "no ActiveTimeBias" in record.reason and "-07:00" in record.reason
    assert events(case) == []


def test_an_autoruns_csv_stays_importable_and_an_import_of_it_counts_as_loaded(tmp_path):
    """The Import page is the way to load an Autoruns CSV when the host's zone isn't known, as the load's reason says;
    a CSV imported there counts as loaded on the Tools page, so Run and load everything ready doesn't load it twice."""
    from glessner.imports import importable, preview, run_import

    case = autoruns_case(tmp_path)
    [listed] = importable(case)
    assert (listed["path"], listed["artifact"], listed["detail"], listed["imported"]) == (
        AUTORUNS_CSV, "csv", "Autoruns CSV", None)
    record = load_found_output(case, "autoruns", "autoruns_csv", "DC01", [AUTORUNS_CSV])
    assert record.status == "failed" and "Import page" in record.reason
    mapping = preview(case, AUTORUNS_CSV)["mapping"]
    mapping = {**mapping, "time": {**mapping["time"], "columns": ["Time"], "format": "mdy", "zone": "-07:00"}}
    imported = run_import(case, AUTORUNS_CSV, mapping, zones={})
    assert (imported.status, imported.loaded_rows) == ("ok", 7), imported.reason   # entries and location rows
    pacific(case)   # the zone known later doesn't make it ready again
    specs = load_registry()
    [group] = [g for g in found_outputs(case, specs, {}) if g["key"] == "autoruns_csv"]
    assert (group["status"], group["loaded"]["rows"]) == ("loaded", 7)
    assert everything_ready(case, specs, {})[1] == []


def test_an_autoruns_csv_loaded_from_the_tools_page_is_listed_as_loaded_and_the_import_refuses_it(tmp_path):
    """Once the Tools page has loaded an Autoruns CSV, the Import page lists it as loaded rather than as not imported,
    and the import refuses it, since it would load the entries a second time. Both pages count the same files: the
    Tools page counts the Autoruns CSVs the Import page lists, not only text logs."""
    from glessner.imports import MappingError, importable, preview, run_import
    from glessner.toolbox import overview

    case = autoruns_case(tmp_path)
    pacific(case)
    specs = load_registry()
    assert overview(case, specs, {})["to_import"] == ["1 Autoruns CSV"]
    assert load_found_output(case, "autoruns", "autoruns_csv", "DC01", [AUTORUNS_CSV]).status == "ok"
    [listed] = importable(case)
    assert (listed["path"], listed["imported"], listed["loaded"]["rows"]) == (AUTORUNS_CSV, None, 5)
    assert overview(case, specs, {})["to_import"] == []
    # A mapping the import would take, as the test above imports with: without the refusal, its 7 rows load beside the 5
    mapping = preview(case, AUTORUNS_CSV)["mapping"]
    mapping = {**mapping, "time": {**mapping["time"], "columns": ["Time"], "format": "mdy", "zone": "-07:00"}}
    with pytest.raises(MappingError, match="loaded already, as found output from the Tools page"):
        run_import(case, AUTORUNS_CSV, mapping, zones={})
    assert len(events(case)) == 5


def test_times_autoruns_wrote_in_a_form_the_app_doesnt_read_fail_the_load(tmp_path):
    """A clock written with a dot, as some locales write it, would load every entry without a time, under a link
    time's description, and the load would say only that they had none. The load fails instead, naming one."""
    rows = [location("18.9.2020 20.30", RUN_KEY, "Logon"),
            entry("22.8.2013 3.59", RUN_KEY, "coreupdate", "Logon", "c:\\a.exe", "a.exe"),
            entry("14.4.2010 15.06", SERVICES, "coreupdater", "Services", "c:\\b.exe", "b.exe")]
    case = autoruns_case(tmp_path, autoruns_bytes(rows))
    pacific(case)
    record = load_found_output(case, "autoruns", "autoruns_csv", "DC01", [AUTORUNS_CSV])
    assert record.status == "failed" and "time '14.4.2010 15.06' isn't a date and time" in record.reason
    assert events(case) == []
    # One value the app can't read among those it can fails the load too.
    rows = [entry("8/22/2013 3:59 AM", RUN_KEY, "a", "Logon", "c:\\a.exe", "a.exe"),
            entry("8/22/2013 3h59", RUN_KEY, "b", "Logon", "c:\\b.exe", "b.exe")]
    case = autoruns_case(tmp_path / "one", autoruns_bytes(rows))
    pacific(case, active="420")
    record = load_found_output(case, "autoruns", "autoruns_csv", "DC01", [AUTORUNS_CSV])
    assert record.status == "failed" and "'8/22/2013 3h59'" in record.reason


def test_rebuild_reads_the_recorded_zone(tmp_path):
    """A rebuild reads the CSV again in the zone the load recorded, so the times and IDs stay, even with the host's
    zone gone: here the zone's rows were loaded outside any run, so the rebuild drops them."""
    case = autoruns_case(tmp_path)
    pacific(case)
    record = load_found_output(case, "autoruns", "autoruns_csv", "DC01", [AUTORUNS_CSV])
    before = [(e["event_uid"], e["ts_us"]) for e in events(case)]
    assert [r.run_id for r in rebuild(case)] == [record.run_id]
    assert [(e["event_uid"], e["ts_us"]) for e in events(case)] == before
    assert json.loads((case.runs_folder / record.run_id / "run.json").read_text())["zone"]["name"] == (
        "America/Los_Angeles")
    [again] = [r for r in read_runs(case) if r.run_id == record.run_id]
    assert again.notes == record.notes   # replaced, not repeated


def test_without_the_hosts_zone_the_load_fails_with_the_reason(tmp_path):
    case = autoruns_case(tmp_path)
    record = load_found_output(case, "autoruns", "autoruns_csv", "DC01", [AUTORUNS_CSV])
    assert record.status == "failed" and "zone isn't known" in record.reason and record.zone is None
    assert events(case) == []
    [group] = [g for g in found_outputs(case, load_registry(), {}) if g["key"] == "autoruns_csv"]
    assert group["status"] == "ready"   # to load again once the zone is in


def test_utc_times_from_t_need_no_zone(tmp_path):
    """autorunsc -t writes normalized UTC, YYYYMMDD-hhmmss, which needs no zone."""
    rows = [location("20200919-033000", RUN_KEY, "Logon"),
            entry("20130822-105900", RUN_KEY, "coreupdate", "Logon", "c:\\windows\\system32\\cmd.exe", "cmd.exe"),
            # Before 1970, which Windows' datetime.fromtimestamp refuses: a Windows 10 link time can be anywhere
            location("19601001-120000", SERVICES, "Services"),
            entry("19370101-000000", SERVICES, "old", "Services", "c:\\windows\\old.sys", "")]
    case = autoruns_case(tmp_path, autoruns_bytes(rows))
    record = load_found_output(case, "autoruns", "autoruns_csv", "DC01", [AUTORUNS_CSV])
    assert (record.status, record.zone, record.notes) == ("ok", None, [])
    ev, old = events(case)
    assert ev["ts_us"] == 1377169140 * 1_000_000   # 2013-08-22 10:59:00 UTC
    assert json.loads(ev["extra"])["LocationLastWritten"] == "2020-09-19 03:30 UTC (20200919-033000 as written)"
    assert old["ts_us"] == -1041379200 * 1_000_000   # 1937-01-01 00:00:00 UTC
    assert json.loads(old["extra"])["LocationLastWritten"] == "1960-10-01 12:00 UTC (19601001-120000 as written)"
    from test_analysis_relations import open_case

    from glessner.queries import fit_range

    con, _, _ = open_case(case)   # a case of nothing but link times: Fit case takes its window from them
    try:
        assert {k: fit_range(con)[k] for k in ("start", "end", "before")} == {"start": old["ts_us"],
                                                                              "end": ev["ts_us"], "before": 0}
    finally:
        con.close()
    pacific(case)   # with the host's zone known, nothing says local times were read, since none were
    again = load_found_output(case, "autoruns", "autoruns_csv", "DC01", [AUTORUNS_CSV])
    assert (again.status, again.notes) == ("ok", [])


def test_day_first_dates_and_an_unsettled_order(tmp_path):
    rows = [entry("22/08/2013 03:59", RUN_KEY, "a", "Logon", "c:\\a.exe", "a.exe"),
            entry("01/02/2020 13:00", RUN_KEY, "b", "Logon", "c:\\b.exe", "b.exe")]
    case = autoruns_case(tmp_path, autoruns_bytes(rows))
    pacific(case, active="420")
    assert load_found_output(case, "autoruns", "autoruns_csv", "DC01", [AUTORUNS_CSV]).status == "ok"
    assert [e["ts_us"] for e in events(case)] == [1377169140 * 1_000_000, 1580587200 * 1_000_000]   # 1 February
    case = autoruns_case(tmp_path / "again", autoruns_bytes(rows[1:]))   # 01/02 alone could be either
    pacific(case, active="420")
    record = load_found_output(case, "autoruns", "autoruns_csv", "DC01", [AUTORUNS_CSV])
    assert record.status == "failed" and "month/day or day/month" in record.reason


def test_link_times_do_not_set_fit_cases_window(tmp_path):
    """In the Szechuan case, DESKTOP's link times, 1902 to 2037, would stretch Fit case from 2013 to 2020 into 1967 to
    2025. They don't set the window, and are counted as strays outside it; a script's last write still sets it."""
    from test_analysis_relations import open_case

    from glessner.queries import fit_range

    case = autoruns_case(tmp_path)
    pacific(case)
    load_found_output(case, "autoruns", "autoruns_csv", "DC01", [AUTORUNS_CSV])
    con, _, _ = open_case(case)
    try:
        fit = fit_range(con)
    finally:
        con.close()
    utc = lambda iso: calendar.timegm(time.strptime(iso, "%Y-%m-%d %H:%M")) * 1_000_000
    # The zone's registry rows, at T0 - 1 h, and the script's last write set the window.
    assert (fit["start"], fit["end"]) == (T0 - 3600 * SEC, utc("2020-09-19 09:15"))
    assert (fit["before"], fit["after"], fit["first"]) == (3, 0, utc("2010-04-14 22:06"))   # 2010, 2013, and 2020-01


def test_run_and_load_everything_ready_loads_recmd_output_before_autoruns(tmp_path):
    """Found RECmd output gives the host's zone, so it loads first, though autoruns_csv sorts ahead of recmd_csv."""
    ev = tmp_path / "evidence"
    write_rows(ev / "DC01" / "Registry" / "20240514_RECmd_Batch_Output.csv",
               ["HivePath", "HiveType", "Description", "Category", "KeyPath", "ValueName", "ValueType", "ValueData",
                "LastWriteTimestamp"],
               [{"HivePath": "D:\\KAPE\\tout\\C\\Windows\\System32\\config\\SYSTEM", "HiveType": "System",
                 "Description": "Time zone", "KeyPath": "ControlSet001\\Control\\TimeZoneInformation",
                 "ValueName": name, "ValueData": value, "LastWriteTimestamp": "2020-09-17 10:00:00"}
                for name, value in (("TimeZoneKeyName", "Pacific Standard Time"), ("Bias", "480"))])
    (ev / "DC01" / "autoruns").mkdir(parents=True)
    (ev / AUTORUNS_CSV).write_bytes(autoruns_bytes())
    case = create_case(tmp_path / "case", "KAPE and Autoruns", ev, "cody")
    intake(case)
    specs = load_registry()
    _, groups = everything_ready(case, specs, {})
    assert [g["key"] for g in groups] == ["recmd_csv", "autoruns_csv"]
    job = start_all_job(case, specs, {}, lambda j: None)
    while not job.finished:
        time.sleep(0.05)
    assert not job.error and [r["status"] for r in job.results] == ["ok", "ok"], job.results
    [record] = [r for r in read_runs(case) if r.tool == "autoruns"]
    assert record.zone["host"] == "DC01" and record.loaded_rows == 5


PILOT = Path("D:/DFIR-Lab/datasets/szechuan-sauce/pilot")
CASES = Path("D:/DFIR-Lab/test-cases")


@pytest.mark.lab
@pytest.mark.skipif(not PILOT.is_dir(), reason="the Szechuan pilot's Autoruns CSVs are not present")
def test_lab_szechuan_autoruns_load_with_both_persistence_entries():
    """The Szechuan case's two Autoruns CSVs, copied into a case under D:/DFIR-Lab: every entry loads, the entries
    without a time are counted, and both hosts' coreupdater service and coreupdate Run entry, the persistence the
    answers name, are events with their image as the file path. Each host's SYSTEM hive records Pacific time and an
    ActiveTimeBias of 420, daylight time, when the hives were taken, as Autoruns ran."""
    CASES.mkdir(exist_ok=True)
    folder = Path(tempfile.mkdtemp(prefix="autoruns_", dir=CASES))
    try:
        for host in ("DC01", "DESKTOP"):
            (folder / "evidence" / host).mkdir(parents=True)
            for src in (PILOT / host / "autoruns").glob("*.csv"):
                shutil.copy2(src, folder / "evidence" / host / src.name)
        case = create_case(folder / "case", "Autoruns", folder / "evidence", "test")
        intake(case)
        for host in ("DC01", "DESKTOP"):
            pacific(case, host, active="420")
        records = {g["host"]: load_found_output(case, "autoruns", "autoruns_csv", g["host"], g["paths"])
                   for g in found_outputs(case, load_registry(), {}) if g["key"] == "autoruns_csv"}
        assert {h: (r.status, r.loaded_rows, r.rows_without_time) for h, r in records.items()} == {
            "DC01": ("ok", 849, 6), "DESKTOP": ("ok", 1283, 8)}
        con = connect(case.db_path, read_only=True)
        found = con.execute(
            "SELECT host, log_channel, json_extract_string(extra, '$.Entry'), ts_desc, file_key FROM events "
            "WHERE tool = 'autoruns' AND json_extract_string(extra, '$.Entry') IN ('coreupdater', 'coreupdate') "
            "ORDER BY host, log_channel").fetchall()
        # December on DESKTOP, read at -07:00, falls in the hour of the MFT's and RECmd's records of the same writes
        # (09:00 UTC in the Szechuan case): gathernetworkinfo.vbs at 09:09, whose $SI modified time is 09:09:48, and the
        # locations written that day. Read with Pacific standard time, they were an hour late.
        script = con.execute("SELECT strftime(make_timestamp(ts_us), '%Y-%m-%d %H:%M') FROM events WHERE "
                             "tool = 'autoruns' AND host = 'DESKTOP' AND file_key LIKE '%gathernetworkinfo.vbs'"
                             ).fetchall()
        december = con.execute(
            "SELECT count(*), count(*) FILTER (WHERE json_extract_string(extra, '$.LocationLastWritten') LIKE "
            "'2019-12-07 09:%') FROM events WHERE tool = 'autoruns' AND host = 'DESKTOP' AND "
            "json_extract_string(extra, '$.LocationLastWritten') LIKE '2019-12-07%'").fetchone()
        con.close()
        assert script == [("2019-12-07 09:09",)]
        assert december[0] > 0 and december[1] == december[0], december
        powershell = "\\windows\\system32\\windowspowershell\\v1.0\\powershell.exe"
        assert found == [(h, *row) for h in ("DC01", "DESKTOP") for row in (
            ("Logon", "coreupdate", BUILT, powershell),
            ("Services", "coreupdater", BUILT, "\\windows\\system32\\coreupdater.exe"))]
    finally:
        shutil.rmtree(folder, ignore_errors=True)
