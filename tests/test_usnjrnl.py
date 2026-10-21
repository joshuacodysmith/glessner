"""The USN journal ($J) through MFTECmd: recognition by name, its volume's $MFT, the one in the nearest folder above the
$J, passed with -m, or a note that the run had none, and one event per change record."""

import csv
import sys
from pathlib import Path

from glessner.case import create_case
from glessner.identify import identify_bytes
from glessner.intake import intake
from glessner.parsers import PARSERS, ParseContext
from glessner.runner import build_argv, plan_runs, run
from glessner.tool_outputs import kind_of
from glessner.tools import DetectedTool, ToolSpec, load_registry

COLUMNS = ["Name", "Extension", "EntryNumber", "SequenceNumber", "ParentEntryNumber", "ParentSequenceNumber",
           "ParentPath", "UpdateSequenceNumber", "UpdateTimestamp", "UpdateReasons", "FileAttributes", "OffsetToData",
           "SourceFile"]


def test_journal_recognized_by_name_and_its_csv_by_header():
    assert identify_bytes("$J", b"\x00" * 4096).artifact == "usnjrnl"            # sparse zeros, no signature
    assert identify_bytes("$UsnJrnl%3A$J", b"\x00" * 64).artifact == "usnjrnl"   # as KAPE names it
    assert identify_bytes("J", b"\x00" * 64).artifact != "usnjrnl"
    assert kind_of("20261014_MFTECmd_$J_Output.csv", ",".join(COLUMNS)).parser == "mftecmd_j_csv"


def test_change_records_become_events_with_their_telling_reason(tmp_path):
    rows = [
        {"Name": "evil.exe", "ParentPath": ".\\Users\\bob\\Downloads", "UpdateSequenceNumber": "1000",
         "UpdateTimestamp": "2024-05-14 12:00:00.1234567", "UpdateReasons": "DataExtend|FileCreate|Close",
         "FileAttributes": "Archive", "EntryNumber": "42", "SourceFile": "D:\\Evidence\\case\\WS01\\$J"},
        {"Name": "evil.exe:Zone.Identifier", "ParentPath": ".\\Users\\bob\\Downloads", "UpdateSequenceNumber": "1100",
         "UpdateTimestamp": "2024-05-14 12:00:01", "UpdateReasons": "NamedDataExtend", "FileAttributes": "Archive",
         "SourceFile": "D:\\Evidence\\case\\WS01\\$J"},
        {"Name": "Temp", "ParentPath": ".", "UpdateSequenceNumber": "1200", "UpdateTimestamp": "2024-05-14 12:05:00",
         "UpdateReasons": "FileDelete|Close", "FileAttributes": "Directory", "SourceFile": "D:\\Evidence\\case\\WS01\\$J"},
    ]
    with (tmp_path / "mftecmd_j.csv").open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS)
        w.writeheader()
        w.writerows(rows)
    create, stream, delete = PARSERS["mftecmd_j_csv"](ParseContext(tmp_path, Path("D:/Evidence/case")))
    assert (create.ts_us, create.event_code, create.file_path, create.source_file, create.source_record) == (
        1715688000123456, "FileCreate", "\\Users\\bob\\Downloads\\evil.exe", "WS01/$J", "1000")
    assert create.message == "DataExtend|FileCreate|Close: \\Users\\bob\\Downloads\\evil.exe"
    assert create.file_key == "\\users\\bob\\downloads\\evil.exe" and create.artifact == "usnjrnl"
    assert stream.event_code == "NamedDataExtend"
    assert (delete.event_code, delete.message) == ("FileDelete", "FileDelete|Close: \\Temp (folder)")


def test_the_hosts_mft_goes_with_its_journal(tmp_path):
    ev = tmp_path / "evidence"
    for host in ("WS01", "WS02"):
        (ev / host).mkdir(parents=True)
        (ev / host / "$J").write_bytes(b"\x00" * 64)
    (ev / "WS01" / "$MFT").write_bytes(b"FILE0" + b"\x00" * 59)   # WS02 has no $MFT
    case = create_case(tmp_path / "case", "Journal", ev, "cody")
    intake(case)
    spec = load_registry()["mftecmd_j"]
    tool = DetectedTool(spec, tmp_path / "MFTECmd.exe", "1.0")
    plans = {p.host: p for p in plan_runs(case, tool)}
    with_mft = build_argv(case, plans["WS01"], tmp_path / "out", {})
    assert with_mft[with_mft.index("-m") + 1] == str(ev / "WS01" / "$MFT")
    assert "-m" not in build_argv(case, plans["WS02"], tmp_path / "out", {})   # runs without folders


# Stands in for MFTECmd: writes the header of an empty $J CSV where --csv names
FAKE_MFTECMD = f"""
import sys
args = sys.argv[1:]
with open(args[args.index("--csv") + 1] + "/mftecmd_j.csv", "w", encoding="utf-8-sig") as f:
    f.write({",".join(COLUMNS)!r} + "\\n")
"""


def test_each_journal_takes_the_mft_of_its_own_volume(tmp_path):
    """A host collected volume by volume, as KAPE writes C/ and D/, has an $MFT for each, and MFTECmd finds a change's
    folder by entry and sequence numbers that repeat across volumes. So each $J takes the $MFT in the folder nearest
    above it, and a $J on a volume with no $MFT runs without -m, with a note in its run that says so."""
    ev = tmp_path / "evidence"
    for volume in ("C", "D", "E"):
        (ev / "WS01" / volume / "$Extend").mkdir(parents=True)
        (ev / "WS01" / volume / "$Extend" / "$UsnJrnl%3A$J").write_bytes(b"\x00" * 64)
    for volume in ("C", "D"):
        (ev / "WS01" / volume / "$MFT").write_bytes(b"FILE0" + b"\x00" * 59)
    case = create_case(tmp_path / "case", "Volumes", ev, "cody")
    intake(case)
    script = tmp_path / "mftecmd.py"
    script.write_text(FAKE_MFTECMD, encoding="utf-8")
    spec = load_registry()["mftecmd_j"]
    tool = DetectedTool(ToolSpec(**{**spec.__dict__, "args": (str(script), *spec.args)}), Path(sys.executable), "1.0")
    records = {p.input_file.split("/")[1]: run(case, p) for p in plan_runs(case, tool)}
    assert {volume: r.status for volume, r in records.items()} == {"C": "ok", "D": "ok", "E": "ok"}
    for volume in ("C", "D"):
        record, mft = records[volume], f"WS01/{volume}/$MFT"
        assert record.argv[record.argv.index("-m") + 1] == str(ev / mft)
        assert record.inputs == [f"WS01/{volume}/$Extend/$UsnJrnl%3A$J", mft] and record.notes == []
    journal = records["E"]
    assert "-m" not in journal.argv and journal.inputs == ["WS01/E/$Extend/$UsnJrnl%3A$J"]
    assert journal.notes == ["Ran without -m: no mft file is in a folder above WS01/E/$Extend/$UsnJrnl%3A$J, where its "
                             "volume's would be."]


# Stands in for MFTECmd: writes a $J CSV of one change record, a file created, where --csv names
FAKE_ONE_CHANGE = f"""
import csv, sys
args = sys.argv[1:]
with open(args[args.index("--csv") + 1] + "/mftecmd_j.csv", "w", encoding="utf-8-sig", newline="") as f:
    writer = csv.DictWriter(f, fieldnames={COLUMNS!r})
    writer.writeheader()
    writer.writerow({{"Name": "evil.exe", "UpdateSequenceNumber": "1000", "UpdateTimestamp": "2024-05-14 12:00:00",
                      "UpdateReasons": "FileCreate", "SourceFile": args[args.index("-f") + 1]}})
"""


def test_a_rerun_of_a_journal_replaces_its_run_whatever_mft_each_took(tmp_path):
    """A $J's run lists the $MFT it took among its inputs, but a rerun of the same $J, with an $MFT added since,
    replaces the earlier run: a rebuild loads the rerun alone, the Tools page counts its rows alone, and an earlier run
    that failed is no longer a gap."""
    from dataclasses import replace

    from glessner.intake import add_new
    from glessner.runner import latest_runs, read_runs, rebuild
    from glessner.toolbox import overview, run_gaps

    ev = tmp_path / "evidence"
    (ev / "WS01" / "D" / "$Extend").mkdir(parents=True)
    (ev / "WS01" / "D" / "$Extend" / "$UsnJrnl%3A$J").write_bytes(b"\x00" * 64)
    case = create_case(tmp_path / "case", "Rerun", ev, "cody")
    intake(case)
    script = tmp_path / "mftecmd.py"
    script.write_text(FAKE_ONE_CHANGE, encoding="utf-8")
    spec = load_registry()["mftecmd_j"]
    tool = DetectedTool(ToolSpec(**{**spec.__dict__, "args": (str(script), *spec.args)}), Path(sys.executable), "1.0")
    first = run(case, *plan_runs(case, tool))
    (ev / "WS01" / "D" / "$MFT").write_bytes(b"FILE0" + b"\x00" * 59)
    add_new(case)
    again = run(case, *plan_runs(case, tool))
    assert first.inputs == ["WS01/D/$Extend/$UsnJrnl%3A$J"] and again.inputs == [*first.inputs, "WS01/D/$MFT"]
    assert (first.status, first.loaded_rows, again.status, again.loaded_rows) == ("ok", 1, "ok", 1)
    assert [r.run_id for r in latest_runs(read_runs(case))] == [again.run_id]
    (row,) = overview(case, {spec.id: tool.spec}, {spec.id: tool})["tools"]
    assert row["last_run"]["rows"] == 1
    assert [r.run_id for r in rebuild(case)] == [again.run_id]
    failed = replace(first, status="failed", reason="exit code 1", loaded_rows=None)
    assert run_gaps([failed, again], {spec.id: tool.spec}) == []
