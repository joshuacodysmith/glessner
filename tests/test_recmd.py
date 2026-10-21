"""RECmd's batch CSV: the plugin detail file is kept relative to the run folder, and a value's name and data have
columns of their own."""

import csv
from pathlib import Path

from glessner.parsers import PARSERS, ParseContext

COLUMNS = ["HivePath", "HiveType", "Description", "Category", "KeyPath", "ValueName", "ValueType", "ValueData",
           "ValueData2", "ValueData3", "Comment", "Recursive", "Deleted", "LastWriteTimestamp", "PluginDetailFile"]


def test_plugin_detail_file_names_no_analysis_machine_path(tmp_path):
    run = tmp_path / "cases" / "verify-szechuan" / "runs" / "20261014T094113Z_recmd_DC01"
    out = run / "output"
    out.mkdir(parents=True)
    detail = out / "20261014094113" / "recmd_CIDSizeMRU.csv"
    with (out / "recmd.csv").open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS)
        w.writeheader()
        w.writerow({"HivePath": "D:\\Evidence\\DC01\\Users\\Administrator\\NTUSER.DAT", "Description": "CIDSizeMRU",
                    "KeyPath": "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\CIDSizeMRU",
                    "ValueName": "0", "ValueData": "mstsc.exe", "LastWriteTimestamp": "2020-09-19 03:30:01.5634434",
                    "PluginDetailFile": str(detail)})
        w.writerow({"HivePath": "D:\\Evidence\\DC01\\Users\\Administrator\\NTUSER.DAT", "Description": "Found output",
                    "KeyPath": "Software\\Run", "ValueName": "x", "LastWriteTimestamp": "2020-09-19 03:30:01",
                    "PluginDetailFile": "C:\\KAPE\\Out\\plugin.csv"})   # another machine's path: kept as written
    ours, found = PARSERS["recmd_csv"](ParseContext(out, Path("D:/Evidence")))
    assert ours.extra["PluginDetailFile"] == "output/20261014094113/recmd_CIDSizeMRU.csv"
    assert "szechuan" not in str(ours.extra).lower() and ours.source_file == "DC01/Users/Administrator/NTUSER.DAT"
    assert found.extra["PluginDetailFile"] == "C:\\KAPE\\Out\\plugin.csv"


def test_value_name_and_data_have_their_own_columns(tmp_path):
    """registry_value is the value's name and registry_data its data, as Sysmon 13's Details fills it; extra keeps
    ValueData for the host readers."""
    with (tmp_path / "recmd.csv").open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS)
        w.writeheader()
        w.writerow({"HivePath": "D:\\Evidence\\DC01\\Windows\\System32\\config\\SOFTWARE", "Description": "Run",
                    "KeyPath": "ROOT\\Microsoft\\Windows\\CurrentVersion\\Run", "ValueName": "Updater",
                    "ValueData": "C:\\Users\\Public\\u.exe", "LastWriteTimestamp": "2020-09-19 03:30:01"})
        w.writerow({"HivePath": "D:\\Evidence\\DC01\\Windows\\System32\\config\\SOFTWARE", "Description": "Run key",
                    "KeyPath": "ROOT\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "LastWriteTimestamp": "2020-09-19"})
        # A plugin's key row names no value; its ValueData is the plugin's summary, not a value's data.
        w.writerow({"HivePath": "D:\\Evidence\\DC01\\Windows\\System32\\config\\SOFTWARE", "Description": "Autoruns",
                    "KeyPath": "ROOT\\Microsoft\\Windows\\CurrentVersion\\Run", "LastWriteTimestamp": "2020-09-19",
                    "ValueData": "Created on: 2020-09-19 03:30:01", "PluginDetailFile": "C:\\KAPE\\Out\\autoruns.csv"})
    value, key, plugin = PARSERS["recmd_csv"](ParseContext(tmp_path, Path("D:/Evidence")))
    assert (value.registry_value, value.registry_data) == ("Updater", "C:\\Users\\Public\\u.exe")
    assert value.extra["ValueData"] == "C:\\Users\\Public\\u.exe"
    assert (key.registry_value, key.registry_data) == ("", "")
    assert (plugin.registry_value, plugin.registry_data) == ("", "")
    assert plugin.extra["ValueData"] == "Created on: 2020-09-19 03:30:01" and "Created on" in plugin.message
