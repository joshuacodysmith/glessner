"""The MFTECmd, PECmd, and LECmd parsers and the file key that links one file across artifacts."""

import csv
import json
from pathlib import Path

import pytest
from sbecmd_log_fixtures import CONSOLE_LOG_NAME, MESSAGES_NAME, console_log_text, messages_text

from glessner.events import event_uid
from glessner.parsers import PARSERS, ParseContext
from glessner.parsers.common import file_key

EVIDENCE = Path("D:/Evidence/case")


@pytest.mark.parametrize("path,key", [
    (r"\VOLUME{01d68d85e0da1e22-b0e0e8ff}\WINDOWS\SYSTEM32\CMD.EXE", r"\windows\system32\cmd.exe"),
    (r".\Windows\System32\cmd.exe", r"\windows\system32\cmd.exe"),
    (r"C:\Windows\System32\cmd.exe", r"\windows\system32\cmd.exe"),
    (r"This PC\C:\FileShare\Secret\Beth_Secret.txt", r"\fileshare\secret\beth_secret.txt"),
    (r"\\?\C:\Temp\x.exe", r"\temp\x.exe"),
    (r"\Device\HarddiskVolume2\Windows\x.dll", r"\windows\x.dll"),
    (r"\Windows\\System32\\", r"\windows\system32"),
    (r"\\.\C:\Temp\x.exe", r"\temp\x.exe"),
    (r"\\.\c:\Temp\x.exe", r"\temp\x.exe"),
    (r"\\.\Volume{3f2504e0-4f89-11d3-9a0c-0305e82c3301}\Temp\x.exe", r"\temp\x.exe"),
    (r"\\.\pipe\x", ""),
    ("//./pipe/x", ""),
    (r"\\?\pipe\x", ""),
    (r"\??\pipe\x", ""),
    ("//?/pipe/x", ""),
    (r"\\.\PhysicalDrive0", ""),
    (r"\\?\PhysicalDrive0", ""),
    (r"\\.\GLOBALROOT\Device\HarddiskVolume3\Windows\x.exe", r"\globalroot\device\harddiskvolume3\windows\x.exe"),
    (r"\\?\GLOBALROOT\Device\HarddiskVolume3\Windows\x.exe", r"\globalroot\device\harddiskvolume3\windows\x.exe"),
    (r"\??\GLOBALROOT\Device\HarddiskVolume3\Windows\x.exe", r"\globalroot\device\harddiskvolume3\windows\x.exe"),
    (r"\\.\HarddiskVolume3\Windows\x.exe", r"\harddiskvolume3\windows\x.exe"),
    (r"\\?\HarddiskVolumeShadowCopy1\Windows\x.exe", r"\harddiskvolumeshadowcopy1\windows\x.exe"),
    (r"\\.\UNC\server\share\x.exe", r"\unc\server\share\x.exe"),
    (r"\\?\UNC\server\share\x.exe", r"\unc\server\share\x.exe"),
    (r"\??\UNC\server\share\x.exe", r"\unc\server\share\x.exe"),
    (r"\??\C:\Temp\x.exe", r"\temp\x.exe"),
    (r"\??\Volume{3f2504e0-4f89-11d3-9a0c-0305e82c3301}\Temp\x.exe", r"\temp\x.exe"),
    (r"\\.\C:", ""),
    (r"\\server\share\x.exe", r"\server\share\x.exe"),
    (r"Applications\Microsoft Edge", ""),
    ("", ""),
    (None, ""),
])
def test_file_key(path, key):
    assert file_key(path) == key


def write_csv(path, rows):
    columns = list(rows[0])
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)


def test_mft_groups_timestamps_into_macb_and_flags_indicators(tmp_path):
    base = {"EntryNumber": "41", "SequenceNumber": "4", "ParentEntryNumber": "5", "ParentSequenceNumber": "5",
            "InUse": "False", "ParentPath": r".\Users\rick\Downloads", "FileName": "coreupdater.exe", "FileSize": "7168",
            "IsDirectory": "False", "IsAds": "False", "SI<FN": "True", "uSecZeros": "True", "Copied": "False",
            "Created0x10": "2020-09-19 03:24:06.0000000", "Created0x30": "2020-09-19 03:24:06.1234567",
            "LastModified0x10": "2020-09-19 03:24:06.0000000", "LastModified0x30": "2020-09-19 03:24:06.1234567",
            "LastRecordChange0x10": "2020-09-19 03:25:00.0000000", "LastRecordChange0x30": "2020-09-19 03:24:06.1234567",
            "LastAccess0x10": "2020-09-19 03:24:06.0000000", "LastAccess0x30": "2020-09-19 03:24:06.1234567",
            "ZoneIdContents": "[ZoneTransfer] ZoneId=3", "SourceFile": r"D:\Evidence\case\DESKTOP\$MFT"}
    write_csv(tmp_path / "mftecmd.csv", [base])
    events = list(PARSERS["mftecmd_csv"](ParseContext(tmp_path, EVIDENCE)))
    assert sorted(e.ts_desc for e in events) == ["$FN MACB", "$SI ..C.", "$SI MA.B"]
    si = next(e for e in events if e.ts_desc == "$SI MA.B")
    assert si.file_path == r"\Users\rick\Downloads\coreupdater.exe"
    assert si.file_key == r"\users\rick\downloads\coreupdater.exe"
    assert si.source_file == "DESKTOP/$MFT" and si.source_record == "41-4:coreupdater.exe"
    assert si.message == r"$SI MA.B \Users\rick\Downloads\coreupdater.exe [deleted; SI<FN; SI times have zero microseconds]"
    assert "timestomping" not in si.message   # MFTECmd marks SI<FN on most records of an ordinary volume
    assert json.loads(si.extra)["ZoneIdContents"] == "[ZoneTransfer] ZoneId=3"   # pre-serialized once per record


SI_TIMES = {"Created0x10": "2015-03-24 14:48:40.7343580", "LastModified0x10": "2015-03-24 14:59:30.6111710",
            "LastRecordChange0x10": "2015-03-24 14:59:30.6111710", "LastAccess0x10": "2015-03-24 14:59:30.5955700"}
FN_BLANK = {"Created0x30": "", "LastModified0x30": "", "LastRecordChange0x30": "", "LastAccess0x30": ""}
FN_EARLIER = {"Created0x30": "2015-03-24 14:32:00.0000000", "LastModified0x30": "2015-03-24 14:32:00.0000000",
              "LastRecordChange0x30": "2015-03-24 14:32:00.0000000", "LastAccess0x30": "2015-03-24 14:32:00.0000000"}


def mft_row(**cells):
    """An MFTECmd $MFT row for a Desktop document, with its $SI times and the $FN cells given."""
    return {"EntryNumber": "23554", "SequenceNumber": "14", "ParentEntryNumber": "5", "ParentSequenceNumber": "5",
            "InUse": "True", "ParentPath": r".\Users\informant\Desktop", "FileName": "Letter.docx",
            "FileSize": "11893", "IsDirectory": "False", "HasAds": "False", "IsAds": "False", "SI<FN": "False",
            "uSecZeros": "False", "Copied": "False", **SI_TIMES, **FN_BLANK, "SourceFile": r"D:\Evidence\case\PC\$MFT",
            **cells}


def mft_extra(tmp_path, row):
    """The extra data of a row's events, which they share."""
    write_csv(tmp_path / "mftecmd.csv", [row])
    [extra] = {e.extra for e in PARSERS["mftecmd_csv"](ParseContext(tmp_path, EVIDENCE))}
    return json.loads(extra)


def test_row_names_the_letters_whose_fn_equals_si(tmp_path):
    """MFTECmd leaves a $FN cell blank where that time equals the $SI time, and `--at` writes the same text in it. A
    $FN cell with another time names no letter, and neither does a blank $FN cell beside a blank $SI cell."""
    row = mft_row(LastAccess0x30=SI_TIMES["LastAccess0x10"], LastRecordChange0x30=FN_EARLIER["LastRecordChange0x30"],
                  Created0x10="")
    assert mft_extra(tmp_path, row)["FnEqualsSi"] == "MA"


def test_si_cell_the_parser_does_not_load_names_no_letter(tmp_path):
    """An $SI cell that makes no event names no letter, whether its $FN cell is blank or holds the same text. Here B's
    $SI cell holds a placeholder time before 1971, and A's holds text that is no time."""
    placeholder = "1601-01-01 00:00:00.0000000"
    row = mft_row(Created0x10=placeholder, LastAccess0x10="not a time", LastAccess0x30="not a time")
    write_csv(tmp_path / "mftecmd.csv", [row])
    events = list(PARSERS["mftecmd_csv"](ParseContext(tmp_path, EVIDENCE)))
    assert sorted(e.ts_desc for e in events) == ["$SI M.C."]
    assert json.loads(events[0].extra)["FnEqualsSi"] == "MC"


def test_row_with_no_fn_columns_names_all_four(tmp_path):
    """A row whose $FN cells are all blank makes $SI events only, and the field names all four letters."""
    write_csv(tmp_path / "mftecmd.csv", [mft_row()])
    events = list(PARSERS["mftecmd_csv"](ParseContext(tmp_path, EVIDENCE)))
    assert sorted(e.ts_desc for e in events) == ["$SI ...B", "$SI .A..", "$SI M.C."]
    assert {json.loads(e.extra)["FnEqualsSi"] for e in events} == {"MACB"}


def test_row_with_every_fn_filled_has_no_field(tmp_path):
    assert "FnEqualsSi" not in mft_extra(tmp_path, mft_row(**FN_EARLIER))


def test_ads_row_has_no_fn_field(tmp_path):
    """An alternate data stream has no $FILE_NAME attribute of its own, so its row's blank $FN cells name nothing."""
    extra = mft_extra(tmp_path, mft_row(FileName="Letter.docx:Zone.Identifier", IsAds="True"))
    assert extra["IsAds"] == "True" and "FnEqualsSi" not in extra


# The IDs of mft_row's events with every $FN cell blank, with only $FN B blank, and with none blank, as a load gives them
# for the collection host PC. An ID hashes the host, artifact, source file, source record, and time description.
MFT_SI_IDS = ["fb94a2cb0415c5ec9bc779254ea51482", "c88d3793d4b7a663be5f10d1bbda882b", "d82b3bd121015a50f43bda39d0f00cc0"]
MFT_IDS = {
    "every $FN blank": MFT_SI_IDS,
    "$FN B blank": [*MFT_SI_IDS, "9f61ac2a48ca2a3f9629f48489ecf09e"],
    "no $FN blank": [*MFT_SI_IDS, "44f423ca998b0cdde9a1a324a7061559"],
}


def test_mft_event_ids_unchanged_by_the_field(tmp_path):
    """The field adds no event and changes none: each row's events keep their pinned IDs."""
    rows = {"every $FN blank": mft_row(), "$FN B blank": mft_row(**{**FN_EARLIER, "Created0x30": ""}),
            "no $FN blank": mft_row(**FN_EARLIER)}
    ids = {}
    for number, (name, row) in enumerate(rows.items()):
        folder = tmp_path / str(number)
        folder.mkdir()
        write_csv(folder / "mftecmd.csv", [row])
        ids[name] = [event_uid("PC", e.artifact, e.source_file, e.source_record, e.ts_desc)
                     for e in PARSERS["mftecmd_csv"](ParseContext(folder, EVIDENCE))]
    assert ids == MFT_IDS


def test_prefetch_one_event_per_run_with_full_path(tmp_path):
    loaded = r"\VOLUME{01d6}\WINDOWS\SYSTEM32\NTDLL.DLL, \VOLUME{01d6}\WINDOWS\SYSTEM32\CMD.EXE"
    write_csv(tmp_path / "pecmd.csv", [{
        "SourceFilename": r"D:\Evidence\case\DESKTOP\Windows\Prefetch\CMD.EXE-0BD30981.pf", "ExecutableName": "CMD.EXE",
        "RunCount": "9", "LastRun": "2020-09-19 05:08:37.5328773", "PreviousRun0": "2020-09-19 03:43:14.9908796",
        "PreviousRun1": "", "PreviousRun2": "", "PreviousRun3": "", "PreviousRun4": "", "PreviousRun5": "",
        "PreviousRun6": "", "FilesLoaded": loaded, "Volume0Name": r"\VOLUME{01d6}", "ParsingError": "False"}])
    events = list(PARSERS["pecmd_csv"](ParseContext(tmp_path, EVIDENCE)))
    assert [e.source_record for e in events] == ["LastRun", "PreviousRun0"]
    assert all(e.file_key == r"\windows\system32\cmd.exe" for e in events)
    assert events[0].message == r"Executed CMD.EXE (\VOLUME{01d6}\WINDOWS\SYSTEM32\CMD.EXE), run count 9"
    assert events[0].source_file == "DESKTOP/Windows/Prefetch/CMD.EXE-0BD30981.pf"
    assert events[0].extra["FilesLoadedCount"] == 2


def test_prefetch_takes_pecmds_full_path_where_it_holds_one(tmp_path):
    """PECmd's FullPath column names the program's path where no FilesLoaded entry ends with its name, and ahead of
    an entry that does. An empty FullPath leaves the path to FilesLoaded."""
    row = {"SourceFilename": r"D:\Evidence\case\DESKTOP\Windows\Prefetch\CMD.EXE-0BD30981.pf", "ExecutableName": "CMD.EXE",
           "RunCount": "9", "LastRun": "2020-09-19 05:08:37.5328773",
           "FilesLoaded": r"\VOLUME{01d6}\WINDOWS\SYSTEM32\NTDLL.DLL",
           "FullPath": r"\VOLUME{01d6}\WINDOWS\SYSTEM32\CMD.EXE"}
    elsewhere = {**row, "SourceFilename": r"D:\Evidence\case\DESKTOP\Windows\Prefetch\SVCHOST.EXE-5D3C9E1A.pf",
                 "ExecutableName": "SVCHOST.EXE",
                 "FilesLoaded": r"\VOLUME{01d6}\WINDOWS\SYSTEM32\SVCHOST.EXE, \VOLUME{01d6}\USERS\PUBLIC\SVCHOST.EXE",
                 "FullPath": r"\VOLUME{01d6}\USERS\PUBLIC\SVCHOST.EXE"}
    derived = {**row, "SourceFilename": r"D:\Evidence\case\DESKTOP\Windows\Prefetch\NOTEPAD.EXE-D8414F97.pf",
               "ExecutableName": "NOTEPAD.EXE", "FilesLoaded": r"\VOLUME{01d6}\WINDOWS\SYSTEM32\NOTEPAD.EXE", "FullPath": ""}
    write_csv(tmp_path / "pecmd.csv", [row, elsewhere, derived])
    stated, preferred, found = PARSERS["pecmd_csv"](ParseContext(tmp_path, EVIDENCE))
    assert (stated.file_path, stated.file_key) == (r"\VOLUME{01d6}\WINDOWS\SYSTEM32\CMD.EXE", r"\windows\system32\cmd.exe")
    assert stated.message == r"Executed CMD.EXE (\VOLUME{01d6}\WINDOWS\SYSTEM32\CMD.EXE), run count 9"
    assert (preferred.file_path, preferred.file_key) == (r"\VOLUME{01d6}\USERS\PUBLIC\SVCHOST.EXE",
                                                         r"\users\public\svchost.exe")
    assert (found.file_path, found.file_key) == (r"\VOLUME{01d6}\WINDOWS\SYSTEM32\NOTEPAD.EXE", r"\windows\system32\notepad.exe")


def test_lnk_uses_embedded_times_not_the_copy_times(tmp_path):
    write_csv(tmp_path / "lecmd.csv", [
        {"SourceFile": r"D:\Evidence\case\DC01\Users\Administrator\AppData\Roaming\Microsoft\Windows\Recent\Secret.lnk",
         "SourceCreated": "2026-10-12 10:36:15", "TargetCreated": "2020-09-19 03:34:56", "TargetModified": "",
         "TargetAccessed": "", "TrackerCreatedOn": "", "LocalPath": "C:\\FileShare\\",
         "CommonPath": r"Secret\Beth_Secret.txt", "NetworkPath": r"\\CITADEL-DC01\FileShare",
         "TargetIDAbsolutePath": r"This PC\C:\FileShare\Secret\Beth_Secret.txt",
         "MachineID": "citadel-dc01", "TargetMFTEntryNumber": "0x1A2B"},
        {"SourceFile": r"D:\Evidence\case\DESKTOP\Users\Admin\Desktop\Microsoft Edge.lnk", "SourceCreated": "2026-10-12",
         "TargetCreated": "", "TargetModified": "", "TargetAccessed": "", "TrackerCreatedOn": "", "LocalPath": "",
         "CommonPath": "", "NetworkPath": "", "TargetIDAbsolutePath": r"Applications\Microsoft Edge",
         "MachineID": "", "TargetMFTEntryNumber": ""},
    ])
    secret, edge = list(PARSERS["lecmd_csv"](ParseContext(tmp_path, EVIDENCE)))
    assert (secret.ts_desc, secret.ts_us) == ("LNK target created", 1600486496000000)
    # LocalPath holds only the base folder; CommonPath completes it.
    assert secret.file_path == r"C:\FileShare\Secret\Beth_Secret.txt"
    assert secret.file_key == r"\fileshare\secret\beth_secret.txt" and secret.host_name_recorded == "citadel-dc01"
    assert secret.extra["TargetMFTEntryNumber"] == "0x1A2B"
    assert edge.ts_us is None and edge.file_key == "" and edge.ts_desc == "LNK without target times"


def test_lnk_tracker_time_later_than_the_link_itself_stays_off_the_timeline(tmp_path):
    """A tracker ID that isn't time-based stays off the timeline: LECmd turns one into the year 3850."""
    row = {"SourceFile": r"D:\Evidence\case\SRV\Users\a\Desktop\x.lnk", "SourceCreated": "2026-10-13 06:00:00",
           "SourceModified": "2026-10-13 06:00:00", "SourceAccessed": "2026-10-13 06:00:00",
           "TargetCreated": "2024-02-05 23:00:00", "TargetModified": "", "TargetAccessed": "",
           "TrackerCreatedOn": "3850-06-18 16:03:31", "LocalPath": r"C:\x.txt", "CommonPath": "", "NetworkPath": "",
           "TargetIDAbsolutePath": "", "MachineID": "srv", "TargetMFTEntryNumber": ""}
    write_csv(tmp_path / "lecmd.csv", [row, {**row, "TrackerCreatedOn": "2024-02-05 23:05:23"}])
    events = list(PARSERS["lecmd_csv"](ParseContext(tmp_path, EVIDENCE)))
    assert [e.ts_desc for e in events] == ["LNK target created", "LNK target created", "LNK tracker created"]
    assert events[0].extra["TrackerCreatedOn"] == "3850-06-18 16:03:31"
    assert "not placed on the timeline" in events[0].extra["TrackerCreatedOnNote"]
    assert "TrackerCreatedOnNote" not in events[1].extra


def test_lnk_keeps_its_droid_columns_in_the_details(tmp_path):
    volume, file = "5c1e2f0a-3b4d-4e6f-8a9b-0c1d2e3f4a5b", "7d2f3a1b-4c5e-11ea-9a8b-000c29a1b2c3"
    droids = {"VolumeDroid": volume, "FileDroid": file, "VolumeDroidBirth": volume, "FileDroidBirth": file}
    write_csv(tmp_path / "lecmd.csv", [
        {"SourceFile": r"D:\Evidence\case\SRV\Users\a\Desktop\x.lnk", "TargetCreated": "2024-02-05 23:00:00",
         "LocalPath": r"C:\x.txt", "MachineID": "srv", **droids}])
    [event] = PARSERS["lecmd_csv"](ParseContext(tmp_path, EVIDENCE))
    assert {k: event.extra[k] for k in droids} == droids


SBE_COLUMNS = ["BagPath", "Slot", "NodeSlot", "MRUPosition", "AbsolutePath", "ShellType", "Value", "ChildBags", "CreatedOn",
               "ModifiedOn", "AccessedOn", "LastWriteTime", "MFTEntry", "MFTSequenceNumber", "ExtensionBlockCount",
               "FirstInteracted", "LastInteracted", "HasExplored", "Miscellaneous"]


def test_shellbags_name_their_hive_and_profile(tmp_path):
    """SBECmd writes one CSV per hive and names the hives only in its messages file."""
    hive = r"D:\Evidence\case\DESKTOP\Users\ricksanchez\AppData\Local\Microsoft\Windows\UsrClass.dat"
    (tmp_path / "!SBECmd_Messages.txt").write_text(
        f"[03:17:41.717 INF] Processing {hive}\n"
        f"[03:17:41.800 INF] Finished processing {hive}\n"
        rf"[03:17:41.800 INF] Exported to: C:\out\ricksanchez_UsrClass.csv" "\n", encoding="utf-8")
    with (tmp_path / "ricksanchez_UsrClass.csv").open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=SBE_COLUMNS)
        w.writeheader()
        w.writerow({"BagPath": "BagMRU\\1", "Slot": "6", "AbsolutePath": "Desktop\\This PC\\C:\\FileShare\\Secret",
                    "ShellType": "Directory", "Value": "Secret", "CreatedOn": "2020-09-19 03:36:48",
                    "LastWriteTime": "2020-09-19 03:51:47", "FirstInteracted": "2020-09-19 03:38:45",
                    "LastInteracted": "2020-09-19 03:51:47", "HasExplored": "True"})
        w.writerow({"BagPath": "BagMRU", "Slot": "0", "AbsolutePath": "Desktop\\Quick Access", "ShellType": "Root folder: GUID",
                    "Value": "Quick Access", "LastWriteTime": "2020-09-19 03:51:14"})
    first, last, quick = list(PARSERS["sbecmd_csv"](ParseContext(tmp_path, EVIDENCE)))
    assert first.source_file == "DESKTOP/Users/ricksanchez/AppData/Local/Microsoft/Windows/UsrClass.dat"
    assert (first.ts_desc, first.user_name, first.artifact) == ("ShellBag first interacted", "ricksanchez", "shellbags")
    assert first.message == "ShellBag first interacted: Desktop\\This PC\\C:\\FileShare\\Secret (Directory)"
    assert (first.file_path, first.file_key) == ("C:\\FileShare\\Secret", "\\fileshare\\secret")
    assert first.extra["CreatedOn"] == "2020-09-19 03:36:48" and first.extra["Hive"] == "UsrClass.dat"
    # LastWriteTime equals LastInteracted there, so it isn't a third event; the Quick Access bag has only a key write.
    assert last.ts_desc == "ShellBag last interacted"
    assert (quick.ts_desc, quick.file_path, quick.file_key) == ("ShellBag key last write", "", "")
    assert first.source_record != quick.source_record


def write_rows(path, columns, rows):
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=columns)
        w.writeheader()
        for row in rows:
            w.writerow(row)


def shellbag_csv(folder, name, folder_name):
    """A ShellBags CSV of one bag, whose path names `folder_name`."""
    write_rows(folder / name, SBE_COLUMNS, [{"BagPath": "BagMRU\\1", "Slot": "6", "ShellType": "Directory",
                                             "AbsolutePath": f"Desktop\\This PC\\C:\\{folder_name}",
                                             "FirstInteracted": "2020-09-19 03:38:45"}])


def hive_of(user):
    return rf"D:\Evidence\case\DESKTOP\Users\{user}\AppData\Local\Microsoft\Windows\UsrClass.dat"


def hive_sources(folder):
    """What each ShellBags event cites as its source, and its profile, for the CSVs in `folder`."""
    return sorted((e.source_file, e.user_name) for e in PARSERS["sbecmd_csv"](ParseContext(folder, EVIDENCE)))


def test_shellbags_name_their_hive_from_the_console_log_of_a_2026_10_build(tmp_path):
    """From 2026.10 SBECmd writes its record of the run to <stamp>_SBECmd_<version>_ConsoleLog.txt and no messages file."""
    (tmp_path / CONSOLE_LOG_NAME).write_text(
        console_log_text(hive_of("ricksanchez"), r"C:\out\ricksanchez_UsrClass.csv"), encoding="utf-8", newline="")
    shellbag_csv(tmp_path, "ricksanchez_UsrClass.csv", "Secret")
    assert hive_sources(tmp_path) == [("DESKTOP/Users/ricksanchez/AppData/Local/Microsoft/Windows/UsrClass.dat", "ricksanchez")]


def test_shellbags_name_their_hives_from_a_messages_file_and_a_console_log_in_one_folder(tmp_path):
    (tmp_path / MESSAGES_NAME).write_text(
        messages_text(hive_of("ricksanchez"), r"C:\out\ricksanchez_UsrClass.csv"), encoding="utf-8", newline="")
    (tmp_path / CONSOLE_LOG_NAME).write_text(
        console_log_text(hive_of("mortysmith"), r"C:\out\mortysmith_UsrClass.csv"), encoding="utf-8", newline="")
    shellbag_csv(tmp_path, "ricksanchez_UsrClass.csv", "One")
    shellbag_csv(tmp_path, "mortysmith_UsrClass.csv", "Two")
    assert [user for _, user in hive_sources(tmp_path)] == ["mortysmith", "ricksanchez"]


def test_the_latest_console_log_names_a_csv_two_runs_wrote(tmp_path):
    """Console logs sort by the UTC stamp that starts their names, so the run that wrote the CSV last names its hive."""
    for stamp, user in (("20261025181337", "mortysmith"), ("20261024090000", "ricksanchez")):
        name = f"{stamp}_SBECmd_2026.10.2_ConsoleLog.txt"
        (tmp_path / name).write_text(console_log_text(hive_of(user), r"C:\out\profile_UsrClass.csv", name=name),
                                     encoding="utf-8", newline="")
    shellbag_csv(tmp_path, "profile_UsrClass.csv", "Tools")
    assert [user for _, user in hive_sources(tmp_path)] == ["mortysmith"]


def test_an_exported_line_ahead_of_a_log_s_first_finished_line_names_no_hive(tmp_path):
    """A hive is named by the finished line before an exported line in the same file. A later log that opens with an
    exported line has no hive of its own yet, and doesn't take the hive its predecessor ended on."""
    earlier, later = "20261024090000_SBECmd_2026.10.2_ConsoleLog.txt", "20261025181337_SBECmd_2026.10.2_ConsoleLog.txt"
    (tmp_path / earlier).write_text(console_log_text(hive_of("ricksanchez"), r"C:\out\ricksanchez_UsrClass.csv", name=earlier),
                                    encoding="utf-8", newline="")
    (tmp_path / later).write_text(r"[01:13:37.728 INF] Exported to: C:\out\mortysmith_UsrClass.csv" "\r\n",
                                  encoding="utf-8", newline="")
    shellbag_csv(tmp_path, "ricksanchez_UsrClass.csv", "Secret")
    shellbag_csv(tmp_path, "mortysmith_UsrClass.csv", "Tools")
    assert [user for _, user in hive_sources(tmp_path)] == ["ricksanchez"]


def test_shellbags_name_no_hive_when_the_folder_holds_no_record_of_the_run(tmp_path):
    shellbag_csv(tmp_path, "ricksanchez_UsrClass.csv", "Secret")
    assert hive_sources(tmp_path) == []


AMCACHE_FILE_COLUMNS = ["ApplicationName", "ProgramId", "FileKeyLastWriteTimestamp", "SHA1", "IsOsComponent", "FullPath", "Name",
                        "FileExtension", "LinkDate", "ProductName", "Size", "Version", "ProductVersion", "LongPathHash"]
AMCACHE_PROGRAM_COLUMNS = ["ProgramId", "KeyLastWriteTimestamp", "Name", "Version", "Publisher", "InstallDate", "RootDirPath"]


def test_amcache_reads_both_layouts(tmp_path):
    """File entries with SHA-1, programs with install dates, and the older Windows 8 and 2012 R2 layout."""
    write_rows(tmp_path / "20261014_Amcache_UnassociatedFileEntries.csv", AMCACHE_FILE_COLUMNS, [
        {"FileKeyLastWriteTimestamp": "2020-09-19 03:40:45", "FullPath": "c:\\windows\\system32\\coreupdater.exe",
         "SHA1": "fd153c66386ca93ec9993d66a84d6f0d129a3a5c", "LinkDate": "2010-04-14 22:06:53", "IsOsComponent": "False"}])
    write_rows(tmp_path / "20261014_Amcache_ProgramEntries.csv", AMCACHE_PROGRAM_COLUMNS, [
        {"ProgramId": "p1", "KeyLastWriteTimestamp": "2020-09-19 01:32:10", "Name": "Tool", "Version": "1.0",
         "Publisher": "Vendor", "InstallDate": "2020-09-18 10:00:00", "RootDirPath": "C:\\Program Files\\Tool"}])
    write_rows(tmp_path / "20261014_Amcache_ShortCuts.csv", ["KeyName", "LnkName", "KeyLastWriteTimestamp"], [
        {"KeyName": "tool.lnk|a9", "LnkName": "C:\\ProgramData\\Start Menu\\Tool.lnk",
         "KeyLastWriteTimestamp": "2020-09-19 01:32:13"}])
    ctx = ParseContext(tmp_path, EVIDENCE, ("DESKTOP/Windows/appcompat/Programs/Amcache.hve",))
    file_entry, program, installed, shortcut = list(PARSERS["amcache_csv"](ctx))
    assert file_entry.source_file == "DESKTOP/Windows/appcompat/Programs/Amcache.hve" and file_entry.artifact == "amcache"
    sha1 = "fd153c66386ca93ec9993d66a84d6f0d129a3a5c"
    assert file_entry.message == f"Amcache file: c:\\windows\\system32\\coreupdater.exe (SHA-1 {sha1})"
    assert (file_entry.file_key, file_entry.extra["SHA1"]) == ("\\windows\\system32\\coreupdater.exe", sha1)
    assert (program.message, installed.ts_desc, installed.ts_us) == ("Amcache program: Tool 1.0, Vendor", "Program installed",
                                                                     1600423200000000)
    assert shortcut.ts_desc == "Amcache shortcut entry written"
    # The older layout.
    old = tmp_path / "old"
    old.mkdir()
    write_rows(old / "x_Amcache_AssociatedFileEntries.csv",
               ["ProgramName", "ProgramID", "FileIDLastWriteTimestamp", "SHA1", "FullPath"], [
        {"ProgramName": "VMware Tools", "ProgramID": "p2", "FileIDLastWriteTimestamp": "2020-09-18 22:37:31",
         "SHA1": "f5c8", "FullPath": "C:\\Program Files\\VMware\\vm.exe"}])
    write_rows(old / "x_Amcache_ProgramEntries.csv", ["ProgramID", "LastWriteTimestamp", "ProgramName_0", "ProgramVersion_1",
                                                      "VendorName_2", "InstallDateEpoch_a", "PathsList_d"], [
        {"ProgramID": "p2", "LastWriteTimestamp": "2020-09-18 22:37:30", "ProgramName_0": "VMware Tools",
         "ProgramVersion_1": "11.0", "VendorName_2": "VMware, Inc.", "InstallDateEpoch_a": "2020-09-18 22:37:30"}])
    events = list(PARSERS["amcache_csv"](ParseContext(old, EVIDENCE, ("DC01/Windows/AppCompat/Programs/Amcache.hve",))))
    assert all(e.ts_us is not None for e in events) and len(events) == 3
    assert events[1].message == "Amcache program: VMware Tools 11.0, VMware, Inc."


JLE_AUTO_COLUMNS = ["SourceFile", "SourceCreated", "AppId", "AppIdDescription", "EntryNumber", "CreationTime", "LastModified",
                    "Hostname", "Path", "InteractionCount", "LocalPath", "NetworkPath", "TargetIDAbsolutePath", "TargetCreated"]
JLE_CUSTOM_COLUMNS = ["SourceFile", "AppId", "AppIdDescription", "EntryName", "TargetCreated", "TargetModified",
                      "TargetAccessed", "LocalPath", "TargetIDAbsolutePath"]


def test_jump_lists_use_destlist_times_and_name_the_profile(tmp_path):
    src = ("D:\\Evidence\\case\\DC01\\Users\\Administrator\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\"
           "AutomaticDestinations\\7e4d.automaticDestinations-ms")
    write_rows(tmp_path / "1_AutomaticDestinations.csv", JLE_AUTO_COLUMNS, [
        {"SourceFile": src, "SourceCreated": "2026-10-14 00:00:00", "AppIdDescription": "Windows Explorer", "EntryNumber": "3",
         "CreationTime": "2020-09-19 03:40:00", "LastModified": "2020-09-19 03:45:00", "Hostname": "citadel-dc01",
         "LocalPath": "C:\\FileShare\\Secret", "TargetCreated": "2020-09-18 22:00:00"}])
    write_rows(tmp_path / "1_CustomDestinations.csv", JLE_CUSTOM_COLUMNS, [
        {"SourceFile": src.replace("AutomaticDestinations", "CustomDestinations").replace("automatic", "custom"),
         "AppIdDescription": "Edge Browser", "TargetIDAbsolutePath": "Microsoft.MicrosoftEdge!MicrosoftEdge"}])
    created, used, custom = list(PARSERS["jlecmd_csv"](ParseContext(tmp_path, EVIDENCE)))
    assert (created.ts_desc, used.ts_desc) == ("Jump list entry created", "Jump list entry last used")
    assert used.message == "Jump list entry last used: Windows Explorer: C:\\FileShare\\Secret"
    assert (used.user_name, used.host_name_recorded, used.file_key) == ("Administrator", "citadel-dc01", "\\fileshare\\secret")
    assert used.source_file.startswith("DC01/Users/Administrator/") and "SourceCreated" not in used.extra
    assert (custom.ts_us, custom.ts_desc) == (None, "Jump list entry without times")


SRUM_COLUMNS = ["Id", "Timestamp", "ExeInfo", "ExeInfoDescription", "SidType", "Sid", "UserName", "UserId", "AppId",
                "BytesReceived", "BytesSent", "InterfaceType", "ProfileName"]


def test_srum_network_use_names_the_application_and_account(tmp_path):
    write_rows(tmp_path / "1_SrumECmd_NetworkUsages_Output.csv", SRUM_COLUMNS, [
        {"Id": "7", "Timestamp": "2020-09-19 04:00:00", "ExeInfo": "\\Device\\HarddiskVolume3\\Windows\\coreupdater.exe",
         "UserName": "C137\\Administrator", "Sid": "S-1-5-21-1-500", "BytesSent": "1048576", "BytesReceived": "2048"}])
    write_rows(tmp_path / "1_SrumECmd_EnergyUsage_Output.csv", ["Id", "Timestamp"],
               [{"Id": "1", "Timestamp": "2020-09-19 04:00:00"}])
    (ev,) = list(PARSERS["srumecmd_csv"](ParseContext(tmp_path, EVIDENCE, ("DESKTOP/Windows/System32/sru/SRUDB.dat",))))
    assert ev.message == ("SRUM network use (hour ending): \\Device\\HarddiskVolume3\\Windows\\coreupdater.exe sent "
                          "1,048,576 bytes, received 2,048")
    assert (ev.user_domain, ev.user_name, ev.file_key) == ("C137", "Administrator", "\\windows\\coreupdater.exe")
    assert ev.source_file == "DESKTOP/Windows/System32/sru/SRUDB.dat" and ev.extra["Table"] == "NetworkUsages"


def test_srum_counts_in_other_digits_are_shown_as_written(tmp_path):
    """A count written in digits int() refuses, such as "²" or more than 4,300 digits, is shown as written and doesn't
    fail the whole parse."""
    long = "1" * 5000
    write_rows(tmp_path / "1_SrumECmd_NetworkUsages_Output.csv", SRUM_COLUMNS, [
        {"Id": "7", "Timestamp": "2020-09-19 04:00:00", "ExeInfo": "x.exe", "BytesSent": "²", "BytesReceived": long}])
    write_rows(tmp_path / "1_SrumECmd_AppResourceUseInfo_Output.csv",
               ["Id", "Timestamp", "ExeInfo", "ForegroundBytesWritten", "BackgroundBytesWritten"],
               [{"Id": "8", "Timestamp": "2020-09-19 04:00:00", "ExeInfo": "x.exe", "ForegroundBytesWritten": "²",
                 "BackgroundBytesWritten": "4096"},
                {"Id": "9", "Timestamp": "2020-09-19 04:00:00", "ExeInfo": "x.exe", "ForegroundBytesWritten": long,
                 "BackgroundBytesWritten": "4096"}])
    usage, resources, more = PARSERS["srumecmd_csv"](ParseContext(tmp_path, EVIDENCE))
    assert usage.message == f"SRUM network use (hour ending): x.exe sent ² bytes, received {long}"
    assert resources.message == more.message == "SRUM app resource use (hour ending): x.exe wrote 4,096 bytes"


def test_recycle_bin_deletion_with_its_sid(tmp_path):
    write_rows(tmp_path / "rbcmd.csv", ["SourceName", "FileType", "FileName", "FileSize", "DeletedOn"], [
        {"SourceName": "D:\\Evidence\\case\\DC01\\$Recycle.Bin\\S-1-5-21-22-500\\$IU2L112.txt", "FileType": "$I",
         "FileName": "C:\\FileShare\\Secret\\SECRET_beth.txt", "FileSize": "28", "DeletedOn": "2020-09-19 03:34:27"}])
    (ev,) = list(PARSERS["rbcmd_csv"](ParseContext(tmp_path, EVIDENCE)))
    assert ev.message == "Deleted to the Recycle Bin: C:\\FileShare\\Secret\\SECRET_beth.txt (28 bytes)"
    assert (ev.source_file, ev.extra["SID"]) == ("DC01/$Recycle.Bin/S-1-5-21-22-500/$IU2L112.txt", "S-1-5-21-22-500")
    assert ev.file_key == "\\fileshare\\secret\\secret_beth.txt"


def test_recycle_bin_records_number_within_each_file(tmp_path):
    # An INFO2 file holds many records; each $I file holds one. Numbering per file keeps IDs stable as files come and go.
    write_rows(tmp_path / "rbcmd.csv", ["SourceName", "FileType", "FileName", "DeletedOn"], [
        {"SourceName": "D:\\Evidence\\case\\XP\\RECYCLER\\S-1-5-21-9-1003\\INFO2", "FileType": "INFO2",
         "FileName": f"C:\\temp\\{n}.txt", "DeletedOn": "2010-01-01 00:00:00"} for n in "ab"] + [
        {"SourceName": "D:\\Evidence\\case\\XP\\RECYCLER\\S-1-5-21-9-1004\\INFO2", "FileType": "INFO2",
         "FileName": "C:\\temp\\c.txt", "DeletedOn": "2010-01-02 00:00:00"}])
    events = list(PARSERS["rbcmd_csv"](ParseContext(tmp_path, EVIDENCE)))
    assert [(e.source_file.split("/")[2], e.source_record) for e in events] == [
        ("S-1-5-21-9-1003", "INFO2|1"), ("S-1-5-21-9-1003", "INFO2|2"), ("S-1-5-21-9-1004", "INFO2|1")]
