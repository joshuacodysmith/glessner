"""RECmd's batch CSV: the plugin detail file is kept relative to the run folder, a value's name and data have
columns of their own, and the MountedDevices plugin's data is decoded. The plugins' detail CSVs beside it add each
entry's columns to its row's details and its own times as events, where the detail row passes the pair check."""

import codecs
import csv
import shutil
from collections import Counter
from dataclasses import asdict, replace
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from glessner.events import EventIds, event_uid, to_us
from glessner.parsers import PARSERS, ParseContext
from glessner.parsers.common import DETAILS_NOTE
from glessner.parsers.recmd import PLUGINS
from glessner.pivots import fits, kind_of

COLUMNS = ["HivePath", "HiveType", "Description", "Category", "KeyPath", "ValueName", "ValueType", "ValueData",
           "ValueData2", "ValueData3", "Comment", "Recursive", "Deleted", "LastWriteTimestamp", "PluginDetailFile"]
MOUNTED_DEVICES = "ROOT\\MountedDevices"
MOUNTED_WRITTEN = "2020-09-18 05:41:08.6214289"
# The plugin's ValueData2 for an MBR volume, a GPT volume, and a USB disk's volume, as RECmd writes them
MBR_DATA = "Data:  AB\xf0\x00\x00P\x06\x00\x00\x00\x00"
GPT_DATA = "Data: Partition: GPT DMIO:ID: 67-45-23-01-AB-89-EF-CD-8F-94-9F-0D-0A-22-5C-7B"
USB_DATA = "Data: \\??\\USBSTOR#Disk&Ven_Acme&Prod_Stick&Rev_1.00#0123456789AB&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}"
DECODED_KEYS = ("DiskSignature", "PartitionOffset", "PartitionSector", "PartitionGuid", "DeviceBus", "DeviceVendorProduct",
                "DeviceInstance", "DeviceClassGuid")


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


def test_a_services_row_leaves_the_value_name_none_out_of_its_message_and_nothing_else(tmp_path):
    """The Services plugin writes the text None as every row's value name. Its message leaves that out, while the value
    name, the data, and the source record, which the event ID hashes, stay as RECmd wrote them. Another plugin's value
    named None keeps its name."""
    hive = "D:\\Evidence\\DC01\\Windows\\System32\\config\\SYSTEM"
    services = "ROOT\\ControlSet001\\Services"
    run = "ROOT\\Microsoft\\Windows\\CurrentVersion\\Run"
    with (tmp_path / "recmd.csv").open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS)
        w.writeheader()
        for description, key, name, data in (("Services", services, "None", "Name: WinUpdSvc Desc: "),
                                             ("Services", services, "None", ""),
                                             ("Services", services, "Start", "2"),
                                             ("Run", run, "None", "C:\\Users\\Public\\u.exe")):
            w.writerow({"HivePath": hive, "Description": description, "KeyPath": key, "ValueName": name, "ValueData": data,
                        "ValueData3": "Image path: C:\\wu.exe ServiceDLL: " if description == "Services" else "",
                        "LastWriteTimestamp": "2020-09-19 03:30:01"})
    service, bare, other_name, other_plugin = PARSERS["recmd_csv"](ParseContext(tmp_path, Path("D:/Evidence")))
    assert service.message == "Services: Name: WinUpdSvc Desc:" and bare.message == "Services:"
    assert (service.registry_value, service.registry_data) == ("None", "Name: WinUpdSvc Desc: ")
    assert service.source_record == f"{services}|None|Services" and bare.source_record == f"{services}|None|Services"
    assert service.file_path == "C:\\wu.exe"
    assert other_name.message == "Services: Start = 2"
    assert other_plugin.message == "Run: None = C:\\Users\\Public\\u.exe"


def write_mounted_devices(folder: Path, hive: str, written: str, *data: str, **columns: str) -> None:
    """A RECmd CSV in `folder` of one MountedDevices plugin row of `hive` per ValueData2 text, named \\DosDevices\\C:,
    D:, and on, each with the key's LastWrite time `written` and the text of any other `columns`."""
    with (folder / "recmd.csv").open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS)
        w.writeheader()
        for letter, text in zip("CDEFGHIJKLMN", data):
            w.writerow({"HivePath": hive, "HiveType": "SYSTEM", "Description": "Mounted Devices", "Category": "Devices",
                        "KeyPath": MOUNTED_DEVICES, "ValueType": "(plugin)", "ValueData": f"Name: \\DosDevices\\{letter}:",
                        "ValueData2": text, "LastWriteTimestamp": written, **columns})


def _mounted_devices(tmp_path, *data: str) -> list:
    """The events of write_mounted_devices's rows for DESKTOP's SYSTEM hive."""
    write_mounted_devices(tmp_path, "D:\\Evidence\\DESKTOP\\Windows\\System32\\config\\SYSTEM", MOUNTED_WRITTEN, *data)
    return list(PARSERS["recmd_csv"](ParseContext(tmp_path, Path("D:/Evidence"))))


def test_mbr_mounted_device_gives_signature_and_offset(tmp_path):
    """An MBR volume's 12 bytes are the disk signature and the partition's offset in bytes, each little-endian. The
    first byte here is a space, which the decode keeps."""
    (ev,) = _mounted_devices(tmp_path, MBR_DATA)
    assert ev.extra["DataFormat"] == "MBR partition"
    assert (ev.extra["DiskSignature"], ev.extra["PartitionOffset"], ev.extra["PartitionSector"]) == (
        "F0424120", 105_906_176, 206_848)
    assert ev.message == ("Mounted Devices: Name: \\DosDevices\\C: Data: MBR disk signature F0424120, partition offset "
                          "105,906,176 bytes (512-byte sector 206,848)")
    assert ev.extra["ValueData2"] == MBR_DATA   # the raw field stays


def test_windows_1252_characters_map_back_to_their_bytes(tmp_path):
    """RECmd writes binary data one character per byte through Windows-1252: most of 0x80 to 0x9F become characters
    above U+00FF, such as 0x83's U+0192, and the five bytes the code page leaves undefined, 0x81, 0x8D, 0x8F, 0x90, and
    0x9D, become the control characters of the same number."""
    defined, undefined = _mounted_devices(tmp_path, "Data: \xb3\u0192\xd7\xb5\x00\x00\xf0\x15\x00\x00\x00\x00",
                                          "Data: \x81\x8d\x8f\x90\x00\u20ac\u0178\x00\x00\x00\x00\x00")
    assert (defined.extra["DiskSignature"], defined.extra["PartitionOffset"]) == ("B5D783B3", 368_050_176)
    assert (undefined.extra["DiskSignature"], undefined.extra["PartitionOffset"]) == ("908F8D81", 10_452_992)
    assert undefined.extra["PartitionSector"] == 20_416


def test_value_starting_with_a_text_byte_maps_back_through_utf16(tmp_path):
    """RECmd reads a value whose first byte is a backslash, an underscore, or an opening brace as UTF-16 text, so an MBR
    value whose disk signature starts with one comes as six characters."""
    (ev,) = _mounted_devices(tmp_path, "Data: \u835c\ub5d7\x00\x10\x00\x00")
    assert (ev.extra["DiskSignature"], ev.extra["PartitionOffset"], ev.extra["PartitionSector"]) == (
        "B5D7835C", 1_048_576, 2_048)


def test_gpt_dmio_id_gives_the_partition_guid(tmp_path):
    """A GPT volume's data is DMIO:ID: and the partition GUID's 16 bytes. Newer RECmd builds write the bytes in hex
    after "Partition: GPT DMIO:ID: "; older ones wrote them as characters, as for any binary value."""
    hex_form, characters = _mounted_devices(tmp_path, GPT_DATA,
                                            'Data: DMIO:ID:gE#\x01\xab\u2030\xef\xcd\x8f\u201d\u0178\r\n"\\{')
    for ev in (hex_form, characters):
        assert ev.extra["DataFormat"] == "GPT partition"
        assert ev.extra["PartitionGuid"] == "{01234567-89ab-cdef-8f94-9f0d0a225c7b}"
    assert hex_form.message == ("Mounted Devices: Name: \\DosDevices\\C: Data: GPT partition "
                                "{01234567-89ab-cdef-8f94-9f0d0a225c7b}")


def test_device_path_is_split_into_its_parts(tmp_path):
    """A device path names the bus, the vendor and product, the instance, which holds a USB disk's serial, and the
    interface class GUID. The path can start \\??\\ or _??_."""
    usb, cd = _mounted_devices(
        tmp_path, USB_DATA,
        "Data: _??_IDE#CdRomAcme_DVD_RW____1.00____#5&1a2b3c4d&0&1.0.0#{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}")
    assert {k: usb.extra[k] for k in ("DataFormat", "DeviceBus", "DeviceVendorProduct", "DeviceInstance",
                                      "DeviceClassGuid")} == {
        "DataFormat": "Device path", "DeviceBus": "USBSTOR", "DeviceVendorProduct": "Disk&Ven_Acme&Prod_Stick&Rev_1.00",
        "DeviceInstance": "0123456789AB&0", "DeviceClassGuid": "{53f56307-b6bf-11d0-94f2-00a0c91efb8b}"}
    assert usb.message == ("Mounted Devices: Name: \\DosDevices\\C: Data: USBSTOR device Disk&Ven_Acme&Prod_Stick&Rev_1.00, "
                           "instance 0123456789AB&0, class {53f56307-b6bf-11d0-94f2-00a0c91efb8b}")
    assert (cd.extra["DeviceBus"], cd.extra["DeviceVendorProduct"], cd.extra["DeviceInstance"]) == (
        "IDE", "CdRomAcme_DVD_RW____1.00____", "5&1a2b3c4d&0&1.0.0")


def test_character_outside_the_table_stays_undecoded(tmp_path):
    """No byte gives U+0080 or U+0100 through Windows-1252, and U+FFFD stands for bytes lost before the CSV was read,
    in either reading. The data stays as it is, and the row says it wasn't decoded."""
    texts = ("Data: \x80AB\xf0\x00\x00P\x06\x00\x00\x00\x00", "Data: \u0100AB\xf0\x00\x00P\x06\x00\x00\x00\x00",
             "Data: \ufffdAB\xf0\x00\x00P\x06\x00\x00\x00\x00", "Data: \u835c\ufffd\x00\x10\x00\x00")
    for ev, text in zip(_mounted_devices(tmp_path, *texts), texts, strict=True):
        assert ev.extra["DataFormat"] == "Not decoded" and ev.extra["ValueData2"] == text
        assert ev.message == f"Mounted Devices: {ev.extra['ValueData']} Data: not decoded"
        assert not set(DECODED_KEYS) & set(ev.extra)


def test_value_of_another_shape_stays_undecoded(tmp_path):
    """Data that maps back to bytes but is neither 12 bytes, a DMIO:ID: value, nor a four-part device path isn't
    decoded: 11 bytes, a short DMIO:ID: value, a device path of three parts, and no data at all. Nor is text in the GPT
    rule's form with other than 16 bytes in hex, here 2 and 17, which the plugin never writes: it isn't read as that
    form, and as characters it is neither 12 bytes nor DMIO:ID: data."""
    texts = ("Data:  AB\xf0\x00\x00P\x06\x00\x00\x00", "Data: DMIO:ID:gE#\x01",
             "Data: \\??\\USBSTOR#Disk&Ven_Acme#0123456789AB&0", "Data: ", "Data: Partition: GPT DMIO:ID: 67-45",
             "Data: Partition: GPT DMIO:ID: " + "-".join(["AB"] * 17))
    for ev in _mounted_devices(tmp_path, *texts):
        assert ev.extra["DataFormat"] == "Not decoded" and ev.message.endswith(" Data: not decoded")
        assert not set(DECODED_KEYS) & set(ev.extra)


def test_mbr_offset_off_a_sector_boundary_gives_no_sector(tmp_path):
    """An MBR offset that isn't a multiple of 512 bytes names no sector: the row gives the offset in bytes alone."""
    (ev,) = _mounted_devices(tmp_path, "Data:  AB\xf0\x01\x00\x10\x00\x00\x00\x00\x00")
    assert (ev.extra["DataFormat"], ev.extra["DiskSignature"], ev.extra["PartitionOffset"]) == (
        "MBR partition", "F0424120", 1_048_577)
    assert "PartitionSector" not in ev.extra
    assert ev.message == ("Mounted Devices: Name: \\DosDevices\\C: Data: MBR disk signature F0424120, partition offset "
                          "1,048,577 bytes")


def test_data_of_16_bytes_or_more_of_another_length_is_not_decoded(tmp_path):
    """Only the lengths Windows writes are decoded: 12 bytes for an MBR volume, and 24 for a GPT volume's DMIO:ID: and
    partition GUID. Character-form DMIO:ID: data of 16, 20, 23, 25, and 32 bytes, other data of 16 and 20 bytes, and
    UTF-16 data of 20 bytes are each marked not decoded, and the row after them still decodes."""
    dmio = [f"Data: DMIO:ID:{'x' * (size - 8)}" for size in (16, 20, 23, 25, 32)]
    other = ["Data:  AB\xf0\x00\x00P\x06\x00\x00\x00\x00\x00\x00\x00\x00",
             "Data:  AB\xf0\x00\x00P\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
             "Data: {012345678"]
    *undecoded, after = _mounted_devices(tmp_path, *dmio, *other, MBR_DATA)
    assert len(undecoded) == 8
    for ev in undecoded:
        assert ev.extra["DataFormat"] == "Not decoded" and ev.message.endswith(" Data: not decoded")
        assert not set(DECODED_KEYS) & set(ev.extra)
    assert after.extra["DataFormat"] == "MBR partition"


def test_value_data2_without_its_data_prefix_is_not_decoded(tmp_path):
    """The plugin starts ValueData2 with "Data: ". Text without it isn't read as the value's data, even text that would
    decode after the prefix, and ValueData2 keeps it as written."""
    texts = tuple(text.removeprefix("Data: ") for text in (MBR_DATA, GPT_DATA, USB_DATA))
    for ev, text in zip(_mounted_devices(tmp_path, *texts), texts, strict=True):
        assert ev.extra["DataFormat"] == "Not decoded" and ev.extra["ValueData2"] == text
        assert ev.message.endswith(" Data: not decoded") and not set(DECODED_KEYS) & set(ev.extra)


def test_rows_cut_short_load(tmp_path):
    """A row cut short, such as the last line of a partly written CSV, has no text for the fields it lacks. A
    MountedDevices row cut after ValueData is marked not decoded, one cut before ValueData has no data to decode, a
    Services row cut before ValueData names no program, and a full row after them still decodes."""
    hive = "D:\\Evidence\\DESKTOP\\Windows\\System32\\config\\SYSTEM"
    mounted = [hive, "SYSTEM", "Mounted Devices", "Devices", MOUNTED_DEVICES, "", "(plugin)", "Name: \\DosDevices\\C:"]
    services = [hive, "SYSTEM", "Services", "Services", "ROOT\\ControlSet001\\Services", "None", "(plugin)"]
    full = [*mounted, MBR_DATA, "", "", "", "", MOUNTED_WRITTEN, ""]
    with (tmp_path / "recmd.csv").open("w", encoding="utf-8", newline="") as f:
        csv.writer(f).writerows([COLUMNS, mounted, mounted[:-1], services, full])
    cut_after_data, cut_before_data, service, after = PARSERS["recmd_csv"](ParseContext(tmp_path, Path("D:/Evidence")))
    assert cut_after_data.extra["DataFormat"] == "Not decoded" and "ValueData2" not in cut_after_data.extra
    assert cut_after_data.message == "Mounted Devices: Name: \\DosDevices\\C: Data: not decoded"
    assert cut_before_data.message == "Mounted Devices:" and "DataFormat" not in cut_before_data.extra
    assert (service.message, service.file_path, service.registry_data) == ("Services:", "", "")
    assert len(COLUMNS) == len(full) and after.extra["DataFormat"] == "MBR partition"


def test_mounted_device_ids_are_unchanged(tmp_path):
    """The decode changes the message and adds to extra, not the parts an event's ID hashes: the plugin's rows share one
    source record, so they take ordinals in their order, as before."""
    events = _mounted_devices(tmp_path, MBR_DATA, GPT_DATA, USB_DATA, "Data: \x80")
    record = f"{MOUNTED_DEVICES}||Mounted Devices"
    expected = [event_uid("DESKTOP", "registry", "DESKTOP/Windows/System32/config/SYSTEM",
                          record if n == 1 else f"{record}#{n}", "Registry Key LastWrite") for n in range(1, 5)]
    ids = EventIds()
    assert [ids("DESKTOP", ev)[0] for ev in events] == expected
    assert {ev.ts_us for ev in events} == {to_us(MOUNTED_WRITTEN)}


def test_rows_not_from_the_mounted_devices_plugin_are_left_alone(tmp_path):
    """A row of another key, or a MountedDevices row a batch dumps without the plugin, keeps its message and extra."""
    hive = "D:\\Evidence\\DESKTOP\\Windows\\System32\\config\\SYSTEM"
    with (tmp_path / "recmd.csv").open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS)
        w.writeheader()
        w.writerow({"HivePath": hive, "Description": "Volume names", "KeyPath": "ROOT\\Volumes", "ValueType": "(plugin)",
                    "ValueData": "Name: \\DosDevices\\C:", "ValueData2": MBR_DATA, "LastWriteTimestamp": MOUNTED_WRITTEN})
        w.writerow({"HivePath": hive, "Description": "Drive letters", "KeyPath": MOUNTED_DEVICES,
                    "ValueName": "\\DosDevices\\C:", "ValueType": "RegBinary", "ValueData": "20-41-42-F0",
                    "LastWriteTimestamp": MOUNTED_WRITTEN})
    other_key, dumped = PARSERS["recmd_csv"](ParseContext(tmp_path, Path("D:/Evidence")))
    assert other_key.message == "Volume names: Name: \\DosDevices\\C:" and "DataFormat" not in other_key.extra
    assert dumped.message == "Drive letters: \\DosDevices\\C: = 20-41-42-F0" and "DataFormat" not in dumped.extra


# Plugin detail CSVs: the entries' own times and the details RECmd writes beside the batch CSV
DETAILS = "20261029150921"   # the folder RECmd writes its plugin CSVs in, named for when it ran
NTUSER = "D:\\Evidence\\PC\\Users\\cody\\NTUSER.DAT"
SAM = "D:\\Evidence\\PC\\Windows\\System32\\config\\SAM"
SOFTWARE = "D:\\Evidence\\PC\\Windows\\System32\\config\\SOFTWARE"
SYSTEM = "D:\\Evidence\\PC\\Windows\\System32\\config\\SYSTEM"
WRITTEN = "2015-03-25 15:31:05.1696086"   # the batch key's LastWrite time, on most rows here
LASTWRITE = "Registry Key LastWrite"
USERASSIST_KEY = ("ROOT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\"
                  "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\\Count")
SAM_USERS = "ROOT\\SAM\\Domains\\Account\\Users"
UNINSTALL_KEY = "ROOT\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
PRODUCTS_KEY = "ROOT\\Microsoft\\Windows\\CurrentVersion\\Installer\\UserData\\S-1-5-18\\Products"
APPCOMPAT_KEY = "ROOT\\ControlSet001\\Control\\Session Manager\\AppCompatCache"
SERVICES_KEY = "ROOT\\ControlSet001\\Services"


def userassist(program: str, executed: str, written: str = WRITTEN) -> tuple[dict, dict]:
    """A UserAssist plugin row and its detail row: a program's run count and its last run, `executed`."""
    name = codecs.encode(program, "rot13")
    return ({"plugin": "UserAssist", "HivePath": NTUSER, "HiveType": "NTUSER", "Description": "UserAssist",
             "Category": "Program Execution", "KeyPath": USERASSIST_KEY, "ValueName": name, "ValueType": "RegBinary",
             "ValueData": program, "ValueData2": f"Last executed: {executed}", "ValueData3": "Run count: 14",
             "LastWriteTimestamp": written},
            {"BatchKeyPath": USERASSIST_KEY, "BatchValueName": name, "ProgramName": program, "RunCounter": "14",
             "FocusCount": "21", "FocusTime": "0d, 0h, 07m, 00s", "LastExecuted": executed})


def sam_account(rid: str, user: str, created: str = "2015-03-22 14:33:30.3285405", login: str = "",
                changed: str = "", incorrect: str = "", expires: str = "", logons: str = "0",
                invalid: str = "0") -> tuple[dict, dict]:
    """A User Accounts (SAM) plugin row and its detail row for one account, with its times and logon counts."""
    return ({"plugin": "UserAccounts", "HivePath": SAM, "HiveType": "SAM", "Description": "User Accounts (SAM)",
             "Category": "User accounts", "KeyPath": SAM_USERS, "ValueName": "V", "ValueType": "RegBinary",
             "ValueData": f"Username: {user} Id: {rid} ValidUserId: True",
             "ValueData2": f"Created: {created} Last login: {login} Last password change: {changed} "
                           f"Last incorrect password: {incorrect} Expires on: {expires}",
             "ValueData3": "Account flags: NormalUserAccount", "Comment": "User accounts in SAM hive",
             "LastWriteTimestamp": "2015-03-22 15:53:01.9000353"},
            {"ValidUserId": "True", "BatchKeyPath": f"{SAM_USERS}\\{int(rid):08X}", "BatchValueName": "V", "UserId": rid,
             "InvalidLoginCount": invalid, "TotalLoginCount": logons, "CreatedOn": created, "LastLoginTime": login,
             "LastPasswordChange": changed, "LastIncorrectPassword": incorrect, "ExpiresOn": expires, "UserName": user,
             "Comment": "Built-in account for administering the computer/domain"})


def uninstall(name: str, display: str, written_own: str, install_date: str = "20150322") -> tuple[dict, dict]:
    """An Uninstall plugin row and its detail row: an application's subkey `name`, its own key's time, and its
    InstallDate, a date with no time."""
    return ({"plugin": "UnInstall", "HivePath": SOFTWARE, "HiveType": "SOFTWARE",
             "Description": "Add/Remove Programs Entries", "Category": "Installed software", "KeyPath": UNINSTALL_KEY,
             "ValueName": "Multiple", "ValueType": "(plugin)",
             "ValueData": f"KeyName: {name} DisplayName: {display} DisplayVersion: 1.0 Publisher: Acme "
                          f"InstallDate: {install_date}",
             "ValueData2": f"Timestamp: {written_own}", "LastWriteTimestamp": WRITTEN},
            {"Timestamp": written_own, "BatchKeyPath": f"{UNINSTALL_KEY}\\{name}", "KeyName": name,
             "BatchValueName": "Multiple", "DisplayName": display, "DisplayVersion": "1.0", "Publisher": "Acme",
             "InstallDate": install_date})


def product(display: str, written_own: str, install_date: str = "20150322") -> tuple[dict, dict]:
    """A Products plugin row and its detail row: an Installer product, its own key's time, and its InstallDate."""
    return ({"plugin": "Products", "HivePath": SOFTWARE, "HiveType": "SOFTWARE", "Description": "Products",
             "Category": "Installed software", "KeyPath": PRODUCTS_KEY, "ValueName": "Multiple", "ValueType": "(plugin)",
             "ValueData": f"DisplayName: {display} PackageName: 15.0 InstallDate: {install_date} Publisher: Acme",
             "ValueData2": f"Timestamp: {written_own}", "LastWriteTimestamp": WRITTEN},
            {"Timestamp": written_own, "BatchKeyPath": f"{PRODUCTS_KEY}\\00005109090090400100000000F01FEC",
             "DisplayName": display, "BatchValueName": "Multiple", "PackageName": "15.0", "InstallDate": install_date,
             "Publisher": "Acme"})


def appcompat(position: str, path: str, modified: str, executed: bool = True) -> tuple[dict, dict]:
    """An AppCompatCache plugin row and its detail row: the entry at `position`, with the file's modified time. Builds
    since 2026.10 add whether it executed to the row's position; earlier ones write the position alone."""
    where = f"Position: {position}, Executed: Yes" if executed else f"Position: {position}"
    return ({"plugin": "AppCompat", "HivePath": SYSTEM, "HiveType": "SYSTEM", "Description": "AppCompatCache",
             "Category": "Program Execution", "KeyPath": APPCOMPAT_KEY, "ValueName": "AppCompatCache",
             "ValueType": "RegBinary", "ValueData": path, "ValueData2": f"Modified: {modified}", "ValueData3": where,
             "LastWriteTimestamp": WRITTEN},
            {"CacheEntryPosition": position, "BatchKeyPath": APPCOMPAT_KEY, "ProgramName": path,
             "BatchValueName": "AppCompatCache", "ModifiedTime": modified, "Executed": "Yes", "FromSlack": "False"})


def usbstor(serial: str, control_set: str, stamp: str, installed: str = "", connected: str = "") -> tuple[dict, dict]:
    """A USBSTOR plugin row and its detail row: a disk's serial under its make and model's key in `control_set`, with
    the plugin's Timestamp, that key's last write, and the disk's install and last connection times."""
    key = f"ROOT\\{control_set}\\Enum\\USBSTOR"
    return ({"plugin": "USBSTOR", "HivePath": SYSTEM, "HiveType": "SYSTEM", "Description": "USBSTOR", "Category": "Devices",
             "KeyPath": key, "ValueName": "Multiple", "ValueType": "(plugin)",
             "ValueData": f"Manufacturer: Ven_Acme Title: Prod_Stick Version: Rev_1.00 SerialNumber: {serial} "
                          "DeviceName:  DiskId: {662626a4-d181-11e4-9591-000c29ff2429}",
             "ValueData2": f"Timestamp: {stamp}",
             "ValueData3": f"Installed: {installed}FirstInstalled: LastConnected: {connected}LastRemoved: ",
             "LastWriteTimestamp": "2015-03-23 18:31:10.5730055"},
            {"Timestamp": stamp, "BatchKeyPath": f"{key}\\Disk&Ven_Acme&Prod_Stick&Rev_1.00", "Manufacturer": "Ven_Acme",
             "BatchValueName": "Multiple", "Title": "Prod_Stick", "Version": "Rev_1.00", "SerialNumber": serial,
             "DeviceName": "", "DiskId": "{662626a4-d181-11e4-9591-000c29ff2429}", "Installed": installed,
             "FirstInstalled": "", "LastConnected": connected, "LastRemoved": ""})


DEVICE_WRITTEN = "2020-09-19 01:00:00.0000000"   # the device plugins' batch key's LastWrite time here
USB_KEY = "ROOT\\ControlSet001\\Enum\\USB"
PORTABLE_KEY = "ROOT\\Microsoft\\Windows Portable Devices"


def scsi(serial: str, stamp: str, initial: str, installed: str,
         product: str = "Disk&Ven_VMware_&Prod_VMware_Virtual_S") -> tuple[dict, dict]:
    """A SCSI plugin row and its detail row: a disk's instance ID, which the plugin writes as its SerialNumber, under
    its make and model's key `product`, with the plugin's Timestamp, that key's last write, its InitialTimestamp,
    which it gives every instance of the model, and the disk's own install times."""
    key = "ROOT\\ControlSet001\\Enum\\SCSI"
    _, vendor, title = product.split("&")
    return ({"plugin": "SCSI", "HivePath": SYSTEM, "HiveType": "SYSTEM", "Description": "SCSI", "Category": "Devices",
             "KeyPath": key, "ValueName": "Multiple", "ValueType": "(plugin)",
             "ValueData": f"Manufacturer: {vendor} Title: {title} SerialNumber: {serial} "
                          "DeviceName: VMware Virtual disk DiskId: ",
             "ValueData2": f"Timestamp: {stamp} InitialTimestamp: {initial}",
             "ValueData3": f"Installed: {installed}FirstInstalled: {installed}LastConnected: LastRemoved: ",
             "LastWriteTimestamp": DEVICE_WRITTEN},
            {"Timestamp": stamp, "BatchKeyPath": f"{key}\\{product}", "Manufacturer": vendor,
             "BatchValueName": "Multiple", "Title": title, "SerialNumber": serial,
             "DeviceName": "VMware Virtual disk", "DiskId": "", "InitialTimestamp": initial, "Installed": installed,
             "FirstInstalled": installed, "LastConnected": "", "LastRemoved": ""})


def usb(vid_pid: str, instance: str, connected: str) -> tuple[dict, dict]:
    """A USB plugin row and its detail row: a device's instance ID, which the plugin writes as its SerialNumber, under
    its vendor and product key, with its last connection time."""
    return ({"plugin": "USB", "HivePath": SYSTEM, "HiveType": "SYSTEM", "Description": "USB", "Category": "Devices",
             "KeyPath": USB_KEY, "ValueName": "Multiple", "ValueType": "(plugin)",
             "ValueData": f"KeyName: {vid_pid} SerialNumber: {instance} ParentIdPrefix:  Service: HidUsb",
             "ValueData2": "DeviceDesc: USB Input Device FriendlyName:  DeviceName:  Location Information: Port_#0001",
             "ValueData3": f"Installed:  FirstInstalled:  LastConnected: {connected} LastRemoved: ",
             "LastWriteTimestamp": DEVICE_WRITTEN},
            {"KeyName": vid_pid, "BatchKeyPath": f"{USB_KEY}\\{vid_pid}\\{instance}", "SerialNumber": instance,
             "BatchValueName": "Multiple", "ParentidPrefix": "", "Service": "HidUsb", "DeviceDesc": "USB Input Device",
             "LocationInformation": "Port_#0001", "Installed": "", "FirstInstalled": "", "LastConnected": connected,
             "LastRemoved": ""})


def portable_device(own_key: str, serial: str, stamp: str) -> tuple[dict, dict]:
    """A Windows Portable Devices plugin row and its detail row: a device's key `own_key` below the plugin's key, the
    serial the plugin reads from it, and that key's last write."""
    device, guid = "DISK&VEN_SANDISK&PROD_CRUZER_GLIDE_3.0&REV_1.00", "{53F56307-B6BF-11D0-94F2-00A0C91EFB8B}"
    return ({"plugin": "WindowsPortableDevices", "HivePath": SOFTWARE, "HiveType": "SOFTWARE",
             "Description": "Windows Portable Devices", "Category": "Devices", "KeyPath": PORTABLE_KEY,
             "ValueName": "Multiple", "ValueType": "(plugin)",
             "ValueData": f"Device: {device} SerialNumber: {serial} Guid: {guid}",
             "ValueData2": "FriendlyName: Incident_drive", "ValueData3": f"Timestamp: {stamp}",
             "LastWriteTimestamp": DEVICE_WRITTEN},
            {"Timestamp": stamp, "BatchKeyPath": f"{PORTABLE_KEY}\\{own_key}", "Device": device,
             "BatchValueName": "Multiple", "SerialNumber": serial, "Guid": guid, "FriendlyName": "Incident_drive"})


DEVICE_CLASSES_KEY = "ROOT\\ControlSet001\\Control\\DeviceClasses"


def device_class(guid: str, name: str, serial: str, stamp: str) -> tuple[dict, dict]:
    """A Device Classes plugin row and its detail row: a disk's interface key under the class `guid`, which names the
    disk's `name` and `serial`, with that key's last write."""
    own = f"{guid}\\##?#USBSTOR#Disk&{name}#{serial}#{guid}"
    return ({"plugin": "DeviceClasses", "HivePath": SYSTEM, "HiveType": "SYSTEM", "Description": "Device Classes",
             "Category": "Devices", "KeyPath": DEVICE_CLASSES_KEY, "ValueName": "Multiple", "ValueType": "(plugin)",
             "ValueData": f"Type: Disk Name: {name} SerialNumber: {serial}", "ValueData2": f"Timestamp: {stamp}",
             "LastWriteTimestamp": WRITTEN},
            {"Timestamp": stamp, "BatchKeyPath": f"{DEVICE_CLASSES_KEY}\\{own}", "BatchValueName": "Multiple",
             "GuidFolder": guid, "DeviceType": "Disk", "Name": name, "SerialNumber": serial})


def profile(sid: str, logon: str, written_own: str = "2019-12-07 09:17:27.2565096") -> tuple[dict, dict]:
    """A ProfileList plugin row and its detail row: a profile's own key time, which the row shows, and its last logon,
    which it doesn't."""
    key = "ROOT\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList"
    return ({"plugin": "ProfileList", "HivePath": SOFTWARE, "HiveType": "SOFTWARE",
             "Description": "User Accounts (SOFTWARE)", "Category": "User accounts", "KeyPath": key,
             "ValueName": "Multiple", "ValueType": "(plugin)", "ValueData": f"KeyName: {sid}",
             "ValueData2": f"Timestamp: {written_own}", "ValueData3": f"ProfileImagePath: C:\\Users\\{sid}",
             "LastWriteTimestamp": "2020-09-19 03:36:24.4589674"},
            {"Timestamp": written_own, "BatchKeyPath": f"{key}\\{sid}", "KeyName": sid, "BatchValueName": "Multiple",
             "ProfileImagePath": f"C:\\Users\\{sid}", "LastLogonTime": logon, "LastLogoffTime": ""})


def bam(program: str, executed: str) -> tuple[dict, dict]:
    """A BAM plugin row and its detail row: a program's last execution under a user's key."""
    key = "ROOT\\ControlSet001\\Services\\bam\\State\\UserSettings\\S-1-5-21-1-2-3-1106"
    return ({"plugin": "BamDam", "HivePath": SYSTEM, "HiveType": "SYSTEM",
             "Description": "Background Activity Moderator (BAM)", "Category": "Program Execution", "KeyPath": key,
             "ValueName": program, "ValueType": "RegBinary", "ValueData": f"Program: {program}",
             "ValueData2": f"Execution time: {executed}", "LastWriteTimestamp": WRITTEN},
            {"Program": program, "BatchKeyPath": key, "ExecutionTime": executed, "BatchValueName": program})


def task(path: str, created: str, key_name: str = "{0016B09F-CFDA-4F5B-A70B-84A75599B89B}") -> tuple[dict, dict]:
    """A TaskCache plugin row and its detail row: a scheduled task, its key's name, and its created time. The plugin
    fills neither BatchKeyPath nor BatchValueName."""
    key = "ROOT\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks"
    return ({"plugin": "TaskCache", "HivePath": SOFTWARE, "HiveType": "SOFTWARE",
             "Description": "Scheduled Tasks (TaskCache)", "Category": "Persistence", "KeyPath": key, "ValueName": "",
             "ValueType": "(plugin)", "ValueData": f"Created on: {created}", "ValueData2": "Last start: , Last stop: ",
             "ValueData3": f"Path: {path}, Command: , Arguments: ", "LastWriteTimestamp": WRITTEN},
            {"Version": "3", "BatchKeyPath": "", "KeyName": key_name, "BatchValueName": "", "Path": path,
             "CreatedOn": created, "LastStart": "", "LastStop": ""})


def known_network() -> tuple[dict, dict]:
    """A Network Connections plugin row and its detail row, whose first and last connection are in local time."""
    key = "ROOT\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList"
    first, last = "2015-03-22 11:08:24.1500000", "2015-03-25 09:05:59.1380000"
    return ({"plugin": "KnownNetworks", "HivePath": SOFTWARE, "HiveType": "SOFTWARE", "Description": "Network Connections",
             "Category": "Network", "KeyPath": key, "ValueName": "Multiple", "ValueType": "(plugin)",
             "ValueData": "Name: Network Type: Wired",
             "ValueData2": f"First Connect LOCAL: {first} Last Connect LOCAL: {last}",
             "LastWriteTimestamp": "2015-03-22 15:08:24.1500000"},
            {"FirstNetwork": "Network", "BatchKeyPath": f"{key}\\Profiles\\{{F299C5AF-D490-4309-B7FD-A96B8945D950}}",
             "NetworkName": "Network", "BatchValueName": "Multiple", "NameType": "Wired", "FirstConnectLOCAL": first,
             "LastConnectedLOCAL": last, "Managed": "False"})


def service(name: str, description: str, written_own: str, parameters: str = "") -> tuple[dict, dict]:
    """A Services plugin row and its detail row: a service with its description and its key's and Parameters key's
    times."""
    return ({"plugin": "Services", "HivePath": SYSTEM, "HiveType": "SYSTEM", "Description": "Services",
             "Category": "Services", "KeyPath": SERVICES_KEY, "ValueName": "None", "ValueType": "(plugin)",
             "ValueData": f"Name: {name} Desc: {description}",
             "ValueData2": f"Name last write: {written_own}, Parameters last write: {parameters}",
             "ValueData3": "Image path: C:\\Windows\\x.exe ServiceDLL: ", "LastWriteTimestamp": WRITTEN},
            {"Name": name, "BatchKeyPath": SERVICES_KEY, "Description": description, "BatchValueName": "None",
             "DisplayName": name, "StartMode": "Automatic", "ServiceType": "Win32OwnProcess",
             "NameKeyLastWrite": written_own, "ParametersKeyLastWrite": parameters, "ImagePath": "C:\\Windows\\x.exe"})


def time_zone() -> tuple[dict, dict]:
    """A System Time Zone Information plugin row and its detail row, whose ValueData equals the batch CSV's."""
    key = "ROOT\\ControlSet001\\Control\\TimeZoneInformation"
    return ({"plugin": "TimeZoneInfo", "HivePath": SYSTEM, "HiveType": "SYSTEM",
             "Description": "System Time Zone Information", "Category": "System info", "KeyPath": key,
             "ValueName": "Bias", "ValueType": "RegDword", "ValueData": "300", "ValueData2": "300",
             "LastWriteTimestamp": WRITTEN},
            {"ValueName": "Bias", "BatchKeyPath": key, "ValueData": "300", "BatchValueName": "Bias", "ValueDataRaw": "300"})


def write_detail(path: Path, rows: list[dict]) -> None:
    """A plugin's detail CSV of `rows`, with each column the rows name, in the order they first name it."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(dict.fromkeys(k for row in rows for k in row)))
        w.writeheader()
        w.writerows(rows)


def write_run(out: Path, *pairs: tuple[dict, dict | None], ran_in: Path | None = None,
              name: str = "recmd.csv") -> Path:
    """A RECmd output folder `out` holding the batch CSV `name`, with each pair's main row, and in the folder DETAILS
    each plugin's detail CSV, named for the batch CSV and the plugin, with the pairs' detail rows in their order. A main
    row names its plugin's CSV by the absolute path RECmd writes, in the output folder it ran in (`ran_in`, else `out`),
    unless it gives a PluginDetailFile of its own. A pair whose detail row is None names its plugin's CSV and adds no
    row to it."""
    out.mkdir(parents=True, exist_ok=True)
    details: dict[str, list[dict]] = {}
    with (out / name).open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS)
        w.writeheader()
        for main, detail in pairs:
            file_name = f"{Path(name).stem}_{main['plugin']}.csv"
            w.writerow({"PluginDetailFile": str((ran_in or out) / DETAILS / file_name),
                        **{k: v for k, v in main.items() if k != "plugin"}})
            if detail is not None:
                details.setdefault(file_name, []).append(detail)
    for file_name, rows in details.items():
        write_detail(out / DETAILS / file_name, rows)
    return out


def parse(out: Path) -> tuple[list, list[str]]:
    """The events of a RECmd run's output folder, and the notes the parse gives its run."""
    ctx = ParseContext(out, Path("D:/Evidence"))
    return list(PARSERS["recmd_csv"](ctx)), ctx.notes


def uids(events: list) -> list[str]:
    """The events' IDs as one load gives them, in their order, on host PC."""
    ids = EventIds()
    return [ids("PC", ev)[0] for ev in events]


def test_entry_time_events_join_the_lastwrite_event(tmp_path):
    """An entry's own time in its plugin's detail CSV is an event of its own beside the row's LastWrite event: the same
    hive, key, value, program, and details, a source record that names the entry, and a ts_desc that names the time."""
    main, detail = userassist("Microsoft.Windows.GettingStarted", "2015-03-22 15:52:15.9991623")
    (written, executed), notes = parse(write_run(tmp_path / "output", (main, detail)))
    assert (written.ts_desc, written.ts_us) == (LASTWRITE, to_us(WRITTEN))
    assert (executed.ts_desc, executed.ts_us) == ("UserAssist last executed", to_us("2015-03-22 15:52:15.9991623"))
    assert executed.source_record == f"{USERASSIST_KEY}|{main['ValueName']}|UserAssist|Microsoft.Windows.GettingStarted"
    for name in ("artifact", "source_file", "registry_path", "registry_value", "registry_data", "file_path", "file_key",
                 "extra"):
        assert getattr(executed, name) == getattr(written, name), name
    assert (written.extra["RunCounter"], written.extra["FocusCount"], written.extra["LastExecuted"]) == (
        "14", "21", "2015-03-22 15:52:15.9991623")
    assert "BatchValueName" not in written.extra   # it repeats the row's value name
    assert written.message == f"UserAssist: {main['ValueName']} = Microsoft.Windows.GettingStarted"
    assert executed.message == f"{written.message} (UserAssist last executed)"
    assert notes == [f"{DETAILS_NOTE}1 entry time became an event."]


# The IDs the parser before the detail CSVs gave some of the LastWrite events below on host PC, by row
IDS_BEFORE_DETAILS = {0: "21ba1312abc24eebab1ad3712350c789", 2: "0778687e07407ffa49cf2f8c1778fa8d",
                      5: "fee6d532aaf100fd142297600bb455fc", 6: "13db47b71ef396607cd98d29326f4f24",
                      9: "48430578f1f77db2cd937600d02b4ca8"}


def test_lastwrite_events_and_their_ids_are_unchanged(tmp_path):
    """Reading the detail CSVs adds events and details and changes no LastWrite event: each has the time, ts_desc,
    source record, message, and fields that a parse without the detail CSVs gives it, its details keep their values,
    and its ID is the one that parse gives it and the one the parser before the detail CSVs gave it, among them a
    UserAssist row's, a SAM row's, two AppCompatCache rows' that share a source record, and a Services row's."""
    pairs = [userassist("cmd.exe", "2015-03-22 15:52:15.9991623"), userassist("calc.exe", "2015-03-22 15:53:15.0000000"),
             sam_account("500", "Administrator", login="2015-03-25 09:58:04.4373155"),
             uninstall("{A1}", "Alpha", "2015-03-22 15:01:11.6084769"), product("Office", "2015-03-22 15:01:13.6832805"),
             appcompat("0", "C:\\Windows\\system32\\LogonUI.exe", "2010-11-21 03:24:09.5725262"),
             appcompat("1", "C:\\Windows\\system32\\cmd.exe", "2010-11-21 03:23:51.7807522"),
             usbstor("0001&0", "ControlSet001", "2015-03-24 13:58:32.8293091"), known_network(),
             service("Spooler", "Loads files to memory for later printing", "2015-03-25 10:00:00.0000000"), time_zone()]
    without = write_run(tmp_path / "without" / "output", *pairs)
    shutil.rmtree(without / DETAILS)
    old, _ = parse(without)
    new, _ = parse(write_run(tmp_path / "with" / "output", *pairs))
    written = [ev for ev in new if ev.ts_desc == LASTWRITE]
    assert len(written) == len(old) == len(pairs) < len(new)
    for before, after in zip(old, written, strict=True):
        assert replace(after, extra=None) == replace(before, extra=None)
        assert {k: after.extra[k] for k in before.extra} == before.extra
    written_ids = [uid for ev, uid in zip(new, uids(new), strict=True) if ev.ts_desc == LASTWRITE]
    assert written_ids == uids(old)
    assert {n: written_ids[n] for n in IDS_BEFORE_DETAILS} == IDS_BEFORE_DETAILS


def test_entry_event_ids_survive_a_dropped_neighbor(tmp_path):
    """Each entry event's source record names its own entry, so an entry that loses its event, here one whose own time
    is now empty, leaves its neighbors' IDs as they were, and the rows' LastWrite events keep theirs."""
    alpha = uninstall("{A1}", "Alpha", "2015-03-22 15:01:11.6084769")
    gamma = uninstall("{C3}", "Gamma", "2015-03-22 15:03:11.6084769")
    beta = uninstall("{B2}", "Beta", "2015-03-22 15:02:11.6084769")
    first, _ = parse(write_run(tmp_path / "first" / "output", alpha, beta, gamma))
    second, _ = parse(write_run(tmp_path / "second" / "output", alpha, uninstall("{B2}", "Beta", ""), gamma))

    def by_record(events: list) -> dict:
        return {ev.source_record: uid for ev, uid in zip(events, uids(events), strict=True) if ev.ts_desc != LASTWRITE}

    assert set(by_record(first)) == {f"{UNINSTALL_KEY}|Multiple|Add/Remove Programs Entries|{name}"
                                     for name in ("{A1}", "{B2}", "{C3}")}
    assert by_record(second) == {k: v for k, v in by_record(first).items() if not k.endswith("{B2}")}
    assert [u for ev, u in zip(second, uids(second), strict=True) if ev.ts_desc == LASTWRITE] == [
        u for ev, u in zip(first, uids(first), strict=True) if ev.ts_desc == LASTWRITE]


def run_mru(hive: str, opened: str) -> tuple[dict, dict]:
    """A RunMRU plugin row and its detail row: a user's newest command, opened at `opened`, the RunMRU key's last write
    as RECmd gives it."""
    return plugin_entry("RunMRU", hive, f"{EXPLORER}\\RunMRU", "a", ("Executable: cmd", f"Opened on: {opened}", "MRU: 0"),
                        {"ValueName": "a", "MruPosition": "0", "Executable": "cmd", "OpenedOn": opened})


def test_batch_key_time_equal_to_lastwrite_adds_no_event(tmp_path):
    """An MRU list's opened time is its key's last write. Equal to the row's LastWrite time, to the microsecond the
    timeline keeps, it repeats the LastWrite event and adds none; a microsecond later it adds one. An entry's own key's
    time equal to the row's LastWrite adds one."""
    same, same_microsecond, later = (run_mru(NTUSER, WRITTEN), run_mru(NTUSER_OTHER, WRITTEN[:-1] + "0"),
                                     run_mru(NTUSER_THIRD, "2015-03-25 15:31:05.1696096"))
    events, notes = parse(write_run(tmp_path / "output", same, same_microsecond, later,
                                    uninstall("{A1}", "Alpha", WRITTEN)))
    assert [(ev.ts_desc, ev.ts_us) for ev in events] == [
        (LASTWRITE, to_us(WRITTEN)), (LASTWRITE, to_us(WRITTEN)), (LASTWRITE, to_us(WRITTEN)),
        ("RunMRU entry opened", to_us(WRITTEN) + 1), (LASTWRITE, to_us(WRITTEN)),
        ("Uninstall key last write", to_us(WRITTEN))]
    assert notes == [f"{DETAILS_NOTE}2 entry times became events."]


def test_pair_failing_its_key_check_adds_nothing_and_is_counted(tmp_path):
    """A row and the detail row in its place that don't name the same entry, by the plugin's key columns and the times
    the row shows, add no details and no entry event, and the run's notes count them by plugin. So do the rows of a
    detail CSV whose row count differs from the count of rows that name it. Their LastWrite events stay."""
    first, second = (appcompat("0", "C:\\a.exe", "2010-11-21 03:24:09.5725262"),
                     appcompat("1", "C:\\b.exe", "2011-01-01 00:00:00.0000000"))
    admin, guest = sam_account("500", "Administrator"), sam_account("501", "Guest")
    events, notes = parse(write_run(tmp_path / "output", (first[0], second[1]), (second[0], first[1]), admin,
                                    (guest[0], None)))
    assert [ev.ts_desc for ev in events] == [LASTWRITE] * 4
    assert not {"CacheEntryPosition", "ModifiedTime", "UserId", "TotalLoginCount"} & {k for ev in events for k in ev.extra}
    assert notes == [f"{DETAILS_NOTE}No entry time became an event. 4 rows didn't match their plugin's detail row and "
                     "added nothing (AppCompat 2, UserAccounts 2)."]


def swapped(first: tuple[dict, dict], second: tuple[dict, dict]) -> list[tuple[dict, dict]]:
    """Two rows, each with the other's detail row."""
    return [(first[0], second[1]), (second[0], first[1])]


def with_detail(pair: tuple[dict, dict], **changes: str) -> tuple[dict, dict]:
    """A row with its detail row changed."""
    main, detail = pair
    return main, {**detail, **changes}


SHARED_MODIFIED = "2010-11-21 03:24:09.5725262"
CACHED = appcompat("0", "C:\\a.exe", SHARED_MODIFIED), appcompat("1", "C:\\b.exe", SHARED_MODIFIED)
PROFILES = profile("S-1-5-21-1-2-3-1001", "2020-09-18 22:56:15.3156706"), profile("S-1-5-21-1-2-3-1002", "")
ACCOUNTS = sam_account("1000", "informant"), sam_account("1001", "admin11")
TEMPORARY = sam_account("10001", "temporary")
LOGGED_ON = sam_account("1000", "informant", login="2015-03-25 09:58:04.4373155")
APPS = uninstall("{A1}", "Alpha", "2015-03-22 15:01:11.6084769"), uninstall("{B2}", "Beta", "2015-03-22 15:01:11.6084769")
RUN = userassist("cmd.exe", "2015-03-22 15:52:15.9991623")
EXPLORER_RUN = bam("\\Device\\HarddiskVolume3\\Windows\\explorer.exe", "2015-03-22 15:52:16.0000000")
MOUSE = usb("VID_046D&PID_C077", "6&b77da92&0&1", "2020-09-18 08:00:00.0000000")
# For each part of the pair check: rows in their right pairs, and the same rows in wrong pairs that only that part
# refuses. The swapped rows share every time the row shows, so only the plugin's key column tells them apart. A
# UserAssist or BAM detail row with another program keeps the row's value name, so only the program column refuses it.
GUARDS = {
    "UserAssist program name": ([RUN], [with_detail(RUN, ProgramName="calc.exe")]),
    "BAM program": ([EXPLORER_RUN],
                    [with_detail(EXPLORER_RUN, Program="\\Device\\HarddiskVolume3\\Windows\\notepad.exe")]),
    "AppCompatCache position": (list(CACHED), swapped(*CACHED)),
    "AppCompatCache position 1 against 10": ([appcompat("10", "C:\\a.exe", SHARED_MODIFIED)],
                                             [(appcompat("10", "C:\\a.exe", SHARED_MODIFIED)[0], CACHED[1][1])]),
    "ProfileList key name": (list(PROFILES), swapped(*PROFILES)),
    "SAM user ID": (list(ACCOUNTS), swapped(*ACCOUNTS)),
    "SAM user ID 10001 against 1000": ([TEMPORARY], [(TEMPORARY[0], ACCOUNTS[0][1])]),
    "Uninstall key name": (list(APPS), swapped(*APPS)),
    "a time the row shows": ([RUN], [(RUN[0], userassist("cmd.exe", "2015-03-22 15:53:15.0000000")[1])]),
    "each time the row shows": ([LOGGED_ON], [with_detail(LOGGED_ON, LastLoginTime="2015-03-24 09:58:04.4373155")]),
    "value name": ([RUN], [with_detail(RUN, BatchValueName=codecs.encode("calc.exe", "rot13"))]),
    "key path": (list(ACCOUNTS), [with_detail(ACCOUNTS[0], BatchKeyPath="ROOT\\SAM\\Domains\\Builtin\\Users\\000003E8"),
                                  with_detail(ACCOUNTS[1], BatchKeyPath=f"{SAM_USERS}2\\000003E9")]),
    "own key below the row's": ([MOUSE], [with_detail(MOUSE, BatchKeyPath=USB_KEY), with_detail(MOUSE, BatchKeyPath="")]),
}


@pytest.mark.parametrize("guard", GUARDS)
def test_each_part_of_the_pair_check_alone_refuses_a_wrong_pair(tmp_path, guard):
    """Each part of the pair check refuses, on its own, a detail row that names another entry: the plugin's key column,
    where the swapped rows share every time the rows show (a profile's last logon, which the row doesn't show, has
    only this guard), or where a UserAssist or BAM detail row names another program under the row's value name; a
    position or a user ID that only starts the row's; a time other than the one the row shows, or
    other than one of the times it shows, here an account's last logon where its ID and name key last write are the row's;
    another value name; a key outside the row's; and, for an entry named by its own key, such as a USB device, the
    row's own key or none, which would leave the entry no name. The wrong pair adds no details and no entry event, and
    the notes count it. The same rows in their right pairs add both."""
    right, wrong = GUARDS[guard]
    events, notes = parse(write_run(tmp_path / "right" / "output", *right))
    written = [ev for ev in events if ev.ts_desc == LASTWRITE]
    assert all("BatchKeyPath" in ev.extra for ev in written) and len(events) > len(written), notes
    events, notes = parse(write_run(tmp_path / "wrong" / "output", *wrong))
    assert [ev.ts_desc for ev in events] == [LASTWRITE] * len(wrong)
    assert not any("BatchKeyPath" in ev.extra for ev in events)
    rows = f"{len(wrong)} rows didn't match their" if len(wrong) > 1 else "1 row didn't match its"
    assert notes == [f"{DETAILS_NOTE}No entry time became an event. {rows} plugin's detail row and added nothing "
                     f"({wrong[0][0]['plugin']} {len(wrong)})."]


def test_detail_csv_with_more_rows_than_rows_naming_it_pairs_none(tmp_path):
    """A plugin's CSV with more rows than the batch rows that name it, as when the batch CSV was cut short, pairs none
    of them, though its first rows are the right ones: the rows keep their LastWrite events alone, and the notes count
    them."""
    third = sam_account("1002", "temporary")
    out = write_run(tmp_path / "output", *ACCOUNTS)
    write_detail(out / DETAILS / "recmd_UserAccounts.csv", [ACCOUNTS[0][1], ACCOUNTS[1][1], third[1]])
    events, notes = parse(out)
    assert [ev.ts_desc for ev in events] == [LASTWRITE] * 2
    assert not any("UserId" in ev.extra for ev in events)
    assert notes == [f"{DETAILS_NOTE}No entry time became an event. 2 rows didn't match their plugin's detail row and "
                     "added nothing (UserAccounts 2)."]


def test_unlisted_plugin_rows_pair_only_on_their_value_and_key(tmp_path):
    """A plugin the app has no rule for still pairs a row only with a detail row that names its value and a key at or
    below its own. Swapped rows, by value or by key, add no details, and the notes count them as failed pairs; the
    same rows in their right pairs add their details."""
    def seen(value: str, own: str) -> tuple[dict, dict]:
        key = f"ROOT\\Software\\Acme\\{own}"
        return ({"plugin": "AcmeSeen", "HivePath": NTUSER, "Description": "Acme Seen", "KeyPath": key, "ValueName": value,
                 "ValueData": f"Name: {value}", "LastWriteTimestamp": WRITTEN},
                {"BatchKeyPath": key, "BatchValueName": value, "Name": value, "Seen": "2015-03-22 10:00:00.0000000"})

    by_value, by_key = (seen("a", "Seen"), seen("b", "Seen")), (seen("a", "Seen"), seen("a", "Other"))
    events, notes = parse(write_run(tmp_path / "right" / "output", *by_value, by_key[1]))
    assert [(ev.ts_desc, ev.extra["Name"]) for ev in events] == [(LASTWRITE, "a"), (LASTWRITE, "b"), (LASTWRITE, "a")]
    assert notes == [f"{DETAILS_NOTE}No entry time became an event. 3 rows of plugins the app has no times for added "
                     "details only (AcmeSeen 3)."]
    for name, pairs in (("value", swapped(*by_value)), ("key", swapped(*by_key))):
        events, notes = parse(write_run(tmp_path / name / "output", *pairs))
        assert [ev.ts_desc for ev in events] == [LASTWRITE] * 2
        assert not any("Name" in ev.extra for ev in events), name
        assert notes == [f"{DETAILS_NOTE}No entry time became an event. 2 rows didn't match their plugin's detail row "
                         "and added nothing (AcmeSeen 2)."], name


def test_empty_or_unreadable_time_adds_no_event(tmp_path):
    """A time column that is empty, a placeholder such as 1601-01-01, or text that isn't a time adds no event. Text
    that isn't empty stays in the event's details, and the run's note counts, by plugin and column, the text that is
    neither a time nor a placeholder: a time in a culture's own form, or text shaped as a time from 1971 on that names
    no real day, such as February 30."""
    account = sam_account("1000", "informant", login="1601-01-01 00:00:00", changed="not a time",
                          incorrect="2015-02-30 10:00:00")
    events, notes = parse(write_run(tmp_path / "output", account, uninstall("{A1}", "Alpha", "3/22/2015 3:01:11 PM"),
                                    product("Office", "")))
    assert [ev.ts_desc for ev in events] == [LASTWRITE, "SAM account name key last write", LASTWRITE, LASTWRITE]
    assert [events[0].extra[column] for column in ("LastLoginTime", "LastPasswordChange", "LastIncorrectPassword")] == [
        "1601-01-01 00:00:00", "not a time", "2015-02-30 10:00:00"]
    assert events[2].extra["Timestamp"] == "3/22/2015 3:01:11 PM"
    assert "Timestamp" not in events[3].extra
    assert notes == [f"{DETAILS_NOTE}1 entry time became an event. 3 entry times the app couldn't read stayed in the "
                     "details (UnInstall Timestamp 1, UserAccounts LastIncorrectPassword 1, UserAccounts "
                     "LastPasswordChange 1)."]


def test_local_time_columns_stay_in_extra(tmp_path):
    """A network's first and last connection times are written in the host's local time with no offset, so they stay
    in the event's details and make no event, and the notes don't count them as times the app doesn't take yet."""
    (written,), notes = parse(write_run(tmp_path / "output", known_network()))
    assert written.ts_desc == LASTWRITE
    assert (written.extra["FirstConnectLOCAL"], written.extra["LastConnectedLOCAL"]) == (
        "2015-03-22 11:08:24.1500000", "2015-03-25 09:05:59.1380000")
    assert notes == [f"{DETAILS_NOTE}No entry time became an event."]


def test_unlisted_plugin_times_stay_in_extra_and_are_counted(tmp_path):
    """A plugin the app has no rule for, and a time column it has no rule for in a plugin it reads, stay in the event's
    details only, and the run's notes count them."""
    key = "ROOT\\Software\\Acme\\Seen"
    newer = ({"plugin": "AcmeSeen", "HivePath": NTUSER, "Description": "Acme Seen", "KeyPath": key, "ValueName": "Multiple",
              "ValueData": "Name: x", "ValueData2": "Seen: 2015-03-22 10:00:00.0000000", "LastWriteTimestamp": WRITTEN},
             {"BatchKeyPath": f"{key}\\x", "BatchValueName": "Multiple", "Name": "x", "Seen": "2015-03-22 10:00:00.0000000"})
    account = sam_account("1000", "informant", expires="2016-01-01 00:00:00.0000000")
    events, notes = parse(write_run(tmp_path / "output", newer, account))
    assert [ev.ts_desc for ev in events] == [LASTWRITE, LASTWRITE, "SAM account name key last write"]
    assert events[0].extra["Seen"] == "2015-03-22 10:00:00.0000000"
    assert events[1].extra["ExpiresOn"] == "2016-01-01 00:00:00.0000000"
    assert to_us("2016-01-01 00:00:00") not in {ev.ts_us for ev in events}
    assert notes == [f"{DETAILS_NOTE}1 entry time became an event. 1 row of plugins the app has no times for added "
                     "details only (AcmeSeen 1). 1 time in columns the app has no rule for stayed in the details "
                     "(UserAccounts ExpiresOn 1)."]


def test_placeholder_in_a_column_without_a_rule_is_not_counted(tmp_path):
    """A placeholder such as 1601-01-01 in a column the app has no rule for is no time: it stays in the details, and
    the run's note doesn't count it among the times in such columns."""
    (written, _), notes = parse(write_run(tmp_path / "output", sam_account("1000", "informant",
                                                                          expires="1601-01-01 00:00:00.0000000")))
    assert written.extra["ExpiresOn"] == "1601-01-01 00:00:00.0000000"
    assert notes == [f"{DETAILS_NOTE}1 entry time became an event."]


def test_user_accounts_rows_carry_logon_counts_and_their_times(tmp_path):
    """A SAM account's row carries its logon counts and names in its details, and its name key last write, last logon,
    password change, and last incorrect password times are events of their own, named for the account."""
    times = ("2015-03-22 14:33:30.3285405", "2015-03-25 09:58:04.4373155", "2015-03-22 14:33:30.3754155",
             "2015-03-22 15:57:41.9562500")
    account = sam_account("1000", "informant", *times, logons="9", invalid="1")
    (written, *entries), _ = parse(write_run(tmp_path / "output", account))
    assert (written.extra["TotalLoginCount"], written.extra["InvalidLoginCount"], written.extra["UserName"]) == (
        "9", "1", "informant")
    assert [(ev.ts_desc, ev.ts_us) for ev in entries] == [
        ("SAM account name key last write", to_us(times[0])), ("SAM account last logon", to_us(times[1])),
        ("SAM account password last changed", to_us(times[2])), ("SAM account last incorrect password", to_us(times[3]))]
    assert {ev.source_record for ev in entries} == {f"{SAM_USERS}|V|User Accounts (SAM)|1000"}
    assert all(ev.extra["TotalLoginCount"] == "9" for ev in entries)


def test_detail_column_clashing_with_a_main_column_keeps_the_main_value(tmp_path):
    """A detail column named as one the event's details already hold from the batch CSV leaves the batch CSV's value
    under that name, and a detail value that differs from it is kept under the name with Detail in front. A detail
    column the details don't hold yet, such as a service's Description, keeps its own name."""
    (account, *_), (spooler, _), (zone,) = (
        parse(write_run(tmp_path / name / "output", pair))[0]
        for name, pair in (("sam", sam_account("500", "Administrator")),
                           ("service", service("Spooler", "Loads files to memory for later printing",
                                               "2015-03-25 10:00:00.0000000")),
                           ("zone", time_zone())))
    assert (account.extra["Comment"], account.extra["DetailComment"]) == (
        "User accounts in SAM hive", "Built-in account for administering the computer/domain")
    assert spooler.extra["Description"] == "Loads files to memory for later printing"
    assert spooler.message == "Services: Name: Spooler Desc: Loads files to memory for later printing"
    assert zone.extra["ValueData"] == "300" and "DetailValueData" not in zone.extra and zone.extra["ValueDataRaw"] == "300"


def test_run_without_detail_files_loads_as_before(tmp_path):
    """A run whose rows name no detail CSV loads its rows' LastWrite events alone, with the batch CSV's details and no
    note. One whose detail CSVs are gone loads the same events, and its note counts the rows naming them."""
    pairs = [userassist("cmd.exe", "2015-03-22 15:52:15.9991623"), sam_account("500", "Administrator")]
    unnamed = write_run(tmp_path / "unnamed" / "output", *(({**main, "PluginDetailFile": ""}, None) for main, _ in pairs))
    gone = write_run(tmp_path / "gone" / "output", *pairs)
    shutil.rmtree(gone / DETAILS)
    (plain, notes), (without, gone_notes) = parse(unnamed), parse(gone)
    assert [ev.ts_desc for ev in plain] == [ev.ts_desc for ev in without] == [LASTWRITE] * 2
    assert all(set(ev.extra) <= {"HiveType", "Category", "ValueType", "ValueData", "ValueData2", "ValueData3", "Comment"}
               for ev in plain)
    assert [replace(ev, extra=None) for ev in plain] == [replace(ev, extra=None) for ev in without]
    assert notes == []
    assert gone_notes == [f"{DETAILS_NOTE}No entry time became an event. 2 rows named a detail file that isn't there or "
                          "can't be read."]


def test_detail_path_outside_the_run_folder_is_refused_and_counted(tmp_path):
    """A detail CSV is read only from the run's own output folder, by the last two parts of the path its row names: the
    folder RECmd named for the run and the file. So a copied or moved case reads its own copy. A path whose last two
    parts aren't two plain names, such as one through .. or at a drive's root, is refused, a CSV the output folder
    doesn't hold is read from nowhere else, and the run's notes count both."""
    elsewhere = tmp_path / "elsewhere" / "recmd_UserAssist.csv"
    write_detail(elsewhere, [userassist("evil.exe", "2015-03-22 15:52:15.9991623")[1]])
    rows = [userassist("cmd.exe", "2015-03-22 15:52:15.9991623")]
    for path in ("D:\\cases\\copy\\..\\recmd_UserAssist.csv", "C:\\recmd_UserAssist.csv", "recmd_UserAssist.csv",
                 str(elsewhere)):
        main, _ = userassist("evil.exe", "2015-03-22 15:52:15.9991623")
        rows.append(({**main, "PluginDetailFile": path}, None))
    out = write_run(tmp_path / "copy" / "runs" / "r1" / "output", *rows,
                    ran_in=Path("D:/cases/original/runs/r1/output"))
    events, notes = parse(out)
    assert [ev.ts_desc for ev in events] == [LASTWRITE, "UserAssist last executed", *[LASTWRITE] * 4]
    assert events[0].extra["ProgramName"] == "cmd.exe"
    assert not any("ProgramName" in ev.extra for ev in events[2:])
    assert notes == [f"{DETAILS_NOTE}1 entry time became an event. 3 rows named a detail file the load may not read. 1 "
                     "row named a detail file that isn't there or can't be read."]


def test_install_date_follows_the_chosen_rule(tmp_path):
    """An application's InstallDate is a date with no time of day, so it stays a field in the event's details and makes
    no event, while its Uninstall or Installer product key's own time does make one."""
    events, notes = parse(write_run(tmp_path / "output", uninstall("{A1}", "Alpha", "2015-03-22 15:01:11.6084769"),
                                    product("Office", "2015-03-22 15:01:13.6832805")))
    assert [ev.ts_desc for ev in events] == [LASTWRITE, "Uninstall key last write", LASTWRITE,
                                             "Installer product key last write"]
    assert all(ev.extra["InstallDate"] == "20150322" for ev in events)
    assert to_us("2015-03-22 00:00:00") not in {ev.ts_us for ev in events}
    assert notes == [f"{DETAILS_NOTE}2 entry times became events."]


def test_usbstor_timestamp_shared_by_two_serials_stays_in_extra(tmp_path):
    """The USBSTOR plugin's Timestamp is the last write of the make and model's key, which two serials share here under
    each control set, so it can't say which disk's time it is. It stays in the details, makes no event, and the notes
    don't count it."""
    stamp = "2015-03-24 13:58:32.8293091"
    pairs = [usbstor(serial, control_set, stamp) for control_set in ("ControlSet001", "ControlSet002")
             for serial in ("0001&0", "0002&0")]
    events, notes = parse(write_run(tmp_path / "output", *pairs))
    assert [ev.ts_desc for ev in events] == [LASTWRITE] * 4
    assert {ev.extra["Timestamp"] for ev in events} == {stamp}
    assert to_us(stamp) not in {ev.ts_us for ev in events}
    assert notes == [f"{DETAILS_NOTE}No entry time became an event."]


def test_scsi_timestamps_shared_by_two_serials_stay_in_extra(tmp_path):
    """The SCSI plugin's Timestamp is the last write of the make and model's key too, so two disks of one model share
    it, often the second disk's arrival. Its InitialTimestamp is the first disk's, which it gives each disk of the
    model. Both stay in the details, make no event, and the notes don't count them. Each disk's own install times are
    events of their own, named for its model's key and its instance ID."""
    stamp, initial = "2020-09-17 15:51:34.7045592", "2020-09-17 15:51:35.1000000"
    first = scsi("5&22be343f&0&000000", stamp, initial, "2020-09-17 15:51:34.7204304")
    second = scsi("5&22be343f&0&000100", stamp, initial, "2020-09-18 09:00:00.0000000")
    events, notes = parse(write_run(tmp_path / "output", first, second))
    assert not {to_us(stamp), to_us(initial)} & {ev.ts_us for ev in events}
    assert {(ev.extra["Timestamp"], ev.extra["InitialTimestamp"]) for ev in events} == {(stamp, initial)}
    assert Counter((ev.ts_desc, ev.source_record.rsplit("|", 1)[-1]) for ev in events if ev.ts_desc != LASTWRITE) == {
        (desc, serial): 1 for desc in ("SCSI device installed", "SCSI device first installed")
        for serial in ("5&22be343f&0&000000", "5&22be343f&0&000100")}
    assert notes == [f"{DETAILS_NOTE}4 entry times became events."]


def test_profile_times_recmd_wrote_without_the_low_half_s_zeros_are_rebuilt(tmp_path):
    """RECmd's ProfileList plugin joins a time's halves as hex text without padding the low half, so a low half below
    0x10000000 loses its leading zeros and the time comes out before 1829. The event takes the time the halves give,
    the details keep RECmd's text, and the run's note counts the rebuilt time. A 1601-01-01 logoff and a logon on a day
    no calendar has add nothing, and the run still loads."""
    high, low = 0x01D68E12, 0x0ABCDEF1
    misread = int(f"{high:X}{low:X}", 16)   # as the plugin's GetDateTime joins them
    text = f"{datetime(1601, 1, 1) + timedelta(seconds=misread // 10**7):%Y-%m-%d %H:%M:%S}.{misread % 10**7:07d}"
    row, detail = profile("S-1-5-21-1-2-3-1001", text)
    detail["LastLogoffTime"] = "1601-01-01 00:00:00.0000000"
    damaged = profile("S-1-5-21-1-2-3-1002", "1627-02-30 00:00:00.0000000")
    events, notes = parse(write_run(tmp_path / "output", (row, detail), damaged))
    (logon,) = [ev for ev in events if ev.ts_desc == "Profile last logon"]
    assert text.startswith("16") and logon.extra["LastLogonTime"] == text
    assert logon.ts_us == ((high << 32 | low) - 116_444_736_000_000_000) // 10
    assert "Profile last logoff" not in {ev.ts_desc for ev in events}
    assert notes == [f"{DETAILS_NOTE}3 entry times became events. 1 entry time that RECmd wrote before 1829 was rebuilt "
                     "(ProfileList LastLogonTime 1)."]


def test_usbstor_device_times_stay_in_extra_and_are_counted(tmp_path):
    """The USBSTOR plugin's install and connection times, which the app doesn't time, stay in the details and make no
    event, and the run's notes count each filled one by column."""
    installed, connected = "2015-03-23 18:31:10.5730055", "2015-03-24 13:38:00.0342227"
    (written,), notes = parse(write_run(tmp_path / "output", usbstor("0001&0", "ControlSet001",
                                                                     "2015-03-24 13:58:32.8293091", installed, connected)))
    assert (written.ts_desc, written.extra["Installed"], written.extra["LastConnected"]) == (LASTWRITE, installed, connected)
    assert notes == [f"{DETAILS_NOTE}No entry time became an event. 2 times in columns the app has no rule for stayed "
                     "in the details (USBSTOR Installed 1, USBSTOR LastConnected 1)."]


def test_appcompat_entry_is_named_by_its_position_in_either_form(tmp_path):
    """An AppCompatCache entry is named by its position in the cache, which RECmd writes alone or followed by whether it
    executed, so a case run with either build pairs its rows, and a row's details tell its entries apart."""
    old = appcompat("0", "C:\\Windows\\system32\\LogonUI.exe", "2010-11-21 03:24:09.5725262", executed=False)
    new = appcompat("1", "C:\\Windows\\system32\\cmd.exe", "2010-11-21 03:23:51.7807522")
    events, _ = parse(write_run(tmp_path / "output", old, new))
    assert [(ev.ts_desc, ev.source_record.rsplit("|", 1)[-1]) for ev in events] == [
        (LASTWRITE, "AppCompatCache"), ("AppCompatCache file modified", "0"),
        (LASTWRITE, "AppCompatCache"), ("AppCompatCache file modified", "1")]
    assert events[1].ts_us == to_us("2010-11-21 03:24:09.5725262")


def test_device_class_entries_are_named_by_their_own_key(tmp_path):
    """A device class entry is named by its own key below the row's, since two devices may share a name and a serial."""
    pairs = [device_class(guid, "Ven_Acme", "0001&0", stamp)
             for guid, stamp in (("{53f56307-b6bf-11d0-94f2-00a0c91efb8b}", "2015-03-23 18:31:10.5730055"),
                                 ("{6ac27878-a6fa-4155-ba85-f98f491d4f33}", "2015-03-23 18:31:11.0000000"))]
    events, _ = parse(write_run(tmp_path / "output", *pairs))
    entries = [ev for ev in events if ev.ts_desc == "Device class key last write"]
    assert [ev.source_record.split("|", 3)[-1] for ev in entries] == [
        f"{guid}\\##?#USBSTOR#Disk&Ven_Acme#0001&0#{guid}" for guid in ("{53f56307-b6bf-11d0-94f2-00a0c91efb8b}",
                                                                       "{6ac27878-a6fa-4155-ba85-f98f491d4f33}")]
    assert len(set(uids(events))) == len(events)


PORTABLE_DEVICE = "SWD#WPDBUSENUM#_??_USBSTOR#DISK&VEN_SANDISK&PROD_CRUZER_GLIDE_3.0&REV_1.00#4C530000261130109435&0#"
DISK_INTERFACE, VOLUME_INTERFACE = "{53F56307-B6BF-11D0-94F2-00A0C91EFB8B}", "{53F5630D-B6BF-11D0-94F2-00A0C91EFB8B}"


def sharing_a_serial(plugin: str, first: str) -> list[tuple[dict, dict]]:
    """Two entries of a device plugin under one batch key that the plugin gives one SerialNumber, the first with its
    times at `first`. A USB device without a serial of its own takes an instance ID from the hub port it used, so a
    mouse and a keyboard that used one port share it. A SCSI disk's instance ID names its controller and its position
    on the bus, so two disk models that held one position share it. Here two portable device keys carry one serial,
    which naming a portable device entry by its own key keeps apart should a host hold such keys."""
    later = "2020-09-18 09:00:00.0000000"
    if plugin == "USB":
        return [usb("VID_046D&PID_C077", "6&b77da92&0&1", first), usb("VID_413C&PID_2113", "6&b77da92&0&1", later)]
    if plugin == "SCSI":
        return [scsi("5&22be343f&0&000000", first, first, first, "Disk&Ven_Acme&Prod_Old_Disk"),
                scsi("5&22be343f&0&000000", later, later, later, "Disk&Ven_Acme&Prod_New_Disk")]
    return [portable_device(f"Devices\\{PORTABLE_DEVICE}{guid}", "4C530000261130109435&0", time)
            for guid, time in ((DISK_INTERFACE, first), (VOLUME_INTERFACE, later))]


SHARED_SERIAL_NAMES = {   # the names the two entries' events take
    "USB": ["VID_046D&PID_C077\\6&b77da92&0&1", "VID_413C&PID_2113\\6&b77da92&0&1"],
    "SCSI": ["Disk&Ven_Acme&Prod_Old_Disk|5&22be343f&0&000000", "Disk&Ven_Acme&Prod_New_Disk|5&22be343f&0&000000"],
    "WindowsPortableDevices": [f"Devices\\{PORTABLE_DEVICE}{guid}" for guid in (DISK_INTERFACE, VOLUME_INTERFACE)],
}


def ids_by_entry(events: list) -> dict:
    """Each entry event's ID, by its detail row's key and serial and its time's name."""
    return {(ev.extra["BatchKeyPath"], ev.extra["SerialNumber"], ev.ts_desc): uid
            for ev, uid in zip(events, uids(events), strict=True) if ev.ts_desc != LASTWRITE}


@pytest.mark.parametrize("plugin", SHARED_SERIAL_NAMES)
def test_device_entries_sharing_a_serial_keep_their_ids(tmp_path, plugin):
    """Two USB devices or two SCSI disk models can share the SerialNumber the plugin writes under one batch key, so a
    USB entry is named by its own key, and a SCSI entry by its model's key and instance ID. A portable device entry is
    named by its own key too, which keeps apart two keys of one serial. Each entry's events get a source record of
    their own, and when the first entry loses its events, here because its times are now empty, the second entry's
    events keep their IDs."""
    first, _ = parse(write_run(tmp_path / "first" / "output", *sharing_a_serial(plugin, "2020-09-18 08:00:00.0000000")))
    pairs = sharing_a_serial(plugin, "")
    second, _ = parse(write_run(tmp_path / "second" / "output", *pairs))
    entries = [ev for ev in first if ev.ts_desc != LASTWRITE]
    each = len(entries) // 2
    assert [ev.source_record.split("|", 3)[-1] for ev in entries] == [
        name for name in SHARED_SERIAL_NAMES[plugin] for _ in range(each)]
    before, after = ids_by_entry(first), ids_by_entry(second)
    assert len(before) == len(entries)
    kept = (pairs[1][1]["BatchKeyPath"], pairs[1][1]["SerialNumber"])
    assert len(after) == each
    assert after == {k: uid for k, uid in before.items() if k[:2] == kept}


def test_entry_events_keep_their_row_s_pivots(tmp_path):
    """An entry event is the same kind of record as its row's LastWrite event, so it offers the same pivots. A kind's
    reason for refusing a time window, that the row's time is a key's last write that its entries share, isn't given
    for an entry's own time, so each kind's entry event keeps the window pivot."""
    pairs = [userassist("cmd.exe", "2015-03-22 15:52:15.9991623"),
             bam("\\Device\\HarddiskVolume3\\Windows\\explorer.exe", "2015-03-22 15:52:16.0000000"),
             service("Spooler", "Loads files to memory for later printing", "2015-03-25 10:00:00.0000000"),
             task("\\Microsoft\\Windows\\Registry\\RegIdleBackup", "2015-03-22 14:41:36.2089124"),
             appcompat("0", "C:\\Windows\\system32\\cmd.exe", "2010-11-21 03:24:09.5725262")]
    events, _ = parse(write_run(tmp_path / "output", *pairs))

    def refused(ev) -> set[str]:
        return {e["pivot"] for e in kind_of(asdict(ev))[0]["not_offered"] if fits(e.get("when", {}), asdict(ev))}

    kinds = []
    for written, entry in zip(events[::2], events[1::2], strict=True):
        kind = kind_of(asdict(written))[0]["kind"]
        assert (written.ts_desc, kind_of(asdict(entry))[0]["kind"]) == (LASTWRITE, kind)
        assert "window" in refused(written) and "window" not in refused(entry), kind
        kinds.append(kind)
    assert kinds == ["userassist", "bam", "recmd_services", "recmd_taskcache", "appcompatcache"]


def test_installer_products_are_named_by_display_name_and_key_time(tmp_path):
    """An Installer product's DisplayName can be empty, as one is on CFReDS, so a product's entry events are named by
    its display name and its key's time, and two products without a display name each get a source record."""
    events, _ = parse(write_run(tmp_path / "output", product("", "2015-03-22 15:01:11.6084769"),
                                product("", "2015-03-22 15:01:13.6832805")))
    assert [ev.source_record.split("|", 3)[-1] for ev in events if ev.ts_desc != LASTWRITE] == [
        "|2015-03-22 15:01:11.6084769", "|2015-03-22 15:01:13.6832805"]


NTUSER_OTHER = "D:\\Evidence\\PC\\Users\\admin11\\NTUSER.DAT"
NTUSER_THIRD = "D:\\Evidence\\PC\\Users\\temporary\\NTUSER.DAT"
USRCLASS = "D:\\Evidence\\PC\\Users\\cody\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat"
EXPLORER = "ROOT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer"
COMDLG = f"{EXPLORER}\\ComDlg32"
ADAPTERS_KEY = "ROOT\\ControlSet001\\Control\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318}"
PACKAGES_KEY = "ROOT\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppModel\\Repository\\Packages"
SHOWN = "2015-03-23 20:26:56.0780002"   # the time two entries of a plugin share
SCSI_TIMES = ("2020-09-17 15:51:34.7045592", "2020-09-17 15:51:35.1000000", "2020-09-17 15:51:34.7204304")


def plugin_entry(plugin: str, hive: str, key: str, value: str, data: tuple[str, ...], detail: dict,
                 own_key: str = "") -> tuple[dict, dict]:
    """A row of `plugin` naming `value` under `key`, with its ValueData, ValueData2, and ValueData3 texts `data`, and its
    detail row: the `detail` columns, at the row's key or at the entry's own key `own_key` below it."""
    main = {"plugin": plugin, "HivePath": hive, "Description": plugin, "KeyPath": key, "ValueName": value,
            "ValueType": "(plugin)", **dict(zip(("ValueData", "ValueData2", "ValueData3"), data)),
            "LastWriteTimestamp": WRITTEN}
    return main, {"BatchKeyPath": f"{key}\\{own_key}" if own_key else key, "BatchValueName": value, **detail}


# Two entries of each plugin the app times, which share every time their rows show, so that swapped, only the
# plugin's key columns tell them apart. Where a key column is the value name or is written from it, as UserAssist's
# ROT13 name, BAM's program path, and the Office and MRU lists' value names are, the two value names differ too.
# Elsewhere they share one: the plugin's own, such as Multiple, or a list's position name in two users' hives, whose
# keys RECmd names alike.
ENTRIES = {
    "AppCompat": CACHED,
    "UserAssist": (RUN, userassist("calc.exe", RUN[1]["LastExecuted"])),
    "BamDam": tuple(bam(f"\\Device\\HarddiskVolume3\\Windows\\{name}", SHOWN) for name in ("explorer.exe", "notepad.exe")),
    "DeviceClasses": tuple(device_class("{53f56307-b6bf-11d0-94f2-00a0c91efb8b}", "Ven_Acme", serial, SHOWN)
                           for serial in ("0001&0", "0002&0")),
    "UnInstall": APPS,
    "Products": (product("Office", SHOWN), product("Visio", SHOWN)),
    "UserAccounts": ACCOUNTS,
    "ProfileList": PROFILES,
    "VolumeInfoCache": tuple(
        plugin_entry("VolumeInfoCache", SOFTWARE, "ROOT\\Microsoft\\Windows Search\\VolumeInfoCache", "Multiple",
                     (f"DriveName: {drive} VolumeLabel:  DriveType: Fixed", f"Timestamp: {SHOWN}"),
                     {"Timestamp": SHOWN, "DriveName": drive, "VolumeLabel": "", "DriveType": "Fixed"}, drive)
        for drive in ("C:", "D:")),
    "NetworkAdapters": tuple(
        plugin_entry("NetworkAdapters", SYSTEM, ADAPTERS_KEY, "Multiple",
                     (f"DriveName: {name} DriverDate: 6-21-2006", f"DeviceInstanceid: {instance}", f"Timestamp: {SHOWN}"),
                     {"Timestamp": SHOWN, "DriverDesc": name, "DeviceInstanceid": instance}, own)
        for own, name, instance in (("0000", "WAN Miniport (SSTP)", "ROOT\\MS_SSTPMINIPORT\\0000"),
                                    ("0001", "WAN Miniport (L2TP)", "ROOT\\MS_L2TPMINIPORT\\0000"))),
    "Services": (service("Spooler", "Loads files to memory for later printing", SHOWN),
                 service("Schedule", "Runs tasks at the times set for them", SHOWN)),
    "OfficeMRU": tuple(
        plugin_entry("OfficeMRU", NTUSER, "ROOT\\Software\\Microsoft\\Office\\15.0\\Word\\File MRU", item,
                     (f"File name: {file}", f"Last opened: {SHOWN}", "Last closed: "),
                     {"ValueName": item, "LastOpened": SHOWN, "LastClosed": "", "FileName": file})
        for item, file in (("Item 1", "C:\\Users\\cody\\a.docx"), ("Item 2", "C:\\Users\\cody\\b.docx"))),
    "TypedURLs": tuple(
        plugin_entry("TypedURLs", hive, "ROOT\\Software\\Microsoft\\Internet Explorer\\TypedURLs", "url1",
                     (url, f"Timestamp: {SHOWN}"), {"Timestamp": SHOWN, "Url": url})
        for hive, url in ((NTUSER, "http://www.bing.com/"), (NTUSER_OTHER, "http://example.com/"))),
    "LastVisitedPidlMRU": tuple(
        plugin_entry("LastVisitedPidlMRU", NTUSER, f"{COMDLG}\\LastVisitedPidlMRU", value,
                     (f"Exe: {exe} Folder: {exe} Absolute path: ", f"Opened: {SHOWN}", f"MRU: {value} Details: "),
                     {"ValueName": value, "MruPosition": value, "Executable": exe, "OpenedOn": SHOWN})
        for value, exe in (("0", "WINWORD.EXE"), ("1", "EXCEL.EXE"))),
    "CIDSizeMRU": tuple(
        plugin_entry("CIDSizeMRU", hive, f"{COMDLG}\\CIDSizeMRU", "0", (exe, f"Opened: {SHOWN}", f"Mru: {position}"),
                     {"Executable": exe, "MRUPosition": position, "OpenedOn": SHOWN})
        for hive, exe, position in ((NTUSER, "WINWORD.EXE", "0"), (NTUSER_OTHER, "EXCEL.EXE", "1"))),
    "FirstFolder": tuple(
        plugin_entry("FirstFolder", hive, f"{COMDLG}\\FirstFolder", "0",
                     (f"Exe: {exe} Folder: C:\\Downloads", f"Opened: {SHOWN}", f"Mru: {position}"),
                     {"Executable": exe, "FolderName": "C:\\Downloads", "MRUPosition": position, "OpenedOn": SHOWN})
        for hive, exe, position in ((NTUSER, "iexplore.exe", "0"), (NTUSER_OTHER, "chrome.exe", "1"))),
    "RunMRU": tuple(
        plugin_entry("RunMRU", NTUSER, f"{EXPLORER}\\RunMRU", value,
                     (f"Executable: {command}", f"Opened on: {SHOWN}", f"MRU: {position}"),
                     {"ValueName": value, "MruPosition": position, "Executable": command, "OpenedOn": SHOWN})
        for value, command, position in (("a", "cmd", "0"), ("b", "regedit", "1"))),
    "OpenSavePidlMRU": tuple(
        plugin_entry("OpenSavePidlMRU", NTUSER, f"{COMDLG}\\OpenSavePidlMRU", "0",
                     (f"Extension: {extension} Absolute path: {file}", f"Opened: {SHOWN}", "MRU: 0 Details: "),
                     {"Extension": extension, "ValueName": "0", "MruPosition": "0", "AbsolutePath": file,
                      "OpenedOn": SHOWN}, extension)
        for extension, file in (("*", "report.xps"), ("docx", "letter.docx"))),
    "RecentDocs": tuple(
        plugin_entry("RecentDocs", NTUSER, f"{EXPLORER}\\RecentDocs", "0",
                     (f"Lnk: {lnk} Target: {target}", f"Opened on: {SHOWN} Ext last open: {SHOWN}", "MRU: 0"),
                     {"Extension": extension, "ValueName": "0", "TargetName": target, "LnkName": lnk, "MruPosition": "0",
                      "OpenedOn": SHOWN, "ExtensionLastOpened": SHOWN}, extension)
        for extension, lnk, target in ((".txt", "notes.lnk", "notes.txt"), (".docx", "letter.lnk", "letter.docx"))),
    "WordWheelQuery": tuple(
        plugin_entry("WordWheelQuery", hive, f"{EXPLORER}\\WordWheelQuery", "0", (f"Term: {term}", f"MRU: {position}"),
                     {"SearchTerm": term, "MruPosition": position, "KeyName": "WordWheelQuery",
                      "LastWriteTimestamp": SHOWN})
        for hive, term, position in ((NTUSER, "secret", "0"), (NTUSER_OTHER, "pricing", "1"))),
    "AppPaths": tuple(
        plugin_entry("AppPaths", SOFTWARE, "ROOT\\Microsoft\\Windows\\CurrentVersion\\App Paths", "Multiple",
                     (f"FileName: {file} Path1: C:\\Program Files\\{file} Path2: ", f"Timestamp: {SHOWN}"),
                     {"Timestamp": SHOWN, "FileName": file, "Path1": f"C:\\Program Files\\{file}", "Path2": ""}, file)
        for file in ("chrome.exe", "excel.exe")),
    "TaskCache": (task("\\Microsoft\\Windows\\Registry\\RegIdleBackup", SHOWN),
                  task("\\Microsoft\\Windows\\Defrag\\ScheduledDefrag", SHOWN, "{7E1F2A3B-4C5D-4E6F-8A9B-0C1D2E3F4A5B}")),
    "USB": (MOUSE, usb("VID_413C&PID_2113", "6&b77da92&0&2", MOUSE[1]["LastConnected"])),
    "SCSI": (scsi("5&22be343f&0&000000", *SCSI_TIMES), scsi("5&22be343f&0&000100", *SCSI_TIMES)),
    "WindowsApp": tuple(
        plugin_entry("WindowsApp", USRCLASS, PACKAGES_KEY, "Multiple",
                     (f"KeyName: {name} DisplayName: {name}", f"InstallTime: {SHOWN}"),
                     {"KeyName": name, "DisplayName": name, "InstallTime": SHOWN}, name)
        for name in ("Microsoft.WindowsCalculator_8wekyb3d8bbwe", "Microsoft.WindowsNotepad_8wekyb3d8bbwe")),
    "JumplistData": tuple(
        plugin_entry("JumplistData", NTUSER, "ROOT\\Software\\Microsoft\\Windows\\CurrentVersion\\Search\\JumplistData",
                     name, (f"Name: {name}", f"Executed: {SHOWN}"), {"JumpListName": name, "ExecutedOn": SHOWN})
        for name in ("{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\notepad.exe",
                     "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\mstsc.exe")),
    "TerminalServerClient": tuple(
        plugin_entry("TerminalServerClient", NTUSER, "ROOT\\Software\\Microsoft\\Terminal Server Client", "UsernameHint",
                     (host, f"User: PC\\cody, MRU: {position}", f"Last modified: {SHOWN}"),
                     {"HostName": host, "Username": "PC\\cody", "MRUPosition": position, "LastModified": SHOWN})
        for host, position in (("DC01", "0"), ("FILESERVER", "1"))),
    "WindowsPortableDevices": tuple(
        portable_device(f"Devices\\SWD#WPDBUSENUM#_??_USBSTOR#DISK&VEN_SANDISK#{serial}#{DISK_INTERFACE}", serial, SHOWN)
        for serial in ("4C530000261130109435&0", "4C530000261130109436&0")),
    "RADAR": tuple(
        plugin_entry("RADAR", SOFTWARE, "ROOT\\Microsoft\\RADAR\\HeapLeakDetection", "Multiple",
                     (f"Filename: {file}", f"LastDetectionTime: {SHOWN}", "KeyName: DiagnosedApplications"),
                     {"KeyName": "DiagnosedApplications", "Filename": file, "LastDetectionTime": SHOWN},
                     f"DiagnosedApplications\\{file}")
        for file in ("winlogon.exe", "explorer.exe")),
}


@pytest.mark.parametrize("plugin", [name for name, spec in PLUGINS.items() if spec.times])
def test_each_timed_plugin_s_key_columns_refuse_its_entries_swapped(tmp_path, plugin):
    """Two entries of each plugin the app times, which share every time their rows show, pair with their own detail
    rows: each row gets its details, and each entry's events a source record of their own. Swapped, the pairs fail on
    the plugin's key columns: they add nothing, and the note counts them. Given back their own key columns and value
    name, the swapped detail rows pair, so nothing else tells the entries apart."""
    entries = ENTRIES[plugin]
    key_columns = {column for column, _, _ in PLUGINS[plugin].checks}
    events, notes = parse(write_run(tmp_path / "right" / "output", *entries))
    written = [ev for ev in events if ev.ts_desc == LASTWRITE]
    assert len(written) == 2 and all(key_columns <= set(ev.extra) for ev in written), notes
    assert len({ev.source_record for ev in events if ev.ts_desc != LASTWRITE}) == 2
    events, notes = parse(write_run(tmp_path / "swapped" / "output", *swapped(*entries)))
    assert [ev.ts_desc for ev in events] == [LASTWRITE] * 2
    assert not any(key_columns & set(ev.extra) for ev in events)
    assert notes == [f"{DETAILS_NOTE}No entry time became an event. 2 rows didn't match their plugin's detail row and "
                     f"added nothing ({plugin} 2)."]
    named = [(main, {**detail, **{column: own[column] for column in (*key_columns, "BatchValueName")}})
             for (main, detail), (_, own) in zip(swapped(*entries), entries, strict=True)]
    events, notes = parse(write_run(tmp_path / "named" / "output", *named))
    assert all(key_columns <= set(ev.extra) for ev in events if ev.ts_desc == LASTWRITE), notes


# The time columns RECmd fills with the last write of the list key that holds the entry as a value, such as an MRU
# list's key for its newest entry. Each other timed column holds a time of the entry's own key or value, such as
# TypedURLs' Timestamp, the data of the url's value in the TypedURLsTime key.
BATCH_KEY_TIMES = {("LastVisitedPidlMRU", "OpenedOn"), ("CIDSizeMRU", "OpenedOn"), ("FirstFolder", "OpenedOn"),
                   ("RunMRU", "OpenedOn"), ("OpenSavePidlMRU", "OpenedOn"), ("RecentDocs", "OpenedOn"),
                   ("WordWheelQuery", "LastWriteTimestamp")}


@pytest.mark.parametrize(("plugin", "column"), [(plugin, column) for plugin, spec in PLUGINS.items()
                                                for column in spec.times])
def test_entry_time_at_its_row_s_lastwrite_is_an_event_unless_it_is_the_list_key_s(tmp_path, plugin, column):
    """An entry's time at its row's LastWrite time is an event of its own when it is a time of the entry's own key or
    value, such as an Uninstall entry's key, a SAM account's Names key, a device's Properties time, a BAM value's run
    time, or a URL's typed time from TypedURLsTime, which the browser writes with the TypedURLs key. It is none when it
    is the last write of the list key that holds the entry as a value, as an MRU list's opened time and WordWheelQuery's
    time are. At another time, each is an event. A time column the entry leaves empty takes another time the row
    shows."""
    main, detail = ENTRIES[plugin][0]
    time = detail[column] or next(detail[other] for other in PLUGINS[plugin].times if detail[other])
    detail = {**detail, column: time}
    assert to_us(main["LastWriteTimestamp"]) != to_us(time)
    ts_desc = PLUGINS[plugin].times[column]

    def times(pair: tuple[dict, dict], name: str) -> list[int]:
        events, notes = parse(write_run(tmp_path / name / "output", pair))
        assert "didn't match" not in notes[0], notes
        return [ev.ts_us for ev in events if ev.ts_desc == ts_desc]

    assert times((main, detail), "elsewhere") == [to_us(time)]
    at_lastwrite = times(({**main, "LastWriteTimestamp": time}, detail), "at")
    assert at_lastwrite == ([] if (plugin, column) in BATCH_KEY_TIMES else [to_us(time)])
