"""Parses RECmd batch-mode CSV output.

Each row is one key or value the batch file selected, timed by the key's LastWrite time. That
time says when the key last changed, not when the value was set.

The plugins whose rows name a program give the row a file path and file key, so Same file reaches the program's
other records: AppCompatCache, BAM, Run and RunOnce values, Services, and UserAssist (_program).

PluginDetailFile names a plugin's own CSV in the run's output folder, an absolute path on the analysis machine. It is
kept relative to the run folder, because the case folder's name, often a client's or a case's, would otherwise match
every search for that word.

The MountedDevices plugin's data is decoded into the message and extra (_mounted_device): an MBR volume's disk signature
and partition offset, a GPT volume's partition GUID, or a device path's parts. ValueData2 keeps the data as RECmd wrote it.

A plugin's CSV holds one row for each batch row that names it, in the same order, with the entry's own columns, such
as a SAM account's logon counts and its last logon. The parser reads it only where the load may: by the last two parts
of the path the row names, the folder RECmd named for its run and the file, under the folder that holds the batch CSV.
In a tool's run that is the run's own output folder, so a copied or moved case reads its own copy; output found in the
evidence reads only the CSVs beside it that intake hashed (ParseContext.beside). It pairs the rows in order, and keeps
a pair only when the detail row names the row's value, names no key outside the row's, names the same entry by the
plugin's key columns (PLUGINS), and holds no listed time the row's data (SHOWN) doesn't show, other than in a column RECmd
never writes there (Plugin.unshown). A CSV with another count of rows than the rows naming it pairs none. A pair adds
the detail row's columns to the row's details, and each time column PLUGINS names adds an event of the entry's own:
its ts_desc names the time, and its source record names the entry by its name columns, so its ID
doesn't depend on its neighbors. Most times are an entry's own key's or value's, such as a service key's last write or
a BAM value's run time, and add an event even when they equal the row's LastWrite time. Some are the last write of the
list key that holds the entry as a value, as an MRU list's opened time is for the list's newest entry. Those add none
when they equal the row's LastWrite time (Plugin.batch_key_times). No placeholder such as 1601-01-01 or text that
isn't a time adds one. The row's LastWrite event is unchanged but for the details. Times the table doesn't name stay
in the details: local times, culture-formatted text, a date with no time of day (InstallDate), and one the plugin
shares across entries, such as the USBSTOR and SCSI plugins' Timestamp and the SCSI plugin's InitialTimestamp. The
ProfileList plugin writes some logon and logoff times wrongly, before 1829, and the parser rebuilds them
(Plugin.unpadded). The run's note (DETAILS_NOTE) counts the entry times, the rebuilt times, the text in a time column
the table names that is neither a time nor a placeholder, the pairs that failed, the rows of plugins the table doesn't
name, the times in columns of a plugin it names that it neither times nor holds (Plugin.held), and the rows naming a
CSV the load may not read or can't find.
"""

from __future__ import annotations

import csv
import re
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path, PureWindowsPath
from uuid import UUID

from ..events import EARLIEST_YEAR, Event, from_us, to_us
from .common import (
    DETAILS_NOTE,
    EXECUTABLE_END,
    ParseContext,
    command_file,
    evidence_relative,
    file_key,
    known_folder,
    output_paths,
    read_csv_rows,
)

OUTPUT_FILE = "recmd.csv"
EXTRA_COLUMNS = ("HiveType", "Category", "ValueType", "ValueData", "ValueData2", "ValueData3", "Comment",
                 "Deleted", "PluginDetailFile")
LASTWRITE = "Registry Key LastWrite"


def parse_recmd(ctx: ParseContext) -> Iterator[Event]:
    tally = Tally()
    for path in output_paths(ctx, "recmd", OUTPUT_FILE):
        rows = list(read_csv_rows(path))
        for row, (plugin, detail) in zip(rows, _details(rows, path, ctx, tally), strict=True):
            yield from _row_events(row, plugin, detail, ctx, tally)
    if tally.named:
        ctx.notes.append(tally.note())


def _row_events(row: dict, plugin: str, detail: dict | None, ctx: ParseContext, tally: Tally) -> Iterator[Event]:
    """The row's LastWrite event, and with a detail row that passed its check, the entry's own times as events."""
    key, value_name = row.get("KeyPath", ""), row.get("ValueName", "")
    # A row cut short, such as the last line of a partly written CSV, has None for each field it lacks
    data, data2, data3 = (row.get(k) or "" for k in ("ValueData", "ValueData2", "ValueData3"))
    description = row.get("Description", "")
    # The Services plugin writes the text "None" as every row's value name, which names no value
    named = "" if description == "Services" and value_name == "None" else value_name
    detail_text = f" {named} = {data}" if named else (f" {data}" if data else "")
    path, path_key = _program(description, key, value_name, data, data3)
    message = f"{description}:{detail_text}".strip()
    extra = {k: _run_relative(row[k], ctx) if k == "PluginDetailFile" else row[k] for k in EXTRA_COLUMNS if row.get(k)}
    if data.startswith(MOUNTED_NAME) and key.rpartition("\\")[2].lower() == MOUNTED_DEVICES_KEY:
        words, fields = _mounted_device(data2)
        message, extra = f"{message} Data: {words}", extra | fields
    spec = PLUGINS.get(plugin, UNLISTED)
    paired = detail is not None and _same_entry(spec, row, detail)
    if paired:
        _add_details(extra, detail)
    elif detail is not None:
        tally.failed[plugin] += 1
    written = Event(
        ts_us=to_us(row.get("LastWriteTimestamp")),
        ts_desc=LASTWRITE,
        artifact="registry",
        source_file=evidence_relative(row.get("HivePath", ""), ctx.evidence_root),
        source_record=f"{key}|{value_name}|{description}",
        message=message,
        registry_path=key,
        registry_value=value_name,
        file_path=path,
        file_key=path_key,
        # A value's data in its own column, as Sysmon 13's is. A plugin's key row names
        # no value, and its ValueData is the plugin's summary of the key, so that stays in extra only. Extra keeps
        # ValueData on every row for the host identity readers.
        registry_data=data if value_name else "",
        extra=extra,
    )
    yield written
    if not paired:
        return
    if plugin not in PLUGINS:
        tally.unlisted_rows[plugin] += 1
        return
    tally.unlisted_times.update((plugin, column) for column, value in detail.items()
                                if column not in spec.times and column not in spec.held and _is_time(value))
    record = f"{written.source_record}|{_entry_name(spec, row, detail)}"
    for column, ts_desc in spec.times.items():
        text = (detail.get(column) or "").strip()
        ts = to_us(text)
        if ts is None and column in spec.unpadded and (ts := _repadded(text)) is not None:
            tally.rebuilt[(plugin, column)] += 1
        if ts is None and text and not _placeholder(text):
            tally.unreadable[(plugin, column)] += 1
        if ts is None or (ts == written.ts_us and column in spec.batch_key_times):
            continue
        tally.entries += 1
        yield Event(ts_us=ts, ts_desc=ts_desc, artifact=written.artifact, source_file=written.source_file,
                    source_record=record, message=f"{message} ({ts_desc})", registry_path=key,
                    registry_value=value_name, file_path=path, file_key=path_key, registry_data=written.registry_data,
                    extra=extra)


# ---------- plugin detail CSVs ----------

@dataclass(frozen=True)
class Plugin:
    """What the parser takes from one plugin's detail CSV. A pair of a batch row and a detail row stands only when each
    check's detail column, written into its pattern at {}, is found in the batch row's column. Each time column gives
    an event with its ts_desc, and a list key time (batch_key_times) gives none where it equals the row's LastWrite
    time; the name columns name the entry in its source record. A held column reads as a time but stays in the details,
    and the run's note doesn't count it."""
    checks: tuple[tuple[str, str, str], ...]   # (detail column, batch column, pattern)
    times: dict[str, str] = field(default_factory=dict)   # time column: ts_desc
    names: tuple[str, ...] = ()
    unshown: frozenset[str] = frozenset()   # time columns the batch row doesn't show, so the pair check skips them
    held: frozenset[str] = frozenset()
    # Time columns RECmd fills with the last write of the list key that holds the entry as a value, such as an MRU
    # list's key for its newest entry. Where BatchKeyPath is the entry's own key, its last write is the entry's own time.
    batch_key_times: frozenset[str] = frozenset()
    # Time columns RECmd builds by joining a FILETIME's high and low halves as hex text without padding the low half to
    # 8 digits, so a time whose low half is below 0x10000000 comes out before 1829. _repadded rebuilds it.
    unpadded: frozenset[str] = frozenset()


SAME = r"\A{}\Z"   # the whole column
OWN_KEY = "BatchKeyPath"   # as a name column: the entry's own key, the part of BatchKeyPath below the row's key
# The USBSTOR and SCSI plugins' Timestamp is the last write of the device's make, model, and revision key, the
# BatchKeyPath they write, so every serial of one model shares it and it can't say which device's time it is
SHARED_TIMESTAMP = frozenset({"Timestamp"})
# The SCSI plugin reads InitialTimestamp from the Device Parameters\Storport key of the first instance under the model's
# key, and gives it to every instance of the model
SCSI_SHARED = SHARED_TIMESTAMP | {"InitialTimestamp"}
DEVICE_TIMES = ("Installed", "FirstInstalled", "LastConnected", "LastRemoved")
# An MRU list's opened time is its key's last write, which RECmd gives the list's newest entry
OPENED_ON = frozenset({"OpenedOn"})
# The plugins whose detail CSVs the parser reads, by the name after the last underscore of the CSV's name. A plugin
# without times adds details only. KnownNetworks' times are local, ETW's is culture-formatted text, and the USBSTOR and
# SCSI plugins' Timestamp and the SCSI plugin's InitialTimestamp are shared by every serial of a model, so those columns
# are held. A time in any other column
# that a plugin doesn't time, such as USBSTOR's device times, stays in the details, and the run's note counts it. An
# Uninstall or Installer product entry's InstallDate is a date with no time of day, which isn't read as a time. The
# ts_desc texts are part of the events' IDs. The MRU lists' opened times and WordWheelQuery's time are their list
# key's last write, so each adds no event where it equals the row's LastWrite time (batch_key_times). TypedURLs' time
# is the data of the url's value in the TypedURLsTime key, a value's own time, so it adds an event even then.
# A device's SerialNumber doesn't name it alone. A USB device without a serial of its own takes an instance ID from
# the hub port it used, which the next such device on that port takes too, and a SCSI instance ID names a controller
# and a position on its bus, which another model can hold. So USB, Device Classes, and portable device entries are
# named by their own key, and SCSI entries, whose BatchKeyPath is the model's key, by that key and the instance ID.
PLUGINS: dict[str, Plugin] = {
    "AppCompat": Plugin((("CacheEntryPosition", "ValueData3", r"^Position: {}(?:,|$)"),),
                        {"ModifiedTime": "AppCompatCache file modified"}, ("CacheEntryPosition",)),
    "UserAssist": Plugin((("ProgramName", "ValueData", SAME),), {"LastExecuted": "UserAssist last executed"},
                         ("ProgramName",)),
    "BamDam": Plugin((("Program", "ValueData", r"^Program: {}$"),), {"ExecutionTime": "BAM last executed"},
                     ("Program",)),
    "DeviceClasses": Plugin((("Name", "ValueData", r" Name: {} SerialNumber:"),
                             ("SerialNumber", "ValueData", r" SerialNumber: {}$")),
                            {"Timestamp": "Device class key last write"}, (OWN_KEY,)),
    "UnInstall": Plugin((("KeyName", "ValueData", r"^KeyName: {} DisplayName:"),),
                        {"Timestamp": "Uninstall key last write"}, ("KeyName",)),
    "Products": Plugin((("DisplayName", "ValueData", r"^DisplayName: {} PackageName:"),
                        ("Timestamp", "ValueData2", r"^Timestamp: {}$")),
                       {"Timestamp": "Installer product key last write"}, ("DisplayName", "Timestamp")),
    "UserAccounts": Plugin((("UserId", "ValueData", r" Id: {} ValidUserId:"),),
                           {"CreatedOn": "SAM account name key last write", "LastLoginTime": "SAM account last logon",
                            "LastPasswordChange": "SAM account password last changed",
                            "LastIncorrectPassword": "SAM account last incorrect password"}, ("UserId",)),
    "ProfileList": Plugin((("KeyName", "ValueData", r"^KeyName: {}$"),),
                          {"Timestamp": "Profile key last write", "LastLogonTime": "Profile last logon",
                           "LastLogoffTime": "Profile last logoff"}, ("KeyName",),
                          unshown=frozenset({"LastLogonTime", "LastLogoffTime"}),
                          unpadded=frozenset({"LastLogonTime", "LastLogoffTime"})),
    "VolumeInfoCache": Plugin((("DriveName", "ValueData", r"^DriveName: {} VolumeLabel:"),),
                              {"Timestamp": "Volume info cache key last write"}, ("DriveName",)),
    "NetworkAdapters": Plugin((("DeviceInstanceid", "ValueData2", r"^DeviceInstanceid: {}$"),),
                              {"Timestamp": "Network adapter key last write"}, ("DeviceInstanceid",)),
    "Services": Plugin((("Name", "ValueData", r"^Name: {} Desc:"),),
                       {"NameKeyLastWrite": "Service key last write",
                        "ParametersKeyLastWrite": "Service Parameters key last write"}, ("Name",)),
    "OfficeMRU": Plugin((("ValueName", "ValueName", SAME),),
                        {"LastOpened": "Office file last opened", "LastClosed": "Office file last closed"},
                        ("ValueName",)),
    "TypedURLs": Plugin((("Url", "ValueData", SAME),), {"Timestamp": "URL last typed"}, ("Url",)),
    "LastVisitedPidlMRU": Plugin((("ValueName", "ValueName", SAME),), {"OpenedOn": "LastVisitedPidlMRU entry opened"},
                                 ("ValueName",), batch_key_times=OPENED_ON),
    "CIDSizeMRU": Plugin((("MRUPosition", "ValueData3", r"^Mru: {}$"),), {"OpenedOn": "CIDSizeMRU entry opened"},
                         ("MRUPosition",), batch_key_times=OPENED_ON),
    "FirstFolder": Plugin((("MRUPosition", "ValueData3", r"^Mru: {}$"),), {"OpenedOn": "FirstFolder entry opened"},
                          ("MRUPosition",), batch_key_times=OPENED_ON),
    "RunMRU": Plugin((("ValueName", "ValueName", SAME),), {"OpenedOn": "RunMRU entry opened"}, ("ValueName",),
                     batch_key_times=OPENED_ON),
    "OpenSavePidlMRU": Plugin((("Extension", "ValueData", r"^Extension: {} Absolute path:"),
                               ("ValueName", "ValueName", SAME)),
                              {"OpenedOn": "OpenSavePidlMRU entry opened"}, ("Extension", "ValueName"),
                              batch_key_times=OPENED_ON),
    "RecentDocs": Plugin((("ValueName", "ValueName", SAME), ("LnkName", "ValueData", r"^Lnk: {} Target:"),
                          ("MruPosition", "ValueData3", r"^MRU: {}$")),
                         {"OpenedOn": "RecentDocs entry opened",
                          "ExtensionLastOpened": "RecentDocs extension last opened"}, ("Extension", "ValueName"),
                         batch_key_times=OPENED_ON),
    "WordWheelQuery": Plugin((("MruPosition", "ValueData2", r"^MRU: {}$"),),
                             {"LastWriteTimestamp": "WordWheelQuery key last write"}, ("MruPosition",),
                             unshown=frozenset({"LastWriteTimestamp"}), batch_key_times=frozenset({"LastWriteTimestamp"})),
    "AppPaths": Plugin((("FileName", "ValueData", r"^FileName: {} Path1:"),), {"Timestamp": "App Paths key last write"},
                       ("FileName",)),
    "TaskCache": Plugin((("Path", "ValueData3", r"^Path: {}, Command:"), ("CreatedOn", "ValueData", r"^Created on: {}$")),
                        {"CreatedOn": "Scheduled task created", "LastStart": "Scheduled task last started",
                         "LastStop": "Scheduled task last stopped"}, ("KeyName",)),
    "USB": Plugin((("SerialNumber", "ValueData", r" SerialNumber: {} ParentIdPrefix:"),),
                  dict(zip(DEVICE_TIMES, ("USB device installed", "USB device first installed",
                                          "USB device last connected", "USB device last removed"), strict=True)),
                  (OWN_KEY,)),
    "SCSI": Plugin((("SerialNumber", "ValueData", r" SerialNumber: {} DeviceName:"),),
                   dict(zip(DEVICE_TIMES, ("SCSI device installed", "SCSI device first installed",
                                           "SCSI device last connected", "SCSI device last removed"), strict=True)),
                   (OWN_KEY, "SerialNumber"), held=SCSI_SHARED),
    "WindowsApp": Plugin((("KeyName", "ValueData", r"^KeyName: {} DisplayName:"),),
                         {"InstallTime": "Windows app installed"}, ("KeyName",)),
    "JumplistData": Plugin((("JumpListName", "ValueName", SAME),), {"ExecutedOn": "JumplistData last executed"},
                           ("JumpListName",)),
    "TerminalServerClient": Plugin((("HostName", "ValueData", SAME),),
                                   {"LastModified": "Remote Desktop server entry last modified"}, ("HostName",)),
    "WindowsPortableDevices": Plugin((("SerialNumber", "ValueData", r" SerialNumber: {} Guid:"),),
                                     {"Timestamp": "Portable device key last write"}, (OWN_KEY,)),
    "RADAR": Plugin((("Filename", "ValueData", r"^Filename: {}$"),), {"LastDetectionTime": "RADAR last detected"},
                    ("Filename",)),
    "KnownNetworks": Plugin((("NetworkName", "ValueData", r"^Name: {} Type:"),),
                            held=frozenset({"FirstConnectLOCAL", "LastConnectedLOCAL"})),
    "ETW": Plugin((("Provider", "ValueData", r"^Provider: {}$"),), held=frozenset({"LastWriteTimestamp"})),
    "MountedDevices": Plugin((("DeviceName", "ValueData", r"^Name: {}$"),)),
    "AppCompatFlags2": Plugin((("Path", "ValueData", r"^Path: {}$"),)),
    "FirewallRules": Plugin((("Action", "ValueData", r"^Action: {} Active:"), ("Name", "ValueData2", r" Name: {}$"),
                             ("App", "ValueData3", r" App: {}$"))),
    "Taskband": Plugin((("LnkName", "ValueData", r"^Lnk Name: {}$"),)),
    "TimeZoneInfo": Plugin((("ValueName", "ValueName", SAME),)),
    "SAMBuiltin": Plugin((("GroupName", "ValueData", r"^GroupName: {}$"),)),
    "FileExts": Plugin((("Extension", "ValueData", r"^Extension: {}$"),)),
    "IconLayouts": Plugin((("Name", "ValueData", r"^Name: {}$"),)),
    "NetworkSetup2": Plugin((("ProtocolList", "ValueData", r"^ProtocolList: {} Alias:"),)),
    "USBSTOR": Plugin((("SerialNumber", "ValueData", r" SerialNumber: {} DeviceName:"),), held=SHARED_TIMESTAMP),
}
UNLISTED = Plugin(())   # a plugin the table doesn't name: the value and key checks only, and details only
SHOWN = ("ValueData", "ValueData2", "ValueData3")   # where a batch row shows its entry's times
TIME_TEXT = re.compile(r"^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}")


@dataclass
class Tally:
    """What a parse took from the detail CSVs and what it left, for the run's note."""
    named: int = 0   # rows that name a detail CSV
    entries: int = 0   # entry times that became events
    rebuilt: Counter = field(default_factory=Counter)   # by plugin and column: unpadded times _repadded rebuilt
    unreadable: Counter = field(default_factory=Counter)   # by plugin and column: text neither a time nor a placeholder
    failed: Counter = field(default_factory=Counter)   # by plugin: rows whose pair failed its check
    unlisted_rows: Counter = field(default_factory=Counter)   # by plugin: rows of plugins PLUGINS doesn't name
    unlisted_times: Counter = field(default_factory=Counter)   # by plugin and column: times it neither times nor holds
    refused: int = 0   # rows naming a CSV the load may not read
    missing: int = 0   # rows naming a CSV that isn't there or can't be read

    def note(self) -> str:
        """The run's note, which starts with DETAILS_NOTE."""
        sentences = [f"{_count(self.entries, 'entry time')} became {'an event' if self.entries == 1 else 'events'}."
                     if self.entries else "No entry time became an event."]
        if self.rebuilt:
            n = self.rebuilt.total()
            sentences.append(f"{_count(n, 'entry time')} that RECmd wrote before 1829 {'was' if n == 1 else 'were'} "
                             f"rebuilt ({_by_column(self.rebuilt)}).")
        if self.unreadable:
            sentences.append(f"{_count(self.unreadable.total(), 'entry time')} the app couldn't read stayed in the "
                             f"details ({_by_column(self.unreadable)}).")
        if self.failed:
            n = self.failed.total()
            sentences.append(f"{_count(n, 'row')} didn't match {'its' if n == 1 else 'their'} plugin's detail row and "
                             f"added nothing ({_by(self.failed)}).")
        if self.unlisted_rows:
            sentences.append(f"{_count(self.unlisted_rows.total(), 'row')} of plugins the app has no times for added "
                             f"details only ({_by(self.unlisted_rows)}).")
        if self.unlisted_times:
            sentences.append(f"{_count(self.unlisted_times.total(), 'time')} in columns the app has no rule for stayed "
                             f"in the details ({_by_column(self.unlisted_times)}).")
        if self.refused:
            sentences.append(f"{_count(self.refused, 'row')} named a detail file the load may not read.")
        if self.missing:
            sentences.append(f"{_count(self.missing, 'row')} named a detail file that isn't there or can't be read.")
        return DETAILS_NOTE + " ".join(sentences)


def _count(n: int, word: str) -> str:
    return f"{n:,} {word}" if n == 1 else f"{n:,} {word}s"


def _by(counts: Counter) -> str:
    return ", ".join(f"{name} {n:,}" for name, n in sorted(counts.items()))


def _by_column(counts: Counter) -> str:
    """Counts by plugin and column, as _by writes them."""
    return _by(Counter({f"{plugin} {column}": n for (plugin, column), n in counts.items()}))


def _details(rows: list[dict], batch: Path, ctx: ParseContext, tally: Tally) -> list[tuple[str, dict | None]]:
    """Each row's plugin and its row in the plugin's detail CSV, in order, or None: for a row that names no CSV, one
    the load may not read or can't find, and each row naming a CSV whose count of rows differs from the count of rows
    naming it, which the tally counts as failed."""
    files: list[Path | None] = []
    for row in rows:
        text = row.get("PluginDetailFile") or ""
        path = None
        if text:
            tally.named += 1
            path = _detail_path(text, batch, ctx)
            if path is None:
                tally.refused += 1
        files.append(path)
    found: dict[Path, Iterator[dict] | None] = {}
    for path, naming in Counter(p for p in files if p is not None).items():
        try:
            detail_rows = list(read_csv_rows(path))
        except (OSError, csv.Error):
            tally.missing += naming
            continue
        found[path] = iter(detail_rows) if len(detail_rows) == naming else None
    paired = []
    for path in files:
        plugin = path.stem.rpartition("_")[2] if path is not None else ""
        if path not in found:
            paired.append((plugin, None))
        elif (detail_rows := found[path]) is None:
            tally.failed[plugin] += 1
            paired.append((plugin, None))
        else:
            paired.append((plugin, next(detail_rows)))
    return paired


def _detail_path(text: str, batch: Path, ctx: ParseContext) -> Path | None:
    """The detail CSV a row's PluginDetailFile names, where the load may read it, or None: the path's last two parts,
    two plain names, under the folder that holds the batch CSV. A tool's run reads any file there that stays in its
    output folder; a load of found output reads only the CSVs intake hashed (ParseContext.beside)."""
    parts = PureWindowsPath(text).parts[-2:]
    if len(parts) != 2 or not all(_plain(part) for part in parts):
        return None
    candidate = batch.parent / parts[0] / parts[1]
    if ctx.files:
        return {str(p).lower(): p for p in ctx.beside}.get(str(candidate).lower())
    resolved = candidate.resolve()
    return resolved if resolved.is_relative_to(ctx.output_dir.resolve()) else None


def _plain(part: str) -> bool:
    """Whether a path part is a plain file or folder name: not empty, . or .., a drive, or a root."""
    return part not in ("", ".", "..") and not any(c in part for c in ':\\/')


def _same_entry(spec: Plugin, row: dict, detail: dict) -> bool:
    """Whether a batch row and the detail row in its place name the same entry: the same value, no key outside the
    row's and a key below it for an entry named by its own key, the plugin's key columns, and no listed time the row's
    data doesn't show, other than in an unshown column."""
    if detail.get("BatchValueName") != (row.get("ValueName") or ""):
        return False
    key, batch_key = (row.get("KeyPath") or "").lower(), (detail.get("BatchKeyPath") or "").lower()
    if batch_key and batch_key != key and not batch_key.startswith(f"{key}\\"):
        return False
    if OWN_KEY in spec.names and not batch_key[len(key) + 1:]:   # without a key of its own, entries would share a name
        return False
    for column, batch_column, pattern in spec.checks:
        value = detail.get(column)
        if value is None or not re.search(pattern.replace("{}", re.escape(value)), row.get(batch_column) or ""):
            return False
    shown = " ".join(row.get(k) or "" for k in SHOWN)
    return all((detail.get(column) or "") in shown for column in spec.times if column not in spec.unshown)


def _add_details(extra: dict, detail: dict) -> None:
    """Add a detail row's filled columns to a row's details. A column the details hold already keeps the batch row's
    value, and a detail value that differs is kept under the name with Detail in front. BatchValueName repeats the
    row's value name and is left out."""
    for column, value in detail.items():
        if not column or column == "BatchValueName" or not value or not isinstance(value, str):
            continue
        if column not in extra:
            extra[column] = value
        elif extra[column] != value:
            extra[f"Detail{column}"] = value


def _entry_name(spec: Plugin, row: dict, detail: dict) -> str:
    """The entry's name in its events' source record: its name columns' values, joined by |."""
    key = row.get("KeyPath") or ""
    return "|".join((detail.get(OWN_KEY) or "")[len(key) + 1:] if column == OWN_KEY else detail.get(column) or ""
                    for column in spec.names)


def _is_time(value) -> bool:
    """Whether a detail value is a time the timeline could hold."""
    return isinstance(value, str) and bool(TIME_TEXT.match(value)) and to_us(value) is not None


def _placeholder(text: str) -> bool:
    """Whether a time column's text is a placeholder: a time before the earliest the timeline holds, such as
    1601-01-01, which to_us reads as no time."""
    return bool(TIME_TEXT.match(text)) and int(text[:4]) < EARLIEST_YEAR


FILETIME_ZERO = datetime(1601, 1, 1)
FILETIME_EPOCH = 116_444_736_000_000_000   # 1970-01-01 as a FILETIME, in 100 ns ticks
HIGH_DIGITS = 7   # a FILETIME's high half in hex, for every time from 1829 to 5254
FULL_TIME = re.compile(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\.(\d{7})")


def _repadded(text: str) -> int | None:
    """The time in epoch microseconds that a FILETIME's halves give, where RECmd joined them as hex text without
    padding the low half (Plugin.unpadded) and wrote the result to the 100 ns. That text's hex digits are the high
    half's 7, then the low half's without its leading zeros. None for text that isn't such a time, such as a
    1601-01-01 time, or whose rebuilt time is still a placeholder."""
    match = FULL_TIME.fullmatch(text)
    if match is None:
        return None
    try:
        span = datetime.strptime(match[1], "%Y-%m-%d %H:%M:%S") - FILETIME_ZERO
    except ValueError:   # not a real date or time, such as 2020-02-30
        return None
    digits = f"{(span.days * 86_400 + span.seconds) * 10_000_000 + int(match[2]):X}"
    # A zero high half gives 8 digits or fewer too, so those stay placeholders, which loses a low half below 0x10
    if not HIGH_DIGITS + 1 < len(digits) < HIGH_DIGITS + 8:
        return None
    us = ((int(digits[:HIGH_DIGITS], 16) << 32 | int(digits[HIGH_DIGITS:], 16)) - FILETIME_EPOCH) // 10
    return us if from_us(us).year >= EARLIEST_YEAR else None


# What each plugin's row holds, from the Szechuan copies: AppCompatCache's ValueData is the entry's path, SYSVOL\ for the system
# volume on a domain controller ("SYSVOL\Windows\System32\services.exe") and a drive letter elsewhere, and a packaged app's
# entry is tab-separated text; BAM names the program as "Program: \Device\HarddiskVolume3\Windows\explorer.exe"; a Run value's
# data is a command line; Services keeps "Image path: <command line> ServiceDLL: <dll>" in ValueData3, where the command line
# can be "\SystemRoot\System32\drivers\x.sys", "System32\drivers\x.sys", or "%SystemRoot%\system32\svchost.exe -k netsvcs",
# and a svchost-hosted service is keyed from its ServiceDLL, which is a path or, where the service has the value in its key
# and in its Parameters subkey, "Services ServiceDll: <dll> / Parameter ServiceDll: <dll>" (svchost reads Parameters first);
# UserAssist writes a known folder as "{System}\NOTEPAD.EXE", or "{1AC14E77-...}\x.exe" where it has no name for it.
SYSVOL = re.compile(r"^SYSVOL(?=\\)", re.IGNORECASE)
IMAGE_PATH = re.compile(r"^Image path:\s*(.*?)\s*(?:ServiceDLL:.*)?$", re.DOTALL)
SERVICE_DLL = re.compile(r"ServiceDLL:\s*(.*?)\s*$", re.DOTALL)
SERVICE_DLL_SOURCE = re.compile(r"\s*/?\s*(?:Services|Parameter) ServiceDll:\s*")
BAM_PROGRAM = "Program: "
RUN_KEY = "\\currentversion\\run"   # Run, RunOnce, RunServices, and the rest, as the Run key kind in the pivot table matches


def _service_dll(data3: str) -> str:
    """The ServiceDLL path of a Services row's ValueData3, or "". Where the row names two, the Parameters subkey's wins, as
    it does for svchost; an empty one falls to the other."""
    found = SERVICE_DLL.search(data3)
    return next(reversed([p for p in SERVICE_DLL_SOURCE.split(found.group(1)) if p]), "") if found else ""


def _program(description: str, key: str, value_name: str, data: str, data3: str) -> tuple[str, str]:
    """The program a row names and its file key, or ("", ""). The path is as the plugin wrote it, reduced as a service's
    command line is (command_file) where the plugin holds one; the key has the system volume, a folder variable, a device
    path, or a known folder written out. A path with no backslash is no file: an app ID, a counter, or a packaged app's
    tab-separated entry, unless it is a bare program name such as ctfmon.exe, which keeps its name and no key. A row can
    have a path and no key, such as a Run value under %APPDATA%, which needs the user's profile (the file name still joins:
    Same file name)."""
    if description == "AppCompatCache":
        path, mapped = ("" if "\t" in data else data), SYSVOL.sub("C:", data)
    elif description == "Background Activity Moderator (BAM)":
        path = mapped = data.removeprefix(BAM_PROGRAM)
    elif description == "UserAssist":
        path, mapped = data, known_folder(data) or data
    elif description == "Services":
        image = IMAGE_PATH.match(data3)
        path = mapped = command_file(image.group(1)) if image else ""
        # A service hosted in svchost.exe is the DLL it loads, not the host every such service shares
        dll = _service_dll(data3)
        if dll and path.lower().rpartition("\\")[2] == "svchost.exe" and file_key(command_file(dll)):
            path = mapped = command_file(dll)
    elif value_name and RUN_KEY in key.lower():
        path = mapped = command_file(data)
    else:
        return "", ""
    if "\\" in path:
        return path, file_key(mapped)
    # A bare program name such as ctfmon.exe has no path to key, but it is a file name: Same file name reaches it.
    return (path, "") if EXECUTABLE_END.search(path) and not any(c.isspace() for c in path) else ("", "")


def _run_relative(path_text: str, ctx: ParseContext) -> str:
    """A path in this run's output folder, relative to the run folder; any other path, such as one in output found in
    the evidence, as written."""
    try:
        return PureWindowsPath(path_text).relative_to(PureWindowsPath(ctx.output_dir.parent)).as_posix()
    except ValueError:
        return path_text


# The MountedDevices plugin writes a value as "Name: <value name>" in ValueData and "Data: <data>" in ValueData2. Where it
# has the GPT rule, data that starts with the 7 characters DMIO:ID and is at least 16 bytes long is written as
# "Partition: GPT DMIO:ID: " and the data's last 16 bytes in hex. That form doesn't show the data's length, so its 16 bytes
# are taken as the partition GUID. The plugin reads other data whose first byte is a backslash, an underscore, or an
# opening brace as UTF-16 text, as a device path such as \??\USBSTOR#... is, and writes any other data one character per
# byte through Windows-1252. Windows writes an MBR volume's data as 12 bytes and a GPT volume's as DMIO:ID: and the
# partition GUID's 16 bytes. Data written as characters, in either reading, shows its length: there DMIO:ID: data that
# isn't 24 bytes long isn't decoded, nor is other data that isn't 12 bytes long and isn't a device path.
MOUNTED_DEVICES_KEY = "mounteddevices"
MOUNTED_NAME, MOUNTED_DATA = "Name: ", "Data: "
UTF16_FIRST_BYTES = frozenset(b"\\_{")
GPT_HEX = re.compile(r"^Partition: GPT DMIO:ID: ([0-9A-F]{2}(?:-[0-9A-F]{2}){15})$", re.IGNORECASE)
DMIO_ID = b"DMIO:ID:"
DEVICE_PATH = re.compile(r"^(?:\\\?\?\\|_\?\?_)([^#]+)#([^#]+)#([^#]+)#(\{[0-9A-F]{8}(?:-[0-9A-F]{4}){3}-[0-9A-F]{12}\})$",
                         re.IGNORECASE)
MBR_SIZE, GUID_SIZE = 12, 16   # an MBR volume's disk signature and offset; a GPT partition's GUID
SECTOR_SIZE = 512
# .NET's Windows-1252 decoder gives the control character of the same number for the five bytes the code page leaves
# undefined (0x81, 0x8D, 0x8F, 0x90, and 0x9D), where Python's codec gives nothing
WINDOWS_1252 = {bytes([b]).decode("cp1252", "ignore") or chr(b): b for b in range(256)}
NOT_DECODED = ("not decoded", {"DataFormat": "Not decoded"})


def _mounted_device(text: str) -> tuple[str, dict]:
    """The words for the message and the fields for extra that a MountedDevices value's data gives, from the plugin's
    ValueData2: an MBR volume's disk signature and partition offset, a GPT volume's partition GUID, or a device path's
    bus, vendor and product, instance, and interface class GUID. Data that can't be mapped back to the plugin's bytes,
    or that has none of these shapes and lengths, is marked as not decoded."""
    data = text.removeprefix(MOUNTED_DATA) if text.startswith(MOUNTED_DATA) else ""
    if gpt := GPT_HEX.match(data):
        return _gpt(bytes.fromhex(gpt.group(1).replace("-", "")))
    if path := DEVICE_PATH.match(data):
        bus, product, instance, interface = path.groups()
        return (f"{bus} device {product}, instance {instance}, class {interface}",
                {"DataFormat": "Device path", "DeviceBus": bus, "DeviceVendorProduct": product, "DeviceInstance": instance,
                 "DeviceClassGuid": interface})
    raw = _value_bytes(data)
    if raw is None:
        return NOT_DECODED
    if raw.startswith(DMIO_ID):
        return _gpt(raw.removeprefix(DMIO_ID))
    if len(raw) != MBR_SIZE:
        return NOT_DECODED
    signature, offset = f"{int.from_bytes(raw[:4], 'little'):08X}", int.from_bytes(raw[4:], "little")
    words = f"MBR disk signature {signature}, partition offset {offset:,} bytes"
    fields = {"DataFormat": "MBR partition", "DiskSignature": signature, "PartitionOffset": offset}
    sector, rest = divmod(offset, SECTOR_SIZE)
    if not rest:
        words += f" ({SECTOR_SIZE}-byte sector {sector:,})"
        fields["PartitionSector"] = sector
    return words, fields


def _gpt(guid: bytes) -> tuple[str, dict]:
    """A GPT volume's words and fields from its partition GUID's 16 bytes, in the GUID's own byte order, or not decoded
    for bytes of another length."""
    if len(guid) != GUID_SIZE:
        return NOT_DECODED
    text = f"{{{UUID(bytes_le=guid)}}}"
    return f"GPT partition {text}", {"DataFormat": "GPT partition", "PartitionGuid": text}


def _value_bytes(data: str) -> bytes | None:
    """The bytes the plugin read to write `data`, or None: no data, a character no Windows-1252 byte gives, or U+FFFD,
    which stands for bytes lost before the CSV was read. A first character whose UTF-16 form starts with a byte the
    plugin reads as UTF-16 came by that reading: no Windows-1252 character other than those bytes' own starts that way."""
    if not data or "\ufffd" in data:
        return None
    utf16 = data.encode("utf-16-le")
    if utf16[0] in UTF16_FIRST_BYTES:
        return utf16
    try:
        return bytes(WINDOWS_1252[c] for c in data)
    except KeyError:
        return None
