"""Parses RECmd batch-mode CSV output.

Each row is one key or value the batch file selected, timed by the key's LastWrite time. That
time says when the key last changed, not when the value was set.

The plugins whose rows name a program give the row a file path and file key, so Same file reaches the program's
other records: AppCompatCache, BAM, Run and RunOnce values, Services, and UserAssist (_program).

PluginDetailFile names a plugin's own CSV in the run's output folder, an absolute path on the analysis machine. It is
kept relative to the run folder, because the case folder's name, often a client's or a case's, would otherwise match
every search for that word.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import PureWindowsPath

from ..events import Event, to_us
from .common import (
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


def parse_recmd(ctx: ParseContext) -> Iterator[Event]:
    for row in (row for path in output_paths(ctx, "recmd", OUTPUT_FILE) for row in read_csv_rows(path)):
        key, value_name = row.get("KeyPath", ""), row.get("ValueName", "")
        data = row.get("ValueData", "")
        description = row.get("Description", "")
        detail = f" {value_name} = {data}" if value_name else (f" {data}" if data else "")
        path, path_key = _program(description, key, value_name, data, row.get("ValueData3", ""))
        yield Event(
            ts_us=to_us(row.get("LastWriteTimestamp")),
            ts_desc="Registry Key LastWrite",
            artifact="registry",
            source_file=evidence_relative(row.get("HivePath", ""), ctx.evidence_root),
            source_record=f"{key}|{value_name}|{description}",
            message=f"{description}:{detail}".strip(),
            registry_path=key,
            registry_value=value_name,
            file_path=path,
            file_key=path_key,
            # A value's data in its own column, as Sysmon 13's is. A plugin's key row names
            # no value, and its ValueData is the plugin's summary of the key, so that stays in extra only. Extra keeps
            # ValueData on every row for the host identity readers.
            registry_data=data if value_name else "",
            extra={k: _run_relative(row[k], ctx) if k == "PluginDetailFile" else row[k]
                   for k in EXTRA_COLUMNS if row.get(k)},
        )


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
