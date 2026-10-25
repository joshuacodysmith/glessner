"""Helpers shared by the tool-output parsers."""

from __future__ import annotations

import csv
import fnmatch
import ipaddress
import json
import re
import sys
from collections.abc import Iterator
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path, PureWindowsPath

from ..identify import kind_of_file
from ..long_paths import DEVICE, PREFIX

csv.field_size_limit(sys.maxsize // 4)
UNC_PREFIX = PREFIX + "UNC\\"   # a share's path in extended-length form, \\?\UNC\server\share


@dataclass(frozen=True)
class ParseContext:
    output_dir: Path        # the run's output folder
    evidence_root: Path     # the case's evidence folder, where it was when the tool ran (runner.RunRecord.evidence_root)
    inputs: tuple[str, ...] = ()   # the run's evidence-relative inputs, for output that doesn't name its source file
    files: tuple[Path, ...] = ()   # for a load of a tool's output found in the evidence: those files
    # The host's zone for output written in local time (parsers.LOCAL_TIME), as runner.host_zone resolves it
    zone: dict | None = None
    input_root: str = ""    # the run's working-copy folder when it ran (runner.RunRecord.input_root)
    # What the parser has to say in the run's record, such as the offset it read local times at (LOCAL_TIME_NOTE)
    notes: list[str] = field(default_factory=list)
    # A case format whose key rule the parser gives each event too, in Event.former, for that format's upgrade
    # (parsers.FORMER_RULES, rekey.py); 0 for none
    former: int = 0
    # For a parser that counts what it makes no event of (parsers.COUNTS_SKIPPED): a count for each file it read, in the
    # order read, 0 for a file it made an event of every row or line of
    skipped: list[int] = field(default_factory=list)


LOCAL_TIME_NOTE = "Local times read in "   # a note the next load replaces (runner.load_output)
SKIPPED_NOTE = "No event was made of "   # likewise: a count of the lines or rows a parser dropped


def output_paths(ctx: ParseContext, kind: str, name: str) -> list[Path]:
    """The output files a parser reads. A run's own output folder holds them by name: a file name, or a glob pattern
    such as *_Amcache_ProgramEntries.csv. A load of output found in the evidence reads its own files instead, those
    whose header shows this kind (tool_outputs.py), and for a glob, whose name fits it too."""
    if not ctx.files:
        return sorted(ctx.output_dir.glob(name)) if "*" in name else [ctx.output_dir / name]
    fits = lambda p: "*" not in name or fnmatch.fnmatch(p.name.lower(), name.lower())
    return sorted(p for p in ctx.files if (k := kind_of_file(p)) and k.kind == kind and fits(p))


def read_csv_rows(path: Path) -> Iterator[dict[str, str]]:
    with path.open(encoding="utf-8-sig", errors="replace", newline="") as f:
        yield from csv.DictReader(f)


def profile_name(path: str) -> str:
    """The user profile a file sits in, the folder after Users, such as cody in DESKTOP/Users/cody/AppData/...; ''
    when the path names none."""
    parts = PureWindowsPath(path).parts
    lower = [p.lower() for p in parts]
    return parts[lower.index("users") + 1] if "users" in lower and lower.index("users") + 1 < len(parts) else ""


def evidence_relative(path_text: str, evidence_root: Path) -> str:
    """Turn a tool's absolute input path into the manifest's evidence-relative form. The path and the evidence root are
    each read in their plain form (_plain), so a path in extended-length form, as a load of output found in the evidence
    opens its files (runner.parse_context), and a root the case keeps as typed in that form or the device form give
    the evidence path that plain ones give."""
    return _evidence_relative(path_text, str(evidence_root))


@lru_cache(maxsize=65536)
def _evidence_relative(path_text: str, evidence_root: str) -> str:
    # Cached: a run has a few hundred distinct source files but up to millions of rows, and
    # PureWindowsPath.relative_to was 55% of EvtxECmd parse time without the cache.
    if not path_text:
        return ""
    path = PureWindowsPath(path_text)
    try:
        return PureWindowsPath(_plain(path_text)).relative_to(PureWindowsPath(_plain(evidence_root))).as_posix()
    except ValueError:
        return path.as_posix()   # outside the evidence root; kept as given so nothing is lost


def _plain(path_text: str) -> str:
    """A path in extended-length form (long_paths.long_path) written as a plain one: \\\\?\\UNC\\ becomes \\\\, \\\\?\\
    before a drive letter is dropped, and \\\\?\\ before anything else, such as Volume{GUID}, becomes the device form,
    \\\\.\\, which resolve() gives a volume with no drive letter. Other text comes back as it was."""
    if path_text.startswith(UNC_PREFIX):
        return "\\\\" + path_text.removeprefix(UNC_PREFIX)
    if not path_text.startswith(PREFIX):
        return path_text
    rest = path_text.removeprefix(PREFIX)
    return rest if re.match(r"[A-Za-z]:", rest) else DEVICE + rest


_IP_AND_PORT = re.compile(r"^(?:\[(?P<v6>[^\]]+)\]|(?P<v4>\d{1,3}(?:\.\d{1,3}){3})):\d{1,5}$")


def normalize_ip(text: str | None) -> str:
    """Return a canonical IP string, mapping ::ffff:a.b.c.d to a.b.c.d. Placeholders become ''.
    An address with a port, such as 1.2.3.4:58132 or [fe80::1]:3389, gives the address alone."""
    return ip_and_port(text)[0]


def is_digits(text: str) -> bool:
    """Whether the text is a whole number in ASCII digits short enough for int() and DuckDB's BIGINT. str.isdigit()
    alone is also true for characters such as the superscript '²', which int() refuses, and int() refuses more than
    4,300 digits; 18 digits stay below 2**63, so a record number fits the BIGINT column."""
    return len(text) <= 18 and text.isascii() and text.isdigit()


def port_number(text: str | None) -> str:
    """A port as written in the event, or '' for a placeholder such as '-' or '0' or anything out of range."""
    text = (text or "").strip()
    return text if is_digits(text) and 0 < int(text) <= 65535 else ""


def ip_and_port(text: str | None) -> tuple[str, str]:
    """The canonical IP and the port from an address that may carry one, such as 1.2.3.4:58132."""
    if not text or text.strip() in ("-", ""):
        return "", ""
    text, port = text.strip(), ""
    with_port = _IP_AND_PORT.match(text)
    if with_port:
        port = port_number(text.rsplit(":", 1)[1])
        text = with_port.group("v6") or with_port.group("v4")
    ip = _canonical_ip(text)
    return ip, port if ip else ""


def _canonical_ip(text: str) -> str:
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return ""
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return str(addr)


_PATH_PREFIXES = re.compile(
    r"^(?:This PC\\)?(?:\\\\\?\\|\\\?\?\\)?"             # LNK shell path, Win32 long-path prefix, NT's \??\
    r"(?:\\VOLUME\{[^}]*\}|\\Device\\HarddiskVolume\d+|[A-Za-z]:|\.(?=\\|$))?",  # prefetch volume, NT device, drive, MFT root
    re.IGNORECASE)


# The folders a path can start with as a variable, as the key writes them out. A user's
# variables (%USERPROFILE%, %APPDATA%, %LOCALAPPDATA%, %TEMP%) need the profile's folder, which is not known here, so a path
# that starts with one gets no key. The drive is C: for these folders; the key ignores it.
FOLDER_VARIABLES = {
    "systemroot": "Windows", "windir": "Windows",
    "programfiles": "Program Files", "programw6432": "Program Files", "programfiles(x86)": "Program Files (x86)",
    "commonprogramfiles": "Program Files\\Common Files", "commonprogramw6432": "Program Files\\Common Files",
    "commonprogramfiles(x86)": "Program Files (x86)\\Common Files",
    "programdata": "ProgramData", "allusersprofile": "ProgramData",
    "systemdrive": "",
}
LEADING_VARIABLE = re.compile(r"^(?:%(?P<name>[A-Za-z0-9_()]+)%|\\SystemRoot)(?=\\)", re.IGNORECASE)


def expand_folder(text: str) -> str:
    """The text with a folder variable, or NT's \\SystemRoot, at its start written out on C:, so %SystemRoot%\\x.sys is
    C:\\Windows\\x.sys. Text that starts with no variable, or with one that isn't in FOLDER_VARIABLES, comes back as it was."""
    match = LEADING_VARIABLE.match(text)
    folder = FOLDER_VARIABLES.get((match.group("name") or "systemroot").lower()) if match else None
    if folder is None:
        return text
    return "C:" + ("\\" + folder if folder else "") + text[match.end():]


@lru_cache(maxsize=262144)
def file_key(path: str | None) -> str:
    """Normalize a file path so the same file matches across tools.

    Prefetch writes \\VOLUME{...}\\WINDOWS\\SYSTEM32\\CMD.EXE, the MFT .\\Windows\\System32\\cmd.exe, LNK
    files C:\\Windows\\System32\\cmd.exe or This PC\\C:\\..., and event logs C:\\Windows\\System32\\cmd.exe.
    All become \\windows\\system32\\cmd.exe. The volume is dropped, so a key cannot tell C: from D:. A path that starts
    with a folder variable or \\SystemRoot has it written out first (expand_folder).
    Text that is not a path, such as "Applications\\Microsoft Edge", gives "". So does text that starts with one slash, a
    URL path or a Unix path such as /coreupdater.exe: read as a Windows path it would be a file at a volume root, and
    none of the 99 such keys on Szechuan matched a file. //server/share is a UNC path and keeps its key.
    """
    if not path:
        return ""
    text = path.strip()
    if text.startswith("/") and not text.startswith("//"):
        return ""
    text = expand_folder(text.replace("/", "\\"))
    if not (text.startswith(("\\", ".\\", "This PC\\")) or re.match(r"^[A-Za-z]:\\", text)):
        return ""
    rest = _PATH_PREFIXES.sub("", text, count=1)
    if not rest.startswith("\\"):
        rest = "\\" + rest
    rest = re.sub(r"\\+", r"\\", rest).rstrip("\\")
    return rest.lower() if rest else ""


# A service's binary or a task's command without its arguments: a quoted path; a path that starts like one (a drive,
# UNC, \??\, a folder variable, \SystemRoot, or the volume's root) up to its executable's extension, spaces and all; or else
# the first word, so "%COMSPEC% /c ... x.bat" gives %COMSPEC%, not a fragment.
QUOTED = re.compile(r'^\s*"([^"]+)"')
EXECUTABLE = r"exe|sys|dll|com|bat|cmd|ps1|scr|vbs|vbe|js|jse|wsf|hta|jar|msc|cpl|lnk|pif"
PATH_TO_EXTENSION = re.compile(r"^\s*((?:[A-Za-z]:\\|\\\\|\\\?\?\\|%[\w()]+%\\|\\SystemRoot\\|\\)"
                               r".+?\.(?:" + EXECUTABLE + r"))(?=\s|$)", re.IGNORECASE)
EXECUTABLE_END = re.compile(r"\.(?:" + EXECUTABLE + r")$", re.IGNORECASE)


def command_file(command: str | None) -> str:
    """The program a command line runs, without its arguments, with \\??\\ dropped and a leading folder variable or
    \\SystemRoot written out, so its file key matches the file's other records. A driver's path relative to the Windows
    folder gets the folder. Every source of a command line reads it through this: a service's or task's (7045, 4697, task
    events), RECmd's Run and Services rows, and Autoruns' launch strings.
    A command that starts like a path but stops at a space short of an executable's extension, such as an unquoted
    C:\\Program Files\\x.xyz, gives "": its first word is a folder's fragment, and as a key it would join unrelated rows."""
    text = clean(command)
    match = QUOTED.match(text) or PATH_TO_EXTENSION.match(text)
    words = text.split() or [""]
    if match:
        binary = match.group(1)
    elif len(words) > 1 and "\\" in words[0] and not EXECUTABLE_END.search(words[0]):
        return ""
    else:
        binary = words[0]
    binary = expand_folder(binary.strip().removeprefix("\\??\\"))
    return "C:\\Windows\\" + binary if binary.lower().startswith("system32\\") else binary


# The folders a known-folder GUID or name stands for, as a path from the volume's root.
# WxTCmd writes a Timeline program as System\cmd.exe or {GUID}\cmd.exe, and RECmd's UserAssist as {System}\cmd.exe or
# {GUID}\cmd.exe. The GUIDs are KNOWNFOLDERID's (MS-knownfolder), checked against the constants the Windows SDK's header gives.
# ProgramFiles is left out: it is the writer's own Program Files, Program Files (x86) for a 32-bit program on 64-bit
# Windows. SystemX86 is syswow64 on 64-bit Windows and system32 on 32-bit Windows, so on 32-bit Windows it misses a file
# and never joins a wrong one (inference).
KNOWN_FOLDERS = {
    "system": ("{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}", "Windows\\System32"),
    "systemx86": ("{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}", "Windows\\SysWOW64"),
    "windows": ("{F38BF404-1D43-42F2-9305-67DE0B28FC23}", "Windows"),
    "programfilesx64": ("{6D809377-6AF0-444B-8957-A3773F02200E}", "Program Files"),
    "programfilesx86": ("{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}", "Program Files (x86)"),
}
KNOWN_FOLDER_START = re.compile(r"^\{?([^{}\\]+?)\}?\\")
KNOWN_FOLDER_BY_NAME = {**{name: folder for name, (_, folder) in KNOWN_FOLDERS.items()},
                        **{guid.strip("{}").lower(): folder for guid, folder in KNOWN_FOLDERS.values()}}


def known_folder(path: str | None) -> str:
    """The path with a known folder at its start written out on C:, such as C:\\Windows\\System32\\cmd.exe for
    {System}\\cmd.exe, System\\cmd.exe, and {1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\cmd.exe, or "" for a path that starts
    with none, such as an app ID or {Common Programs}\\x.lnk. It reads only the sources that write such paths (WxTCmd and
    UserAssist): a bare System\\x elsewhere could be a relative path."""
    match = KNOWN_FOLDER_START.match((path or "").strip())
    folder = KNOWN_FOLDER_BY_NAME.get(match.group(1).lower()) if match else None
    return f"C:\\{folder}\\{path.strip()[match.end():]}" if folder else ""


def clean(text: str | None) -> str:
    """Treat the '-' placeholder Windows writes for empty fields as empty."""
    if text is None:
        return ""
    text = text.strip()
    return "" if text == "-" else text


def flatten(obj: dict) -> dict[str, str]:
    """A JSON object's fields as text, for an import's records and Suricata's EVE: nested objects as dotted names, such
    as source.ip, and lists as JSON text. It walks the nesting with a stack of its own, so a record nested 1,000 deep
    doesn't raise RecursionError; json.dumps still can, on a list nested about 16,000 deep."""
    out: dict[str, str] = {}
    stack = [("", iter(obj.items()))]
    while stack:
        prefix, items = stack[-1]
        for key, value in items:
            name = f"{prefix}{key}"
            if isinstance(value, dict):
                stack.append((name + ".", iter(value.items())))
                break   # read the nested object now, then go on with this one, so names keep the record's order
            if isinstance(value, list):
                out[name] = json.dumps(value, ensure_ascii=False)
            elif isinstance(value, bool):
                out[name] = "true" if value else "false"
            else:
                out[name] = "" if value is None else str(value)
        else:
            stack.pop()
    return out


def payload_fields(raw: str | None) -> dict[str, str]:
    """Flatten an EvtxECmd Payload JSON value into field name -> value.

    EventData arrives as {"EventData": {"Data": [{"@Name": ..., "#text": ...}, ...]}}. UserData
    has a free-form tree, which is flattened to its leaf names.
    """
    if not raw:
        return {}
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    out: dict[str, str] = {}
    event_data = doc.get("EventData") if isinstance(doc, dict) else None
    data = event_data.get("Data") if isinstance(event_data, dict) else None
    if isinstance(data, str):
        # Unnamed values, such as MSSQL's: EvtxECmd joins them into one string with ", ". The XML reader numbers them
        # Data1 to DataN, as a list of them is numbered below.
        out["Data"] = data
        data = None
    elif isinstance(data, dict):
        data = [data]
    for i, item in enumerate(data or [], 1):
        if isinstance(item, dict) and "@Name" in item:
            value = item.get("#text", "")
            out[item["@Name"]] = "" if value is None else str(value)
        elif isinstance(item, (str, int, float)):
            out.setdefault(f"Data{i}", str(item))

    def walk(node) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if isinstance(value, (dict, list)):
                    walk(value)
                elif not key.startswith("@") and key not in out:
                    out[key] = "" if value is None else str(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    if isinstance(doc, dict):
        walk(doc.get("UserData"))
        # An event whose data didn't fit its provider's template, such as WinRM 91 in EVTX-ATTACK-SAMPLES, has
        # ProcessingErrorData in place of EventData: an error code, the item that failed, and the data as hex.
        # The EvtxECmd parser reads the hex as text (payload_text) after unescaping, since decoded text has no entities.
        walk(doc.get("ProcessingErrorData"))
    return out


HYPHENATED_HEX = re.compile(r"^[0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2})*$")   # EvtxECmd's form, "68-00-74"
PLAIN_HEX = re.compile(r"^(?:[0-9A-Fa-f]{2})+$")                     # the event XML's, "680074"
UTF16_STRINGS = re.compile(rb"(?:[\x20-\x7e]\x00){3,}")              # runs of 3 or more ASCII characters, as strings -el


def payload_text(hexed: str) -> str:
    """ProcessingErrorData's EventPayload as text: the UTF-16 strings in its bytes, as `strings -el` finds them, joined
    with " | ", so WinRM 91's shell URI reads. Bytes that only decode as UTF-16, such as binary numbers, give nothing,
    and nor does text outside ASCII; the hex stays in extra either way."""
    if not hexed or len(hexed) > 1 << 17 or not (HYPHENATED_HEX.match(hexed) or PLAIN_HEX.match(hexed)):
        return ""
    raw = bytes.fromhex(hexed.replace("-", ""))
    return " | ".join(run.decode("utf-16-le") for run in UTF16_STRINGS.findall(raw))
