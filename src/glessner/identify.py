"""Identifies artifact types from file signatures, using the filename only as a hint.

The signatures are the magic-byte constants below. Text logs that the import reads have no signature;
they're recognized from their first lines, with the method "content": W3C extended logs
by their #Fields directive, JSON lines by a first line that is a JSON object, key=value logs by a first line of at
least three key=value pairs, and CSV by a .csv or .tsv name and a delimited first line.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from .line_logs import detect_layout
from .tool_outputs import OutputKind
from .tool_outputs import kind_of as output_kind

HEADER_BYTES = 32
SNIFF_BYTES = 8192   # read for text logs, whose first lines identify them
IMPORTABLE = ("w3c_log", "kv_log", "csv", "jsonl", "line_log")   # text logs the import reads; see imports.py

EVTX_MAGIC = b"ElfFile\x00"
REGF_MAGIC = b"regf"
LNK_HEADER_SIZE = b"\x4c\x00\x00\x00"
# {00021401-0000-0000-C000-000000000046} in its on-disk byte order.
LNK_CLSID = bytes.fromhex("0114020000000000c000000000000046")
PREFETCH_MAGIC = b"SCCA"            # at offset 4 in uncompressed prefetch
PREFETCH_COMPRESSED = b"MAM\x04"    # at offset 0 in compressed Windows 10 and later prefetch
MFT_RECORD_MAGIC = b"FILE"
OLE_MAGIC = bytes.fromhex("d0cf11e0a1b11ae1")       # compound file: automatic jump lists
DESTINATIONS_VERSIONS = (b"\x01\x00\x00\x00", b"\x02\x00\x00\x00")   # custom jump lists start with a version
RECYCLE_VERSIONS = {bytes([v]) + b"\x00" * 7: v for v in (1, 2)}   # $I files: 1 before Windows 10, 2 after
ESE_MAGIC = b"\xef\xcd\xab\x89"                     # at offset 4 in an ESE database such as SRUDB.dat
# Packet captures: pcap in either byte order, with microsecond or nanosecond times, and pcapng's section header.
PCAP_MAGICS = (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
SQLITE_MAGIC = b"SQLite format 3\x00"
# SQLite databases the registry's tools read, by name (SQLECmd's maps and WxTCmd); any other SQLite file is a database.
SQLITE_ROLES = {"activitiescache.db": "ActivitiesCache", "history": "Chromium history", "shortcuts": "Chromium shortcuts",
                "places.sqlite": "Firefox places", "downloads.sqlite": "Firefox downloads",
                "wpndatabase.db": "Windows notifications"}
SQLITE_LOGS = ("-wal", "-shm", "-journal")   # a database's write-ahead log, shared memory, and rollback journal
EVENT_XML_NAMESPACE = "http://schemas.microsoft.com/win/2004/08/events/event"   # Windows event XML (event_xml.py)
EVENT_ELEMENT = re.compile(r"<Event[\s>]")

# Plaso's image_export.py writes $MFT as _MFT.
MFT_NAMES = {"$mft", "_mft"}
MFT_MIRROR_NAMES = {"$mftmirr", "_mftmirr"}
# The USN journal's $J stream, as collection tools name it: $J, or $UsnJrnl with the stream name joined on. Its start is
# usually sparse zeros, so it's known by name alone.
USNJRNL_NAMES = {"$j", "$usnjrnl%3a$j", "$usnjrnl_$j", "$usnjrnl.$j", "$usnjrnl$j"}
HIVE_TYPES = {
    "system": "SYSTEM",
    "software": "SOFTWARE",
    "sam": "SAM",
    "security": "SECURITY",
    "default": "DEFAULT",
    "ntuser.dat": "NTUSER",
    "usrclass.dat": "USRCLASS",
    "amcache.hve": "AMCACHE",
}
HIVE_LOG_SUFFIXES = (".log", ".log1", ".log2")


@dataclass(frozen=True)
class Identification:
    artifact: str | None   # evtx, registry, registry_log, lnk, prefetch, mft, mft_mirror, jumplist,
                           # recycle_bin, srum, event_xml, pcap, usnjrnl, sqlite, sqlite_log, tool_output (detail: the kind in
                           # tool_outputs.py),
                           # or a text log in IMPORTABLE; None if unidentified
    method: str            # "signature", "content" (a text log), "name" (the USN journal), or "unidentified"
    detail: str = ""       # hive type, prefetch format, the product a text log comes from, or why a file was not
                           # identified


def identify_bytes(name: str, header: bytes) -> Identification:
    """Identify an artifact from its filename and first bytes."""
    lower = name.lower()
    if header.startswith(EVTX_MAGIC):
        return Identification("evtx", "signature")
    if header.startswith(REGF_MAGIC):
        # Windows 8.1 and later transaction logs begin with a copy of the hive's base block.
        if lower.endswith(HIVE_LOG_SUFFIXES):
            return Identification("registry_log", "signature", _hive_type(lower.rsplit(".", 1)[0]))
        return Identification("registry", "signature", _hive_type(lower))
    if header[:4] == LNK_HEADER_SIZE and header[4:20] == LNK_CLSID:
        return Identification("lnk", "signature")
    if lower.endswith(".automaticdestinations-ms") and header.startswith(OLE_MAGIC):
        return Identification("jumplist", "signature", "automatic")
    if lower.endswith(".customdestinations-ms") and header[:4] in DESTINATIONS_VERSIONS:
        return Identification("jumplist", "signature", "custom")
    if lower.startswith("$i") and header[:8] in RECYCLE_VERSIONS:
        return Identification("recycle_bin", "signature", f"$I version {RECYCLE_VERSIONS[header[:8]]}")
    if lower == "srudb.dat" and header[4:8] == ESE_MAGIC:
        return Identification("srum", "signature")
    if header[4:8] == PREFETCH_MAGIC:
        return Identification("prefetch", "signature", "uncompressed")
    if header.startswith(PREFETCH_COMPRESSED):
        return Identification("prefetch", "signature", "compressed")
    if header.startswith(MFT_RECORD_MAGIC):
        if lower in MFT_NAMES:
            return Identification("mft", "signature")
        if lower in MFT_MIRROR_NAMES:
            return Identification("mft_mirror", "signature")
        return Identification(None, "unidentified", "NTFS FILE record header without an $MFT name")
    if lower in USNJRNL_NAMES:
        return Identification("usnjrnl", "name", "USN journal $J")
    if header.startswith(SQLITE_MAGIC):
        return Identification("sqlite", "signature", SQLITE_ROLES.get(lower, "SQLite database"))
    if lower.endswith(SQLITE_LOGS) and lower.rsplit("-", 1)[0] in SQLITE_ROLES:
        return Identification("sqlite_log", "name", lower.rsplit("-", 1)[1])
    if header[:4] in PCAP_MAGICS:
        return Identification("pcap", "signature", "pcap")
    if header[:4] == PCAPNG_MAGIC:
        return Identification("pcap", "signature", "pcapng")
    if not header:
        return Identification(None, "unidentified", "empty file")
    if lower.endswith(".xml") and _event_xml(header):
        return Identification("event_xml", "content", "Windows event XML")
    text = _text(header)
    if text is not None:   # another tool's output, such as KAPE's CSVs or Zeek's logs
        output = output_kind(name, text.split("\n", 1)[0].rstrip("\r"))
        if output:
            return Identification("tool_output", "content", output.kind)
    if text is not None:
        found = _text_log(lower, text)
        if found:
            return found
    return Identification(None, "unidentified", _name_hint(lower, header[:HEADER_BYTES]))


def identify_file(path: Path) -> Identification:
    """Read a file's first bytes in read-only mode and identify it."""
    with path.open("rb") as f:
        header = f.read(SNIFF_BYTES)
    return identify_bytes(path.name, header)


def text_encoding(head: bytes) -> str:
    """The encoding a text file is read in, from its first bytes: UTF-16 by its byte order mark, as autorunsc and Event
    Viewer write it, or without a mark when the text starts with '<', as some event XML exports do; UTF-8 otherwise.
    Intake's sniff and every reader of text evidence use it, so a file intake takes as text is one its reader can
    decode."""
    if head[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return "utf-16"
    if head[:2] == b"<\x00":
        return "utf-16-le"
    if head[:2] == b"\x00<":
        return "utf-16-be"
    return "utf-8-sig"


def kind_of_file(path: Path) -> OutputKind | None:
    """The tool output kind a file's header line shows (tool_outputs.kind_of), cached by the file's size and time."""
    st = path.stat()
    return _kind_cached(str(path), st.st_size, st.st_mtime_ns)


@lru_cache(maxsize=65536)
def _kind_cached(path: str, size: int, mtime_ns: int) -> OutputKind | None:
    with open(path, "rb") as f:
        head = f.read(2)
    with open(path, encoding=text_encoding(head), errors="replace", newline="") as f:
        first = f.readline(65536)
    return output_kind(Path(path).name, first.rstrip("\r\n"))


KV_PAIR = re.compile(r'(?:^|[\s>,])([A-Za-z_][\w.-]{0,40})=(?:"[^"]*"|[^\s,]*)')
JSONL_NAMES = (".jsonl", ".ndjson")
CSV_NAMES = (".csv", ".tsv")
DELIMITERS = {",": "comma-separated", "\t": "tab-separated", ";": "semicolon-separated", "|": "pipe-separated"}


def _text(header: bytes) -> str | None:
    """The header as text, in text_encoding's encoding, or None when it looks binary."""
    encoding = text_encoding(header)
    if encoding.startswith("utf-16"):
        text = header.decode(encoding, errors="ignore")   # the sniff may end inside a character
    elif b"\x00" in header:
        return None
    else:
        text = header.decode(encoding, errors="replace")
    # Invalid UTF-8 decodes to U+FFFD, which counts as printable, so it's counted apart: binary data gives many.
    printable = sum(1 for c in text if (c.isprintable() and c != "\ufffd") or c in "\r\n\t")
    return text if text and printable / len(text) > 0.98 else None


def _text_log(lower_name: str, text: str) -> Identification | None:
    lines = [line.strip() for line in text.lstrip("\ufeff").splitlines() if line.strip()]
    if not lines:
        return None
    first = lines[0]
    if first.startswith("#"):
        directives = [line.lower() for line in lines if line.startswith("#")]
        if any(d.startswith("#fields:") for d in directives):
            software = next((d.split(":", 1)[1] for d in directives if d.startswith("#software:")), "")
            detail = ("Windows Firewall" if "windows firewall" in software else
                      "IIS" if "internet information services" in software else "W3C extended")
            return Identification("w3c_log", "content", detail)
    # JSON lines need two records, so a .json file holding one object, such as an app's settings, isn't listed.
    if first.startswith("{") and (lower_name.endswith(JSONL_NAMES) or (len(lines) > 1 and lines[1].startswith("{")
                                                                       and _json_object(first))):
        return Identification("jsonl", "content", "JSON lines")
    if first.startswith("[") and lower_name.endswith(".json"):
        return Identification("jsonl", "content", "JSON array")
    # The sniff may cut the last line short, so it isn't counted. Known layouts come before key=value lines, since
    # UFW's syslog lines and some proxies' access lines carry KEY=value pairs too (line_logs.py).
    whole = lines[:-1] if len(lines) > 1 else lines
    layout = detect_layout(whole)
    if layout:
        return Identification("line_log", "content", layout.label)
    keys = {k.lower() for k in KV_PAIR.findall(first)}
    if len(keys) >= 3:
        detail = ("Fortinet" if "logid" in keys and keys & {"devid", "devname"} else
                  "SonicWall" if {"sn", "m"} <= keys or {"id", "fw"} <= keys else "key=value")
        return Identification("kv_log", "content", detail)
    if lower_name.endswith(CSV_NAMES):
        counts = {d: first.count(d) for d in DELIMITERS}
        delimiter = max(counts, key=counts.get)
        if counts[delimiter]:
            return Identification("csv", "content", DELIMITERS[delimiter])
    layout = detect_layout(whole, generic=True)   # last: any lines that start with a date and time
    if layout:
        return Identification("line_log", "content", layout.label)
    return None


def _hive_type(lower_name: str) -> str:
    return HIVE_TYPES.get(lower_name, "unknown hive")


NAME_HINTS = {".evtx": "evtx", ".pf": "prefetch", ".lnk": "lnk", ".automaticdestinations-ms": "jumplist",
              ".customdestinations-ms": "jumplist"}
# Names worth reading again when an older intake left them unidentified (intake.current_entries).
NEWER_SIGNATURE_NAMES = (".automaticdestinations-ms", ".customdestinations-ms", "srudb.dat", ".xml", ".log", ".pcap",
                         ".pcapng", ".cap", "$j", "history", "shortcuts", ".sqlite", ".db", "-wal", "-shm",
                         "-journal")


def _name_hint(lower_name: str, header: bytes) -> str:
    """Explain an unidentified file whose name suggests an artifact type."""
    suggested = next((kind for ext, kind in NAME_HINTS.items() if lower_name.endswith(ext)), None)
    if suggested is None and (lower_name in HIVE_TYPES or lower_name in MFT_NAMES):
        suggested = "registry" if lower_name in HIVE_TYPES else "mft"
    if suggested is None:
        return ""
    zeros = "; header is all zero bytes" if not header.strip(b"\x00") else ""
    return f"named like {suggested}, but no {suggested} signature{zeros}"


def _event_xml(header: bytes) -> bool:
    """Windows event XML: the event namespace and an <Event> element in the first bytes, read as the reader reads them
    (text_encoding). UTF-16 without a byte order mark that starts with anything but '<' isn't taken: the reader can't
    decode it."""
    text = header.decode(text_encoding(header), errors="ignore")
    return EVENT_XML_NAMESPACE in text and EVENT_ELEMENT.search(text) is not None


def _json_object(line: str) -> bool:
    try:
        return isinstance(json.loads(line), dict)
    except ValueError:
        return False
