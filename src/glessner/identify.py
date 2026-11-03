"""Identifies artifact types from file signatures, using the filename only as a hint.

The signatures are the magic-byte constants below. Text logs that the import reads have no signature;
they're recognized from their first lines, with the method "content": W3C extended logs
by their #Fields directive, JSON lines by a first line that is a JSON object, key=value logs by a first line of at
least three key=value pairs, and CSV by a .csv or .tsv name and a delimited first line.

Disk images and containers are recognized last, after every other check, so that no file another rule identifies is
taken for one. No tool reads them: the analyst mounts or extracts an image first. The app reads only the MD5 and SHA-1
that an E01 stores for its disk (stored_hashes).
"""

from __future__ import annotations

import json
import os
import re
import zlib
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

DISK_IMAGE = "disk_image"
# Containers, known by a signature at offset 0. An EWF segment (E01, SMART's s01, and L01) holds its segment number as
# a 16-bit little-endian value at offset 9. SMART writes E01's signature.
EWF_MAGICS = {b"EVF\x09\x0d\x0a\xff\x00": "E01", b"LVF\x09\x0d\x0a\xff\x00": "L01"}
EWF_SEGMENT_OFFSET = 9
E01_SEGMENT = "E01 segment "   # how an E01's detail starts
# An EWF segment is a chain of sections after its 13-byte header. Each section starts with a 76-byte descriptor: its type
# in 16 bytes, the next section's offset in the file in 8, and last an Adler-32 of the 72 bytes before it. An image's last
# segment holds a digest section, whose data starts with the MD5 and the SHA-1, and a hash section, whose data starts
# with the MD5. Each section's data has an Adler-32 after the bytes it covers.
EWF_HEADER_BYTES = 13
EWF_DESCRIPTOR_BYTES = 76
EWF_DESCRIPTOR_COVERED = 72
EWF_HASH_SECTIONS = {b"digest": 76, b"hash": 32}   # by section type, the bytes of its data that its checksum covers
EWF_LAST_SECTIONS = (b"done", b"next")
EWF_MAX_SECTIONS = 100_000   # past what a segment of 4 TB holds, so a crafted chain of sections ends
MD5_BYTES, SHA1_BYTES = 16, 20
CONTAINER_MAGICS ={b"EVF2\x0d\x0a\x81\x00": "Ex01", b"LEF2\x0d\x0a\x81\x00": "Lx01", b"ADSEGMENTEDFILE": "AD1 logical image",
                    b"vhdxfile": "VHDX", b"conectix": "VHD, dynamic", b"KDMV": "VMDK sparse extent",
                    b"# Disk DescriptorFile": "VMDK descriptor", b"QFI\xfb": "QCOW"}
# The formats that hold files rather than a volume, by the first word of their detail
LOGICAL_IMAGES = ("AD1", "L01", "Lx01")
# A fixed VHD has no header: its only signature is the footer in its last 512 bytes.
VHD_FOOTER_BYTES = 512
VHD_FOOTER_MAGIC = b"conectix"
# A raw image needs one of these names and a boot sector: the 0x55AA boot signature at offset 510, or a ReFS volume's
# boot sector, which has none. A collected $Boot holds a boot sector too, and its name keeps it out.
RAW_IMAGE_NAMES = (".dd", ".raw", ".img", ".001")
BOOT_SIGNATURE = b"\x55\xaa"
BOOT_SIGNATURE_OFFSET = 510
# A volume boot sector's file system name at offset 3; FAT names its type at offset 54 (FAT12 and FAT16) or 82 (FAT32).
# ReFS is checked apart, before the boot signature.
FILE_SYSTEM_OFFSET = 3
REFS_NAME = b"ReFS\x00\x00\x00\x00"
FILE_SYSTEM_NAMES = {b"NTFS    ": "NTFS volume", b"EXFAT   ": "exFAT volume"}
FAT_NAMES = ((54, b"FAT1"), (82, b"FAT32"))
# A GPT disk's header follows its protective MBR, in the second sector of 512 or of 4,096 bytes.
GPT_MAGIC = b"EFI PART"
GPT_OFFSETS = (512, 4096)
# An MBR's four partition entries each start with a status byte of 0x00 or 0x80 (active).
MBR_STATUS_OFFSETS = (446, 462, 478, 494)


@dataclass(frozen=True)
class Identification:
    artifact: str | None   # evtx, registry, registry_log, lnk, prefetch, mft, mft_mirror, jumplist,
                           # recycle_bin, srum, event_xml, pcap, usnjrnl, sqlite, sqlite_log, tool_output (detail: the kind in
                           # tool_outputs.py), console_log, disk_image (detail: the image's format),
                           # or a text log in IMPORTABLE; None if unidentified
    method: str            # "signature", "content" (a text log, event XML, or another tool's output), "name" (known by
                           # its name alone: the USN journal, a SQLite log, or a console log), or "unidentified"
    detail: str = ""       # hive type, prefetch format, the product a text log comes from, the tool that wrote a console
                           # log, or why a file was not identified


def identify_bytes(name: str, header: bytes, tail: bytes = b"") -> Identification:
    """Identify an artifact from its filename and first bytes. `tail` is a .vhd file's last bytes, where a fixed VHD
    keeps its only signature (identify_file reads them)."""
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
    if console_log := CONSOLE_LOG.fullmatch(name):
        return Identification("console_log", "name", console_log["tool"])
    if image := _disk_image(lower, header, tail):
        return Identification(DISK_IMAGE, "signature", image)
    return Identification(None, "unidentified", _name_hint(lower, header[:HEADER_BYTES]))


def identify_file(path: Path) -> Identification:
    """Read a file's first bytes in read-only mode and identify it. A .vhd file's last bytes are read too, for a fixed
    VHD's footer."""
    tail = b""
    with path.open("rb") as f:
        header = f.read(SNIFF_BYTES)
        if path.name.lower().endswith(".vhd"):
            size = f.seek(0, os.SEEK_END)
            if size >= VHD_FOOTER_BYTES:
                f.seek(size - VHD_FOOTER_BYTES)
                tail = f.read(VHD_FOOTER_BYTES)
    return identify_bytes(path.name, header, tail)


def _disk_image(lower_name: str, header: bytes, tail: bytes) -> str:
    """The format of a disk image or container, as a detail such as "E01 segment 1"; '' for any other file."""
    for magic, kind in EWF_MAGICS.items():
        if header.startswith(magic) and len(header) >= EWF_SEGMENT_OFFSET + 2:
            segment = int.from_bytes(header[EWF_SEGMENT_OFFSET:EWF_SEGMENT_OFFSET + 2], "little")
            return f"{kind} segment {segment}"
    if container := next((kind for magic, kind in CONTAINER_MAGICS.items() if header.startswith(magic)), ""):
        return container
    if lower_name.endswith(".vhd") and tail.startswith(VHD_FOOTER_MAGIC):
        return "VHD, fixed"
    if lower_name.endswith(RAW_IMAGE_NAMES):
        return _raw_image(header)
    return ""


def _raw_image(header: bytes) -> str:
    """What a raw image's first sectors show it to be: a volume by its file system's name, or a GPT or MBR disk; '' when
    they hold no boot sector."""
    file_system = header[FILE_SYSTEM_OFFSET:FILE_SYSTEM_OFFSET + 8]
    if file_system == REFS_NAME:   # a ReFS boot sector has no boot signature
        return "raw image, ReFS volume"
    if header[BOOT_SIGNATURE_OFFSET:BOOT_SIGNATURE_OFFSET + 2] != BOOT_SIGNATURE:
        return ""
    if file_system in FILE_SYSTEM_NAMES:
        return f"raw image, {FILE_SYSTEM_NAMES[file_system]}"
    if any(header[offset:offset + len(name)] == name for offset, name in FAT_NAMES):
        return "raw image, FAT volume"
    if any(header[offset:offset + len(GPT_MAGIC)] == GPT_MAGIC for offset in GPT_OFFSETS):
        return "raw image, GPT disk"
    if all(header[offset] in (0x00, 0x80) for offset in MBR_STATUS_OFFSETS):
        return "raw image, MBR disk"
    return "raw image"


def image_note(detail: str) -> str:
    """What the analyst needs to know about a disk image of this format (its detail) beyond mounting or extracting it;
    '' for most."""
    if (kind := detail.split(" ", 1)[0]) in LOGICAL_IMAGES:
        return f"An {kind} image holds files, not a volume: export its files first."
    if detail.endswith("ReFS volume"):
        return "A ReFS volume's extracted files hold no $MFT or $J for the file system tools."
    return ""


def stored_hashes(path: Path) -> tuple[str, str]:
    """The MD5 and SHA-1 an E01 segment stores for the disk it imaged, in hex, '' for one it doesn't hold, cached by the
    file's size and time. The imaging tool wrote them, and nothing here checks them against the image's data. Only an
    image's last segment holds them. A section that fails its checksum gives nothing, and the walk stops at a
    descriptor that does, and at a next offset that doesn't move forward within the file."""
    st = path.stat()
    return _stored_cached(str(path), st.st_size, st.st_mtime_ns)


@lru_cache(maxsize=65536)
def _stored_cached(path: str, size: int, mtime_ns: int) -> tuple[str, str]:
    md5 = sha1 = ""
    offset = EWF_HEADER_BYTES
    with open(path, "rb") as f:
        for _ in range(EWF_MAX_SECTIONS):
            f.seek(offset)
            descriptor = f.read(EWF_DESCRIPTOR_BYTES)
            if not _checksum_holds(descriptor, EWF_DESCRIPTOR_COVERED):
                break
            kind = descriptor[:16].rstrip(b"\x00")
            covered = EWF_HASH_SECTIONS.get(kind)
            if covered and _checksum_holds(data := f.read(covered + 4), covered):
                md5 = md5 or _hex_unless_zero(data[:MD5_BYTES])
                if kind == b"digest":
                    sha1 = sha1 or _hex_unless_zero(data[MD5_BYTES:MD5_BYTES + SHA1_BYTES])
            following = int.from_bytes(descriptor[16:24], "little")
            if kind in EWF_LAST_SECTIONS or not offset < following < size:
                break
            offset = following
    return md5, sha1


def _checksum_holds(data: bytes, covered: int) -> bool:
    """Whether `data` is whole, and its first `covered` bytes give the Adler-32 written after them."""
    return len(data) == covered + 4 and zlib.adler32(data[:covered]) == int.from_bytes(data[covered:], "little")


def _hex_unless_zero(value: bytes) -> str:
    """A stored hash in hex; '' for all zeros, which a tool writes for a hash it didn't compute."""
    return value.hex() if any(value) else ""


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


# The log each of Eric Zimmerman's tools writes to its output folder from release 2026.10, named
# <yyyyMMddHHmmss>_<Tool>_<version>_ConsoleLog.txt, known by its name. It holds no events, and no tool reads it, though
# SBECmd's parser reads its own to name each CSV's hive.
CONSOLE_LOG = re.compile(r"\d{14}_(?P<tool>\w+?)_\d+(?:\.\d+)+_consolelog\.txt", re.IGNORECASE)
NAME_HINTS = {".evtx": "evtx", ".pf": "prefetch", ".lnk": "lnk", ".automaticdestinations-ms": "jumplist",
              ".customdestinations-ms": "jumplist"}
# Names worth reading again when an older intake left them unidentified (intake.current_entries).
NEWER_SIGNATURE_NAMES = (".automaticdestinations-ms", ".customdestinations-ms", "srudb.dat", ".xml", ".log", ".pcap",
                         ".pcapng", ".cap", "$j", "history", "shortcuts", ".sqlite", ".db", "-wal", "-shm",
                         "-journal")
# The names of a disk image's first file: an EWF or AD1 image's first segment, a container, or a raw image. A split
# VMDK's extents have a .vmdk name too (VMDK_EXTENT_NAME).
IMAGE_NAMES = (".e01", ".ex01", ".l01", ".lx01", ".s01", ".ad1", ".vhd", ".vhdx", ".vmdk", ".qcow", ".qcow2",
               *RAW_IMAGE_NAMES)
# The extents of a split VMDK, <name>-s001.vmdk on, which its descriptor, <name>.vmdk, names. The number has at least
# three digits, so a disk of more than 999 extents goes on at <name>-s1000.vmdk. Each extent starts with a sparse
# extent's signature, but the descriptor is the image's first file.
VMDK_EXTENT_NAME = re.compile(r"-s\d{3,}\.vmdk$")
# The names of any segment: EWF names its segments .E01 to .E99 and then .EAA on, L01 and SMART (.s01) the same way,
# Ex01 and Lx01 .Ex01 and .Lx01 on, and AD1 .ad1 on. A few other names fit too, such as .exe and .sys, and reading such
# a file again costs one read of its first bytes.
SEGMENT_NAME = re.compile(r"\.(?:[el]x?\d\d|s\d\d|[els][a-z]{2}|ad\d+)$")


def image_name(lower_name: str) -> bool:
    """Whether a file's name, in lower case, is one a disk image's file may have."""
    return lower_name.endswith(IMAGE_NAMES) or SEGMENT_NAME.search(lower_name) is not None


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
