"""Recognizes other tools' output in the evidence.

An analyst may bring the source evidence or what collection and processing tools made of it, such as KAPE's module
output, and the app recognizes which it has and starts from there. This module names the output
kinds by their CSV headers, which stay the same however the file is named: KAPE writes `<time>_EvtxECmd_Output.csv`
where the app's own runs write `evtxecmd.csv`. Tables that one tool writes to several files, such as AmcacheParser's,
are also told apart by the name the tool gives them.

Network monitors' logs are recognized too: Zeek's, in its tab-separated form or as JSON lines, which load through the
import with a ready-made mapping (imports.PRESETS), since the app doesn't run Zeek; and Suricata's EVE JSON, read by
the parser for the app's own Suricata runs, so a host with packet captures runs Suricata on them first.

Sysinternals Autoruns' CSV (autorunsc -c), from a live response, loads by its own parser as an inventory of autostart
entries; the app doesn't run Autoruns, so its output is never waiting behind raw evidence. autorunsc writes UTF-16
with a byte order mark.

Each kind names the registry tool whose parser reads it, or the import preset that loads it, or neither when nothing
loads it yet. Raw evidence comes first: for a host that has the raw files a tool reads, the app runs the tool, and the
output found in the evidence is listed but not loaded unless the analyst asks.

The headers are those of EZ tools 2026.5.0 and Hayabusa 4.1.0 output, MFTECmd's `$J` output included.
"""

from __future__ import annotations

import csv
import io
import json
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class OutputKind:
    kind: str                   # such as evtxecmd or amcache
    tool: str                   # the registry tool that made it, whose parser reads it
    label: str                  # what the page calls it
    columns: frozenset[str]     # header columns it always has
    parser: str = ""            # the parser that reads it; "" when none does yet
    without: frozenset[str] = frozenset()   # columns it never has, to tell it from a similar kind
    name: str = ""              # a file name pattern, for kinds known by name rather than header
    note: str = ""              # why it isn't loaded, for kinds without a parser
    preset: str = ""            # the import preset that loads it, for tools the app doesn't run
    maker: str = ""             # the tool's name, when it isn't in the registry


def _cols(text: str) -> frozenset[str]:
    return frozenset(text.split())


# Most specific first: a JLECmd CSV has LECmd's target columns too.
KINDS: tuple[OutputKind, ...] = (
    OutputKind("evtxecmd", "evtxecmd", "EvtxECmd CSV",
               _cols("EventRecordId TimeCreated EventId Provider Channel MapDescription PayloadData1"), "evtxecmd_csv"),
    OutputKind("hayabusa", "hayabusa", "Hayabusa CSV", _cols("Timestamp RuleTitle Level Computer Channel EventID"),
               "hayabusa_csv"),
    OutputKind("jlecmd_auto", "jlecmd", "JLECmd CSV", _cols("SourceFile AppId DestListVersion"), "jlecmd_csv"),
    OutputKind("jlecmd_custom", "jlecmd", "JLECmd CSV", _cols("SourceFile AppId EntryName"), "jlecmd_csv"),
    OutputKind("lecmd", "lecmd", "LECmd CSV", _cols("SourceFile TargetCreated LocalPath WorkingDirectory"), "lecmd_csv",
               without=_cols("AppId")),
    OutputKind("pecmd", "pecmd", "PECmd CSV", _cols("SourceFilename ExecutableName RunCount LastRun"), "pecmd_csv"),
    OutputKind("pecmd_timeline", "pecmd", "PECmd timeline CSV", _cols("RunTime ExecutableName"),
               note="Repeats the run times in PECmd's main CSV, which is loaded instead"),
    OutputKind("mftecmd", "mftecmd", "MFTECmd $MFT CSV", _cols("EntryNumber SequenceNumber InUse ParentPath Created0x10"),
               "mftecmd_csv"),
    OutputKind("mftecmd_j", "mftecmd_j", "MFTECmd $J CSV", _cols("UpdateSequenceNumber UpdateTimestamp UpdateReasons"),
               "mftecmd_j_csv"),
    OutputKind("recmd", "recmd", "RECmd batch CSV", _cols("HivePath HiveType KeyPath ValueName LastWriteTimestamp"),
               "recmd_csv"),
    OutputKind("recmd_plugin", "recmd", "RECmd plugin CSV", _cols("BatchKeyPath BatchValueName"),
               note="Details from RECmd's plugins; the batch CSV holds the timeline rows"),
    OutputKind("sbecmd", "sbecmd", "SBECmd CSV", _cols("BagPath Slot AbsolutePath ShellType"), "sbecmd_csv"),
    OutputKind("rbcmd", "rbcmd", "RBCmd CSV", _cols("SourceName FileType FileName FileSize DeletedOn"), "rbcmd_csv"),
    OutputKind("amcache", "amcacheparser", "AmcacheParser CSV", frozenset(), "amcache_csv", name=r"_Amcache_\w+\.csv$"),
    OutputKind("srumecmd", "srumecmd", "SrumECmd CSV", frozenset(), "srumecmd_csv", name=r"_SrumECmd_\w+_Output\.csv$"),
    OutputKind("wxtcmd", "wxtcmd", "WxTCmd Timeline CSV",
               _cols("Id ActivityTypeOrg ActivityType Executable DisplayText StartTime"), "wxtcmd_csv"),
    OutputKind("wxtcmd_other", "wxtcmd", "WxTCmd package or operation CSV", _cols("Id Platform Name Expires"),
               note="Timeline package IDs; the activities name their program already"),
    OutputKind("sqlecmd", "sqlecmd", "SQLECmd CSV", frozenset(), "sqlecmd_csv",
               name=r"_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12,13}\.csv$"),
    OutputKind("zeek_tsv", "zeek", "Zeek log", frozenset(), preset="zeek", maker="Zeek"),
    OutputKind("zeek_json", "zeek", "Zeek log, JSON", frozenset(), preset="zeek", maker="Zeek"),
    OutputKind("suricata_eve", "suricata", "Suricata EVE JSON", frozenset(), "suricata_eve"),
    # Column names with spaces, so not through _cols. Read from autorunsc output written with -h and -s.
    OutputKind("autoruns", "autoruns", "Autoruns CSV",
               frozenset(("Time", "Entry Location", "Entry", "Enabled", "Category", "Profile", "Image Path",
                          "Launch String")), "autoruns_csv", maker="Autoruns"),
)
BY_KIND = {k.kind: k for k in KINDS}
# Packet captures are evidence, not output, but the Tools page lists them with found output,
# until a tool reads them.
CAPTURES = OutputKind("pcap", "", "Capture files", frozenset(), maker="None installed",
                      note="Packet captures; no installed tool reads them yet")


def header_columns(first_line: str) -> frozenset[str]:
    try:
        row = next(csv.reader(io.StringIO(first_line.lstrip("\ufeff"))))
    except (csv.Error, StopIteration):
        return frozenset()
    return frozenset(c.strip() for c in row)


def kind_of(name: str, first_line: str) -> OutputKind | None:
    """The output kind of a file from its name and first line, or None."""
    if first_line.startswith("#separator"):   # Zeek's tab-separated logs start with their separator
        return BY_KIND["zeek_tsv"]
    if first_line.startswith("{"):
        return _json_kind(name, first_line)
    if not name.lower().endswith(".csv"):
        return None
    for k in KINDS:
        if k.name and re.search(k.name, name, re.IGNORECASE):
            return k
    columns = header_columns(first_line)
    if not columns:
        return None
    for k in KINDS:
        if k.columns and k.columns <= columns and not (k.without & columns):
            return k
    return None


ZEEK_LOGS = frozenset(("conn dce_rpc dhcp dnp3 dns dpd files ftp http intel irc kerberos known_certs known_hosts "
                        "known_services modbus mysql notice ntlm ntp ocsp pe radius rdp rfb sip smb_files smb_mapping smtp "
                        "snmp socks software ssh ssl syslog tunnel weird x509").split())


def _json_kind(name: str, first_line: str) -> OutputKind | None:
    """Suricata's EVE records carry timestamp and event_type. Zeek's carry ts, with a connection ID (uid or uids), a
    file ID (fuid), or the connection's endpoints; logs such as x509 and pe carry only an id, so their file name, the
    log's type, settles them. A first line too long for the sniff is matched by its keys as text."""
    try:
        record = json.loads(first_line)
        keys = set(record) if isinstance(record, dict) else set()
    except (ValueError, RecursionError):   # RecursionError: a line nested too deep to read
        keys = {k for k in ("timestamp", "event_type", "ts", "uid", "uids", "fuid", "id.orig_h") if f'"{k}"' in first_line}
    if {"timestamp", "event_type"} <= keys:
        return BY_KIND["suricata_eve"]
    if "ts" in keys and (keys & {"uid", "uids", "fuid", "id.orig_h"} or name.lower().split(".", 1)[0] in ZEEK_LOGS):
        return BY_KIND["zeek_json"]
    return None
