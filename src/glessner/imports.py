"""Imports log files that no registered tool reads: CSV, JSON lines, W3C extended logs
such as Windows Firewall and IIS logs, key=value lines such as Fortinet's and SonicWall's, and log lines in a known
layout (line_logs.py): Apache and NGINX access and error logs, syslog, Cisco ASA, Snort and Suricata fast alerts, and
lines that start with a date and time.

A mapping says how a file's records become events:
  format    csv, jsonl, w3c, kv, or lines; a CSV's delimiter and whether its first row names the fields; the layout of
            lines
  time      the field holding the time, or a date and a time field joined with a space; how to read it; and the
            zone for times written without one: UTC, an offset such as -08:00, an IANA zone, or a host's own zone
            ("host:DC01"), or a field holding each record's offset (Fortinet's tz). Times written without a year, as
            syslog, Cisco ASA, and Snort write them, take the mapping's year, which moves on when the times jump back
            more than six months, as from December to January
  fields    which record fields fill the event's own columns (ROLES): source and destination address and port,
            account, computer, event code, process, and so on
  host      the host lane: the host whose evidence folder holds the file, a name, or a field of each record
  message   a template such as "{action} {srcip}[:{srcport}]"; a part in [brackets] is left out when a field in
            it is empty. Without one, the message field, or the first fields as name=value
  ignore    fields not kept
Every field not ignored is also kept as the event's own data, under the file's own field name, so data.<field>
filters and search reach it, and a vendor's field names keep working. A "-", which W3C logs write for an empty
field, counts as empty.

Speed, measured on a 500,000-line Windows Firewall log: about 32 s to import, half building events in Python and
half loading them.

An import is a run (runner.py): its run.json records the file, hash checks before and after reading it, and the
whole mapping with its zone resolved, so a rebuild reads the file again the same way even after a host's zone
changes. The file is read in place, from the evidence folder, and never changed. Importing a file again replaces
its earlier events.
"""

from __future__ import annotations

import csv
import io
import json
import re
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

import duckdb

from .case import Case, write_atomically
from .events import Event, connect, from_us, load
from .identify import IMPORTABLE, identify_file, text_encoding
from .intake import PLACEHOLDER, current_entries, file_stamp, placeholders_among, read_manifest, verify
from .line_logs import BY_LABEL, KV_KEY, LAYOUTS
from .long_paths import long_path
from .parsers import LOCAL_TIME
from .parsers.common import clean, file_key, flatten, ip_and_port, port_number
from .parsers.evtxecmd import NO_LOGON
from .runner import IMPORT as TOOL
from .runner import (
    UNREADABLE,
    check_result,
    cloud_placeholders_text,
    finish_run,
    not_reread,
    read_runs,
    records_format_4,
    start_run,
)
from .timezones import (
    DATE_TIME,
    OFFSET,
    Parsed,
    ZoneClock,
    ZoneError,
    host_timezones,
    offset_minutes,
    parse_time,
    resolve_zone,
)
from .tool_outputs import BY_KIND
from .version import build_id

TS_DESC = "Logged"
SAMPLE_RECORDS = 200   # records read to guess a mapping and check it before an import
PREVIEW_ROWS = 20
MAX_JSON_ARRAY_BYTES = 512 * 1024 * 1024   # a JSON array is read whole; bigger exports need JSON lines
MAX_MESSAGE = 2000
FORMATS = {"csv": "CSV", "jsonl": "JSON lines", "w3c": "W3C extended log", "kv": "key=value lines",
           "lines": "Log lines in a known layout", "zeek": "Zeek log, TSV or JSON"}
FORMAT_OF = {"csv": "csv", "jsonl": "jsonl", "w3c_log": "w3c", "kv_log": "kv", "line_log": "lines"}   # artifact to format
ROLES = {
    "source_ip": "Source IP", "source_port": "Source port", "dest_ip": "Destination IP",
    "dest_port": "Destination port", "user": "Account", "domain": "Account domain",
    "workstation": "Source workstation", "logon_id": "Logon ID", "logon_type": "Logon type",
    "computer": "Computer (as recorded)", "code": "Event code",
    "provider": "Provider", "channel": "Channel", "process": "Process", "command_line": "Command line",
    "parent": "Parent process", "parent_command_line": "Parent command line",
    "path": "File path", "message": "Message",
}
TIME_FORMATS = {"ymd": "year-month-day, as in ISO 8601", "mdy": "month/day/year", "dmy": "day/month/year",
                "epoch": "Unix time: seconds, milliseconds, microseconds, or nanoseconds"}
# Any other format is a strptime pattern, such as %d.%m.%Y %H:%M:%S.
STRPTIME_GUESSES = ("%d-%b-%Y %H:%M:%S", "%d %b %Y %H:%M:%S", "%b %d %Y %H:%M:%S", "%a %b %d %H:%M:%S %Y",
                    "%d/%b/%Y:%H:%M:%S %z", "%a %b %d %H:%M:%S.%f %Y", "%m/%d/%y-%H:%M:%S.%f", "%m/%d/%Y-%H:%M:%S.%f",
                    "%b %d %Y %H:%M:%S.%f")
# Formats without a year, as syslog (RFC 3164), Cisco ASA, and Snort write times; read with the mapping's year.
YEARLESS_GUESSES = ("%b %d %H:%M:%S", "%b %d %H:%M:%S.%f", "%m/%d-%H:%M:%S.%f")
YEAR_DIRECTIVES = ("%Y", "%y", "%G", "%c")
ROLLOVER_US = 183 * 24 * 3600 * 1_000_000   # a year-less time this far before the last one is in the next year
NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")   # saved mapping names
ARTIFACT = re.compile(r"^[a-z0-9_]{1,40}$")
HOST_NAME = re.compile(r"^[^\x00-\x1f/\\]{1,64}$")


class MappingError(ValueError):
    """A mapping or import that can't go ahead, with a message for the analyst."""


# ---------- reading records ----------

@dataclass
class Stats:
    records: int = 0
    skipped: int = 0          # lines that weren't a record: not JSON, or no key=value pairs
    without_time: int = 0
    bad_times: list[str] = field(default_factory=list)   # a few time values that couldn't be read, for the notes
    array: int | None = None  # a JSON array's records, counted when it's read whole; None for any other file


def open_text(path: Path) -> io.TextIOWrapper:
    """Open a text log for reading, in the encoding intake's sniff read it in (identify.text_encoding)."""
    with path.open("rb") as f:
        head = f.read(2)
    return path.open(encoding=text_encoding(head), errors="replace", newline="")


def records(path: Path, mapping: dict, stats: Stats | None = None, limit: int | None = None) -> Iterator[tuple[str, dict]]:
    """Yield (record number, fields) for each record in the file. Numbers are line numbers, so they stay the same
    each time the file is read, and point to the record in the file."""
    stats = stats if stats is not None else Stats()
    reader = {"csv": _csv_records, "jsonl": _json_records, "w3c": _w3c_records, "kv": _kv_records,
              "lines": _line_records, "zeek": _zeek_records}[mapping["format"]]
    for n, (number, rec) in enumerate(reader(path, mapping, stats)):
        if limit is not None and n >= limit:
            return
        stats.records += 1
        yield number, rec


def _csv_records(path: Path, mapping: dict, stats: Stats):
    with open_text(path) as f:
        reader = csv.reader(f, delimiter=mapping.get("delimiter") or ",")
        names = None if mapping.get("header", True) else []
        for row in reader:
            if not any(v.strip() for v in row):
                continue
            if names is None:
                names = _unique([v.strip() or f"column{i + 1}" for i, v in enumerate(row)])
                continue
            while len(names) < len(row):
                names.append(f"column{len(names) + 1}")
            yield str(reader.line_num), dict(zip(names, row))


def _json_records(path: Path, mapping: dict, stats: Stats):
    """JSON lines, or one JSON array. A record nested too deep to read, which raises RecursionError, is skipped and
    counted like a line that isn't JSON."""
    with open_text(path) as f:
        start = f.read(1)
        while start.isspace():
            start = f.read(1)
        if start == "[":
            if path.stat().st_size > MAX_JSON_ARRAY_BYTES:
                raise MappingError(f"{path.name} is a JSON array over {MAX_JSON_ARRAY_BYTES >> 20} MB; "
                                   "export it as JSON lines, one object per line.")
            f.seek(0)
            try:
                items = json.load(f)
            except RecursionError as exc:
                raise MappingError(f"{path.name} nests its values too deep to read.") from exc
            stats.array = len(items)
            for i, item in enumerate(items):
                if (rec := _flat(item)) is not None:
                    yield str(i + 1), rec
                else:
                    stats.skipped += 1
            return
        f.seek(0)
        for i, line in enumerate(f):
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except (ValueError, RecursionError):
                item = None
            if (rec := _flat(item)) is not None:
                yield str(i + 1), rec
            else:
                stats.skipped += 1


def _flat(item) -> dict[str, str] | None:
    """A JSON object's fields, or None for anything else, or for an object holding a list too deep to write back."""
    if not isinstance(item, dict):
        return None
    try:
        return flatten(item)
    except RecursionError:
        return None


def _w3c_records(path: Path, mapping: dict, stats: Stats):
    """W3C extended logs: #Fields names the fields, and can change partway, as IIS writes a new header when it
    restarts. Fields are separated by spaces, or by commas where #Fields is (as Exchange writes it)."""
    names: list[str] = []
    comma = False
    with open_text(path) as f:
        for i, line in enumerate(f):
            line = line.rstrip("\r\n")
            if line.startswith("#"):
                if line.lower().startswith("#fields:"):
                    spec = line.split(":", 1)[1].strip()
                    comma = "," in spec
                    names = _unique([n.strip() for n in (spec.split(",") if comma else spec.split())])
                continue
            if not line.strip():
                continue
            if not names:
                stats.skipped += 1
                continue
            values = next(csv.reader([line])) if comma else line.split()
            yield str(i + 1), dict(zip(names, values))


KV_PAIR = re.compile(KV_KEY + r'("(?:[^"\\]|\\.)*"|[^\s"]*)')
KV_PAIR_COMMA = re.compile(KV_KEY + r'("(?:[^"\\]|\\.)*"|[^,"]*)')
SYSLOG_PRI = re.compile(r"^<\d{1,3}>\s*$")


def _kv_records(path: Path, mapping: dict, stats: Stats):
    """key=value lines, such as FortiGate and SonicWall logs. Quoted values may hold spaces. Text before the first
    pair, such as a syslog header, is kept as syslog_header; a bare <priority> is dropped."""
    pair = KV_PAIR_COMMA if mapping.get("delimiter") == "," else KV_PAIR
    with open_text(path) as f:
        for i, line in enumerate(f):
            line = line.strip()
            if not line:
                continue
            rec, first = {}, None
            for m in pair.finditer(line):
                if first is None:
                    first = m.start(1)   # the key's start: the match can start at digits before it (KV_KEY)
                value = m.group(2)
                if len(value) >= 2 and value[0] == value[-1] == '"':
                    value = value[1:-1].replace('\\"', '"')
                rec.setdefault(m.group(1), value.strip())
            if not rec:
                stats.skipped += 1
                continue
            prefix = line[:first].strip().rstrip(",")
            if prefix and not SYSLOG_PRI.match(prefix):
                rec = {"syslog_header": prefix, **rec}
            yield str(i + 1), rec


def _line_records(path: Path, mapping: dict, stats: Stats):
    """Log lines in a known layout (line_logs.py). A line that doesn't fit, such as a stack trace's second line, is
    skipped and counted."""
    layout = LAYOUTS.get(mapping.get("layout") or "")
    if layout is None:
        raise MappingError(f"Choose the layout of the lines: {', '.join(option.label for option in LAYOUTS.values())}.")
    parse = layout.parser()
    with open_text(path) as f:
        for i, line in enumerate(f):
            line = line.rstrip("\r\n")
            if not line.strip():
                continue
            rec = parse(line)
            if rec is None:
                stats.skipped += 1
                continue
            yield str(i + 1), rec


def _zeek_records(path: Path, mapping: dict, stats: Stats):
    """Zeek's logs, in its tab-separated form or as JSON lines. Each record gets _path, the log's type, such as conn
    or dns: from the #path line, or the file name for JSON, where conn.json and conn.00:00:00-01:00:00.log are conn.
    Zeek writes "-" for an unset field and "(empty)" for an empty one; both become empty."""
    kind = path.name.split(".", 1)[0]
    with open_text(path) as f:
        first = f.readline()
        f.seek(0)
        if not first.startswith("#"):
            for number, rec in _json_records(path, mapping, stats):
                yield number, {"_path": rec.get("_path") or kind, **rec}
            return
        names: list[str] = []
        separator, unset, empty = "\t", "-", "(empty)"
        for i, line in enumerate(f):
            line = line.rstrip("\r\n")
            if line.startswith("#"):
                key, _, value = line[1:].partition(separator if not line.startswith("#separator") else " ")
                if key == "separator":
                    separator = value.encode().decode("unicode_escape")
                elif key == "fields":
                    names = _unique(value.split(separator))
                elif key == "path":
                    kind = value
                elif key == "unset_field":
                    unset = value
                elif key == "empty_field":
                    empty = value
                continue
            if not line.strip():
                continue
            if not names:
                stats.skipped += 1
                continue
            values = ["" if v in (unset, empty) else v for v in line.split(separator)]
            yield str(i + 1), {"_path": kind, **dict(zip(names, values))}


def _unique(names: list[str]) -> list[str]:
    seen: dict[str, int] = {}
    out = []
    for n in names:
        seen[n] = seen.get(n, 0) + 1
        out.append(n if seen[n] == 1 else f"{n}_{seen[n]}")
    return out


# ---------- times ----------

def needs_year(fmt: str) -> bool:
    """Whether a time format leaves out the year, as syslog's %b %d %H:%M:%S does."""
    return "%" in fmt and not any(d in fmt for d in YEAR_DIRECTIVES)


def time_with_year(text: str, fmt: str, year) -> tuple[str, str]:
    """The text and format to read, with the year put in front when the format has none."""
    return (f"{year} {text}", f"%Y {fmt}") if year and needs_year(fmt) else (text, fmt)


def read_time(text: str, t: dict) -> Parsed | None:
    """One record's time by a mapping's time settings, without year rollover."""
    if needs_year(t["format"]) and not t.get("year"):
        return None   # a year-less time is never read as 1900
    return parse_time(*time_with_year(text, t["format"], t.get("year")))


@dataclass(frozen=True)
class TimeGuess:
    format: str          # "" when the values could be read two ways, or not at all
    zoned: bool          # every value carries its zone
    problem: str = ""
    ambiguous: bool = False   # dates that could be month/day or day/month: times, but the analyst picks the order


def guess_time_format(values: list[str]) -> TimeGuess:
    values = [v.strip() for v in values if v and v.strip()][:SAMPLE_RECORDS]
    if not values:
        return TimeGuess("", False, "The time field is empty in the records read.")
    for fmt in ("epoch", "ymd"):
        parsed = [parse_time(v, fmt) for v in values]
        if all(parsed):
            return TimeGuess(fmt, all(p.zoned for p in parsed))
    matches = [DATE_TIME.match(v) for v in values]
    if all(matches) and all(len(m.group(1)) <= 2 for m in matches):
        if any(int(m.group(1)) > 12 for m in matches):
            fmt = "dmy"
        elif any(int(m.group(2)) > 12 for m in matches):
            fmt = "mdy"
        else:
            return TimeGuess("", False, f"Times such as {values[0]} could be month/day/year or day/month/year; "
                                        "choose the date order.", ambiguous=True)
        parsed = [parse_time(v, fmt) for v in values]
        if all(parsed):
            return TimeGuess(fmt, all(p.zoned for p in parsed))
    for fmt in STRPTIME_GUESSES:
        parsed = [parse_time(v, fmt) for v in values]
        if all(parsed):
            return TimeGuess(fmt, all(p.zoned for p in parsed))
    for fmt in YEARLESS_GUESSES:   # tried in a leap year, so 29 February reads
        if all(parse_time(*time_with_year(v, fmt, 2000)) for v in values):
            return TimeGuess(fmt, False)
    return TimeGuess("", False, f"Times such as {values[0]} aren't in a format the import knows; give a strptime "
                                "format such as %d.%m.%Y %H:%M:%S.")


# ---------- mappings ----------

# Ready-made mappings. A field given as a list takes the first name the file has; "time" lists alternatives.
PRESETS: dict[str, dict] = {
    "windows_firewall": {
        "label": "Windows Firewall log (pfirewall.log)", "format": "w3c", "artifact": "windows_firewall",
        "match": {"artifact": "w3c_log", "detail": "Windows Firewall"},
        # "#Time Format: Local": the host's own clock, so the import asks for the zone.
        "time": [{"columns": ["date", "time"], "format": "ymd", "zone": ""}],
        "fields": {"source_ip": "src-ip", "source_port": "src-port", "dest_ip": "dst-ip", "dest_port": "dst-port",
                   "code": "action"},
        "message": "{action} {protocol} {src-ip}[:{src-port}] -> {dst-ip}[:{dst-port}][ {path}][ pid {pid}]",
    },
    "iis": {
        "label": "IIS log (W3C extended)", "format": "w3c", "artifact": "iis",
        "match": {"artifact": "w3c_log", "detail": "IIS"},
        # IIS writes W3C times in UTC, whatever the local-time rollover setting says.
        "time": [{"columns": ["date", "time"], "format": "ymd", "zone": "UTC"}],
        "fields": {"source_ip": "c-ip", "dest_ip": "s-ip", "dest_port": "s-port", "user": "cs-username",
                   "code": "sc-status", "computer": "s-computername"},
        "message": "{cs-method} {cs-uri-stem}[?{cs-uri-query}] {sc-status}[ user {cs-username}][ {cs(User-Agent)}]",
    },
    "fortinet": {
        "label": "FortiGate log (key=value)", "format": "kv", "artifact": "fortinet",
        "match": {"artifact": "kv_log", "detail": "Fortinet"},
        # eventtime is Unix time, so it needs no zone; date and time are the device's clock, offset by tz.
        "time": [{"columns": ["eventtime"], "format": "epoch", "zone": "UTC"},
                 {"columns": ["date", "time"], "format": "ymd", "zone": "", "zone_column": "tz"}],
        "fields": {"source_ip": "srcip", "source_port": "srcport", "dest_ip": "dstip", "dest_port": "dstport",
                   "user": ["user", "unauthuser"], "computer": "devname", "code": "logid", "channel": "type"},
        "message": "{type}[/{subtype}][ {action}][ {srcip}][:{srcport}][ -> {dstip}][:{dstport}][ {service}]"
                   "[ user {user}][ policy {policyid}][ {logdesc}][: {msg}]",
    },
    "sonicwall": {
        "label": "SonicWall log (key=value)", "format": "kv", "artifact": "sonicwall",
        "match": {"artifact": "kv_log", "detail": "SonicWall"},
        # time is the firewall's clock unless the log is set to UTC, which writes "UTC" after it.
        "time": [{"columns": ["time"], "format": "ymd", "zone": ""}],
        # src and dst are written as address:port:interface.
        "fields": {"source_ip": "src", "dest_ip": "dst", "user": ["usr", "user"], "computer": "id", "code": "m"},
        "message": "{msg}[ {src}][ -> {dst}][ {proto}][ {fw_action}]",
    },
    # Log lines (line_logs.py). "guess" reads the format from the file's own times, since syslog writes RFC 3164,
    # RFC 5424, or RFC 3339 times, and Cisco ASA and Snort may or may not write the year.
    "apache_access": {
        "label": "Apache or NGINX access log", "format": "lines", "layout": "apache_access", "artifact": "web_access",
        "match": {"artifact": "line_log", "detail": "Apache or NGINX access log"},
        "time": [{"columns": ["time"], "format": "%d/%b/%Y:%H:%M:%S %z", "zone": ""}],   # each line has its offset
        "fields": {"source_ip": "client", "user": "user", "code": "status"},
        "message": "[{method} ]{url} {status}[ {bytes} bytes][ user {user}][ referer {referer}][ {agent}]",
    },
    "apache_error": {
        "label": "Apache error log", "format": "lines", "layout": "apache_error", "artifact": "web_error",
        "match": {"artifact": "line_log", "detail": "Apache error log"},
        "time": [{"columns": ["time"], "format": "guess", "zone": ""}],   # the server's clock
        "fields": {"source_ip": "client", "code": "level"},
        "message": "{level}[ {module}][ client {client}]: {message}",
    },
    "syslog": {
        "label": "Syslog", "format": "lines", "layout": "syslog", "artifact": "syslog",
        "match": {"artifact": "line_log", "detail": "Syslog"},
        "time": [{"columns": ["time"], "format": "guess", "zone": ""}],
        "fields": {"computer": "hostname", "process": "app", "source_ip": "src_ip", "source_port": "src_port",
                   "dest_ip": "dst_ip", "dest_port": "dst_port", "user": "user", "command_line": "command",
                   "code": "action"},
        "message": "[{app}: ]{message}",
    },
    "cisco_asa": {
        "label": "Cisco ASA", "format": "lines", "layout": "cisco_asa", "artifact": "cisco_asa",
        "match": {"artifact": "line_log", "detail": "Cisco ASA"},
        "time": [{"columns": ["time"], "format": "guess", "zone": ""}],   # the firewall's clock, unless set to UTC
        "fields": {"source_ip": "src_ip", "source_port": "src_port", "dest_ip": "dst_ip", "dest_port": "dst_port",
                   "user": "user", "computer": "hostname", "code": "msgid"},
        "message": "%{facility}-{severity}-{msgid}: {message}",
    },
    "snort_fast": {
        "label": "Snort or Suricata fast alert", "format": "lines", "layout": "snort_fast", "artifact": "ids_alert",
        "match": {"artifact": "line_log", "detail": "Snort or Suricata fast alert"},
        "time": [{"columns": ["time"], "format": "guess", "zone": ""}],   # the sensor's clock, unless run with -U
        "fields": {"source_ip": "src", "dest_ip": "dst", "code": "rule", "channel": "classification"},
        "message": "{signature}[ ({classification})][ priority {priority}] {proto} {src} -> {dst}",
    },
    # Network monitors' own logs, found in the evidence; the Tools page loads them with these.
    "zeek": {
        "label": "Zeek log", "format": "zeek", "artifact": "zeek",
        "match": {"artifact": "tool_output", "detail": "zeek"},
        "time": [{"columns": ["ts"], "format": "guess", "zone": ""}],   # Unix time, or ISO 8601 when so configured
        # Zeek joins a nested field's name with a dot, id.orig_h, or with an underscore, id_orig_h, when its scope
        # separator is set so. A log holds one form, so each field and message part reads both.
        "fields": {"source_ip": ["id.orig_h", "id_orig_h", "client_addr"], "source_port": ["id.orig_p", "id_orig_p"],
                   "dest_ip": ["id.resp_h", "id_resp_h", "server_addr"], "dest_port": ["id.resp_p", "id_resp_p"],
                   "user": ["username", "user", "client"], "domain": ["domainname"], "path": ["filename"], "channel": "_path",
                   "code": ["service", "qtype_name", "method", "note"]},
        # One template for every log type: each part shows only where the log has its fields.
        "message": "[{_path}: ][{id.orig_h}][{id_orig_h}][:{id.orig_p}][:{id_orig_p}][ -> {id.resp_h}][ -> {id_resp_h}]"
                   "[:{id.resp_p}][:{id_resp_p}][ {proto}][ {service}]"
                   "[ {query}][ {qtype_name}][ {method}][ {host}][ {uri}][ {status_code}][ {server_name}][ {note}]"
                   "[ {msg}][ {client_addr}][ {assigned_addr}][ {host_name}][ {mac}][ {certificate.subject}]"
                   "[ {certificate_subject}][ {certStatus}][ {machine}][ sections {section_names}][ {mime_type}]"
                   "[ {filename}][ {md5}][ {conn_state}]",
    },
    "timestamped": {
        "label": "Lines that start with a date and time", "format": "lines", "layout": "timestamped",
        "artifact": "text_log", "match": {"artifact": "line_log", "detail": "Lines that start with a date and time"},
        "time": [{"columns": ["time"], "format": "guess", "zone": ""}],
        "fields": {}, "message": "{message}",
    },
}

NAME_GUESSES = {   # normalized field names (lower case, letters and digits only), most specific first
    "source_ip": ("srcip", "sourceip", "src", "srcaddr", "sourceaddress", "clientip", "cip", "ipaddress", "remoteip",
                  "remoteaddress"),
    "source_port": ("srcport", "sourceport", "sport", "clientport", "ipport"),
    "dest_ip": ("dstip", "destip", "destinationip", "dst", "dest", "dstaddr", "destaddress", "destinationaddress",
                "serverip", "sip"),
    "dest_port": ("dstport", "destport", "destinationport", "dport", "serverport"),
    "user": ("username", "user", "account", "accountname", "targetusername", "subjectusername", "srcuser", "usr",
             "csusername"),
    "domain": ("userdomain", "domain", "targetdomainname", "subjectdomainname"),
    "workstation": ("workstationname", "workstation", "srchost", "sourcehostname", "clientname"),
    "logon_id": ("targetlogonid", "logonid"),
    "logon_type": ("logontype",),
    "computer": ("computer", "computername", "hostname", "host", "devname", "devicename", "dvc", "dvchost",
                 "scomputername", "agentname"),
    "code": ("eventid", "eventcode", "logid", "eventtype"),
    "provider": ("provider", "providername", "sourcename", "eventprovider"),
    "channel": ("channel", "logname", "logchannel", "eventdataset", "eventmodule"),
    "process": ("processname", "process", "image", "newprocessname", "processexecutable", "exe", "executable"),
    "command_line": ("commandline", "processcommandline", "cmdline", "cmd"),
    "parent": ("parentimage", "parentprocessname", "parentprocess", "parentprocessexecutable", "parentexecutable"),
    "parent_command_line": ("parentcommandline", "parentprocesscommandline", "parentcmdline"),
    "path": ("filepath", "targetfilename", "filename", "path"),
    "message": ("message", "msg", "description", "eventoriginal", "raw"),
}
TIME_NAMES = ("timestamp", "eventtime", "timegenerated", "time", "datetime", "date", "receivetime", "generatedtime",
              "timecreated", "utctime", "systemtime", "eventtimestamp", "logtime", "starttime", "ts", "created",
              "datetimeutc")


def norm(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


@dataclass
class Sample:
    path: str               # evidence-relative
    format: str
    delimiter: str
    columns: list[str]      # every field name in the records read, in first-seen order
    records: list[tuple[str, dict]]
    product: str            # from identification, such as Fortinet; "" if none
    stats: Stats
    layout: str = ""        # for lines: the layout name in line_logs.LAYOUTS


def sniff(case: Case, rel_path: str, base: dict | None = None) -> Sample:
    """Read the first records of a file, in the format given or the one its content shows."""
    path = _evidence_file(case, rel_path)
    ident = identify_file(path)
    base = dict(base or {})
    fmt = base.get("format") or FORMAT_OF.get(ident.artifact or "") or "csv"
    if fmt not in FORMATS:
        raise MappingError(f"Unknown format {fmt!r}; the import reads {', '.join(FORMATS)}.")
    delimiter = base.get("delimiter") or _guess_delimiter(path, fmt)
    layout = ""
    if fmt == "lines":   # the layout chosen, else the one intake sees, else lines that start with a time
        layout = base.get("layout") if base.get("layout") in LAYOUTS else BY_LABEL.get(ident.detail, "timestamped")
    stats = Stats()
    recs = list(records(path, {**base, "format": fmt, "delimiter": delimiter, "layout": layout}, stats, SAMPLE_RECORDS))
    # A layout's fields are all offered, even those the first records leave out, such as an ASA log's user.
    columns: dict[str, None] = dict.fromkeys(LAYOUTS[layout].columns) if layout else {}
    for _, rec in recs:
        columns.update(dict.fromkeys(rec))
    product = ident.detail if ident.method == "content" else ""
    if layout and product not in BY_LABEL:
        product = LAYOUTS[layout].label
    return Sample(rel_path, fmt, delimiter, list(columns), recs, product, stats, layout)


def _guess_delimiter(path: Path, fmt: str) -> str:
    if fmt not in ("csv", "kv"):
        return ""
    with open_text(path) as f:
        first = next((line for line in f if line.strip()), "")
    if fmt == "kv":
        return "," if len(re.findall(r",[A-Za-z_][\w.-]*=", first)) > len(re.findall(r"\s[A-Za-z_][\w.-]*=", first)) else " "
    counts = {d: first.count(d) for d in (",", "\t", ";", "|")}
    return max(counts, key=counts.get) if max(counts.values()) else ","


def preset_for(sample: Sample) -> str:
    if sample.format == "lines":
        return next((name for name, p in PRESETS.items() if p.get("layout") == sample.layout), "")
    return next((name for name, p in PRESETS.items()
                 if p["format"] == sample.format and p["match"]["detail"] == sample.product), "")


def apply_preset(name: str, sample: Sample) -> dict:
    p = PRESETS[name]
    have = set(sample.columns)
    pick = lambda names: next((n for n in ([names] if isinstance(names, str) else names) if n in have), None)
    time_spec = dict(next((t for t in p["time"] if all(c in have for c in t["columns"])), p["time"][0]))
    if time_spec["format"] == "guess":
        g = guess_time_format([" ".join(rec.get(c, "") for c in time_spec["columns"]) for _, rec in sample.records])
        time_spec["format"] = g.format
        if g.zoned:
            time_spec["zone"] = "UTC"   # never used: each time carries its zone
    fields = {role: col for role, names in p["fields"].items() if (col := pick(names))}
    out = {"format": p["format"], "delimiter": sample.delimiter, "artifact": p["artifact"], "preset": name,
           "time": time_spec, "fields": fields, "host": {"from": "folder"}, "message": p["message"], "ignore": []}
    if p.get("layout"):
        out["layout"] = p["layout"]
    return out


def guess_mapping(sample: Sample, saved: dict[str, dict] | None = None) -> dict:
    """A mapping for a file: a saved one whose fields the file has, else a ready-made one for its product, else one
    guessed from the field names and values."""
    have = set(sample.columns)
    for name, m in (saved or {}).items():
        used = set(m.get("time", {}).get("columns", [])) | set(m.get("fields", {}).values())
        if m.get("format") == sample.format and used and used <= have and m.get("layout", "") == sample.layout:
            return {**m, "saved_as": name}
    preset = preset_for(sample)
    if preset:
        return apply_preset(preset, sample)
    by_norm: dict[str, str] = {}
    for c in sample.columns:
        by_norm.setdefault(norm(c), c)
    fields, taken = {}, set()
    for role, names in NAME_GUESSES.items():
        col = next((by_norm[n] for n in names if n in by_norm and by_norm[n] not in taken), None)
        if col:
            fields[role] = col
            taken.add(col)
    values = lambda col: [rec.get(col, "") for _, rec in sample.records]
    time_cols: list[str] = []
    if "date" in by_norm and "time" in by_norm and not guess_time_format(values(by_norm["time"])).format:
        time_cols = [by_norm["date"], by_norm["time"]]   # a date field and a time-of-day field
    if not time_cols:
        for n in TIME_NAMES:
            if n in by_norm and _looks_like_time(values(by_norm[n])):
                time_cols = [by_norm[n]]
                break
    if not time_cols:
        time_cols = next(([c] for c in sample.columns if c not in taken and _looks_like_time(values(c))), [])
    for c in time_cols:
        for role in [r for r, col in fields.items() if col == c]:
            del fields[role]
    joined = [" ".join(rec.get(c, "") for c in time_cols) for _, rec in sample.records] if time_cols else []
    guess = guess_time_format(joined) if time_cols else TimeGuess("", False)
    out = {"format": sample.format, "delimiter": sample.delimiter, "artifact": sample.format,
           "time": {"columns": time_cols, "format": guess.format, "zone": "UTC" if guess.zoned else ""},
           "fields": fields, "host": {"from": "folder"}, "message": _template(fields, time_cols, sample.columns),
           "ignore": []}
    if sample.layout:
        out["layout"] = sample.layout
    return out


def _template(fields: dict[str, str], time_cols: list[str], columns: list[str], others: int = 6) -> str:
    """A message template from the guessed fields: the code, source -> destination, the account, the message
    field, then the first few other fields as name=value. Fields whose names would break the template are left out."""
    usable = lambda c: c and not any(ch in c for ch in "{}[]")
    f = {role: col for role, col in fields.items() if usable(col)}
    parts = [f"[{{{f['code']}}} ]" if "code" in f else ""]
    parts += [f"[{{{f['source_ip']}}}]" if "source_ip" in f else "", f"[:{{{f['source_port']}}}]" if "source_port" in f else "",
              f"[ -> {{{f['dest_ip']}}}]" if "dest_ip" in f else "", f"[:{{{f['dest_port']}}}]" if "dest_port" in f else "",
              f"[ user {{{f['user']}}}]" if "user" in f else "", f"[ {{{f['message']}}}]" if "message" in f else ""]
    used = set(time_cols) | set(fields.values())
    parts += [f"[ {c}={{{c}}}]" for c in [c for c in columns if c not in used and usable(c)][:others]]
    return "".join(parts)


def _looks_like_time(values: list[str]) -> bool:
    values = [v for v in values if v.strip()]
    if not values or all(v.strip().isdigit() and len(v.strip()) < 9 for v in values):
        return False
    g = guess_time_format(values)
    return bool(g.format) or g.ambiguous


def normalize_mapping(m: dict) -> dict:
    """Check a mapping's shape and values; returns a clean copy. Says what's wrong in the analyst's terms."""
    if not isinstance(m, dict):
        raise MappingError("A mapping is a JSON object.")
    fmt = m.get("format")
    if fmt not in FORMATS:
        raise MappingError(f"Choose a format: {', '.join(FORMATS)}.")
    out: dict = {"format": fmt}
    delimiter = m.get("delimiter") or ("," if fmt == "csv" else " " if fmt == "kv" else "")
    if fmt in ("csv", "kv") and (not isinstance(delimiter, str) or len(delimiter) != 1 or delimiter in '"\r\n'):
        raise MappingError("The delimiter is one character, such as a comma or a tab.")
    out["delimiter"] = delimiter
    if fmt == "csv":
        out["header"] = bool(m.get("header", True))
    if fmt == "lines":
        if m.get("layout") not in LAYOUTS:
            raise MappingError(f"Choose the layout of the lines: {', '.join(option.label for option in LAYOUTS.values())}.")
        out["layout"] = m["layout"]
    artifact = str(m.get("artifact") or fmt)
    if not ARTIFACT.match(artifact):
        raise MappingError("The artifact name uses lower-case letters, digits, and underscores, such as palo_alto.")
    out["artifact"] = artifact
    t = m.get("time") or {}
    columns = [c for c in t.get("columns") or [] if isinstance(c, str) and c]
    if not columns:
        raise MappingError("Choose the field that holds each record's time.")
    tfmt = str(t.get("format") or "")
    if not tfmt:
        raise MappingError("Choose how the times are written.")
    if tfmt not in TIME_FORMATS and "%" not in tfmt:
        raise MappingError(f"Unknown time format {tfmt!r}: use {', '.join(TIME_FORMATS)}, or a strptime format.")
    out["time"] = {"columns": columns, "format": tfmt, "zone": str(t.get("zone") or "")}
    if t.get("zone_column"):
        out["time"]["zone_column"] = str(t["zone_column"])
    if t.get("year") not in (None, ""):
        try:
            year = int(t["year"])
        except (TypeError, ValueError):
            year = 0
        if not 1970 <= year <= 2100:
            raise MappingError("The year is a number such as 2024.")
        out["time"]["year"] = year
    # zone_resolved is never taken from outside: check() resolves the zone again, so a changed choice takes effect.
    fields = m.get("fields") or {}
    unknown = sorted(set(fields) - set(ROLES))
    if unknown:
        raise MappingError(f"Unknown event fields {unknown}; the import fills {', '.join(ROLES)}.")
    out["fields"] = {role: str(col) for role, col in fields.items() if col}
    host = m.get("host") or {"from": "folder"}
    how = host.get("from")
    if how == "folder":
        out["host"] = {"from": "folder"}
    elif how == "name":
        name = str(host.get("name") or "").strip()
        if not HOST_NAME.match(name):
            raise MappingError("Type a host name for the lane, up to 64 characters, without slashes.")
        out["host"] = {"from": "name", "name": name}
    elif how == "column":
        fallback = str(host.get("fallback") or "").strip()
        if not host.get("column") or (fallback and not HOST_NAME.match(fallback)):
            raise MappingError("Choose the field that names each record's host, and a lane for records without one.")
        out["host"] = {"from": "column", "column": str(host["column"]), "fallback": fallback}
    else:
        raise MappingError("Choose the host lane: the folder's host, a name, or a field.")
    out["message"] = str(m.get("message") or "")
    out["ignore"] = sorted({str(c) for c in m.get("ignore") or []})
    for key in ("preset", "saved_as"):
        if m.get(key):
            out[key] = str(m[key])
    return out


# ---------- events ----------

TEMPLATE_FIELD = re.compile(r"\{([^{}]+)\}")
TEMPLATE_OPTIONAL = re.compile(r"\[([^\[\]]*)\]")


def render(template: str, rec: dict) -> str:
    """A message from a template: {field} is the record's field, and a [part] is left out when a field in it is
    empty. Runs once per record, so the template is split up once and kept."""
    out = []
    for optional, texts, names in _compile(template):
        values = [_value(rec.get(n)) for n in names]
        if optional and not all(values):
            continue
        out.append(texts[0] + "".join(v + t for v, t in zip(values, texts[1:])))
    return " ".join("".join(out).split())


def _value(text: str | None) -> str:
    text = text.strip() if text else ""
    return "" if text == "-" else text


@lru_cache(maxsize=64)
def _compile(template: str) -> tuple[tuple[bool, tuple[str, ...], tuple[str, ...]], ...]:
    """(optional, texts, names) parts: the literal texts around the field names, one more text than names."""
    def part(optional: bool, text: str):
        pieces = TEMPLATE_FIELD.split(text)
        return optional, tuple(pieces[0::2]), tuple(pieces[1::2])
    parts, pos = [], 0
    for m in TEMPLATE_OPTIONAL.finditer(template):
        parts += [part(False, template[pos:m.start()]), part(True, m.group(1))]
        pos = m.end()
    parts.append(part(False, template[pos:]))
    return tuple(parts)


@lru_cache(maxsize=1 << 16)   # a log names the same addresses again and again
def endpoint(text: str | None) -> tuple[str, str]:
    """An address and port from 10.0.0.5, 10.0.0.5:443, [fe80::1]:443, or SonicWall's 10.0.0.5:443:X1."""
    ip, port = ip_and_port(text)
    if ip or not text:
        return ip, port
    head, _, rest = text.strip().partition(":")
    ip, _ = ip_and_port(head)
    return (ip, port_number(rest.split(":", 1)[0])) if ip else ("", "")


# A Kerberos realm or a DNS domain: dotted labels of letters, digits, and hyphens, and not an address. N/A, root/admin, and
# user@web01 are not accounts with a realm.
REALM = re.compile(r"^(?![0-9.]+$)[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$")


@lru_cache(maxsize=1 << 16)
def split_account(text: str) -> tuple[str, str]:
    """The domain and name of an account as a log writes it: DOMAIN\\name, name@realm (split at the last @), or Zeek's
    name/REALM (split at the last /, when the text holds no backslash or @). The realm must be dotted and not an address, so
    N/A and root/admin stay names. Anything else is a name with no domain. The
    mapping's domain field, where it has one, still wins."""
    domain, _, name = text.rpartition("\\")
    if "\\" in text:
        return domain, name
    if "@" in text:
        name, _, realm = text.rpartition("@")
    elif "/" in text:
        name, _, realm = text.rpartition("/")
    else:
        return "", text
    return (realm, name) if name and REALM.match(realm) else ("", text)


def host_lane(case: Case, rel_path: str, mapping: dict) -> str | None:
    """The lane for a whole file, or None when it comes from each record."""
    how = mapping["host"]["from"]
    if how == "name":
        return mapping["host"]["name"]
    if how == "folder":
        host = case.host_of(rel_path)
        if host is None:
            raise MappingError("The file is in the evidence folder's top level, which belongs to no host; "
                               "type a host name for its lane, or choose a field.")
        return host
    return None


class EventBuilder:
    """Turns one file's records into events by a checked mapping whose zone is resolved."""

    def __init__(self, case: Case, rel_path: str, mapping: dict):
        self.rel_path = rel_path
        self.m = mapping
        self.t = mapping["time"]
        self.clock = ZoneClock(self.t.get("zone_resolved"))
        self.lane = host_lane(case, rel_path, mapping)
        self.ignore = set(mapping["ignore"])
        self.f = mapping["fields"]
        self.year = self.t.get("year") if needs_year(self.t["format"]) else None
        self.last_us: int | None = None   # the last year-less time read, to see a new year begin

    def time(self, rec: dict, stats: Stats) -> int | None:
        text = " ".join(rec.get(c, "") for c in self.t["columns"]).strip()
        if self.year:
            parsed = parse_time(*time_with_year(text, self.t["format"], self.year))
            if parsed and self.last_us is not None and parsed.us < self.last_us - ROLLOVER_US:
                self.year += 1   # December to January
                parsed = parse_time(*time_with_year(text, self.t["format"], self.year))
            if parsed:
                self.last_us = parsed.us
        else:
            parsed = read_time(text, self.t)
        if parsed is None:
            if text and len(stats.bad_times) < 5:
                stats.bad_times.append(text)
            return None
        if parsed.zoned:
            return parsed.us
        offset_field = self.t.get("zone_column")
        if offset_field and OFFSET.match(rec.get(offset_field) or ""):
            return parsed.us - offset_minutes(rec[offset_field]) * 60_000_000
        return self.clock.to_utc(parsed.us)

    def event(self, number: str, rec: dict, stats: Stats) -> Event:
        mapped = {role: _value(rec.get(col)) for role, col in self.f.items()}
        g = lambda role: mapped.get(role, "")
        source_ip, source_port = endpoint(g("source_ip"))
        dest_ip, dest_port = endpoint(g("dest_ip"))
        domain, name = split_account(g("user"))
        logon_id = g("logon_id")
        if self.m["message"]:
            message = render(self.m["message"], rec)
        elif "message" in self.f:
            message = g("message")
        else:
            message = " ".join([f"{k}={clean(v)}" for k, v in rec.items() if k not in self.ignore and clean(v)][:12])
        ts = self.time(rec, stats)
        if ts is None:
            stats.without_time += 1
        lane = self.lane
        if lane is None:
            lane = clean(rec.get(self.m["host"]["column"])) or self.m["host"]["fallback"] or "UNKNOWN"
        return Event(
            ts_us=ts, ts_desc=TS_DESC, artifact=self.m["artifact"], source_file=self.rel_path, source_record=number,
            message=message[:MAX_MESSAGE], host_name_recorded=g("computer"), event_code=g("code"),
            event_provider=g("provider"), log_channel=g("channel"), user_name=name, user_domain=g("domain") or domain,
            source_ip=source_ip, source_port=port_number(g("source_port")) or source_port,
            source_workstation=g("workstation"), logon_type=g("logon_type"),
            logon_id="" if NO_LOGON.match(logon_id) else logon_id, process_executable=g("process"),
            process_command_line=g("command_line"), process_parent_executable=g("parent"),
            process_parent_command_line=g("parent_command_line"), file_path=g("path"), dest_ip=dest_ip,
            dest_port=port_number(g("dest_port")) or dest_port,
            # The file's key is the path's, else the process's, and only for a Windows-form path (file_key gives none for a
            # Unix or URL path or a bare name); the file name still joins through Same file name
            file_key=file_key(g("path") or g("process")),
            extra={k: v for k, v in rec.items() if v not in ("", "-") and k not in self.ignore} or None, lane=lane)

    def events(self, path: Path, stats: Stats) -> Iterator[Event]:
        try:
            for number, rec in records(path, self.m, stats):
                yield self.event(number, rec, stats)
        finally:
            self.clock.close()


# ---------- preview, checks, and the import itself ----------

def host_zones(case: Case) -> dict[str, dict]:
    """Each host's zone from its SYSTEM hive, read from the events database when there is one. The server passes
    its own, since a second connection in the same process can't open the database read-only."""
    if not case.db_path.exists():
        return {}
    con = connect(case.db_path, read_only=True)
    try:
        return host_timezones(con)
    finally:
        con.close()


def check(case: Case, sample: Sample, mapping: dict, zones: dict[str, dict]) -> tuple[dict | None, list[str], list[str]]:
    """The mapping, normalized and with its zone resolved, plus what blocks the import and what only warns."""
    problems, warnings = [], []
    try:
        m = normalize_mapping(mapping)
    except MappingError as exc:
        return None, [str(exc)], []
    try:
        host_lane(case, sample.path, m)
    except MappingError as exc:
        problems.append(str(exc))
    if not sample.records:
        problems.append("No records were read from the file in this format.")
    have = set(sample.columns)
    problems.extend(f"The time field {c!r} isn't in the records read." for c in m["time"]["columns"] if c not in have)
    missing = sorted({c for c in m["fields"].values() if c not in have})
    if missing:
        warnings.append(f"Not in the records read: {', '.join(missing)}. Events from those records leave them empty.")
    times = [read_time(" ".join(rec.get(c, "") for c in m["time"]["columns"]), m["time"])
             for _, rec in sample.records]
    read = [t for t in times if t]
    if needs_year(m["time"]["format"]) and not m["time"].get("year"):
        problems.append("These times have no year, as syslog, Cisco ASA, and Snort write them. Type the year of the "
                        "file's first record.")
    elif sample.records and not read:
        problems.append("None of the times read fit the time format.")
    elif len(read) < len(times):
        warnings.append(f"{len(times) - len(read)} of the first {len(times)} times don't fit the format; "
                        "those events have no time and stay off the timeline.")
    needs_zone = any(not t.zoned for t in read)
    if needs_zone and m["time"].get("zone_column"):
        offsets = [OFFSET.match(rec.get(m["time"]["zone_column"]) or "") for _, rec in sample.records]
        needs_zone = not all(offsets)
    try:
        resolved = resolve_zone(m["time"]["zone"], zones)
    except ZoneError as exc:
        problems.append(str(exc))
    else:
        if resolved:
            m["time"]["zone_resolved"] = resolved   # also for records further on that carry no zone
        elif needs_zone:
            problems.append("The times carry no zone. Choose the zone they were written in: UTC, a host's zone, "
                            "or another zone.")
    return m, problems, warnings


def preview(case: Case, rel_path: str, mapping: dict | None = None, zones: dict[str, dict] | None = None,
            rows: int = PREVIEW_ROWS, year_hint: int | None = None) -> dict:
    """What the import page shows: the file's records, the mapping (guessed when none is given), the events the
    first records become, and anything that blocks the import. year_hint is the year of the case's latest events,
    which the server passes from its own connection; times without a year default to it."""
    zones = host_zones(case) if zones is None else zones
    if mapping is not None:
        mapping = resolve_named(case, rel_path, mapping)
    sample = sniff(case, rel_path, mapping)
    saved = saved_mappings(case)
    guessed = mapping is None
    mapping = guess_mapping(sample, saved) if guessed else {**mapping, "format": sample.format,
                                                            "delimiter": sample.delimiter, **_layout_of(sample)}
    # A time field chosen without a format, as the page sends when the analyst picks a new one: guess the format,
    # and say why when the values can't settle it.
    hint, t = "", mapping.get("time") or {}
    if t.get("columns") and not t.get("format"):
        g = guess_time_format([" ".join(rec.get(c, "") for c in t["columns"]) for _, rec in sample.records])
        mapping, hint = {**mapping, "time": {**t, "format": g.format}}, g.problem
    year_note, t = "", mapping.get("time") or {}
    if needs_year(t.get("format") or ""):
        year, source = t.get("year"), ""
        if not year:
            year = year_hint if year_hint is not None else case_year(case)
            source = ", the year of the case's latest events"
            if year:
                mapping = {**mapping, "time": {**t, "year": year}}
        if year:
            year_note = (f"These times have no year, so the first reads as {year}{source}, and a time that jumps back "
                         "over six months starts the next year. Change the year if the log starts in another.")
    m, problems, warnings = check(case, sample, mapping, zones)
    if hint:
        problems = [hint] + [p for p in problems if not p.startswith("Choose how the times")]
    if year_note:
        warnings = [year_note] + warnings
    events = []
    if m is not None and not problems:
        builder = EventBuilder(case, rel_path, m)
        stats = Stats()
        try:
            for number, rec in sample.records[:rows]:
                ev = builder.event(number, rec, stats)
                events.append({"record": number, "ts": ev.ts_us, "host": ev.lane, "message": ev.message,
                               "fields": {r: getattr(ev, a) for r, a in EVENT_ATTR.items() if getattr(ev, a)}})
        finally:
            builder.clock.close()
    # A JSON array is read by the JSON lines reader, and named and counted as what it is
    label = "JSON array" if sample.stats.array is not None else FORMATS[sample.format]
    return {"path": rel_path, "format": sample.format, "format_label": label,
            "delimiter": sample.delimiter, "product": sample.product, "columns": sample.columns,
            "layout": sample.layout, "needs_year": needs_year(((m or mapping).get("time") or {}).get("format") or ""),
            "records": [{"record": n, "fields": rec} for n, rec in sample.records[:rows]],
            "skipped": sample.stats.skipped, "mapping": m or mapping, "guessed": guessed, "problems": problems,
            "warnings": warnings, "events": events, "lines": count_lines(_evidence_file(case, rel_path)),
            "array_records": sample.stats.array,
            "lane": _lane_text(case, rel_path, m) if m else "", "imported": last_import(case, rel_path)}


def _layout_of(sample: Sample) -> dict:
    return {"layout": sample.layout} if sample.layout else {}


def case_year(case: Case, con: duckdb.DuckDBPyConnection | None = None) -> int | None:
    """The year of the case's latest events, leaving out the latest 1% as strays; None for a case without events.
    The server passes a cursor on its own connection, which holds the database open."""
    if con is None:
        if not case.db_path.exists():
            return None
        con = connect(case.db_path, read_only=True)
        try:
            return case_year(case, con)
        finally:
            con.close()
    try:
        row = con.execute("SELECT quantile_disc(ts_us, 0.99) FROM events WHERE ts_us IS NOT NULL").fetchone()
    except duckdb.Error:
        return None
    return from_us(row[0]).year if row and row[0] is not None else None


EVENT_ATTR = {"source_ip": "source_ip", "source_port": "source_port", "dest_ip": "dest_ip", "dest_port": "dest_port",
              "user": "user_name", "domain": "user_domain", "workstation": "source_workstation",
              "logon_id": "logon_id", "logon_type": "logon_type",
              "computer": "host_name_recorded", "code": "event_code", "provider": "event_provider",
              "channel": "log_channel", "process": "process_executable", "command_line": "process_command_line",
              "parent": "process_parent_executable", "parent_command_line": "process_parent_command_line",
              "path": "file_path"}


def _lane_text(case: Case, rel_path: str, m: dict) -> str:
    try:
        lane = host_lane(case, rel_path, m)
    except MappingError:
        return ""
    return lane if lane is not None else f"from {m['host']['column']}"


def run_import(case: Case, rel_path: str, mapping: dict, zones: dict[str, dict] | None = None):
    """Import one file as a run: check the mapping on the file's first records, check the file's hash, read and load
    every record, check the hash again, and record it all in run.json."""
    zones = host_zones(case) if zones is None else zones
    if rel_path in loaded_as_output(case):
        raise MappingError(f"{rel_path} is loaded already, as found output from the Tools page; importing it would "
                           "load its events a second time.")
    mapping = resolve_named(case, rel_path, mapping)
    sample = sniff(case, rel_path, mapping)
    m, problems, _ = check(case, sample, {**mapping, "format": sample.format, "delimiter": sample.delimiter,
                                          **_layout_of(sample)}, zones)
    if problems:
        raise MappingError(" ".join(problems))
    record, folder = start_run(case, TOOL, re.sub(r"[^A-Za-z0-9_.-]", "_", Path(rel_path).name)[:48],
                               tool_version=build_id(), host=_lane_text(case, rel_path, m), inputs=[rel_path],
                               parser=TOOL, mapping=m)
    t0 = time.perf_counter()
    before = verify(case, [rel_path], reason=f"before import {record.run_id}")
    if before:
        record.evidence_check, record.evidence_problems = check_result(before), before
        record.status = "failed"
        record.reason = (not_reread("the check before the import", before, "import it again")
                         if record.evidence_check == UNREADABLE
                         else f"the file doesn't match its intake hash: {'; '.join(before)}")
    else:
        try:
            load_import(case, record, folder)
        except (MappingError, OSError, ValueError, duckdb.Error) as exc:
            record.status, record.reason = "failed", f"could not load: {exc}"
            finish_run(folder, record)
            raise MappingError(record.reason) from exc
        after = verify(case, [rel_path], reason=f"after import {record.run_id}")
        record.evidence_check, record.evidence_problems = check_result(after), after
        record.status = "ok" if not after else "failed"
        if record.evidence_check == UNREADABLE:
            record.reason = not_reread("the check after the import", after, "import it again")
        elif after:
            record.reason = "evidence changed during the import"
    record.seconds = round(time.perf_counter() - t0, 2)
    finish_run(folder, record)
    return record


def load_import(case: Case, record, folder: Path) -> None:
    """Read an import's file by its recorded mapping and replace the file's events. Also used by rebuild."""
    path = _evidence_file(case, record.inputs[0])
    stats = Stats()
    builder = EventBuilder(case, record.inputs[0], record.mapping)
    t0 = time.perf_counter()
    result = load(case.db_path, builder.events(path, stats), host=None, tool=record.tool,
                  tool_version=record.tool_version, run_id=record.run_id, replaces_sources=record.inputs,
                  staging_dir=folder)
    record.loaded_rows, record.replaced_rows, record.rows_without_time = result.rows, result.replaced, result.without_time
    record.load_seconds = round(time.perf_counter() - t0, 2)
    if records_format_4(case):
        record.rows_skipped = stats.skipped
    zone = (record.mapping["time"].get("zone_resolved") or {}).get("label")
    notes = [f"Times without a zone read as {zone}." if zone else "Times carry their own zone."]
    if stats.skipped:
        notes.append("1 line wasn't a record and was skipped." if stats.skipped == 1
                     else f"{stats.skipped:,} lines weren't records and were skipped.")
    if stats.bad_times:
        notes.append(f"{result.without_time:,} records have no time that fits the format, such as "
                     + "; ".join(repr(t) for t in stats.bad_times[:3]) + ".")
    record.notes = notes


def count_lines(path: Path) -> int:
    return _count_lines(str(path), *file_stamp(path))


@lru_cache(maxsize=256)
def _count_lines(path: str, size: int, mtime_ns: int) -> int:
    n, last = 0, b"\n"
    with open(path, "rb") as f:
        while chunk := f.read(8 << 20):
            n += chunk.count(b"\n")
            last = chunk[-1:]
    return n + (last != b"\n")


def _evidence_file(case: Case, rel_path: str) -> Path:
    """An evidence file by its manifest path, in extended-length form (long_path), so the file opened is the one the
    manifest names; refuses paths outside the evidence folder or not in the manifest, and a file that is a cloud
    placeholder now, since opening it would download it. A manifest file's attributes are read before the path is
    resolved or opened. Every read of an import's file takes its path from here."""
    root = long_path(case.evidence)
    path = long_path(root, rel_path)
    in_manifest = rel_path in _manifest_paths(case, *file_stamp(case.manifest_path))
    if in_manifest and placeholders_among(case, [rel_path]):
        raise MappingError(_placeholder_refusal(case, rel_path))
    if not path.resolve().is_relative_to(root) or not path.is_file():
        raise MappingError(f"Not an evidence file: {rel_path}")
    if not in_manifest:
        raise MappingError(f"{rel_path} isn't in the manifest yet; use Add new evidence first.")
    return path


def _placeholder_refusal(case: Case, rel_path: str) -> str:
    """Why the import won't read a manifest file that is a cloud placeholder now: intake hashed it before it became one,
    recorded it as one, or couldn't read it for another reason, such as a lock."""
    error = {e.path: e.error for e in current_entries(case)}[rel_path]
    hashed = not error
    if hashed:
        when = "intake hashed it before it became a cloud placeholder"
    elif error == PLACEHOLDER:
        when = "intake recorded it as a cloud placeholder"
    else:
        when = "intake couldn't read it, and it is a cloud placeholder now"
    return f"The file wasn't read: {when}. {cloud_placeholders_text([rel_path], 'the import', hashed=hashed)}"


@lru_cache(maxsize=4)
def _manifest_paths(case: Case, size: int, mtime_ns: int) -> frozenset[str]:
    return frozenset(e.path for e in read_manifest(case))


# ---------- files to import, saved mappings, and earlier imports ----------

def listed_as(entry) -> tuple[str | None, str]:
    """The artifact and detail the Import page lists a manifest entry under. Output in local time, such as an Autoruns
    CSV, is listed as a CSV: the Tools page's load needs the host's SYSTEM hive, and the import is the way to load it
    without one, or at an offset the analyst knows."""
    if entry.artifact == "tool_output" and (kind := BY_KIND.get(entry.detail)) and kind.parser in LOCAL_TIME:
        return "csv", kind.label
    return entry.artifact, entry.detail


def loaded_as_output(case: Case, runs: list | None = None) -> dict[str, dict]:
    """Files loaded as a tool's output found in the evidence, such as an Autoruns CSV from the Tools page, by path:
    importing one would load its events a second time."""
    out = {}
    for r in read_runs(case) if runs is None else runs:   # oldest first, so the latest load wins
        if r.from_output and r.status == "ok":
            for p in r.inputs:
                out[p] = {"rows": r.loaded_rows, "at": r.finished_utc}
    return out


def importable(case: Case, include_unidentified: bool = False) -> list[dict]:
    """Evidence files the import reads: text logs, identified at intake or read again since (intake.current_entries),
    such as unidentified files from a case taken in before the import existed, and, on request, every other
    unidentified file. A file loaded as found output says so in `loaded`, and the import refuses it."""
    runs = read_runs(case)
    imports = {r.inputs[0]: r for r in runs if r.tool == TOOL and r.status == "ok"}
    loaded = loaded_as_output(case, runs)
    out = []
    for e in current_entries(case):
        artifact, detail = listed_as(e)
        if artifact in IMPORTABLE or (include_unidentified and artifact is None and not e.error):
            r = imports.get(e.path)
            out.append({"path": e.path, "artifact": artifact or "", "detail": detail, "size": e.size,
                        "host": case.host_of(e.path), "added_utc": e.added_utc,
                        "imported": {"run_id": r.run_id, "rows": r.loaded_rows, "at": r.finished_utc,
                                     "mapping": r.mapping.get("saved_as") or r.mapping.get("preset") or ""} if r else None,
                        "loaded": loaded.get(e.path)})
    return out


def last_import(case: Case, rel_path: str) -> dict | None:
    runs = [r for r in read_runs(case) if r.tool == TOOL and r.inputs == [rel_path]]
    if not runs:
        return None
    r = runs[-1]
    return {"run_id": r.run_id, "status": r.status, "rows": r.loaded_rows, "at": r.finished_utc, "reason": r.reason}


def mappings_folder(case: Case) -> Path:
    return case.folder / "mappings"


def saved_mappings(case: Case) -> dict[str, dict]:
    """Mappings saved in the case's mappings folder, newest first."""
    folder = mappings_folder(case)
    if not folder.is_dir():
        return {}
    out = {}
    for p in sorted(folder.glob("*.json"), key=lambda p: p.stat().st_mtime_ns, reverse=True):
        try:
            out[p.stem] = normalize_mapping(json.loads(p.read_text(encoding="utf-8")))
        except (ValueError, OSError):
            continue   # a hand-edited file that doesn't parse is left alone, and not offered
    return out


def check_mapping_name(name: str) -> str:
    """The name, when save_mapping can save a mapping under it; otherwise a MappingError that says what a name may
    hold. An import checks its save-as name with this before its first file, so a refused name imports nothing."""
    if not NAME.fullmatch(name or ""):
        raise MappingError("A mapping name uses letters, digits, dots, dashes, and underscores, such as palo-alto-traffic.")
    return name


def save_mapping(case: Case, name: str, mapping: dict) -> str:
    check_mapping_name(name)
    m = normalize_mapping(mapping)
    m.pop("saved_as", None)
    m["time"].pop("zone_resolved", None)   # resolved again for each file, from the hosts' zones at the time
    folder = mappings_folder(case)
    folder.mkdir(exist_ok=True)
    write_atomically(folder / f"{name}.json", json.dumps(m, indent=2))
    return name


def mapping_named(case: Case, name: str) -> dict:
    """A saved mapping, a ready-made one by name, or a mapping file."""
    saved = saved_mappings(case)
    if name in saved:
        return {**saved[name], "saved_as": name}
    if name in PRESETS:
        return {"preset": name}
    path = Path(name)
    if path.suffix.lower() == ".json" and path.is_file():
        return normalize_mapping(json.loads(path.read_text(encoding="utf-8")))
    raise MappingError(f"No mapping {name!r}: saved ones are {sorted(saved) or 'none yet'}; ready-made ones are "
                       f"{sorted(PRESETS)}; or give a .json file.")


def resolve_named(case: Case, rel_path: str, mapping: dict) -> dict:
    """A {"preset": name} placeholder becomes that preset applied to the file's fields, and {"saved": name} that
    saved mapping."""
    if set(mapping) == {"saved"}:
        saved = saved_mappings(case)
        if mapping["saved"] not in saved:
            raise MappingError(f"No saved mapping {mapping['saved']!r}.")
        return {**saved[mapping["saved"]], "saved_as": mapping["saved"]}
    if set(mapping) == {"preset"}:
        p = PRESETS[mapping["preset"]]
        return apply_preset(mapping["preset"], sniff(case, rel_path, {"format": p["format"], "layout": p.get("layout")}))
    return mapping
