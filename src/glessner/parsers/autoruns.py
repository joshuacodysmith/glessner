"""Parses Sysinternals Autoruns CSVs found in the evidence (autorunsc -c) as an inventory of autostart entries.

One event per entry: the image path is the file path, so Same file joins the binary's MFT and prefetch records; the
launch string is the command line; the entry's location is the registry key where it is one; and the signer, company,
description, version, and hashes stay in the details. The category is the channel, and a user profile's entry has
that account. Autoruns also writes a row for each location, with no entry; those rows aren't entries, so their time
goes into the details of the entries under them, as LocationLastWritten.

Autoruns' Time column isn't when an entry was set. Sysinternals' own reference (Margosis and Russinovich,
Troubleshooting with the Windows Sysinternals Tools, 2nd edition, the Autoruns chapter) says: for an image that is a
PE file, it is when the linker built the image; for another file, such as a script, the file's last write time; on a
location's row, the key's or folder's last modification. The CSV doesn't say whether Autoruns found a PE file, so the
event's time description follows the image's extension. Windows 10 links its own binaries with a hash in place of a
time, so their times fall anywhere from 1902 to 2037. Autoruns gives no time when it can't read the image, such as a
file not found.

Times are local to the computer Autoruns ran on, to the minute, in its date format, unless it ran with -t, which writes
UTC as YYYYMMDD-hhmmss. Autoruns converts every time at the one UTC offset in force when it ran, as Windows'
FileTimeToLocalFileTime does, not at the offset each date had. For example, the Szechuan case's DESKTOP ran
Autoruns in September, and its December dates, read with Pacific standard time, fell an hour after the MFT's and
RECmd's records of the same writes. So all of a CSV's local times are read at one offset: the host's ActiveTimeBias
from its SYSTEM hive, as a live collection runs on the host (runner.host_zone), or else the host zone's offset at the
newest location row's time, the nearest the CSV comes to saying when Autoruns ran. A CSV made offline with -z carries
the analyzing computer's zone instead, which nothing in the file shows.
"""

from __future__ import annotations

import csv
import io
import re
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path, PureWindowsPath

from ..events import EPOCH, Event, from_us
from ..identify import text_encoding
from ..timezones import DATE_TIME, ZoneClock, fmt_offset, parse_time
from .common import LOCAL_TIME_NOTE, ParseContext, command_file, evidence_relative, file_key, output_paths

OUTPUT_FILE = "*.csv"   # the app doesn't run Autoruns: a found CSV is known by its header (tool_outputs.py)
BUILT = "Image built (PE link time)"
WRITTEN = "Image file last written"
NO_TIME = "Autoruns entry without a time"
# Extensions of PE images: programs, DLLs, drivers, codecs (.ax, .acm), Control Panel items, screen savers, and kin.
PE_EXTENSIONS = frozenset(".exe .dll .sys .drv .ocx .cpl .scr .ax .acm .efi .tsp .com .ime".split())
NOT_FOUND = "File not found: "   # Autoruns' image path when the file is gone, before the path it looked for
UTC_STAMP = re.compile(r"^\d{8}-\d{6}$")   # -t: "normalized UTC", YYYYMMDD-hhmmss
REGISTRY_ROOTS = ("HKLM\\", "HKCU\\", "HKU\\", "HKCR\\", "HKCC\\", "HKEY_")
MINUTE_US = 60_000_000
# Where a load that can't read the times sends the analyst: the Import page lists Autoruns CSVs for this (imports.py).
IMPORT_IT = ("import the CSV on the Import page, with the UTC offset the computer had when Autoruns ran, such as "
             "-07:00, since Autoruns wrote every time at that one offset")


def parse_autoruns(ctx: ParseContext) -> Iterator[Event]:
    for path in output_paths(ctx, "autoruns", OUTPUT_FILE):
        yield from _parse_file(path, ctx)


def _parse_file(path: Path, ctx: ParseContext) -> Iterator[Event]:
    rows = _rows(path)
    times = _read_times(rows, ctx)
    source = evidence_relative(str(path), ctx.evidence_root)
    location_time: dict[str, str] = {}
    for line, row in rows:
        g = lambda k, row=row: (row.get(k) or "").strip()
        location, entry, written = g("Entry Location"), g("Entry"), g("Time")
        if not entry:   # a location's own row: its key's or folder's last modification
            if written:
                location_time[location] = f"{_iso(times[written])} UTC ({written} as written)"
            continue
        image = g("Image Path")
        path_text = image.removeprefix(NOT_FOUND)
        # "File not found: " can stand before a command fragment, which is no file
        file_path = path_text if re.match(r"^(?:[A-Za-z]:\\|\\\\)", path_text) else ""
        if not written:
            desc = NO_TIME
        elif PureWindowsPath(file_path or path_text).suffix.lower() in PE_EXTENSIONS:
            desc = BUILT
        else:
            desc = WRITTEN
        extra = {k: v for k, v in row.items() if k and v}
        if location in location_time:
            extra["LocationLastWritten"] = location_time[location]
        domain, _, name = g("Profile").rpartition("\\") if g("Profile") != "System-wide" else ("", "", "")
        launch, signer = g("Launch String"), g("Signer")
        # An entry whose image path names no file (empty, or a fragment after "File not found: ") is keyed from the program its
        # launch string runs, which is shown as its process. This comes after the time description is chosen from the image
        # path above, since that description is part of the event's ID.
        program = "" if file_path else command_file(launch)
        program = program if file_key(program) else ""
        parts = [f"{g('Category')}: {entry}", image]
        if g("Enabled").lower() == "disabled":
            parts.append("disabled")
        if "Signer" in row:   # written with -s; empty when Autoruns found no signature
            parts.append(signer or "no signer")
        if launch and launch.lower() != image.lower():
            parts.append(f"Runs: {launch}")
        yield Event(
            ts_us=times[written] if written else None, ts_desc=desc, artifact="autoruns",
            source_file=source, source_record=str(line), message=" | ".join(p for p in parts if p),
            event_provider="Autoruns", log_channel=g("Category"), user_name=name, user_domain=domain,
            process_command_line=launch, process_executable=program, file_path=file_path,
            file_key=file_key(file_path or program),
            registry_path=location if location.upper().startswith(REGISTRY_ROOTS) else "", extra=extra)


def _rows(path: Path) -> list[tuple[int, dict[str, str]]]:
    """The CSV's rows, each with the line it ends on. autorunsc writes UTF-16 with a byte order mark; UTF-8 is read
    too, as a copy saved by another program may be. A location's row is one column short, which leaves IMP out."""
    raw = path.read_bytes()
    text = raw.decode(text_encoding(raw[:2]), errors="replace")
    reader = csv.reader(io.StringIO(text, newline=""))
    header = [h.strip() for h in next(reader, [])]
    return [(reader.line_num, dict(zip(header, row))) for row in reader if any(row)]


def _read_times(rows: list[tuple[int, dict[str, str]]], ctx: ParseContext) -> dict[str, int]:
    """Every Time value in the file, read to UTC microseconds, after settling the file's date order from all its
    values: a first part above 12 is a day, and so is a second part above 12. Raises ValueError, with the reason, when
    the order can't be settled, when a value can't be read, or when local times have no offset to be read at: a file
    whose times all failed once loaded with none, under a link time's description. Notes in ctx the
    offset local times were read at, when there were any."""
    values = {(r.get("Time") or "").strip() for _, r in rows} - {""}
    out: dict[str, int] = {}
    for text in sorted(v for v in values if UTC_STAMP.match(v)):
        try:
            dt = datetime.strptime(text, "%Y%m%d-%H%M%S").replace(tzinfo=UTC)
        except ValueError:
            raise ValueError(_unread(text)) from None
        out[text] = (dt - EPOCH) // timedelta(microseconds=1)
    local = sorted(values - out.keys())
    if not local:
        return out
    order = "mdy"
    matches = [m for m in (DATE_TIME.match(v) for v in local) if m]
    if matches and all(len(m.group(1)) == 4 for m in matches):
        order = "ymd"
    elif any(int(m.group(1)) > 12 for m in matches if len(m.group(1)) <= 2):
        order = "dmy"
    elif matches and not any(int(m.group(2)) > 12 for m in matches):
        raise ValueError(f"Autoruns' dates here, such as {local[0]!r}, could be month/day or day/month. Import the "
                         "CSV on the Import page and choose the date order, with the UTC offset the computer had when "
                         "Autoruns ran.")
    parsed = {v: parse_time(v, order) for v in local}
    if (bad := next((v for v in local if parsed[v] is None), None)) is not None:
        raise ValueError(_unread(bad))
    naive = [v for v in local if not parsed[v].zoned]
    out.update((v, parsed[v].us) for v in local if parsed[v].zoned)
    if naive:
        locations = [(r.get("Time") or "").strip() for _, r in rows if not (r.get("Entry") or "").strip()]
        newest = max(((parsed[v].us, v) for v in locations if v in naive), default=None)
        minutes, how = _offset(ctx.zone, newest)
        out.update((v, parsed[v].us - minutes * MINUTE_US) for v in naive)
        ctx.notes.append(f"{LOCAL_TIME_NOTE}{how}.")
    return out


def _offset(zone: dict | None, newest: tuple[int, str] | None) -> tuple[int, str]:
    """The one UTC offset, in minutes, to read local times at, and how it was found. A zone with daylight saving rules
    gives its offset at the newest location row's time, a key's or folder's last change before Autoruns ran."""
    kind = (zone or {}).get("kind")
    if kind == "utc":
        return 0, "UTC"
    if kind == "offset":
        return zone["minutes"], zone["label"]
    if kind == "iana" and newest:
        clock = ZoneClock(zone)
        try:
            minutes = (newest[0] - clock.to_utc(newest[0])) // MINUTE_US
        finally:
            clock.close()
        return minutes, (f"UTC{fmt_offset(minutes)}, the offset of {zone['label']}, at the newest location row's time, "
                         f"{newest[1]}")
    if kind == "iana":
        raise ValueError("Autoruns wrote its times in the local time of the computer it ran on, at the offset in force "
                         "then. This host's SYSTEM hive records no ActiveTimeBias, and the CSV has no location row "
                         f"time to take the zone's offset at: {IMPORT_IT}.")
    raise ValueError("Autoruns wrote its times in the local time of the computer it ran on, and this host's zone isn't "
                     f"known: load or run RECmd on the host's SYSTEM hive first, or {IMPORT_IT}.")


def _unread(text: str) -> str:
    return (f"Autoruns' time {text!r} isn't a date and time the app reads, so no entry was loaded. Import the CSV on "
            "the Import page and give its time format, with the UTC offset the computer had when Autoruns ran.")


def _iso(us: int) -> str:
    return f"{from_us(us):%Y-%m-%d %H:%M}"
