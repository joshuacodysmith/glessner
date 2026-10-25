"""Time zones and clock times: host zones, from each SYSTEM hive's TimeZoneInformation key as
RECmd's DFIRBatch records it, for the page's zone axes and the hosts' local times; and reading a time written as text,
with or without its zone, into UTC, for the import (imports.py) and Autoruns' parser.

Windows names its zones, such as "Pacific Standard Time"; browsers and the tz database use IANA names, such
as "America/Los_Angeles". Windows 10 and later ship ICU, whose ucal_getTimeZoneIDForWindowsID gives the CLDR
mapping, so no mapping table is copied here. Where ICU or a match is missing, or the host had daylight saving
turned off, a zone falls back to the registry's fixed Bias, without daylight saving rules, and says so.
"""

from __future__ import annotations

import ctypes
import functools
import re
import sys
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import duckdb

from .events import EPOCH, NO_EXTENSION_FETCH, live_hive_first

VALUES = ("TimeZoneKeyName", "Bias", "DaylightBias", "StandardStart", "DaylightStart", "DynamicDaylightTimeDisabled",
          "ActiveTimeBias")
IANA_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_+\-]*(/[A-Za-z0-9_+\-]+){0,2}$")   # such as Europe/London or Etc/GMT+8
MAX_AXES = 6
ONE_US = timedelta(microseconds=1)
QUARTER_US = 15 * 60 * 1_000_000   # zone offsets are looked up per local quarter hour; every DST rule changes on one


class ZoneError(ValueError):
    """A zone choice that can't be read, with the reason in the analyst's terms."""


@functools.cache
def windows_to_iana(name: str) -> str:
    """The IANA zone for a Windows zone name, from the ICU that ships with Windows, or '' when there is none."""
    if sys.platform != "win32" or not name:
        return ""
    try:
        fn = ctypes.WinDLL("icu.dll").ucal_getTimeZoneIDForWindowsID
    except (OSError, AttributeError):
        return ""
    fn.restype = ctypes.c_int32
    fn.argtypes = [ctypes.c_wchar_p, ctypes.c_int32, ctypes.c_char_p, ctypes.c_wchar_p, ctypes.c_int32,
                   ctypes.POINTER(ctypes.c_int)]
    buf = ctypes.create_unicode_buffer(128)
    status = ctypes.c_int(0)
    n = fn(name, -1, None, buf, len(buf), ctypes.byref(status))
    return buf.value[:n] if status.value <= 0 and n > 0 else ""


def zone_key_name(text: str) -> str:
    """A TimeZoneKeyName as Windows reads it, up to the value's terminating null. RECmd can write the bytes that follow
    the null in the value's data too, such as "Eastern Standard Time ard Time". Where the null isn't kept, the name is
    its longest run of leading words that names a Windows zone, or the whole text when none does."""
    name = text.split("\x00", 1)[0].strip()
    if windows_to_iana(name):
        return name
    words = name.split()
    for end in range(len(words) - 1, 0, -1):
        leading = " ".join(words[:end])
        if windows_to_iana(leading):
            return leading
    return name


def host_timezones(con: duckdb.DuckDBPyConnection) -> dict[str, dict]:
    """Each host's zone from its live SYSTEM hive, from the lowest-numbered control set that records one. Values come
    from one hive file and key, so a Windows.old or RegBack copy, which has the same key paths, can't mix in."""
    raw: dict[str, dict] = {}
    names = ", ".join(f"'{v}'" for v in VALUES)
    for host, source, path, name, data in con.execute(
            "SELECT host, source_file, registry_path, registry_value, json_extract_string(NULLIF(extra, ''), '$.ValueData') "
            f"FROM events WHERE tool = 'recmd' AND registry_path ILIKE '%\\Control\\TimeZoneInformation' "
            f"AND registry_value IN ({names}) ORDER BY host, {live_hive_first('system')}, registry_path").fetchall():
        values = raw.setdefault(host, {"_path": path, "_key": (source, path)})
        if values["_key"] == (source, path):
            values[name] = (data or "").strip()
    zones = {}
    for host, values in raw.items():
        windows, bias = zone_key_name(values.get("TimeZoneKeyName", "")), _int(values.get("Bias"))
        if not windows and bias is None:
            continue
        dst_off = values.get("DynamicDaylightTimeDisabled") == "1"
        zones[host] = {
            "windows": windows,
            "iana": "" if dst_off else windows_to_iana(windows),
            "bias_minutes": bias,                    # UTC = local time + bias
            # The bias in force when the hive was last written, daylight saving included. Autoruns writes every time
            # at the offset in force when it ran, so its local times are read at this one.
            "active_bias_minutes": _dword(values.get("ActiveTimeBias")),
            "dst_disabled": dst_off,
            "daylight_start": values.get("DaylightStart", ""),
            "standard_start": values.get("StandardStart", ""),
            "source": "SYSTEM hive " + values["_path"].split("\\", 1)[-1],   # without the hive's root key name
        }
    return zones


def validate_axes(value, hosts: set[str]) -> list[dict]:
    """The zone axes setting: up to MAX_AXES of {"host": name} for a host's own zone, or {"zone": IANA name}."""
    if not isinstance(value, list) or len(value) > MAX_AXES:
        raise ValueError(f"time_zones must be a list of at most {MAX_AXES} zones")
    out, seen = [], set()
    for item in value:
        if isinstance(item, dict) and set(item) == {"host"} and item["host"] in hosts:
            axis = {"host": item["host"]}
        elif isinstance(item, dict) and set(item) == {"zone"} and isinstance(item["zone"], str) and IANA_NAME.match(item["zone"]):
            axis = {"zone": item["zone"]}
        else:
            raise ValueError("each time zone is {'host': a case host} or {'zone': an IANA name such as Europe/London}")
        key = tuple(axis.items())
        if key not in seen:
            seen.add(key)
            out.append(axis)
    return out


def _int(text: str | None) -> int | None:
    try:
        return int(str(text).strip())
    except (TypeError, ValueError):
        return None


def _dword(text: str | None) -> int | None:
    """A signed DWORD, such as a bias east of UTC, which is negative, read whether it was written signed or not."""
    value = _int(text)
    return value - (1 << 32) if value is not None and value > 0x7FFFFFFF else value


# ---------- reading times ----------

# Possessive (++, *+), so each run of spaces is read once: as [T\s]+ and \s* the runs could be split every way, and
# matching time would grow with the cube of a run's length, 21.9 s for 2 KB of spaces.
DATE_TIME = re.compile(
    r"^\s*+(\d{1,4})[-/.](\d{1,2})[-/.](\d{1,4})"
    r"(?:(?:[T\s]++|:)(\d{1,2}):(\d{2})(?::(\d{2})(?:[.,](\d{1,9}))?)?)?"
    r"\s*+([AaPp]\.?[Mm]\.?)?"
    r"\s*+(Z|UTC|GMT|[+-]\d{2}(?::?\d{2})?)?\s*+$")
EPOCH_NUMBER = re.compile(r"^\s*(\d{9,20})(?:\.(\d+))?\s*$")
OFFSET = re.compile(r"^\s*(?:UTC|GMT)?\s*([+-])(\d{1,2}):?(\d{2})?\s*$")


@dataclass(frozen=True)
class Parsed:
    us: int              # epoch microseconds: UTC when zoned, else the clock time as if it were UTC
    zoned: bool          # the text carried Z, UTC, or an offset


@functools.lru_cache(maxsize=1 << 16)   # logs write many records a second, so the same text comes again and again
def parse_time(text: str, fmt: str) -> Parsed | None:
    """Read one time value in the given format; None when it doesn't fit."""
    text = (text or "").strip()
    if not text:
        return None
    if fmt == "epoch":
        m = EPOCH_NUMBER.match(text)
        if not m:
            return None
        whole, frac = m.group(1), m.group(2) or ""
        if len(whole) <= 11:     # seconds
            us = int(whole) * 1_000_000 + int(frac[:6].ljust(6, "0"))
        elif len(whole) <= 14:   # milliseconds
            us = int(whole) * 1_000 + int(frac[:3].ljust(3, "0"))
        elif len(whole) <= 17:   # microseconds
            us = int(whole)
        else:                    # nanoseconds, as FortiOS writes eventtime
            us = int(whole) // 1_000
        return Parsed(us, True)
    if fmt in ("ymd", "mdy", "dmy"):
        m = DATE_TIME.match(text)
        if not m:
            return None
        a, b, c, hh, mi, ss, frac, ampm, zone = m.groups()
        if fmt == "ymd":
            if len(a) != 4:
                return None
            y, mo, d = int(a), int(b), int(c)
        else:
            if len(a) > 2 or len(c) not in (2, 4):
                return None
            (mo, d), y = ((int(a), int(b)) if fmt == "mdy" else (int(b), int(a))), int(c)
        if y < 100:
            y += 2000
        hour = int(hh or 0)
        if ampm:
            if not 1 <= hour <= 12:
                return None
            hour = hour % 12 + (12 if ampm[0] in "Pp" else 0)
        try:
            dt = datetime(y, mo, d, hour, int(mi or 0), int(ss or 0), int((frac or "").ljust(6, "0")[:6]), tzinfo=UTC)
        except ValueError:
            return None
        us = (dt - EPOCH) // ONE_US
        if not zone:
            return Parsed(us, False)
        return Parsed(us - offset_minutes(zone) * 60_000_000, True)
    try:
        dt = datetime.strptime(text, fmt)
    except ValueError:
        return None
    if dt.tzinfo is None:
        return Parsed((dt.replace(tzinfo=UTC) - EPOCH) // ONE_US, False)
    return Parsed((dt - EPOCH) // ONE_US, True)


def offset_minutes(zone: str) -> int:
    """A UTC offset written as Z, UTC, GMT, or such as +02:00, -0800, or UTC+2, in minutes east of UTC."""
    if zone.upper() in ("Z", "UTC", "GMT"):
        return 0
    m = OFFSET.match(zone)
    if not m:
        raise ZoneError(f"Not an offset: {zone}")
    minutes = int(m.group(2)) * 60 + int(m.group(3) or 0)
    return -minutes if m.group(1) == "-" else minutes


def fmt_offset(minutes: int) -> str:
    """An offset in minutes east of UTC as it's shown after UTC, such as +05:30 or -08:00."""
    sign = "-" if minutes < 0 else "+"
    return f"{sign}{abs(minutes) // 60:02d}:{abs(minutes) % 60:02d}"


# ---------- zones a time is read in ----------

class ZoneClock:
    """Turns clock times written without a zone into UTC, by a resolved zone (see resolve_zone).

    IANA zones are converted by DuckDB's built-in ICU, which needs no download and no tzdata package. The offset is
    looked up once per local quarter hour. A time in the hour skipped when clocks go forward, or repeated when they
    go back, is read as ICU reads it: the repeated hour as standard time.
    """

    def __init__(self, resolved: dict | None):
        self.resolved = resolved or {}
        self.kind = self.resolved.get("kind", "")
        self.cache: dict[int, int] = {}
        self.con = None

    def to_utc(self, local_us: int) -> int | None:
        if self.kind == "utc":
            return local_us
        if self.kind == "offset":
            return local_us - self.resolved["minutes"] * 60_000_000
        if self.kind != "iana":
            return None
        bucket = local_us // QUARTER_US
        offset = self.cache.get(bucket)
        if offset is None:
            self._fill(bucket)
            offset = self.cache[bucket]
        return local_us - offset

    def _fill(self, bucket: int) -> None:
        """Offsets for the 4 days from this quarter hour, in one query: a query costs milliseconds."""
        if self.con is None:
            self.con = _icu()
        rows = self.con.execute(
            "SELECT b, b * ? - epoch_us(timezone(?, make_timestamp((b * ?)::BIGINT))) FROM range(?, ?) t(b)",
            [QUARTER_US, self.resolved["name"], QUARTER_US, bucket, bucket + 4 * 96]).fetchall()
        self.cache.update(rows)

    def close(self) -> None:
        if self.con is not None:
            self.con.close()


def _icu() -> duckdb.DuckDBPyConnection:
    return duckdb.connect(":memory:", config=dict(NO_EXTENSION_FETCH))   # ICU is built into DuckDB's Python package


@functools.lru_cache(maxsize=1)
def zone_names() -> tuple[str, ...]:
    con = _icu()
    try:
        return tuple(sorted(r[0] for r in con.execute("SELECT name FROM pg_timezone_names()").fetchall()))
    finally:
        con.close()


def resolve_zone(zone: str, host_zones: dict[str, dict]) -> dict | None:
    """A zone choice as the import uses it: {"kind": "utc" | "offset" | "iana", ..., "label": how it reads}.
    host_zones is each host's zone from its SYSTEM hive (host_timezones). None for no choice yet."""
    zone = (zone or "").strip()
    if not zone:
        return None
    if zone.upper() in ("UTC", "Z", "GMT", "ETC/UTC"):
        return {"kind": "utc", "label": "UTC"}
    if OFFSET.match(zone):
        minutes = offset_minutes(zone)
        return {"kind": "offset", "minutes": minutes, "label": f"UTC{fmt_offset(minutes)}"}
    if zone.startswith("host:"):
        host = zone[5:]
        info = host_zones.get(host)
        if not info:
            raise ZoneError(f"{host} has no zone from its SYSTEM hive; choose UTC, an offset, or a named zone.")
        if info.get("iana"):
            return {"kind": "iana", "name": info["iana"], "host": host,
                    "label": f"{host}'s zone, {info.get('windows') or info['iana']} ({info['iana']})"}
        if info.get("bias_minutes") is None:
            raise ZoneError(f"{host}'s zone {info.get('windows')} has no IANA match or offset; choose a zone.")
        minutes = -int(info["bias_minutes"])   # Windows: UTC = local time + bias
        return {"kind": "offset", "minutes": minutes, "host": host,
                "label": f"{host}'s fixed offset UTC{fmt_offset(minutes)}, without daylight saving"}
    if zone in zone_names():
        return {"kind": "iana", "name": zone, "label": zone}
    raise ZoneError(f"Unknown zone {zone!r}: give UTC, an offset such as -08:00, a zone such as Europe/London, "
                    "or a host's zone.")
