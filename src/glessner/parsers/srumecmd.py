"""Parses SrumECmd CSV output.

SRUM, the System Resource Usage Monitor, records per-application network use and activity in SRUDB.dat. SrumECmd
writes one CSV per table, each name starting with a timestamp. The parser reads four tables: network usage (bytes
sent and received per application, which bears on exfiltration), network connections, application resource use, and
the application timeline. Energy use, push notifications, and the vfuprov table stay out.

Windows writes SRUM records about once an hour, so a record's time is when the interval was saved, not when the
activity happened. The messages say so. The account is the name SrumECmd resolved from the SOFTWARE hive's profile
list; the SID is in the details. The CSVs don't name the database, so an event's source file is the run's input,
SRUDB.dat, for SrumECmd's own run, and the CSV it was read from for output found in the evidence. Found output
cites its CSV, so two collections' records of one table and Id keep separate keys, and a mark can't move from one to
the other. ParseContext.former gives the format 1 rule, which cited no file, in Event.former, for the case format
upgrade.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import PureWindowsPath

from ..events import Event, to_us
from .common import ParseContext, evidence_relative, file_key, is_digits, output_paths, read_csv_rows

TABLES = {
    "NetworkUsages": "SRUM network use",
    "NetworkConnections": "SRUM network connection",
    "AppResourceUseInfo": "SRUM app resource use",
    "AppTimelineProvider": "SRUM app timeline",
}


def parse_srumecmd(ctx: ParseContext) -> Iterator[Event]:
    database = next((p for p in ctx.inputs if PureWindowsPath(p).name.lower() == "srudb.dat"), "")
    for table, label in TABLES.items():
        for path in output_paths(ctx, "srumecmd", f"*_SrumECmd_{table}_Output.csv"):
            source = evidence_relative(str(path), ctx.evidence_root) if ctx.files else database
            former = ctx.former == 1 and source != database   # format 1's source: the database, "" for found output
            for row in read_csv_rows(path):
                ev = _event(row, table, label, source)
                if former:
                    ev.former = (database, ev.source_record)
                yield ev


def _event(row: dict[str, str], table: str, label: str, source: str) -> Event:
    exe = row.get("ExeInfo", "")
    domain, _, name = row.get("UserName", "").rpartition("\\")
    if table == "NetworkUsages":
        detail = f"{exe or 'unknown application'} sent {_n(row.get('BytesSent'))} bytes, received {_n(row.get('BytesReceived'))}"
    elif table == "NetworkConnections":
        detail = (f"{row.get('ProfileName') or row.get('InterfaceType') or 'network'} connected for "
                  f"{_n(row.get('ConnectedTime'))} s from {row.get('ConnectStartTime', '')}")
    elif table == "AppTimelineProvider":
        detail = f"{exe} ran {_n(row.get('DurationMs'))} ms, ending {row.get('EndTime', '')}"
    else:
        written = sum(int(row.get(c) or 0) for c in ("ForegroundBytesWritten", "BackgroundBytesWritten")
                      if is_digits(row.get(c) or ""))
        detail = f"{exe} wrote {written:,} bytes"
    return Event(ts_us=to_us(row.get("Timestamp")), ts_desc=f"{label} recorded", artifact="srum", source_file=source,
                 source_record=f"{table}|{row.get('Id', '')}", message=f"{label} (hour ending): {detail}",
                 user_name=name, user_domain=domain, process_executable=exe, file_key=file_key(exe),
                 extra={**{k: v for k, v in row.items() if v}, "Table": table})


def _n(text: str | None) -> str:
    return f"{int(text):,}" if is_digits(text or "") else (text or "?")
