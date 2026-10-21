"""Parses AmcacheParser CSV output.

Amcache.hve records programs and the executable files Windows saw, with each file's SHA-1, even on servers, where
prefetch is off by default. AmcacheParser writes one CSV per table, each name starting with a timestamp. The parser
reads the file entries (with and without a program), the program entries, and the shortcuts. The device and driver
tables are mostly the operating system's own inventory, so they stay out of the timeline.

Times on the timeline are the keys' last write times, plus a program's install date where Amcache records one. A file
entry's key is written when Windows records the file, which is evidence of its presence and often of its execution;
it isn't the execution time itself. LinkDate, the compile time in the PE header, stays in the details.

The CSVs don't name the hive, so an event's source file is the run's input, the hive, for AmcacheParser's own run, and
the CSV it was read from for output found in the evidence. Each row cites its own CSV, so a CSV added later never changes
the IDs of events it doesn't hold. ParseContext.former gives the format 1 rule, which cited the group's first CSV for
every row, in Event.former, for the case format upgrade. A file's SHA-1 is in the event data, so data.SHA1 works in
search and the View filter.

AmcacheParser writes two layouts. Windows 10 and later give FileKeyLastWriteTimestamp, Name, Version, and Publisher;
Windows 8 and Server 2012 R2 give FileIDLastWriteTimestamp, ProgramName_0, ProgramVersion_1, VendorName_2, and file
Created and LastModified times, which stay in the details. Szechuan's DC01 has the older layout. The parser reads both.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator
from pathlib import Path

from ..events import Event, to_us
from .common import ParseContext, evidence_relative, file_key, output_paths, read_csv_rows

FILE_TABLES = (("AssociatedFileEntries", "associated"), ("UnassociatedFileEntries", "unassociated"))


def parse_amcache(ctx: ParseContext) -> Iterator[Event]:
    for table, kind in FILE_TABLES:
        for path in output_paths(ctx, "amcache", f"*_Amcache_{table}.csv"):
            yield from _read(ctx, path, lambda row, source, kind=kind: _file_entry(row, source, kind))
    for path in output_paths(ctx, "amcache", "*_Amcache_ProgramEntries.csv"):
        yield from _read(ctx, path, _program)
    for path in output_paths(ctx, "amcache", "*_Amcache_ShortCuts.csv"):
        yield from _read(ctx, path, lambda row, source: [_shortcut(row, source)])


def _read(ctx: ParseContext, path: Path, events: Callable[[dict[str, str], str], Iterable[Event]]) -> Iterator[Event]:
    """One CSV's events, each citing the CSV for found output and the hive for a run, with format 1's source, the run's
    first input, in Event.former when ParseContext.former asks and it differs."""
    hive = ctx.inputs[0] if ctx.inputs else ""
    source = evidence_relative(str(path), ctx.evidence_root) if ctx.files else hive
    former = ctx.former == 1 and source != hive
    for row in read_csv_rows(path):
        for ev in events(row, source):
            if former:
                ev.former = (hive, ev.source_record)
            yield ev


def _extra(row: dict[str, str]) -> dict[str, str] | None:
    return {k: v for k, v in row.items() if v} or None


def _first(row: dict[str, str], *names: str) -> str:
    """The first of the names the row has a value for: the two layouts name the same field differently."""
    return next((row[n] for n in names if row.get(n)), "")


def _file_entry(row: dict[str, str], source: str, kind: str) -> Iterator[Event]:
    path = row.get("FullPath", "")
    sha1 = row.get("SHA1", "")
    yield Event(ts_us=to_us(_first(row, "FileKeyLastWriteTimestamp", "FileIDLastWriteTimestamp")),
                ts_desc="Amcache file entry written", artifact="amcache", source_file=source,
                source_record=f"file|{kind}|{_first(row, 'ProgramId', 'ProgramID')}|{path}",
                message=f"Amcache file: {path}" + (f" (SHA-1 {sha1})" if sha1 else ""),
                file_path=path, file_key=file_key(path), extra={**(_extra(row) or {}), "Table": f"{kind} file entries"})


def _program(row: dict[str, str], source: str) -> Iterator[Event]:
    name = " ".join(x for x in (_first(row, "Name", "ProgramName_0"), _first(row, "Version", "ProgramVersion_1")) if x)
    publisher = _first(row, "Publisher", "VendorName_2")
    message = f"Amcache program: {name}" + (f", {publisher}" if publisher else "")
    root = _first(row, "RootDirPath", "PathsList_d")
    common = dict(artifact="amcache", source_file=source, source_record=f"program|{_first(row, 'ProgramId', 'ProgramID')}",
                  file_path=root, file_key=file_key(root), extra={**(_extra(row) or {}), "Table": "program entries"})
    yield Event(ts_us=to_us(_first(row, "KeyLastWriteTimestamp", "LastWriteTimestamp")),
                ts_desc="Amcache program entry written", message=message, **common)
    installed = to_us(_first(row, "InstallDate", "InstallDateEpoch_a"))
    if installed is not None:
        yield Event(ts_us=installed, ts_desc="Program installed", message=f"Installed: {name}", **common)


def _shortcut(row: dict[str, str], source: str) -> Event:
    lnk = row.get("LnkName", "")
    return Event(ts_us=to_us(row.get("KeyLastWriteTimestamp")), ts_desc="Amcache shortcut entry written",
                 artifact="amcache", source_file=source, source_record=f"shortcut|{row.get('KeyName', '')}",
                 message=f"Amcache shortcut: {lnk}", file_path=lnk, file_key=file_key(lnk),
                 extra={**(_extra(row) or {}), "Table": "shortcuts"})
