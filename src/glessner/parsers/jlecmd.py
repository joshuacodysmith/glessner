"""Parses JLECmd jump list CSV output.

A jump list records the files and places one application opened, per user. JLECmd writes AutomaticDestinations and
CustomDestinations CSVs, each name starting with a timestamp.

Automatic jump lists hold a DestList: each entry has a creation time, when the application first opened the target,
and a last-modified time, when it last did, with an interaction count. Both go on the timeline. The target's own
times, from the embedded shell link, stay in the details. Custom jump lists have no DestList, so their target times go
on the timeline, as the LNK parser does. The Source* columns describe the collected copy and are left out, as for LNK.

The account is the profile folder the jump list sits in. Hostname, from the shell link's tracker, names the machine
that held the target, which shows remote files.
"""

from __future__ import annotations

from collections.abc import Iterator

from ..events import Event, to_us
from .common import ParseContext, evidence_relative, file_key, output_paths, profile_name, read_csv_rows

AUTO_TIMES = (("CreationTime", "Jump list entry created"), ("LastModified", "Jump list entry last used"))
CUSTOM_TIMES = (("TargetCreated", "Jump list target created"), ("TargetModified", "Jump list target modified"),
                ("TargetAccessed", "Jump list target accessed"))
SOURCE_TIMES = ("SourceCreated", "SourceModified", "SourceAccessed")


def parse_jlecmd(ctx: ParseContext) -> Iterator[Event]:
    for path in output_paths(ctx, "jlecmd_auto", "*_AutomaticDestinations.csv"):
        for row in read_csv_rows(path):
            yield from _entry(row, ctx, AUTO_TIMES, row.get("EntryNumber", ""))
    for path in output_paths(ctx, "jlecmd_custom", "*_CustomDestinations.csv"):
        seen: dict[str, int] = {}
        for row in read_csv_rows(path):
            n = seen[row.get("SourceFile", "")] = seen.get(row.get("SourceFile", ""), 0) + 1
            yield from _entry(row, ctx, CUSTOM_TIMES, f"custom|{n}")


def _entry(row: dict[str, str], ctx: ParseContext, times, record: str) -> Iterator[Event]:
    source = evidence_relative(row.get("SourceFile", ""), ctx.evidence_root)
    target = (row.get("LocalPath") or row.get("NetworkPath") or row.get("TargetIDAbsolutePath") or row.get("Path")
              or row.get("EntryName") or "")
    app = row.get("AppIdDescription") or row.get("AppId") or "Unknown application"
    extra = {k: v for k, v in row.items() if v and k not in SOURCE_TIMES and k != "SourceFile"}
    common = dict(artifact="jumplist", source_file=source, source_record=record, user_name=profile_name(source),
                  host_name_recorded=row.get("Hostname") or row.get("MachineID") or "", file_path=target,
                  file_key=file_key(row.get("LocalPath") or target), extra=extra or None)
    emitted = False
    for column, label in times:
        ts = to_us(row.get(column))
        if ts is not None:
            emitted = True
            yield Event(ts_us=ts, ts_desc=label, message=f"{label}: {app}: {target}", **common)
    if not emitted:   # keep the entry on record even without times
        yield Event(ts_us=None, ts_desc="Jump list entry without times", message=f"Jump list entry: {app}: {target}",
                    **common)
