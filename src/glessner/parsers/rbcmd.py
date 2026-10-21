"""Parses RBCmd Recycle Bin CSV output.

Each $I file in $Recycle.Bin records a deleted file's original path, size, and deletion time. One event per record,
at the deletion time. Deletion bears on anti-forensics. Intake identifies only $I files, so a host
that has only an INFO2 file (older Windows) gets no RBCmd run. The numbering below still handles a source with many records.

The Recycle Bin folder is named for the user's SID, which goes in the details; the profile name isn't in the record.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import PureWindowsPath

from ..events import Event, to_us
from .common import ParseContext, evidence_relative, file_key, output_paths, read_csv_rows

OUTPUT_FILE = "rbcmd.csv"


def parse_rbcmd(ctx: ParseContext) -> Iterator[Event]:
    seen: dict[str, int] = {}   # records per source file: one per $I file, several in an INFO2 file
    for row in (row for path in output_paths(ctx, "rbcmd", OUTPUT_FILE) for row in read_csv_rows(path)):
        source = evidence_relative(row.get("SourceName", ""), ctx.evidence_root)
        i = seen[source] = seen.get(source, 0) + 1
        name = row.get("FileName", "")
        sid = next((p for p in PureWindowsPath(source).parts if p.upper().startswith("S-1-")), "")
        extra = {k: v for k, v in row.items() if v and k != "SourceName"}
        if sid:
            extra["SID"] = sid
        yield Event(ts_us=to_us(row.get("DeletedOn")), ts_desc="File deleted to the Recycle Bin", artifact="recycle_bin",
                    source_file=source, source_record=f"{row.get('FileType', '')}|{i}",
                    message=f"Deleted to the Recycle Bin: {name} ({row.get('FileSize', '?')} bytes)",
                    file_path=name, file_key=file_key(name), extra=extra or None)
