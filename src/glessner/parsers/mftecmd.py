"""Parses MFTECmd $MFT CSV output into one event per distinct timestamp per attribute.

Each MFT record carries four $STANDARD_INFORMATION (0x10) and four $FILE_NAME (0x30) times. Times
that share a value become one event labeled with MACB letters (Modified, Accessed, Changed, Born),
as a supertimeline does. Deleted records and timestomping indicators are kept and flagged. A row with no readable time
makes no event, and the run's notes count such rows.
"""

from __future__ import annotations

import json
from collections.abc import Iterator

from ..events import Event, to_us
from .common import SKIPPED_NOTE, ParseContext, evidence_relative, file_key, output_paths, read_csv_rows

OUTPUT_FILE = "mftecmd.csv"
TIME_COLUMNS = (("M", "LastModified"), ("A", "LastAccess"), ("C", "LastRecordChange"), ("B", "Created"))
ATTRIBUTES = (("0x10", "$SI"), ("0x30", "$FN"))
EXTRA_COLUMNS = ("EntryNumber", "SequenceNumber", "ParentEntryNumber", "ParentSequenceNumber", "InUse", "FileSize",
                 "IsDirectory", "HasAds", "IsAds", "SI<FN", "uSecZeros", "Copied", "SiFlags", "ReparseTarget",
                 "ZoneIdContents")


def parse_mftecmd(ctx: ParseContext) -> Iterator[Event]:
    dropped = 0
    for row in (row for path in output_paths(ctx, "mftecmd", OUTPUT_FILE) for row in read_csv_rows(path)):
        events = list(events_from_row(row, ctx))   # a row has at most eight
        if not events:
            dropped += 1
        yield from events
    if dropped:
        one = dropped == 1
        ctx.notes.append(f"{SKIPPED_NOTE}{dropped:,} {'row' if one else 'rows'} of MFTECmd's CSV: none of "
                         f"{'its' if one else 'their'} times could be read.")


def events_from_row(row: dict[str, str], ctx: ParseContext) -> Iterator[Event]:
    parent, name = row.get("ParentPath", ""), row.get("FileName", "")
    display = ("\\" + name) if parent in (".", "") else parent.removeprefix(".") + "\\" + name
    flags = []
    if row.get("InUse") == "False":
        flags.append("deleted")
    if row.get("SI<FN") == "True":
        flags.append("SI<FN, possible timestomping")
    if row.get("uSecZeros") == "True":
        flags.append("SI times have zero microseconds")
    if row.get("Copied") == "True":
        flags.append("copied")
    suffix = f" [{'; '.join(flags)}]" if flags else ""
    record = f"{row.get('EntryNumber', '')}-{row.get('SequenceNumber', '')}:{name}"
    extra_fields = {k: row[k] for k in EXTRA_COLUMNS if row.get(k)}
    extra = json.dumps(extra_fields, ensure_ascii=False) if extra_fields else None   # once per record, not per event
    key = file_key(display)
    source = evidence_relative(row.get("SourceFile", ""), ctx.evidence_root)
    for column_suffix, label in ATTRIBUTES:
        stamps: dict[int, list[str]] = {}
        for letter, column in TIME_COLUMNS:
            ts = to_us(row.get(column + column_suffix))
            if ts is not None:
                stamps.setdefault(ts, []).append(letter)
        for ts, letters in stamps.items():
            macb = "".join(c if c in letters else "." for c in "MACB")
            yield Event(
                ts_us=ts,
                ts_desc=f"{label} {macb}",
                artifact="mft",
                source_file=source,
                source_record=record,
                message=f"{label} {macb} {display}{suffix}",
                file_path=display,
                extra=extra,
                file_key=key,
            )
