"""Parses MFTECmd $MFT CSV output into one event per distinct timestamp per attribute.

Each MFT record carries four $STANDARD_INFORMATION (0x10) and four $FILE_NAME (0x30) times. Times
that share a value become one event labeled with MACB letters (Modified, Accessed, Changed, Born),
as a supertimeline does. Deleted records are kept. The message flags a deleted record, MFTECmd's SI<FN and copied
marks, and $SI times with zero microseconds. MFTECmd sets SI<FN on most records of an ordinary volume, so the flag
names the mark and nothing more. A row with no readable time makes no event, and the run's notes count such rows.

MFTECmd leaves a $FN cell blank where that time equals the $SI time, so such a time makes no $FN event. The record's
FnEqualsSi field names those letters, such as "MACB" or "B", so each $FN time can be read from the $SI events. An
alternate data stream's row gets no such field: the stream has no $FILE_NAME attribute of its own, and MFTECmd repeats
its file's times on it, so the file's own row carries the field.
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
    for path in output_paths(ctx, "mftecmd", OUTPUT_FILE):
        in_file = 0
        for row in read_csv_rows(path):
            events = list(events_from_row(row, ctx))   # a row has at most eight
            if not events:
                in_file += 1
            yield from events
        ctx.skipped.append(in_file)
        dropped += in_file
    if dropped:
        one = dropped == 1
        ctx.notes.append(f"{SKIPPED_NOTE}{dropped:,} {'row' if one else 'rows'} of MFTECmd's CSV: none of "
                         f"{'its' if one else 'their'} times could be read.")


def fn_equals_si(row: dict[str, str]) -> str:
    """The MACB letters whose $FN time equals the $SI time, or "" for none. A letter counts where its $SI cell holds a
    time the parser loads and its $FN cell is blank, which is how MFTECmd writes an equal time, or holds the same text,
    as MFTECmd's `--at` writes every $FN time."""
    letters = []
    for letter, column in TIME_COLUMNS:
        si, fn = row.get(column + "0x10"), row.get(column + "0x30")
        if to_us(si) is not None and (not fn or fn == si):
            letters.append(letter)
    return "".join(letters)


def events_from_row(row: dict[str, str], ctx: ParseContext) -> Iterator[Event]:
    parent, name = row.get("ParentPath", ""), row.get("FileName", "")
    display = ("\\" + name) if parent in (".", "") else parent.removeprefix(".") + "\\" + name
    flags = []
    if row.get("InUse") == "False":
        flags.append("deleted")
    if row.get("SI<FN") == "True":
        flags.append("SI<FN")
    if row.get("uSecZeros") == "True":
        flags.append("SI times have zero microseconds")
    if row.get("Copied") == "True":
        flags.append("copied")
    suffix = f" [{'; '.join(flags)}]" if flags else ""
    record = f"{row.get('EntryNumber', '')}-{row.get('SequenceNumber', '')}:{name}"
    extra_fields = {k: row[k] for k in EXTRA_COLUMNS if row.get(k)}
    if row.get("IsAds") != "True" and (equal_letters := fn_equals_si(row)):
        extra_fields["FnEqualsSi"] = equal_letters
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
