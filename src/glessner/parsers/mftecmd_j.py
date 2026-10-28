"""Parses MFTECmd's USN journal ($J) CSV output.

The journal records changes to files and folders: creation, renames, writes, attribute and security changes, and
deletion, each record with the reasons that applied, joined with "|", such as FileCreate|DataExtend|Close. One event
per record, at its UpdateTimestamp (UTC). The event code is the record's most telling reason: FileDelete, FileCreate,
RenameNewName, RenameOldName, a data change, BasicInfoChange (attributes or times, so timestomping), SecurityChange, or
a stream change, such as a Zone.Identifier written on download; else the first reason given. A Close record repeats
the reasons gathered since the file was opened.

The folder comes from the $MFT given with -m, as MFTECmd resolves it, written like the $MFT parser's paths, such as
\\Windows\\Prefetch\\X.pf. Without -m it's empty. A folder gone from the $MFT read .\\PathUnknown\\Directory with ID ...
before 2026.10; from 2026.10, MFTECmd can resolve such a folder from the journal's own records. The record's update
sequence number identifies it within the journal.
"""

from __future__ import annotations

import json
from collections.abc import Iterator

from ..events import Event, to_us
from .common import ParseContext, evidence_relative, file_key, output_paths, read_csv_rows

OUTPUT_FILE = "mftecmd_j.csv"
PRIORITY = ("FileDelete", "FileCreate", "RenameNewName", "RenameOldName", "DataOverwrite", "DataExtend",
            "DataTruncation", "BasicInfoChange", "SecurityChange", "NamedDataExtend", "NamedDataOverwrite",
            "NamedDataTruncation", "StreamChange", "HardLinkChange", "ReparsePointChange", "ObjectIdChange", "EaChange")
EXTRA_COLUMNS = ("EntryNumber", "SequenceNumber", "ParentEntryNumber", "ParentSequenceNumber", "UpdateReasons",
                 "FileAttributes", "UpdateSequenceNumber", "OffsetToData")


def parse_mftecmd_j(ctx: ParseContext) -> Iterator[Event]:
    for path in output_paths(ctx, "mftecmd_j", OUTPUT_FILE):
        for row in read_csv_rows(path):
            yield _event(row, ctx)


def _event(row: dict[str, str], ctx: ParseContext) -> Event:
    parent, name = row.get("ParentPath", ""), row.get("Name", "")
    full = ("\\" + name) if parent in (".", "") else parent.removeprefix(".") + "\\" + name
    reasons = [r for r in row.get("UpdateReasons", "").split("|") if r]
    code = next((r for r in PRIORITY if r in reasons), reasons[0] if reasons else "")
    folder = " (folder)" if "Directory" in row.get("FileAttributes", "") else ""
    extra = {k: row[k] for k in EXTRA_COLUMNS if row.get(k)}
    return Event(
        ts_us=to_us(row.get("UpdateTimestamp")), ts_desc="USN journal change", artifact="usnjrnl",
        source_file=evidence_relative(row.get("SourceFile", ""), ctx.evidence_root),
        source_record=row.get("UpdateSequenceNumber", ""), event_code=code,
        message=f"{row.get('UpdateReasons', '')}: {full}{folder}", file_path=full, file_key=file_key(full),
        extra=json.dumps(extra, ensure_ascii=False) if extra else None)
