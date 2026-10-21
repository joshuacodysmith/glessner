"""Parses LECmd LNK CSV output.

The times used are the ones embedded in the LNK: the target's created, modified, and accessed
times when the link was made, and the tracker's creation time. The LNK file's own Source* times
describe the collected copy, which may carry the export time, so they are not placed on the timeline.
The original LNK file times are in the $MFT, which the same-file pivot reaches.

LECmd reads the tracker's creation time out of the tracker's ID, which holds a time only when the ID
is time-based (version 1). Other IDs give noise, such as the year 3850. A real tracker time can't be
later than the LNK file's own times, so a later one stays in the event details, marked, instead of
on the timeline. The Source* times serve only as that upper bound.
"""

from __future__ import annotations

from collections.abc import Iterator

from ..events import Event, to_us
from .common import ParseContext, evidence_relative, file_key, output_paths, read_csv_rows

OUTPUT_FILE = "lecmd.csv"
TIME_COLUMNS = (("TargetCreated", "LNK target created"), ("TargetModified", "LNK target modified"),
                ("TargetAccessed", "LNK target accessed"), ("TrackerCreatedOn", "LNK tracker created"))
EXTRA_COLUMNS = ("LocalPath", "NetworkPath", "CommonPath", "TargetIDAbsolutePath", "RelativePath", "WorkingDirectory",
                 "Arguments", "FileSize", "FileAttributes", "DriveType", "VolumeSerialNumber", "VolumeLabel",
                 "TargetMFTEntryNumber", "TargetMFTSequenceNumber", "MachineID", "MachineMACAddress", "MACVendor")
SOURCE_TIMES = ("SourceCreated", "SourceModified", "SourceAccessed")
TRACKER_NOTE = ("Later than the LNK file's own times, so not placed on the timeline. LECmd derives this time from "
                "the tracker's ID, which holds a time only when the ID is time-based.")


def parse_lecmd(ctx: ParseContext) -> Iterator[Event]:
    for row in (row for path in output_paths(ctx, "lecmd", OUTPUT_FILE) for row in read_csv_rows(path)):
        # LinkInfo splits the target: LocalPath (or NetworkPath) is a base, CommonPath the rest,
        # for example C:\FileShare\ + Secret\Beth_Secret.txt.
        common = row.get("CommonPath", "")
        local = _join(row.get("LocalPath", ""), common)
        network = _join(row.get("NetworkPath", ""), common)
        target = local or network or row.get("TargetIDAbsolutePath", "")
        source = evidence_relative(row.get("SourceFile", ""), ctx.evidence_root)
        extra = {k: row[k] for k in EXTRA_COLUMNS if row.get(k)}
        tracker = to_us(row.get("TrackerCreatedOn"))
        bound = max((t for t in (to_us(row.get(c)) for c in SOURCE_TIMES) if t is not None), default=None)
        not_a_time = tracker is not None and bound is not None and tracker > bound
        if not_a_time:
            extra["TrackerCreatedOn"] = row["TrackerCreatedOn"]
            extra["TrackerCreatedOnNote"] = TRACKER_NOTE
        key = file_key(local) or file_key(row.get("TargetIDAbsolutePath", ""))
        emitted = False
        for column, label in TIME_COLUMNS:
            ts = to_us(row.get(column))
            if ts is None or (column == "TrackerCreatedOn" and not_a_time):
                continue
            emitted = True
            yield Event(ts_us=ts, ts_desc=label, artifact="lnk", source_file=source, source_record=column,
                        message=f"{label}: {target}", host_name_recorded=row.get("MachineID", ""),
                        file_path=target, extra=extra or None, file_key=key)
        if not emitted:   # keep the LNK on record even when it holds no target times
            yield Event(ts_us=None, ts_desc="LNK without target times", artifact="lnk", source_file=source,
                        source_record="none", message=f"LNK without target times: {target}",
                        host_name_recorded=row.get("MachineID", ""), file_path=target, extra=extra or None,
                        file_key=key)


def _join(base: str, suffix: str) -> str:
    if not base:
        return ""
    if not suffix:
        return base
    return base.rstrip("\\") + "\\" + suffix.lstrip("\\")
