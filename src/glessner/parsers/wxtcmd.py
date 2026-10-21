"""Parses WxTCmd's Windows Timeline output, <time>_<user>_Activity.csv.

The Timeline database, ActivitiesCache.db, records what a user opened and used on Windows 10: programs, files, and
pages, with when the activity started and, for focus activities, ended. WxTCmd writes its times in UTC. One event at
StartTime and one at EndTime where that's set and differs. The event code is the activity type, such as ExecuteOpen
or InFocus.

The account is the profile folder the database sits in, from the run's input, or for a CSV found in the evidence, the
name WxTCmd gives the file. WxTCmd's package and pending-operation CSVs aren't read: the activities name their program
already.

A program is written as a path (C:\\Windows\\notepad.exe), as a known folder and a name (System\\cmd.exe, or the folder's
GUID in braces), or as an app ID (Microsoft.Windows.Explorer). The first two have a file key, the known folders through
common.known_folder; an app ID has none.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import PureWindowsPath

from ..events import Event, to_us
from .common import ParseContext, evidence_relative, file_key, known_folder, output_paths, profile_name, read_csv_rows


def parse_wxtcmd(ctx: ParseContext) -> Iterator[Event]:
    for path in output_paths(ctx, "wxtcmd", "*_Activity.csv"):
        if ctx.files:   # a CSV found in the evidence: <time>_<user>_Activity.csv
            source = evidence_relative(str(path), ctx.evidence_root)
            parts = path.stem.split("_")
            user = "_".join(parts[1:-1]) if len(parts) > 2 else ""
        else:           # the app's run: the database it read
            source = next((p for p in ctx.inputs if PureWindowsPath(p).name.lower() == "activitiescache.db"), "")
            user = profile_name(source)
        for row in read_csv_rows(path):
            yield from _events(row, source, user)


def _events(row: dict[str, str], source: str, user: str) -> Iterator[Event]:
    kind, exe = row.get("ActivityType", ""), row.get("Executable", "")
    details = " ".join(x for x in (row.get("DisplayText", ""), row.get("ContentInfo", "")) if x)
    message = f"Timeline {kind}: {exe}{' - ' + details if details else ''}"
    extra = {k: v for k, v in row.items() if v and k not in ("Payload", "ClipboardPayload")}
    start, end = to_us(row.get("StartTime")), to_us(row.get("EndTime"))
    common = dict(artifact="timeline", source_file=source, event_code=kind, user_name=user,
                  process_executable=exe, file_key=file_key(known_folder(exe) or exe) if exe else "",
                  extra=extra or None)
    if start is not None:
        yield Event(ts_us=start, ts_desc="Timeline activity started", source_record=f"{row.get('Id', '')}|start",
                    message=message, **common)
    if end is not None and end != start:
        yield Event(ts_us=end, ts_desc="Timeline activity ended", source_record=f"{row.get('Id', '')}|end",
                    message=message, **common)
    if start is None and end is None:
        yield Event(ts_us=to_us(row.get("LastModifiedTime")), ts_desc="Timeline activity last modified",
                    source_record=f"{row.get('Id', '')}|modified", message=message, **common)
