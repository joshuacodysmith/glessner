"""Parses PECmd prefetch CSV output into one execution event per recorded run time.

A prefetch file records up to eight run times: LastRun and PreviousRun0 to PreviousRun6. The
executable's full path comes from the FilesLoaded entry that ends with the executable's name. Prefetch keeps only 29
characters of a name, so a name that long is matched by prefix instead, to the one entry that starts with it; with no entry or
more than one, the program has no path and no key.
The prefetch file's own Source* times describe the collected copy and are not used.
"""

from __future__ import annotations

from collections.abc import Iterator

from ..events import Event, to_us
from .common import EXECUTABLE_END, ParseContext, evidence_relative, file_key, output_paths, read_csv_rows

OUTPUT_FILE = "pecmd.csv"
RUN_COLUMNS = ("LastRun", *(f"PreviousRun{i}" for i in range(7)))
NAME_LIMIT = 29   # characters of a program's name that a prefetch file keeps (libscca)
EXTRA_COLUMNS = ("RunCount", "Hash", "Size", "Version", "Volume0Name", "Volume0Serial", "Volume0Created",
                 "Volume1Name", "Volume1Serial", "ParsingError", "Note")


def _by_prefix(exe: str, loaded: list[str]) -> str:
    """The one loaded file whose name starts with a program's cut name, else the name alone. A name that isn't cut, or whose
    prefix fits no entry or several, keeps its bare name. A name that ends in an extension is whole, not cut, and its own
    entry was looked for first: a prefix match would take a sidecar such as NAME.EXE.CONFIG."""
    if len(exe) != NAME_LIMIT or EXECUTABLE_END.search(exe):
        return exe
    starts = {f.upper(): f for f in loaded if f.rsplit("\\", 1)[-1].upper().startswith(exe.upper())}
    return next(iter(starts.values())) if len(starts) == 1 else exe


def parse_pecmd(ctx: ParseContext) -> Iterator[Event]:
    for row in (row for path in output_paths(ctx, "pecmd", OUTPUT_FILE) for row in read_csv_rows(path)):
        exe = row.get("ExecutableName", "")
        loaded = [f for f in row.get("FilesLoaded", "").split(", ") if f]
        full = next((f for f in loaded if f.upper().endswith("\\" + exe.upper())), None) or _by_prefix(exe, loaded)
        extra = {k: row[k] for k in EXTRA_COLUMNS if row.get(k)}
        extra["FilesLoadedCount"] = len(loaded)
        extra["FilesLoaded"] = loaded
        source = evidence_relative(row.get("SourceFilename", ""), ctx.evidence_root)
        runs = row.get("RunCount", "")
        for column in RUN_COLUMNS:
            ts = to_us(row.get(column))
            if ts is None:
                continue
            yield Event(
                ts_us=ts,
                ts_desc="Prefetch Run Time",
                artifact="prefetch",
                source_file=source,
                source_record=column,
                message=f"Executed {exe} ({full}), run count {runs}",
                file_path=full,
                extra=extra,
                file_key=file_key(full),
            )
