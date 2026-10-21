"""Parses SBECmd ShellBags CSV output.

ShellBags record the folders a user browsed in Explorer, including drives and network shares, in the user's
UsrClass.dat, and in NTUSER.DAT on older Windows. SBECmd writes one CSV per hive, named for the profile folder and the
hive type, such as Administrator_UsrClass.csv. The CSV doesn't name the hive, so the parser reads the pairs of
"Finished processing <hive>" and "Exported to: <csv>" lines in SBECmd's messages file.

Times on the timeline: FirstInteracted and LastInteracted, when Windows recorded the user opening the folder, and the
bag key's LastWriteTime where it differs from both. CreatedOn, ModifiedOn, and AccessedOn are the folder's own times as
the shell item recorded them; they stay in the event details. All of SBECmd's times are UTC.

The account is the profile the hive belongs to, taken from the hive's path under Users; SBECmd doesn't record it.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path, PureWindowsPath

from ..events import Event, to_us
from .common import ParseContext, evidence_relative, file_key, output_paths, read_csv_rows

MESSAGES = "!SBECmd_Messages.txt"
TIMES = (("FirstInteracted", "ShellBag first interacted"), ("LastInteracted", "ShellBag last interacted"))
KEY_WRITE = "ShellBag key last write"
FINISHED = re.compile(r"Finished processing (.+?)\s*$")
EXPORTED = re.compile(r"Exported to: (.+?)\s*$")
FOLDER = re.compile(r"([A-Za-z]:(?:\\.*)?|\\\\.+)$")   # the drive or UNC part of a shell path


def parse_sbecmd(ctx: ParseContext) -> Iterator[Event]:
    if ctx.files:   # output found in the evidence
        yield from _from_evidence(ctx)
        return
    for csv_path, hive in sorted(_hives(ctx.output_dir).items()):
        source = evidence_relative(hive, ctx.evidence_root)
        profile, hive_type = _profile(hive), PureWindowsPath(hive).name
        for row in read_csv_rows(ctx.output_dir / csv_path):
            yield from _events(row, source, profile, hive_type)


def _from_evidence(ctx: ParseContext) -> Iterator[Event]:
    """SBECmd's CSVs found in the evidence, such as KAPE's module output. The messages file beside them names each
    CSV's hive when it's there; otherwise the CSV's own name does, as SBECmd writes it: Administrator_UsrClass.csv."""
    hives: dict[Path, dict[str, str]] = {}
    for path in output_paths(ctx, "sbecmd", "*.csv"):
        named = hives.setdefault(path.parent, _hives(path.parent)).get(path.name)
        if named:
            source, profile, hive_type = evidence_relative(named, ctx.evidence_root), _profile(named), PureWindowsPath(named).name
        else:
            profile, _, kind = path.stem.rpartition("_")
            source = evidence_relative(str(path), ctx.evidence_root)
            hive_type = {"ntuser": "NTUSER.DAT", "usrclass": "UsrClass.dat"}.get(kind.lower(), kind)
        for row in read_csv_rows(path):
            yield from _events(row, source, profile, hive_type)


def _events(row: dict[str, str], source: str, profile: str, hive_type: str) -> Iterator[Event]:
    shell_path = row.get("AbsolutePath", "")
    match = FOLDER.search(shell_path)   # Desktop\This PC\C:\Users gives C:\Users; Desktop\This PC\Documents, nothing
    folder = match.group(1) if match else ""
    common = dict(artifact="shellbags", source_file=source, source_record=f"{row.get('BagPath', '')}|{row.get('Slot', '')}",
                  user_name=profile, file_path=folder, file_key=file_key(folder),
                  extra={**{k: v for k, v in row.items() if v}, "Profile": profile, "Hive": hive_type})
    kind = f" ({row['ShellType']})" if row.get("ShellType") else ""
    seen = set()
    for column, label in TIMES:
        ts = to_us(row.get(column))
        if ts is not None:
            seen.add(ts)
            yield Event(ts_us=ts, ts_desc=label, message=f"{label}: {shell_path}{kind}", **common)
    written = to_us(row.get("LastWriteTime"))
    if written is not None and written not in seen:
        yield Event(ts_us=written, ts_desc=KEY_WRITE, message=f"{KEY_WRITE}: {shell_path}{kind}", **common)
    elif not seen and written is None:   # keep the bag on record even without a time
        yield Event(ts_us=None, ts_desc="ShellBag without times", message=f"ShellBag: {shell_path}{kind}", **common)


def _hives(output_dir: Path) -> dict[str, str]:
    """CSV file name to the hive it came from, from the messages file."""
    out, hive = {}, ""
    messages = output_dir / MESSAGES
    if not messages.exists():
        return out
    for line in messages.read_text(encoding="utf-8-sig", errors="replace").splitlines():
        if m := FINISHED.search(line):
            hive = m.group(1)
        elif (m := EXPORTED.search(line)) and hive:
            out[PureWindowsPath(m.group(1)).name] = hive
    return out


def _profile(hive: str) -> str:
    parts = PureWindowsPath(hive).parts
    lower = [p.lower() for p in parts]
    for marker in ("users", "documents and settings"):
        if marker in lower and lower.index(marker) + 1 < len(parts) - 1:
            return parts[lower.index(marker) + 1]
    return ""
