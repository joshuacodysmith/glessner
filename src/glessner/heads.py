"""The head this app last recorded for each case, kept outside the case folder.

One small file per case in the settings folder's heads folder, named by the SHA-256 of the case folder's path, written
by temporary file and replace under the case's journal lock, so by one writer at a time. Each append and each open for
work moves it to the newest line. An open for work compares it with the journal: a recorded head that is no line of the
chain is a break, which shows the newest entries removed or changed, or the journal rewritten, while the app was closed.
It sits on the same computer as the case, so it proves nothing against that computer's user. Another spelling of the
same folder finds no record, which reads as "no head recorded", never as a break.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path

from .case import write_atomically

FOLDER = "heads"


def path_for(folder: Path) -> Path:
    """Where the record of the case in `folder` is kept. start is imported here, since it imports rekey, which imports
    the journal, which imports this module."""
    from .start import config_dir

    key = hashlib.sha256(os.path.normcase(str(folder)).encode("utf-8")).hexdigest()
    return config_dir() / FOLDER / f"{key}.json"


def read(folder: Path) -> dict | None:
    """The record of the case in `folder`: {folder, seq, head, at, build}, or None when there is none, or none that can
    be read, which is treated as no record, never as a break."""
    try:
        data = json.loads(path_for(folder).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not (isinstance(data, dict) and isinstance(data.get("head"), str) and isinstance(data.get("seq"), int)
            and os.path.normcase(str(data.get("folder", ""))) == os.path.normcase(str(folder))):
        return None
    return data


def forget(folder: Path) -> None:
    """Remove the record of the case in `folder`, for a new case made there whose journal has no chain yet: it isn't the
    case the record names."""
    path_for(folder).unlink(missing_ok=True)


def write(folder: Path, seq: int, head: str, build: str) -> None:
    """Record `head`, the SHA-256 of entry `seq`, as the case's newest, with the time and the build that wrote it."""
    path = path_for(folder)
    path.parent.mkdir(parents=True, exist_ok=True)
    record = {"folder": str(folder), "seq": seq, "head": head,
              "at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ"), "build": build}
    write_atomically(path, json.dumps(record, indent=2))
