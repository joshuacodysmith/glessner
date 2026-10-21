"""Paths in Windows' extended-length form, which reach a file by the names it has.

A plain Win32 path fails past 260 characters unless the system enables long paths, drops a trailing dot or space from
each name, so note.txt. opens note.txt, and opens a device for a name such as NUL. The extended-length form, \\\\?\\
(\\\\?\\UNC\\ for a share), passes each name to the file system as it is. Elsewhere than Windows a path is used as given.
"""

from __future__ import annotations

import os
from pathlib import Path

PREFIX = "\\\\?\\"
DEVICE = "\\\\.\\"   # the device form, such as \\.\Volume{GUID}\ for a volume with no drive letter


def long_path(root: Path, rel: str = "") -> Path:
    """`root`, resolved, in extended-length form, with `rel` joined on and its names kept as they are. `rel` is a path
    relative to root with forward slashes, such as a manifest entry's, or one built from the names scandir gave. Only
    the root is resolved, since resolve() drops a trailing dot from a name. A root already in this form is taken as it
    is, so a loop passes the root a first call returned and resolves it once. A root in the device form, \\\\.\\, which
    resolve() keeps for a volume with no drive letter, takes the extended-length prefix in place of its own.

    On Windows the result stays under root: `rel` is joined on as text, so one that pathlib would read as absolute,
    such as C:/x or /x, names a path under root, and a ".." opens nothing, since this form passes it to the file system
    as a name, which it refuses."""
    if os.name != "nt":
        return Path(root, *rel.split("/"))
    text = str(root)
    if not text.startswith(PREFIX):
        text = str(root.resolve())
        if text.startswith(DEVICE):
            text = PREFIX + text.removeprefix(DEVICE)
        elif not text.startswith(PREFIX):
            text = PREFIX + ("UNC\\" + text[2:] if text.startswith("\\\\") else text)
    return Path(text + "\\" + rel.replace("/", "\\")) if rel else Path(text)
