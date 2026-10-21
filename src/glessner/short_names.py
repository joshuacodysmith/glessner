"""8.3 short names resolved per host from the MFT.

A path in a 7045, a Run value, or a USN record can hold a short name, such as C:\\Users\\ADMINI~1\\AppData\\Local\\Temp\\1\\
ad_driver.sys, while the same file's MFT, Prefetch, and Autoruns records hold the long path, so Same file found only the
event itself. Windows builds the alias from the long name: upper case, spaces and periods dropped, the characters + , ; = [ ]
written as _, the base cut to six characters and followed by ~ and a number, the extension cut to three (MS-naming;
inference where the page doesn't say). Only the host's own MFT says which long name an alias stands for.

The resolution is the derived table short_paths (event_uid, host, short_key, long_key), built with the others when a case
opens and after every load, split, and import, so it is right whatever the order the tools loaded in and after a rebuild; the
stored file keys never change. For each host's file key that has a short part, left to right from the root, a short part
resolves to the one name directly under the parent so far, among the MFT's records for that host, whose alias would start with
its characters; a name that is a legal 8.3 name already has no alias, so it never counts. Two such names, or none, leave the
key as it is, and so does a name that is already one of the siblings, since
the ~ is then part of a long name. The ~ number isn't used: a file created after another was deleted can hold ~2 alone.

The siblings are distinct names, not MFT rows: MFTECmd gives each entry up to eight rows, and deleted entries and hard links add
more. Left out: after the fourth collision NTFS writes two characters and four hex digits (AD12F3~1),
which no name starts with; a name with characters outside the OEM set; hashed aliases; and the ~ number.
"""

from __future__ import annotations

import re
from collections.abc import Callable

import duckdb

from .events import insert_columns

# A part of a lower-case file key that looks like an alias: one to six characters, ~, a number, and perhaps a short extension
SHORT_PART = re.compile(r"^(?P<base>[^~.\s]{1,6})~\d+(?:\.(?P<ext>[^.]{0,3}))?$")
# The same test as one of SHORT_PART's parts, for a key as a whole, in SQL
SQL_SHORT_PART = r"(^|\\)[^~.\s\\]{1,6}~[0-9]+(\.[^.\\]{0,3})?(\\|$)"
ALIAS_CHARACTERS = str.maketrans(dict.fromkeys("+,;=[]", "_"))


def alias_parts(name: str) -> tuple[str, str]:
    """The base and extension an alias of a long name is built from, in lower case: leading periods dropped, the extension
    taken after the last period, spaces and the other periods dropped from the base, + , ; = [ ] written as _."""
    base, dot, ext = name.lower().lstrip(".").rpartition(".")
    if not dot:
        base, ext = ext, ""
    return base.replace(" ", "").replace(".", "").translate(ALIAS_CHARACTERS), ext.replace(" ", "").translate(ALIAS_CHARACTERS)


def stands_for(short: re.Match, name: str) -> bool:
    """Whether the long `name` (lower case) could have the alias a part of a key shows. Its base starts with the alias's, and its
    extension starts with the alias's, or neither has one. A name that is a legal 8.3 name already (a base of eight characters
    or fewer, an extension of three or fewer, no space, extra period, or character an alias changes) has no alias, so it is
    not one that makes ADMINI~1."""
    base, ext = alias_parts(name)
    wanted_base, wanted_ext = short.group("base"), short.group("ext") or ""
    if not base.startswith(wanted_base) or not (ext.startswith(wanted_ext) if wanted_ext else ext == ""):
        return False
    return len(base) > 8 or len(ext) > 3 or name != (f"{base}.{ext}" if ext else base)


def resolve(key: str, siblings: Callable[[str], set[str]]) -> str | None:
    """The long form of a lower-case file key whose short parts all resolve, else None: the key holds no short part, or one
    that stands for two names, for none, or that sits under a part that didn't resolve. `siblings` gives the lower-case names
    directly under a parent path such as \\users."""
    parent, changed = "", False
    for part in key.split("\\")[1:]:
        short = SHORT_PART.match(part)
        if short:
            names = siblings(parent)
            if part not in names:   # a name that is there already is a long name, tilde and all
                found = sorted(n for n in names if stands_for(short, n))
                if len(found) != 1:
                    return None
                part, changed = found[0], True
        parent += "\\" + part
    return parent if changed else None


def build_short_paths(con: duckdb.DuckDBPyConnection) -> None:
    """Recreate short_paths from the events. With no file key that holds a ~, which is nearly every case, it is empty after one
    cheap scan; otherwise each distinct parent that a short part sits under is read once, from its host's MFT records."""
    con.execute("CREATE OR REPLACE TABLE short_paths (event_uid VARCHAR, host VARCHAR, short_key VARCHAR, long_key VARCHAR)")
    # The contains test runs first and the pattern after it, on the few keys that hold a ~: the pattern alone over every event
    # took 79 ms at 1.2 million events against 20 ms, and Python's test of each of 10,859 keys with a ~ took 35 ms more
    candidates = [(host, key) for host, key in con.execute(
        "SELECT DISTINCT host, file_key FROM events WHERE contains(file_key, '~') AND regexp_matches(file_key, ?)",
        [SQL_SHORT_PART]).fetchall() if any(SHORT_PART.match(part) for part in key.split("\\")[1:])]
    if not candidates:
        return
    seen: dict[tuple[str, str], set[str]] = {}

    def names_under(host: str) -> Callable[[str], set[str]]:
        def siblings(parent: str) -> set[str]:
            if (host, parent) not in seen:
                prefix = parent + "\\"
                seen[host, parent] = {name for (name,) in con.execute(
                    "SELECT DISTINCT substr(file_key, ?) FROM events WHERE host = ? AND artifact = 'mft' "
                    "AND starts_with(file_key, ?) AND NOT contains(substr(file_key, ?), '\\')",
                    [len(prefix) + 1, host, prefix, len(prefix) + 1]).fetchall()}
            return seen[host, parent]
        return siblings

    resolved = [(host, key, long) for host, key in sorted(candidates)
                if (long := resolve(key, names_under(host))) is not None]
    if not resolved:
        return
    con.execute("CREATE OR REPLACE TEMP TABLE short_map (host VARCHAR, short_key VARCHAR, long_key VARCHAR)")
    insert_columns(con, "short_map", *zip(*resolved, strict=True))
    con.execute("INSERT INTO short_paths SELECT e.event_uid, e.host, m.short_key, m.long_key FROM events e "
                "JOIN short_map m ON m.host = e.host AND m.short_key = e.file_key")
    con.execute("DROP TABLE short_map")
