"""The hash list: each event's file hashes, lower-case hexadecimal of any algorithm, sorted, with no repeats,
separated by single spaces, '' when it has none, as ECS's related.hash lists them. Same hash (queries._branches)
matches on it.

The list is one SQL expression over the row's artifact, provider, channel, and extra, which reads extra only on the
rows of the sources below, each of which stores its hashes in the row. The load (events.load) and the case format 3
step's fill (rekey._fill_columns) use this one expression, so the two can't differ. Only values of 32,
40, or 64 hexadecimal characters are kept: MD5, SHA-1, and SHA-256.

Left out on purpose: PECmd's Hash, the prefetch path hash, which hashes a path, not a file's bytes, and must not
join; Sysmon's IMPHASH and Autoruns' IMP, PESHA-1, and PESHA-256, since an import hash joins different programs with
the same imports and an Authenticode hash isn't what any other source records, while Same hash means the same file's
bytes; Zeek's x509 fingerprints, which hash certificates; and generic imports, which have no hash role.
"""

from __future__ import annotations

HEX = "[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}"
# The algorithm a hash's length gives, strongest first, for the value Same hash shows (pivots._value_of)
ALGORITHMS = {64: "SHA-256", 40: "SHA-1", 32: "MD5"}


def _field(name: str) -> str:
    """A key of extra, quoted in the JSON path, since keys such as SHA-1 and fileinfo.sha256 hold a hyphen or a dot."""
    return f"json_extract_string(extra, '$.\"{name}\"')"


def _listed(values: str) -> str:
    """A list expression of candidate values as the column holds them: trimmed, lower case, only whole MD5, SHA-1, and
    SHA-256 values, distinct, sorted, and joined by spaces."""
    return (f"array_to_string(list_sort(list_distinct([lower(trim(h)) FOR h IN {values} "
            f"IF regexp_full_match(lower(trim(h)), '{HEX}')])), ' ')")


# AmcacheParser's SHA1 is lower case already; a 44-character value starting 0000 is Amcache's FileId form of it
AMCACHE = (f"[CASE WHEN length({_field('SHA1')}) = 44 AND starts_with({_field('SHA1')}, '0000') "
           f"THEN substr({_field('SHA1')}, 5) ELSE {_field('SHA1')} END]")
AUTORUNS = f"[{_field('MD5')}, {_field('SHA-1')}, {_field('SHA-256')}]"
# Sysmon's Hashes (events 1, 6, 7, 23, 26, 29) or Hash (15), as SHA1=...,MD5=...,SHA256=...,IMPHASH=...: the three
# algorithms by name, so IMPHASH stays out
SYSMON = (f"[split_part(p, '=', 2) FOR p IN string_split(COALESCE({_field('Hashes')}, {_field('Hash')}), ',') "
          "IF upper(trim(split_part(p, '=', 1))) IN ('MD5', 'SHA1', 'SHA256')]")
SURICATA = f"[{_field('fileinfo.md5')}, {_field('fileinfo.sha1')}, {_field('fileinfo.sha256')}]"
ZEEK_FILES = f"[{_field('md5')}, {_field('sha1')}, {_field('sha256')}]"

HASHES_SQL = (
    "COALESCE(CASE"
    f" WHEN artifact = 'amcache' THEN {_listed(AMCACHE)}"
    f" WHEN artifact = 'autoruns' THEN {_listed(AUTORUNS)}"
    f" WHEN artifact = 'evtx' AND lower(event_provider) = 'microsoft-windows-sysmon' THEN {_listed(SYSMON)}"
    f" WHEN artifact = 'suricata' THEN {_listed(SURICATA)}"
    f" WHEN artifact = 'zeek' AND log_channel = 'files' THEN {_listed(ZEEK_FILES)}"
    " END, '')")


def strongest(hashes: str) -> tuple[str, list[str]]:
    """The hash Same hash shows, with its algorithm by length, such as "SHA-256 9f86d081...e7a3", and the others in
    full with theirs, strongest first."""
    found = sorted(hashes.split(), key=lambda h: (-len(h), h))
    if not found:
        return "", []
    named = [f"{ALGORITHMS.get(len(h), 'hash')} {h}" for h in found]
    first = found[0]
    return f"{ALGORITHMS.get(len(first), 'hash')} {first[:8]}...{first[-4:]}", named[1:]
