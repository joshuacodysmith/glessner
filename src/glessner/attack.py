"""Enterprise ATT&CK's techniques, for a finding's ATT&CK field.

attack_techniques.json holds each current technique and sub-technique of the ATT&CK version it names, with its name and
tactics, and each revoked ID with the technique MITRE revoked it in favor of. scripts/attack_list.py makes it from
MITRE's STIX data, with MITRE's copyright line and license, which every copy carries. The finding form picks from the
list, and a finding's add or edit takes only listed IDs. A finding saved before the list came keeps what it holds: its
card, its form, and the report flag an ID that isn't listed, and an edit of its techniques must drop that ID first.
The journal's own check stays the ID's form, so replay reads every case as before.

The tag picker picks from the same list, and an added technique tag must be listed: a revoked ID
is refused with its replacement named, and Hayabusa's suggestion of one is made as its
replacement. An older tag on an ID off the list is kept and flagged as a finding's is.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from functools import cache
from pathlib import Path

LIST_FILE = Path(__file__).with_name("attack_techniques.json")


@cache
def _data() -> dict:
    return json.loads(LIST_FILE.read_text(encoding="utf-8"))


@cache
def _listed() -> frozenset[str]:
    return frozenset(row[0] for row in _data()["techniques"])


def version() -> str:
    return _data()["attack"]["version"]


def flag(tid: str) -> str:
    """How the card, the form, and the report flag an ID that isn't listed; "" for a listed one."""
    if tid in _listed():
        return ""
    now = _data()["revoked"].get(tid)
    return f"revoked; now {now}" if now else f"not in ATT&CK v{version()}"


def name(tid: str) -> str:
    """A listed technique's name, such as "Command and Scripting Interpreter: PowerShell"; "" for one not listed."""
    return _names().get(tid, "")


@cache
def _names() -> dict[str, str]:
    return {row[0]: row[1] for row in _data()["techniques"]}


def tag_refusal(tid: str) -> str:
    """Why a technique tag can't take this ID, or "" for a listed one. A revoked ID names its replacement."""
    if tid in _listed():
        return ""
    now = _data()["revoked"].get(tid)
    return f"{tid} is revoked in ATT&CK v{version()}; it's now {now}." if now else f"{tid} isn't in ATT&CK v{version()}."


def current() -> dict[str, str]:
    """Each ID with the listed technique it currently stands for: a listed one itself, a revoked one its replacement. Hayabusa's
    suggestions read it, so a rule's revoked ID is suggested as its replacement and an ID it doesn't hold isn't."""
    return {**{t: t for t in _listed()}, **_data()["revoked"]}


def flags(ids: Iterable[str]) -> dict[str, str]:
    """The flagged IDs among these, each with its flag."""
    return {t: f for t in ids if (f := flag(t))}


def worded(ids: Iterable[str]) -> str:
    """The IDs as the card and the report write them: each in its order, an unlisted one with its flag in brackets."""
    return ", ".join(f"{t} ({f})" if (f := flag(t)) else t for t in ids)


def refusal(ids: object) -> str:
    """Why an add or edit can't take these techniques, or "" when every one is listed. Anything but a list of text is
    left to the journal's check, which names the form it needs."""
    if not isinstance(ids, list) or not all(isinstance(t, str) for t in ids):
        return ""
    off = [t for t in ids if t not in _listed()]
    if not off:
        return ""
    one = len(off) == 1
    return (f"{', '.join(off)} {'isn' if one else 'aren'}'t in ATT&CK v{version()}. "
            f"Remove {'it' if one else 'them'} to save the ATT&CK field.")


def picker() -> dict:
    """What the pick lists read: the version, the tactics, the techniques, and the revoked IDs with their replacements, so
    a revoked ID typed names its replacement, with MITRE's copyright."""
    d = _data()
    return {"version": version(), "copyright": d["copyright"], "tactics": d["tactics"], "techniques": d["techniques"],
            "revoked": d["revoked"]}
