"""Attack-phase and technique tags.

A tag is one of three kinds, kept as a key in the journal:
  tactic:TA0008       an ATT&CK Enterprise tactic, by ID, so a renamed tactic keeps its tags
  technique:T1021.001 an ATT&CK technique or sub-technique ID
  tag:staging         the analyst's own tag, in lower case with single spaces
An event can carry several. The analyst's tags are journaled like marks. Hayabusa's rule tags are only suggestions,
shown until the analyst accepts or dismisses them.

The tactics are ATT&CK v19.2's, listed at https://attack.mitre.org/tactics/enterprise/: Defense
Evasion became Stealth (TA0005) and Defense Impairment (TA0112). Hayabusa's abbreviations are from its
config/mitre_tactics.txt (4.1.0), which also folds older defense-evasion rules into Stealth. v20.0's are the same
(test_attack.py holds it).

A technique the analyst adds must be in the bundled Enterprise ATT&CK list (attack.py), as a finding's must. The
journal's replay and a tag's removal check only the ID's form, so an older tag on an ID off the
list replays unchanged and can be taken off.
"""

from __future__ import annotations

import re

from . import attack

# (ID, name, Hayabusa abbreviation), in kill-chain order
TACTICS = (
    ("TA0043", "Reconnaissance", "Recon"), ("TA0042", "Resource Development", "ResDev"),
    ("TA0001", "Initial Access", "InitAccess"), ("TA0002", "Execution", "Exec"), ("TA0003", "Persistence", "Persis"),
    ("TA0004", "Privilege Escalation", "PrivEsc"), ("TA0005", "Stealth", "Stealth"),
    ("TA0112", "Defense Impairment", "DefImpair"), ("TA0006", "Credential Access", "CredAccess"),
    ("TA0007", "Discovery", "Disc"), ("TA0008", "Lateral Movement", "LatMov"), ("TA0009", "Collection", "Collect"),
    ("TA0011", "Command and Control", "C2"), ("TA0010", "Exfiltration", "Exfil"), ("TA0040", "Impact", "Impact"))
TACTIC_NAME = {tid: name for tid, name, _ in TACTICS}
TACTIC_BY_NAME = {**{abbr.lower(): tid for tid, _, abbr in TACTICS}, **{name.lower(): tid for tid, name, _ in TACTICS}}
TECHNIQUE = re.compile(r"^[Tt](\d{4})(?:\.(\d{3}))?$")
CUSTOM = re.compile(r"^[^\x00-\x1f\x7f]{1,40}$")
HAYABUSA_SEPARATOR = "¦"   # Hayabusa joins several tactics or techniques with " ¦ "


class TagError(ValueError):
    """A tag the app doesn't accept, with a message for the analyst."""


def normalize_tag(text: str, listed: bool = True) -> str:
    """The key for what the analyst typed or picked: a tactic name or ID, a technique ID, or a tag of their own. A
    technique must be in the ATT&CK list; with `listed` false, any ID of the right form will do."""
    if not isinstance(text, str) or not text.strip():
        raise TagError("A tag can't be empty.")
    text = " ".join(text.split())
    kind, _, rest = text.partition(":")
    if kind in ("tactic", "technique", "tag") and rest:
        text = rest.strip()
        if kind == "tag":
            return _custom(text)
    upper = text.upper()
    if upper in TACTIC_NAME:
        return f"tactic:{upper}"
    if text.lower() in TACTIC_BY_NAME:
        return f"tactic:{TACTIC_BY_NAME[text.lower()]}"
    m = TECHNIQUE.match(text)
    if m:
        tid = f"T{m.group(1)}" + (f".{m.group(2)}" if m.group(2) else "")
        if listed and (why := attack.tag_refusal(tid)):
            raise TagError(why)
        return f"technique:{tid}"
    if kind in ("tactic", "technique"):
        raise TagError(f"{text} isn't an ATT&CK {kind}.")
    return _custom(text)


def _custom(text: str) -> str:
    if not CUSTOM.match(text):
        raise TagError("Your own tags are 1 to 40 printable characters.")
    return f"tag:{text.lower()}"


def tag_kind(key: str) -> str:
    return key.partition(":")[0]


def tag_label(key: str) -> str:
    kind, _, value = key.partition(":")
    return TACTIC_NAME.get(value, value) if kind == "tactic" else value


def tactic_order(key: str) -> int:
    """Kill-chain position for sorting; techniques and the analyst's tags come after the tactics."""
    ids = [tid for tid, _, _ in TACTICS]
    kind, _, value = key.partition(":")
    return ids.index(value) if kind == "tactic" and value in ids else len(ids)
