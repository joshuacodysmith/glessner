"""Parsers turn one tool run's output folder into Event rows. Each registry file names its parser."""

from __future__ import annotations

from collections.abc import Callable, Iterator

from ..events import Event
from .amcache import parse_amcache
from .autoruns import parse_autoruns
from .common import ParseContext
from .evtxecmd import parse_event_xml, parse_evtxecmd
from .hayabusa import parse_hayabusa
from .jlecmd import parse_jlecmd
from .lecmd import parse_lecmd
from .mftecmd import parse_mftecmd
from .mftecmd_j import parse_mftecmd_j
from .pecmd import parse_pecmd
from .rbcmd import parse_rbcmd
from .recmd import parse_recmd
from .sbecmd import parse_sbecmd
from .sqlecmd import parse_sqlecmd
from .srumecmd import parse_srumecmd
from .suricata import parse_suricata_eve
from .wxtcmd import parse_wxtcmd

Parser = Callable[[ParseContext], Iterator[Event]]

PARSERS: dict[str, Parser] = {
    "evtxecmd_csv": parse_evtxecmd,
    "hayabusa_csv": parse_hayabusa,
    "recmd_csv": parse_recmd,
    "mftecmd_csv": parse_mftecmd,
    "pecmd_csv": parse_pecmd,
    "lecmd_csv": parse_lecmd,
    "sbecmd_csv": parse_sbecmd,
    "amcache_csv": parse_amcache,
    "jlecmd_csv": parse_jlecmd,
    "srumecmd_csv": parse_srumecmd,
    "rbcmd_csv": parse_rbcmd,
    "mftecmd_j_csv": parse_mftecmd_j,   # the USN journal
    "sqlecmd_csv": parse_sqlecmd,   # browser history, downloads, and notifications
    "wxtcmd_csv": parse_wxtcmd,   # the Windows Timeline
    "event_xml_csv": parse_event_xml,   # the built-in Windows event XML reader
    "suricata_eve": parse_suricata_eve,   # packet captures, and EVE files found in the evidence
    "autoruns_csv": parse_autoruns,   # Autoruns CSVs found in the evidence; the app doesn't run Autoruns
}
# The parsers whose event keys a case format changed, by the formats whose rule each still gives in Event.former when
# ParseContext.former asks: format 1's, which format 2 replaced.
# A format's upgrade parses these parsers' runs with both rules and journals the old IDs' new ones (rekey.py).
FORMER_RULES: dict[str, frozenset[int]] = {
    "amcache_csv": frozenset({1}), "srumecmd_csv": frozenset({1}), "suricata_eve": frozenset({1}),
    "sqlecmd_csv": frozenset({1}),
}
# Parsers of output written in the local time of the computer that made it, at the one offset in force when it ran. A
# load resolves the host's zone from its SYSTEM hive (runner.host_zone), records it, and passes it in ParseContext.zone.
LOCAL_TIME = frozenset({"autoruns_csv"})
# What the page calls each parser's events, by their artifact: the Event page's header and the Hosts panel.
# An import's ready-made mappings name their own (imports.PRESETS).
ARTIFACT_NAMES = {
    "evtx": "Event log", "hayabusa": "Hayabusa", "registry": "Registry", "mft": "MFT", "usnjrnl": "USN journal",
    "prefetch": "Prefetch", "lnk": "Shortcut (LNK)", "shellbags": "ShellBag", "amcache": "Amcache", "jumplist": "Jump list",
    "srum": "SRUM", "recycle_bin": "Recycle Bin", "browser": "Browser", "notification": "Windows notification",
    "timeline": "Windows Timeline", "suricata": "Suricata", "autoruns": "Autoruns",
}

__all__ = ["ARTIFACT_NAMES", "FORMER_RULES", "LOCAL_TIME", "PARSERS", "ParseContext", "Parser"]
