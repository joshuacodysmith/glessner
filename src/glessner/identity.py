"""Host identity: each host's role, names, addresses, clock offset, zone, and release, as analysis.build_identity
reads them from the evidence and the journal, and the lookup that resolves a name or an address to a host.

It lives in a module of its own so relations.py and clock.py, which analysis.py imports, can import it
without a cycle. queries.TS applies each host's offset_seconds, which analysis.build_identity_tables writes to the
hosts table.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .parsers.common import normalize_ip


@dataclass
class HostIdentity:
    host: str
    role: str
    role_source: str                       # "guess" or "analyst"
    names: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    offset_seconds: float = 0.0            # analyst-set clock correction, added to this host's event times
    offset_aligned: bool = False           # the offset is the Case panel's switch's, which it can undo
    guessed_role: str = ""                 # what the evidence suggests, kept after the analyst sets a role
    role_reason: str = ""                  # why the guess, in a sentence
    role_by: str = ""                      # who set or confirmed the role, and when
    role_at: str = ""
    review: list[str] = field(default_factory=list)   # why the host needs the analyst's review; empty when it doesn't
    timezone: dict = field(default_factory=dict)        # the host's own zone from its SYSTEM hive; see timezones.py
    os: dict = field(default_factory=dict)              # the host's Windows release from its SOFTWARE hive; see host_os
    clock: dict = field(default_factory=dict)           # its clock against the network capture; see clock.py
    registry_names: list[str] = field(default_factory=list)   # SYSTEM ComputerName values, which a split keeps


@dataclass
class Identity:
    hosts: dict[str, HostIdentity]
    lookup: dict[str, str]                  # upper-case name or IP -> host
    conflicts: list[str]                    # names or IPs claimed by more than one host
    mixed: dict[str, dict] = field(default_factory=dict)   # hosts whose event logs record several computers

    def offsets_us(self) -> dict[str, int]:
        return {h.host: round(h.offset_seconds * 1_000_000) for h in self.hosts.values() if h.offset_seconds}

    def offset_bounds_us(self) -> tuple[int, int]:
        """Smallest and largest offset, each including zero, for widening raw-time filters."""
        values = [0, *self.offsets_us().values()]
        return min(values), max(values)

    def resolve_ip(self, ip: str) -> str | None:
        return self.lookup.get(ip) if ip else None

    def resolve_name(self, name: str) -> str | None:
        """A host by a computer name, or by an address written where a name goes, read as lookup_key reads it."""
        key = lookup_key(name)
        return self.lookup.get(key) if key else None


def lookup_key(name: str) -> str:
    """The key a computer name finds its host by in Identity.lookup: an address written where a name goes, as a 4648's
    TargetServerName is when the account connected to an IP, in normalize_ip's form; otherwise the name's first label
    in upper case. Empty for a blank name."""
    name = name.strip() if name else ""
    if not name:
        return ""
    # Only text with a colon or a leading digit can be an address, and a failed parse costs about 17 times the
    # lookup, which runs for every logon a view or a refresh links
    ip = normalize_ip(name) if ":" in name or name[0].isdigit() else ""
    return ip or name.split(".")[0].upper()
