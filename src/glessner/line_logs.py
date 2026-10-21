"""Log lines in known layouts, for the import: Apache and NGINX access logs, Apache error
logs, syslog, Cisco ASA, Snort and Suricata fast alerts, and any lines that start with a date and time.

Each layout is a few regular expressions whose named groups become a record's fields, and an extractor that adds
fields read from the message: addresses and ports, the account, an action. Intake identifies a file by layout when
most of its first lines fit one (identify.py); imports.py reads the records and its presets map the fields.

Cisco ASA connection messages (302013 to 302016) name two hosts, and the order depends on the direction. Inbound runs
from a lower security level to a higher one, and Cisco writes its initiator first. Outbound runs the other way, and
Cisco writes the lower-level responder first, so the initiator comes second (Cisco TAC, "ASA syslog" Q&A 116149).
EvidenceForge (https://github.com/Cisco-Talos/EvidenceForge), Cisco Talos's synthetic log generator, writes outbound
connections with the initiator first. The extractor tells the two apart by the interfaces' levels: "outside" is the
lowest, and each inbound connection shows its first interface below its second. When neither is known, Cisco's order
holds. A teardown carries no direction, so it takes its connection's from the
Built message; a teardown whose Built isn't in the file keeps the order written and says the direction is unknown.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

Extractor = Callable[[dict], None]


@dataclass(frozen=True)
class Layout:
    name: str
    label: str
    patterns: tuple[re.Pattern, ...]
    columns: tuple[str, ...]                        # every field a record can have, in display order
    extractor: Callable[[], Extractor] | None = None   # makes one file's extractor, which may keep state
    generic: bool = False                           # identified only when no structured format fits

    def parser(self) -> Callable[[str], dict | None]:
        """A function that turns one line into a record, or None when the line doesn't fit."""
        add = self.extractor() if self.extractor else None

        def parse(line: str) -> dict | None:
            for pattern in self.patterns:
                m = pattern.match(line)
                if m:
                    rec = {k: v or "" for k, v in m.groupdict().items()}
                    if add:
                        add(rec)
                    return rec
            return None
        return parse

    def fits(self, line: str) -> bool:
        return any(p.match(line) for p in self.patterns)


# ---------- Apache and NGINX ----------

QUOTED = r'(?:[^"\\]|\\.)*'
APACHE_ACCESS = re.compile(rf'^(?P<client>\S+) (?P<ident>\S+) (?P<user>\S+) \[(?P<time>[^\]]+)\] "(?P<request>{QUOTED})" '
                           rf'(?P<status>\d{{3}}|-) (?P<bytes>\d+|-)(?: "(?P<referer>{QUOTED})" "(?P<agent>{QUOTED})")?'
                           r'(?P<rest>.*)$')
# A key=value key: a run of name characters from its first letter or underscore, so "9abc=1" has the key abc. The run
# is read once from its start, digits, dots, and dashes skipped (possessive), not tried again from each of its letters,
# which takes time with the square of a long word's length when the word has no =. The key is group 1, and a match can
# start at the skipped characters, before the key.
KV_KEY = r'(?<![\w.-])(?:[^\W_A-Za-z]|[.-])*+([A-Za-z_][\w.-]*+)='
KV_EXTRA = re.compile(KV_KEY + r'("[^"]*"|\S*)')


def _apache_access() -> Extractor:
    def add(rec: dict) -> None:
        parts = rec["request"].split(" ")
        if len(parts) >= 2 and parts[0].isalpha() and parts[0].isupper():
            rec["method"], rec["url"] = parts[0], parts[1]
            rec["protocol"] = parts[2] if len(parts) > 2 else ""
        else:   # a request that isn't HTTP, such as a TLS handshake sent to port 80
            rec["method"], rec["url"], rec["protocol"] = "", rec["request"], ""
        rest = rec.pop("rest").strip()
        for k, v in KV_EXTRA.findall(rest):   # extra fields some proxies append, such as "cs_bytes=434 ..."
            rec.setdefault(k, v.strip('"'))
    return add


APACHE_ERROR = re.compile(r'^\[(?P<time>[A-Z][a-z]{2} [A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2}(?:\.\d+)? \d{4})\] '
                          r'\[(?:(?P<module>[^:\]\s]+):)?(?P<level>[^\]\s]+)\]'
                          r'(?: \[pid (?P<pid>\d+)(?::tid (?P<tid>\d+))?\])?(?: \[client (?P<client>[^\]]+)\])? ?'
                          r'(?P<message>.*)$')


# ---------- syslog ----------

SYSLOG_5424 = re.compile(r'^<(?P<pri>\d{1,3})>(?P<version>\d{1,2}) (?P<time>\S+) (?P<hostname>\S+) (?P<app>\S+) '
                         r'(?P<procid>\S+) (?P<msgid>\S+) (?P<sd>-|(?:\[(?:[^\]\\]|\\.)*\])+)(?: (?P<message>.*))?$')
SYSLOG_3339 = re.compile(r'^(?:<(?P<pri>\d{1,3})>)?(?P<time>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?'
                         r'(?:Z|[+-]\d{2}:\d{2})) (?P<hostname>\S+) (?P<app>[^\s:\[]+)(?:\[(?P<procid>[^\]]*)\])?: ?'
                         r'(?P<message>.*)$')
SYSLOG_3164 = re.compile(r'^(?:<(?P<pri>\d{1,3})>)?(?P<time>[A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2}(?:\.\d+)?) '
                         r'(?:(?P<hostname>[^\s:\[]+) )?(?P<app>[^\s:\[]+)(?:\[(?P<procid>[^\]]*)\])?: ?(?P<message>.*)$')
FACILITIES = ("kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron", "authpriv", "ftp",
              "ntp", "audit", "alert", "clock", "local0", "local1", "local2", "local3", "local4", "local5", "local6",
              "local7")
SEVERITIES = ("emerg", "alert", "crit", "err", "warning", "notice", "info", "debug")
NETFILTER = re.compile(r'\b([A-Z][A-Z0-9_]*)=(\S*)')   # iptables and UFW: SRC=, DST=, SPT=, DPT=, PROTO=
UFW_ACTION = re.compile(r'\[UFW (\w+)\]')
SSHD = (
    re.compile(r'^(?P<action>Accepted|Failed) (?P<auth>\S+) for (?:invalid user )?(?P<user>\S+) from (?P<src_ip>\S+) '
               r'port (?P<src_port>\d+)'),
    re.compile(r'^(?P<action>Invalid user) (?P<user>\S*) from (?P<src_ip>\S+)(?: port (?P<src_port>\d+))?'),
    re.compile(r'^(?P<action>Disconnected) from (?:invalid |authenticating )?user (?P<user>\S+) (?P<src_ip>\S+) '
               r'port (?P<src_port>\d+)'),
)
SESSION = re.compile(r'session (?P<action>opened|closed) for user (?P<user>[^\s(]+)')
# The text before PWD= runs to the first "; PWD=", and the directory to the first " ; USER=" that a COMMAND= follows,
# each read once (possessive). A lazy .*? tries both again from every "; PWD=", so its matching time grows with the
# square of the line's length.
SUDO = re.compile(r'^\s*(?P<user>\S+) : (?:(?:(?!; PWD=).)*+; )?'
                  r'PWD=(?P<pwd>(?:(?! ; USER=\S+ ; COMMAND=).)*+) ; USER=(?P<as_user>\S+) ; COMMAND=(?P<command>.*)$')


def _syslog() -> Extractor:
    def add(rec: dict) -> None:
        for k in ("hostname", "app", "procid", "msgid", "sd", "time"):
            if rec.get(k) == "-":   # RFC 5424's nil value
                rec[k] = ""
        if rec.get("pri"):
            pri = int(rec["pri"])
            rec["facility"] = FACILITIES[pri // 8] if pri // 8 < len(FACILITIES) else str(pri // 8)
            rec["severity"] = SEVERITIES[pri % 8]
        message = rec.get("message", "")
        if "SRC=" in message and "DST=" in message:
            for k, v in NETFILTER.findall(message):
                rec.setdefault(k, v)
            rec.update(src_ip=rec.get("SRC", ""), dst_ip=rec.get("DST", ""), src_port=rec.get("SPT", ""),
                       dst_port=rec.get("DPT", ""), proto=rec.get("PROTO", ""))
            action = UFW_ACTION.search(message)
            if action:
                rec["action"] = action.group(1)
        app = rec.get("app", "").lower()
        if app.startswith("sshd"):
            for pattern in SSHD:
                m = pattern.match(message)
                if m:
                    rec.update({k: v for k, v in m.groupdict().items() if v})
                    break
        if app == "sudo":
            m = SUDO.match(message)
            if m:
                rec.update(m.groupdict())
        if "user" not in rec:
            m = SESSION.search(message)
            if m:
                rec.update(action=f"session {m.group('action')}", user=m.group("user"))
    return add


# ---------- Cisco ASA ----------

ASA_TIME = (r'(?:[A-Z][a-z]{2} +\d{1,2}(?: \d{4})? \d{2}:\d{2}:\d{2}(?:\.\d+)?'
            r'|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)')
ASA_LINE = re.compile(r'^(?P<prefix>.*?)%(?P<facility>ASA|FTD|PIX|FWSM)-(?P<severity>\d)-(?P<msgid>\d{6}):?\s*'
                      r'(?P<message>.*)$')
ASA_PREFIX_TIME = re.compile(ASA_TIME)
PRI = re.compile(r'^<(\d{1,3})>')
END = r'(?P<{0}_if>[^\s:]+):(?P<{0}_ip>[0-9A-Fa-f.:]+?)/(?P<{0}_port>\d+)'
A, B = END.format("a"), END.format("b")
PAREN = r'(?:\s*\([^)]*\))*'
ASA_BUILT = re.compile(rf'^(?P<action>Built) (?P<direction>inbound|outbound) (?P<proto>\w+) connection (?P<conn>\d+) '
                       rf'for {A}{PAREN} to {B}{PAREN}')
ASA_TEARDOWN = re.compile(rf'^(?P<action>Teardown) (?P<proto>\w+) connection (?P<conn>\d+) for {A}{PAREN} to {B}{PAREN}'
                          r'(?: duration (?P<duration>\S+))?(?: bytes (?P<bytes>\d+))?\s*(?P<reason>.*)$')
ASA_ICMP = re.compile(r'^(?P<action>Built|Teardown) (?:(?P<direction>inbound|outbound) )?(?P<proto>ICMP\w*) connection '
                      r'for faddr (?P<f_ip>[^/\s]+)/(?P<f_port>\d+)(?:\s*\([^)]*\))* gaddr (?P<g_ip>[^/\s]+)/\d+ '
                      r'laddr (?P<l_ip>[^/\s]+)/(?P<l_port>\d+)')
ASA_TRANSLATION = re.compile(rf'^(?P<action>Built|Teardown) (?:dynamic|static) (?P<proto>\w+) translation from {A} '
                             rf'to {B}(?: duration (?P<duration>\S+))?')
ASA_DENY = re.compile(r'^(?P<action>Deny)(?: (?P<direction>inbound|outbound))? (?P<proto>\w+) src '
                      r'(?P<a_if>[^\s:]+):(?P<a_ip>[^/\s]+)(?:/(?P<a_port>\d+))? dst (?P<b_if>[^\s:]+):(?P<b_ip>[^/\s]+)'
                      r'(?:/(?P<b_port>\d+))?(?: \(type \d+, code \d+\))?(?: by access-group "(?P<acl>[^"]*)")?')
ASA_ACL = re.compile(r'^access-list (?P<acl>\S+) (?P<action>permitted|denied|est-allowed) (?P<proto>\w+) '
                     r'(?P<a_if>[^/\s]+)/(?P<a_ip>[^(\s]+)\((?P<a_port>\d+)\)(?:\([^)]*\))? -> '
                     r'(?P<b_if>[^/\s]+)/(?P<b_ip>[^(\s]+)\((?P<b_port>\d+)\)')
ASA_FROM_TO = re.compile(r'\bfrom (?:(?P<a_if>[^\s:/]+):)?(?P<a_ip>[0-9A-Fa-f.:]+?)/(?P<a_port>[\w-]+) '
                         r'to (?:(?P<b_if>[^\s:/]+):)?(?P<b_ip>[0-9A-Fa-f.:]+?)/(?P<b_port>[\w-]+)')
ASA_USER = re.compile(r'(?:\buser(?:name)? = |\bUname: |\buser "|\bUser <|\bUsername = )(?P<user>[^"\s>,:]+)')
ASA_COLUMNS = ("action", "direction", "proto", "conn", "src_if", "src_ip", "src_port", "dst_if", "dst_ip", "dst_port",
               "nat_ip", "nat_port", "duration", "bytes", "reason", "acl", "user")


def _ends(rec: dict, m: re.Match, src: str, dst: str) -> None:
    g = m.groupdict()
    for side, name in ((src, "src"), (dst, "dst")):
        for part in ("if", "ip", "port"):
            if g.get(f"{side}_{part}"):
                rec[f"{name}_{part}"] = g[f"{side}_{part}"]


def _cisco_asa() -> Extractor:
    below: set[tuple[str, str]] = set()   # (lower, higher) security levels, as inbound connections show them
    connections: dict[str, bool] = {}   # connection ID: whether the first address written is the initiator

    def lower(x: str, y: str) -> bool:
        return x == "outside" or (x, y) in below
    icmp: dict[tuple[str, str], str] = {}   # (faddr, laddr): the direction of its Built message

    def add(rec: dict) -> None:
        prefix = rec.pop("prefix", "")
        pri = PRI.match(prefix.strip())
        rec["pri"] = pri.group(1) if pri else ""
        stamps = list(ASA_PREFIX_TIME.finditer(prefix))
        rec["time"] = stamps[0].group(0) if stamps else ""
        tail = prefix[stamps[-1].end():] if stamps else prefix[pri.end():] if pri else prefix
        words = tail.replace(":", " ").split()
        rec["hostname"] = words[-1] if words else ""
        message = rec["message"]
        if m := ASA_BUILT.match(message):
            rec.update(action="Built", direction=m["direction"], proto=m["proto"], conn=m["conn"])
            a_if, b_if = m["a_if"].lower(), m["b_if"].lower()
            if m["direction"] == "inbound":   # from a lower security level to a higher one, initiator first
                below.add((a_if, b_if))
                first = True
            else:   # Cisco writes the lower-level responder first; EvidenceForge, the initiator
                first = lower(b_if, a_if) and not lower(a_if, b_if)
            connections[m["conn"]] = first
            if len(connections) > 1_000_000:
                connections.clear()
            _ends(rec, m, *(("a", "b") if first else ("b", "a")))
        elif m := ASA_TEARDOWN.match(message):
            rec.update({k: v for k, v in m.groupdict().items() if v and k[:2] not in ("a_", "b_")})
            first = connections.pop(m["conn"], None)
            if first is None:
                rec["direction"] = "unknown: the connection was built before the log starts"
            _ends(rec, m, *(("a", "b") if first in (True, None) else ("b", "a")))
        elif m := ASA_ICMP.match(message):
            rec.update(action=m["action"], proto=m["proto"])
            direction = m["direction"] or icmp.pop((m["f_ip"], m["l_ip"]), "")
            if m["action"] == "Built" and m["direction"]:
                icmp[(m["f_ip"], m["l_ip"])] = m["direction"]
            rec["direction"] = direction or "unknown"
            outbound = direction == "outbound"
            rec.update(src_ip=m["l_ip"] if outbound else m["f_ip"], dst_ip=m["f_ip"] if outbound else m["l_ip"],
                       nat_ip=m["g_ip"])
        elif m := ASA_TRANSLATION.match(message):
            rec.update(action=m["action"], proto=m["proto"], src_if=m["a_if"], src_ip=m["a_ip"], src_port=m["a_port"],
                       nat_ip=m["b_ip"], nat_port=m["b_port"], duration=m["duration"] or "")
        elif m := ASA_DENY.match(message) or ASA_ACL.match(message):
            rec.update({k: v for k, v in m.groupdict().items() if v and k[:2] not in ("a_", "b_")})
            _ends(rec, m, "a", "b")
        elif m := ASA_FROM_TO.search(message):
            _ends(rec, m, "a", "b")
            word = re.match(r'^(\w+)', message)
            if "denied" in message.lower() or message.startswith("Deny"):
                rec["action"] = "denied"
            elif "permitted" in message.lower():
                rec["action"] = "permitted"
            elif word:
                rec["action"] = word.group(1)
        if "user" not in rec and (u := ASA_USER.search(message)):
            rec["user"] = u["user"]
    return add


# ---------- Snort, Suricata, and lines that start with a time ----------

# The signature is words separated by spaces, up to a word that begins [**]. Its quantifiers are possessive (++, *+):
# with the spaces around a lazy .*? able to share a run of spaces, matching time would grow with the cube of the run, and
# one crafted 8 KB line would hold intake for 445 s.
SNORT_FAST = re.compile(r'^(?P<time>\d{2}/\d{2}(?:/\d{2,4})?-\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+\[\*\*\]\s+'
                        r'\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s++'
                        r'(?:(?P<signature>(?!\[\*\*\])\S++(?:\s++(?!\[\*\*\])\S++)*+)\s++)?\[\*\*\]'
                        r'(?:\s+\[Classification: (?P<classification>[^\]]*)\])?(?:\s+\[Priority: (?P<priority>\d+)\])?'
                        r'\s+\{(?P<proto>[^}]*)\}\s+(?P<src>\S+)\s+->\s+(?P<dst>\S+)')


def _snort() -> Extractor:
    def add(rec: dict) -> None:
        rec["rule"] = f"{rec['gid']}:{rec['sid']}:{rec['rev']}"
    return add


STAMPED = re.compile(r'^\[?(?P<time>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,9})?'
                     r'(?: ?(?:Z|UTC|[+-]\d{2}:?\d{2}))?)\]?[\s,;|]+(?P<message>\S.*)$')

SYSLOG_COLUMNS = ("pri", "facility", "severity", "version", "time", "hostname", "app", "procid", "msgid", "sd",
                  "message", "action", "auth", "user", "src_ip", "src_port", "dst_ip", "dst_port", "proto", "command")
# Most specific first: an ASA line is also a syslog line.
LAYOUTS: dict[str, Layout] = {layout.name: layout for layout in (
    Layout("cisco_asa", "Cisco ASA", (ASA_LINE,),
           ("pri", "time", "hostname", "facility", "severity", "msgid", "message") + ASA_COLUMNS, _cisco_asa),
    Layout("snort_fast", "Snort or Suricata fast alert", (SNORT_FAST,),
           ("time", "gid", "sid", "rev", "rule", "signature", "classification", "priority", "proto", "src", "dst"),
           _snort),
    Layout("apache_access", "Apache or NGINX access log", (APACHE_ACCESS,),
           ("client", "ident", "user", "time", "request", "method", "url", "protocol", "status", "bytes", "referer",
            "agent"), _apache_access),
    Layout("apache_error", "Apache error log", (APACHE_ERROR,),
           ("time", "module", "level", "pid", "tid", "client", "message")),
    Layout("syslog", "Syslog", (SYSLOG_5424, SYSLOG_3339, SYSLOG_3164), SYSLOG_COLUMNS, _syslog),
    Layout("timestamped", "Lines that start with a date and time", (STAMPED,), ("time", "message"), generic=True),
)}
BY_LABEL = {layout.label: layout.name for layout in LAYOUTS.values()}


def detect_layout(lines: list[str], generic: bool = False) -> Layout | None:
    """The layout most of a file's first lines fit: the structured ones, or with generic, the timestamped one."""
    lines = [line for line in lines if line.strip()][:12]
    if not lines:
        return None
    for layout in LAYOUTS.values():
        if layout.generic != generic:
            continue
        fit = sum(1 for line in lines if layout.fits(line))
        if fit and fit >= 0.8 * len(lines):
            return layout
    return None
