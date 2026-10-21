"""Derived analysis tables: host identity, marks, Hayabusa hits per event, and Suricata and imported fast alerts.

These tables live in events.duckdb next to the events table. They are rebuilt from the events
and the journal every time a case opens, so they never hold anything that cannot be recreated.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass

import duckdb

from . import attack
from .accounts import build_account_domains
from .clock import check_clocks
from .events import id_table, insert_columns, live_hive_first, sql_literal
from .identity import HostIdentity, Identity
from .journal import State
from .parsers.common import is_digits, normalize_ip
from .relations import build_logon_links
from .rules import RuleError, parse
from .short_names import build_short_paths
from .tags import HAYABUSA_SEPARATOR, TACTICS, tactic_order, tag_kind, tag_label
from .timezones import host_timezones

MARK_LABELS = {"authorized": "Authorized", "suspicious": "Suspicious", "malicious": "Malicious"}
# Hayabusa's rule levels by rank, the one ordering the hits table, the Suggestions page's groups, and the to-investigate
# list read. An unknown level ranks as informational.
LEVEL_RANK = {"informational": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
DC_PATTERN = re.compile(r"(^|[^A-Z])DC(\d|[^A-Z]|$)")
SERVER_PATTERN = re.compile(r"SRV|SERVER|(^|[^A-Z])(FS|SQL|EXCH|WEB|APP)(\d|[^A-Z]|$)")


# Windows records a machine's type in the SYSTEM hive: ControlSet00N\Control\ProductOptions\ProductType.
ROLE_BY_PRODUCT_TYPE = {"LANMANNT": "Domain controllers", "SERVERNT": "Servers", "WINNT": "Workstations"}
# Imported firewall logs (imports.py presets): a host lane holding only these is the firewall itself. A lane
# holding only network sensor output, from Suricata on a capture or Zeek's logs, is the sensor, not a workstation.
NETWORK_DEVICE_ARTIFACTS = {"fortinet": "FortiGate", "sonicwall": "SonicWall", "cisco_asa": "Cisco ASA",
                            "ids_alert": "Snort or Suricata alert", "suricata": "Suricata", "zeek": "Zeek"}
# Windows records its release in the SOFTWARE hive: Microsoft\Windows NT\CurrentVersion, which RECmd's DFIRBatch
# reports as "System Info (Current)".
OS_VALUES = ("ProductName", "EditionID", "InstallationType", "CurrentBuildNumber", "CurrentBuild", "UBR",
             "DisplayVersion", "ReleaseId", "CSDVersion", "InstallDate")
WINDOWS_11_BUILD = 22000   # Windows 11 still writes "Windows 10" as ProductName; its client builds start here


@dataclass
class RoleEvidence:
    """What the evidence says about a host's role, before names are considered."""
    product_type: str = ""            # SYSTEM ProductOptions\ProductType: LanmanNT, ServerNT, or WinNT
    product_name: str = ""            # SOFTWARE Windows NT\CurrentVersion\ProductName
    kerberos_tgt: int = 0              # Security event 4768 (Kerberos TGT requested), which only DCs log
    network_device: str = ""           # the firewall or sensor, when every event of the host comes from its logs


def build_identity(con: duckdb.DuckDBPyConnection, state: State) -> Identity:
    """Names from each host's EVTX Computer values and SYSTEM ComputerName; IPs from Tcpip interfaces."""
    hosts: dict[str, HostIdentity] = {}
    for (host,) in con.execute("SELECT DISTINCT host FROM events ORDER BY host").fetchall():
        hosts[host] = HostIdentity(host, "", "guess")
    # Registry first, so the current ComputerName leads; EVTX names, newest first, add earlier names.
    for host, _path, name, data in con.execute(
            "SELECT host, registry_path, registry_value, json_extract_string(NULLIF(extra, ''), '$.ValueData') FROM events "
            "WHERE tool = 'recmd' AND ((registry_path LIKE '%\\Control\\ComputerName\\ComputerName' "
            "AND registry_value = 'ComputerName') "
            "OR (registry_path LIKE '%\\Services\\Tcpip\\Parameters\\Interfaces\\%' "
            "AND registry_value IN ('IPAddress', 'DhcpIPAddress')))"
    ).fetchall():
        if name == "ComputerName":
            _add(hosts[host].names, (data or "").strip().upper())
            _add(hosts[host].registry_names, (data or "").strip().upper())
        else:
            for ip in _ips(data or ""):
                _add(hosts[host].ips, ip)
    for host, computer in con.execute(
            "SELECT host, host_name_recorded FROM events WHERE artifact = 'evtx' AND host_name_recorded <> '' "
            "GROUP BY ALL ORDER BY host, max(ts_us) DESC").fetchall():
        _add(hosts[host].names, computer.split(".")[0].upper())
    systems = host_os(con)
    evidence = role_evidence(con, systems)
    zones = host_timezones(con)
    for host, edits in state.hosts.items():
        if host not in hosts:
            continue
        h = hosts[host]
        h.names = [n for n in h.names if n not in edits.remove_names] + sorted(edits.add_names - set(h.names))
        h.ips = [i for i in h.ips if i not in edits.remove_ips] + sorted(edits.add_ips - set(h.ips))
        if edits.role:
            h.role, h.role_source = edits.role, "analyst"
            h.role_by, h.role_at = edits.role_who, edits.role_at
        h.offset_seconds = edits.offset_seconds
        h.offset_aligned = edits.offset_align == "capture" and bool(edits.offset_seconds)
    for h in hosts.values():
        h.guessed_role, h.role_reason = guess_role([h.host, *h.names], evidence.get(h.host))
        h.timezone = zones.get(h.host, {})
        h.os = systems.get(h.host, {})
        if not h.role:
            h.role = h.guessed_role
    lookup: dict[str, str] = {}
    claims: dict[str, list[str]] = {}
    for h in hosts.values():
        for key in [h.host.upper(), *h.names, *h.ips]:
            if h.host not in claims.setdefault(key, []):
                claims[key].append(h.host)
            lookup.setdefault(key, h.host)
    conflicts = sorted(key for key, owners in claims.items() if len(owners) > 1)
    for key in conflicts:
        lookup.pop(key, None)   # an ambiguous name or IP resolves to nothing rather than to the wrong host
    for h in hosts.values():
        if h.role_source == "guess":
            h.review.append("Role not confirmed")
        for key in [*h.names, *h.ips]:
            if key in conflicts:
                h.review.append(f"{key} is also claimed by {', '.join(o for o in claims[key] if o != h.host)}")
    return Identity(hosts, lookup, conflicts)


def role_evidence(con: duckdb.DuckDBPyConnection, systems: dict[str, dict] | None = None) -> dict[str, RoleEvidence]:
    """ProductType from RECmd output, ProductName from host_os (or the `systems` it already returned), and
    Kerberos TGT requests from the Security log."""
    evidence: dict[str, RoleEvidence] = {}
    for host, data in con.execute(
            "SELECT host, json_extract_string(NULLIF(extra, ''), '$.ValueData') FROM events "
            "WHERE tool = 'recmd' AND registry_path LIKE '%\\Control\\ProductOptions' AND registry_value = 'ProductType' "
            f"ORDER BY host, {live_hive_first('system')}, registry_path").fetchall():
        e = evidence.setdefault(host, RoleEvidence())
        if not e.product_type:   # the live hive's lowest-numbered control set comes first
            e.product_type = (data or "").strip()
    for host, system in (host_os(con) if systems is None else systems).items():
        if system["product"]:
            evidence.setdefault(host, RoleEvidence()).product_name = system["product"]
    for host, count in con.execute(
            "SELECT host, count(*) FROM events WHERE artifact = 'evtx' AND event_code = '4768' GROUP BY host").fetchall():
        evidence.setdefault(host, RoleEvidence()).kerberos_tgt = count
    artifacts = ", ".join(f"'{a}'" for a in NETWORK_DEVICE_ARTIFACTS)
    for host, found in con.execute(
            f"SELECT host, list(DISTINCT artifact ORDER BY artifact) FROM events GROUP BY host "
            f"HAVING bool_and(artifact IN ({artifacts}))").fetchall():
        evidence.setdefault(host, RoleEvidence()).network_device = " and ".join(NETWORK_DEVICE_ARTIFACTS[a] for a in found)
    return evidence


def host_os(con: duckdb.DuckDBPyConnection) -> dict[str, dict]:
    """Each host's Windows release from its SOFTWARE hive's Windows NT\\CurrentVersion key.

    The values come from one key per host, so a second SOFTWARE hive in the evidence, such as a RegBack or Windows.old
    copy, or the Wow6432Node key can't mix in. RECmd reads every hive under the host's folder, so the file is ranked
    before the key: a path ending in Windows/System32/config/SOFTWARE, then one outside Windows.old, then the shortest;
    within that file, the shallowest key. `source` names the file read. A host without the key, such as a network
    lane, is left out.
    """
    raw: dict[str, dict] = {}
    names = ", ".join(f"'{v}'" for v in OS_VALUES)
    # Windows.old, or Windows.old.000 after a later upgrade, holds the release from before the upgrade, and its root key
    # name can be the shorter one, so the file is ranked before the key.
    for host, source, path, name, data in con.execute(
            "SELECT host, source_file, registry_path, registry_value, json_extract_string(NULLIF(extra, ''), '$.ValueData') "
            "FROM events WHERE tool = 'recmd' AND registry_path LIKE '%\\Windows NT\\CurrentVersion' "
            f"AND registry_value IN ({names}) "
            f"ORDER BY host, {live_hive_first('software')}, length(registry_path), registry_path").fetchall():
        values = raw.setdefault(host, {"_key": (source, path)})
        if values["_key"] == (source, path):
            values[name] = (data or "").strip()
    systems = {}
    for host, values in raw.items():
        product = values.get("ProductName", "")
        number = values.get("CurrentBuildNumber") or values.get("CurrentBuild", "")
        build = f"{number}.{values['UBR']}" if number and values.get("UBR") else number   # UBR: the update revision
        named = values.get("DisplayVersion") or values.get("ReleaseId", "")   # DisplayVersion from 20H2 on, ReleaseId before
        version = named or values.get("CSDVersion", "")                       # CSDVersion: Service Pack 1 and the like
        installation = values.get("InstallationType", "")
        shown = product
        if (installation.lower() == "client" and product.startswith("Windows 10") and is_digits(number)
                and int(number) >= WINDOWS_11_BUILD):
            shown = "Windows 11" + product[len("Windows 10"):]
        display = ", ".join(p for p in (shown, f"version {named}" if named else version, f"build {build}" if build else "") if p)
        if not display:
            continue
        systems[host] = {
            "product": product,                      # as the registry records it, even where the display says Windows 11
            "edition": values.get("EditionID", ""),
            "installation_type": installation,       # Client, Server, or Server Core
            "build": build,
            "version": version,
            "install_date": values.get("InstallDate", ""),   # RECmd's UTC text, as the host's own clock set it
            # The hive file as the evidence folder holds it, and the key without the hive's root key name
            "source": f"SOFTWARE hive {values['_key'][0]}, key " + values["_key"][1].split("\\", 1)[-1],
            "display": display,
        }
    return systems


def guess_role(names: list[str], evidence: RoleEvidence | None = None) -> tuple[str, str]:
    """A host's likely role and the reason, strongest evidence first: the machine type Windows records,
    Kerberos ticket requests only a DC logs, the product name, and last the host's names."""
    e = evidence or RoleEvidence()
    if e.network_device:
        return "Network devices", f"Its events all come from {e.network_device} logs"
    if e.product_type.upper() in ROLE_BY_PRODUCT_TYPE:
        return ROLE_BY_PRODUCT_TYPE[e.product_type.upper()], f"The SYSTEM hive records its product type as {e.product_type}"
    if e.kerberos_tgt:
        return "Domain controllers", (f"It logged {e.kerberos_tgt:,} Kerberos ticket requests (event 4768), "
                                      "which only domain controllers record")
    if "SERVER" in e.product_name.upper():
        return "Servers", f"Its product name is {e.product_name}"
    upper = [n.upper() for n in names if n]
    for n in upper:
        if DC_PATTERN.search(n):
            return "Domain controllers", f"The name {n} contains DC"
    for n in upper:
        if SERVER_PATTERN.search(n):
            return "Servers", f"The name {n} looks like a server's"
    if e.product_name:
        return "Workstations", f"Its product name is {e.product_name}"
    return "Workstations", "Nothing points to a server or domain controller"


def build_tables(con: duckdb.DuckDBPyConnection, state: State, identity: Identity,
                 clock_cache: dict | None = None) -> dict[str, dict]:
    """Recreate the derived tables, when a case opens or events load. Returns the suggestion report.

    The marks, Hayabusa hits, alerts, and tags read only the events and the journal, so they're built here; the tables
    that read host identity too are built by build_identity_tables, which a host edit calls alone.

    Several tables are created empty and then filled, so the server runs this, build_identity_tables, and
    build_suggestions in one transaction (events.transaction): a request never reads a table between the two."""
    con.execute("CREATE OR REPLACE TABLE marks (event_uid VARCHAR, label VARCHAR, note VARCHAR, seq BIGINT)")
    replace_marks(con, state)
    con.execute(f"""
        CREATE OR REPLACE TABLE hits AS
        SELECT e.event_uid,
               max({level_rank("h.rule_level")}) AS max_level,
               list(h.rule_title ORDER BY h.rule_title) AS titles,
               bool_or(e.ts_us IS NOT NULL) AS timed   -- on the timeline, which a pivot's count of a rule's events reads
        FROM events h {hit_join("h", "e")}
        WHERE h.tool = 'hayabusa'
        GROUP BY e.event_uid""")
    # Each Suricata alert's signature and severity, read once here rather than after every decision. The parser keeps
    # nested fields as dotted names, so the key is quoted: '$.alert.severity' gives NULL for every alert without an
    # error. A missing or non-numeric severity is NULL and never suggested.
    con.execute("""
        CREATE OR REPLACE TABLE suricata_alerts AS
        SELECT event_uid, json_extract_string(NULLIF(extra, ''), '$."alert.signature"') AS signature,
               TRY_CAST(json_extract_string(NULLIF(extra, ''), '$."alert.severity"') AS INTEGER) AS severity
        FROM events WHERE tool = 'suricata' AND log_channel = 'alert'""")
    # Imported Snort or Suricata fast alerts: the line's signature and its
    # "[Priority: N]", which the import keeps as the event's own data under the layout's names (line_logs.py). The
    # artifact is the ready-made mapping's. A line without a priority is NULL and never suggested, as an EVE alert
    # without a severity.
    con.execute("""
        CREATE OR REPLACE TABLE fast_alerts AS
        SELECT event_uid, json_extract_string(NULLIF(extra, ''), '$.signature') AS signature,
               TRY_CAST(json_extract_string(NULLIF(extra, ''), '$.priority') AS INTEGER) AS priority
        FROM events WHERE tool = 'import' AND artifact = 'ids_alert'""")
    # The two names each host gives a service, for Same service name: Autoruns' entry is the
    # key name, and its description starts with the display name ("Windows Audio: Manages audio ..."); a 7040 writes the
    # display name as param1 and the key name as param4. 7045 writes the display name and 4697 the key name, so the
    # pivot joins them through these pairs, in lower case, on any host. Built here, from the events alone, so a case
    # needs no new column or format (pivot_names.service_aliases reads it).
    con.execute("""
        CREATE OR REPLACE TABLE service_aliases AS
        SELECT DISTINCT host, lower(key_name) AS key_name, lower(display_name) AS display_name FROM (
            SELECT e.host, json_extract_string(NULLIF(e.extra, ''), '$."Entry"') AS key_name,
                   split_part(json_extract_string(NULLIF(e.extra, ''), '$."Description"'), ': ', 1) AS display_name
            FROM events e WHERE e.artifact = 'autoruns' AND e.log_channel IN ('Services', 'Drivers')
            UNION ALL
            SELECT e.host, json_extract_string(NULLIF(e.extra, ''), '$."param4"'),
                   json_extract_string(NULLIF(e.extra, ''), '$."param1"')
            FROM events e WHERE e.log_channel = 'System' AND e.event_code = '7040')
        WHERE key_name <> '' AND display_name <> '' AND lower(key_name) <> lower(display_name)""")
    # The file name of each event that has no file key, for Same file name: a bare name such as SRUM's, or a path
    # the key left out. The few such events are read once here, so the pivot's count is the key's ending plus a lookup
    # here, where two scans for them took 28 to 37 ms each at 10.9 million events (pivot_names.file_name_branches).
    con.execute(r"""
        CREATE OR REPLACE TABLE keyless_names AS
        SELECT event_uid, regexp_extract(lower(COALESCE(NULLIF(file_path, ''), process_executable)), '[^\\/]*$') AS name
        FROM events
        WHERE file_key = '' AND COALESCE(NULLIF(file_path, ''), process_executable, '') <> ''""")
    # Each host's 8.3 paths with the long path its MFT says they stand for, for Same file.
    # Built after every load, so it is right in whatever order the tools loaded.
    build_short_paths(con)
    # The spellings of one domain, folded by the SIDs its accounts' logons record, for Same account
    build_account_domains(con)
    con.execute("CREATE OR REPLACE TABLE tags (event_uid VARCHAR, tag VARCHAR, kind VARCHAR, label VARCHAR, "
                "ord INTEGER, seq BIGINT)")
    # origin: the revoked IDs a rule tagged that a technique suggestion stands for, or NULL
    con.execute("CREATE OR REPLACE TABLE tag_suggestions (event_uid VARCHAR, tag VARCHAR, kind VARCHAR, label VARCHAR, "
                "ord INTEGER, origin VARCHAR)")
    refresh_tags(con, state)
    return build_identity_tables(con, state, identity, clock_cache)


def build_identity_tables(con: duckdb.DuckDBPyConnection, state: State, identity: Identity,
                          clock_cache: dict | None = None) -> dict[str, dict]:
    """Recreate the derived tables that read host identity: hosts, the logon links (relations.py), the clock check, and
    the suggestions, since a rule can read a logon's source_host. A host edit (role, offset, name, IP, confirm, or
    align) changes only these, so the marks, hits, alerts, and tags stay as they are. Returns
    the suggestion report.

    The clock check measures each host against the network capture, keeps the result on `identity`, and the pairs that
    agree in the table clock_pairs. It reads recorded times only; it took about 0.1 s on
    the Szechuan case's 1.2 million events. `clock_cache` keeps its measurement between calls, and the lookup the logon
    links were built from, which only a name or IP edit changes; see clock.check_clocks and
    relations.build_logon_links."""
    con.execute("CREATE OR REPLACE TABLE hosts (host VARCHAR, role VARCHAR, names VARCHAR, ips VARCHAR, offset_us BIGINT)")
    insert_columns(con, "hosts", *zip(*[(h.host, h.role, json.dumps(h.names), json.dumps(h.ips),
                                         round(h.offset_seconds * 1_000_000)) for h in identity.hosts.values()]))
    con.execute("DROP TABLE IF EXISTS logon_sources")   # a table that an older version's database may still hold
    build_logon_links(con, identity, clock_cache)
    check_clocks(con, identity, clock_cache)
    return build_suggestions(con, state)


def hit_join(hit: str, event: str) -> str:
    """The join from a Hayabusa hit, under the alias `hit`, to the EvtxECmd event it matched, under `event`. By the host
    both were loaded under, not their lanes: after a split by recorded computer a hit whose Computer differs
    from its event's, or is empty, still finds it."""
    return (f"JOIN events {event} ON {event}.tool = 'evtxecmd' AND {event}.origin_host = {hit}.origin_host "
            f"AND {event}.log_channel = {hit}.log_channel AND {event}.record_id = {hit}.record_id "
            f"AND {event}.source_file = {hit}.source_file")


def level_rank(column: str) -> str:
    """SQL for a rule level column's rank in LEVEL_RANK."""
    whens = " ".join(f"WHEN {sql_literal(name)} THEN {rank}" for name, rank in LEVEL_RANK.items())
    return f"CASE {column} {whens} ELSE 1 END"


def refresh_tags(con: duckdb.DuckDBPyConnection, state: State, uids: list[str] | None = None) -> None:
    """Rewrite the tags and tag suggestions of all events, or only the given ones, from the journal and Hayabusa.
    A suggestion goes once the analyst applies or dismisses that tag."""
    if uids is None:
        con.execute("DELETE FROM tags")
        con.execute("DELETE FROM tag_suggestions")
        targets, where = list(state.tags), ""
    else:
        changed = id_table(con, "changed_tags", list(uids))
        con.execute(f"DELETE FROM tags WHERE event_uid IN (SELECT v FROM {changed})")
        con.execute(f"DELETE FROM tag_suggestions WHERE event_uid IN (SELECT v FROM {changed})")
        targets, where = [u for u in uids if u in state.tags], f" AND e.event_uid IN (SELECT v FROM {changed})"
    rows = [(u, key, info["seq"]) for u in targets for key, info in state.tags[u].items()]
    if rows:
        insert_columns(con, "tags", [r[0] for r in rows], [r[1] for r in rows], [tag_kind(r[1]) for r in rows],
                       [tag_label(r[1]) for r in rows], [tactic_order(r[1]) for r in rows], [r[2] for r in rows])
    # Hayabusa's fields are split, mapped, and screened in one statement: the Server 2022 case has 721,232
    # suggestions, and building them row by row in Python took 42 s.
    con.execute("CREATE OR REPLACE TEMP TABLE hayabusa_tactics (abbr VARCHAR, tag VARCHAR, label VARCHAR, ord INTEGER)")
    con.executemany("INSERT INTO hayabusa_tactics VALUES (?, ?, ?, ?)",
                    [(abbr, f"tactic:{tid}", name, i) for i, (tid, name, abbr) in enumerate(TACTICS)])
    # A rule's technique ID is suggested as the listed one it stands for, a revoked ID as its replacement, with the
    # revoked ID kept as the suggestion's origin; an ID the ATT&CK list doesn't hold isn't suggested, since the server
    # refuses it. A dismissal of the revoked ID, journaled before, still holds. A tag of the
    # revoked ID accepted before doesn't hold back its replacement: that tag shows flagged, and the suggestion beside it is
    # how the analyst swaps it for the current ID (accept the one, remove the other).
    con.execute("CREATE OR REPLACE TEMP TABLE attack_ids (id VARCHAR, listed VARCHAR)")
    insert_columns(con, "attack_ids", *map(list, zip(*sorted(attack.current().items()))))
    con.execute("CREATE OR REPLACE TEMP TABLE dismissed_tags (event_uid VARCHAR, tag VARCHAR)")
    if state.dismissed_tags:
        insert_columns(con, "dismissed_tags", *map(list, zip(*sorted(state.dismissed_tags))))
    sep = sql_literal(HAYABUSA_SEPARATOR)
    con.execute(f"""
        INSERT INTO tag_suggestions SELECT * FROM (
          WITH hit AS (
            SELECT DISTINCT e.event_uid, json_extract_string(h.extra, '$.MitreTactics') AS tac,
                   json_extract_string(h.extra, '$.MitreTags') AS tech
            FROM events h {hit_join("h", "e")}
            WHERE h.tool = 'hayabusa' AND (json_extract_string(h.extra, '$.MitreTactics') IS NOT NULL
                                           OR json_extract_string(h.extra, '$.MitreTags') IS NOT NULL){where}),
          tac AS (SELECT event_uid, trim(unnest(string_split(tac, {sep}))) AS abbr FROM hit WHERE tac IS NOT NULL),
          tech AS (SELECT event_uid, upper(trim(unnest(string_split(tech, {sep})))) AS id FROM hit WHERE tech IS NOT NULL),
          mapped AS (
            SELECT DISTINCT t.event_uid, a.listed, CASE WHEN a.id <> a.listed THEN a.id END AS origin
            FROM tech t JOIN attack_ids a ON a.id = t.id
            WHERE NOT EXISTS (SELECT 1 FROM dismissed_tags d WHERE d.event_uid = t.event_uid AND d.tag = 'technique:' || t.id)),
          cand AS (
            SELECT DISTINCT t.event_uid, m.tag, 'tactic' AS kind, m.label, m.ord, NULL AS origin
            FROM tac t JOIN hayabusa_tactics m USING (abbr)
            UNION
            SELECT event_uid, 'technique:' || listed, 'technique', listed, {len(TACTICS)},
                   string_agg(DISTINCT origin, ', ' ORDER BY origin) FROM mapped GROUP BY event_uid, listed)
          SELECT c.* FROM cand c
          WHERE NOT EXISTS (SELECT 1 FROM tags g WHERE g.event_uid = c.event_uid AND g.tag = c.tag)
            AND NOT EXISTS (SELECT 1 FROM dismissed_tags d WHERE d.event_uid = c.event_uid AND d.tag = c.tag)
          ORDER BY c.event_uid, c.tag)""")


HAYABUSA_SOURCE = "hayabusa"   # Hayabusa hits at medium level or above suggest Suspicious
# Suricata alerts at severity 1 or 2 suggest Suspicious; severity 3 stays searchable only.
SURICATA_SOURCE = "suricata"
# Imported Snort or Suricata fast alerts at priority 1 or 2 suggest Suspicious, like EVE alerts. Both programs write
# the rule's priority there; Suricata writes the same number (the rule's prio, in alert-fastlog.c and
# output-json-alert.c) as EVE's severity.
IDS_ALERT_SOURCE = "ids_alert"
# The journal keeps a source's ID in every rejection and accept note, so a built-in ID is fixed, and no analyst rule may
# take one: the two would share a source key.
BUILTIN_SOURCES = (HAYABUSA_SOURCE, SURICATA_SOURCE, IDS_ALERT_SOURCE)


def build_suggestions(con: duckdb.DuckDBPyConnection, state: State) -> dict[str, dict]:
    """Evaluate every rule, Hayabusa hit, Suricata alert, and imported fast alert into suggestions; return per-source
    counts and errors.

    `suggestions` holds one row per event and source. `suggested` holds, per event, the most severe
    suggestion the analyst has not rejected, which decides the event's lane until it is marked.
    """
    con.execute("CREATE OR REPLACE TABLE suggestions (event_uid VARCHAR, value VARCHAR, source VARCHAR)")
    report: dict[str, dict] = {}
    shadowed = []
    for rule_id, rule in sorted(state.rules.items()):
        if rule_id in BUILTIN_SOURCES:
            # Saved before the ID became a built-in source's: run, it would share the source key and double
            # that source's suggestions, so it waits for the analyst to rename it.
            shadowed.append(rule_id)
            continue
        try:
            parsed = parse(rule["text"])
        except RuleError as exc:
            report[rule_id] = {"error": str(exc), "builtin": rule["builtin"]}
            continue
        try:
            con.execute(
                f"INSERT INTO suggestions SELECT e.event_uid, ?, ? FROM events e "
                f"LEFT JOIN logon_links ls ON ls.event_uid = e.event_uid "
                f"WHERE e.tool <> 'hayabusa' AND {parsed.where}", [parsed.suggest, rule_id, *parsed.params])
        except duckdb.Error as exc:   # raised before the rule runs, which leaves the server's transaction open
            report[rule_id] = {"error": f"could not run: {exc}", "builtin": rule["builtin"]}
            continue
        report[rule_id] = {"suggest": parsed.suggest, "description": parsed.description, "builtin": rule["builtin"]}
    con.execute("INSERT INTO suggestions SELECT event_uid, 'suspicious', ? FROM hits WHERE max_level >= 3",
                [HAYABUSA_SOURCE])
    report.setdefault(HAYABUSA_SOURCE, {"suggest": "suspicious", "description": "Hayabusa hits at medium level or above",
                                        "builtin": True})
    con.execute("INSERT INTO suggestions SELECT event_uid, 'suspicious', ? FROM suricata_alerts "
                "WHERE severity BETWEEN 1 AND 2", [SURICATA_SOURCE])
    report.setdefault(SURICATA_SOURCE, {"suggest": "suspicious", "description": "Suricata alerts at severity 1 or 2",
                                        "builtin": True})
    con.execute("INSERT INTO suggestions SELECT event_uid, 'suspicious', ? FROM fast_alerts "
                "WHERE priority BETWEEN 1 AND 2", [IDS_ALERT_SOURCE])
    report.setdefault(IDS_ALERT_SOURCE, {"suggest": "suspicious",
                                         "description": "Imported Snort or Suricata fast alerts at priority 1 or 2",
                                         "builtin": True})
    for rule_id in shadowed:
        report[rule_id]["error"] = (f"The rule {rule_id} was not run: {rule_id} is now a built-in suggestion source. "
                                    "Remove the rule and add it again under another ID.")
    rebuild_suggested(con, state)
    for source, (matched, pending) in suggestion_counts(con).items():
        report.setdefault(source, {})
        report[source].update(matched=matched, pending=pending)
    for entry in report.values():
        entry.setdefault("matched", 0)
        entry.setdefault("pending", 0)
    return report


def suggestion_counts(con: duckdb.DuckDBPyConnection) -> dict[str, tuple[int, int]]:
    """Per source, the events it suggests and those still pending: neither marked nor rejected. To investigate and the
    Rules page read them live, since a mark changes them without building the suggestions again, so they
    can't come from the last build."""
    return {source: (matched, pending) for source, matched, pending in con.execute(
        "SELECT s.source, count(*), count(*) FILTER (WHERE m.event_uid IS NULL AND r.event_uid IS NULL) "
        "FROM suggestions s LEFT JOIN marks m ON m.event_uid = s.event_uid "
        "LEFT JOIN rejected r ON r.event_uid = s.event_uid AND r.source = s.source GROUP BY s.source").fetchall()}


def rebuild_suggested(con: duckdb.DuckDBPyConnection, state: State) -> None:
    con.execute("CREATE OR REPLACE TABLE rejected (event_uid VARCHAR, source VARCHAR)")
    if state.rejected:
        pairs = sorted(state.rejected)
        insert_columns(con, "rejected", [p[0] for p in pairs], [p[1] for p in pairs])
    con.execute("""
        CREATE OR REPLACE TABLE suggested AS
        SELECT s.event_uid,
               arg_max(s.value, CASE s.value WHEN 'malicious' THEN 3 WHEN 'suspicious' THEN 2 ELSE 1 END) AS value,
               list(DISTINCT s.source ORDER BY s.source) AS sources
        FROM suggestions s
        LEFT JOIN rejected r ON r.event_uid = s.event_uid AND r.source = s.source
        WHERE r.event_uid IS NULL
        GROUP BY s.event_uid""")


def replace_marks(con: duckdb.DuckDBPyConnection, state: State, uids: list[str] | None = None) -> None:
    """Rewrite all marks, or only the given event IDs, from the journal state."""
    if uids is None:
        con.execute("DELETE FROM marks")
        targets = list(state.marks)
    else:
        changed = id_table(con, "changed_marks", list(uids))
        con.execute(f"DELETE FROM marks WHERE event_uid IN (SELECT v FROM {changed})")
        targets = [u for u in uids if u in state.marks]
    if targets:
        insert_columns(con, "marks", targets, [MARK_LABELS[state.marks[u].value] for u in targets],
                       [state.marks[u].note for u in targets], [state.marks[u].seq for u in targets])


def orphan_marks(con: duckdb.DuckDBPyConnection) -> int:
    """Marks whose event ID doesn't exist, for example after a tool changed its record keys. Counted from the marks,
    so a case without marks reads no event."""
    return con.execute("SELECT count(*) FROM marks m ANTI JOIN events e ON e.event_uid = m.event_uid").fetchone()[0]


def _add(items: list[str], value: str) -> None:
    if value and value not in items:
        items.append(value)


def _ips(text: str) -> list[str]:
    """A registry value's addresses, in normalize_ip's form, which the parsers store."""
    out = []
    for part in re.split(r"[\s,;]+", text):
        ip = normalize_ip(part)
        if not ip:
            continue
        addr = ipaddress.ip_address(ip)
        if not (addr.is_unspecified or addr.is_loopback or addr.is_link_local):
            out.append(ip)
    return out
