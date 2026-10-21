"""Cross-host logon links between collected hosts, and from sources outside the case.

4624 type 3 and type 10 logons draw from the logon's source to the host that recorded it. The
source resolves by IP first, because a 4624's WorkstationName is unreliable: type 10 logons
often record the target's own name there, and Kerberos network logons leave it blank. 4648
(explicit credentials) draws from the host that recorded it to its TargetServerName.

Every logon in the case is resolved once per host identity's lookup of names and addresses, into the derived table
logon_links. The timeline reads a window's links from it with their clock-adjusted times and lanes (queries.view_links),
rules read a logon's source_host from it, and the outside sources lane lists its outside sources. A domain controller's
Security log can hold hundreds of thousands of logons from a few hundred sources, so each distinct address and name is
resolved through the identity in Python, and the logons are joined to them in SQL. Resolving every logon in Python
would cost about 8.5 µs a logon on every view, links shown or not.
"""

from __future__ import annotations

import ipaddress

import duckdb

from .events import insert_columns
from .identity import Identity

# The logons that can draw a link, from EvtxECmd or the event XML reader. One without a time is on no timeline.
LOGON_WHERE = ("e.artifact = 'evtx' AND e.ts_us IS NOT NULL "
               "AND ((e.event_code = '4624' AND e.logon_type IN ('3', '10')) OR e.event_code = '4648')")
LINKS_SQL = """
    CREATE OR REPLACE TABLE logon_links AS
    WITH r AS (
        SELECT *, CASE WHEN user_domain <> '' THEN user_domain || '\\' || user_name ELSE user_name END AS account,
               ends_with(user_name, '$') AS machine
        FROM logon_rows),
    -- 4648: from the host that recorded it to its TargetServerName
    explicit AS (
        SELECT r.event_uid, r.host AS source_host, n.host AS target_host, false AS outside, r.account, r.machine,
               '4648 explicit credentials' AS kind, 'recorded host' AS via, r.ts_us
        FROM r JOIN logon_names n ON n.name = r.target_server
        WHERE r.event_code = '4648' AND n.host <> r.host),
    -- 4624: from its source, by IP first and by WorkstationName when there's none; a source outside the case is its IP,
    -- when that's a real address. A host logging on to itself draws nothing.
    logons AS (
        SELECT r.event_uid, COALESCE(i.host, n.host, r.source_ip) AS source_host, r.host AS target_host,
               i.host IS NULL AND n.host IS NULL AS outside, r.account, r.machine, '4624 type ' || r.logon_type AS kind,
               CASE WHEN r.source_ip <> '' THEN 'ip' ELSE 'name' END AS via, r.ts_us
        FROM r LEFT JOIN logon_ips i ON i.ip = r.source_ip
             LEFT JOIN logon_names n ON r.source_ip = '' AND n.name = r.source_workstation
        WHERE r.event_code = '4624' AND (i.host IS NOT NULL OR n.host IS NOT NULL OR i.remote)
          AND COALESCE(i.host, n.host, '') <> r.host)
    SELECT * FROM explicit UNION ALL SELECT * FROM logons"""


def build_logon_links(con: duckdb.DuckDBPyConnection, identity: Identity, cache: dict | None = None) -> None:
    """Resolve every cross-host logon into the table logon_links: the event, its source and target hosts, whether the
    source is outside the case (its IP is then the source), the account, whether that's a machine account (ending in
    $), the kind, such as "4624 type 10", what resolved the source: "ip", "name", or "recorded host", and the event's
    recorded time, ts_us. A view reads that copy to pass over a window without links before it reads any event; the
    link's clock-adjusted time still comes from the event, through queries.TS and its join.

    The links read only the events and identity.lookup, through resolve_ip and resolve_name. Given a `cache`, the
    lookup they were built from is kept there, and while it's the same the table stays as it is, so an offset, role, or
    confirm edit, or an alignment, doesn't build it again. The caller empties the cache when events load or a rebuild
    fails. On a synthetic case of 1 million events, keeping the table took an offset edit's rebuild, commit included,
    from a median of 2.53 s to 0.84 s."""
    if cache is not None and cache.get("links_lookup") == identity.lookup:
        return
    con.execute(f"""
        CREATE OR REPLACE TEMP TABLE logon_rows AS
        SELECT e.event_uid, e.ts_us, e.host, e.event_code, e.logon_type, COALESCE(e.user_domain, '') AS user_domain,
               COALESCE(e.user_name, '') AS user_name, COALESCE(e.source_ip, '') AS source_ip,
               COALESCE(e.source_workstation, '') AS source_workstation,
               CASE WHEN e.event_code = '4648'
                    THEN json_extract_string(NULLIF(e.extra, ''), '$.TargetServerName') END AS target_server
        FROM events e WHERE {LOGON_WHERE}""")
    ips = [ip for (ip,) in con.execute(
        "SELECT DISTINCT source_ip FROM logon_rows WHERE event_code = '4624' AND source_ip <> ''").fetchall()]
    names = [name for (name,) in con.execute(
        "SELECT source_workstation FROM logon_rows WHERE event_code = '4624' AND source_ip = '' "
        "UNION SELECT target_server FROM logon_rows WHERE target_server IS NOT NULL").fetchall()]
    con.execute("CREATE OR REPLACE TEMP TABLE logon_ips (ip VARCHAR, host VARCHAR, remote BOOLEAN)")
    insert_columns(con, "logon_ips", ips, map(identity.resolve_ip, ips), map(is_remote, ips))
    con.execute("CREATE OR REPLACE TEMP TABLE logon_names (name VARCHAR, host VARCHAR)")
    insert_columns(con, "logon_names", names, map(identity.resolve_name, names))
    con.execute(LINKS_SQL)
    for table in ("logon_rows", "logon_ips", "logon_names"):
        con.execute(f"DROP TABLE {table}")
    if cache is not None:
        cache["links_lookup"] = dict(identity.lookup)


def outside_sources(con: duckdb.DuckDBPyConnection) -> list[str]:
    """Every outside source IP across the whole case, so its lane exists before the analyst zooms in."""
    return [ip for (ip,) in con.execute(
        "SELECT DISTINCT source_host FROM logon_links WHERE outside ORDER BY source_host").fetchall()]


def is_remote(ip: str) -> bool:
    """True for a real source address: not empty, loopback, link-local, or unspecified."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_loopback or addr.is_link_local or addr.is_unspecified)


def is_local(ip: str) -> bool:
    """True for a real address that is loopback, link-local, or unspecified: one every host has for itself, so a pivot on
    it stays within the seed's host. False for anything that isn't an address."""
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not is_remote(ip)
