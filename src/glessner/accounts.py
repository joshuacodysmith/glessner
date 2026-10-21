"""Names for accounts known only by their SID.

Some event log events give a user's SID as their account, with no name. Where an event's data names no account, the
EvtxECmd parser takes the SID from the event's System element and keeps it in extra as SecurityUserID
(parsers/evtxecmd.py); on a real host PowerShell's script block events (4104) are among them. Others record the SID
in their own data, such as AppReadiness's and AppModel-Runtime's User field. Either way one person read as two
accounts, CORP\\alice and S-1-5-21-...-1013. Each such SID takes the name the same host's 4624s
(TargetUserSid with TargetUserName and TargetDomainName) and 4672s (SubjectUserSid with SubjectUserName and
SubjectDomainName) record with it. A SID the host never names stays the SID.

A load that adds or removes event log rows, or 4624s and 4672s from any reader, ends with this lookup (events.load),
inside its transaction, for the hosts whose rows it changed. It reads the table as it stands and redoes those hosts'
earlier lookups, so the names depend on what is loaded, not on the order: a host's PowerShell run loaded before its
Security run is named once the Security run loads, and a rebuild gives the same names. Event IDs don't depend on the
account, so marks hold.

The name goes into user_name and user_domain, which every reader uses: lanes by account, the Same account pivot, rule
fields, the View filter, search, and the export's user.name. extra gains AccountLookedUp, a sentence naming the SID,
the name, and the events that gave it, so an analyst can tell a looked-up name from a recorded one (the Event page
shows it under the account), and AccountLookedUpSid, the SID, which the export writes as user.id and a user: search
for the SID still matches. The View filter, like the lanes, has the name.
"""

from __future__ import annotations

from collections.abc import Iterable

import duckdb

from .events import insert_columns, sql_literal
from .parsers.evtxecmd import ACCOUNT_SID

LOOKED_UP, SID_KEY = "AccountLookedUp", "AccountLookedUpSid"
# The events that record a SID with its name: the event ID, then the extra keys of the SID, the name, and the domain.
NAMING_EVENTS = (("4624", "TargetUserSid", "TargetUserName", "TargetDomainName"),
                 ("4672", "SubjectUserSid", "SubjectUserName", "SubjectDomainName"))
NAMING_CODES = frozenset(code for code, *_ in NAMING_EVENTS)
OTHER_NAMES = 3   # a renamed account's other names the marker lists, most frequent first
# The rows whose change can change a lookup: event log rows, which hold the SID-only accounts, and the naming events.
# A load of none, such as MFT, registry, or prefetch rows, skips the lookup; on the Szechuan dataset each lookup cost
# about 70 ms, and without this test a rebuild would run one for every host of every run. events.load makes the same
# test on each row it stages.
AFFECTS_SQL = f"artifact = 'evtx' OR event_code IN ({', '.join(sql_literal(c) for c in sorted(NAMING_CODES))})"
# The SID a looked-up account was named from, over events as e. The JSON is read only on rows that carry the key.
SID_SQL = f"CASE WHEN contains(e.extra, '\"{SID_KEY}\"') THEN json_extract_string(e.extra, '$.{SID_KEY}') END"


def key_sql(name: str, domain: str) -> str:
    """The account key: one SQL expression over the name and
    domain expressions given, the account in one form, '' when there is none. Both are trimmed, and a domain of "-" is
    none, as Windows writes an empty one. A name holding a backslash with no domain is split at the last backslash, as
    imports.split_account splits it. A name holding @ is split at the last @ when the part after it is a realm, dotted
    letters, digits, and hyphens and not an address, and the event's own domain, when it has one, wins over the realm,
    since a UPN suffix can be an alternate one. Zeek's name/REALM, with no domain and no @, is split at the last / the
    same way. The key is domain\\name in lower case, or the name alone. The load, accounts.name_sids, and the case
    format 3 step's fill all use this one expression, so they can't differ; a test holds it to
    split_account. DuckDB's expressions are RE2's, with no lookahead, so the realm test is two matches."""
    n = f"trim(COALESCE({name}, ''))"
    d = f"(CASE WHEN trim(COALESCE({domain}, '')) = '-' THEN '' ELSE trim(COALESCE({domain}, '')) END)"

    def before(sep: str) -> str:   # up to the last `sep`; (?s) so a line break in a name is text like any other
        return f"regexp_extract({n}, '(?s)^(.*){sep}[^{sep}]*$', 1)"

    def after(sep: str) -> str:
        return f"regexp_extract({n}, '{sep}([^{sep}]*)$', 1)"

    def realm(text: str) -> str:
        return (f"(regexp_full_match({text}, '[A-Za-z0-9-]+(\\.[A-Za-z0-9-]+)+') "
                f"AND NOT regexp_full_match({text}, '[0-9.]+'))")

    def key(dom: str, nm: str) -> str:
        return f"(CASE WHEN {dom} = '' THEN lower({nm}) ELSE lower({dom}) || '\\' || lower({nm}) END)"

    bs = "\\\\"   # RE2's escaped backslash
    upn_domain = f"(CASE WHEN {d} <> '' THEN {d} ELSE {after('@')} END)"
    return (f"(CASE WHEN {n} = '' THEN '' "
            f"WHEN {d} = '' AND contains({n}, '\\') THEN {key(before(bs), after(bs))} "
            f"WHEN contains({n}, '@') AND {before('@')} <> '' AND {realm(after('@'))} THEN {key(upn_domain, before('@'))} "
            f"WHEN {d} = '' AND NOT contains({n}, '@') AND contains({n}, '/') AND {before('/')} <> '' "
            f"AND {realm(after('/'))} THEN {key(after('/'), before('/'))} "
            f"ELSE {key(d, n)} END)")


def is_sid(value: str) -> bool:
    """Whether a search or View value is a SID, which then also matches the accounts looked up from it."""
    return value[:4].lower() == "s-1-"


def name_sids(con: duckdb.DuckDBPyConnection, hosts: Iterable[str]) -> int:
    """Name the SID-only accounts of these hosts' events from each host's own 4624s and 4672s, and undo an earlier
    lookup the host's events no longer support. Returns how many events changed. Runs in the caller's transaction.

    A SID with several names on a host, as a renamed account has, takes the one most of those events record; a tie goes
    to the name recorded latest, then to the first in sort order, so a rebuild always chooses the same."""
    hosts = sorted(set(hosts))
    if not hosts:
        return 0
    host_list = ", ".join(sql_literal(h) for h in hosts)   # a load changes a few hosts at most
    # Event log rows whose account is a user's SID with no domain, whether the parser took it from the System element
    # (SecurityUserID) or the event's data gave it, and those an earlier lookup named. The column tests go first, so
    # only event log rows' extra is read and only the few rows left parse JSON. On the Szechuan dataset's DC01 (597,000
    # events), reading every row's extra took 40 ms; event log rows only, 11 ms.
    con.execute(f"""
        CREATE OR REPLACE TEMP TABLE sid_accounts AS
        SELECT * FROM (
            SELECT rowid AS rid, host, user_name, user_domain,
                   COALESCE(json_extract_string(extra, '$.{SID_KEY}'), user_name) AS sid,
                   json_extract_string(extra, '$.{LOOKED_UP}') AS looked_up
            FROM events
            WHERE host IN ({host_list}) AND artifact = 'evtx'
              AND ((COALESCE(user_domain, '') = ''
                    AND (starts_with(user_name, 'S-1-5-21-') OR starts_with(user_name, 'S-1-12-1-')))
                   OR contains(extra, '"{SID_KEY}"')))
        WHERE looked_up IS NOT NULL OR regexp_full_match(sid, {sql_literal(ACCOUNT_SID.pattern)})""")
    if con.execute("SELECT count(*) FROM sid_accounts").fetchone()[0] == 0:   # hosts with no account known by SID
        con.execute("DROP TABLE sid_accounts")
        return 0
    naming = " UNION ALL ".join(
        f"SELECT host, ts_us, '{code}' AS code, "
        f"json_extract_string(extra, ['$.{sid}', '$.{name}', '$.{domain}']) AS f FROM events "
        f"WHERE event_code = '{code}' AND host IN ({host_list}) AND contains(extra, '\"{sid}\"')"
        for code, sid, name, domain in NAMING_EVENTS)
    # One row per host and SID with its chosen name and the marker. Windows writes "-" for an empty name or domain.
    con.execute(f"""
        CREATE OR REPLACE TEMP TABLE sid_names AS
        WITH wanted AS (SELECT DISTINCT host, sid FROM sid_accounts),
        named AS (
            SELECT n.host, n.ts_us, n.code, n.f[1] AS sid, trim(n.f[2]) AS name,
                   CASE WHEN trim(COALESCE(n.f[3], '')) = '-' THEN '' ELSE trim(COALESCE(n.f[3], '')) END AS domain
            FROM ({naming}) n JOIN wanted w ON w.host = n.host AND w.sid = n.f[1]
            WHERE trim(COALESCE(n.f[2], '')) NOT IN ('', '-')),
        counted AS (
            SELECT host, sid, name, domain, count(*) AS n, max(ts_us) AS last_us,
                   array_to_string(list_sort(list_distinct(list(code))), ' and ') AS codes,
                   CASE WHEN domain = '' THEN name ELSE domain || '\\' || name END AS account
            FROM named GROUP BY host, sid, name, domain),
        ranked AS (
            SELECT *, row_number() OVER (PARTITION BY host, sid
                                         ORDER BY n DESC, last_us DESC NULLS LAST, name, domain) AS rank
            FROM counted)
        SELECT host, sid,
               any_value(name) FILTER (WHERE rank = 1) AS name,
               any_value(domain) FILTER (WHERE rank = 1) AS domain,
               sid || ' is ' || any_value(account) FILTER (WHERE rank = 1) || ' in '
                   || any_value(n) FILTER (WHERE rank = 1) || ' of this host''s '
                   || any_value(codes) FILTER (WHERE rank = 1) || ' events'
                   || COALESCE(', ' || string_agg(account || ' in ' || n, ', ' ORDER BY rank)
                                       FILTER (WHERE rank BETWEEN 2 AND {1 + OTHER_NAMES}), '')
                   || CASE WHEN count(*) > {1 + OTHER_NAMES}
                           THEN ', and ' || (count(*) - {1 + OTHER_NAMES}) || ' more names' ELSE '' END AS marker
        FROM ranked GROUP BY host, sid""")
    # Only rows whose account or marker changes are written, so a load that names nothing new writes nothing. The
    # update joins on every row's rowid, 13 ms on the Szechuan dataset's DC01 even with nothing to write, so it runs only when
    # there is something to write.
    con.execute("""
        CREATE OR REPLACE TEMP TABLE sid_changes AS
        SELECT a.rid, a.sid, COALESCE(s.name, a.sid) AS name, COALESCE(s.domain, '') AS domain, s.marker
        FROM sid_accounts a LEFT JOIN sid_names s ON s.host = a.host AND s.sid = a.sid
        WHERE a.user_name IS DISTINCT FROM COALESCE(s.name, a.sid)
           OR COALESCE(a.user_domain, '') <> COALESCE(s.domain, '') OR a.looked_up IS DISTINCT FROM s.marker""")
    changed = con.execute("SELECT count(*) FROM sid_changes").fetchone()[0]
    if changed:
        # Both keys come and go together: a name the host no longer supports leaves the event as the parser wrote it.
        # The account key follows the name, in the same transaction (case format 3).
        con.execute(f"""
            UPDATE events SET user_name = c.name, user_domain = c.domain, account_key = {key_sql('c.name', 'c.domain')},
                   extra = CASE WHEN c.marker IS NULL
                                THEN json_merge_patch(COALESCE(events.extra, '{{}}'),
                                                      '{{"{LOOKED_UP}": null, "{SID_KEY}": null}}')
                                ELSE json_merge_patch(COALESCE(events.extra, '{{}}'),
                                                      json_object('{LOOKED_UP}', c.marker, '{SID_KEY}', c.sid)) END
            FROM sid_changes c WHERE events.rowid = c.rid""")
    for table in ("sid_accounts", "sid_names", "sid_changes"):
        con.execute(f"DROP TABLE {table}")
    return changed


# The events that give a domain's spelling with an account's SID, for the fold: the naming events, and 4768, whose
# TargetDomainName is the Kerberos spelling (the event ID, then the extra keys of the SID and the domain)
FOLD_EVENTS = (*((code, sid, domain) for code, sid, _, domain in NAMING_EVENTS), ("4768", "TargetSid", "TargetDomainName"))
DOMAIN_SID = r"^(S-1-5-21-[0-9]+-[0-9]+-[0-9]+)-[0-9]+$"   # an account's SID in a domain or on a machine, less its RID


def build_account_domains(con: duckdb.DuckDBPyConnection) -> None:
    """The derived table account_domains (spelling, domain, basis): the spellings of one domain, folded to one, for Same
    account (queries._account). Built with the other derived tables at each open and after
    each load, split, and import, as short_paths is, so a fold learned from a later load reaches every row, while each
    stored account key stays a function of its own row.

    Spellings, in lower case, that the naming events record with accounts of one domain SID are one domain (basis
    "sid"): on Szechuan, 4624's TargetUserSid appears under both C137 and C137.LOCAL, while DESKTOP-SDN1RPT's local
    Administrator has its machine's own SID and stays apart. Else a dotted spelling with no SID of its own folds into
    the dotless spelling equal to its first label, when the case has one (basis "label"): the guidance marks this as
    inference, which fails where the NetBIOS name differs from the first DNS label, as a missed fold, never a false
    one. Each group folds to its dotless spelling, else its first in sort order, so the table is the same however the
    tools loaded. Only spellings of a group of two or more are listed. A label fold joins only a spelling with no SID
    of its own, so two spellings of a group are one domain by their SIDs exactly when both have basis "sid"."""
    evidence = " UNION ALL ".join(
        f"SELECT lower(trim(json_extract_string(extra, '$.{domain}'))) AS spelling, "
        f"upper(trim(json_extract_string(extra, '$.{sid}'))) AS sid FROM events "
        f"WHERE event_code = '{code}' AND contains(extra, '\"{sid}\"')"
        for code, sid, domain in FOLD_EVENTS)
    seen = con.execute(f"SELECT DISTINCT spelling, regexp_extract(sid, '{DOMAIN_SID}', 1) FROM ({evidence}) "
                       f"WHERE spelling NOT IN ('', '-') AND regexp_full_match(sid, '{DOMAIN_SID[1:-1]}')").fetchall()
    keyed = {s for (s,) in con.execute("SELECT DISTINCT split_part(account_key, '\\', 1) FROM events "
                                       "WHERE contains(account_key, '\\')").fetchall()}
    parent: dict[str, str] = {}

    def root(s: str) -> str:
        while parent.setdefault(s, s) != s:
            s = parent[s]
        return s

    def join(a: str, b: str) -> None:
        parent[root(a)] = root(b)

    by_sid: dict[str, str] = {}
    for spelling, domain_sid in sorted(seen):
        join(spelling, by_sid.setdefault(domain_sid, spelling))
    with_sid = {s for s, _ in seen}
    spellings = keyed | with_sid
    for spelling in sorted(spellings - with_sid):
        first = spelling.split(".", 1)[0]
        if "." in spelling and first in spellings:
            join(spelling, first)
    groups: dict[str, list[str]] = {}
    for spelling in parent:
        groups.setdefault(root(spelling), []).append(spelling)
    rows = []
    for members in groups.values():
        if len(members) < 2:
            continue
        target = min((s for s in members if "." not in s), default=min(members))
        rows += [(s, target, "sid" if s in with_sid else "label") for s in sorted(members)]
    con.execute("CREATE OR REPLACE TABLE account_domains (spelling VARCHAR, domain VARCHAR, basis VARCHAR)")
    if rows:
        insert_columns(con, "account_domains", *zip(*rows, strict=True))
