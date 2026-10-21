"""Search: find events by text across all their fields.

Syntax, one term per word, all of which must match:
  word          the word anywhere in the event, any letter case; * stands for any text
  "nmap"        the word alone, any letter case: letters a to z, digits, and underscore on either side of it end no match,
                so "nmap" finds nmap.exe and not WinMaps. A side that ends in another character (".dll") has no bound
  "a phrase"    the words together as written, as whole words, any letter case
  field:value   a whole field value, any letter case in every field, * for any text: ip:10.42.85.10, user:*admin*,
                code:4624. A field the app doesn't name is the event's own data field: ProcessName:*\\cmd.exe.
                addr:10.0.2.17 is an address at either end, the events ip: or dst: would find. An address
                matches in normalize_ip's form, shortened: type IPv6 as fe80::1 (letter case doesn't matter)
  path:value    a full path matches the file's other forms by its file key, as Same file does (MFT, Prefetch, event logs; the
                volume and letter case ignored), and the process's path on an event that names no file. A value with * or a
                bare name compares the path as written
  rule:title    a Hayabusa rule's title: the events the rule hit (kept out of the View; it reads the hits table)
  -term         excludes events that match the term

A search's matches are saved once in the search_hits table under an ID made from the query and MEANING, so the View
can show them on every pan and zoom without searching again. search_runs records each saved search. Both tables are
derived data, like hits and marks, and a rebuild drops them. The server drops them too whenever events load and when a
case opens, and saves a View's search again before each use, so neither a search repeated after a load nor a View
holding one returns the matches of an older timeline.

A search writes its matches on a reader, outside the server's lock, under a staging ID, so marks and notes don't wait
behind it, and takes the lock only to give them the search's ID (server.App.save_search).

Results also say where the matches are: how many fall in each of BUCKETS stretches of time, the
shortest stretch holding half of them, every match's ID for the timeline to mark, and for each listed event the
field a word or phrase was found in, when that isn't the shown start of the message.
"""

from __future__ import annotations

import functools
import hashlib
import json
import math
import re
import secrets
import string
from collections import Counter
from dataclasses import dataclass, replace

import duckdb

from .accounts import SID_SQL, is_sid
from .analysis import level_rank
from .events import sql_literal
from .parsers.common import file_key
from .queries import BASE_FROM, BASE_WHERE, EITHER_END, FIELDS, LISTED_MESSAGE, MARK_EXPR, TIME_FROM, TS, mark_counts

MAX_QUERY = 500
JOURNAL_FIELDS = {"mark", "role", "tag", "tactic"}   # filter fields the journal changes, which saved matches would get wrong
MAX_TERMS = 20
KEEP = 50   # searches whose matches stay saved; the least recently used are dropped
SEARCH_ONLY = {"rule"}   # fields search reads and the View's filter doesn't (filters.normalize_pred refuses them)
ALIASES = {"rule_title": "rule", "account": "user", "id": "code", "eventid": "code", "cmd": "command_line",
           "commandline": "command_line",
           "key": "registry_key", "workstation_name": "workstation", "src": "ip", "src_ip": "ip", "source_ip": "ip",
           "sport": "port", "src_port": "port", "dst": "dest_ip", "dst_ip": "dest_ip", "dport": "dest_port",
           "dst_port": "dest_port", "parent_process": "parent", "parent_cmd": "parent_command_line"}
# The text a word or phrase is looked for in: every text field the app reads, and the event's own data.
SEARCHED = (("message", "Message"), ("user_domain", "Domain"), ("user_name", "Account"), ("source_ip", "Source IP"),
            ("source_port", "Source port"), ("dest_ip", "Destination IP"), ("dest_port", "Destination port"),
            ("source_workstation", "Source workstation"), ("process_executable", "Process"),
            ("process_command_line", "Command line"), ("process_parent_executable", "Parent process"),
            ("process_parent_command_line", "Parent command line"), ("file_path", "File"),
            ("registry_path", "Registry key"), ("registry_value", "Registry value"), ("registry_data", "Registry data"),
            ("host", "Host"), ("event_code", "Event code"),
            ("event_provider", "Provider"), ("log_channel", "Channel"), ("host_name_recorded", "Computer"))
HAYSTACK = "concat_ws(' ', " + ", ".join(f"e.{c}" for c, _ in SEARCHED) + ", e.extra)"
BUCKETS = 60         # stretches of time in a search's match strip
MARKED = 20_000      # matches the timeline marks; more would make the response slow to send
SHOWN_MESSAGE = 160  # the start of the message each listed event shows
EXCERPT = 60         # characters either side of a match in a "found in" excerpt
# Part of every search ID. Raised when a term changes meaning, so a search saved under the old meaning runs again
# rather than returning its old matches. From 2, addr: is an address at either end, where it was the event data field
# addr. From 3, a quoted value's inner spaces count: a search saved under its collapsed text, such as the two-space
# path:"C:\Program  Files", would otherwise answer the one-space search that has its ID. From 4, path: compares a full
# path by its file key: a search saved under the raw path would return only the events that spelled it the same way.
# From 5, every field term compares without case; under 4, host:desktop found nothing, so a search saved under 4 would
# return its nothing. From 6, a quoted word or phrase matches whole words, so "nmap" doesn't find WinMaps, and rule: is
# a search field of its own, where it read the event data field rule.
MEANING = 6
VALUE = "view value "   # the start of a View data value's key (value_key)
STAGED = "staged "      # the start of matches' ID until they're saved (stage_matches); a search ID has no space
TOKEN = re.compile(r'\s*(-)?(?:([A-Za-z_][\w.]{1,80}):)?(?:"([^"]*)"|(\S+))')
WORD = frozenset(string.ascii_letters + string.digits + "_")   # what joins a word: ASCII only, as RE2's boundary


class SearchError(ValueError):
    """A search that can't run, with a message for the analyst."""


@dataclass(frozen=True)
class Term:
    negate: bool
    field: str      # '' for text anywhere
    value: str
    phrase: bool    # quoted

    @property
    def bounded(self) -> bool:
        """Whether the term matches whole words: free text in quotes. A field term's quotes only hold
        spaces, and the field compares its whole value."""
        return self.phrase and not self.field

    def describe(self) -> str:
        if self.field == "rule":   # the page reads "Looking for events hit by ...", so a rule's words are a whole phrase
            return f'events {"not " if self.negate else ""}hit by the Hayabusa rule "{self.value}"'
        what = (f'IP "{self.value}" at either end' if self.field in EITHER_END else
                f'{self.field} is "{self.value}"' if self.field else
                (f'the words "{self.value}" as whole words' if re.search(r"\s", self.value)
                 else f'the whole word "{self.value}"') if self.bounded else f'"{self.value}" anywhere')
        return f"not {what}" if self.negate else what


def parse(query: str) -> list[Term]:
    query = (query or "").strip()
    if not query:
        raise SearchError("Type something to search for.")
    if len(query) > MAX_QUERY:
        raise SearchError(f"A search can be at most {MAX_QUERY} characters.")
    terms = []
    for m in TOKEN.finditer(query):
        negate, field, quoted, bare = m.group(1) == "-", m.group(2) or "", m.group(3), m.group(4)
        value = quoted if quoted is not None else (bare or "")
        if not value:
            continue
        if field:
            field = ALIASES.get(field.lower(), field)
            if field.lower() in JOURNAL_FIELDS:
                raise SearchError(f"Search saves its matches, and {field.lower()}s change as you work, so it leaves them "
                                  "to the View filter: tick them there, or choose them as lanes.")
            if field.lower() in FIELDS or field.lower() in EITHER_END or field.lower() in SEARCH_ONLY:
                field = field.lower()
            elif not field.startswith("data."):
                field = f"data.{field}"   # the event's own data, by name
            if '"' in field or "\\" in field:
                raise SearchError(f"A field name can't hold a quote or backslash: {field}")
        terms.append(Term(negate, field, value, quoted is not None))
    if not terms:
        raise SearchError("Type something to search for.")
    if len(terms) > MAX_TERMS:
        raise SearchError(f"A search can have at most {MAX_TERMS} terms.")
    if all(t.negate for t in terms):
        raise SearchError("A search needs at least one term that isn't excluded.")
    return terms


def _like(value: str, anywhere: bool) -> str:
    """LIKE and a value's pattern in lower case, with * as the wildcard and LIKE's own wildcards taken literally. ESCAPE
    is given only when the pattern escapes something: with it, DuckDB 1.5.6 takes no fast path. A word in HAYSTACK took
    3.8 s to find at 5.2 million events with ILIKE, and 2.3 s with lower() and LIKE."""
    escaped = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_").replace("*", "%")
    pattern = f"%{escaped}%" if anywhere else escaped
    return f"LIKE lower({sql_literal(pattern)})" + (" ESCAPE '\\'" if "\\" in pattern else "")


def account_exprs(value: str) -> list[str]:
    """What a user: value is compared with: DOMAIN\\name as the event wrote it, the bare name, so user:administrator needs no
    domain, and for a SID the accounts looked up from it, so a SID taken from a ProfileList key or a Recycle Bin folder still
    finds the user's events once the host's logons name it. The View's user value reads the same
    (filters.py), so the two can't drift. An imported log's account is split into domain and name
    (imports.split_account), so a value written as the log wrote it, alice@example.com or alice/EXAMPLE.COM, is compared with
    the parts joined that way too."""
    exprs = [FIELDS["user"], "e.user_name"]
    if "\\" not in value:
        if "@" in value:
            exprs.append("e.user_name || '@' || e.user_domain")
        if "/" in value:
            exprs.append("e.user_name || '/' || e.user_domain")
    return exprs + ([SID_SQL] if is_sid(value) else [])


def bounded_pattern(value: str) -> str:
    """A quoted word's or phrase's pattern for RE2, DuckDB's engine: the value as written, * for any text, and \\b at an
    end that is an ASCII word character (letter, digit, underscore), so "nmap" doesn't match inside WinMaps and ".dll"
    still matches inside WinMaps.dll. RE2's \\b is ASCII only, as the lookarounds the highlights use (wildcard_span)."""
    body = "".join(".*" if c == "*" else "\\" + c if c in "\\.+?()|[]{}^$" else c for c in value)
    left = "\\b" if value[:1] in WORD else ""
    right = "\\b" if value[-1:] in WORD else ""
    return left + body + right


def text_sql(t: Term, expr: str) -> str:
    """The condition that a free-text term (a word, or a quoted word or phrase) is found in the text `expr`, by the term's own
    meaning. `expr` is HAYSTACK for a search, and a rule title or a tag's label for the hint that names what free text skips."""
    if t.bounded:   # 's' lets * cross a line break; no lower() or LIKE, both measured slower
        return f"regexp_matches({expr}, {sql_literal(bounded_pattern(t.value))}, 'is')"
    return f"lower({expr}) {_like(t.value, True)}"   # as ILIKE, which lowers both sides


def term_sql(t: Term) -> str:
    if t.field == "rule":   # a Hayabusa rule's title: the events the rule hit, as Same rule lists them (queries.rule_branches)
        like = _like(t.value, False) if "*" in t.value else f"= lower({sql_literal(t.value)})"
        cond = ("e.event_uid IN (SELECT event_uid FROM (SELECT event_uid, unnest(titles) AS t FROM hits) "
                f"WHERE lower(t) {like})")
    elif not t.field:
        cond = text_sql(t, HAYSTACK)
    else:
        if t.field in EITHER_END:   # addr: compares either column as ip: and dst: compare one
            exprs = list(EITHER_END[t.field])
        elif t.field.startswith("data."):
            path = '$."' + t.field[5:] + '"'
            exprs = [f"json_extract_string(NULLIF(e.extra, ''), {sql_literal(path)})"]
        else:
            exprs = account_exprs(t.value) if t.field == "user" else [FIELDS[t.field]]
        if t.field == "path" and "*" not in t.value and file_key(t.value):
            # A full path is the file's key, which Same file compares: the MFT's .\Windows\x and Prefetch's \VOLUME{...} forms
            # meet the event log's C:\Windows\x. An event that names no file has its process's key.
            cond = f"e.file_key = {sql_literal(file_key(t.value))}"
        elif "*" in t.value:
            cond = " OR ".join(f"lower({x}) {_like(t.value, False)}" for x in exprs)
        else:   # every field compares without case; lower() cost 3 to 6 ms over a plain = at 5.2 million events
            cond = " OR ".join(f"lower({x}) = lower({sql_literal(t.value)})" for x in exprs)
    return f"NOT COALESCE({cond}, false)" if t.negate else f"COALESCE({cond}, false)"


def normalize_query(query: str) -> str:
    """The query as its search ID, search_runs, and the page's View read it: its terms as parse reads them, one space
    apart. A quoted value keeps its own spaces and tabs, which it compares as written; collapsing them would give
    path:"C:\\Program  Files" the ID, the saved matches, and the query text of path:"C:\\Program Files"."""
    return " ".join(m.group(0).strip() for m in TOKEN.finditer((query or "").strip()))


def whole_word(query: str) -> dict | None:
    """What the page's Whole word tick does to a query, built from the same TOKEN matches parse reads, so the page has no
    tokenizer of its own: `state` is "all", "some", or "none" of the free-text terms in quotes, `on` the query with each bare
    word quoted, `off` the query with each quoted word unquoted. A phrase with spaces stays quoted, as does a value that
    would read as a field or an exclusion bare, and a bare word holding a quote is left alone. None without a free-text
    term."""
    on, off, quoted, bare = [], [], 0, 0
    for m in TOKEN.finditer((query or "").strip()):
        text, minus, field, inside, word = m.group(0).strip(), m.group(1) or "", m.group(2), m.group(3), m.group(4)
        on.append(text)
        off.append(text)
        if field or (word is None and not inside) or (word is not None and '"' in word):
            continue
        if word is not None:
            bare += 1
            on[-1] = f'{minus}"{word}"'
        else:
            quoted += 1
            if _bare_word(inside):
                off[-1] = f"{minus}{inside}"
    if not quoted + bare:
        return None
    return {"state": "all" if not bare else "none" if not quoted else "some", "on": " ".join(on), "off": " ".join(off)}


def _bare_word(value: str) -> bool:
    """Whether `value` typed without quotes is read as the one free-text word it is, not as a field or an exclusion."""
    plain = TOKEN.fullmatch(value)
    return bool(plain) and not (plain.group(1) or plain.group(2)) and plain.group(4) == value


def swap_term(query: str, index: int, text: str) -> str:
    """The query with its `index`th term, counted as parse counts them, replaced by `text`; the other terms stay as
    written, one space apart. The forgiving line and the hints make their links from it."""
    out, n = [], 0
    for m in TOKEN.finditer((query or "").strip()):
        piece = m.group(0).strip()
        if m.group(3) if m.group(3) is not None else m.group(4):   # an empty value is no term (parse)
            if n == index:
                piece = text
            n += 1
        out.append(piece)
    return " ".join(out)


def forgiving_term(terms: list[Term]) -> int | None:
    """The index of the first quoted word the forgiving line can show what the search without its quotes adds for: a positive
    free-text term with no * and no space, which the same word typed bare reads as. None when there is none."""
    for i, t in enumerate(terms):
        if t.bounded and not t.negate and "*" not in t.value and not re.search(r"\s", t.value) and _bare_word(t.value):
            return i
    return None


def _re2_literal(value: str) -> str:
    return "".join("\\" + c if c in "\\.+*?()|[]{}^$" else c for c in value)


ADDS_GROUPS = 10   # words the forgiving line names


def search_adds(con: duckdb.DuckDBPyConnection, query: str) -> dict:
    """What a quoted word's search would add without its quotes: in one scan, the events the forgiving
    search finds, how many of them hold the word only inside other words, and those words by the events they sit in, the
    ADDS_GROUPS largest, each with the search for it. An event holding two words counts in both, so the groups can sum past
    `inside`. The scan finds "inside" directly: RE2's i option folds a letter that lower() doesn't. Nothing is saved."""
    terms = parse(query)
    i = forgiving_term(terms)
    if i is None:
        raise SearchError('The forgiving search needs a word in quotes with no space or *, such as "nmap".')
    t = terms[i]
    loose = search_sql([*terms[:i], replace(t, phrase=False), *terms[i + 1:]])
    pattern = sql_literal(bounded_pattern(t.value))
    grab = sql_literal("[a-z0-9_]*" + _re2_literal(t.value) + "[a-z0-9_]*")
    total, inside, words, groups = con.execute(f"""
        WITH m AS MATERIALIZED (SELECT e.event_uid, {HAYSTACK} AS h FROM events e WHERE {BASE_WHERE} AND {loose}),
        inner_hits AS MATERIALIZED (SELECT event_uid, h FROM m
                                    WHERE NOT COALESCE(regexp_matches(h, {pattern}, 'is'), false)),
        found AS (SELECT DISTINCT event_uid, unnest(regexp_extract_all(h, {grab}, 0, 'i')) AS w FROM inner_hits)
        SELECT (SELECT count(*) FROM m), (SELECT count(*) FROM inner_hits), (SELECT count(DISTINCT lower(w)) FROM found),
               (SELECT list({{'word': w, 'count': n}} ORDER BY n DESC, w)
                FROM (SELECT mode(w) AS w, count(DISTINCT event_uid) AS n FROM found GROUP BY lower(w)
                      ORDER BY n DESC, lower(w) LIMIT {ADDS_GROUPS}))""").fetchone()
    groups = groups or []
    return {"forgiving_query": swap_term(query, i, t.value), "total": total, "inside": inside, "words": words,
            "groups": [{"word": g["word"], "count": g["count"], "query": swap_term(query, i, f'"{g["word"]}"')}
                       for g in groups],
            "more": words - len(groups)}


def search_id(query: str) -> str:
    return hashlib.sha256(f"{MEANING} {normalize_query(query)}".encode()).hexdigest()[:16]


def ensure_tables(con: duckdb.DuckDBPyConnection) -> None:
    con.execute("CREATE TABLE IF NOT EXISTS search_hits (sid VARCHAR, event_uid VARCHAR)")
    con.execute("CREATE TABLE IF NOT EXISTS search_runs (sid VARCHAR, query VARCHAR, matches BIGINT, seq BIGINT)")
    # A search saved under an older MEANING is out of reach of its ID now; drop it, so it doesn't hold one of the
    # last KEEP places.
    for sid, query in con.execute("SELECT sid, query FROM search_runs").fetchall():
        if sid != search_id(query):
            con.execute("DELETE FROM search_hits WHERE sid = ?", [sid])
            con.execute("DELETE FROM search_runs WHERE sid = ?", [sid])


def clear_saved(con: duckdb.DuckDBPyConnection) -> None:
    """Drop every saved search, so each runs again when next asked for. A host split changes events' host, which every
    word search reads (HAYSTACK) and host: matches, so matches saved before it would be wrong."""
    ensure_tables(con)
    con.execute("DELETE FROM search_hits")
    con.execute("DELETE FROM search_runs")


def is_saved(con: duckdb.DuckDBPyConnection, query: str) -> bool:
    return con.execute("SELECT 1 FROM search_runs WHERE sid = ?", [search_id(query)]).fetchone() is not None


def use_saved(con: duckdb.DuckDBPyConnection, query: str) -> bool:
    """Whether a search is saved. One that is becomes the last of the KEEP to be dropped, so one just read isn't dropped
    by the next. Needs the write connection."""
    ensure_tables(con)
    if not is_saved(con, query):
        return False
    con.execute("UPDATE search_runs SET seq = (SELECT max(seq) FROM search_runs) + 1 WHERE sid = ?", [search_id(query)])
    return True


def search_sql(terms: list[Term]) -> str:
    """The condition a search's matches meet."""
    return " AND ".join(term_sql(t) for t in terms)


def value_key(field: str, value: str) -> str:
    """The key a View's event data value is saved under, as a search is under its query: pans then read its matches
    rather than every event's data. Its spaces are escaped, so normalize_query leaves it whole."""
    return VALUE + json.dumps([field, value]).replace(" ", "\\u0020")


def value_sql(field: str, value: str) -> str:
    """The condition a View's event data value meets: the whole value of `field`, "data." and the field's name, in any
    letter case. Events without the field don't match."""
    path = sql_literal('$."' + field.removeprefix("data.") + '"')
    return f"lower(json_extract_string(NULLIF(e.extra, ''), {path})) = lower({sql_literal(value)})"


def stage_matches(con: duckdb.DuckDBPyConnection, condition: str) -> str:
    """Write the events that meet a search's or a View value's condition into search_hits under a staging ID of their
    own, which nothing reads, and return that ID. It only appends, so the server runs it on a reader outside its lock.
    The matches stay in DuckDB: read into Python and written back under the lock, a search matching all 5.2 million
    events takes 8.9 s, against 2.4 s staged."""
    staged = f"{STAGED}{secrets.token_hex(8)}"
    con.execute(f"INSERT INTO search_hits SELECT ?, e.event_uid FROM events e WHERE {BASE_WHERE} AND {condition}",
                [staged])
    return staged


def drop_staged(con: duckdb.DuckDBPyConnection, staged: str) -> None:
    con.execute("DELETE FROM search_hits WHERE sid = ?", [staged])


def save_staged(con: duckdb.DuckDBPyConnection, query: str, staged: str) -> str:
    """Save staged matches as a search's and return its ID, keeping the KEEP most recently used searches. A search
    another request saved meanwhile is used again, and the staged matches dropped. Needs the write connection."""
    sid = search_id(query)
    if use_saved(con, query):
        drop_staged(con, staged)
        return sid
    (count,) = con.execute("UPDATE search_hits SET sid = ? WHERE sid = ?", [sid, staged]).fetchone()
    con.execute("INSERT INTO search_runs SELECT ?, ?, ?, COALESCE((SELECT max(seq) FROM search_runs), 0) + 1",
                [sid, normalize_query(query), count])
    for (old,) in con.execute("SELECT sid FROM search_runs ORDER BY seq DESC OFFSET ?", [KEEP]).fetchall():
        con.execute("DELETE FROM search_hits WHERE sid = ?", [old])
        con.execute("DELETE FROM search_runs WHERE sid = ?", [old])
    return sid


def save_hits(con: duckdb.DuckDBPyConnection, query: str) -> tuple[str, list[Term]]:
    """Run a search once and save its matches, all on the write connection; a search already saved isn't run again,
    only used again (use_saved). The server runs the search itself outside its lock (server.App.save_search)."""
    terms = parse(query)
    if not use_saved(con, query):
        save_staged(con, query, stage_matches(con, search_sql(terms)))
    return search_id(query), terms


def save_value(con: duckdb.DuckDBPyConnection, field: str, value: str) -> str:
    """Save a View's event data value's matches, as save_hits saves a search's, and return its ID."""
    key = value_key(field, value)
    if not use_saved(con, key):
        save_staged(con, key, stage_matches(con, value_sql(field, value)))
    return search_id(key)


def results(con: duckdb.DuckDBPyConnection, sid: str, shown: str = "true", limit: int = 500,
            terms: list[Term] | None = None) -> dict:
    """A saved search's matches: how many, their time span, where in time they fall, and the first `limit` in time
    order, each with where a word or phrase was found when `terms` are given.

    The matches and their times are read once, into a table of the connection's own, which the counts, the strip, and
    the IDs read; then the first `limit` take their columns, read only from events recorded within those events'
    recorded times, so none of the five queries reads every event, and the listing reads its columns for the listed
    events alone."""
    con.execute(f"CREATE OR REPLACE TEMP TABLE search_found AS SELECT e.event_uid, {TS} AS ts, e.ts_us AS recorded "
                f"FROM {TIME_FROM} WHERE e.event_uid IN (SELECT event_uid FROM search_hits WHERE sid = ?)", [sid])
    total, first, last = con.execute("SELECT count(*), min(ts), max(ts) FROM search_found").fetchone()
    listed = f"(SELECT * FROM search_found ORDER BY ts, event_uid LIMIT {limit})"
    span = con.execute(f"SELECT min(recorded), max(recorded) FROM {listed}").fetchone()
    cols = ", ".join(f"e.{c}" for c, _ in SEARCHED)
    rows = con.execute(
        f"SELECT e.event_uid, f.ts, e.host, e.event_code, left(e.message, {SHOWN_MESSAGE}), {MARK_EXPR}, ({shown}), "
        f"{cols}, e.extra FROM {BASE_FROM} JOIN {listed} f ON f.event_uid = e.event_uid "
        "WHERE e.ts_us BETWEEN ? AND ? ORDER BY f.ts, e.event_uid", span).fetchall()
    words = [t for t in terms or [] if not t.negate and not t.field]
    events = []
    for r in rows:
        ev = {"uid": r[0], "ts": r[1], "host": r[2], "code": r[3], "msg": r[4], "mark": r[5], "shown": bool(r[6])}
        found = found_in(dict(zip([c for c, _ in SEARCHED] + ["extra"], r[7:])), words)
        if found:
            ev["found"] = found
        events.append(ev)
    out = {"total": total, "first": first, "last": last, "limited": total > len(rows), "events": events,
           # A rule: term names a rule, not text on the page, so nothing is highlighted for it
           "highlight": [{"value": t.value, "whole": bool(t.field), "bounded": t.bounded}
                         for t in terms or [] if not t.negate and t.field != "rule"]}
    if total and first is not None:
        out.update(where_in_time(con, total, first, last))
    con.execute("DROP TABLE search_found")
    return out


def where_in_time(con: duckdb.DuckDBPyConnection, total: int, first: int, last: int) -> dict:
    """The match strip, from results' search_found: counts in BUCKETS equal stretches from the first match to the
    last; the shortest stretch holding half the matches, which a spread-out search needs to be seen at all; and the IDs
    the timeline marks."""
    width = max(1, math.ceil((last - first + 1) / BUCKETS))
    counts = [0] * BUCKETS
    for b, n in con.execute("SELECT least((ts - ?) // ?, ?) AS b, count(*) FROM search_found WHERE ts IS NOT NULL "
                            "GROUP BY b", [first, width, BUCKETS - 1]).fetchall():
        counts[int(b)] += n
    half = math.ceil(total / 2)
    core = con.execute(
        f"SELECT a, b FROM (SELECT ts AS a, lead(ts, {half - 1}) OVER (ORDER BY ts) AS b FROM search_found "
        "WHERE ts IS NOT NULL) WHERE b IS NOT NULL ORDER BY b - a, a LIMIT 1").fetchone()
    uids = [r[0] for r in con.execute(f"SELECT event_uid FROM search_found ORDER BY ts, event_uid LIMIT {MARKED}")
            .fetchall()]
    return {"strip": {"start": first, "width": width, "counts": counts},
            "core": {"start": core[0], "end": core[1], "count": half} if core else None,
            "uids": uids, "uids_limited": total > len(uids)}


def wildcard_span(value: str, text: str, bounded: bool = False) -> tuple[int, int] | None:
    """Where a word or phrase, with * for any text, is first found in `text`, in any letter case: from its first
    piece's start to its last piece's end, the span a regular expression with .*? for each * finds. Each piece is
    searched for once, after the one before, so the time is linear in the text. One expression for the whole value
    would backtrack over every way to split a repeated text when a later piece was missing: a*a*a*a*a*b takes 3.7 s on
    a message of 80 a's, holding the GIL, so every request of the server waits. A `bounded` value (a quoted word) must
    also start and end between word characters where its own first and last character is one, as bounded_pattern says."""
    start = pos = 0
    parts = value.split("*")
    for i, part in enumerate(parts):
        left = bounded and i == 0 and part[:1] in WORD
        right = bounded and i == len(parts) - 1 and part[-1:] in WORD
        m = _piece(part, left, right).search(text, pos)
        if m is None:
            return None
        start, pos = (m.start() if i == 0 else start), m.end()
    return start, pos


@functools.lru_cache(maxsize=256)
def _piece(part: str, left: bool = False, right: bool = False) -> re.Pattern:
    """A piece of a value as a pattern. The lookarounds are ASCII, as RE2's word boundary is; Python's own reads accented
    letters as word characters. They look at the text before the search's start too, so a piece found after another
    keeps its bound."""
    return re.compile((r"(?<![A-Za-z0-9_])" if left else "") + re.escape(part) + (r"(?![A-Za-z0-9_])" if right else ""),
                      re.IGNORECASE)


def found_in(fields: dict, words: list[Term]) -> dict | None:
    """Where the first word or phrase of a search was found in one event: the field and an excerpt around it. None
    when it's in the start of the message the list already shows, or when the search has no words."""
    if not words:
        return None
    candidates = [(label, fields.get(col) or "") for col, label in SEARCHED]
    try:
        extra = json.loads(fields.get("extra") or "{}")
    except ValueError:
        extra = {}
    if isinstance(extra, dict):
        candidates += [(f"data.{k}", v if isinstance(v, str) else json.dumps(v)) for k, v in extra.items()]
    for label, text in candidates:
        text = str(text)
        span = wildcard_span(words[0].value, text, words[0].bounded)
        if span is None or span[0] == span[1]:
            continue
        if label == "Message" and span[1] <= SHOWN_MESSAGE:
            return None
        start, end = max(0, span[0] - EXCERPT), min(len(text), span[1] + EXCERPT)
        return {"field": label, "text": text[start:end], "before": start > 0, "after": end < len(text)}
    return None


def rule_titles(con: duckdb.DuckDBPyConnection, t: Term, limit: int) -> list[dict]:
    """The Hayabusa rules a free-text term finds in their titles, by the term's own meaning: the title, its level, and how
    many events on the timeline the rule hit, the most first. A title holding a quote is left out, since rule:"..." cannot
    carry it. Read from the hits table alone (2 to 71 ms at 5.2 million events, the map-search reader measured)."""
    rows = con.execute(
        "SELECT t, count(DISTINCT event_uid) FILTER (WHERE timed) FROM (SELECT event_uid, unnest(titles) AS t, timed FROM hits) "
        f"WHERE strpos(t, '\"') = 0 AND {text_sql(t, 't')} GROUP BY t HAVING count(*) FILTER (WHERE timed) > 0 "
        f"ORDER BY 2 DESC, t LIMIT {limit}").fetchall()
    if not rows:
        return []
    levels = dict(con.execute(
        f"SELECT rule_title, arg_max(rule_level, {level_rank('rule_level')}) FROM events WHERE tool = 'hayabusa' "
        f"AND rule_title IN ({', '.join(sql_literal(title) for title, _ in rows)}) GROUP BY rule_title").fetchall())
    return [{"title": title, "level": levels.get(title, ""), "count": n} for title, n in rows]


BY_NAME = 3             # rules the box under the results names
BY_NAME_EVENTS = 20     # events of each rule the box lists
BY_NAME_CANDIDATES = 12  # titles the word finds that the rest of the query is tried on, the most hits first


def by_name(con: duckdb.DuckDBPyConnection, query: str, terms: list[Term], sid: str) -> list[dict]:
    """The Hayabusa rules a search's first free-text word finds in their titles, which free text does not read:
    at most BY_NAME, the most events first under the whole query, each with `query` (the search with the word replaced
    by the rule's field form), `count` (the events that query finds), `events` (up to BY_NAME_EVENTS of them that the search
    `sid` did not find) and `in_results` (the events the two share). A rule the rest of the query leaves no event of is left
    out, and so is one whose search would pass MAX_QUERY. The first word that finds any title is the one used.

    The titles are tried by their own events: the rest of the query runs over the events the candidates hit, not over every
    event, once for all of them. Run over every event for each rule, "service svc" takes 15 s at 5.2 million events.
    The candidates are the BY_NAME_CANDIDATES titles with the most hits case-wide, since a rule the rest of the query
    narrows could rank low there."""
    for i, t in enumerate(terms):
        if t.negate or t.field:
            continue
        titles = rule_titles(con, t, BY_NAME_CANDIDATES)
        if not titles:
            continue
        rest = [x for j, x in enumerate(terms) if j != i]
        seen = f"e.event_uid IN (SELECT event_uid FROM search_hits WHERE sid = {sql_literal(sid)})"
        names = ", ".join(sql_literal(r["title"].lower()) for r in titles)
        # Per rule, as lower(title), which is how rule: compares: its events under the rest of the query, how many the results
        # hold, and the first of the rest by time. `listed_events` joins marks, hosts, hits and suggestions before it filters,
        # 0.8 s a rule at 5.2 million events; the rows are read once for all the rules below, by event ID, in 0.3 s.
        # The candidates' events go into a table of the connection's own first: in one statement the optimizer moved the rest of
        # the query below the join, onto all 5.2 million events (5 s for "service svc"), even from a MATERIALIZED CTE.
        # Whole rows only when the rest of the query reads them: the wide columns of 900 events took 1.1 s to read.
        cols = "e.*" if rest else "e.event_uid, e.host, e.ts_us"
        con.execute(f"""CREATE OR REPLACE TEMP TABLE by_name_events AS SELECT {cols}, r.rt FROM events e JOIN (
                SELECT DISTINCT event_uid, lower(t) AS rt FROM (SELECT event_uid, unnest(titles) AS t FROM hits)
                WHERE lower(t) IN ({names})) r ON r.event_uid = e.event_uid WHERE {BASE_WHERE}""")
        try:
            by_rule = {name: (n, shared, uids or []) for name, n, shared, uids in con.execute(f"""
                SELECT rt, count(*), count(*) FILTER (WHERE seen),
                       (list(event_uid ORDER BY ts, event_uid) FILTER (WHERE NOT seen))[1:{BY_NAME_EVENTS}]
                FROM (SELECT e.rt, e.event_uid, {TS} AS ts, ({seen}) AS seen FROM by_name_events e
                      LEFT JOIN hosts h ON h.host = e.host WHERE {search_sql(rest) if rest else 'true'})
                GROUP BY rt""").fetchall()}
        finally:
            con.execute("DROP TABLE by_name_events")
        found = []
        for rule in titles:
            n, shared, uids = by_rule.get(rule["title"].lower(), (0, 0, []))
            swapped = swap_term(query, i, f'rule:"{rule["title"]}"')
            if n and len(swapped) <= MAX_QUERY:   # a rule the rest of the query leaves no event of is left out
                found.append({**rule, "count": n, "query": normalize_query(swapped), "in_results": shared, "uids": uids})
        found = sorted(found, key=lambda rule: (-rule["count"], rule["title"]))[:BY_NAME]
        if found:
            every = [uid for rule in found for uid in rule["uids"]]
            listed = {r[0]: {"uid": r[0], "ts": r[1], "host": r[2], "code": r[3], "msg": r[4], "mark": r[5], "shown": True}
                      for r in con.execute(
                          f"SELECT e.event_uid, {TS}, e.host, e.event_code, left(e.message, {LISTED_MESSAGE}), {MARK_EXPR} "
                          "FROM events e LEFT JOIN marks m ON m.event_uid = e.event_uid LEFT JOIN hosts h ON h.host = e.host "
                          "LEFT JOIN suggested sg ON sg.event_uid = e.event_uid "
                          f"WHERE e.event_uid IN ({', '.join(sql_literal(u) for u in every)})").fetchall()} if every else {}
            return [{**{k: v for k, v in rule.items() if k != "uids"}, "events": [listed[u] for u in rule["uids"]]}
                    for rule in found]
    return []


HINT_PER_FIELD = 5
HINT_TOTAL = 12
SKIPPED = ("tool", "artifact", "run", "source file", "mark", "role", "tag", "Hayabusa rule titles")   # what free text skips
MARK_WORDS = ("Malicious", "Suspicious", "Authorized", "Unreviewed", "Suggested")


def _plain(label: str) -> str:
    """A field's label in running text: lower case unless it starts with an abbreviation, such as IP."""
    return label[0].lower() + label[1:] if label[1:2].islower() else label


def zero_hint(con: duckdb.DuckDBPyConnection, terms: list[Term], listing: dict) -> dict | None:
    """What a search with no match can say: the text free text covers, the fields it skips, and
    the values of those fields that hold the search's words, each by the word's own meaning, with the search for the value
    (or, for a mark, a role, or a tag, the View value that shows it, since search leaves those to the View). The search is
    the field's term alone, whose count is the value's own, not the rest of the query's. `listing` is the Sources listing
    (App.sources_cache). At most HINT_PER_FIELD of a field and HINT_TOTAL in all, the rule titles first. None when the
    search has no free-text word."""
    words = [t for t in terms if not t.negate and not t.field]
    if not words:
        return None

    def has(t: Term, text: str) -> bool:
        span = wildcard_span(t.value, text, t.bounded)
        return span is not None and span[0] != span[1]
    by_field: dict[str, list[dict]] = {}

    def add(field: str, value: str, count: int, **more) -> None:
        mine = by_field.setdefault(field, [])
        if count and '"' not in value and not any(f["value"] == value for f in mine):
            quote = field in ("rule", "file") or not re.fullmatch(r"[\w.]+", value)
            mine.append({"field": field, "value": value, "count": count, **more,
                         **({} if "view" in more else {"query": f'{field}:"{value}"' if quote else f"{field}:{value}"})})
    counts: dict[str, Counter] = {k: Counter() for k in ("tool", "artifact", "run", "file")}
    for kind in listing.get("types", []):
        counts["tool"][kind["tool"]] += kind["count"]
        counts["artifact"][kind["artifact"]] += kind["count"]
        for run in kind["runs"]:
            counts["run"][run["run"]] += run["count"]
    for host in listing.get("hosts", []):
        for artifact in host["artifacts"]:
            for f in artifact["files"]:
                counts["file"][f["file"]] += f["count"]
    host_events = {h["host"]: h["count"] for h in listing.get("hosts", [])}
    roles: Counter = Counter()
    view_marks: dict[str, int] | None = None
    for host, role in con.execute("SELECT host, role FROM hosts").fetchall():
        roles[role] += host_events.get(host, 0)
    for t in words:
        for rule in rule_titles(con, t, HINT_PER_FIELD):
            add("rule", rule["title"], rule["count"], level=rule["level"])
        for field, found in counts.items():
            for value, n in found.items():
                if value and has(t, value):
                    add(field, value, n)
        for label in MARK_WORDS:
            if has(t, label):
                if label in ("Unreviewed", "Suggested"):   # the View's counts: a pending suggestion is not Unreviewed
                    if view_marks is None:
                        view_marks = mark_counts(con)
                    n = view_marks.get(label, 0)
                else:
                    n = con.execute(f"SELECT count(*) FROM events e WHERE {BASE_WHERE} AND e.event_uid IN "
                                    "(SELECT event_uid FROM marks WHERE label = ?)", [label]).fetchone()[0]
                add("mark", label, n, view={"mark": label})
        for role, n in roles.items():
            if role and has(t, role):
                add("role", role, n, view={"role": role})
        for tag, label, n in con.execute(
                f"SELECT tag, any_value(label), count(DISTINCT event_uid) FROM tags WHERE {text_sql(t, 'label')} "
                "GROUP BY tag ORDER BY 3 DESC, 1 LIMIT ?", [HINT_PER_FIELD]).fetchall():
            add("tag", label or tag, n, view={"tag": tag})
    found = [e for field in ("rule", "tool", "artifact", "run", "file", "mark", "role", "tag")
             for e in sorted(by_field.get(field, []), key=lambda e: (-e["count"], e["value"]))[:HINT_PER_FIELD]]
    one = words[0].value if len(words) == 1 and not re.search(r"[\s*]", words[0].value) else None
    return {"covers": [_plain(label) for _, label in SEARCHED] + ["event data"], "skips": list(SKIPPED),
            "found": found[:HINT_TOTAL], "text_only": len(words) == len(terms), "word": one}


def hits_sql(query: str) -> str:
    """The View condition for a saved search's matches."""
    return f"e.event_uid IN (SELECT event_uid FROM search_hits WHERE sid = {sql_literal(search_id(query))})"
