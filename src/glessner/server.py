"""Local HTTP server for the timeline page and its JSON API.

Security: listens on 127.0.0.1 only. The launch link carries a
random session token, which the server swaps for an HttpOnly, SameSite=Strict cookie. Every
other request needs that cookie, and a Host header naming this server, which blocks DNS
rebinding. A POST from another origin is refused by its Origin header, and a GET by the browser's
Sec-Fetch-Site header, since a page on another 127.0.0.1 port gets the cookie sent with its requests.
Pages get a Content-Security-Policy that forbids external requests.
"""

from __future__ import annotations

import functools
import getpass
import hashlib
import json
import os
import secrets
import sys
import threading
import time
import traceback
from collections.abc import Sequence
from datetime import UTC, datetime
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import duckdb

from . import attack
from .analysis import (
    BUILTIN_SOURCES,
    MARK_LABELS,
    build_identity,
    build_identity_tables,
    build_suggestions,
    build_tables,
    orphan_marks,
    refresh_tags,
    replace_marks,
    suggestion_counts,
)
from .audit import (
    AuditError,
    entry_targets,
    file_words,
    mark_unreadable,
    markdown,
    plan_undo,
    read_entries,
    rows,
    short,
    single_targets,
)
from .case import Case, CaseError, open_case, upgrade
from .caveats import CAVEAT_COLUMNS, caveat_for, caveats_for
from .clock import MEASURED, alignment, in_segment
from .events import BIGINT_COLUMNS, connect, id_table, transaction, well_formed
from .export import (
    WHOLE_CASE,
    export_path,
    export_timeline,
    file_payload,
    indicators,
    record_file,
    report_text,
    write_indicators,
    write_report,
)
from .filters import FilterStore, condition, data_values, describe, normalize, normalize_pred, pred_sql, searches
from .imports import (
    FORMATS,
    ROLES,
    TIME_FORMATS,
    MappingError,
    case_year,
    check_mapping_name,
    importable,
    preview,
    run_import,
    save_mapping,
    saved_mappings,
)
from .imports import PRESETS as IMPORT_PRESETS
from .intake import add_new, current_entries, evidence_checks, manifest_hashes, read_manifest
from .journal import (
    REPLAY_ERRORS,
    SYSTEM,
    Check,
    Journal,
    JournalError,
    rekey_map,
    renamed,
    unplaced,
    upgrade_recorder,
)
from .line_logs import LAYOUTS
from .overview import case_overview, journal_facts, journal_row, lead_events, manifest_facts, problem_files
from .parsers import ARTIFACT_NAMES
from .parsers.common import normalize_ip
from .pivots import checked_name, count_pivot, guidance, window_kinds, worklist_rows
from .queries import (
    BASE_FROM,
    BASE_WHERE,
    MARK_EXPR,
    PENDING_LIMIT,
    PRESETS,
    TS,
    WINDOW_DEFAULT_SECONDS,
    WINDOW_RANGE_SECONDS,
    QueryError,
    account_names,
    case_range,
    categories,
    event_details,
    event_keys,
    event_pairs,
    fit_range,
    investigate,
    lanes,
    listed_events,
    mark_counts,
    parse_groupby,
    pending_events,
    pending_for_source,
    pending_group_uids,
    pending_source_events,
    related,
    shown_counts,
    sources,
    tag_counts,
    timeline_count,
    view,
)
from .relations import outside_sources
from .rules import BUILTIN_RULES, RuleError
from .rules import parse as parse_rule
from .runner import IMPORT, RunError, read_runs
from .search import (
    Term,
    by_name,
    clear_saved,
    drop_staged,
    forgiving_term,
    is_saved,
    normalize_query,
    results,
    save_staged,
    search_adds,
    search_id,
    search_sql,
    stage_matches,
    use_saved,
    value_key,
    value_sql,
    whole_word,
    zero_hint,
)
from .search import parse as parse_search
from .splits import apply_layout, intake_folders, kept_keys, kept_list, machines, mark_mixed, proposal, split_list
from .start import browse, check, forget_missing, load_recent, remember, start_copy, start_new_case, start_open_case
from .tags import TACTICS, TagError, normalize_tag, tactic_order, tag_kind, tag_label
from .timezones import validate_axes, zone_names
from .tool_outputs import KINDS
from .toolbox import close_interrupted, everything_ready, overview, run_gaps, start_all_job, start_load_job
from .toolbox import start_job as start_tool_job
from .tools import detect, load_registry
from .version import build_id

STATIC_DIR = Path(__file__).parent / "static"
STATIC = {"/": ("index.html", "text/html; charset=utf-8"), "/app.css": ("app.css", "text/css; charset=utf-8"),
          "/start": ("start.html", "text/html; charset=utf-8")}   # the start page: no case open, or switching
STATIC.update({f"/js/{p.name}": (f"js/{p.name}", "text/javascript; charset=utf-8")   # the page's ES modules
               for p in sorted((STATIC_DIR / "js").glob("*.js"))})
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
       "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
# The session cookie's name carries the port (cookie_name), since a browser keeps cookies by host and not by port: two runs
# at once, one on PREFERRED_PORT and one on a free port, would share one name, and the second's link would make the first
# refuse its own tab as an earlier run. A tab whose run is gone still sends the old token under this run's name.
COOKIE = "glessner_session"
CASE_HEADER = "X-Glessner-Case"   # the case open, App.case_id, as the page last read it from /api/meta
# Measured on the Szechuan case: canvas drawing costs about 0.6 ms per 1,000 events; query plus
# transfer dominates (67,333 events: 512 ms end to end; 77,016: 608 ms). 50,000 keeps a refresh near 0.5 s.
DEFAULT_EVENT_THRESHOLD = 50_000
MAX_MARK_TARGETS = 200_000
LISTED_EVENTS = 500   # events listed for an audit entry or a selection; the rest are counted
# The longest POST body the server reads (Handler._length), twice the page's largest: a mark of MAX_MARK_TARGETS event
# IDs, about 7 MB. A longer one is answered 413 and left unread, so a client that sends it before reading the answer
# may get a connection reset instead (see Handler._refuse).
MAX_BODY = 16 * 1024 * 1024
# How long a socket read or write may wait, and so how long a kept-alive connection idles before the server closes it
# and its thread ends (Handler.timeout). A whole answer's write must finish within it too: a 67,333-event view took
# 512 ms end to end when measured.
KEEP_ALIVE_SECONDS = 60
REOPEN_WAIT_SECONDS = 5   # how long Hub.open waits for a retired App of the same case to close
# The port `serve` tries first when --port isn't given. The browser keeps the page's layout preferences by
# origin, and the port is part of the origin, so a port that changes with every run loses them. It is below Windows'
# dynamic range, 49152 and up, and outside the ranges `netsh interface ipv4 show excludedportrange protocol=tcp` listed
# when it was chosen. When another program holds it, serve_hub falls back to a free port.
PREFERRED_PORT = 47613
# The answer to an API request whose session cookie is missing or not this run's: a tab left open from an earlier run
# reaches the new run's server on the same port. JSON, so the page can show it as it shows the refusal of a request
# meant for another case.
STALE_SESSION = ("This page is from an earlier run of glessner serve, or has no session. Open the link the new run "
                 "printed; this page's request did nothing.")
MAX_OFFSET_SECONDS = 86_400
# A host's clock result as the event page gives it
EVENT_CLOCK = ("state", "reference", "seconds", "skew_seconds", "skew_text", "display", "basis_text", "inliers",
               "pairs", "zone_note", "steps_text", "span_note")


class App:
    """Case state shared by all request threads. Writes go through self.lock: a request that journals holds it from its
    first read of what decides the entry, through the append and the rewrite of the derived tables.
    An undo that planned outside it would append its plan over a mark made meanwhile. Requests that only read
    take it only briefly, to fill a cache or name a search's saved matches, and only those wait behind a long holder:
    a search not yet saved waited 1.8 s behind an undo of 200,000 events."""

    def __init__(self, case: Case, token: str | None = None, *, client: str = "server", for_work: bool = False,
                 report=None):
        """`for_work` for the server's case open (Hub.open), which upgrades an older case format and journals the build
        when it differs from the newest the journal names. The command line's commands open the case
        without it, upgrading it first themselves (rekey.upgraded), and with `client` "cli", which their entries name.
        An open for work runs in this order: the upgrade, whose steps hold the events database themselves; the
        connection, so a database another program holds stops the open before any other journal write; then, under the
        journal's held context, its checks, recovery, case_yaml, case_open, and the built-in rules. A broken chain writes
        none of them, and the journal then refuses every write with the reason (Journal.read_only). Last, any run still
        recorded as running is marked failed (toolbox.close_interrupted). `report(stage, done,
        total)`, when given, gets the upgrade's stages and then "Opening" (the start page's open job)."""
        self.token = token or secrets.token_urlsafe(32)
        # This open's ID, which /api/meta gives the page and the page sends with each request, so a page whose case
        # another tab has since replaced is refused rather than written into the case open now
        self.case_id = secrets.token_hex(8)
        self.lock = threading.RLock()   # reentrant, so an alignment holds it across its rebuild
        # The requests running on this App (Handler._api), so a switch of case closes its connection once they end.
        # The count has its own lock, held only to change it, never across a request's work.
        self.counting = threading.Lock()
        self.inflight = 0
        self.retired = False
        self.closed = threading.Event()   # set once the connection is closed, which Hub.open waits for on a reopen
        self.journal = Journal(case, client)
        if for_work:
            # The upgrade first, so an open it refuses, such as one whose loaded events the format 1 rules don't account
            # for, leaves the journal as it was
            case = upgrade(case, upgrade_recorder(self.journal), report)
            if report:
                report("Opening", 0, 0)
        self.case = case
        try:
            self.con = connect(case.db_path)
        except duckdb.Error as exc:   # IOException from another process; ConnectionException from a connection in this one
            raise CaseError(f"{case.settings.name} can't be opened now: another program has its events database open, "
                            f"such as glessner serving the case. Close it, then try again. ({exc})") from exc
        try:
            self.journal.open_for_work(lambda: ensure_builtin_rules(self.journal), record_build=for_work)
        except BaseException:
            self.con.close()
            raise
        if for_work:
            close_interrupted(case)   # after the connection: a run another process is loading holds the database
        self.opened_at = _now()   # when the open checked the journal, which Integrity's row says
        self.last_check: tuple | None = None   # Check now's (Check, the head record it compared, when)
        self.manifest = manifest_hashes(case) if case.manifest_path.exists() else {}
        # The clock check's measurement (clock.check_clocks) and the lookup the logon links were built from
        # (relations.build_logon_links), until events load or a rebuild fails
        self.clock_cache: dict = {}
        self.machines_cache: dict = {}   # the computers in each host's event logs, until events load (splits.py)
        self.sources_cache: dict | None = None
        self.loads = 0   # refreshes after events changed, which a search's matches read outside the lock must predate
        # Rewrites of the derived tables, counted once each commits, and the Case overview kept with what it read
        # (see overview_key)
        self.generation = 0
        self.overview_cache: tuple[tuple, dict] | None = None
        self.facts_cache: tuple[tuple | None, dict] | None = None   # overview.manifest_facts, by the manifest's size and time
        # As after a load, which the CLI may have made while the case was closed: the lanes are brought into line with
        # the journal's host splits, which also mends a split whose journal entry was written but whose update a crash
        # stopped, and saved searches are dropped.
        self.refresh_identity(events_changed=True)
        self.filters = FilterStore()   # view filters by ID; in memory only, never journaled
        self.tool_cache: tuple[dict, dict] | None = None   # the registry and detected tools, until a rescan
        self.job = None   # the tool running from the Tools page, if any
        self.anchors: dict = {}   # the events the Event page read last, for the counts of its pivots (see anchor)
        self.checks_cache: tuple[tuple[int, int] | None, dict] | None = None   # evidence_checks, by the log's size and time

    def after_job(self, job) -> None:
        """When a Tools page job ends, also partway through: if any of its steps committed a load, the
        derived tables are built again (hits, marks, relations, identity). A step's status doesn't say: a load can
        commit and then fail its evidence check, and a group fails when any of its runs does. A job
        that a fault stopped refreshes too: the fault can come after a load committed and before its step's result was
        recorded, as when a group's later member raises what its import doesn't catch."""
        if job.error or any(r.get("loaded") for r in job.results):
            self.refresh_identity(events_changed=True)
            self.remember()

    def remember(self) -> None:
        """Recent cases' count of timeline events, when the case opens (Hub.open) and after a load. It is the case's
        current count, not the last open's (0 for a new case), and leaves out Hayabusa's hit rows. The list is the
        start page's bookkeeping, so a list that can't be written, such as one whose recent.json another program holds
        open, fails neither the open nor the load."""
        try:
            remember(self.case, timeline_count(self.reader()))   # a cursor: requests may run
        except OSError as exc:
            print(f"Recent cases not updated: {exc}", file=sys.stderr)   # for the console `serve` runs in

    def enter(self) -> bool:
        """A request begins on this App. False once the App is retired, which the request answers by reading the hub's
        App again: the connection may be closed already."""
        with self.counting:
            if self.retired:
                return False
            self.inflight += 1
            return True

    def leave(self) -> None:
        """A request ends. The last one out of a retired App closes its connection."""
        with self.counting:
            self.inflight -= 1
            last = self.retired and self.inflight == 0
        if last:
            self.con.close()
            self.closed.set()

    def retire(self) -> None:
        """Another case is open now. The connection closes at once when no request is running on the App, and otherwise
        when the last one ends. No request takes the App after this, so no thread waits for another."""
        with self.counting:
            self.retired = True
            idle = self.inflight == 0
        if idle:
            self.con.close()
            self.closed.set()

    def refresh_identity(self, events_changed: bool = False) -> None:
        """Build the host identity and the derived tables again: all of them when events changed (a case open, a load,
        or a split), and only those that read the identity after a host edit."""
        with self.lock:
            if events_changed:   # under the lock, so a rebuild that read the old events can't store them after this
                # A load routes its rows by the splits it read from the journal; this also covers one that raced a
                # split, and a split host whose rows were loaded before it.
                apply_layout(self.con, self.journal.state)
                # Saved searches and the Sources listing describe the events as they were: a load, a split, or its
                # undo changes them. Each search runs again when next asked for.
                clear_saved(self.con)
                self.loads += 1
                self.sources_cache = None
                self.clock_cache.clear()
                self.machines_cache.clear()
            # Readers take self.identity without the lock, so it's replaced only once the tables have checked each
            # host's clock.
            identity = build_identity(self.con, self.journal.state)
            mark_mixed(identity, self.journal.state, machines(self.con, self.machines_cache))
            build = build_tables if events_changed else build_identity_tables
            # In one transaction, so a request reading meanwhile sees the derived tables as they were until all are
            # rebuilt. Statements that committed alone would let an Event page read no host offset between CREATE OR
            # REPLACE TABLE hosts and its insert.
            try:
                with transaction(self.con):
                    report = build(self.con, self.journal.state, identity, self.clock_cache)
            except Exception:
                # It may hold a measurement whose clock_pairs rows, or a lookup whose logon_links, the rollback took back
                self.clock_cache.clear()
                raise
            self.suggestion_report = report
            self.outside = outside_sources(self.con)
            self.identity = identity
            if events_changed:   # a rerun can drop marked events, which the page warns of when it loads
                self.orphans = orphan_marks(self.con)
            self.generation += 1

    def filter(self, fid: str) -> tuple[dict, str, str]:
        """A registered filter, as FilterStore.get gives it, with the searches it reads saved first."""
        entry = self.filters.get(fid)
        self.save_searches(entry[0])
        return entry

    def save_searches(self, spec: dict) -> None:
        """Save each search and event data value a filter reads that isn't saved: a load drops them all, and KEEP newer
        ones push one out, while the page keeps the filter's ID. Checked without the
        lock, which a pan takes only when one must be saved. Under it, the filter's saved ones are used first, which
        makes them the most recent, so saving a missing one can't push out another this filter reads."""
        conditions = {q: search_sql(parse_search(q)) for q in searches(spec)}
        conditions |= {value_key(f, v): value_sql(f, v) for f, v in data_values(spec)}
        cur = self.reader()
        if all(is_saved(cur, key) for key in conditions):
            return
        with self.lock:
            missing = [key for key in conditions if not use_saved(self.con, key)]
        for key in missing:
            self._save(key, conditions[key])

    def save_search(self, query: str) -> tuple[str, list[Term]]:
        """Run a search once and save its matches (search.py)."""
        terms = parse_search(query)
        return self._save(query, search_sql(terms)), terms

    def _save(self, key: str, condition: str) -> str:
        """Save the matches of a search, or of a View's event data value, under its key, and return its ID. The scan
        writes them on a reader under a staging ID, outside the lock, so marks and notes don't wait behind it; the lock
        is held only to give them the key's ID. Matches staged while a load's refresh ran may describe the events
        before it, so they're read again under the lock. Staged matches that a failure leaves behind
        go with the other saved searches at the next load or case open."""
        with self.lock:
            if use_saved(self.con, key):
                return search_id(key)
            loads = self.loads
        staged = stage_matches(self.reader(), condition)
        with self.lock:
            if loads != self.loads:
                drop_staged(self.con, staged)
                staged = stage_matches(self.con, condition)
            return save_staged(self.con, key, staged)

    def refresh_suggestions(self) -> None:
        self.rewrite(suggestions=True)

    def rewrite(self, marks: Sequence[str] = (), tags: Sequence[str] = (), suggestions: bool = False) -> None:
        """Rewrite from the journal the marks of the events in `marks`, the tags and tag suggestions of the events in
        `tags`, and with `suggestions` every suggestion, all in one transaction under the lock, as refresh_identity's
        rebuild is. Each event's rows are deleted and then inserted, and a request between the two would read the
        events unmarked or untagged if each statement committed alone."""
        with self.lock:
            with transaction(self.con):
                if marks:
                    replace_marks(self.con, self.journal.state, list(marks))
                if tags:
                    refresh_tags(self.con, self.journal.state, list(tags))
                report = build_suggestions(self.con, self.journal.state) if suggestions else None
            if report is not None:
                self.suggestion_report = report
            self.generation += 1

    def reader(self):
        return self.con.cursor()   # one DuckDB cursor per request thread

    def keep_anchor(self, uid: str, event: dict) -> None:
        """Keep the event an Event page read, for the counts of its pivots, which each start from it: reading the event
        again takes 50 ms at 11 million events. The few kept go when events load or a host edit moves the times, which the key
        names."""
        row = {k: ("" if v is None and k not in BIGINT_COLUMNS else v) for k, v in event.items()}
        key = (uid, self.loads, id(self.identity))
        self.anchors = dict([*self.anchors.items(), (key, (row, event["adjusted_ts_us"]))][-8:])

    def anchor(self, uid: str, ts: int | None) -> tuple[dict, int | None] | None:
        """The kept event, when it is still the one at the time the page shows it."""
        kept = self.anchors.get((uid, self.loads, id(self.identity)))
        return kept if kept is not None and (ts is None or ts == kept[1]) else None

    @property
    def event_threshold(self) -> int:
        return int(self.journal.state.settings.get("event_threshold", DEFAULT_EVENT_THRESHOLD))

    @property
    def time_window_seconds(self) -> int:
        return int(self.journal.state.settings.get("time_window_seconds", WINDOW_DEFAULT_SECONDS))

    @property
    def pivot_windows(self) -> dict[str, int]:
        """The analyst's time window for each kind of event, in seconds, where it isn't the table's;
        a case_setting, as the case's window is."""
        value = self.journal.state.settings.get("pivot_windows")
        return {k: v for k, v in value.items() if isinstance(v, int)} if isinstance(value, dict) else {}


class Hub:
    """The server across cases: the session token, the open case's App, if any, and the start page's job."""

    def __init__(self, case: Case | None = None, report=None):
        """`report` gets the open's stages, as App's does (the serve command's lines)."""
        self.token = secrets.token_urlsafe(32)
        self.app: App | None = None
        self.job = None   # a case being created or copied from the start page
        # Each open's ID (App.case_id) and its case folder, so a page refused for naming an earlier open learns
        # whether it was of the case open now
        self.opened: dict[str, Path] = {}
        self.retired: list[App] = []   # Apps switched away from whose connection may still be open
        self.lock = threading.Lock()
        self.job_lock = threading.Lock()   # the start page's one job at a time (_start_job)
        if case is not None:
            self.open(case, report)

    def open(self, case: Case, report=None) -> App:
        """Make a case the open one, retiring the one before; refused while a tool runs in it. The old App's connection
        stays open until its requests in flight end (App.retire), so each finishes in the case it began in. Closing
        it at once would answer a mark or note in flight with a 500; closing it under the App's lock would still answer
        a request that read the old App before the switch with a 500, and the switch would wait for any request
        holding that lock, an import's whole length. Opening a case whose earlier App is
        still closing waits for that App, and refuses after REOPEN_WAIT_SECONDS; a different case never waits."""
        with self.lock:
            if self.app and self.app.job and not self.app.job.finished:
                raise ValueError(f"{self.app.job.tool} is still running in {self.app.case.settings.name}.")
            # Two Apps of one case never run at once: they would share one DuckDB instance, and their writes collide
            # (transaction conflicts answered 500), and a reopen while the old connection is closing fails on the
            # file. A different case never waits. Waits briefly, then refuses, since a request
            # such as an import can hold the old App for minutes.
            self.retired = [r for r in self.retired if not r.closed.is_set()]
            for r in self.retired:
                if r.case.folder == case.folder and not r.closed.wait(REOPEN_WAIT_SECONDS):
                    raise ValueError(f"{case.settings.name} is still finishing a request from its earlier open. "
                                     "Try again in a moment.")
            old, self.app = self.app, App(case, self.token, for_work=True, report=report)
            app = self.app
            self.opened[app.case_id] = app.case.folder
            if old is not None:
                self.retired.append(old)
        if old is not None:
            old.retire()
        app.remember()
        return app


class BodyError(Exception):
    """A POST body the server won't read or the routes can't take, with the status to answer."""

    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code


def cookie_name(port: int) -> str:
    """The session cookie's name for a run on `port`, such as glessner_session_47613."""
    return f"{COOKIE}_{port}"


def make_handler(hub: Hub, port_ref: list[int]):
    class Handler(BaseHTTPRequestHandler):
        """Answers HTTP/1.1, so a page's requests share the few connections the browser keeps open to the server. A new
        connection per request takes a local port that stays in TIME_WAIT after it closes: a page load makes about 37
        requests, and a run of the browser tests about 5,000, a large share of the dynamic port range the whole machine
        shares. When the range runs out, Windows refuses the browser a local port (net::ERR_NO_BUFFER_SPACE; Tcpip event
        4231). Every answer has a Content-Length, an answer after which the connection can't carry another request closes
        it, and the Host, cookie, Origin or Sec-Fetch-Site, and case checks run on every request, not once per
        connection. A request that isn't HTTP/1.1 closes, since its answer can't say it stays open."""

        server_version = "glessner"
        protocol_version = "HTTP/1.1"
        timeout = KEEP_ALIVE_SECONDS   # StreamRequestHandler sets it on the socket; handle_one_request closes on it

        def handle_one_request(self):
            # A browser that drops a kept-alive connection, as when its tab or context closes, can reset it while the
            # handler waits for the next request. The reset ends the connection, not with a traceback.
            try:
                super().handle_one_request()
            except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
                self.close_connection = True

        def parse_request(self):
            ok = super().parse_request()
            if ok and self.request_version != "HTTP/1.1":
                self.close_connection = True   # an HTTP/1.0 client that asked to keep it open would wait for an end we don't mark
            return ok

        def handle_expect_100(self):
            """Send "100 Continue" only to a request do_POST would take, so the checks come before a body is invited (up to
            MAX_BODY). One that fails them is refused now, without its body, and the connection closes (RFC 9110, 10.1.1)."""
            if not (self._host_ok() and self._cookie_ok() and self._origin_ok()):
                self.close_connection = True
                self._text(403, "Forbidden.")
                return False
            return super().handle_expect_100()

        def do_GET(self):
            url = urlparse(self.path)
            if "Transfer-Encoding" in self.headers or self.headers.get("Content-Length", "0").strip(" \t") != "0":
                self.close_connection = True   # a GET's body isn't read, and the next request would start inside it
            if not self._host_ok():
                return self._text(403, "Bad Host header.")
            if not self._site_ok():
                return self._text(403, "Forbidden.")
            query = parse_qs(url.query)
            if url.path == "/" and len(sent := query.get("token", [])) == 1 and self._is_token(sent[0]):
                self.send_response(303)
                self.send_header("Set-Cookie", f"{cookie_name(port_ref[0])}={hub.token}; HttpOnly; SameSite=Strict; Path=/")
                self.send_header("Location", "/")
                self.send_header("Content-Length", "0")   # without it an HTTP/1.1 client reads until the connection closes
                if self.close_connection:
                    self.send_header("Connection", "close")
                self.end_headers()
                return
            if not self._cookie_ok():
                if url.path.startswith("/api/"):
                    return self._json(403, {"error": STALE_SESSION, "stale_session": True})
                return self._text(403, "Open the link that `glessner serve` printed.")
            if url.path in STATIC:
                name, ctype = STATIC["/start" if url.path == "/" and hub.app is None else url.path]
                return self._send(200, ctype, (STATIC_DIR / name).read_bytes())
            if url.path in START_GET_ROUTES:
                return self._api(START_GET_ROUTES[url.path], query, hub)
            route = GET_ROUTES.get(url.path)
            if route is None:
                return self._text(404, "Not found.")
            self._api(route, query)

        def do_POST(self):
            url = urlparse(self.path)
            if not (self._host_ok() and self._origin_ok()):
                return self._refuse(403, "Forbidden.")
            if not self._cookie_ok():
                return self._refuse(403, "Forbidden.", {"error": STALE_SESSION, "stale_session": True})
            if not self.headers.get("Content-Type", "").startswith("application/json"):
                return self._refuse(415, "Send JSON.")
            route = POST_ROUTES.get(url.path) or START_POST_ROUTES.get(url.path)
            if route is None:
                return self._refuse(404, "Not found.")
            try:
                body = self._read_json()
            except BodyError as exc:
                return self._json(exc.code, {"error": str(exc)})
            except (ConnectionAbortedError, ConnectionResetError):
                return   # the client went away while sending
            self._api(route, body, hub if url.path in START_POST_ROUTES else None)

        def _api(self, route, arg, target=None):
            """Run a route against the open case's App, or against the hub for the start page's routes. A case route
            from a page that names another open than the App's (CASE_HEADER) is refused before it runs: a tab still
            showing case A would mark, note, and set settings in case B, which a second tab opened on the same
            server. A request without the header, from a client other than the page, runs without the check; the page
            sends it on every request once /api/meta has named the open. A page whose case was opened again, from
            another tab, is told so, not that another case is open. A case route counts itself on the App it runs on
            (App.enter), which keeps that App's connection open until the route ends though a switch of case has
            published another meanwhile; an App already retired is passed over for the hub's current one."""
            if target is not None:
                return self._answer(route, arg, target)
            while True:
                app = hub.app   # read once, so the check and the route see the same App
                if app is None:
                    return self._json(409, {"error": "No case is open.", "no_case": True})
                if app.enter():
                    break
            try:
                sent = self.headers.get(CASE_HEADER)
                if sent is not None and sent != app.case_id:
                    again = sent in hub.opened and hub.opened[sent] == app.case.folder
                    return self._json(409, {"error": "This case was opened again in another tab or window. Reload the "
                                                     "page to go on; this page's request did nothing." if again else
                                                     f"Another case is open now: {app.case.settings.name}. Reload "
                                                     "the page to work on it; this page's request did nothing.",
                                            "case_changed": True})
                return self._answer(route, arg, app)
            finally:
                app.leave()

        def _answer(self, route, arg, target):
            t0 = time.perf_counter()
            try:
                result = route(target, arg)
            except (QueryError, JournalError, ValueError, KeyError, CaseError) as exc:
                return self._json(400, {"error": str(exc)})
            except Exception as exc:   # noqa: BLE001  (a fault still gets an answer the page can show)
                traceback.print_exc()   # for the console `serve` runs in
                return self._json(500, {"error": f"{type(exc).__name__}: {exc}"})
            result["server_ms"] = round((time.perf_counter() - t0) * 1000, 1)
            self._json(200, result)

        def _length(self) -> int:
            """_body_length. A length it refuses leaves the body unread, so the connection closes after the answer: kept
            alive, it would read the body as the next request."""
            try:
                return self._body_length()
            except BodyError:
                self.close_connection = True
                raise

        def _body_length(self) -> int:
            """The body's length by Content-Length, or 0 when the request has neither it nor Transfer-Encoding (RFC
            9112, 6.3). Raises BodyError for a length the server won't read by."""
            if "Transfer-Encoding" in self.headers:   # the server reads by Content-Length only
                codings = ",".join(self.headers.get_all("Transfer-Encoding")).split(",")
                if codings[-1].strip(" \t").lower() != "chunked":   # the body's end can't be found (RFC 9112, 6.3)
                    raise BodyError(400, "Transfer-Encoding must end with chunked.")
                raise BodyError(411, "Send the body with a Content-Length.")
            values = [v.strip(" \t") for v in self.headers.get_all("Content-Length", ["0"])]
            if len(values) > 1 or not (values[0].isascii() and values[0].isdigit()):
                raise BodyError(400, "Content-Length must be a single number.")
            digits = values[0].lstrip("0") or "0"
            if len(digits) > len(str(MAX_BODY)) or int(digits) > MAX_BODY:   # int() refuses over 4,300 digits
                raise BodyError(413, f"The body is over {MAX_BODY:,} bytes.")
            return int(digits)

        def _read_json(self) -> dict:
            """The POST body as a JSON object, {} when empty. Raises BodyError for a body the routes can't take."""
            data = self.rfile.read(self._length())
            try:
                body = json.loads(data or b"{}")
            except (ValueError, RecursionError):   # also bytes that don't decode, and nesting deeper than the stack
                raise BodyError(400, "invalid JSON") from None
            if not isinstance(body, dict):
                raise BodyError(400, "Send a JSON object.")
            return body

        def _refuse(self, code: int, text: str, obj: dict | None = None):
            """Refuse a POST after reading its body. Closed with the body unread, the connection is reset on Windows,
            and the reset can reach the client before it reads the refusal (WinError 10053 in the tests).
            A body whose length _length refuses isn't read. `obj` answers JSON instead of the text."""
            try:
                left = self._length()
            except BodyError:
                left = 0
            try:
                while left > 0 and (chunk := self.rfile.read(min(left, 65_536))):
                    left -= len(chunk)
            except (ConnectionAbortedError, ConnectionResetError):
                return   # the client went away while sending
            if obj is not None:
                self._json(code, obj)
            else:
                self._text(code, text)

        def _host_ok(self) -> bool:
            return self.headers.get("Host", "") in (f"127.0.0.1:{port_ref[0]}", f"localhost:{port_ref[0]}")

        def _cookie_ok(self) -> bool:
            cookie = SimpleCookie(self.headers.get("Cookie", ""))
            name = cookie_name(port_ref[0])
            return name in cookie and self._is_token(cookie[name].value)

        def _is_token(self, value: str) -> bool:
            # Compared as bytes: compare_digest refuses text with characters outside ASCII
            return secrets.compare_digest(value.encode(), hub.token.encode())

        def _site_ok(self) -> bool:
            """Whether the browser sent the request from this server's own pages, or from a link typed or opened from
            the command line (Sec-Fetch-Site same-origin or none). A page on another 127.0.0.1 port is same-site, so the
            cookie goes with its <img> or no-cors fetch, which sends no Origin. A client other than a browser sends no
            Sec-Fetch-Site and passes."""
            return self.headers.get("Sec-Fetch-Site", "none") in ("same-origin", "none")

        def _origin_ok(self) -> bool:
            origin = self.headers.get("Origin")
            return origin is None or origin in (f"http://127.0.0.1:{port_ref[0]}", f"http://localhost:{port_ref[0]}")

        def _json(self, code: int, obj: dict):
            self._send(code, "application/json", json.dumps(obj, default=str).encode())

        def _text(self, code: int, text: str):
            self._send(code, "text/plain; charset=utf-8", text.encode())

        def _send(self, code: int, ctype: str, body: bytes):
            # A reset means the page canceled this request, for example by zooming on before it finished.
            try:
                self._write(code, ctype, body)
            except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
                self.close_connection = True

        def _write(self, code: int, ctype: str, body: bytes):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            if ctype.startswith("text/html"):
                self.send_header("Content-Security-Policy", CSP)
            if self.close_connection:   # the request asked for it, or the body was left unread
                self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt, *args):
            pass

    return Handler


def _one(query: dict, name: str, default=None):
    value = query.get(name, [default])[0]
    if value is None:
        raise QueryError(f"missing parameter {name}")
    return value


def _number(body: dict, name: str, kind: type[int | float] = int, default=None) -> int | float:
    """A POST body's field read with int or float. A missing field, a null, a list, an object, or text that isn't a
    number raises QueryError naming the field, answered 400; int() and float() raise TypeError for some of these,
    which would answer 500 uncaught."""
    try:
        return kind(body.get(name, default))
    except (TypeError, ValueError, OverflowError):
        raise QueryError(f"{name} must be a number") from None


def case_key(case: Case) -> str:
    """A stable name for the case folder, for the preferences the browser keeps per case, such as the lane folds:
    the first 16 hex characters of the SHA-256 of the folder's resolved path, compared as Windows
    compares paths, without case. `App.case_id` names an open, and changes with every open."""
    return hashlib.sha256(os.path.normcase(str(case.folder.resolve())).encode("utf-8")).hexdigest()[:16]


def api_meta(app: App, query: dict) -> dict:
    cur = app.reader()
    start, end, rows = case_range(cur)
    return {"case": app.case.settings.name, "case_id": app.case_id, "case_key": case_key(app.case),
            "evidence": app.case.settings.evidence_path,
            "start": start, "end": end,
            "fit": fit_range(cur), "rows": rows, "presets": PRESETS, "keys": ["mark", "role", "host", "user", "tool", "artifact"],
            "hosts": [vars(h) for h in app.identity.hosts.values()], "identity_conflicts": app.identity.conflicts,
            "outside_sources": app.outside, "event_threshold": app.event_threshold, "orphan_marks": app.orphans,
            "time_window_seconds": app.time_window_seconds, "pivot_windows": app.pivot_windows, "build": build_id(),
            "analyst": app.case.settings.analyst,
            "time_zones": app.journal.state.settings.get("time_zones", []),
            "tactics": [{"id": tid, "name": name} for tid, name, _ in TACTICS],
            "clock_alignment": alignment(list(app.identity.hosts.values())),
            "case_state": _case_state(app), **page_names(), **_split_state(app)}


def _case_state(app: App) -> dict:
    """What the header's line under the case name says: whether the case was closed, from the journal's
    file, so a close the command line journals beside the server shows; the evidence intake hashed, with the files it
    couldn't read and the folders it couldn't list counted apart; and what the evidence checks found since
    (intake.evidence_checks), which a close outranks no more than any other check, with the files changed and those not
    re-read counted apart (overview.problem_files)."""
    _, close = journal_facts(app.journal.path)
    value = (close or {}).get("value")
    files = _manifest_facts(app)
    checks = evidence_checks(app.case)
    changed, not_reread = problem_files(checks["problems"])
    return {"closed": {"at": value.get("at") or close.get("at", "")} if isinstance(value, dict) else None,
            "intake": app.case.manifest_path.exists(), "evidence_files": files["hashed"], "added_files": files["added"],
            "unreadable": len(files["unreadable"]), "unlisted": len(files["unlisted"]),
            "checks": {**checks, "changed_files": len(changed), "not_reread": len(not_reread)},
            "journal": _journal_state(app)}


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _journal_state(app: App) -> dict:
    """The chain's state for the header's "Journal changed" and the page's read-only hints: whether it
    is broken, why the journal refuses writes, whether Continue with the break on record can apply (not to a journal
    that has not started its chain, which record_break refuses: no chained line, and no first line missing only its LF),
    and the head the app holds."""
    journal = app.journal
    reason = journal.read_only
    return {"broken": bool(reason), "read_only": reason, "can_continue": bool(reason) and journal._started(),
            "head": journal.chain.head, "short": short(journal.chain.head), "seq": journal.chain.seq}


def _journal_row(app: App) -> dict:
    """Integrity's Journal row: Check now's while the journal hasn't grown since, and otherwise the open's, with the
    head the app holds now."""
    last = app.last_check
    if last and last[0].seq == app.journal.chain.seq:
        return journal_row(app.journal, last[2], last[0], last[1])
    return journal_row(app.journal, app.opened_at)


def _refuse_on_break(app: App) -> None:
    """An export or report is refused on a broken chain before it writes its file: the journal would refuse the file's
    entry, and record_file would then remove the file."""
    if reason := app.journal.read_only:
        raise JournalError(reason)


def _manifest_facts(app: App) -> dict:
    """overview.manifest_facts for the manifest as it stands, read again only once Add new evidence changes it."""
    stamp = _stamp(app.case.manifest_path)
    if app.facts_cache is None or app.facts_cache[0] != stamp:
        app.facts_cache = (stamp, manifest_facts(read_manifest(app.case) if stamp else []))
    return app.facts_cache[1]


def api_case_state(app: App, query: dict) -> dict:
    """The header's case state again, after something that checks the evidence: the report, a run, an import,
    or the overview's own reading."""
    return _case_state(app)


@functools.cache
def page_names() -> dict[str, dict[str, str]]:
    """What the page calls each tool and each kind of event, by ID: the registry's tools, the makers
    of output found in the evidence, and the import; the parsers' artifacts and the import presets'. The page shows an
    ID that none names, such as a custom import's artifact, as it is."""
    tools = {k.tool: k.maker for k in KINDS if k.maker} | {s.id: s.name for s in load_registry().values()}
    artifacts = {p["artifact"]: p["label"].split(" (")[0] for p in IMPORT_PRESETS.values()} | ARTIFACT_NAMES
    artifacts["text_log"] = "Text log"   # its preset's label names its lines' form
    return {"tool_names": {**tools, IMPORT: "Import"}, "artifact_names": artifacts}


def _filter_sql(app: App, query: dict) -> str:
    fid = _one(query, "filter", "")
    return app.filter(fid)[1] if fid else ""


def _filter_cond(app: App, query: dict) -> str:
    fid = _one(query, "filter", "")
    return app.filter(fid)[2] if fid else "true"


def _view_sql(app: App, fid: str) -> str:
    """What the filter's View shows, for saying which pivot and search results it shows; 'true' with no filter."""
    if not fid:
        return "true"
    app.filter(fid)
    return app.filters.view_sql(fid)


def api_lanes(app: App, query: dict) -> dict:
    """The lanes and their counts, and, grouped by user, the label of each lane keyed by an account's lower-case name.
    For the state line: `shown`, how many events the filter shows over the whole case,
    which is the lanes' sum, but null by tactic, where an event with two tactics sits in two lanes (api_shown_counts
    counts those); and `machine_links`, the case's logon links by machine accounts, which Hide machine accounts leaves
    off the timeline. Neither costs a scan, so the redraw that waits on the lanes isn't held up."""
    cur, keys = app.reader(), parse_groupby(_one(query, "groupby", "mark,role,host"))
    found = lanes(cur, keys, _filter_sql(app, query))
    return {"lanes": found, "names": {"user": account_names(cur)} if "user" in keys else {},
            "shown": None if "tactic" in keys else sum(lane["count"] for lane in found),
            "machine_links": cur.execute("SELECT count(*) FROM logon_links WHERE machine").fetchone()[0]}


def sources_part(spec: dict) -> dict:
    """A filter's Sources choice alone. It hides something only with an only or a hide pred: a show pred only makes an
    exception to a hide (filters.condition)."""
    return {k: spec.get(k, []) for k in ("only", "hide", "show")}


def api_shown_counts(app: App, query: dict) -> dict:
    """The state line's counts that the lanes can't give, which the page asks for after the lanes answer,
    so no redraw waits on them: `shown`, the events the filter shows over the whole case, for lanes by tactic; and when
    a Sources choice hides something and a View is on, `sources_shown` and `view_shown`, what each part alone shows, so
    each pill counts its own hidden events and a View opened from the overview can say how many of its events the
    Sources hide. One scan counts them all, faded pivot results with the View."""
    fid = _one(query, "filter", "")
    spec, _, cond = app.filter(fid) if fid else ({}, "", "")
    counts = {"shown": cond or "true"}
    sources = sources_part(spec)
    if "view" in spec and (sources["only"] or sources["hide"]):
        counts["sources_shown"] = condition(sources) or "true"
        counts["view_shown"] = condition({"only": [], "hide": [], "show": [], "view": spec["view"],
                                          "faded": spec.get("faded", [])}) or "true"
    row = app.reader().execute(f"SELECT {', '.join(f'count(*) FILTER (WHERE {c})' for c in counts.values())} "
                               f"FROM {BASE_FROM} WHERE {BASE_WHERE}").fetchone()
    return dict(zip(counts, row, strict=True))


def api_view(app: App, query: dict) -> dict:
    fid = _one(query, "filter", "")
    return view(app.reader(), app.identity, parse_groupby(_one(query, "groupby", "mark,role,host")),
                int(_one(query, "start")), int(_one(query, "end")), int(_one(query, "buckets", "200")),
                int(_one(query, "limit", str(app.event_threshold))), _one(query, "hide_machine", "1") == "1",
                _filter_sql(app, query), app.filters.faded(fid) if fid else "false",
                links=_one(query, "links", "1") == "1",   # the page's Logon links checkbox
                outside=_one(query, "outside", "0") == "1")   # the status line's note while Fit case is in view


def api_event_keys(app: App, query: dict) -> dict:
    """Events' lane keys under the timeline's group-by and filter, by ID, for drawing an event that isn't a tick: an
    end of the link to a clock pair. Looked up by time, a crowded microsecond comes back as
    density cells, with no events and so no lane."""
    uids = [u for u in _one(query, "uids").split(",") if u]
    return {"keys": event_keys(app.reader(), parse_groupby(_one(query, "groupby", "mark,role,host")), uids,
                               _filter_sql(app, query))}


def api_marks(app: App, query: dict) -> dict:
    return {"counts": mark_counts(app.reader())}


def api_tags(app: App, query: dict) -> dict:
    return tag_counts(app.reader())


def _event_tags(app: App, uid: str) -> tuple[list[dict], list[dict]]:
    """An event's tags and suggested tags. Read without the lock, so the journal's tags are copied before the loop: a
    tag journaled meanwhile would change the dict as it is read and make the Event page answer 500."""
    applied = [{"key": k, "kind": tag_kind(k), "label": tag_label(k), **_technique(k), **info}
               for k, info in list(app.journal.state.tags.get(uid, {}).items())]
    applied.sort(key=lambda t: (tactic_order(t["key"]), t["kind"] != "technique", t["label"]))
    suggested = [{"key": r[0], "kind": r[1], "label": r[2], **_technique(r[0]), **({"origin": r[3]} if r[3] else {})}
                 for r in app.reader().execute("SELECT tag, kind, label, origin FROM tag_suggestions WHERE event_uid = ? "
                                               "ORDER BY ord, label", [uid]).fetchall()]
    return applied, suggested


def _technique(key: str) -> dict:
    """A technique tag's name for its hover, and the flag of an older one off the ATT&CK list."""
    if tag_kind(key) != "technique":
        return {}
    tid = tag_label(key)
    return {"name": attack.name(tid), **({"flag": f} if (f := attack.flag(tid)) else {})}


def api_tag(app: App, body: dict) -> dict:
    """Add or remove tags on events. Tags are typed or picked as text and stored as keys. An added technique
    must be in the ATT&CK list; a removed one need not be, so an older tag off the list can be taken off."""
    uids = body.get("uids") or []
    if not isinstance(uids, list) or not uids or len(uids) > MAX_MARK_TARGETS:
        raise QueryError(f"uids must be a list of 1 to {MAX_MARK_TARGETS} event IDs")
    try:
        add = [normalize_tag(t) for t in body.get("add") or []]
        remove = [normalize_tag(t, listed=False) for t in body.get("remove") or []]
    except TagError as exc:
        raise QueryError(str(exc)) from exc
    via = "hayabusa" if body.get("via") == "hayabusa" else ""
    with app.lock:   # an undo plans from the journal under it
        entry = app.journal.append("tag", targets=uids, add=add, remove=remove, **({"via": via} if via else {}),
                                   **_consent(body))
        app.rewrite(tags=uids)
    applied, suggested = _event_tags(app, uids[0])
    return {"seq": entry["seq"], "tagged": len(uids), "tags": applied, "suggested": suggested}


NAME_MESSAGE = 1000   # of an event's message in its trail name; the page cuts the name at a boundary


def _event_facts(app: App, uids: set[str]) -> dict[str, tuple[str, int | None]]:
    """Each event the audit trail names, as its name (host, event ID or artifact, and the message) and its clock-adjusted
    time. The name holds the message to NAME_MESSAGE characters, not a short cut that falls inside an address, and the
    page cuts it at a word boundary with the whole in its hover."""
    if not uids:
        return {}
    con = app.reader()
    wanted = id_table(con, "audit_events", sorted(uids))
    return {r[0]: (f"{r[1]} {r[2] or r[3]}: {r[4]}", r[5]) for r in con.execute(
        f"SELECT e.event_uid, e.host, e.event_code, e.artifact, left(e.message, {NAME_MESSAGE}), {TS} FROM events e "
        f"LEFT JOIN hosts h ON h.host = e.host WHERE e.event_uid IN (SELECT v FROM {wanted})").fetchall()}


def _event_names(app: App, uids: set[str]) -> dict[str, str]:
    """The names alone, for the trail's export and an undo's plan."""
    return {uid: name for uid, (name, _) in _event_facts(app, uids).items()}


def _trail_check(app: App) -> tuple[Check, dict | None]:
    """The journal's full check with its entries, for the trail, undo, and the export: each entry the state couldn't
    apply, or the trail can't read, is marked, so no reader of the trail stops on a changed line."""
    found, record = app.journal.full_check(keep=True)
    found.entries = mark_unreadable(found.entries)
    return found, record


def api_audit(app: App, query: dict) -> dict:
    """The audit trail, newest first, filtered by kind, analyst, text, corrections, or one event."""
    # A full check, whose entries the trail lists with the chain's state and head; a break it finds
    # puts the journal in read-only mode
    found, record = _trail_check(app)
    entries = found.entries
    event = _one(query, "event", "")
    moved = renamed(app.journal.state, event) if event else None
    also = None
    if moved:
        if app.reader().execute("SELECT 1 FROM events WHERE event_uid = ? LIMIT 1", [event]).fetchone():
            also = _also_named(moved)   # a loaded event's ID, so the trail keeps it
        else:
            event = moved[0]   # an ID an upgrade changed, as the Event page reads it (api_event): the trail reads new IDs
    out = rows(entries, {}, kind=_one(query, "kind", ""), who=_one(query, "who", ""), q=_one(query, "q", ""),
               corrections=_one(query, "corrections", "0") == "1", event=event,
               offset=int(_one(query, "offset", "0")), limit=int(_one(query, "limit", "200")))
    # Name single events only for the rows on this page, then describe them again with the names, each row carrying the
    # event it names, with the name cut for the page and its whole for the hover
    shown = {r["seq"] for r in out["rows"]}
    page = [e for e in entries if e["seq"] in shown]
    facts = _event_facts(app, single_targets(page))
    if facts:
        names = {uid: name for uid, (name, _) in facts.items()}
        times = {uid: ts for uid, (_, ts) in facts.items()}
        described = {r["seq"]: r for r in rows(page, names, offset=0, limit=len(page), times=times)["rows"]}
        for r in out["rows"]:
            r["text"], r["event"] = described[r["seq"]]["text"], described[r["seq"]]["event"]
    if also:
        out["id_also_named"] = also
    out["journal"] = journal_row(app.journal, _now(), found, record)
    return out


def _also_named(moved: tuple[str, list[int]]) -> dict:
    """The notice for an ID that names a loaded event and is also an earlier ID that an upgrade gave another event: the
    old ID's successor and the upgrades' entry numbers. A remap can pair one event's old ID with the ID another event
    has now (two spellings of one instant in one EVE file, for one), so the event the ID names now is shown, and this
    says that the entries made under it before the upgrade belong to the other."""
    return {"now": moved[0], "seqs": moved[1]}


def api_audit_events(app: App, query: dict) -> dict:
    """The events an entry touched, for the trail's "N events" link."""
    seq = int(_one(query, "seq"))
    entry = next((e for e in read_entries(app.journal.path) if e["seq"] == seq), None)
    if entry is None:
        raise QueryError(f"There's no entry #{seq}.")
    try:
        total, events = _entry_events(app, entry)
    except REPLAY_ERRORS as exc:   # a changed line the trail marks damaged names no events
        raise QueryError(f"Entry #{seq}'s stored payload can't be read.") from exc
    return {"seq": seq, "total": total, "events": events}


def _entry_events(app: App, entry: dict) -> tuple[int, list[dict]]:
    """How many events an audit entry touched, and the first LISTED_EVENTS of them in time order, of its first 2,000."""
    uids = entry_targets(entry)
    return len(uids), _listed_events(app, "audit_targets", uids[:2000])


def api_selected(app: App, query: dict) -> dict:
    """The selected events and their current marks, which the verdict zone lists when several are selected, so a group
    mark can't replace a Malicious mark the zone never showed. The page sends up to LISTED_EVENTS IDs."""
    uids = query.get("uid", [])
    return {"total": len(uids), "events": _listed_events(app, "selected_events", uids[:LISTED_EVENTS])}


def _listed_events(app: App, table: str, uids: list[str]) -> list[dict]:
    """Events by ID as the page lists them: time, host, event code, message, current mark, and artifact (for a finding's
    chips, which name a record with no code by its kind), at most LISTED_EVENTS, in time order, with events at one
    time, and those without one last, in ID order."""
    con = app.reader()
    wanted = id_table(con, table, uids)
    found = con.execute(f"SELECT e.event_uid, {TS} AS ts, e.host, e.event_code, left(e.message, 160), {MARK_EXPR}, e.artifact "
                        f"FROM {BASE_FROM} WHERE e.event_uid IN (SELECT v FROM {wanted}) "
                        f"ORDER BY ts NULLS LAST, e.event_uid LIMIT {LISTED_EVENTS}").fetchall()
    return _mark_info(app, [{"uid": r[0], "ts": r[1], "host": r[2], "code": r[3], "msg": r[4], "mark": r[5], "artifact": r[6],
                             "shown": True} for r in found])


def _mark_info(app: App, events: list[dict]) -> list[dict]:
    """Who set each listed event's mark, and when, as `mark_who` and `mark_at`, for the review-state badge's hover.
    One lookup per row in the journal's state, never a walk over it: a mark journaled meanwhile changes the dict, and
    a walk over it can raise. The state is ahead of the table between a journal append and the table's
    rewrite, so a mark whose label is not the row's gives the row no detail, and its badge keeps its letter. Unreviewed
    rows and pending suggestions have no mark to name. After an undo the entry is the undo's, as on the Event page."""
    marks = app.journal.state.marks
    for e in events:
        m = marks.get(e["uid"])
        if m is not None and MARK_LABELS.get(m.value) == e["mark"]:
            e["mark_who"], e["mark_at"] = m.who, m.at
    return events


def api_undo_plan(app: App, query: dict) -> dict:
    """What undoing an entry would change, for the confirmation, without writing anything."""
    try:
        plan = plan_undo(_checked_entries(app), int(_one(query, "seq")))
    except AuditError as exc:
        raise QueryError(str(exc)) from exc
    return {"seq": plan["entry"]["seq"], "changes": len(plan["changes"]), "changed": len(plan["changed"]),
            "kept": len(plan["kept"]),
            "text": rows([plan["entry"]], _event_names(app, single_targets([plan["entry"]])))["rows"][0]["text"]}


def api_undo(app: App, body: dict) -> dict:
    """Undo an entry as a correction of an accident: one new entry holding the reversing changes. The plan, its
    append, and the rewrite hold the lock, which every other entry an undo reads is appended under: planned outside
    it, a mark made while the plan ran would be overwritten, as if no event had changed since. The
    plan reads the whole journal: undoing a mark of 200,000 events in a 36 MB journal held the lock 2.2 s, 0.8 s of it
    reading and planning. Requests that only read don't wait for it, except those
    that take the lock briefly: a search not yet saved, to name its matches, waited 1.8 s.
    api_undo_plan's preview plans without the lock."""
    seq = _number(body, "seq", default=0)
    with app.lock:
        try:
            plan = plan_undo(_checked_entries(app), seq)
        except AuditError as exc:
            raise QueryError(str(exc)) from exc
        if not plan["changes"]:
            raise QueryError(f"Nothing left to undo: every event in #{plan['entry']['seq']} was changed since.")
        entry = app.journal.append("undo", undoes=plan["entry"]["seq"], correction="accident", changes=plan["changes"],
                                   kept=len(plan["kept"]), note=str(body.get("note", "")).strip())
        uids = plan["changed"]
        kinds = {c["action"] for c in plan["changes"]}
        app.rewrite(marks=uids if "mark" in kinds else (), tags=uids if kinds & {"tag", "tag_suggestion"} else (),
                    suggestions="suggestion_decision" in kinds)
    return {"seq": entry["seq"], "changed": len(uids), "kept": len(plan["kept"])}


def _checked_entries(app: App) -> list[dict]:
    """The entries an undo plans from, by a full check that refuses on a break: an edited older line could otherwise
    yield a validly chained undo."""
    found, _ = _trail_check(app)
    _refuse_on_break(app)
    return found.entries


def api_note_retract(app: App, body: dict) -> dict:
    """Retract a note: it stays on record, marked retracted. Checked and journaled under the lock, so two
    retractions of one note can't both pass the check."""
    uid, note_seq = body.get("uid"), body.get("note_seq")
    with app.lock:
        notes = app.journal.state.notes.get(uid or "", [])
        note = next((n for n in notes if n["seq"] == note_seq), None)
        if note is None:
            raise QueryError("There's no such note on this event.")
        if note.get("retracted"):
            raise QueryError(f"That note was already retracted by #{note['retracted']['seq']}.")
        entry = app.journal.append("note_retract", target=uid, note_seq=note_seq)
    return {"seq": entry["seq"]}


def api_audit_export(app: App, body: dict) -> dict:
    """Write the whole trail as Markdown to the case's exports folder, for training or review. Its opening line names
    the head of the full check whose entries it lists, so the two agree, and its file entry follows."""
    found, record = _trail_check(app)
    _refuse_on_break(app)
    entries = found.entries
    # An entry of several events lists them under it, as the trail's "N events" does
    listed = {e["seq"]: _entry_events(app, e) for e in entries if len(entry_targets(e)) > 1}
    row = journal_row(app.journal, _now(), found, record)
    text = markdown(entries, app.case.settings.name, _event_names(app, single_targets(entries)), listed,
                    head=(found.head, found.seq), chain=row["summary"][0])
    path = export_path(app.case, "audit_trail", "md")
    path.write_text(text, encoding="utf-8")
    payload = file_payload(app.case, path, kind="audit_trail", fmt="md", rows=len(entries),
                           head=(found.head, found.seq) if isinstance(found.seq, int) else None)
    entry, head = record_file(app.journal, payload, path, app.lock)
    return {"path": str(path), "entries": len(entries), **_head_after(entry, head)}


def _head_after(entry: dict, head: str) -> dict:
    """The head after a file's entry, which the page's notice shows with Copy."""
    return {"head": head, "head_seq": entry["seq"], "head_short": short(head)}


def api_tag_suggestion(app: App, body: dict) -> dict:
    """Dismiss Hayabusa's suggested tags on events, or restore them."""
    uids = body.get("uids") or []
    if not isinstance(uids, list) or not uids or len(uids) > MAX_MARK_TARGETS:
        raise QueryError(f"uids must be a list of 1 to {MAX_MARK_TARGETS} event IDs")
    with app.lock:   # an undo plans from the journal under it
        entry = app.journal.append("tag_suggestion", targets=uids, tags=body.get("tags") or [],
                                   decision=body.get("decision"))
        app.rewrite(tags=uids)
    return {"seq": entry["seq"]}


def _ts(query: dict) -> int | None:
    """The time the page shows an event at, which narrows the lookup of the event by its ID."""
    ts = _one(query, "ts", "")
    return int(ts) if ts else None


def api_event(app: App, query: dict) -> dict:
    """An event's page. An earlier ID that a case format upgrade changed, such as one pasted from an export made before
    it, opens the event it names now, which says so; it resolves when the journal named it, as only those IDs are in the
    upgrade's record. An ID that names a loaded event and is also an earlier ID the upgrade
    gave another event opens the event it names, with `id_also_named` pointing at the other."""
    uid = _one(query, "uid")
    details = event_details(app.reader(), uid, app.identity, _ts(query))
    moved = renamed(app.journal.state, uid) if details is None else None
    if moved:
        details = event_details(app.reader(), moved[0], app.identity, None)
    if details is None:
        left = [(r["seq"], len(rekey_map(r, "unplaced")[uid])) for r in app.journal.state.rekeys
                if isinstance(rekey_map(r, "unplaced").get(uid), list)]
        if left:   # named more than one event before an upgrade, and names none of them now
            seq, n = left[0]
            raise QueryError(f"This event ID named more than one event before the case format upgrade at #{seq}, so the "
                             f"journal's entries naming it were left as written. It names none now; the {n} events it "
                             "may have meant each say so, and the Case overview counts it.")
        raise QueryError("unknown event")
    if moved:
        details["id_changed"] = {"from": uid, "seqs": moved[1]}
        uid = moved[0]
    elif also := renamed(app.journal.state, uid):   # a loaded event's ID that an upgrade also changed to another's
        details["id_also_named"] = _also_named(also)
    # Entries made before an upgrade under an ID it couldn't place on one event, which may have meant this one
    details["unplaced"] = [{"seq": u["seq"], "id": u["id"], "others": len(u["candidates"]) - 1}
                           for u in unplaced(app.journal.state).get(uid, [])]
    details["evidence_sha256"] = app.manifest.get(details.get("source_file", ""), "")
    details["notes"] = app.journal.state.notes.get(uid, [])
    state = app.journal.state
    details["followup"] = state.followed.get(uid)   # Followed up: {seq, at, who}, kept when the mark changes
    # A rejected suggestion's note, by source
    details["rejection_notes"] = {source: note for (target, source), note in state.decision_notes.items()
                                  if target == uid}
    # What this kind of record does not prove, from the caveat table; and the open findings this event supports
    details["caveat"] = caveat_for(details)
    details["findings"] = [{"id": fid, "number": n, "title": f["title"]}
                           for n, (fid, f) in enumerate(sorted(state.findings.items()), 1)
                           if not f["retired"] and uid in f["targets"]]
    mark = app.journal.state.marks.get(uid)   # who set the current mark, and when; Unreviewed has no entry
    if mark:
        details["mark"].update(who=mark.who, at=mark.at)
    details["tags"], details["tag_suggestions"] = _event_tags(app, uid)
    # The page's additions to the event: a fault in either is shown in its place, and never hides the event
    try:
        details["provenance"] = _provenance(app, details)
    except Exception as exc:   # noqa: BLE001  (answered as _api answers a fault)
        traceback.print_exc()
        details["provenance"] = {"sha256": "", "state": "error", "text": f"could not be read ({type(exc).__name__}: {exc})",
                                 "checks": 0}
    try:
        details["pivots"] = guidance(details, app.identity, app.pivot_windows, app.time_window_seconds)
    except Exception as exc:   # noqa: BLE001
        traceback.print_exc()
        details["pivots"] = {"error": f"{type(exc).__name__}: {exc}"}
    app.keep_anchor(uid, details)
    details["pair"], details["clock"] = _event_clock(app, details)
    # Moved by a split by recorded computer: the host it was loaded under and the split that moved it. After a
    # second split of the host, that's the entry whose new hosts include the event's, not the latest.
    splits = app.journal.state.split_info.get(details.get("origin_host") or "", [])
    if details.get("origin_host") and details["origin_host"] != details["host"] and splits:
        info = next((i for i in splits if details["host"] in i["lanes"]), splits[-1])
        details["split"] = {"from": details["origin_host"], "seq": info["seq"], "at": info["at"]}
    return {"event": details}


def _provenance(app: App, details: dict) -> dict:
    """The evidence file's hash against the intake manifest, for the Event page's one line of provenance: the hash intake
    took, and what the case's checks since have found of the file. The re-hash each run and each full check makes
    names the files that changed and those it couldn't read (intake.evidence_checks, overview.problem_files), so a file
    no check names matches intake, unless a line of the check log that can't be read may have named it."""
    path = details.get("source_file", "")
    sha = app.manifest.get(path, "")
    unreadable = any(well_formed(f["path"]) == path for f in _manifest_facts(app)["unreadable"])
    stamp = _stamp(app.case.verification_path)   # read again only when a check adds to the log
    if app.checks_cache is None or app.checks_cache[0] != stamp:
        app.checks_cache = (stamp, evidence_checks(app.case))
    checks = app.checks_cache[1]
    changed, not_reread = problem_files(checks["problems"])
    problem = next((found for rel, found in changed.items() if well_formed(rel) == path), "")
    unread = next((found for rel, found in not_reread.items() if well_formed(rel) == path), "")
    lines = checks["unreadable_lines"]
    if unreadable:
        state, text = "unreadable", "intake could not read this file, so it has no hash to check"
    elif not sha:
        state, text = "absent", "not in the intake manifest"
    elif problem:
        state, text = "changed", f"differs from intake ({problem})"
    elif unread:
        state, text = "unreadable", f"could not be re-read {unread.removeprefix('unreadable ')}, so not compared with intake"
    elif lines:
        state, text = "uncounted", (f"no readable check found it changed; {lines:,} check-log "
                                    f"{'line' if lines == 1 else 'lines'} unreadable")
    elif not checks["checks"]:
        state, text = "unchecked", "the intake hash; nothing has re-checked the file since"
    else:
        state, text = "matches", "matches intake"
    return {"sha256": sha, "state": state, "text": text, "checks": checks["checks"], "unreadable_lines": lines}


def _event_clock(app: App, details: dict) -> tuple[dict | None, dict | None]:
    """The event's other half when the clock check paired it with the capture, and the measured host's clock result
    when its offset fits the event. The host is the event's own, or for a capture record,
    its pair's; `clock.host` names it. A pair always fits: it's what the offset was measured on."""
    pair = event_pairs(app.reader(), [details["event_uid"]]).get(details["event_uid"])
    host = pair["host"] if pair and not pair["in_capture"] else details["host"]
    h = app.identity.hosts.get(host)
    result = h.clock if h else {}
    if result.get("state") not in MEASURED or not (pair or in_segment(result, details["ts_us"])):
        return pair, None
    return pair, {"host": host, **{k: result[k] for k in EVENT_CLOCK}}


def api_related(app: App, query: dict) -> dict:
    """A pivot's results. The IP pivot at either end (kind=addr) names one of the event's addresses as `ip`; Same file name
    on a kind of event with a fixed name, the name as `name`. `unreviewed=1` keeps the list to events with no mark, so
    the list a To investigate count opens has the count as its total."""
    seconds = int(_one(query, "seconds", str(app.time_window_seconds)))
    fid = _one(query, "filter", "")
    out = related(app.reader(), _one(query, "uid"), _one(query, "kind"), seconds,
                  _view_sql(app, fid), _one(query, "ip", ""), app.identity, _ts(query), _source(query),
                  _one(query, "scope", ""), checked_name(_one(query, "name", "")), _flag(query, "unreviewed"))
    _mark_info(app, out["events"])
    return out


def _flag(query: dict, name: str) -> bool:
    """A query parameter that is on when it is 1."""
    return _one(query, name, "") == "1"


def _source(query: dict) -> list[str] | None:
    """The source a pivot's list is narrowed to, as the page names it: a JSON list of the evidence type and up to three more
    parts (queries.source_parts)."""
    text = _one(query, "source", "")
    if not text:
        return None
    try:
        source = json.loads(text)
    except ValueError:
        raise QueryError("source must be a JSON list of text") from None
    if not isinstance(source, list):
        raise QueryError("source must be a JSON list of text")
    return source


def api_pivot_count(app: App, query: dict) -> dict:
    """One row of the Event page's next pivots counted, once the page has drawn: how many events the pivot's click lists
    across the whole case (not within the View), and with `breakdown` their top sources. `check` asks the case a caveat's
    question with it. A row's breakdown for a window is always asked; the others' only when the count passed the list's
    limit."""
    seconds = int(_one(query, "seconds", str(app.time_window_seconds)))
    uid, ts = _one(query, "uid"), _ts(query)
    return count_pivot(app.reader(), app.identity, uid, ts, _one(query, "kind"),
                       ip=_one(query, "ip", ""), seconds=seconds, term=_one(query, "term", ""),
                       breakdown=_flag(query, "breakdown"), scope=_one(query, "scope", ""),
                       check=_one(query, "check", ""), anchor=app.anchor(uid, ts), name=_one(query, "name", ""),
                       unreviewed=_flag(query, "unreviewed"))


SETTINGS = {"time_window_seconds": WINDOW_RANGE_SECONDS, "event_threshold": (1_000, 500_000)}
SUMMARY_MAX = 20_000   # characters of the report's Summary, the analyst's paragraph


def api_setting(app: App, body: dict) -> dict:
    """A case setting, journaled under the lock as every analysis entry is: a time zone axis is
    checked against the hosts, which a host edit rebuilds under it."""
    name = body.get("name")
    if name == "time_zones":   # the zone axes under the UTC axis, saved with the case
        with app.lock:
            value = validate_axes(body.get("value"), set(app.identity.hosts))
            app.journal.append("case_setting", name=name, value=value)
        return {"name": name, "value": value}
    if name == "pivot_windows":   # the time window per kind of event: {kind: seconds, or null to go back to the table's}
        return {"name": name, "value": _set_pivot_windows(app, body.get("value"))}
    if name == "report_summary":   # the report's Summary, in the analyst's words; empty clears it
        value = body.get("value")
        if not isinstance(value, str) or len(value) > SUMMARY_MAX:
            raise QueryError(f"report_summary is text of at most {SUMMARY_MAX:,} characters")
        value = value.replace("\r\n", "\n").strip()
        with app.lock:
            app.journal.append("case_setting", name=name, value=value)
        return {"name": name, "value": value}
    if name not in SETTINGS:
        raise QueryError(f"setting must be one of {sorted([*SETTINGS, 'time_zones', 'pivot_windows', 'report_summary'])}")
    lo, hi = SETTINGS[name]
    value = _number(body, "value")
    if not lo <= value <= hi:
        raise QueryError(f"{name} must be {lo} to {hi}")
    with app.lock:
        app.journal.append("case_setting", name=name, value=value)
    return {"name": name, "value": value}


def _set_pivot_windows(app: App, edits) -> dict[str, int]:
    """Change some kinds' windows and journal all of them, under the lock so two edits can't each drop the other's."""
    kinds = window_kinds()
    lo, hi = WINDOW_RANGE_SECONDS
    if not isinstance(edits, dict) or not edits:
        raise QueryError("value must name the kinds of event whose window changes")
    for kind, seconds in edits.items():
        if kind not in kinds:
            raise QueryError(f"{kind} is not a kind of event with a time window")
        if seconds is not None and not (isinstance(seconds, int) and not isinstance(seconds, bool) and lo <= seconds <= hi):
            raise QueryError(f"a time window must be {lo} to {hi} seconds")
    with app.lock:
        merged = {**app.pivot_windows, **{k: v for k, v in edits.items() if v is not None}}
        for kind, seconds in edits.items():
            if seconds is None:
                merged.pop(kind, None)
        app.journal.append("case_setting", name="pivot_windows", value=merged)
    return merged


def api_mark(app: App, body: dict) -> dict:
    uids = body.get("uids") or []
    if not isinstance(uids, list) or len(uids) > MAX_MARK_TARGETS:
        raise QueryError(f"uids must be a list of at most {MAX_MARK_TARGETS} event IDs")
    # Under the lock, which an undo plans and an accept reads the pending suggestions under; a rewrite also reads
    # the journal's state, which an append outside it would change as it reads
    with app.lock:
        entry = app.journal.append("mark", targets=uids, value=body.get("value"), note=str(body.get("note", "")),
                                   **({"filter": body["filter"]} if body.get("filter") else {}), **_consent(body))
        app.rewrite(marks=uids)
    return {"seq": entry["seq"], "marked": len(uids)}


def _consent(body: dict) -> dict:
    """The `confirmed` record for a mark or a tag the analyst confirmed first (a hand-picked selection above 25
    events): the count the confirm stated, and no event skipped, since a mark or a tag covers every event it names."""
    count = _confirmed(body)
    return {"confirmed": {"count": count, "skipped": 0}} if count is not None else {}


def api_note(app: App, body: dict) -> dict:
    with app.lock:   # the report reads the notes under it
        entry = app.journal.append("note", target=body.get("uid"), text=str(body.get("text", "")))
    return {"seq": entry["seq"]}


def _hosts_payload(app: App) -> dict:
    return {"hosts": [vars(h) for h in app.identity.hosts.values()], "outside_sources": app.outside,
            "identity_conflicts": app.identity.conflicts,
            "clock_alignment": alignment(list(app.identity.hosts.values())),
            **_split_state(app)}


def _machines(app: App, con) -> dict:
    """The computers in each host's event logs, as refresh_identity found them. Only it stores them, under the lock,
    so a request that read the events before a load can't store what it found after the load cleared them."""
    return app.machines_cache.get("machines") or machines(con)


def _split_state(app: App) -> dict:
    """What the Hosts panel's split notices and lines read: the hosts whose logs record several computers,
    the splits in force, and the hosts kept as one host that could still be split."""
    return {"mixed": list(app.identity.mixed.values()), "splits": split_list(app.journal.state),
            "kept": kept_list(app.journal.state, app.identity, _machines(app, app.reader()))}


def _split_proposal(app: App, host: str) -> dict:
    con = app.reader()
    return proposal(con, app.journal.state, app.identity, host, _machines(app, con), intake_folders(app.case, app.manifest))


def api_host_split(app: App, query: dict) -> dict:
    """What splitting a host by recorded computer would do, for the Hosts panel's preview."""
    found = _split_proposal(app, _one(query, "host"))
    found.pop("routes")   # the server recomputes them when the split is made
    return found


def _host_split(app: App, body: dict) -> None:
    """Split a host by recorded computer, undo its splits, or keep it as one host. Each is a journal entry;
    the events table's lanes follow it in the same refresh. Refused while a tool runs, whose load read the journal's
    splits when it started. A split checks the preview's basis, so one made from a preview the evidence has outgrown
    is refused rather than splitting what the analyst didn't see."""
    state = app.journal.state
    with app.lock:
        # Under the lock, as the run endpoints start their jobs: a split that waited behind an import or an alignment
        # sees a job started meanwhile.
        if app.job and not app.job.finished:
            raise ValueError(f"{app.job.tool} is still running; split, keep, or undo once it finishes.")
        if "split" in body:
            plan = _split_proposal(app, str(body["split"]))
            if body.get("basis") != plan["basis"]:
                raise QueryError("The evidence changed since the preview. Open the preview again.")
            app.journal.append("host_split", op="split", host=plan["host"], routes=plan["routes"],
                               groups=[{k: g[k] for k in ("lane", "names", "events", "hayabusa", "files")}
                                       for g in plan["groups"]],
                               stays=[n for c in plan["stays"]["computers"] for n in c["names"]])
        elif "unsplit" in body:
            host = str(body["unsplit"])
            if host not in state.splits:
                raise QueryError(f"{host} isn't split.")
            app.journal.append("host_split", op="undo", host=host, undoes=[i["seq"] for i in state.split_info[host]])
        else:
            host = str(body["keep_host"])
            if host not in app.identity.mixed:
                raise QueryError(f"{host}'s event logs don't record several computers.")
            app.journal.append("host_split", op="keep", host=host, computers=kept_keys(_machines(app, app.reader()), host))
            # No lane changes, so saved searches, the clock measurement, and the computers found all stay valid;
            # the identity is built again for the notice.
            app.refresh_identity()
            return
        app.refresh_identity(events_changed=True)   # moves the lanes, and redoes saved searches and Sources


def _align(app: App, to: str, host: str | None) -> None:
    """The Case panel's switch. "capture" applies each suggested offset, and "recorded"
    sets back to 0 each offset the switch set, whatever its host's clock state is now, and leaves typed ones alone;
    `host` limits it to one host. Each change is an ordinary host_offset entry, which for "capture" also records the
    reference and the basis, for the audit trail."""
    if to not in ("capture", "recorded"):
        raise QueryError("align must be capture or recorded")
    if host is not None and host not in app.identity.hosts:
        raise QueryError("unknown host")
    changes = []
    for h in app.identity.hosts.values():
        if host not in (None, h.host):
            continue
        c = h.clock
        if to == "capture" and c.get("state") == "suggest":
            if not -MAX_OFFSET_SECONDS <= c["seconds"] <= MAX_OFFSET_SECONDS:
                raise QueryError(f"{h.host}'s suggested offset, {c['display']}, is more than one day")
            changes.append({"host": h.host, "seconds": c["seconds"], "align": "capture", "reference": c["reference"],
                            "basis": c["basis_text"]})
        elif to == "recorded" and h.offset_aligned:
            changes.append({"host": h.host, "seconds": 0.0, "align": "recorded"})
    for change in changes:
        app.journal.append("host_offset", **change)


def api_host(app: App, body: dict) -> dict:
    if "align" in body:
        # One alignment at a time, from reading the clocks to the rebuild, so a second one reads the offsets the first
        # set and finds nothing left to change.
        with app.lock:
            _align(app, str(body["align"]), None if body.get("host") is None else str(body["host"]))
            app.refresh_identity()
        return _hosts_payload(app)
    if "confirm_hosts" in body:
        # Confirm journals each host's guessed role as checked by the analyst, then rebuilds once. The guess is read
        # under the lock, so a role typed meanwhile, whose rebuild waits for it, isn't replaced.
        names = [str(n) for n in body["confirm_hosts"]]
        with app.lock:
            unknown = [n for n in names if n not in app.identity.hosts]
            if unknown or not names:
                raise QueryError(f"unknown host: {unknown[0]}" if unknown else "no hosts to confirm")
            for name in names:
                h = app.identity.hosts[name]
                if h.role_source == "guess":
                    app.journal.append("host_role", host=name, role=h.role, confirmed=True)
            app.refresh_identity()
        return _hosts_payload(app)
    if body.keys() & {"split", "unsplit", "keep_host"}:   # before the check below: a split host may have no lane left
        _host_split(app, body)
        return _hosts_payload(app)
    host = body.get("host")
    # Each edit from its check through its append and rebuild under the lock, as an alignment is: an alignment that
    # read the clocks before a typed offset's rebuild would set back to 0 the offset just typed
    with app.lock:
        if host not in app.identity.hosts:
            raise QueryError("unknown host")
        if "role" in body:
            app.journal.append("host_role", host=host, role=str(body["role"]).strip())
        elif "offset_seconds" in body:
            seconds = _number(body, "offset_seconds", float)
            if not -MAX_OFFSET_SECONDS <= seconds <= MAX_OFFSET_SECONDS:
                raise QueryError(f"a clock offset must be within {MAX_OFFSET_SECONDS:,} seconds (one day)")
            app.journal.append("host_offset", host=host, seconds=seconds)
        else:
            op, value = body.get("op"), str(body.get("value", "")).strip()
            if op == "add_ip" and not normalize_ip(value):   # it would never match an event's address
                raise QueryError(f"{value or 'That'} isn't an IP address.")
            app.journal.append("host_identity", host=host, op=op, value=value)
        app.refresh_identity()
    return _hosts_payload(app)


def ensure_builtin_rules(journal: Journal) -> None:
    """Add built-in rules a case does not have yet, unless the analyst removed them, and bring a built-in rule the
    analyst hasn't changed up to the app's current text. Rules that read the parser's messages change when the parser
    does; an analyst's own change clears the rule's built-in mark, so it stays."""
    for rule_id, text in BUILTIN_RULES.items():
        stored = journal.state.rules.get(rule_id)
        if stored is None:
            if rule_id not in journal.state.removed_rules:
                journal.append("rule_add", who=SYSTEM, id=rule_id, text=text, builtin=True)
        elif stored["builtin"] and stored["text"] != text:
            journal.append("rule_change", who=SYSTEM, id=rule_id, text=text, builtin=True)


def _rules_payload(app: App) -> dict:
    """Each suggestion source with its rule and its counts, which are read live: a mark changes them without building
    the suggestions again."""
    counts = suggestion_counts(app.reader())
    rules = []
    for source, info in sorted(app.suggestion_report.items()):
        stored = app.journal.state.rules.get(source)
        matched, pending = counts.get(source, (0, 0))
        rules.append({"id": source, "text": stored["text"] if stored else "", "who": stored["who"] if stored else SYSTEM,
                      "editable": stored is not None, **info, "matched": matched, "pending": pending})
    return {"rules": rules}


def api_rules(app: App, query: dict) -> dict:
    return _rules_payload(app)


def api_rule(app: App, body: dict) -> dict:
    """Add, change, or remove a rule. The check that it exists, or doesn't, holds the lock through the append and the
    suggestions' rebuild, so two requests can't both add one rule."""
    op = body.get("op")
    text = str(body.get("text", ""))
    parsed = parse_rule_request(op, text)
    with app.lock:
        rule_id = parsed.id if parsed else body.get("id")
        rule_known(app.journal.state.rules, op, rule_id)
        if op == "remove":
            app.journal.append("rule_remove", id=rule_id)
        else:
            app.journal.append(f"rule_{op}", id=parsed.id, text=text)
        app.refresh_suggestions()
    return _rules_payload(app)


def parse_rule_request(op, text: str):
    """The rule a request adds or changes, or None for a removal; QueryError for a request that can't be saved. The
    command line asks this, and rule_known, before it upgrades the case, so a bad request changes nothing."""
    if op not in ("add", "change", "remove"):
        raise QueryError("op must be add, change, or remove")
    if op == "remove":
        return None
    try:
        parsed = parse_rule(text)
    except RuleError as exc:
        raise QueryError(f"rule not saved: {exc}") from exc
    if parsed.id in BUILTIN_SOURCES:   # it would merge with that source's suggestions
        raise QueryError(f"rule not saved: {parsed.id} is a built-in suggestion source; choose another id")
    return parsed


def rule_known(rules: dict, op: str, rule_id) -> None:
    """QueryError unless the rule exists, or doesn't, as the operation needs, among `rules` (State.rules)."""
    exists = rule_id in rules
    if op == "remove" and not exists:
        raise QueryError("unknown rule")
    if op == "add" and exists:
        raise QueryError(f"a rule named {rule_id} already exists; change it instead")
    if op == "change" and not exists:
        raise QueryError(f"no rule named {rule_id}")


def api_suggestion(app: App, body: dict) -> dict:
    """Accept, reject, or restore one source's suggestions, for chosen events or all pending ones. The pending
    suggestions are read, and the decisions journaled and written, under the lock: read outside it, an accept could mark
    Malicious an event the analyst had marked Authorized meanwhile.

    A group action the analyst confirmed names the exact events the page counted in `uids` and the count its
    confirm stated in `confirmed: {count}`. The server acts on those alone, skips any no longer pending, answers how
    many it skipped, and records `confirmed: {count, skipped}` on the entry."""
    decision, source = body.get("decision"), body.get("source")
    if decision not in ("accept", "reject", "restore") or not source:
        raise QueryError("decision must be accept, reject, or restore, with a source")
    confirmed = _confirmed(body)
    with app.lock:
        changed, skipped = _decide(app, body, decision, source, confirmed)
    return {"changed": changed, "skipped": skipped, **_rules_payload(app)}


def _confirmed(body: dict) -> int | None:
    """The count a confirm stated, when the request carries one: with it the request names its events, and the entry
    records the consent. None when the action was not one that asks first."""
    if "confirmed" not in body:
        return None
    confirmed = body["confirmed"]
    count = confirmed.get("count") if isinstance(confirmed, dict) else None
    if not isinstance(count, int) or isinstance(count, bool) or count < 0:
        raise QueryError("confirmed gives the count the confirm stated, as {\"count\": N}")
    if not isinstance(body.get("uids"), list):
        raise QueryError("a confirmed action names the events it covers in uids")
    return count


def _decide(app: App, body: dict, decision: str, source: str, confirmed: int | None = None) -> tuple[int, int]:
    """api_suggestion's work, under the lock: how many events it decided, and how many of a confirmed request's events
    it skipped as no longer pending."""
    uids = body.get("uids")
    if "group" in body:   # a whole group from the Suggestions page, which lists only a group's first events
        try:
            uids = pending_group_uids(app.reader(), source, str(body.get("group_by", "")), str(body["group"]))
        except ValueError as exc:
            raise QueryError(str(exc)) from exc
        if not uids:
            return 0, 0
    pending = pending_for_source(app.reader(), source)
    still = {u for group in pending.values() for u in group}
    skipped = 0
    if confirmed is not None and decision != "restore":   # a confirmed action covers its counted events that are still pending
        asked = list(uids)
        uids = [u for u in asked if u in still]
        skipped = len(asked) - len(uids)
    consent = {"confirmed": {"count": confirmed, "skipped": skipped}} if confirmed is not None else {}
    if decision == "restore":
        targets = list(uids or [])
        if not targets:
            raise QueryError("restore needs uids")
        app.journal.append("suggestion_decision", targets=targets, source=source, decision="restored", **consent)
    elif decision == "reject":
        targets = list(uids) if uids or confirmed is not None else [u for group in pending.values() for u in group]
        note = str(body.get("note") or "").strip()   # a Reject's note, which the trail and the Event page show
        if targets:
            app.journal.append("suggestion_decision", targets=targets, source=source, decision="rejected",
                               **({"note": note} if note else {}), **consent)
    else:
        wanted = set(uids) if uids or confirmed is not None else None
        chosen = {value: [u for u in group if wanted is None or u in wanted] for value, group in pending.items()}
        total = sum(map(len, chosen.values()))
        if total > MAX_MARK_TARGETS:   # as a mark is capped; each accept is a mark
            fewer = ("Group the suggestions another way, by rule, host, account, or event ID, and accept smaller groups."
                     if "group" in body else "Accept fewer at a time." if uids else
                     "Accept them a group at a time from the source's Suggestions page.")
            raise QueryError(f"Accepting these would mark {total:,} events, more than the {MAX_MARK_TARGETS:,} a mark "
                             f"can hold. {fewer}")
        # The analyst's own note follows the fixed text. A source is a rule ID,
        # which holds no colon or space, or a built-in source's name, so the first ": " ends it.
        typed = str(body.get("note") or "").strip()
        note = f"Accepted suggestion from {source}" + (f": {typed}" if typed else "")
        targets = []
        for value, group in chosen.items():
            if group:
                app.journal.append("mark", targets=group, value=value, note=note, **consent)
                app.rewrite(marks=group)
                targets += group
    app.refresh_suggestions()
    return len(targets), skipped


def api_investigate(app: App, query: dict) -> dict:
    """The To investigate worklist: each Malicious or Suspicious event with who marked it, its Followed up tick
    (`followup`: the entry's seq, at, and who, and `after_mark` when the mark changed after the tick, which the row says),
    and the pivots the page counts beside it (`rows`, pivots.worklist_rows); and each
    suggestion source with its counts, its description, and for one with pending suggestions the events it would act on
    (`uids`) and the first few of them, which the confirm shows."""
    con = app.reader()
    state = app.journal.state
    items = investigate(con)
    for item in items:
        ev = item.pop("event")
        item["rows"] = worklist_rows(ev, app.identity, app.pivot_windows, app.time_window_seconds)
        tick = state.followed.get(item["uid"])
        mark = state.marks.get(item["uid"])
        item["followup"] = {**tick, "after_mark": bool(mark and mark.seq > tick["seq"])} if tick else None
    _mark_info(app, items)
    payload = _rules_payload(app)
    for rule in payload["rules"]:
        if rule.get("pending"):
            rule.update(pending_source_events(con, rule["id"]))
    return {"items": items, **payload}


PENDING_LIMIT_MAX = 5_000   # the most events a group lists when the page asks to show a whole group first


def api_pending(app: App, query: dict) -> dict:
    """One source's pending suggestions in groups. `limit` lists more than the first 200 of each group, up to
    PENDING_LIMIT_MAX, for the page's "Show all N first"."""
    source = _one(query, "source")
    # The built-in sources group by rule: Hayabusa rules, and the signatures of Suricata's and imported fast alerts
    default = "rule" if source in BUILTIN_SOURCES else "account"
    limit = min(max(int(_one(query, "limit", str(PENDING_LIMIT))), 1), PENDING_LIMIT_MAX)
    try:
        return pending_events(app.reader(), source, _one(query, "group_by", default), limit)
    except ValueError as exc:
        raise QueryError(str(exc)) from exc


def api_pending_uids(app: App, query: dict) -> dict:
    """The events pending now for a source, or for one group of it: the confirm compares them with the set the page
    counted when it loaded, to say how many arrived since and are not included."""
    source = _one(query, "source")
    if "group" in query:
        try:
            uids = pending_group_uids(app.reader(), source, _one(query, "group_by", ""), _one(query, "group"))
        except ValueError as exc:
            raise QueryError(str(exc)) from exc
    else:
        uids = [u for group in pending_for_source(app.reader(), source).values() for u in group]
    return {"uids": uids}


def _stamp(path: Path) -> tuple[int, int] | None:
    try:
        st = path.stat()
    except FileNotFoundError:
        return None
    return st.st_size, st.st_mtime_ns


def overview_key(app: App) -> tuple:
    """What the Case overview reads, as it stands: the derived tables' rewrites, the journal's length, the runs folder
    and the Tools page's job, whose runs' records change inside it, the manifest, and the evidence checks. A mark
    appends to the journal and then rewrites its rows, so an overview read between the two is kept under a key the
    rewrite's count makes stale; an import counts as a rewrite too, since it rewrites its run's record inside the runs
    folder, which leaves the folder's own time as it was (api_import)."""
    job = app.job
    case = app.case
    return (app.generation, app.loads, _stamp(app.journal.path), _stamp(case.runs_folder), _stamp(case.manifest_path),
            _stamp(case.verification_path), (id(job), job.finished, len(job.results)) if job else None)


def api_overview(app: App, query: dict) -> dict:
    """The Case overview, computed from the case database, the journal, the runs, the manifest, and the
    evidence checks, and kept until any of them changes (overview_key)."""
    key = overview_key(app)
    cached = app.overview_cache
    if cached is None or cached[0] != key:
        case = app.case
        runs = read_runs(case)
        specs = load_registry()
        entries = current_entries(case) if case.manifest_path.exists() else []
        names = page_names()
        result = case_overview(
            app.reader(), identity=app.identity, state=app.journal.state, report=app.suggestion_report,
            journal_path=app.journal.path, runs=runs, run_gaps=run_gaps(runs, specs),
            manifest=read_manifest(case) if case.manifest_path.exists() else [],
            unidentified=sum(1 for e in entries if e.artifact is None and not e.error), orphans=app.orphans,
            checks=evidence_checks(case), tool_names=names["tool_names"], artifact_names=names["artifact_names"],
            build=build_id(), alignment=alignment(list(app.identity.hosts.values())), journal=_journal_row(app))
        app.overview_cache = cached = (key, result)
    return dict(cached[1])


def api_lead_events(app: App, query: dict) -> dict:
    """The events of one of the overview's alert leads, for its Open on timeline, and with the page's
    filter, how many of them it hides, so the page can say so rather than select events it doesn't draw: by the
    Sources, and of those the Sources show, by the View (faded pivot results show)."""
    cur = app.reader()
    uids = lead_events(cur, _one(query, "tool"), _one(query, "host"), int(_one(query, "start")), int(_one(query, "end")))
    fid = _one(query, "filter", "")
    if not fid or not uids:
        return {"uids": uids, "hidden_sources": 0, "hidden_view": 0}
    spec, _, cond = app.filter(fid)
    sources = condition(sources_part(spec)) or "true"
    wanted = id_table(cur, "lead_uids", uids)
    hidden = cur.execute(f"SELECT count(*) FILTER (WHERE NOT ({sources})), count(*) FILTER (WHERE ({sources}) AND NOT "
                         f"({cond})) FROM {BASE_FROM} WHERE e.event_uid IN (SELECT v FROM {wanted})").fetchone()
    return {"uids": uids, "hidden_sources": hidden[0], "hidden_view": hidden[1]}


def api_view_events(app: App, query: dict) -> dict:
    """The events the page's View shows, listed for a click on an overview count that opened the timeline on them,
    so the Details panel holds the set the click named: the filter's View part alone, as the click's own count
    reads it, whatever the Sources hide."""
    fid = _one(query, "filter")
    spec = app.filter(fid)[0]
    if "view" not in spec:
        raise QueryError("the filter has no View to list")
    out = listed_events(app.reader(), app.filters.view_sql(fid))
    _mark_info(app, out["events"])
    return out


def api_counts(app: App, query: dict) -> dict:
    """The numbers on the case buttons."""
    cur = app.reader()
    flagged = cur.execute("SELECT count(*) FROM marks WHERE label IN ('Malicious', 'Suspicious')").fetchone()[0]
    pending = cur.execute("SELECT count(*) FROM suggested s LEFT JOIN marks m ON m.event_uid = s.event_uid "
                          "WHERE m.event_uid IS NULL").fetchone()[0]
    return {"flagged": flagged, "pending": pending,
            "hosts_review": sum(1 for h in app.identity.hosts.values() if h.review),
            "hosts_mixed": sorted(app.identity.mixed),   # named in the Hosts button's hover text
            "rule_errors": sum(1 for r in app.suggestion_report.values() if r.get("error"))}


def _export_filter(app: App, body: dict) -> tuple[str, str, dict | None]:
    """The view filter an export applies, only when the analyst ticked "Apply the current filters": its clause, its
    words, and its file entry's `filters`."""
    if not body.get("filter"):
        return "", "", None
    spec, sql, _ = app.filter(str(body["filter"]))
    text = describe(spec)
    return sql, text, {"text": text, "spec": spec}


def api_export(app: App, body: dict) -> dict:
    """A timeline export and its file entry, whose head the answer gives. With `marks` all it covers the
    window [start, end); marked and flagged cover the whole case whatever the window, as the report does, and their
    entry's scope has no start or end. The rows are read on a reader, without the lock, so marks and
    notes don't wait for an export; only the entry's append holds it. The entry says when the file was
    recorded, not which state its rows show, so it carries no head."""
    _refuse_on_break(app)
    extra, note, filters = _export_filter(app, body)
    fmt, marks = str(body.get("format", "csv")), str(body.get("marks", "all"))
    if marks in WHOLE_CASE:
        start = end = None
        scope = {"marks": marks}
    else:
        start, end = _number(body, "start"), _number(body, "end")
        scope = {"marks": marks, "start": int(start), "end": int(end)}
    path, rows = export_timeline(app.reader(), app.case, app.identity, start, end, fmt, marks, extra)
    payload = file_payload(app.case, path, kind="timeline", fmt=fmt, rows=rows, scope=scope, filters=filters)
    entry, head = record_file(app.journal, payload, path, app.lock)
    return {"path": str(path), "rows": rows, "filter": note, "scope": scope, **_head_after(entry, head)}


def api_report(app: App, body: dict) -> dict:
    """The report and its file entry. Under the lock, so nothing it prints, marks, notes, hosts,
    findings, or the summary, is newer or older than the head it prints, which comes from the journal whose state it
    reads, after a full check that refuses on a break."""
    extra, note, filters = _export_filter(app, body)
    with app.lock:
        found, record = app.journal.full_check()
        _refuse_on_break(app)
        journal = app.journal
        head = (journal.chain.head, journal.chain.seq)
        row = {**journal_row(journal, _now(), found, record), "head": head[0], "seq": head[1]}
        path, count = write_report(app.con, app.case, app.identity, app.manifest, journal.state, extra, note, journal=row)
        payload = file_payload(app.case, path, kind="report", fmt="md", rows=count,
                               scope={"marks": "flagged"}, filters=filters, head=head)
        entry, after = record_file(journal, payload, path)
    return {"path": str(path), "events": count, "filter": note, **_head_after(entry, after)}


def api_report_preview(app: App, query: dict) -> dict:
    """The report's text as Write report would write it now, without a file, a journal entry, or the evidence re-hash,
    which the text says. Under the lock, so its head and its state agree as the written report's do."""
    extra, note, _ = _export_filter(app, {"filter": _one(query, "filter", "")})
    with app.lock:
        journal = app.journal
        row = {**_journal_row(app), "head": journal.chain.head, "seq": journal.chain.seq}
        text, count = report_text(app.con, app.case, app.identity, app.manifest, journal.state, extra, note, journal=row,
                                  rehash=False)
    return {"text": text, "events": count, "filter": note}


# The marks on events that are loaded. The marks table keeps a mark whose event is gone, for example after a re-run with
# new record keys (analysis.orphan_marks), and every file the page offers reads events, so a count of the marks alone could
# name more than the file holds. A Hayabusa row is no timeline event, and the exports leave it out.
MARKS_IN_CASE = "marks m JOIN events e ON e.event_uid = m.event_uid WHERE e.tool <> 'hayabusa'"


def _malicious_uids(con) -> list[str]:
    return [r[0] for r in con.execute(f"SELECT m.event_uid FROM {MARKS_IN_CASE} AND m.label = 'Malicious' "
                                      "ORDER BY m.event_uid").fetchall()]


def api_indicators(app: App, body: dict) -> dict:
    """The indicators file: the values among the events marked Malicious, read from parsed fields only, as
    indicators.csv with its file entry. Read on a reader, as a timeline export is; the entry's append holds the lock."""
    _refuse_on_break(app)
    con = app.reader()
    uids = _malicious_uids(con)
    found = indicators(con, uids, app.identity)
    path = write_indicators(app.case, found)
    payload = file_payload(app.case, path, kind="indicators", fmt="csv", rows=len(found))
    entry, head = record_file(app.journal, payload, path, app.lock)
    return {"path": str(path), "values": len(found), "events": len(uids), **_head_after(entry, head)}


FILES_SHOWN = 20   # the newest files the Findings page's "Written from this case" lists


def api_exports_page(app: App, query: dict) -> dict:
    """What the Findings page's right column says before a click: the report's outline counts, the summary, each
    export's scope and count, and the files the case wrote (`state.files`, newest first, each with its SHA-256 short and
    in full), so the page states a scope before the analyst writes anything. The evidence files are those the report
    re-hashes, the ones with a hash in the manifest: a file intake couldn't read, or a folder it couldn't list, has
    none."""
    state = app.journal.state
    con = app.reader()
    counts = dict(con.execute(f"SELECT m.label, count(*) FROM {MARKS_IN_CASE} GROUP BY m.label").fetchall())
    malicious = _malicious_uids(con)
    findings = list(state.findings.values())   # one snapshot: a finding added on another request thread changes the dict
    runs = con.execute("SELECT count(DISTINCT run_id) FROM events").fetchone()[0]
    files = [{**f, "short": short(f.get("sha256") or ""), "words": file_words(f)} for f in reversed(list(state.files))]
    return {"summary": str(state.settings.get("report_summary") or ""),
            "findings": sum(1 for f in findings if not f["retired"]),
            "retired": sum(1 for f in findings if f["retired"]),
            "marked": sum(counts.values()), "flagged": counts.get("Malicious", 0) + counts.get("Suspicious", 0),
            "malicious": len(malicious), "indicators": len(indicators(con, malicious, app.identity)),
            "hosts": len(app.identity.hosts), "evidence_files": sum(1 for sha in app.manifest.values() if sha),
            "runs": runs,
            "journal_entries": app.journal.chain.nonblank,
            "files": files[:FILES_SHOWN], "files_total": len(files)}


def api_followup(app: App, body: dict) -> dict:
    """Tick or clear Followed up on events. A later mark leaves the tick."""
    uids = body.get("uids") or []
    if not isinstance(uids, list) or not uids or len(uids) > MAX_MARK_TARGETS:
        raise QueryError(f"uids must be a list of 1 to {MAX_MARK_TARGETS} event IDs")
    with app.lock:   # an undo plans from the journal under it
        entry = app.journal.append("followup", targets=uids, done=body.get("done"),
                                   **({"confirmed": body["confirmed"]} if "confirmed" in body else {}))
    return {"seq": entry["seq"], "changed": len(uids)}


FINDING_KEYS = ("title", "severity", "narrative", "techniques", "targets", "reason", "confirmed")
FLAGGED = ("Malicious", "Suspicious")   # the marks a finding draws on, and the worklist and the report list


def api_findings_page(app: App, query: dict) -> dict:
    """The Findings page: every finding in the order of its add, numbered so, with its events as the page lists
    them, through _listed_events and _mark_info, so each shows its current mark, its
    caveats from those events' types, and the count of Malicious and Suspicious events in no open finding, which
    `unassigned=1` lists. A retired finding keeps its number and holds no event: its events count as unassigned."""
    state = app.journal.state
    con = app.reader()
    findings, held = [], set()
    # A snapshot, each finding's targets copied once: a link on another request thread changes both in place
    snapshot = [(fid, {**f, "targets": list(f["targets"])}) for fid, f in sorted(state.findings.items())]
    for number, (fid, f) in enumerate(snapshot, 1):
        kinds = con.execute(f"SELECT {', '.join(CAVEAT_COLUMNS)} FROM events WHERE event_uid IN "
                            f"(SELECT v FROM {id_table(con, 'finding_kinds', f['targets'])})").fetchall()
        findings.append({"id": fid, "number": number, "title": f["title"], "severity": f["severity"],
                         "narrative": f["narrative"], "techniques": f["techniques"],
                         "technique_flags": attack.flags(f["techniques"]), "added": f["added"],
                         "edited": f["edited"], "retired": f["retired"], "total": len(f["targets"]),
                         "events": _listed_events(app, "finding_events", f["targets"]),
                         "caveats": caveats_for([dict(zip(CAVEAT_COLUMNS, row, strict=True)) for row in kinds])})
        if not f["retired"]:
            held.update(f["targets"])
    marked = [r[0] for r in con.execute("SELECT m.event_uid FROM marks m JOIN events e ON e.event_uid = m.event_uid "
                                        f"WHERE m.label IN {FLAGGED} ORDER BY m.event_uid").fetchall()]
    loose = [u for u in marked if u not in held]
    out = {"findings": findings, "unassigned": len(loose)}
    if query.get("unassigned") == ["1"]:
        out["unassigned_events"] = _listed_events(app, "unassigned_events", loose)
    return out


def api_finding(app: App, body: dict) -> dict:
    """Add, edit, link, unlink, retire, or restore a finding. The finding's state is read again under the lock
    and the journal's held context, which the append re-enters, so what decides the refusal is what the entry follows:
    an op naming no finding, an edit, link, or unlink of a retired one, a retire of a retired one, and a restore of one
    that isn't. A finding is named by the number of its add. An add the analyst confirmed first (more
    than 25 selected events) is written as the add without its events and a link of them carrying `confirmed`, since
    format 3's validator accepts `confirmed` on a link and not on an add; the answer's `seq` is the link's."""
    op = body.get("op")
    if "techniques" in body and (refused := attack.refusal(body["techniques"])):   # only listed IDs
        raise QueryError(refused)
    # The consent the page sends as {count}; the entry records {count, skipped: 0}, since a link covers every event it names
    count = _confirmed({**body, "uids": body.get("targets")})
    consent = {"confirmed": {"count": count, "skipped": 0}} if count is not None else {}
    with app.lock, app.journal.held():
        app.journal.refresh()
        if op == "add" and consent:
            targets = body.get("targets")   # checked before the add, so a refused link leaves no empty finding behind
            if not isinstance(targets, list) or not targets or not all(isinstance(t, str) and t for t in targets):
                raise QueryError("a confirmed finding names the events it links, as a non-empty list of event IDs")
            first = app.journal.append("finding", op="add", targets=[], **{k: body[k] for k in FINDING_KEYS[:4] if k in body})
            entry = app.journal.append("finding", op="link", finding=first["seq"],
                                       targets=list(dict.fromkeys(body.get("targets") or [])), **consent)
            return {"seq": entry["seq"], "finding": first["seq"]}
        payload: dict = {"op": op, **consent}
        if op != "add":
            fid = body.get("finding")
            finding = app.journal.state.findings.get(fid) if type(fid) is int else None
            if finding is None:
                raise QueryError(f"There's no finding #{fid}.")
            title, retired = finding["title"], finding["retired"]
            if retired and op == "retire":
                raise QueryError(f'The finding "{title}" is retired already, by #{retired["seq"]}.')
            if retired and op in ("edit", "link", "unlink"):
                raise QueryError(f'The finding "{title}" was retired by #{retired["seq"]}. Restore it first.')
            if op == "restore" and not retired:
                raise QueryError(f'The finding "{title}" is not retired.')
            payload["finding"] = fid
        payload.update({k: body[k] for k in FINDING_KEYS if k in body and k != "confirmed"})
        if isinstance(payload.get("targets"), list):   # each event once, as replay keeps them
            payload["targets"] = list(dict.fromkeys(payload["targets"]))
        if op == "add":
            payload.setdefault("targets", [])
        entry = app.journal.append("finding", **payload)
    return {"seq": entry["seq"], "finding": entry["seq"] if op == "add" else payload["finding"]}


def api_attack(app: App, query: dict) -> dict:
    """Enterprise ATT&CK's techniques, for the finding form's pick list."""
    return attack.picker()


def api_journal_check(app: App, body: dict) -> dict:
    """Check now (Integrity): the full check and the head this app recorded, writing nothing. A break it finds puts
    the journal in read-only mode. Under app.lock, so no write of this App lands during it; not under the journal's
    held context, whose OS lock would make bytes after the last LF read as another writer's write in progress."""
    with app.lock:
        found, record = app.journal.full_check()
        app.last_check = (found, record, _now())
        app.overview_cache = None
        row = _journal_row(app)
    return {"journal": row, "state": _journal_state(app)}


def api_chain_break(app: App, body: dict) -> dict:
    """Continue with the break on record: a chain_break entry with the analyst's reason, which seals every
    byte before it and ends read-only mode. Nothing is repaired. The state is read again from the file, so the derived
    tables are built again from it."""
    with app.lock:
        entry = app.journal.record_break(str(body.get("reason") or ""))
        app.last_check = None
        app.overview_cache = None
        app.refresh_identity(events_changed=True)
    return {"seq": entry["seq"], "state": _journal_state(app)}


def api_filter(app: App, body: dict) -> dict:
    """Register a view filter; the page passes the returned ID with its lane and view requests."""
    spec = normalize(body)
    app.save_searches(spec)   # a search in the View: its matches are saved here, and again whenever they're dropped
    return {"id": app.filters.add(spec), "description": describe(spec)}


def api_search(app: App, query: dict) -> dict:
    """Search every event. The matches are saved, so adding the search to the View costs nothing more."""
    q = _one(query, "q")
    sid, terms = app.save_search(q)
    fid = _one(query, "filter", "")
    out = {"query": normalize_query(q), "terms": [t.describe() for t in terms], "whole_word": whole_word(q),
           "forgiving": forgiving_term(terms) is not None,   # whether /api/search_adds has a quoted word to take off
           **results(app.reader(), sid, _view_sql(app, fid), terms=terms)}
    _mark_info(app, out["events"])
    # Hayabusa rule titles are not event text, so free text lists the rules it finds in them below the matches, or,
    # when nothing matched, says which fields free text skips and which hold the words.
    if out["total"]:
        names = by_name(app.reader(), q, terms, sid)
        for rule in names:
            _mark_info(app, rule["events"])
        if names:
            out["by_name"] = names
    elif (hint := zero_hint(app.reader(), terms, api_sources(app, {}))) is not None:
        out["hint"] = hint
    # What the View shows, for the rows it hides to say which of it they miss: they meet none of these
    out["view_terms"] = app.filters.view_terms(fid) if fid else []
    return out


def api_search_adds(app: App, query: dict) -> dict:
    """What the search's first quoted word would add without its quotes: one scan on a reader, outside the
    lock, that saves nothing. The page asks for it on a click, since it is a scan of its own."""
    return search_adds(app.reader(), _one(query, "q"))


def api_sources(app: App, query: dict) -> dict:
    listing = app.sources_cache
    if listing is None:
        # Read and stored under the lock, which refresh_identity clears it under after a load commits, so a listing
        # read before the load can't be stored after it.
        with app.lock:
            if app.sources_cache is None:
                app.sources_cache = sources(app.reader())
            listing = app.sources_cache
    return listing


def api_categories(app: App, query: dict) -> dict:
    pred = normalize_pred(json.loads(_one(query, "pred")))
    app.save_searches({"only": [pred], "hide": [], "show": []})   # a search or data value the pred reads
    return categories(app.reader(), pred_sql(pred), _filter_cond(app, query))


def _zones(app: App) -> dict[str, dict]:
    return {h.host: h.timezone for h in app.identity.hosts.values() if h.timezone}


def api_imports(app: App, query: dict) -> dict:
    """The Import page: files to import and the choices a mapping offers."""
    zones = _zones(app)
    return {"files": importable(app.case, _one(query, "all", "") == "1"),
            "presets": [{"name": n, "label": p["label"], "format": p["format"]} for n, p in IMPORT_PRESETS.items()],
            "saved": sorted(saved_mappings(app.case)), "formats": FORMATS, "roles": ROLES, "time_formats": TIME_FORMATS,
            "layouts": {name: layout.label for name, layout in LAYOUTS.items()},
            "host_zones": [{"host": h, "value": f"host:{h}", "label": f"{h}: {z.get('windows') or z.get('iana')}"}
                           for h, z in sorted(zones.items())],
            "zone_names": zone_names(), "evidence": str(app.case.evidence)}


def api_import_preview(app: App, body: dict) -> dict:
    return preview(app.case, str(body.get("path", "")), body.get("mapping"), _zones(app),   # MappingError is a ValueError
                   year_hint=case_year(app.case, app.reader()))   # a cursor: app.con is for use under app.lock


def api_import(app: App, body: dict) -> dict:
    """Import one or more files with one mapping, each as its own run; then the page reloads to show them."""
    paths, mapping = body.get("paths") or [], body.get("mapping")
    if not paths or not isinstance(paths, list) or not isinstance(mapping, dict):
        raise ValueError("Choose the files and the mapping to import them with.")
    name = (body.get("save_as") or "").strip()
    if name:
        check_mapping_name(name)   # before any file's rows are committed
    runs, errors = [], []
    with app.lock:   # one import at a time; the events table changes under every reader
        for path in paths:
            try:
                r = run_import(app.case, str(path), mapping, _zones(app))
                runs.append({"path": path, "run_id": r.run_id, "status": r.status, "rows": r.loaded_rows,
                             "replaced": r.replaced_rows, "reason": r.reason, "notes": r.notes})
            except MappingError as exc:
                errors.append({"path": path, "error": str(exc)})
        if name and any(r["status"] == "ok" for r in runs):
            save_mapping(app.case, name, mapping)
        # Each run's record was rewritten inside its own folder, which leaves the runs folder's time as it was, so the
        # Case overview's key counts it here, as a failed import refreshes nothing else (overview_key)
        app.generation += 1
    # The derived tables (hits, marks, relations, identity), after any load that committed, also one whose run then
    # failed because the file changed while it was read: its rows are in the events table
    if any(r["rows"] is not None for r in runs):
        app.refresh_identity(events_changed=True)
        app.remember()
    return {"runs": runs, "errors": errors, "saved_as": name or None}


def api_evidence_add(app: App, body: dict) -> dict:
    """Add new evidence: hash and list the files copied into the evidence folder since intake."""
    with app.lock:
        summary = add_new(app.case)
        app.manifest = manifest_hashes(app.case)
    return {"files": summary.files, "bytes": summary.total_bytes, "by_artifact": summary.by_artifact,
            "errors": summary.errors, "missing": summary.missing, "links": summary.links}


def _tools(app: App, rescan: bool = False) -> tuple[dict, dict]:
    if app.tool_cache is None or rescan:
        specs = load_registry()
        folder = Path(app.case.settings.tools_folder) if app.case.settings.tools_folder else None
        app.tool_cache = (specs, detect(specs.values(), folder))
    return app.tool_cache


def api_tools(app: App, query: dict) -> dict:
    """The Tools page: what's installed, what each tool reads here, and what ran."""
    specs, detected = _tools(app, _one(query, "rescan", "") == "1")
    view = overview(app.case, specs, detected)
    tools, groups = everything_ready(app.case, specs, detected, view)
    return {**view, "job": app.job.state() if app.job else None,
            "ready": {"tools": [t.spec.name for t in tools], "outputs": len(groups)}}


def _begin_job(app: App, start) -> dict:
    """Start a background job, checking for a running one and setting app.job under the lock. A host split checks
    app.job under the same lock, so one that waited behind an import can't go ahead while a job's load is in flight."""
    with app.lock:
        if app.job and not app.job.finished:
            raise ValueError(f"{app.job.tool} is still running.")
        try:
            app.job = start()
        except RunError as exc:
            raise ValueError(str(exc)) from exc
        return {"job": app.job.state()}


def api_run_tool(app: App, body: dict) -> dict:
    """Run one tool on its hosts in the background; the page follows it with /api/run_status."""
    specs, detected = _tools(app)
    tool_id = str(body.get("tool", ""))
    if tool_id not in specs:
        raise ValueError(f"No tool {tool_id!r} in the registry.")
    if tool_id not in detected:
        raise ValueError(f"{specs[tool_id].name} isn't installed. Get it from {specs[tool_id].download_url}")
    return _begin_job(app, lambda: start_tool_job(app.case, detected[tool_id], body.get("hosts") or None,
                                                  app.after_job))


def api_load_output(app: App, body: dict) -> dict:
    """Load a tool's output found in the evidence, such as KAPE's, host by host in the background."""
    specs, detected = _tools(app)
    return _begin_job(app, lambda: start_load_job(app.case, specs, detected, str(body.get("key", "")),
                                                  body.get("hosts") or None, bool(body.get("anyway")), app.after_job))


def api_run_all(app: App, body: dict) -> dict:
    """Run every ready tool, then load every ready group of found output, in the background."""
    specs, detected = _tools(app)
    return _begin_job(app, lambda: start_all_job(app.case, specs, detected, app.after_job))


def api_run_status(app: App, query: dict) -> dict:
    return {"job": app.job.state() if app.job else None}


def api_shown(app: App, query: dict) -> dict:
    """How many events the current filter shows per source file, so the Filter panel shows the true state."""
    return {"counts": shown_counts(app.reader(), _filter_cond(app, query))}


GET_ROUTES = {"/api/meta": api_meta, "/api/lanes": api_lanes, "/api/view": api_view, "/api/event": api_event,
              "/api/event_keys": api_event_keys,
              "/api/related": api_related, "/api/pivot_count": api_pivot_count, "/api/rules": api_rules,
              "/api/investigate": api_investigate, "/api/findings_page": api_findings_page,
              "/api/attack": api_attack,
              "/api/counts": api_counts, "/api/pending": api_pending, "/api/pending_uids": api_pending_uids,
              "/api/sources": api_sources,
              "/api/categories": api_categories, "/api/shown": api_shown, "/api/marks": api_marks,
              "/api/search": api_search, "/api/search_adds": api_search_adds, "/api/tags": api_tags, "/api/audit": api_audit,
              "/api/audit_events": api_audit_events, "/api/undo_plan": api_undo_plan, "/api/imports": api_imports,
              "/api/tools": api_tools, "/api/run_status": api_run_status, "/api/host_split": api_host_split,
              "/api/selected": api_selected, "/api/overview": api_overview, "/api/lead_events": api_lead_events,
              "/api/view_events": api_view_events, "/api/report_preview": api_report_preview,
              "/api/exports_page": api_exports_page,
              "/api/shown_counts": api_shown_counts, "/api/case_state": api_case_state}
POST_ROUTES = {"/api/mark": api_mark, "/api/note": api_note, "/api/host": api_host, "/api/rule": api_rule,
               "/api/suggestion": api_suggestion, "/api/export": api_export, "/api/report": api_report,
               "/api/indicators": api_indicators,
               "/api/setting": api_setting, "/api/filter": api_filter, "/api/tag": api_tag,
               "/api/tag_suggestion": api_tag_suggestion, "/api/undo": api_undo, "/api/note_retract": api_note_retract,
               "/api/audit_export": api_audit_export, "/api/import_preview": api_import_preview,
               "/api/import": api_import, "/api/evidence_add": api_evidence_add, "/api/run_tool": api_run_tool,
               "/api/load_output": api_load_output, "/api/run_all": api_run_all, "/api/followup": api_followup,
               "/api/finding": api_finding, "/api/journal_check": api_journal_check,
               "/api/chain_break": api_chain_break}


def serve(case: Case, port: int = 0) -> tuple[ThreadingHTTPServer, App, str]:
    """Create the server for one case without starting it. Returns the server, the app, and the launch URL."""
    server, hub, url = serve_hub(Hub(case), port)
    return server, hub.app, url


def serve_start(port: int = 0) -> tuple[ThreadingHTTPServer, Hub, str]:
    """Create the server with no case open, showing the start page."""
    return serve_hub(Hub(), port)


class Server(ThreadingHTTPServer):
    """The HTTP server, with a listen backlog of 128 connections. socketserver's default of 5 is fewer than the 6 a
    browser opens to one host at once to fetch the page's files. When the accept loop falls behind, as on a busy
    machine, Windows refuses each connection the full backlog can't take, about 2 s after the attempt, so a browser
    test's page can find its server refusing connections.

    The port is bound without SO_REUSEADDR, which HTTPServer sets. On Windows that option lets a second server bind a
    port the first still listens on, so two `serve` runs would share PREFERRED_PORT and take turns at its
    connections (probed on Windows). Without it a held port is refused, and serve_hub falls back to a free one; a port
    just closed binds again at once, so nothing is lost."""

    request_queue_size = 128
    allow_reuse_address = False


def serve_hub(hub: Hub, port: int | None) -> tuple[ThreadingHTTPServer, Hub, str]:
    """The server on 127.0.0.1, at `port`, or at a free port for 0. None tries PREFERRED_PORT first and falls back to a
    free port when it is held; the caller reads the port bound from the server, and `serve` says in one
    line when it isn't the preferred one."""
    port_ref = [port or 0]
    handler = make_handler(hub, port_ref)
    if port is None:
        try:
            server = Server(("127.0.0.1", PREFERRED_PORT), handler)
        except OSError:   # in use, or in a range Windows excludes (WinError 10048 and 10013)
            server = Server(("127.0.0.1", 0), handler)
    else:
        server = Server(("127.0.0.1", port), handler)
    port_ref[0] = server.server_address[1]
    return server, hub, f"http://127.0.0.1:{port_ref[0]}/?token={hub.token}"


# ---------- the start page: routes that take the hub, so they work with no case open ----------

def start_info(hub: Hub, query: dict) -> dict:
    app = hub.app
    return {"recent": load_recent(), "job": hub.job.state() if hub.job else None,
            "open_case": {"name": app.case.settings.name, "folder": str(app.case.folder)} if app else None,
            "analyst": getpass.getuser(), "build": build_id()}


def start_browse(hub: Hub, query: dict) -> dict:
    return browse(_one(query, "path", ""))


def start_check(hub: Hub, body: dict) -> dict:
    return check(str(body.get("evidence") or ""), str(body.get("case_folder") or ""), str(body.get("tools") or ""))


def _start_job(hub: Hub, make):
    # The check and the start are one step, or two requests handled at once both pass the check
    with hub.job_lock:
        if hub.job and not hub.job.finished:
            raise ValueError(f"Still working on {hub.job.name}.")
        hub.job = make()
        return {"job": hub.job.state()}


def _analyst(body: dict) -> str:
    """The analyst the start page names, which case.yaml keeps and the journal credits; the Windows
    account when none is given, as the command line's --analyst defaults to."""
    return str(body.get("analyst") or "").strip() or getpass.getuser()


def start_new(hub: Hub, body: dict) -> dict:
    return _start_job(hub, lambda: start_new_case(body, _analyst(body), hub.open))


def start_copy_case(hub: Hub, body: dict) -> dict:
    return _start_job(hub, lambda: start_copy(body, _analyst(body)))


def start_open(hub: Hub, body: dict) -> dict:
    case = open_case(Path(str(body.get("folder") or "")).expanduser())   # refused at once, as a bad folder is for a new case
    return _start_job(hub, lambda: start_open_case(case, hub.open))


def start_job(hub: Hub, query: dict) -> dict:
    return {"job": hub.job.state() if hub.job else None}


def start_forget(hub: Hub, body: dict) -> dict:
    """Recent cases whose folder is gone, off the list: `folder` names one, and `all` takes every one. The
    answer is the list as it is now, which the page draws."""
    folder = str(body.get("folder") or "").strip()
    if not folder and body.get("all") is not True:
        raise ValueError("Name the case to remove, or all.")
    try:
        removed, recent = forget_missing(folder)
    except OSError as exc:   # such as recent.json held open by another program: the list stays as it was
        raise ValueError(f"The list wasn't changed: {exc}") from exc
    return {"removed": removed, "recent": recent}


START_GET_ROUTES = {"/api/start": start_info, "/api/start/browse": start_browse, "/api/start/job": start_job}
START_POST_ROUTES = {"/api/start/check": start_check, "/api/start/new": start_new, "/api/start/copy": start_copy_case,
                     "/api/start/open": start_open, "/api/start/forget": start_forget}
