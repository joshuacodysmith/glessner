"""The events table: schema, stable event IDs, timestamp parsing, and loading into DuckDB.

coverage_reference.md gives the columns each artifact fills. The database can always be rebuilt from the run folders, so
loads replace earlier rows instead of merging with them.
"""

from __future__ import annotations

import csv
import hashlib
import json
import re
from bisect import bisect_right
from collections import Counter
from collections.abc import Callable, Iterable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from functools import cache, lru_cache
from pathlib import Path, PureWindowsPath

import duckdb

COLUMNS = (
    "event_uid", "ts_us", "ts_desc", "host", "host_name_recorded", "tool", "tool_version", "run_id",
    "artifact", "source_file", "source_record", "record_id", "event_code", "event_provider", "log_channel",
    "message", "user_name", "user_domain", "source_ip", "source_workstation", "logon_type", "logon_id",
    "process_executable", "process_command_line", "file_path", "registry_path", "registry_value",
    "rule_title", "rule_level", "extra",
    "file_key",   # new columns go last so older databases can be migrated with ADD COLUMN
    "source_port",   # a rebuild fills it in older cases
    "dest_ip", "dest_port",   # network events (Sysmon 3, 5156) and firewall logs
    "process_parent_executable", "process_parent_command_line",
    "registry_data",   # a registry value's data; registry_value is its name
    # The host the event was loaded under, which its ID hashes. host is the lane, which a split by recorded computer
    # changes; origin_host never changes.
    "origin_host",
    # Case format 3: the account in one form, for Same account, and the file hashes, for
    # Same hash (accounts.key_sql, hashes.HASHES_SQL). A load fills both from the row's own values; the format 3 step
    # fills the rows loaded before it. Text, '' when an event has none, so NULL means not filled yet.
    "account_key", "hashes",
)
BIGINT_COLUMNS = {"ts_us", "record_id"}
NULLABLE = {*BIGINT_COLUMNS, "extra"}   # the columns a load leaves NULL when the event has no value; text is '' instead
EXTRA = COLUMNS.index("extra")
MESSAGE = COLUMNS.index("message")
# The columns a cut never shortens: they identify the event, its time, and its lane, and none is long.
UNCUT = {"event_uid", "ts_us", "ts_desc", "host", "origin_host", "tool", "tool_version", "run_id", "artifact",
         "source_file", "source_record", "record_id"}
CUTTABLE = tuple(i for i, column in enumerate(COLUMNS) if column not in UNCUT)
# A row over MAX_LINE_SIZE bytes in the staging CSV fails read_csv, and with it the whole load. A row over ROW_BUDGET
# bytes is cut; the budget sits far enough under the limit to cover the delimiters, which the measure leaves out. A
# character is at most 4 bytes in UTF-8 and the measure adds 2 for the quotes around each field, so a row of CUT_CHECK
# characters or fewer measures at most ROW_BUDGET, and only a longer row is measured.
MAX_LINE_SIZE = 20_000_000
ROW_BUDGET = 16_000_000
CUT_CHECK = (ROW_BUDGET - 2 * len(COLUMNS)) // 4
SURROGATE = re.compile(r"[\ud800-\udfff]")
# The tools whose rows a split moves by the computer each records: event logs and Hayabusa's hits on them. An import
# never moves, whatever its artifact; neither does a reader whose recorded name isn't the computer's own, such as an
# LNK's MachineID.
SPLIT_TOOLS = ("evtxecmd", "event_xml", "hayabusa")
DDL = "CREATE TABLE IF NOT EXISTS events (" + ", ".join(
    f"{c} {'BIGINT' if c in BIGINT_COLUMNS else 'VARCHAR'}" for c in COLUMNS) + ")"
EARLIEST_YEAR = 1971   # earlier values are placeholders such as 1601-01-01 or the Unix epoch
EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
MEMORY_SHARE = 0.5     # of DuckDB's default memory limit; see memory_limit
# Every DuckDB connection the app opens takes this configuration. DuckDB would otherwise install a missing extension
# from its repository on the internet, and load it, when a query needs one, such as httpfs for a URL. The extensions
# the app uses, json, icu, and core_functions, are built into DuckDB's Python package.
NO_EXTENSION_FETCH = {"autoinstall_known_extensions": False, "autoload_known_extensions": False}


@dataclass
class Event:
    """One parsed event. Parsers fill what they know; the loader sets the provenance fields."""
    ts_us: int | None
    ts_desc: str
    artifact: str
    source_file: str
    source_record: str
    message: str
    host_name_recorded: str = ""
    record_id: int | None = None
    event_code: str = ""
    event_provider: str = ""
    log_channel: str = ""
    user_name: str = ""
    user_domain: str = ""
    source_ip: str = ""
    source_workstation: str = ""
    logon_type: str = ""
    logon_id: str = ""
    process_executable: str = ""
    process_command_line: str = ""
    file_path: str = ""
    registry_path: str = ""
    registry_value: str = ""
    rule_title: str = ""
    rule_level: str = ""
    extra: dict | str | None = None   # a str is already-serialized JSON, shared by events from one record
    file_key: str = ""   # normalized path for matching the same file across artifacts; see parsers.common
    source_port: str = ""   # the source's port where the event records one, such as 4624's IpPort
    dest_ip: str = ""       # the destination of a network event, as the event records it
    dest_port: str = ""
    process_parent_executable: str = ""     # the process that started this one, such as Sysmon 1's ParentImage
    process_parent_command_line: str = ""
    registry_data: str = ""   # the data a registry value holds or was set to, such as Sysmon 13's Details
    lane: str = ""          # not a column: the event's host, for a load whose events name their own (imports.py)
    # Not a column: the source file and source record under the key rule of the case format ParseContext.former names,
    # when they differ from these, so an upgrade pairs the record's ID under both rules (rekey.py)
    former: tuple[str, str] | None = None


def event_uid(host: str, artifact: str, source_file: str, source_record: str, ts_desc: str) -> str:
    """Stable ID: the same record gets the same ID across reruns, tool versions, and rebuilds. A lone surrogate, such as
    one json.loads makes from a \\ud83d escape in a Suricata URL, is encoded as it stands (surrogatepass): strict UTF-8
    refuses it, which would fail the whole load. Text without one encodes to the same bytes either way,
    so every other ID is the one strict encoding gives, and a surrogate's ID differs from U+FFFD's."""
    key = "\x1f".join((host, artifact, source_file, source_record, ts_desc))
    return hashlib.sha256(key.encode("utf-8", "surrogatepass")).hexdigest()[:32]


class EventIds:
    """Each event's ID as a load gives it, and with `former`, its ID under the former case format's key rule as well,
    from Event.former. A tool can emit one record twice, and both are kept: a repeat takes the next ordinal, #2, #3, in
    the source record the ID hashes. Each rule keeps a seen set of its own, so each numbers its repeats as a load under
    that rule did. load and the case format upgrade (rekey.py) share this, so the two can't drift."""

    def __init__(self, former: bool = False):
        self.seen: set[str] = set()
        self.former_seen: set[str] | None = set() if former else None

    def __call__(self, origin: str, ev: Event) -> tuple[str, str | None]:
        """The event's ID under `origin`, the host it is loaded under, and its former ID, or None without `former`."""
        uid = _numbered(self.seen, origin, ev.artifact, ev.source_file, ev.source_record, ev.ts_desc)
        if self.former_seen is None:
            return uid, None
        source_file, source_record = ev.former or (ev.source_file, ev.source_record)
        return uid, _numbered(self.former_seen, origin, ev.artifact, source_file, source_record, ev.ts_desc)


def _numbered(seen: set[str], host: str, artifact: str, source_file: str, source_record: str, ts_desc: str) -> str:
    uid = event_uid(host, artifact, source_file, source_record, ts_desc)
    ordinal = 1
    while uid in seen:   # a tool emitted the same record twice; keep both, deterministically
        ordinal += 1
        uid = event_uid(host, artifact, source_file, f"{source_record}#{ordinal}", ts_desc)
    seen.add(uid)
    return uid


@lru_cache(maxsize=1 << 18)
def to_us(text: str | None) -> int | None:
    """Parse a UTC timestamp from EZ Tools or Hayabusa output into epoch microseconds.

    Cached: MFT records repeat the same time strings across their $SI and $FN columns.

    Accepts "2020-09-17 17:57:31.0000000", "2020-09-17T17:01:56Z", "2020-09-17T17:01:56.123456Z", and an offset
    after the fraction, as Suricata writes: "2024-05-14T19:00:00.000000+0700" is 12:00 UTC.
    Returns None for empty, unparseable, or placeholder times.
    """
    if not text:
        return None
    t = text.strip().removesuffix("Z")
    if "." in t:   # tools write up to 7 fraction digits; keep microseconds, padded to 6 digits, and any offset after
        head, frac = t.split(".", 1)
        digits = len(frac) - len(frac.lstrip("0123456789"))
        t = f"{head}.{frac[:digits][:6].ljust(6, '0')}{frac[digits:].strip()}"
    try:
        dt = datetime.fromisoformat(t)   # several times faster than strptime on millions of rows
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    if dt.year < EARLIEST_YEAR:
        return None
    return int(dt.timestamp()) * 1_000_000 + dt.microsecond


def from_us(us: int) -> datetime:
    """Epoch microseconds as a UTC datetime, for every time the app writes as text. Not datetime.fromtimestamp, which
    on Windows refuses times before 1970, as PE link times and imported times can be."""
    return EPOCH + timedelta(microseconds=us)


def live_hive_first(hive: str) -> str:
    """ORDER BY terms that put a host's live registry hive first among copies of it, for RECmd rows: a path ending in
    Windows/System32/config/<hive>, then one outside Windows.old, then the shortest. RECmd reads every hive under the
    host's folder, so a RegBack or Windows.old copy can sit beside the live one with the same key paths, and a
    Windows.old path sorts first ('.' before '/'). `hive` is the file name in lower case, such as 'software'."""
    path = "('/' || lower(replace(source_file, '\\', '/')))"   # matched by whole folder names
    return (f"{path} NOT LIKE '%/windows/system32/config/{hive}', {path} LIKE '%/windows.old%/%', "
            "length(source_file), source_file")


def sql_literal(value) -> str:
    """One SQL literal. Strings have single quotes doubled; only plain scalar types are accepted. For a value written
    into SQL text, such as a view filter's; bulk lists go in through insert_columns."""
    if value is None:
        return "NULL"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise ValueError("NaN and infinity are not SQL literals")
        return repr(value)
    if isinstance(value, str):
        if "\x00" in value:
            raise ValueError("NUL characters are not allowed in SQL literals")
        return "'" + value.replace("'", "''") + "'"
    raise TypeError(f"no SQL literal for {type(value).__name__}")


def insert_columns(con: duckdb.DuckDBPyConnection, table: str, *columns: Iterable) -> None:
    """Insert rows given as parallel column lists, one per column of the table, in one statement.

    The rows go in as one JSON text parameter, which DuckDB reads with from_json as the table's own column types. In
    DuckDB 1.5.6 on Python 3.14, with the failed pandas import cached (see the package's __init__), executemany took 90 s
    for 200,000 rows of three columns, and a Python list parameter 2.6 s for 200,000 IDs. VALUES statements of 10,000
    literal rows each took 1.9 s for 200,000 IDs and 7.4 s for 200,000 marks; one JSON text takes 0.17 s and 0.56 s.
    Text goes in as it is, NUL characters included, which a literal can't hold.
    """
    data = {f"c{i}": list(column) for i, column in enumerate(columns)}
    if not data or not data["c0"]:
        return
    types = [t for (t,) in con.execute(f"SELECT column_type FROM (DESCRIBE {table})").fetchall()]
    shape = sql_literal(json.dumps({name: [t] for name, t in zip(data, types, strict=True)}))
    con.execute(f"INSERT INTO {table} SELECT {', '.join(f'unnest(j.{name})' for name in data)} "
                f"FROM (SELECT from_json(?, {shape}) AS j)", [json.dumps(data)])


def id_table(con: duckdb.DuckDBPyConnection, name: str, values: Iterable[str]) -> str:
    """Fill a one-column temp table with values and return its name, for IN and JOIN filters."""
    con.execute(f"CREATE OR REPLACE TEMP TABLE {name} (v VARCHAR)")
    insert_columns(con, name, values)
    return name


@cache
def memory_limit() -> str | None:
    """MEMORY_SHARE of DuckDB's default memory limit, which is 80% of the machine's memory, or None when DuckDB words its
    limit in a way this doesn't read. Under the default limit, a full-range JSONL export of a 9.5-million-event case
    held 44 GB of 64 GB; past this limit, a sort spills to the database's .tmp folder in the case folder."""
    with duckdb.connect(config=dict(NO_EXTENSION_FETCH)) as probe:
        number, _, unit = probe.execute("SELECT current_setting('memory_limit')").fetchone()[0].partition(" ")
    scale = {"KiB": 2**10, "MiB": 2**20, "GiB": 2**30, "TiB": 2**40}.get(unit)
    return f"{int(float(number) * scale * MEMORY_SHARE) >> 20}MiB" if scale else None


def connect(db_path: Path, read_only: bool = False) -> duckdb.DuckDBPyConnection:
    con = duckdb.connect(str(db_path), read_only=read_only, config=dict(NO_EXTENSION_FETCH))
    if limit := memory_limit():
        con.execute(f"SET memory_limit = '{limit}'")
    if not read_only:
        con.execute(DDL)
        existing = {row[0] for row in con.execute("DESCRIBE events").fetchall()}
        for column in COLUMNS:
            if column in existing:
                continue
            if column == "origin_host":
                # Filled from host in the same transaction: a row left NULL would escape the delete of a rerun, which
                # matches on origin_host, and be loaded twice.
                con.execute("BEGIN TRANSACTION")
                try:
                    con.execute("ALTER TABLE events ADD COLUMN origin_host VARCHAR")
                    con.execute("UPDATE events SET origin_host = host")
                    con.execute("COMMIT")
                except Exception:
                    con.execute("ROLLBACK")
                    raise
            else:   # a database from an earlier version; reload runs to fill the column, or for the account key and
                # the hashes, the case format 3 step (rekey._fill_columns), which runs under this connection's hold
                con.execute(f"ALTER TABLE events ADD COLUMN {column} {'BIGINT' if column in BIGINT_COLUMNS else 'VARCHAR'}")
    return con


@contextmanager
def transaction(con: duckdb.DuckDBPyConnection) -> Iterator[None]:
    """The block's statements as one transaction. Until the commit, a request reading through a cursor of its own sees
    the tables as they were before the block, and a failure rolls back every statement.

    In DuckDB 1.5.6, a statement that fails as it runs, such as a regex RE2 can't compile or a failed cast, aborts the
    transaction, and every statement after it fails, even when the error is caught. A binder or parser error doesn't."""
    con.execute("BEGIN TRANSACTION")
    try:
        yield
    except BaseException:
        con.execute("ROLLBACK")
        raise
    con.execute("COMMIT")


@dataclass(frozen=True)
class LoadResult:
    rows: int
    replaced: int
    without_time: int
    # For a load of found output, the events left out because the database holds rows of the file they name from a run
    # of the tool that read the evidence itself (SeenSources.direct): their count by the file they name
    left_out: dict[str, int] = field(default_factory=dict)


@dataclass(frozen=True)
class SeenSources:
    """What a load of a tool's output found in the evidence replaces. Its events name the files the tool read, not the
    output they were loaded from, so the rows it may replace are found by run: only those of `runs`, the found-output
    runs of the tool on the host. The rows of the runs in `superseded`, which read no file this load doesn't, are
    replaced whole. Of the other runs' rows, those of the files the load reads are replaced, and those of each file its
    events name under `folder`, the host's folder in the evidence ("" for a single-host case, whose host folder is the
    evidence folder). An event isn't loaded when it names a file that the database holds rows of from a run in
    `direct`, the tool's runs on the host that read the evidence itself: those rows stand for the file, and the event
    may take one of their IDs. `inputs` are the files each of `runs` read, evidence-relative, which tell the whole path
    a row of an earlier load names from the evidence-relative path under it (_extended_forms), and `root` is the evidence
    folder's extended-length path, which tells them apart when the rows fit two roots equally well."""
    runs: frozenset[str]
    superseded: frozenset[str]
    folder: str
    direct: frozenset[str] = frozenset()
    inputs: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    root: str = ""


def under_folder(path: str, folder: str) -> bool:
    """Whether an evidence-relative path names a file under `folder`, a host's top-level folder in the evidence, or
    anywhere in the evidence when `folder` is "". A path with a drive, a root, or a .. part is outside it, and Windows
    reads the folder's name without regard to case."""
    pure = PureWindowsPath(path)
    if not pure.parts or pure.anchor or ".." in pure.parts:
        return False
    return not folder or (len(pure.parts) > 1 and pure.parts[0].casefold() == folder.casefold())


def held_sources(db_path: Path, tool: str, host: str, runs: Iterable[str]) -> set[str]:
    """The source files the database holds rows of from the given runs of the tool, among the rows loaded under the
    host (origin_host)."""
    with connect(db_path) as con:
        held = id_table(con, "held_runs", sorted(runs))
        return {path for (path,) in con.execute(
            f"SELECT DISTINCT source_file FROM events WHERE tool = ? AND origin_host = ? "
            f"AND run_id IN (SELECT v FROM {held})", [tool, host]).fetchall()}


def names_by_root(sources: Iterable[str], inputs: Iterable[str], root: str = "") -> dict[str, str]:
    """The one of `inputs`, evidence-relative paths, that each of `sources`, the files a run's rows name in extended-length
    form, names. A run named all its files under one root, so a source is an input's when it is that root, a slash, and
    the input, without regard to case: `logs/eve.json` ends in `eve.json` and is another file. The root is the one that
    explains the most sources. Of those that explain as many, it is `root`, the evidence folder's extended-length path
    when the evidence is still there, and otherwise the shortest, so a run with one source takes the longest input its
    path ends in. A source that is the root and none of the inputs is not in the answer."""
    tails = {path: path.casefold() for path in inputs}
    by_root: dict[str, dict[str, str]] = {}
    for source in sources:
        low = source.casefold()
        for path, tail in tails.items():
            if low.endswith(f"/{tail}"):
                by_root.setdefault(low[:-len(tail) - 1], {})[source] = path
    here = root.casefold()
    return by_root[max(by_root, key=lambda r: (len(by_root[r]), r == here, -len(r)))] if by_root else {}


def _extended_forms(con: duckdb.DuckDBPyConnection, tool: str, host: str | None, inputs: Mapping[str, Iterable[str]],
                    sources: Iterable[str], root: str = "") -> set[str]:
    """The source paths of the rows of the runs in `inputs`, each with the files it read, that name one of `sources`,
    evidence-relative paths, by its extended-length path (`//?/D:/folder/WS01/a.csv`). A load of found output whose
    evidence root is the resolved one writes a file's evidence-relative path. An earlier load whose root was the
    evidence path as case.yaml writes it, when that names the evidence through a junction, a substituted drive, or a
    mapped one, wrote the file's whole path in this form, since a resolved file path doesn't start with that root. Those
    rows are the same file's, so the load replaces them with its own.

    A row names the file its run read that fits the run's root (names_by_root, which `root` helps), so the rows of
    `logs/eve.json` are not those of `eve.json`, whatever else the run read and wherever the evidence was. A run whose
    rows fit two roots equally well, because a folder named like the root's last folder holds a file of the same name,
    takes the root the evidence is at, or the shortest when it is not at either. A row that fits none of its run's files
    is left."""
    wanted = {well_formed(PureWindowsPath(source).as_posix()).casefold() for source in sources}
    read = {run: [well_formed(PureWindowsPath(p).as_posix()) for p in files] for run, files in inputs.items()}
    held = id_table(con, "extended_runs", sorted(read))
    where = f"tool = ? AND {'origin_host = ? AND ' if host is not None else ''}"
    rows = con.execute(f"SELECT DISTINCT run_id, source_file FROM events WHERE {where}run_id IN (SELECT v FROM {held}) "
                       "AND source_file LIKE '//?/%'", [tool] if host is None else [tool, host]).fetchall()
    stored: dict[str, list[str]] = {}
    for run_id, path in rows:
        stored.setdefault(run_id, []).append(path)
    return {path for run_id, paths in stored.items() for path, named in names_by_root(paths, read.get(run_id, ()), root).items()
            if named.casefold() in wanted}


def load(db_path: Path, events: Iterable[Event], *, host: str | None, tool: str, tool_version: str, run_id: str,
         replaces_sources: Iterable[str], staging_dir: Path, replace_seen_sources: SeenSources | None = None,
         routes: dict[str, str] | None = None) -> LoadResult:
    """Replace this tool's rows for the given source files on this host with the new events.

    With host None, each event names its host in lane, as an import's events can, and the tool's rows for the
    source files are replaced on every host. With replace_seen_sources, for a tool's output found in the evidence,
    which names the files the tool read rather than the output it was loaded from, only rows of earlier loads of found
    output are replaced, and the events naming a file that a run of the tool loaded from the evidence itself are left
    out, as SeenSources says.
    `routes` is the host's split by recorded computer from the journal (splits.py): an event log or Hayabusa
    row goes to the lane its computer is routed to. Its ID, and the rows a rerun replaces, still go by the host it was
    loaded under (origin_host), so a split never changes an ID.
    Rows are written to a staging CSV in staging_dir and bulk-loaded, which is far faster in DuckDB than row-by-row
    inserts. In the same transaction, accounts known only by their SID on the lanes whose event log rows or logons the
    load changed take the names those lanes' logons record (accounts.py). Each row's
    account key and hashes are computed in the insert (accounts.key_sql, hashes.HASHES_SQL; case format 3).
    A row too long for one CSV line has its longest text fields cut to fit, each ending in a note of how much text it
    held (_fit). Its ID and the other rows are unchanged.
    """
    from .accounts import AFFECTS_SQL, NAMING_CODES, key_sql, name_sids  # imported here: accounts.py uses this module
    from .hashes import HASHES_SQL
    from .splits import Routes

    router = Routes(routes) if routes and tool in SPLIT_TOOLS else None
    staging = staging_dir / "events_staging.csv"
    ids = EventIds()
    named: set[str] = set()
    held = (held_sources(db_path, tool, host, replace_seen_sources.direct)
            if replace_seen_sources is not None and replace_seen_sources.direct else set())
    left_out: Counter[str] = Counter()
    lookup: set[str] = set()   # lanes gaining rows that can change their SID lookup
    count = without_time = 0
    with staging.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f, lineterminator="\n")   # read_csv's new_line below
        for ev in events:
            if replace_seen_sources is not None:
                named.add(ev.source_file)
                if held and well_formed(ev.source_file) in held:
                    left_out[ev.source_file] += 1
                    continue
            # An event's own host, from an import's field, is part of its ID, which is made from UTF-8
            origin = host if host is not None else well_formed(ev.lane)
            lane = (router.lane(ev.host_name_recorded) or origin) if router else origin
            if lane not in lookup and (ev.artifact == "evtx" or ev.event_code in NAMING_CODES):   # AFFECTS_SQL's test
                lookup.add(lane)
            uid, _ = ids(origin, ev)
            if ev.ts_us is None:
                without_time += 1
            row = _row(ev, uid, lane, tool, tool_version, run_id, origin)
            try:
                characters = len("".join(row))
            except TypeError:   # a field that isn't text, such as a parser's None for a column its source row lacks
                row = _as_text(row)
                characters = len("".join(row))
            if characters > CUT_CHECK:
                row = _fit(row)
            try:
                writer.writerow(row)
            except UnicodeEncodeError:   # a failed row writes nothing, so it's written again without the surrogate
                writer.writerow(_without_surrogates(row))
            count += 1
    if replace_seen_sources is not None:   # a path the output names elsewhere replaces nothing
        named = {path for path in named if path and under_folder(path, replace_seen_sources.folder)}
    # The rows hold each source path as well_formed makes it, so the rows to replace are named the same way, and a path
    # with a lone surrogate, which from_json refuses, finds its earlier rows
    sources = sorted({well_formed(s) for s in set(replaces_sources) | named})
    con = connect(db_path)
    try:
        con.execute("BEGIN TRANSACTION")
        if replace_seen_sources is not None:
            sources = sorted({*sources, *_extended_forms(con, tool, host, replace_seen_sources.inputs, sources,
                                                         replace_seen_sources.root)})
        replaced_sources = id_table(con, "replaced_sources", sources)   # see insert_columns for why not parameters
        # By the host the rows were loaded under, not their lane, so a rerun on a split host replaces every lane's rows.
        where = f"tool = ? AND {'origin_host = ? AND ' if host is not None else ''}"
        params = [tool, host] if host is not None else [tool]
        if replace_seen_sources is None:
            where += f"source_file IN (SELECT v FROM {replaced_sources})"
        else:
            runs = id_table(con, "replaced_runs", sorted(replace_seen_sources.runs))
            whole = id_table(con, "superseded_runs", sorted(replace_seen_sources.superseded))
            where += (f"run_id IN (SELECT v FROM {runs}) AND (run_id IN (SELECT v FROM {whole}) "
                      f"OR source_file IN (SELECT v FROM {replaced_sources}))")
        replaced, replaced_hosts = con.execute(
            f"SELECT count(*), list(DISTINCT host) FILTER (WHERE {AFFECTS_SQL}) FROM events WHERE {where}",
            params).fetchone()
        con.execute(f"DELETE FROM events WHERE {where}", params)
        types = {c: ("BIGINT" if c in BIGINT_COLUMNS else "VARCHAR") for c in COLUMNS}
        # Rows end in \n, named here, so a line break in a quoted value of the first row isn't read as the row's end.
        # NULL is an empty field, read as NULL only in the columns _row leaves empty for it, so every text is a value,
        # \N included.
        text = [c for c in COLUMNS if c not in NULLABLE]
        # The account key and the hashes come from each row's own values, by the expressions the format 3 step fills
        # older rows with, so no Python copy of either rule exists
        con.execute(f"INSERT INTO events SELECT * REPLACE ({key_sql('user_name', 'user_domain')} AS account_key, "
                    f"{HASHES_SQL} AS hashes) FROM read_csv(?, header = false, columns = {types!r}, "
                    f"quote = '\"', escape = '\"', max_line_size = {MAX_LINE_SIZE}, new_line = '\\n', nullstr = '', "
                    f"force_not_null = {text!r}, auto_detect = false)", [str(staging)])
        # The lanes whose event log rows or logons this load removed or added: a lane's lookup reads only its own rows.
        name_sids(con, lookup | set(replaced_hosts or ()))
        con.execute("COMMIT")
    except Exception:
        con.execute("ROLLBACK")
        raise
    finally:
        con.close()
        staging.unlink(missing_ok=True)
    return LoadResult(count, replaced, without_time, dict(left_out))


def _row(ev: Event, uid: str, host: str, tool: str, tool_version: str, run_id: str, origin: str) -> tuple:
    """One CSV row in COLUMNS order. Built directly, without an intermediate dict: this runs once per event. The ID, host,
    tool, tool version, run ID, and origin come from the arguments, and the account key and the hashes are empty for the
    load's insert to fill, so those eight fields are always text. The two number columns and extra are text too, empty
    when the event has no value, which loads as NULL in the NULLABLE columns. The event's other fields pass through as
    they are, and a parser may leave None or a number in one, so the row is text throughout only after _as_text."""
    # With no extra fields the field is empty, which loads as NULL: DuckDB's JSON functions reject an empty string.
    extra = (ev.extra if isinstance(ev.extra, str) else json.dumps(ev.extra, ensure_ascii=False)) if ev.extra else ""
    ts_us = "" if ev.ts_us is None else str(ev.ts_us)
    record_id = "" if ev.record_id is None else str(ev.record_id)
    return (uid, ts_us, ev.ts_desc, host, ev.host_name_recorded, tool, tool_version,
            run_id, ev.artifact, ev.source_file, ev.source_record, record_id,
            ev.event_code, ev.event_provider, ev.log_channel, ev.message, ev.user_name, ev.user_domain, ev.source_ip,
            ev.source_workstation, ev.logon_type, ev.logon_id, ev.process_executable, ev.process_command_line,
            ev.file_path, ev.registry_path, ev.registry_value, ev.rule_title, ev.rule_level, extra, ev.file_key,
            ev.source_port, ev.dest_ip, ev.dest_port, ev.process_parent_executable, ev.process_parent_command_line,
            ev.registry_data, origin, "", "")   # the account key and the hashes, which load's insert computes


def _as_text(row: tuple) -> tuple[str, ...]:
    """The row with each field as csv.writer writes it: None as an empty field and any other value as its text."""
    return tuple("" if value is None else str(value) for value in row)


def _csv_size(text: str) -> int:
    """The most bytes a field takes in the staging CSV: its UTF-8 bytes (a lone surrogate takes 3, as its replacement
    does), each double quote written twice, and the quotes around it."""
    return len(text.encode("utf-8", "surrogatepass")) + text.count('"') + 2


def _json_size(text: str) -> int:
    """The bytes a string takes in the staging CSV as a value in JSON text: _csv_size of the JSON string, less the
    quotes around the whole field, so the sizes of a JSON text's strings and its other characters add up to its size."""
    return _csv_size(json.dumps(text, ensure_ascii=False)) - 2


def _fit(row: tuple[str, ...]) -> tuple[str, ...]:
    """The row with its longest text fields cut until it takes at most ROW_BUDGET bytes in the staging CSV, or the row
    itself when it already fits. The fields larger than a common size are cut to it and the smaller ones stay whole, so
    the longest lose the most. The UNCUT columns stay whole. extra is cut as JSON, so it still parses: when it can't be
    made to fit, it is left out and the message says so."""
    sizes = [_csv_size(text) for text in row]
    excess = sum(sizes) - ROW_BUDGET
    if excess <= 0:
        return row
    cap = _cap([sizes[i] for i in CUTTABLE], sum(sizes[i] for i in CUTTABLE) - excess)
    fitted = list(row)
    for i in CUTTABLE:
        if sizes[i] > cap:
            fitted[i] = _cut_extra(row[i], cap) if i == EXTRA else _cut_text(row[i], cap, _csv_size)
    if row[EXTRA] and not fitted[EXTRA]:
        fitted[MESSAGE] += " [extra fields left out to fit one row]"
    return tuple(fitted)


def _cap(sizes: list[int], room: int) -> int:
    """The largest size to cut every larger item to so that all the items fit in room. An item under it keeps its size,
    and room it leaves unused goes to the larger ones."""
    ordered = sorted(sizes)
    for position, size in enumerate(ordered):
        share = room // (len(ordered) - position)
        if size > share:
            return share
        room -= size
    return ordered[-1]


def _cut_text(text: str, room: int, size: Callable[[str], int]) -> str:
    """The longest start of the text that, followed by a note of how many characters the text held, takes at most `room`
    bytes, where `size` measures a candidate. A longer start never takes fewer bytes, so the bisection finds it."""
    note = f" [cut to fit one row: {len(text):,} characters in all]"
    # A start of more than `room` characters can't fit, since a character takes at least one byte
    starts = range(min(len(text), room) + 1)
    fitting = bisect_right(starts, room, key=lambda length: size(text[:length] + note))
    return text[:max(fitting - 1, 0)] + note


def _cut_extra(text: str, room: int) -> str:
    """extra's JSON text with its longest strings cut so it takes at most `room` bytes in the staging CSV, or '' when
    the text isn't JSON, or cutting its strings can't make it fit."""
    try:
        value = json.loads(text)
        strings = list(_strings(value))
    except (ValueError, RecursionError):
        return ""
    sizes = [_json_size(container[key]) for container, key in strings]
    excess = _csv_size(json.dumps(value, ensure_ascii=False)) - room
    cap = _cap(sizes, sum(sizes) - excess) if sizes else 0
    for (container, key), size in zip(strings, sizes):
        if size > cap:
            container[key] = _cut_text(container[key], cap, _json_size)
    cut = json.dumps(value, ensure_ascii=False)
    return cut if _csv_size(cut) <= room else ""


def _strings(value) -> Iterator[tuple[dict | list, str | int]]:
    """Where each string in parsed JSON sits: its container and its key or position."""
    if isinstance(value, dict):
        children = value.items()
    elif isinstance(value, list):
        children = enumerate(value)
    else:
        return
    for key, child in children:
        if isinstance(child, str):
            yield value, key
        else:
            yield from _strings(child)


def well_formed(text: str) -> str:
    """The text with each lone surrogate as U+FFFD. UTF-8 can't hold one, and json.loads makes one from a \\ud83d
    escape in a JSON-lines export of cut UTF-16 text. It is how the events table holds every text, so a
    source path is named this way to replace its rows or to find its hash in the manifest. An ID is
    made first, from the text as it stands (event_uid), so none depends on it."""
    return SURROGATE.sub("\ufffd", text)


def _without_surrogates(row: tuple) -> tuple:
    return tuple(well_formed(v) if isinstance(v, str) else v for v in row)


assert len(_row(Event(0, "", "", "", "", ""), "", "", "", "", "", "")) == len(COLUMNS), "_row must match COLUMNS"
