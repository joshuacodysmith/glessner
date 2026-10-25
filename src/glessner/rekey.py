"""The case format upgrades: 1 to 2, the event IDs that the Amcache, SRUM, Suricata, and SQLECmd key rules changed;
2 to 3, the seal that starts the journal's hash chain (upgrade_chain, near the end of this module); and 3 to 4, which
journals itself and, for output found in the evidence that was loaded while case.yaml named the evidence through a link,
the IDs its events took (upgrade_format_4). The three share the hold on the events database (_held_database), which each
enters on its own.

Format 1 to 2 has ten steps, which the comments below cite by number: (1) hold the events database; (2) when the
journal already holds the step's entry, repair the rows a crash left, in place of steps 3 to 10; (3) group the runs by
tool and host; (4) parse each run for its events' IDs under both rules; (5) check that the pairs account for every
loaded row; (6) check each run's output against its record, before step 4, and its event count, after it; (7) place the
journal's references on the new IDs; (8) reload the rows; (9) record the evidence folder in each tool run made before
runs recorded their folders; (10) word the entry's text.

Each parser whose key rule changed gives every event its ID under format 1's rule too (parsers.FORMER_RULES,
Event.former), from the same record, so the step pairs each loaded ID with its new one without matching by content or
time. It parses every run of each tool and host those parsers touch, checks that the pairs account for every loaded
row of that tool and host, reloads those rows, records the evidence folder in each tool run made before runs
recorded their folders, and returns the case_upgrade entry's fields: the pairs for the IDs the journal names, the IDs it can't
place on one event, and the full map's size and SHA-256. case.upgrade journals them and writes format 2 while the step
still holds the events database, so no other process loads or rebuilds in between. Every part can run again after a
crash: the map comes from the runs' output, not the database.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, replace
from pathlib import Path, PureWindowsPath

import duckdb

from . import case as cases
from . import heads
from .accounts import AFFECTS_SQL, key_sql, name_sids
from .case import JOURNAL_FILE, Case, CaseError, report_stage, upgrade, write_atomically
from .events import EventIds, connect, id_table, names_by_root, transaction
from .hashes import HASHES_SQL
from .intake import counted_record, record_at_head, records_manifest
from .journal import (
    REPLAY_ERRORS,
    SYSTEM,
    UNVOUCHED_WORDS,
    Journal,
    JournalError,
    check,
    copied_from,
    has_chain,
    held,
    host_layout,
    mend_unchained,
    parse_line,
    referenced_ids,
    replay,
    seal_of,
    start_chain,
    unchained_tail,
    upgrade_recorder,
)
from .long_paths import long_path
from .parsers import FORMER_RULES, PARSERS
from .parsers.common import evidence_relative
from .runner import (
    IMPORT,
    RunRecord,
    _write_record,
    evidence_root_name,
    latest_runs,
    parse_context,
    read_runs,
    reload_run,
    run_problems,
)
from .tool_outputs import KINDS

FROM_FORMAT = 1   # the format whose key rules the parsers give in Event.former for this step
REASONS = ["R107", "S3-M9", "R6"]
# Parsers whose tool runs kept their keys: the current rule changed the keys of their output found in the evidence only, so a
# tool and host joins the step through a found-output run. Their tool runs on such a host share its tool ID, and so its rows.
FOUND_ONLY = frozenset({"amcache_csv", "srumecmd_csv"})
# Step 8's dropped runs as the database gave them before it deleted their rows, for a run of the step after a crash
# there (_dropped). Removed once the entry is journaled.
DROPPED_FILE = "upgrade_dropped_runs.json"
LABELS = {"suricata_eve": "Suricata", "amcache_csv": "Amcache", "srumecmd_csv": "SRUM", "sqlecmd_csv": "SQLECmd"}
UPGRADING = "Upgrading the case format"   # the start of every stage the step reports
# The format 3 step's runs to pin and each one's result, for a run of the step after a crash (_pin_runs). Removed once
# the seal is journaled.
PINNED_FILE = "upgrade_pinned_runs.json"
# The format 4 step's runs of found output whose events take new IDs, each with the old ID of every event and its new one,
# written before the step deletes a row and read by a run of the step after a stop (_remap_found_output). Removed once
# the entry is journaled.
RENAMED_FILE = "upgrade_renamed_ids.json"


@dataclass
class Parsed:
    record: RunRecord
    ids: dict[str, str]   # each event's ID under format 1's rule -> its ID now, every event, unchanged ones included
    outside: int          # events whose source names a file outside the evidence folder and the run folders (step 9)


def _reached(step: int) -> None:
    """Called after steps 4, 8, and 9 of format 2's step. Nothing happens here; the tests stop the step at each."""


def _filled(host: str) -> None:
    """Called after the format 3 step fills a host's rows (_fill_columns). Nothing happens here; the tests stop the step
    there."""


@contextmanager
def upgrade_ids(case: Case) -> Iterator[dict | None]:
    """UPGRADES[1] (case.upgrade): the fields of the case_upgrade entry, or None when an earlier run of the step
    journaled them and stopped before case.yaml took format 2. The events database stays open from the first step until
    case.upgrade has written both (step 1). A case without one, such as a fresh copy, has nothing loaded,
    so nothing is checked or reloaded; an empty one is made and held all the same, so a second process upgrading the
    case at once stops rather than journaling the step twice. (After a crash, the step runs again on that one as on any
    database, and its reload loads what a rebuild loads; the entry is the same.)

    First, the bytes after the journal's last LF are mended as the seal step mends them, so a rekey line a crash cut
    short is moved aside and the step runs again. The entry's `recovered` names what was done."""
    loaded = case.db_path.exists()
    # Before the connection adds the format 3 columns: nothing is written when a check refuses, a whole line format 2's
    # reader can't apply included, which the Journal made before this step skips
    _check_unsealed(case, case.folder / JOURNAL_FILE)
    with _held_database(case) as con:
        recovered = _mend(case)
        runs = read_runs(case)
        if _journaled(case, 1, 2):
            if loaded:
                _repair(case, con, runs)
            yield None
        else:
            fields = _remap(case, con if loaded else None, runs)
            yield {**fields, "recovered": recovered} if recovered else fields
        (case.folder / DROPPED_FILE).unlink(missing_ok=True)   # the entry is journaled


@contextmanager
def _held_database(case: Case) -> Iterator[duckdb.DuckDBPyConnection]:
    """The events database, opened read-write and held, with a Windows handle that refuses another process's delete or
    rename, from the first line of an upgrade step to its last. Another process's open fails while it is, so a running
    app stops the step, and another process's load can't start until it ends. Made, empty, when the case has none. Each
    step enters it on its own, one after the other, never nested: a second delete-refusing handle would fail, since the
    first shares no delete access."""
    try:
        con = connect(case.db_path)
    except duckdb.Error as exc:   # IOException from another process; ConnectionException from a connection in this one
        raise CaseError(f"{case.settings.name} needs a case format upgrade, and another program has its events database "
                        f"open, such as glessner serving the case. Close it, then try again. ({exc})") from exc
    try:
        keep = _undeletable(case.db_path)
        try:
            yield con
        finally:
            if keep is not None:
                keep()
    finally:
        con.close()


def _unreadable(case: Case, exc: Exception) -> CaseError:
    return CaseError(f"{case.settings.name} needs a case format upgrade, and its journal can't be read: {exc}")


def _mend(case: Case) -> list[dict]:
    """The unchained tail rule, mend_unchained, as a step runs it: a journal line that parses but can't be applied stops
    the step, as it stops an open, with nothing changed."""
    path = case.folder / JOURNAL_FILE
    if not path.exists():
        return []
    try:
        return mend_unchained(path)
    except JournalError as exc:
        raise _unreadable(case, exc) from exc


def _check_tail(case: Case) -> None:
    """What _mend would refuse, found without writing: both steps ask before their first write, the columns their
    connection adds included, since the reader that stops at the last LF never sees these bytes. _mend asks
    again under the journal's lock."""
    path = case.folder / JOURNAL_FILE
    if not path.exists():
        return
    try:
        unchained_tail(path)
    except JournalError as exc:
        raise _unreadable(case, exc) from exc


def _undeletable(path: Path) -> Callable[[], None] | None:
    """Keep another process from deleting, renaming, or replacing the file until the returned function is called.
    DuckDB opens its database letting another process delete it (measured with DuckDB 1.5.6 on Windows 11), so a
    rebuild in another process, which loads a new database beside the file and then moves it into the file's place,
    could replace the database while the step held it. A handle that asks for delete access and shares only reading
    and writing stops that and leaves DuckDB's own handle alone. Elsewhere a delete can't be refused; DuckDB's lock
    still keeps another process from connecting."""
    if os.name != "nt":
        return None
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
                                     wintypes.DWORD, wintypes.HANDLE]
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    delete, share_read_write, open_existing = 0x00010000, 0x1 | 0x2, 3
    handle = kernel32.CreateFileW(str(path), delete, share_read_write, None, open_existing, 0, None)
    if handle in (None, wintypes.HANDLE(-1).value):
        raise CaseError(f"The case format upgrade can't keep {path} in place: Windows error {ctypes.get_last_error()}.")
    return lambda: kernel32.CloseHandle(handle)


def _journaled(case: Case, from_format: int, to_format: int) -> bool:
    """Whether the journal holds a step's case_upgrade entry already, from `from_format` to `to_format` (format 2's step
    2, and format 4's step): a line of it, the last one too, which a crash may leave without its LF. For a step from a
    format with the chain, only a chained line after the newest chain_break counts: an unchained one that a seal covers
    never stands for it, and a chain_break after one may have put that very line on record as a break, so the step
    writes its own entry after it."""
    path = case.folder / JOURNAL_FILE
    if not path.exists():
        return False
    chained = from_format >= cases.FIRST_CHAINED
    step = ("case_upgrade", from_format, to_format)
    found = False
    with path.open("rb") as f:
        for line in f:
            if b'"case_upgrade"' not in line and not (chained and b'"chain_break"' in line):
                continue
            entry = parse_line(line.rstrip(b"\n"))   # by the rule every reader shares
            if entry is None or (chained and "prev" not in entry):
                continue   # a torn line, which the journal's own read names, or an unchained one
            if (entry.get("action"), entry.get("from_format"), entry.get("to_format")) == step:
                found = True
            elif chained and entry.get("action") == "chain_break":
                found = False
    return found


def _qualifying(runs: list[RunRecord]) -> tuple[set[str], list[RunRecord]]:
    """The parsers with a format 1 rule, and their runs that are successful or put rows in the database."""
    parsers = {name for name, formats in FORMER_RULES.items() if FROM_FORMAT in formats}
    return parsers, [r for r in runs if r.parser in parsers and (r.status == "ok" or r.loaded_rows)]


def _groups(runs: list[RunRecord]) -> dict[tuple[str, str], list[RunRecord]]:
    """Step 3: each tool and host with a run whose parser has a format 1 rule that is successful or put rows in the
    database, Amcache and SRUM only through found output, with every such run of that tool on that host, oldest first:
    runs a later one superseded, a found-output run that loaded and then failed its check (runner.load_found_output),
    and AmcacheParser and SrumECmd tool runs on a host with found output of theirs. A host whose only run of the tool
    loaded and then failed joins too, so its rows drop as a rebuild drops them, named in the entry."""
    _, members = _qualifying(runs)
    keys = {(r.tool, r.host) for r in members if r.from_output or r.parser not in FOUND_ONLY}
    groups: dict[tuple[str, str], list[RunRecord]] = {key: [] for key in sorted(keys)}
    for r in members:
        if (r.tool, r.host) in groups:
            groups[(r.tool, r.host)].append(r)
    return groups


def _unrecorded(con: duckdb.DuckDBPyConnection, runs: list[RunRecord], groups: dict) -> list[str]:
    """The runs, on a tool and host no group selects, of loaded rows whose run has no qualifying record, for a tool whose
    parser has a format 1 rule: the record is gone, or a crash left it running after its load committed. No record
    selects such a tool and host, and a rebuild drops the rows, so step 8 deletes them by run and the entry names them,
    as _check's strays in a group. The pair's other runs, such as an AmcacheParser tool run with no
    found output beside it, are not parsed or pinned; one is reloaded only when those rows had replaced its own
    (_restore). The tools are the ones those parsers' records and found output name, so imports and other tools' rows
    never come in."""
    parsers, members = _qualifying(runs)
    tools = sorted({k.tool for k in KINDS if k.parser in parsers} | {r.tool for r in runs if r.parser in parsers})
    covered = {r.run_id for r in members}
    rows = con.execute(f"SELECT DISTINCT tool, origin_host, run_id FROM events WHERE tool IN ({','.join('?' * len(tools))})",
                       tools).fetchall()
    return sorted({run_id for tool, host, run_id in rows if (tool, host) not in groups and run_id not in covered})


def _parse(case: Case, record: RunRecord) -> Parsed:
    """Step 4: a run's events as its load read them, each ID with its format 1 ID, numbered as each rule's load did."""
    ctx = parse_context(case, record, case.runs_folder / record.run_id, former=FROM_FORMAT)
    ids = EventIds(former=True)
    pairs: dict[str, str] = {}
    outside = 0
    for ev in PARSERS[record.parser](ctx):
        new, old = ids(record.host, ev)
        pairs[old] = new
        # Format 1's source, where it differs: SQLECmd's current rule reads a path in any runs\<run ID>\input folder, so
        # only the old one shows a path its output names outside the case's own folders (step 9)
        outside += _outside(ev.former[0] if ev.former else ev.source_file)
    return Parsed(record, pairs, outside)


def _outside(source: str) -> bool:
    """Whether an event's source file is a path of its own, outside the evidence folder and the run's own folders,
    which parsers.common.evidence_relative keeps as given."""
    return bool(PureWindowsPath(source).drive) or source.startswith(("/", "\\"))


def _remap(case: Case, con: duckdb.DuckDBPyConnection | None, runs: list[RunRecord]) -> dict:
    groups = _groups(runs)
    members = [r for group in groups.values() for r in group]
    reloads = [r for r in latest_runs(runs) if (r.tool, r.host) in groups]
    reloaded = {r.run_id for r in reloads}
    # Step 6, first: a run's output is trusted only when it matches its record. A run that fails stops the step when a
    # rebuild would load it and its rows are still loaded. Any other is skipped and named: a run a rebuild wouldn't
    # load, whose rows step 8 drops; one with no rows, such as one an earlier rebuild left out for the same reason; and
    # any in a case with nothing loaded yet. The check is recorded in verification.jsonl, as every check of the
    # evidence is, also when it stops the step.
    skipped: dict[str, str] = {}
    for i, r in enumerate(members):
        report_stage(f"{UPGRADING}: checking the output of the runs", i + 1, len(members))
        problems, _ = run_problems(case, r, f"case format upgrade reads {r.run_id}")
        if not problems:
            continue
        if r.run_id in reloaded and con is not None and _rows_of(con, r.run_id):
            raise CaseError(f"{case.settings.name} needs a case format upgrade, which reads the output of run {r.run_id} "
                            f"again, and it doesn't match its record: {'; '.join(problems)}. The case is unchanged, at "
                            "format 1. Restore the output, or rerun the tool with the build that made the case.")
        skipped[r.run_id] = f"its output doesn't match its record: {'; '.join(problems)}"
    reading = [r for r in members if r.run_id not in skipped]
    parsed = {}   # step 4
    for i, r in enumerate(reading):
        report_stage(f"{UPGRADING}: reading the output of the runs", i + 1, len(reading))
        parsed[r.run_id] = _parse(case, r)
    _reached(4)
    for run_id, p in list(parsed.items()):   # step 6's count: a parser change since the load shifts repeats' ordinals
        r = p.record
        if run_id not in reloaded and r.loaded_rows is not None and len(p.ids) != r.loaded_rows:
            skipped[run_id] = f"its output gives {len(p.ids):,} events, where its load gave {r.loaded_rows:,}"
            del parsed[run_id]
    report_stage(f"{UPGRADING}: checking the loaded events against the output")
    strays = _check(case, con, groups, parsed, skipped) if con is not None else {}   # step 5
    unrecorded = _unrecorded(con, runs, groups) if con is not None else []
    for run_id in unrecorded:
        strays.setdefault(run_id, set()).update(_rows_of(con, run_id))
    named, candidates = referenced_ids(case.folder / JOURNAL_FILE)
    placed = _place(named, parsed, candidates)   # step 7
    dropped = _dropped(case, con, members, reloaded, parsed, strays, named)
    unreached = None   # the references that reach no loaded event, which only a database can tell
    if con is not None:
        _reload(case, con, groups, reloads)   # step 8
        for run_id in unrecorded:
            _delete(con, "run_id = ?", [run_id])
        _restore(case, con, runs, groups)
        unreached = _unreached(con, named, placed["pairs"], placed["unplaced"])
    _reached(8)
    unpinned = _pin(case, parsed)   # step 9
    _reached(9)
    lines = sorted({f"{old} {new}" for p in parsed.values() for old, new in p.ids.items() if old != new})
    text = "\n".join(lines)
    rekey = {"reasons": REASONS, **placed, "skipped_runs": skipped, "dropped_runs": dropped, "unpinned_runs": unpinned,
             "runs": {run_id: {"parser": p.record.parser, "events": len(p.ids),
                               "changed": sum(old != new for old, new in p.ids.items())}
                      for run_id, p in sorted(parsed.items())},
             "map_size": len(lines), "map_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest()}
    loads = {run_id: p for run_id, p in parsed.items() if run_id in reloaded}   # the case's events
    return {"text": _sentence(loads, placed["pairs"], placed["unplaced"], named, unreached), "rekey": rekey}   # step 10


def _check(case: Case, con: duckdb.DuckDBPyConnection, groups: dict, parsed: dict[str, Parsed],
           skipped: dict[str, str]) -> dict[str, set[str]]:
    """Step 5: every row the reload deletes, each tool's rows on each host whatever run loaded them, must be an event
    its own run's output gives, by its format 1 ID or its ID now (after a crash in the reload). Otherwise the pairs would
    miss it and the references to it would orphan silently, so the step stops, the case unchanged. Rows of a
    skipped run are left to drop, and so are those of a run no rebuild loads and the step can't parse: one whose folder
    is gone, or one a crash stopped between its load and its record. The IDs of those last rows, by run."""
    sets = {run_id: (set(p.ids), set(p.ids.values())) for run_id, p in parsed.items()}
    strays: dict[str, set[str]] = {}
    missed: dict[str, int] = {}
    members = {r.run_id for group in groups.values() for r in group}
    for tool, host in groups:
        for run_id, uid in con.execute("SELECT run_id, event_uid FROM events WHERE tool = ? AND origin_host = ?",
                                       [tool, host]).fetchall():
            if run_id in skipped:
                continue
            if run_id not in members:
                strays.setdefault(run_id, set()).add(uid)
                continue
            former, new = sets[run_id]
            if uid not in former and uid not in new:
                missed[run_id] = missed.get(run_id, 0) + 1
    if missed:
        run_id, n = sorted(missed.items())[0]
        others = f", and {len(missed) - 1:,} other runs have more" if len(missed) > 1 else ""
        raise CaseError(f"{case.settings.name} needs a case format upgrade, and {n:,} loaded "
                        f"{'event' if n == 1 else 'events'} of run {run_id} {'is' if n == 1 else 'are'} not among the "
                        f"events its output gives{others}, so the journal's references to them can't be placed. The case "
                        "is unchanged, at format 1, and the build that loaded it still opens it.")
    return strays


def _dropped(case: Case, con: duckdb.DuckDBPyConnection | None, members: list[RunRecord], reloaded: set[str],
             parsed: dict[str, Parsed], strays: dict[str, set[str]], referenced: set[str]) -> dict[str, dict]:
    """The runs whose rows a rebuild leaves out, which drop in step 8, each with its rows and every journal reference to
    them, so a reference that ends as an orphan is among them. Not every one ends so: a reference also reaches an event
    when a reloaded run gives the same ID, through a pair or unchanged, as a rerun of the same input does. The events
    table says which; the entry names them all. A run the
    step parsed gives them from its output and its record. Otherwise they come from the database, which step 8 empties
    of them, so they are kept in DROPPED_FILE before it, and a run of the step after a crash in step 8 reads them there:
    the entry is the same either way."""
    dropped, from_db = {}, {}
    for r in members:
        if r.run_id not in reloaded and r.status != "ok" and r.loaded_rows:
            p = parsed.get(r.run_id)
            if p:
                dropped[r.run_id] = {"rows": r.loaded_rows, "references": sorted(referenced & {*p.ids, *p.ids.values()})}
            else:
                from_db[r.run_id] = {"rows": r.loaded_rows, "references": sorted(referenced & _rows_of(con, r.run_id))}
    for run_id, uids in strays.items():
        from_db[run_id] = {"rows": len(uids), "references": sorted(referenced & uids)}
    path = case.folder / DROPPED_FILE
    if path.exists():   # read before an earlier run of the step deleted any row
        from_db.update({run_id: v for run_id, v in json.loads(path.read_text(encoding="utf-8")).items()
                        if run_id not in dropped})
    if con is not None and from_db:
        write_atomically(path, json.dumps(from_db, sort_keys=True))   # whole or not there, whenever a crash comes
    return dict(sorted({**dropped, **from_db}.items()))


def _place(named: set[str], parsed: dict[str, Parsed], candidates: set[str]) -> dict:
    """Step 7, the rekey map's pairs, unplaced, merged, and candidates_unplaced: each ID the journal names (`named`) and
    each event an earlier rekey's unplaced ID may have meant (`candidates`, journal.referenced_ids) that a run gives
    under format 1's rule, with its successor in every run that gives it, itself when a run left it unchanged. One
    successor other than itself is a pair; two or more leave it unplaced, with all of them as candidates. An ID no run
    gives is outside the map and stays as written. The IDs two or more of the journal's references reach, an unchanged
    one reaching itself, are merged. A candidate no entry names is no reference: it is placed so the earlier rekey's
    list reads through this map (journal.unplaced), and merges nothing. When it is left unplaced it goes in
    candidates_unplaced, apart from the IDs the journal names, and that map is left out when it holds none."""
    placing = named | candidates
    successors: dict[str, set[str]] = {}
    for p in parsed.values():
        for uid in placing & p.ids.keys():
            successors.setdefault(uid, set()).add(p.ids[uid])
    pairs = {uid: next(iter(s)) for uid, s in sorted(successors.items()) if len(s) == 1 and uid not in s}
    several = {uid: sorted(s) for uid, s in sorted(successors.items()) if len(s) > 1}
    unplaced = {uid: s for uid, s in several.items() if uid in named}
    reach: dict[str, list[str]] = {}
    for uid in sorted(named - unplaced.keys()):
        reach.setdefault(pairs.get(uid, uid), []).append(uid)
    merged = {final: uids for final, uids in sorted(reach.items()) if len(uids) > 1}
    fields = {"pairs": pairs, "unplaced": unplaced, "merged": merged}
    if left := {uid: s for uid, s in several.items() if uid not in named}:
        fields["candidates_unplaced"] = left
    return fields


def _rows_of(con: duckdb.DuckDBPyConnection | None, run_id: str) -> set[str]:
    if con is None:
        return set()
    return {uid for (uid,) in con.execute("SELECT event_uid FROM events WHERE run_id = ?", [run_id]).fetchall()}


def _unreached(con: duckdb.DuckDBPyConnection, named: set[str], pairs: dict, unplaced: dict) -> int:
    """After step 8: how many of the IDs the journal names (`named`) reach no event in the events table, each one
    followed to the ID its pair gives it, so two references to one missing event count twice. The events are those of any
    tool, so a mark on an event of an EVTX log counts only when the event is gone. An ID step 7 left unplaced names more
    than one event and has its own count, so it is left out, and so are an earlier rekey's candidates, which no entry
    names. The IDs go to one query as a list."""
    reached = [pairs.get(uid, uid) for uid in sorted(named - unplaced.keys())]
    return con.execute("SELECT count(*) FROM (SELECT unnest(?::VARCHAR[]) AS uid) AS r ANTI JOIN events e "
                       "ON e.event_uid = r.uid", [reached]).fetchone()[0]


def _reload(case: Case, con: duckdb.DuckDBPyConnection, groups, reloads: list[RunRecord]) -> None:
    """Step 8: each tool's rows on each host are deleted, then the runs a rebuild loads for it are loaded again, in its
    order and with its checks. Found SRUM's empty sources and SQLECmd's absolute paths differ from the new ones, so a load
    alone would leave them as duplicates. Loads of other tools never touch these rows, so the result is a rebuild's. The
    loads connect in this process, beside the held connection."""
    layout = host_layout(case)
    for i, (tool, host) in enumerate(groups):
        rows = con.execute("SELECT count(*) FROM events WHERE tool = ? AND origin_host = ?", [tool, host]).fetchone()[0]
        label = LABELS.get(next((r.parser for r in reloads if (r.tool, r.host) == (tool, host)), ""), tool)
        report_stage(f"{UPGRADING}: reloading {rows:,} {label} {'event' if rows == 1 else 'events'}", i + 1, len(groups))
        _delete(con, "tool = ? AND origin_host = ?", [tool, host])
        for record in reloads:
            if (record.tool, record.host) == (tool, host):
                reload_run(case, record, layout)


def _delete(con: duckdb.DuckDBPyConnection, where: str, params: list) -> None:
    with transaction(con):
        lanes = con.execute(f"SELECT list(DISTINCT host) FILTER (WHERE {AFFECTS_SQL}) FROM events WHERE {where}",
                            params).fetchone()[0]
        con.execute(f"DELETE FROM events WHERE {where}", params)
        name_sids(con, lanes or ())   # as a load's delete does, for rows that name accounts


def _repair(case: Case, con: duckdb.DuckDBPyConnection, runs: list[RunRecord]) -> None:
    """Step 2: the entry is in the journal, and case.yaml didn't take format 2. A tool and host whose rows aren't all
    events of the runs a rebuild loads, by their IDs now, or one of whose runs has no rows, is reloaded: a crash in the
    reload, or a rebuild by a format 1 build meanwhile, left it so. Rows _unrecorded finds, such as a format 1 build's
    load meanwhile that stopped before its record, are deleted, and the runs whose rows that load replaced are loaded
    again (_restore)."""
    groups = _groups(runs)
    reloads = [r for r in latest_runs(runs) if (r.tool, r.host) in groups]
    new = {r.run_id: set(_parse(case, r).ids.values()) for r in reloads}
    for key in groups:
        rows = con.execute("SELECT run_id, event_uid FROM events WHERE tool = ? AND origin_host = ?", list(key)).fetchall()
        present = {run_id for run_id, _ in rows}
        if (any(uid not in new.get(run_id, ()) for run_id, uid in rows)
                or any(new[r.run_id] and r.run_id not in present for r in reloads if (r.tool, r.host) == key)):
            _reload(case, con, {key: groups[key]}, reloads)
    for run_id in _unrecorded(con, runs, groups):
        _delete(con, "run_id = ?", [run_id])
    _restore(case, con, runs, groups)


def _restore(case: Case, con: duckdb.DuckDBPyConnection, runs: list[RunRecord], groups: dict) -> None:
    """After _unrecorded's rows are deleted: a run a rebuild loads on a tool and host no group selects, an AmcacheParser
    or SrumECmd tool run, can have fewer rows than its load gave, because a rerun of it on the same input replaced them
    and then lost its record. Each such tool and host is reloaded as a rebuild loads it. No rule changed
    those runs' IDs, so the entry is the same. A crash at any point leaves the runs short, so the next run of the step
    reloads them. Once reloaded, none is short: a run the check before its load leaves out, as a rebuild does, records
    0 rows."""
    latest = [r for r in latest_runs(runs) if (r.tool, r.host) not in groups and r.parser in FOUND_ONLY]
    rows = lambda run_id: con.execute("SELECT count(*) FROM events WHERE run_id = ?", [run_id]).fetchone()[0]
    short = sorted({(r.tool, r.host) for r in latest if r.loaded_rows and rows(r.run_id) < r.loaded_rows})
    if short:
        _reload(case, con, {key: [] for key in short}, latest)


def _pin(case: Case, parsed: dict[str, Parsed]) -> dict[str, str]:
    """Step 9: a tool run made before runs recorded their folders is read against the case's evidence
    folder and its own run folder. Both are written into its record when every file its output names lies under them,
    so a later move of the evidence keeps its IDs. Found-output and import runs leave the fields empty on purpose: they
    are read where the evidence is now. The runs left empty, with why."""
    unpinned = {}
    for i, (run_id, p) in enumerate(sorted(parsed.items())):
        report_stage(f"{UPGRADING}: recording where the runs read their files", i + 1, len(parsed))
        r = p.record
        if r.from_output or r.parser == IMPORT or r.evidence_root:
            continue
        if why := _pin_one(case, r, p.outside):
            unpinned[run_id] = why
    return unpinned


def _pin_one(case: Case, r: RunRecord, outside: int) -> str:
    """One tool run's pin, for a run made before runs recorded their folders, which both format steps make (_pin,
    _pin_runs): with no event of its output naming a file outside the case's folders, the evidence folder and, for a
    run that worked on copies, its own input folder are written into its record, so a later move of the evidence keeps
    its IDs. Otherwise why it is left empty, or ''."""
    if outside:
        return (f"{outside:,} of its events name a file outside the case's evidence folder and the run's own folder, "
                "so where it read its files can't be known")
    r.evidence_root = str(case.evidence)
    if r.working_copies and not r.input_root:
        r.input_root = str(case.runs_folder / r.run_id / "input")
    _write_record(case.runs_folder / r.run_id, r)
    return ""


def _sentence(parsed: dict[str, Parsed], pairs: dict, unplaced: dict, named: set[str], unreached: int | None = None) -> str:
    """The entry's text: the events of the runs a rebuild loads whose IDs the new rules change, by tool, and the
    journal references the map moved: the IDs the journal names (`named`) among its pairs, and its unplaced IDs. The
    pairs also hold the earlier rekeys' candidates it placed, which are no reference. Counted from the runs' output, so a
    run of the step after a crash says the same. A moved case's SQLECmd rows loaded before the move already have their
    new IDs, and are counted too. A last sentence gives how many references name no loaded event (`unreached`, from
    _unreached) when that is above 0; with no database it is None and the text says nothing of it."""
    changed: dict[str, set[str]] = {}
    for p in parsed.values():
        changed.setdefault(p.record.parser, set()).update(new for old, new in p.ids.items() if old != new)
    counts = [f"{len(changed[name]):,} {label} {'event' if len(changed[name]) == 1 else 'events'}"
              for name, label in LABELS.items() if changed.get(name)]
    what = "Event IDs no longer depend on where or in which time zone a tool ran"
    text = f"{what}: {_listed(counts)} took new IDs." if counts else f"{what}; no event here took a new ID."
    return text + _references_sentence(pairs, unplaced, named, unreached)


def _references_sentence(pairs: dict, unplaced: dict, named: set[str], unreached: int | None) -> str:
    """What a rekey's text says of the journal's references, each sentence after a space: how many now name their
    event's new ID, how many are left unplaced, and how many name no loaded event."""
    text = ""
    n, u = len(pairs.keys() & named), len(unplaced)
    if not n and not u:
        text += " No journal reference changed."
    else:
        text += (" No journal reference was placed on a new ID." if n == 0
                 else " 1 journal reference now names its event's new ID." if n == 1
                 else f" {n:,} journal references now name their events' new IDs.")
        text += (" None was left unplaced." if not u
                 else f" {u:,} {'was' if u == 1 else 'were'} left unplaced, each naming more than one event; the Case "
                      "overview counts them, and each event they may mean says so.")
    if unreached:
        text += (" 1 journal reference names no loaded event." if unreached == 1
                 else f" {unreached:,} journal references name no loaded event.")
    return text


def _listed(items: list[str]) -> str:
    if len(items) < 3:
        return " and ".join(items)
    return f"{', '.join(items[:-1])}, and {items[-1]}"


@contextmanager
def upgrade_chain(case: Case) -> Iterator[dict | None]:
    """UPGRADES[2] (case.upgrade): the seal, which starts the journal's hash chain. The fields of its case_upgrade entry,
    which upgrade_recorder writes as the chain's first line, or None when the journal holds a chained line already: a
    crash came after the seal and before case.yaml took format 3, so only the number is written.

    The events database is held from the first line of the step to the last, as format 2's step holds it, so a running
    app stops the step. The checks that can refuse the step come before it writes anything, the columns its connection
    adds included: format 2's reader over every line, the bytes after the last LF, and the head recorded outside the
    case. The pins and the column fill (_pin_runs, _fill_columns) are the slow parts and run under that hold only. Then,
    under the journal's held context, which the record re-enters in this thread: the checks again, since the journal
    could change meanwhile; the bytes after the last LF, mended so the seal covers whole lines only and the replayed
    state stays the same; and the seal's fields, naming every byte before it. Leaving the step releases both."""
    path = case.folder / JOURNAL_FILE
    if not (path.exists() and has_chain(path)):
        _check_unsealed(case, path)   # the read-only checks first: a refusal leaves the columns, pins, and fill undone
    elif any(p["kind"] == "chain_missing" for p in check(path).problems):
        # Its only chained-looking line is a last line without its LF that starts no chain (the start rule): format 3
        # would open it read-only with no Continue to offer, so the step stops with the case at format 2
        raise CaseError(f"{case.settings.name} needs a case format upgrade, and the last line of its journal looks like "
                        "the hash chain's first line but is not one: it has no line end, and it is neither a case_created "
                        "nor the seal of the lines before it. Nothing was changed; restore the journal from a copy of the "
                        "case folder, or remove that line by hand.")
    with _held_database(case) as con:
        path.touch(exist_ok=True)
        if has_chain(path):
            yield None
            (case.folder / PINNED_FILE).unlink(missing_ok=True)   # the seal is journaled
            return
        pins, pinned = _pin_runs(case, con)
        columns, filled = _fill_columns(case, con)
        with held(path):
            _check_unsealed(case, path)   # again, since the pins and the fill take minutes
            recovered = _mend(case)
            sealed = seal_of(path)
            fields = {"text": " ".join(t for t in (_seal_sentence(sealed), pinned, filled) if t), "sealed": sealed}
            if recovered:
                fields["recovered"] = recovered
            fields.update(pins=pins, columns=columns)
            yield fields
        (case.folder / PINNED_FILE).unlink(missing_ok=True)   # the seal is journaled


def _pin_runs(case: Case, con: duckdb.DuckDBPyConnection) -> tuple[dict, str]:
    """The seal step's pinning: the evidence folder recorded on every remaining tool run made before runs recorded
    their folders, whose output names no file outside the case's folders. The runs are format 2's _qualifying
    ones of every parser: tool runs (not found output, not imports) of a parser this build has, with no folder recorded,
    that succeeded or loaded rows. Each one's output is checked against its record (run_problems, which for a tool run
    reads only its own output folder), then parsed as format 2's step parses (_parse, with format 1's sources: SQLECmd's
    rule reads a path in any run's input folder as its own, so only format 1's source shows one outside the case's
    folders), and pinned by _pin_one, as format 2's step pins. The rest are named in _pin's words.

    PINNED_FILE holds the runs to check and each one's result, written before the first record changes and after each
    result, so a run of the step after a crash names every run, also the ones whose records it had already pinned. It
    is removed once the seal is journaled (upgrade_chain). The `pins` field and its sentence.

    A run whose check fails, or whose output today's parser refuses, is left as it was and named with the reason, like
    one that names files outside the case: one such run must not stop a step that runs again at every open."""
    path = case.folder / PINNED_FILE
    kept = json.loads(path.read_text(encoding="utf-8")) if path.exists() else None
    records = {r.run_id: r for r in read_runs(case)}
    if kept is None:
        chosen = sorted(r.run_id for r in records.values() if not r.from_output and r.parser != IMPORT
                        and r.parser in PARSERS and not r.evidence_root and (r.status == "ok" or r.loaded_rows))
        kept = {"runs": chosen, "pinned": [], "unpinned_runs": {}}
        if chosen:
            write_atomically(path, json.dumps(kept, sort_keys=True))
    for i, run_id in enumerate(kept["runs"]):
        report_stage(f"{UPGRADING}: recording where the runs read their files", i + 1, len(kept["runs"]))
        if run_id in kept["pinned"] or run_id in kept["unpinned_runs"]:
            continue
        r = records.get(run_id)
        if r is None:
            kept["unpinned_runs"][run_id] = "its run record is gone"
        elif r.evidence_root:   # pinned by a run of the step that stopped before it wrote this run's result
            kept["pinned"].append(run_id)
        else:
            if why := _pin_check(case, r):
                kept["unpinned_runs"][run_id] = why
            else:
                kept["pinned"].append(run_id)
        write_atomically(path, json.dumps(kept, sort_keys=True))
    pins = {"pinned": sorted(kept["pinned"]), "unpinned_runs": dict(sorted(kept["unpinned_runs"].items()))}
    return pins, _pins_sentence(pins)


def _pin_check(case: Case, r: RunRecord) -> str:
    """Why a run can't be pinned, or '' once it is: its output doesn't match its record, today's parser can't read it, or
    it names files outside the case's folders (_pin_one)."""
    try:
        problems, _ = run_problems(case, r, f"case format upgrade reads {r.run_id}")
        if problems:
            return f"its output doesn't match its record: {'; '.join(problems)}"
        outside = _count_outside(case, r)
    except Exception as exc:   # noqa: BLE001  (a parser refusing older output, or any failure reading it, is named, never fatal)
        return f"its output can't be read by this build ({type(exc).__name__}: {exc})"
    return _pin_one(case, r, outside)


def _count_outside(case: Case, record: RunRecord) -> int:
    """_parse's `outside`, counted event by event without its ID maps, which the pins don't need and which would hold two
    IDs per event of a run in memory."""
    ctx = parse_context(case, record, case.runs_folder / record.run_id, former=FROM_FORMAT)
    return sum(_outside(ev.former[0] if ev.former else ev.source_file) for ev in PARSERS[record.parser](ctx))


def _pins_sentence(pins: dict) -> str:
    pinned, left = len(pins["pinned"]), len(pins["unpinned_runs"])
    if not pinned and not left:
        return ""
    its = "its" if pinned == 1 else "their"
    text = (f"Recorded where {pinned:,} earlier tool {'run' if pinned == 1 else 'runs'} read {its} files, so a later "
            f"move of the evidence keeps {its} events' IDs" if pinned else "Recorded where no earlier tool run read its files")
    if left == 1:
        text += "; 1 run was left as it was, named with the reason"
    elif left:
        text += f"; {left:,} runs were left as they were, each named with the reason"
    return f"{text}."


def _fill_columns(case: Case, con: duckdb.DuckDBPyConnection) -> tuple[dict, str]:
    """The seal step's fill: the account key and the hashes filled in place for the events loaded
    before the step, from each row's own stored values, by the expressions a load computes them with
    (accounts.key_sql, hashes.HASHES_SQL), so the two can't differ. The connection's hold added both columns, NULL in
    every older row (events.connect). Each host is filled in its own transaction, and only the rows still NULL, so a
    run of the step after a crash fills what is left, and its counts are the rows this run filled. Every source this
    build reads a hash from stores it in the row, so none waits for a rebuild. No ID, mark, or reference changes: the
    fill writes only the two columns. Returns the `columns` field, the rows filled in each column, which the entry
    holds even when both are 0, and its sentence, which is empty then."""
    hosts = [h for (h,) in con.execute("SELECT DISTINCT origin_host FROM events WHERE account_key IS NULL OR hashes IS NULL "
                                       "ORDER BY origin_host").fetchall()]
    filled = {"account_key": 0, "hashes": 0}
    for i, host in enumerate(hosts):
        report_stage(f"{UPGRADING}: filling the account key and the hashes", i + 1, len(hosts))
        with transaction(con):
            for column, expression in (("account_key", key_sql("user_name", "user_domain")), ("hashes", HASHES_SQL)):
                filled[column] += con.execute(f"UPDATE events SET {column} = {expression} "
                                              f"WHERE origin_host IS NOT DISTINCT FROM ? AND {column} IS NULL",
                                              [host]).fetchone()[0]
        _filled(host)
    n = max(filled.values())
    if not n:
        return filled, ""
    return filled, (f"Filled the account key and the hashes for {n:,} loaded {'event' if n == 1 else 'events'}, for "
                    "Same account and Same hash. The key comes from each event's stored user name and domain, so events "
                    "loaded before the account lookup keep the key those names give, and a rebuild can change it.")


def _check_unsealed(case: Case, path: Path) -> None:
    """The checks of an open for work on a journal with no chain yet. Format 2's reader takes every whole line,
    or the step stops, as an open stops: with the line's number for one that isn't JSON, and with the reader's error for
    a line it can't apply. And _check_set_back, and the bytes after the last LF (_check_tail)."""
    try:
        replay(path)
    except (JournalError, *REPLAY_ERRORS) as exc:
        raise _unreadable(case, exc) from exc
    _check_set_back(case)
    _check_tail(case)


def _check_set_back(case: Case) -> None:
    """A head recorded outside the case, with a journal that has no chain, means the case had a chain and was set back
    from a format with the chain, so a step stops before it writes anything, naming the record. Both steps ask first:
    format 2's step would otherwise reload and write format 2 into a case that is refused a moment later."""
    path = case.folder / JOURNAL_FILE
    if path.exists() and has_chain(path):
        return
    record = heads.read(case.folder)
    if record is not None:
        raise CaseError(
            f"{case.settings.name} is at case format {case.settings.case_format} and its journal has no hash chain, but "
            f"this computer recorded the head of its chain, entry #{record['seq']}, at {record.get('at', '')}, in "
            f"{heads.path_for(case.folder)}. The case was set back from a format with the chain and its chained lines "
            "removed, or its folder was restored from a copy made before its upgrade. Nothing was changed. Restore the "
            "case folder from a copy made after the upgrade; or, if the reset was intended, remove that file and open "
            "the case again, which seals the journal as it stands.")


def _seal_sentence(sealed: dict) -> str:
    chain = "the hash chain: each entry from here names the one before it and the build that wrote it."
    if not sealed["bytes"]:
        return f"Started {chain} The journal had no earlier entries to seal."
    n = sealed["lines"]
    return (f"Sealed the {n:,} earlier journal {'entry' if n == 1 else 'entries'} ({sealed['bytes']:,} bytes) and "
            f"started {chain}")


FORMAT_4_OPENS = "Only builds that read case format 4 open the case from here on."
FORMAT_4_TEXT = f"{FORMAT_4_OPENS} Nothing already in the case changed."


@contextmanager
def upgrade_format_4(case: Case) -> Iterator[dict | None]:
    """UPGRADES[3] (case.upgrade): the fields of the case_upgrade entry, which upgrade_recorder writes as an ordinary
    chained entry after the journal's read-only checks; or None when the journal holds the step's chained entry
    already: a crash came after it and before case.yaml took format 4, so upgrade_recorder runs the same checks and
    only the number is written. Either way a journal with no chain or with a break raises KeptAtFormat, and the case
    stays at format 3. The events database is held from the first line of the step to the last, as the earlier steps
    hold it, so a running app stops the step before it writes.

    The entry says only that nothing in the case changed, except for found output (_remap_found_output), whose step
    changes the events database and so asks the journal's checks first (case.check_journal). The names the moved runs'
    events carried are kept in RENAMED_FILE until the entry is journaled. A journal that holds a line a case at format 4
    has already can't take the step's rekey, so the step moves nothing then and names the runs, except for runs an
    earlier open began to load again, which stop it."""
    loaded = case.db_path.exists()
    with _held_database(case) as con:
        if _journaled(case, 3, 4):
            yield None
        else:
            closed = cases.check_journal()
            yield _remap_found_output(case, con if loaded else None, closed) or {"text": FORMAT_4_TEXT}
        (case.folder / RENAMED_FILE).unlink(missing_ok=True)   # the entry is journaled


def _linked(case: Case) -> bool:
    """Whether a file in the evidence is named differently against the evidence path as case.yaml writes it than against
    the resolved path, which found output is read under (parse_context): case.yaml names the evidence through a
    junction, a substituted drive, or a mapped one."""
    return evidence_relative(str(long_path(case.evidence, "probe")), case.evidence) != "probe"


LONG_FORM = "//?/"   # how a source file names a file outside the evidence root it was read under (evidence_relative)


def _stored_sources(con: duckdb.DuckDBPyConnection, runs: list[RunRecord]) -> dict[str, set[str]]:
    """Each run's source files in the events table. A run with no rows is not in the answer."""
    held = id_table(con, "found_runs", sorted(r.run_id for r in runs))
    rows = con.execute(f"SELECT DISTINCT run_id, source_file FROM events WHERE run_id IN (SELECT v FROM {held})").fetchall()
    found: dict[str, set[str]] = {}
    for run_id, source in rows:
        found.setdefault(run_id, set()).add(source)
    return found


def _inputs_by_name(case: Case, record: RunRecord) -> dict[str, str]:
    """A run of found output's inputs, each by the name its events carry now: the path under the resolved evidence root
    (parse_context), evidence-relative."""
    root = long_path(case.evidence)
    return {evidence_relative(str(long_path(root, p)), root): p for p in (PureWindowsPath(q).as_posix() for q in record.inputs)}


def _old_names(case: Case, record: RunRecord, stored: set[str] | None) -> dict[str, str]:
    """Each input of a run of found output, by the name its events carry now, with the name a load under a link gave
    them: the file's whole path. The stored names (`stored`, the events table's extended-length ones) are matched to the
    inputs by the run's root (events.names_by_root, which a later load of found output replaces rows by), so the old name
    is the one the rows carry, whatever has happened to the evidence since. With none, it is where the file is now."""
    inputs = _inputs_by_name(case, record)
    if stored is None:
        root = long_path(case.evidence)
        return {name: PureWindowsPath(str(long_path(root, p))).as_posix() for name, p in inputs.items()}
    by_input = {p: name for name, p in inputs.items()}
    return {by_input[p]: source for source, p in names_by_root(stored, inputs.values(), evidence_root_name(case)).items()}


def _renamed_ids(case: Case, record: RunRecord, old: dict[str, str], con: duckdb.DuckDBPyConnection | None) -> Parsed:
    """A run of found output's events, each ID with the one a load gave it while the evidence root was the path as
    case.yaml writes it, which names a file by its whole path when that path is a link: the output is read once, and
    each event's file is named as `old` gives it (_old_names). With `con`, only the IDs the run's rows hold, so a pair is
    always of an event that is stored."""
    now = parse_context(case, record, case.runs_folder / record.run_id)
    ids_then, ids_now = EventIds(), EventIds()
    pairs = {}
    for event in PARSERS[record.parser](now):
        then = replace(event, source_file=old.get(event.source_file, event.source_file))
        pairs[ids_then(record.host, then)[0]] = ids_now(record.host, event)[0]
    if con is not None:
        held = id_table(con, "renamed_ids", pairs)
        rows = con.execute(f"SELECT event_uid FROM events WHERE run_id = ? AND event_uid IN (SELECT v FROM {held})",
                           [record.run_id]).fetchall()
        present = {uid for (uid,) in rows}
        pairs = {before: after for before, after in pairs.items() if before in present}
    return Parsed(record, pairs, 0)


def _read_run(case: Case, record: RunRecord, names: dict[str, str] | None, stored: set[str] | None,
              con: duckdb.DuckDBPyConnection | None) -> tuple[Parsed | None, dict[str, str], str]:
    """A run of found output checked against its record and read once (_renamed_ids): the pairs, the names the events
    carried (`names`, or _old_names of the run's `stored` rows when none are given), and why not, "" when it was read. A
    run that fails either check, or that this build can't read, has no pairs and says why."""
    try:
        problems, _ = run_problems(case, record, f"case format upgrade reads {record.run_id}")
        if problems:
            return None, {}, f"its output doesn't match its record: {'; '.join(problems)}"
        names = names or _old_names(case, record, stored)
        return _renamed_ids(case, record, names, con if stored else None), names, ""
    except Exception as exc:   # noqa: BLE001  (a parser refusing the output, or any failure reading it, is named, never fatal)
        return None, {}, f"its output can't be read by this build ({type(exc).__name__}: {exc})"


def _remap_found_output(case: Case, con: duckdb.DuckDBPyConnection | None, closed: bool = False) -> dict | None:
    """The 3 to 4 entry's fields for output found in the evidence that a build loaded while case.yaml named the evidence
    through a link, or None when the step has nothing to say of it, which is the usual case and reads no output.

    The runs are the ones a rebuild loads (latest_runs) whose rows in the events table name a file by an extended-length
    path. A run with no rows, such as every run of a case with no events database or one the step stopped in, is read
    when case.yaml names the evidence through a link (_linked), and counts only if the journal names an ID the old naming
    gives, since nothing else shows it was loaded that way. A run with rows in the plain form is left alone, whatever
    case.yaml says now. Each run is checked against its record and read once under the name its rows carry
    (_read_run); one that fails either is left as it is and named, since one run must not stop a step that runs
    again at every open, and its events keep the IDs they have. When `closed`, the journal holds a line that closes the
    place of the rekey from format 3 to 4 (journal.check_for_upgrade), so every run whose IDs would move is left as it is
    and named instead, before the first row is deleted: every reader would call the entry a break. The pairs for the IDs
    the journal names are placed as format 2's step places them (_place). With a database, the rows of the runs whose
    events took new IDs are deleted and the runs loaded again, in a rebuild's order, so the rows are a rebuild's and the
    references find them.

    Before the first row is deleted, the name each such run's events carried is written to RENAMED_FILE (_keep_names). A
    case with no events database has no run to finish, so the step leaves the file unread there and removes it with the
    entry. A run of the step that finds the file reads the runs whose rows a stop left plain or took from it
    (_stopped_names): the names are only the old half of each pair, so the pairs come from the run's output, and the
    run's rows must be the ones that output gives. Such a run that can't be read, whose names or rows don't fit it, or
    that the journal can't take a rekey for, stops the step instead (_cannot_finish): its old IDs are in no row, so
    naming it would lose them. A run whose rows are still in the old form is read from them, as a run the step never
    touched. A stopped run with rows is moved again only when the journal names one of its old IDs, and one with none
    always is, since it has no events until it is loaded. Nothing is journaled before the load, so a stop anywhere in the
    step leaves format 3 and the next run of the step does the load again and journals the same pairs."""
    members = [r for r in latest_runs(read_runs(case)) if r.from_output and r.parser in PARSERS]
    sources = _stored_sources(con, members) if con is not None else {}
    linked = _linked(case)
    kept = _kept_names(case) if con is not None else {}   # a stop that kept names had a database
    long_names: dict[str, set[str] | None] = {}   # each run to read, with the extended-length names its rows hold
    for r in members:
        names = {source for source in sources.get(r.run_id, ()) if source.startswith(LONG_FORM)}
        if names or (linked and r.run_id not in sources) or r.run_id in kept:
            long_names[r.run_id] = names or None
    runs = [r for r in members if r.run_id in long_names]
    stopped = {r.run_id for r in runs if r.run_id in kept and not long_names[r.run_id]}   # rows a stop left plain or took
    named, candidates = referenced_ids(case.folder / JOURNAL_FILE) if runs else (set(), set())
    parsed: dict[str, Parsed] = {}
    olds: dict[str, dict[str, str]] = {}
    skipped: dict[str, str] = {}
    for i, r in enumerate(runs):
        report_stage(f"{UPGRADING}: reading the found output of the runs", i + 1, len(runs))
        stored, resumed = long_names[r.run_id], r.run_id in stopped
        read, names, reason = _read_run(case, r, _stopped_names(case, r, kept[r.run_id]) if resumed else None, stored, con)
        if read is None:
            if resumed:
                raise _cannot_finish(
                    case, f"run {r.run_id} can't be read now ({reason}), and the step began to load it again, so its old IDs "
                    "are in no row",
                    f"Put the evidence back as it was and open the case again, or remove {RENAMED_FILE}, after which the "
                    "marks, tags, notes, and findings on that run's events name IDs no event has")
            skipped[r.run_id] = reason
        elif resumed and r.run_id in sources and con is not None and not _rows_fit(con, r.run_id, read.ids.values()):
            raise _cannot_finish(
                case, f"the rows of run {r.run_id} aren't the ones its output gives",
                f"Remove {RENAMED_FILE}, which only a stopped upgrade leaves, then open the case again")
        elif stored and not read.ids:
            skipped[r.run_id] = "none of the events its output gives are in the events table under the names its rows carry"
        elif stored or (resumed and r.run_id not in sources) or (named | candidates) & read.ids.keys():
            parsed[r.run_id], olds[r.run_id] = read, names
    moved = {run_id: p for run_id, p in parsed.items() if any(old != new for old, new in p.ids.items())}
    if closed and (again := [run_id for run_id in moved if run_id in stopped]):
        raise _cannot_finish(
            case, f"the journal holds a line only a case at format 4 has, after which a rekey of event IDs is a break, and "
            f"run {again[0]} was loaded again by an earlier open, so its old IDs are in no row",
            f"Remove {RENAMED_FILE}, after which the marks, tags, notes, and findings on that run's events name IDs no "
            "event has, or restore the journal and case.yaml from a copy made before the line was added")
    left = list(moved) if closed else []   # the runs whose IDs would move, left as they are when the journal can't take a rekey
    if left:
        moved = {}
    if not moved:
        if not (skipped or left):
            return None
        text = " ".join(filter(None, (FORMAT_4_TEXT, left and _closed_sentence(left), skipped and _skipped_sentence(skipped))))
        return {"text": text, "skipped_runs": {**skipped, **dict.fromkeys(left, CLOSED_REASON)}}
    placed = _place(named, parsed, candidates)
    unreached = None
    if con is not None:
        _keep_names(case, kept, {run_id: olds[run_id] for run_id in moved})
        _reload_found(case, con, runs, moved)
        unreached = _unreached(con, named, placed["pairs"], placed["unplaced"])
    lines = sorted({f"{old} {new}" for p in moved.values() for old, new in p.ids.items() if old != new})
    rekey = {**placed, "skipped_runs": skipped,
             "runs": {run_id: {"parser": p.record.parser, "events": len(p.ids),
                               "changed": sum(old != new for old, new in p.ids.items())}
                      for run_id, p in sorted(moved.items())},
             "map_size": len(lines), "map_sha256": hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()}
    text = _found_output_sentence(len(lines), placed["pairs"], placed["unplaced"], named, unreached)
    return {"text": f"{text} {_skipped_sentence(skipped)}" if skipped else text, "rekey": rekey}


def _cannot_finish(case: Case, why: str, remedy: str) -> CaseError:
    """The error for a step that can't finish what an earlier open began: nothing has been changed, so the case stays at
    format 3 with RENAMED_FILE in place, and `remedy` says what to do."""
    return CaseError(f"{case.settings.name} needs a case format upgrade that an earlier open began, and it can't finish: "
                     f"{why}. The case is unchanged, at format 3, and {RENAMED_FILE} is in place. {remedy}.")


def _kept_names(case: Case) -> dict[str, dict[str, str]]:
    """The runs an earlier run of the step began to load again, each with the name its events carried for every file it
    read (_old_names), by the name they carry now (_keep_names); none when no such run stopped. A file that isn't a map of
    runs to maps of names stops the step, with the case unchanged."""
    path = case.folder / RENAMED_FILE
    if not path.is_file():
        return {}
    try:
        kept = json.loads(path.read_text(encoding="utf-8"))
        if not (isinstance(kept, dict) and all(
                isinstance(names, dict) and names and all(isinstance(now, str) and isinstance(old, str)
                                                          for now, old in names.items())
                for names in kept.values())):
            raise ValueError("it isn't a map of runs to maps of file names")
    except (OSError, ValueError, RecursionError) as exc:
        raise CaseError(f"{case.settings.name} needs a case format upgrade, and {path} can't be read: {exc}. The case is "
                        "unchanged, at format 3. Remove the file, which only a stopped upgrade leaves, then open the "
                        "case again.") from exc
    return kept


def _stopped_names(case: Case, record: RunRecord, kept: dict[str, str]) -> dict[str, str]:
    """The names a stopped step kept for a run whose rows it left plain or took, when they are ones a load under a link
    gives the run's files: each is the extended-length name of one of its inputs, by the name that input's events carry
    now, ends in the input's path, and all share one root. A CaseError otherwise, since the step wrote no such file."""
    inputs = _inputs_by_name(case, record)
    roots = set()
    for name, old in kept.items():
        path = inputs.get(name)
        if path is None or not old.startswith(LONG_FORM) or not old.casefold().endswith(f"/{path.casefold()}"):
            raise _cannot_finish(
                case, f"{RENAMED_FILE} names {name!r} for run {record.run_id}, which is not a name a load under a link gave a "
                "file the run read",
                f"Remove {RENAMED_FILE}, which only a stopped upgrade leaves, then open the case again")
        roots.add(old.casefold()[:-len(path.casefold()) - 1])   # folding can lengthen a name: "ß" folds to "ss"
    if len(roots) != 1:
        raise _cannot_finish(
            case, f"{RENAMED_FILE} gives the files of run {record.run_id} more than one root",
            f"Remove {RENAMED_FILE}, which only a stopped upgrade leaves, then open the case again")
    return kept


def _rows_fit(con: duckdb.DuckDBPyConnection, run_id: str, ids: Iterable[str]) -> bool:
    """Whether every row of the run has one of `ids`."""
    held = id_table(con, "fitting_ids", ids)
    (strangers,) = con.execute(f"SELECT count(*) FROM events WHERE run_id = ? AND event_uid NOT IN (SELECT v FROM {held})",
                               [run_id]).fetchone()
    return not strangers


def _keep_names(case: Case, kept: dict[str, dict[str, str]], moved: dict[str, dict[str, str]]) -> None:
    """Before the step deletes a row: the runs in `moved` and those already in RENAMED_FILE (`kept`), each with the name
    its events carried for every file, written whole or not at all. A stop after that leaves a file the next run of the
    step reads, whatever state the rows and case.yaml are in. The file is removed once the entry is journaled
    (upgrade_format_4)."""
    now = {**kept, **moved}
    if now != kept:
        write_atomically(case.folder / RENAMED_FILE, json.dumps(now, sort_keys=True))


def _reload_found(case: Case, con: duckdb.DuckDBPyConnection, runs: list[RunRecord], moved: dict[str, Parsed]) -> None:
    """The rows of the runs in `moved` deleted, then loaded again as a rebuild loads them, in its order and with its
    checks (runner.reload_run), which writes each run's record again. `runs` are the ones a rebuild loads."""
    for i, run_id in enumerate(moved):
        report_stage(f"{UPGRADING}: reloading the found output of the runs", i + 1, len(moved))
        _delete(con, "run_id = ?", [run_id])
    layout = host_layout(case)
    for record in runs:
        if record.run_id in moved:
            reload_run(case, record, layout)


CLOSED_REASON = "the journal holds a line only a case at format 4 has, after which a rekey of event IDs is a break"


def _closed_sentence(runs: list[str]) -> str:
    """What the 3 to 4 entry says of the runs it left as they are because the journal can't take a rekey (CLOSED_REASON):
    their events keep the IDs they have, and a rebuild would give them IDs that no journal reference follows."""
    one = len(runs) == 1
    return (f"The found output of {'this run' if one else 'these runs'} ({', '.join(runs)}) was loaded while case.yaml named "
            "the evidence through a link, but its events keep the IDs they have: the journal holds a line only a case at "
            "format 4 has, after which a rekey of event IDs is a break. A rebuild gives them IDs under the evidence folder "
            "that no mark, tag, or finding follows.")


def _skipped_sentence(skipped: dict[str, str]) -> str:
    """What the 3 to 4 entry says of the runs it couldn't read: it could not tell which IDs a rebuild would give their
    events. Where they were loaded while case.yaml named the evidence through a link, they keep the IDs they have, and
    a rebuild would give them IDs that no journal reference follows."""
    one = len(skipped) == 1
    return (f"The found output of {'this run' if one else 'these runs'} could not be read now ({', '.join(skipped)}), so "
            "the step could not tell which IDs a rebuild gives its events. Where they were loaded while case.yaml named the "
            "evidence through a link, they keep the IDs they have, and a rebuild gives them IDs under the evidence folder "
            "that no mark, tag, or finding follows.")


def _found_output_sentence(changed: int, pairs: dict, unplaced: dict, named: set[str], unreached: int | None) -> str:
    """The text of the 3 to 4 entry that moved `changed` IDs: what changed, then what _references_sentence says."""
    return (f"{FORMAT_4_OPENS} Output found in the evidence was loaded while case.yaml named the evidence through a link, "
            "so its events named each file by its whole path. They now name it by its path under "
            f"the evidence folder, and {changed:,} {'event' if changed == 1 else 'events'} took new IDs."
            + _references_sentence(pairs, unplaced, named, unreached))


def upgraded(case: Case, client: str = "cli") -> Case:
    """The case at CASE_FORMAT, upgraded first if it is older, for a command that writes to it: a load into a format 1
    case would add new IDs to a journal that has no map from the old ones, and a journal from before format 3 takes
    no ordinary entry until its chain has started. A case whose journal is read-only stays at the format it reached,
    from format 3 on (KeptAtFormat), and the command's first write then fails on the read-only reason. The command line
    calls it right before the first load or write, after the command checks its arguments, so a command that stops
    before then leaves the format as it is. `client` is the kind of process, which the chained entries name."""
    if case.settings.case_format >= cases.CASE_FORMAT:   # read at the call, as case.upgrade reads it
        return case
    return upgrade(case, upgrade_recorder(Journal(case, client)))


def upgraded_copy(case: Case, source: Case, client: str = "cli") -> Case:
    """A new copy (case.copy_case) at CASE_FORMAT, before its rebuild loads under this build's rules. A copy of an older
    source keeps its format and an empty journal, so the steps up to the chain run first, format 2's step for a format
    1 source and then the seal, and case_created follows the seal, naming the source and its journal's bytes. A copy of
    a source with the chain has its case_created already. The steps from a format with the chain then follow
    case_created, so every copy's journal reads the same way after it, whatever its source's format. Last, for a source
    whose journal holds a record of the manifest, a manifest_recorded entry by the app carries the values of the record
    source_record gives: the copy holds the source's manifest.jsonl byte for byte, so verify gives the copy its source's
    answer, whatever it is. When the source's check can't vouch for that record, the entry names the reasons in
    `unvouched`, so every output keeps the warning."""
    if case.settings.case_format < cases.FIRST_CHAINED:
        case = upgrade(case, upgrade_recorder(Journal(case, client)), until=cases.FIRST_CHAINED)
        start_chain(case, client, copied_from=copied_from(source))
    case = upgraded(case, client)
    if records_manifest(case) and (carried := source_record(source)):
        record, reasons = carried
        Journal(case, client).append("manifest_recorded", SYSTEM, **{k: record[k] for k in ("sha256", "bytes", "lines")},
                                     via="copy", **({"unvouched": reasons} if reasons else {}))
    return case


def source_record(source: Case) -> tuple[dict, list[str]] | None:
    """The manifest record a copy of `source` carries, with the reasons its source couldn't vouch for it (journal's
    UNVOUCHED_WORDS), in their order; None for a source whose journal doesn't record the manifest or whose verify counts
    no record.

    The record is the one the source's own verify counts (intake.record_at_head): the newest at or before the head this
    computer recorded outside the journal, whether the journal has a break or not, so the copy gives the source's
    answer. With no head recorded, verify counts the newest record. A head that is no line of the journal counts none;
    the copy then carries the newest record, with a break, since a copy with no record would carry no warning. The
    reasons: "break" for a journal with a break, one on record included, or a head that is no line of it; "no_head" for
    no head recorded here, which leaves nothing to show the record wasn't added later; "add" when the first record came
    with Add new evidence, which leaves the lines before it unrecorded. The reasons the first record names pass on to
    its copy, so a copy never vouches for more than its source."""
    path = source.folder / JOURNAL_FILE
    if not (records_manifest(source) and path.is_file()):
        return None
    head = heads.read(source.folder)
    found = check(path, head["head"] if head else None)
    compared = found.expected is not None   # the head recorded here is a chained line of the journal
    record = record_at_head(found, True)[0] if compared else counted_record(found.manifests, None)[0]
    if record is None:
        return None
    first = found.manifests[0]
    reasons = {*first.get("unvouched", ())}
    if not found.consistent or (head and not compared):
        reasons.add("break")
    if not head:
        reasons.add("no_head")
    if first["via"] == "add":
        reasons.add("add")
    return record, [reason for reason in UNVOUCHED_WORDS if reason in reasons]
