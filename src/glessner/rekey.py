"""The case format upgrades: 1 to 2, the event IDs that the Amcache, SRUM, Suricata, and SQLECmd key rules changed, and
2 to 3, the seal that starts the journal's hash chain (upgrade_chain, at the end of this module). The two share the
hold on the events database (_held_database), which each enters on its own.

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
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath

import duckdb

from . import case as cases
from . import heads
from .accounts import AFFECTS_SQL, key_sql, name_sids
from .case import JOURNAL_FILE, Case, CaseError, report_stage, upgrade, write_atomically
from .events import EventIds, connect, transaction
from .hashes import HASHES_SQL
from .journal import (
    REPLAY_ERRORS,
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
from .parsers import FORMER_RULES, PARSERS
from .runner import (
    IMPORT,
    RunRecord,
    _write_record,
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
        if _journaled(case):
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


def _journaled(case: Case) -> bool:
    """Whether the journal holds this step's entry already (step 2)."""
    path = case.folder / JOURNAL_FILE
    if not path.exists():
        return False
    with path.open("rb") as f:
        for line in f:
            if b'"case_upgrade"' in line:
                entry = parse_line(line.rstrip(b"\n"))   # by the rule every reader shares
                if entry is None:
                    continue   # the journal's own read names a torn line
                if (entry.get("action"), entry.get("from_format"), entry.get("to_format")) == ("case_upgrade", 1, 2):
                    return True
    return False


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
    if con is not None:
        _reload(case, con, groups, reloads)   # step 8
        for run_id in unrecorded:
            _delete(con, "run_id = ?", [run_id])
        _restore(case, con, runs, groups)
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
    return {"text": _sentence(loads, placed["pairs"], placed["unplaced"], named), "rekey": rekey}   # step 10


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


def _sentence(parsed: dict[str, Parsed], pairs: dict, unplaced: dict, named: set[str]) -> str:
    """The entry's text: the events of the runs a rebuild loads whose IDs the new rules change, by tool, and the
    journal references the map moved: the IDs the journal names (`named`) among its pairs, and its unplaced IDs. The
    pairs also hold the earlier rekeys' candidates it placed, which are no reference. Counted from the runs' output, so a
    run of the step after a crash says the same. A moved case's SQLECmd rows loaded before the move already have their
    new IDs, and are counted too."""
    changed: dict[str, set[str]] = {}
    for p in parsed.values():
        changed.setdefault(p.record.parser, set()).update(new for old, new in p.ids.items() if old != new)
    counts = [f"{len(changed[name]):,} {label} {'event' if len(changed[name]) == 1 else 'events'}"
              for name, label in LABELS.items() if changed.get(name)]
    what = "Event IDs no longer depend on where or in which time zone a tool ran"
    text = f"{what}: {_listed(counts)} took new IDs." if counts else f"{what}; no event here took a new ID."
    n, u = len(pairs.keys() & named), len(unplaced)
    if not n and not u:
        return f"{text} No journal reference changed."
    text += (" No journal reference was placed on a new ID." if n == 0
             else " 1 journal reference now names its event's new ID." if n == 1
             else f" {n:,} journal references now name their events' new IDs.")
    if not u:
        return f"{text} None was left unplaced."
    return (f"{text} {u:,} {'was' if u == 1 else 'were'} left unplaced, each naming more than one event; the Case overview "
            "counts them, and each event they may mean says so.")


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
    from format 3, so a step stops before it writes anything, naming the record. Both steps ask first: format 2's step
    would otherwise reload and write format 2 into a case that is refused a moment later."""
    path = case.folder / JOURNAL_FILE
    if path.exists() and has_chain(path):
        return
    record = heads.read(case.folder)
    if record is not None:
        raise CaseError(
            f"{case.settings.name} is at case format {case.settings.case_format} and its journal has no hash chain, but "
            f"this computer recorded the head of its chain, entry #{record['seq']}, at {record.get('at', '')}, in "
            f"{heads.path_for(case.folder)}. The case was set back from format 3 and its chained lines removed, or its "
            "folder was restored from a copy made before its upgrade. Nothing was changed. Restore the case folder from "
            "a copy made after the upgrade; or, if the reset was intended, remove that file and open the case again, "
            "which seals the journal as it stands.")


def _seal_sentence(sealed: dict) -> str:
    chain = "the hash chain: each entry from here names the one before it and the build that wrote it."
    if not sealed["bytes"]:
        return f"Started {chain} The journal had no earlier entries to seal."
    n = sealed["lines"]
    return (f"Sealed the {n:,} earlier journal {'entry' if n == 1 else 'entries'} ({sealed['bytes']:,} bytes) and "
            f"started {chain}")


def upgraded(case: Case, client: str = "cli") -> Case:
    """The case at CASE_FORMAT, upgraded first if it is older, for a command that writes to it: a load into a format 1
    case would add new IDs to a journal that has no map from the old ones, and a format 3 journal takes
    no ordinary entry until its chain has started. The command line calls it right before the first
    load or write, after the command checks its arguments, so a command that stops before then leaves the format as it
    is. `client` is the kind of process, which the seal names."""
    if case.settings.case_format >= cases.CASE_FORMAT:   # read at the call, as case.upgrade reads it
        return case
    return upgrade(case, upgrade_recorder(Journal(case, client)))


def upgraded_copy(case: Case, source: Case, client: str = "cli") -> Case:
    """A new copy (case.copy_case) at CASE_FORMAT, before its rebuild loads under this build's rules. A copy of an older
    source keeps its format and an empty journal, so the upgrade seals it, after format 2's step for a format 1 source,
    and case_created then follows the seal, naming the source and its journal's bytes. A format 3 source's copy has its
    case_created already."""
    older = case.settings.case_format < cases.FIRST_CHAINED
    case = upgraded(case, client)
    if older and case.settings.case_format >= cases.FIRST_CHAINED:
        start_chain(case, client, copied_from=copied_from(source))
    return case
