"""Creates and opens case folders.

A case folder holds case.yaml (the settings), manifest.jsonl (the evidence's hashes), verification.jsonl (each
re-hash), journal.jsonl (the analyst's actions) with journal.lock, events.duckdb, and the runs, mappings, and exports
subfolders. The evidence folder and the tools folder stay outside it.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import threading
import time
from collections.abc import Callable
from contextlib import AbstractContextManager, suppress
from contextvars import ContextVar
from dataclasses import MISSING, asdict, dataclass, fields, replace
from datetime import UTC, datetime
from pathlib import Path

import yaml

from .version import build_id

CASE_FILE = "case.yaml"
DB_FILE = "events.duckdb"
MANIFEST_FILE = "manifest.jsonl"
VERIFICATION_FILE = "verification.jsonl"
JOURNAL_FILE = "journal.jsonl"
SUBFOLDERS = ("runs", "exports")   # suggestion rules live in the journal, not in files
# The case format this build writes, case.yaml's case_format. It goes up only when the events database,
# the journal, or the manifest changes shape; open_case refuses a case of a higher one. A setting added to case.yaml
# doesn't raise it, since open_case also refuses, by name, a setting it doesn't read. Format 2 changed event IDs:
# rekey.py's upgrade journals the old IDs' new ones. Format 3 chains the journal: each line names the SHA-256 of the
# one before it, and the upgrade seals the unchained lines. Format 4's upgrade journals the step and, for output found
# in the evidence that was loaded under a linked evidence path, gives its events the IDs of the path under the evidence
# folder, so a build of an earlier format refuses the case before it reads what format 4 records.
CASE_FORMAT = 4
FIRST_CHAINED = 3   # the first format whose journal has a hash chain
NOT_IN_FILE_NAMES = '<>:"|?*'   # the printable characters Windows refuses in a file's or folder's name


class CaseError(Exception):
    """Raised when a case cannot be created or opened safely."""


class KeptAtFormat(Exception):
    """Raised inside an upgrade step from a format with the chain, by the journal's checks before the step's entry or
    before the number of a step journaled already, when the journal has no chain or a break puts it in read-only mode.
    upgrade() keeps the case at the format it reached, without writing case.yaml, and the open then finds the same
    break. It is not a CaseError, which the command line prints as an error."""


@dataclass(frozen=True)
class CaseSettings:
    name: str
    evidence_path: str
    analyst: str
    created_utc: str
    tools_folder: str = ""
    single_host: str = ""   # set for a single-host collection; empty means one top-level folder per host
    copied_from: str = ""   # the case folder copy_case copied this one from, and when
    case_format: int = 1    # the case's format (CASE_FORMAT); a case.yaml without one is format 1


@dataclass(frozen=True)
class Case:
    folder: Path
    settings: CaseSettings
    db_file: str = DB_FILE   # the events database's name in the folder; a rebuild loads its new one under another

    @property
    def evidence(self) -> Path:
        return Path(self.settings.evidence_path)

    @property
    def manifest_path(self) -> Path:
        return self.folder / MANIFEST_FILE

    @property
    def verification_path(self) -> Path:
        return self.folder / VERIFICATION_FILE

    @property
    def runs_folder(self) -> Path:
        return self.folder / "runs"

    @property
    def db_path(self) -> Path:
        return self.folder / self.db_file

    def host_of(self, rel_path: str) -> str | None:
        """Host that owns an evidence file, from its path relative to the evidence root.

        Multi-host collections use one top-level folder per host. Files directly in the
        evidence root belong to no host.
        """
        if self.settings.single_host:
            return self.settings.single_host
        head, sep, _ = rel_path.partition("/")
        return head if sep else None

    def host_dir(self, host: str) -> Path:
        return self.evidence if self.settings.single_host else self.evidence / host


def create_case(folder: Path, name: str, evidence: Path, analyst: str, tools_folder: Path | None = None,
                single_host: str = "", client: str = "cli") -> Case:
    """Create a new case folder. The evidence folder must exist and must not overlap the case folder, and the tools
    folder must not overlap either (tools_folder_problem). `single_host`, the name of a single-host collection's host,
    goes into each run folder's name, so it has no slash or backslash, as an import's lane name has none, none of the
    characters Windows refuses in a file's name (NOT_IN_FILE_NAMES), and no space or dot at its end, which Windows drops
    from a folder's name. Its journal starts with case_created, written by `client`, the kind of process making it.
    The journal head record that an earlier case in the same folder path left outside the folder is removed as the folder
    is made (_make_folder), so the new journal is compared with no head but its own, and a record that can't be removed
    is a CaseError.
    HOST_NAME is imported here, since imports.py imports the runner, which imports this module."""
    from .imports import HOST_NAME

    if single_host and not HOST_NAME.fullmatch(single_host):   # match's $ would pass a name ending in a line break
        raise CaseError(f"{single_host!r} can't be the host's name: a host name has up to 64 characters, without "
                        "slashes, backslashes, or control characters.")
    if refused := [c for c in NOT_IN_FILE_NAMES if c in single_host]:
        raise CaseError(f"{single_host!r} can't be the host's name: a host name can't hold {' '.join(refused)}, which "
                        "Windows refuses in a folder's name, and each run's folder is named for the host.")
    if single_host.endswith((" ", ".")):
        raise CaseError(f"{single_host!r} can't be the host's name: a host name can't end in a space or a dot, which "
                        "Windows drops from a folder's name, and each run's folder is named for the host.")
    folder = folder.resolve()
    evidence = evidence.resolve()
    if not evidence.is_dir():
        raise CaseError(f"Evidence folder not found: {evidence}")
    check_outside_evidence(folder, evidence)
    if tools_folder and (problem := tools_folder_problem(tools_folder, evidence, folder)):
        raise CaseError(problem)
    if folder.exists() and any(folder.iterdir()):
        raise CaseError(f"Case folder is not empty: {folder}")
    _make_folder(folder)
    for sub in SUBFOLDERS:
        (folder / sub).mkdir()
    settings = CaseSettings(
        name=name,
        evidence_path=str(evidence),
        analyst=analyst,
        created_utc=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        tools_folder=str(tools_folder.resolve()) if tools_folder else "",
        single_host=single_host,
        case_format=CASE_FORMAT,
    )
    _write_settings(folder, settings)
    case = Case(folder, settings)
    _start_journal(case, client, {})
    return case


def _make_folder(folder: Path) -> None:
    """Make the case folder, after removing the journal head record (heads.py) that an earlier case in `folder` left
    outside it, so the journal of a case made there now is compared with no head but its own: the record of a case that
    was deleted would otherwise put the new journal in read-only mode, also when the new case's own record can't be
    written. The record goes only once the folder's parent exists, so a path that can't be reached, such as one on an
    absent drive or share, raises the OS's error and keeps the record of the case that is there. CaseError, naming the
    record's file, when it can't be removed; the disk is as it was then: the folder is not made, and the folders above
    it that this call made are removed again, each only while it is empty. Imported here, since heads.py imports this
    module."""
    from .heads import forget, path_for

    made = [each for each in (folder.parent, *folder.parent.parents) if not each.exists()]   # deepest first
    folder.parent.mkdir(parents=True, exist_ok=True)
    try:
        forget(folder)
    except OSError as exc:
        for each in made:
            with suppress(OSError):   # rmdir refuses a folder that something has put a file in since, which stays
                each.rmdir()
        raise CaseError(f"Can't remove the journal head record an earlier case in this folder left: {path_for(folder)} "
                        f"({exc.strerror or exc}). Remove that file, then make the case again.") from exc
    folder.mkdir(exist_ok=True)


def _start_journal(case: Case, client: str, payload: dict) -> None:
    """A case's journal at its making: case_created at byte 0 for a case of a format with a hash chain, so no crash can
    leave the empty journal that a chained format calls "chain missing"; empty for an older one, whose
    upgrade seals it first. The caller has removed any head record of an earlier case in the folder (_make_folder).
    Imported here, since the journal imports this module, as _rekey reaches rekey.py."""
    from .journal import start_chain

    (case.folder / JOURNAL_FILE).touch()
    if case.settings.case_format >= FIRST_CHAINED:
        start_chain(case, client, **payload)


def copy_case(source: Case, folder: Path, name: str, analyst: str, client: str = "cli") -> Case:
    """A new case on the same evidence, with the source's intake and tool runs and a journal of its own.

    For a clean pass over a case that was already worked, such as a second analyst's blind review: no
    marks, tags, notes, rules, or settings carry over. The verification history and saved import mappings do. Tool
    output is copied rather than run again, so the copy needs a rebuild to load it (the copy-case command does both).
    A copy of a source whose format has the chain starts its journal with case_created naming the source and its head;
    an older source's copy keeps the source's format, so its journal stays empty until its upgrade seals it and
    case_created follows. In both, the entries of the upgrade steps from a format with the chain follow case_created
    (rekey.upgraded_copy). As create_case does, it removes the journal head record that an earlier case in the same
    folder path left outside the folder as it makes the folder, and a record that can't be removed is a CaseError.
    """
    folder = folder.resolve()
    if _overlaps(folder, source.evidence) or _overlaps(folder, source.folder):
        raise CaseError(f"The copy must sit outside the evidence folder and the source case: {folder}")
    tools = source.settings.tools_folder
    if tools and (problem := tools_folder_problem(Path(tools), source.evidence, folder)):
        raise CaseError(problem)
    if folder.exists() and any(folder.iterdir()):
        raise CaseError(f"Case folder is not empty: {folder}")
    _make_folder(folder)
    for file in (MANIFEST_FILE, VERIFICATION_FILE):
        if (source.folder / file).is_file():
            shutil.copy2(source.folder / file, folder / file)
    for sub in ("runs", "mappings"):
        if (source.folder / sub).is_dir():
            shutil.copytree(source.folder / sub, folder / sub)
    _name_input_roots(source, folder / "runs")
    for sub in SUBFOLDERS:
        (folder / sub).mkdir(exist_ok=True)
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    # The source's case format comes along with its runs and manifest, which are in that format
    settings = replace(source.settings, name=name, analyst=analyst, created_utc=now,
                       copied_from=f"{source.folder} at {now}")
    _write_settings(folder, settings)
    case = Case(folder, settings)
    from .journal import copied_from

    _start_journal(case, client, {"copied_from": copied_from(source)} if settings.case_format >= FIRST_CHAINED else {})
    return case


REPLACE_TRIES = 10   # write_atomically's tries of a replace Windows refuses, REPLACE_WAIT seconds apart: about 1 s
REPLACE_WAIT = 0.1


def write_atomically(path: Path, data: str | bytes, shared: bool = False) -> None:
    """Replace `path` with `data` whole or not at all: it goes to a temporary file beside it, which is flushed to disk
    before it takes the name, so a stop at any point leaves the old file or the new one, never a cut-short one. On
    Windows the replace is refused while another process has the target open, as an open_case read does for
    milliseconds; it is tried again for about 1 s, and then the old file stays and the error is raised. The temporary
    file's name is fixed, so a file has one writer at a time: case.yaml's under the upgrade's hold on the events
    database, a run.json its run's, the head record its case's journal lock's. `shared` is for a file several processes
    write, recent.json: the temporary name then carries the process and thread IDs, so one writer's replace never takes
    another's file. Text is written in text mode, so lines end in CRLF on Windows, as Path.write_text writes them; bytes
    as given, such as the manifest's LF lines."""
    temp = path.with_name(f"{path.name}.{os.getpid()}-{threading.get_ident()}.tmp" if shared else path.name + ".tmp")
    try:
        with (temp.open("wb") if isinstance(data, bytes) else temp.open("w", encoding="utf-8")) as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        for tries_left in range(REPLACE_TRIES - 1, -1, -1):
            try:
                os.replace(temp, path)
                break
            except PermissionError:
                if not tries_left:
                    raise
                time.sleep(REPLACE_WAIT)
    except BaseException:
        with suppress(OSError):
            temp.unlink(missing_ok=True)
        raise


def ends_open(path: Path) -> bool:
    """Whether the file has a last line that no LF ends, such as a hand edit can leave. An append to a JSON-lines file
    writes a LF first then, so its line doesn't join the last one."""
    with path.open("rb") as f:
        if f.seek(0, os.SEEK_END) == 0:
            return False
        f.seek(-1, os.SEEK_END)
        return f.read(1) != b"\n"


def _write_settings(folder: Path, settings: CaseSettings) -> None:
    write_atomically(folder / CASE_FILE, yaml.safe_dump(asdict(settings), sort_keys=False))


def _name_input_roots(source: Case, runs: Path) -> None:
    """Record, in each copied run that worked on copies of the evidence and predates runs recording it, the folder its
    copies were in: the source case's, as the paths in its output name them. The copy's rebuild then reads those paths
    as evidence paths, and its events take the source's IDs. The copy's journal is empty, so no mark
    can lose its event; a copy made by a build without this record keeps its IDs as they are."""
    for path in runs.glob("*/run.json"):
        record = json.loads(path.read_text(encoding="utf-8"))
        if record.get("working_copies") and not record.get("input_root"):
            record["input_root"] = str(source.runs_folder / path.parent.name / "input")
            write_atomically(path, json.dumps(record, indent=2))   # a stop leaves the record as copied


RESTORE_SETTINGS = ("Restore it from a copy of the case folder, or write it again with the name, evidence_path, analyst, "
                    "and created_utc the case was made with.")


def _first_line(exc: Exception) -> str:
    return (str(exc).strip().splitlines() or [type(exc).__name__])[0]


def open_case(folder: Path) -> Case:
    """Open an existing case folder. A case of a newer format than this build reads is refused."""
    folder = folder.resolve()
    case_file = folder / CASE_FILE
    if not case_file.is_file():
        raise CaseError(f"Not a case folder (no {CASE_FILE}): {folder}")
    try:
        data = yaml.safe_load(case_file.read_text(encoding="utf-8"))
    except (yaml.YAMLError, UnicodeDecodeError) as exc:   # NUL bytes, as a write cut short can leave, are a YAMLError
        raise CaseError(f"{case_file} can't be read as the case's settings: {_first_line(exc)}. {RESTORE_SETTINGS}") from exc
    if not isinstance(data, dict):
        found = "is empty" if data is None else "isn't a list of settings"
        raise CaseError(f"{case_file} {found}. {RESTORE_SETTINGS}")
    data.pop("case_timezone", None)   # an older build wrote this setting, and nothing reads it
    # Checked before the other settings are read, since a newer format's case.yaml may hold settings this build lacks
    found = data.get("case_format", 1)
    if not isinstance(found, int) or isinstance(found, bool) or found < 1:
        raise CaseError(f"{case_file} gives case_format {found!r}, which should be a whole number from 1.")
    if found > CASE_FORMAT:
        raise CaseError(f"{folder} is a case of format {found}, and this build of glessner ({build_id()}) reads "
                        f"formats up to {CASE_FORMAT}. Open it with a build that reads format {found}.")
    # A newer build's setting, such as a closed case's, would otherwise fail as a TypeError or be ignored
    if unknown := sorted(map(str, set(data) - {f.name for f in fields(CaseSettings)})):   # a hand edit's key may be a number
        raise CaseError(f"{case_file} has settings this build of glessner ({build_id()}) doesn't read: "
                        f"{', '.join(unknown)}. A newer build may have written them; open the case with that build.")
    if missing := [f.name for f in fields(CaseSettings) if f.default is MISSING and f.name not in data]:
        raise CaseError(f"{case_file} lacks {', '.join(missing)}, so it may have been cut short. {RESTORE_SETTINGS}")
    # A hand edit's number or list fails later as a TypeError in pathlib or a join, so it is named here
    if wrong := [f.name for f in fields(CaseSettings) if f.type == "str" and not isinstance(data.get(f.name, ""), str)]:
        raise CaseError(f"{case_file} gives {wrong[0]} {data[wrong[0]]!r}, which should be text. {RESTORE_SETTINGS}")
    case = Case(folder, CaseSettings(**data))
    try:
        check_outside_evidence(folder, case.evidence)
    except CaseError as exc:
        raise CaseError(f"{exc} Move the case folder out of the evidence folder, or correct evidence_path in "
                        f"{case_file}.") from exc
    tools = case.settings.tools_folder
    if tools and (problem := tools_folder_problem(Path(tools), case.evidence, folder)):
        raise CaseError(f"{problem} Set tools_folder in {case_file} to another folder, or to '' for PATH only.")
    return case


def check_outside_evidence(folder: Path, evidence: Path) -> None:
    """Refuse a case folder, given resolved, that holds or sits in its evidence folder: each write of the case, its
    journal, database, and runs, would land in the evidence, and Add new evidence would hash the case's own files. A
    network evidence path is compared as written, not resolved, so an offline share can't stall an open."""
    evidence = evidence if _network(evidence) else evidence.resolve()
    if _overlaps(folder, evidence):
        raise CaseError(f"The case folder and the evidence folder must not contain each other: {folder} and {evidence}")


def _rekey(case: Case) -> AbstractContextManager[dict | None]:
    """Format 1 to 2: event IDs that don't depend on where or in which time zone a tool ran. Imported
    here, since rekey.py imports the runner, which imports this module."""
    from .rekey import upgrade_ids

    return upgrade_ids(case)


def _chain(case: Case) -> AbstractContextManager[dict | None]:
    """Format 2 to 3: the journal's hash chain, which starts with a seal over the unchained lines.
    In rekey.py beside format 2's step, since it shares that step's hold on the events database."""
    from .rekey import upgrade_chain

    return upgrade_chain(case)


def _format_4(case: Case) -> AbstractContextManager[dict | None]:
    """Format 3 to 4: one chained entry, which rekeys found output that was loaded under a linked evidence path and
    otherwise says only that nothing changed. In rekey.py beside the earlier steps, since it shares their hold on the
    events database."""
    from .rekey import upgrade_format_4

    return upgrade_format_4(case)


# The steps that bring a case of an older format up to CASE_FORMAT, by the format each starts from:
# UPGRADES[n] changes a format n case into format n + 1. It is a context manager, entered with the case, that gives the
# fields of the case_upgrade entry saying what it changed, at least the sentence in `text`, or None when an earlier run
# of it had journaled them already, before a crash kept case.yaml from taking the next number. It can hold what it needs
# until upgrade has journaled the entry and written the number, such as rekey.py's connection to the events database,
# and a failure inside it changes neither. The server runs the steps when it opens a case for work, and the commands
# that load events run them first, so a step must be safe to run again. For a step from a format with the chain,
# upgrade's record raises KeptAtFormat when the journal is read-only, and the case stays at the format it is at.
UPGRADES: dict[int, Callable[[Case], AbstractContextManager[dict | None]]] = {1: _rekey, 2: _chain, 3: _format_4}


# Where the upgrade running in this thread reports its stages, set by upgrade() while its steps run: report(stage, done,
# total), as the start page's job takes them. A step reports through report_stage, so its signature stays the
# case's alone.
_stage_report: ContextVar[Callable[[str, int, int], None] | None] = ContextVar("upgrade_stage_report", default=None)


def report_stage(stage: str, done: int = 0, total: int = 0) -> None:
    """A step of upgrade() says what it is doing now, with how far it is when it counts. Nothing happens when no one asked."""
    if report := _stage_report.get():
        report(stage, done, total)


# The journal checks the upgrade running in this thread makes before a step's entry, set by upgrade() from its record
_journal_check: ContextVar[Callable[[], bool] | None] = ContextVar("upgrade_journal_check", default=None)


def check_journal() -> bool:
    """A step that changes the case before its entry is journaled calls this first. A journal with no chain or with a break
    keeps the case at its format, as the record's own checks would after the change (KeptAtFormat), so the step changes
    nothing. Returns whether the journal already holds a line that closes the place of the rekey from format 3 to 4
    (journal.check_for_upgrade); False when the upgrade's record offers no check."""
    check = _journal_check.get()
    return bool(check and check())


def upgrade(case: Case, record: Callable[[int, int, dict | None], object],
            report: Callable[[str, int, int], None] | None = None, until: int | None = None) -> Case:
    """The case brought up to `until`, CASE_FORMAT unless given, one UPGRADES step at a time; record(from, to, fields)
    journals each step's case_upgrade entry with its fields, and case.yaml then takes the step's number, both inside the
    step. For a step journaled already, fields is None, and record writes no entry but runs any checks the entry would
    have followed. A record that finds the journal read-only (KeptAtFormat) ends the upgrade with the case at the format
    it reached, case.yaml unchanged. report(stage, done, total), when given, gets each stage a step reports
    (report_stage), for the start page's open. A record with a `check` attribute (journal.upgrade_recorder's) lets a step
    run the journal's checks ahead of its changes (check_journal)."""
    token, checking = _stage_report.set(report), _journal_check.set(getattr(record, "check", None))
    try:
        return _upgrade(case, record, CASE_FORMAT if until is None else until)
    finally:
        _journal_check.reset(checking)
        _stage_report.reset(token)


def _upgrade(case: Case, record: Callable[[int, int, dict | None], object], until: int) -> Case:
    while case.settings.case_format < until:
        start = case.settings.case_format
        if start not in UPGRADES:
            raise CaseError(f"This build of glessner ({build_id()}) has no upgrade from case format {start}.")
        try:
            with UPGRADES[start](case) as fields:
                record(start, start + 1, fields)   # None: journaled already, by a run that stopped before case.yaml
                case = Case(case.folder, replace(case.settings, case_format=start + 1))
                try:
                    _write_settings(case.folder, case.settings)
                except OSError as exc:   # the old case.yaml stays; the next open finishes the step, which is journaled
                    raise CaseError(f"The upgrade of {case.settings.name} stopped before {CASE_FILE} took the new "
                                    f"format ({exc}). {CASE_FILE} is as it was; close any program that has it open, "
                                    "then open the case again, which finishes the upgrade.") from exc
        except KeptAtFormat:   # raised by the record, so case.yaml and `case` keep the format reached
            return case
    return case


def tools_folder_problem(tools: Path, evidence: Path | None, case_folder: Path | None = None) -> str:
    """Why a folder can't be the tools folder, or "" when it can.

    Detection runs the executables it finds in the tools folder. One that holds the evidence or the case, whose runs
    keep copies of evidence files, could run a suspect's file named like a registry tool, such as EvtxECmd.exe. A
    network folder is refused too: case.yaml names the tools folder, so a case folder made elsewhere could run
    executables from any share. The check reads the path text first, so a network path isn't opened."""
    if _network(tools):
        return f"The tools folder must be on this computer, not a network path: {tools}."
    tools = tools.resolve()
    if _network(tools):   # a mapped network drive resolves to its share
        return f"The tools folder must be on this computer, not a network drive: {tools}."
    for what, other in (("evidence", evidence), ("case", case_folder)):
        if other is None or _network(other):   # not resolved, so an offline share can't stall this; it can't overlap
            continue
        other = other.resolve()
        if _overlaps(tools, other):
            return f"The tools folder and the {what} folder must not contain each other: {tools} and {other}."
    return ""


def _network(path: Path) -> bool:
    """A UNC path, such as \\\\server\\share, in any of its forms. A local folder's device forms, \\\\?\\C:\\ and
    \\\\?\\Volume{...}\\, are not: resolve() gives both as a drive letter's path."""
    text = str(path).replace("/", "\\")
    return text.startswith("\\\\") and not re.match(r"\\\\[?.]\\(?:[a-z]:|volume\{)", text, re.IGNORECASE)


def _overlaps(a: Path, b: Path) -> bool:
    """Whether one of two resolved paths holds the other. resolve() keeps a \\\\?\\ prefix it was given, so \\\\?\\D:\\x
    is compared as D:\\x, so both spellings get the same check."""
    a, b = _plain(a), _plain(b)
    return a == b or a.is_relative_to(b) or b.is_relative_to(a)


def _plain(path: Path) -> Path:
    text = str(path)
    return Path(text[4:]) if re.match(r"\\\\\?\\[a-z]:", text, re.IGNORECASE) else path
