"""Runs one tool at a time against a host's evidence and records everything about the run.

Each run gets a fresh folder under runs/ holding run.json, stdout.txt, stderr.txt, and the
tool's output. After the tool exits, the runner checks that every expected output exists,
re-hashes the evidence files the run read, and loads the output through the tool's parser.
"""

from __future__ import annotations

import csv
import fnmatch
import json
import os
import shutil
import subprocess
import time
from contextlib import closing, suppress
from dataclasses import MISSING, asdict, dataclass, field, fields, replace
from datetime import UTC, datetime
from pathlib import Path

import duckdb

from .case import CASE_FILE, Case, CaseError, check_outside_evidence, write_atomically
from .events import connect, load
from .intake import NOT_IN_MANIFEST, current_entries, sha256_file, verify, walk_evidence
from .journal import host_layout
from .long_paths import long_path
from .parsers import LOCAL_TIME, PARSERS, ParseContext
from .parsers.common import LOCAL_TIME_NOTE, SKIPPED_NOTE
from .parsers.sbecmd import MESSAGES
from .timezones import ZoneError, fmt_offset, host_timezones, resolve_zone
from .tools import DetectedTool, ToolSpec, load_registry, rules_file, tool_env
from .version import build_id

RUN_FILE = "run.json"
IMPORT = "import"   # the tool and parser name of an import (imports.py), which reads evidence instead of output
PLACEHOLDERS = ("{host_dir}", "{input_file}", "{input_list}", "{output_dir}", "{tool_dir}", "{value}")
INPUT_LIST = "inputs.txt"   # {input_list}: the run's input files, one full path per line, in the run folder


class RunError(Exception):
    """Raised when a run cannot be planned or started safely."""


@dataclass(frozen=True)
class RunPlan:
    tool: DetectedTool
    host: str
    inputs: tuple[str, ...]    # evidence-relative paths the tool will read
    input_file: str = ""       # set in each_file mode
    left_out: tuple[str, ...] = ()   # inputs the tool won't open, as its name patterns select files (ToolSpec.selects)


@dataclass
class RunRecord:
    run_id: str
    tool: str
    tool_version: str
    executable: str
    host: str
    argv: list[str]
    cwd: str
    inputs: list[str]
    started_utc: str
    status: str = "running"                  # running, ok, failed
    reason: str = ""
    finished_utc: str = ""
    seconds: float = 0.0
    exit_code: int | None = None
    timed_out: bool = False
    outputs: list[dict] = field(default_factory=list)
    # Whether `outputs` holds every file under the output folder, so a rebuild can tell a file added since the run.
    # A run recorded without it holds only the files the registry's outputs patterns name.
    outputs_all: bool = False
    missing_outputs: list[str] = field(default_factory=list)
    evidence_check: str = ""                 # ok, mismatch, unreadable (check_result), NOT_CHECKED, or "" when none was recorded
    evidence_problems: list[str] = field(default_factory=list)
    parser: str = ""
    loaded_rows: int | None = None
    replaced_rows: int | None = None
    rows_without_time: int | None = None
    load_seconds: float | None = None
    mapping: dict | None = None                # an import's mapping, with its zone resolved (imports.py)
    notes: list[str] = field(default_factory=list)
    working_copies: list[str] = field(default_factory=list)        # inputs copied for a work_on_copies tool
    working_copy_changes: list[str] = field(default_factory=list)  # copies the tool changed; the evidence didn't
    # The folders the tool's output names files in, as they were when it ran: the evidence, and the working copies, so
    # a moved case or evidence folder, or a copied case, still reads them as evidence paths. "" for a
    # run made before runs recorded them, and for an import or found output, which are read where the evidence is now
    evidence_root: str = ""
    input_root: str = ""
    dotnet_root: str = ""                    # the private .NET runtime the tool ran on, if any
    from_output: bool = False                # loaded a tool's output found in the evidence, not run
    rules: str = ""                          # the rule set the tool ran with, such as "ET Open 11310"
    # The host's zone a load read local times in (parsers.LOCAL_TIME, runner.host_zone), so a rebuild reads them the
    # same way after the zone changes; None when the host had none or the output needs none
    zone: dict | None = None


# The keys a run.json may hold, which are the record's fields, and those it must hold, which have no default
RECORD_KEYS = frozenset(f.name for f in fields(RunRecord))
REQUIRED_KEYS = frozenset(f.name for f in fields(RunRecord) if f.default is MISSING and f.default_factory is MISSING)


def plan_runs(case: Case, tool: DetectedTool, hosts: list[str] | None = None) -> list[RunPlan]:
    """One plan per host (host_dir tools) or per matching file (each_file tools)."""
    by_host: dict[str, list[str]] = {}
    for entry in current_entries(case):
        if handles(tool.spec, entry.artifact, entry.detail):
            host = case.host_of(entry.path)
            if host is not None and (not hosts or host in hosts):
                by_host.setdefault(host, []).append(entry.path)
    plans = []
    for host, paths in sorted(by_host.items()):
        if tool.spec.input == "host_dir":
            plans.append(RunPlan(tool, host, tuple(paths), left_out=_unselected(tool.spec, paths)))
        else:
            plans.extend(RunPlan(tool, host, (p,), input_file=p) for p in paths)
    return plans


def _unselected(spec: ToolSpec, paths: list[str]) -> tuple[str, ...]:
    """The paths a tool with name patterns (ToolSpec.selects) wouldn't read in a folder: those whose file name fits none
    of them, without regard to case."""
    if not spec.selects:
        return ()
    patterns = [pattern.lower() for pattern in spec.selects]
    return tuple(path for path in paths
                 if not any(fnmatch.fnmatchcase(path.rsplit("/", 1)[-1].lower(), p) for p in patterns))


def handles(spec: ToolSpec, artifact: str | None, detail: str) -> bool:
    """Whether a tool reads an artifact: a registry entry names an artifact type, such as evtx, or a type and its
    detail, such as registry:AMCACHE for one hive type."""
    return _matches(spec.handles, artifact, detail)


def _matches(patterns: tuple[str, ...], artifact: str | None, detail: str) -> bool:
    return artifact is not None and (artifact in patterns or f"{artifact}:{detail}" in patterns)


def build_argv(case: Case, plan: RunPlan, output_dir: Path, options: dict[str, str],
               input_root: Path | None = None) -> list[str]:
    """The tool's argument list. With input_root, the tool reads the working copies there instead of the evidence."""
    spec = plan.tool.spec
    base = input_root or case.evidence
    host_dir = (base if case.settings.single_host else base / plan.host) if input_root else case.host_dir(plan.host)
    values = {
        "{host_dir}": str(host_dir),
        "{input_file}": str(base / plan.input_file) if plan.input_file else "",
        "{input_list}": str(output_dir.parent / INPUT_LIST),
        "{output_dir}": str(output_dir),
        "{tool_dir}": str(plan.tool.executable.parent),
    }
    args = [_fill(a, values, spec) for a in spec.args]
    for rel in spec.related:   # another of the host's files, such as $MFT for MFTECmd reading $J
        for path in related_files(case, plan, rel["artifact"]):
            args += [_fill(a.replace("{related}", str(base / path)), values, spec) for a in rel.get("args", [])]
    for entry in spec.without_related:   # such as SBECmd's --nl, when a hive has no transaction log beside it
        if inputs_without(case, plan, entry["artifact"]):
            args += [_fill(a, values, spec) for a in entry.get("args", [])]
    rules = rules_file(spec, plan.tool.executable)
    if rules is not None:   # a rule set beside the tool, such as Suricata's; without one it runs without rules
        args += [_fill(a.replace("{rules_file}", str(rules)), values, spec) for a in spec.rules.get("args", [])]
    check_options(spec, options)
    known = {o.id: o for o in spec.options}
    for option_id, value in options.items():
        args += [_fill(a, {**values, "{value}": value}, spec) for a in known[option_id].args]
    return [str(plan.tool.executable), *args]


def check_options(spec: ToolSpec, options: dict[str, str]) -> None:
    """Refuse an option the tool's registry entry doesn't list. The command line checks before it upgrades the case,
    and build_argv checks again for every other caller."""
    known = sorted(o.id for o in spec.options)
    for option_id in options:
        if option_id not in known:
            raise RunError(f"{spec.id} has no option {option_id!r}; known options: {known}")


def related_files(case: Case, plan: RunPlan, artifact: str) -> list[str]:
    """The host's file of an artifact a tool reads alongside its input, such as the $MFT beside a $J: the one in the
    folder nearest above the input (a host_dir run's first), as a list of one, or none when no folder above it holds
    one. A host collected volume by volume, as KAPE writes C/ and D/, has an $MFT for each, and a $J's entry numbers
    name records in its own volume's."""
    target = _input_of(plan)
    found = []
    for e in current_entries(case):
        folder = e.path.rpartition("/")[0]
        if (e.artifact == artifact and not e.error and case.host_of(e.path) == plan.host
                and (not folder or target.startswith(f"{folder}/"))):
            found.append(e.path)
    return sorted(found, key=lambda path: (-path.count("/"), path))[:1]   # the deepest folder is the nearest


def files_beside(case: Case, plan: RunPlan, artifact: str) -> dict[str, list[str]]:
    """Each of the plan's inputs with the files of an artifact beside it: those in the input's folder named for it with
    .log after its name, as a hive's transaction logs are (NTUSER.DAT.LOG1), without regard to case. An input with none
    has an empty list."""
    in_folder: dict[str, list[str]] = {}
    for e in current_entries(case):
        if e.artifact == artifact and not e.error:
            in_folder.setdefault(e.path.rpartition("/")[0], []).append(e.path)
    beside = {}
    for path in plan.inputs:
        folder, _, name = path.rpartition("/")
        prefix = f"{name}.log".lower()
        beside[path] = [other for other in in_folder.get(folder, ()) if other.rpartition("/")[2].lower().startswith(prefix)]
    return beside


def inputs_without(case: Case, plan: RunPlan, artifact: str) -> list[str]:
    """The plan's inputs that have no file of an artifact beside them (files_beside)."""
    return [path for path, found in files_beside(case, plan, artifact).items() if not found]


def read_beside(case: Case, plan: RunPlan) -> list[str]:
    """The files the tool reads beside the plan's inputs because build_argv left out the arguments of a without_related
    entry, which it does when every input has a file of the entry's artifact beside it (files_beside): those files, as
    sorted evidence-relative paths. A run's inputs don't list them, and the evidence check after the run covers them."""
    read = set()
    for entry in plan.tool.spec.without_related:
        beside = files_beside(case, plan, entry["artifact"])
        if all(beside.values()):
            read.update(path for found in beside.values() for path in found)
    return sorted(read)


def _input_of(plan: RunPlan) -> str:
    return plan.input_file or plan.inputs[0]


SHOWN = 5   # the paths a refusal names before saying how many more


def reads_host_folder(spec: ToolSpec) -> bool:
    """Whether a tool lists the host's evidence folder itself, given {host_dir}, rather than reading the files its run
    names, or working copies of them."""
    return not spec.work_on_copies and any("{host_dir}" in a for a in spec.args)


def check_host_folder(case: Case, plan: RunPlan) -> None:
    """Refuse a run of a tool that lists the host's folder itself (reads_host_folder) when the folder holds what intake
    didn't hash: a file the manifest doesn't list, which the tool would load though no evidence check covers it, a
    link, which the tool may follow out of the evidence, or a cloud placeholder, which the tool would download by
    reading it. The folder is listed as intake lists it (intake.walk), from its extended-length path, so a name that is
    long or ends in a dot is listed as it is."""
    spec = plan.tool.spec
    if not reads_host_folder(spec):
        return
    host = "" if case.settings.single_host else plan.host
    prefix = f"{host}/" if host else ""
    known = {e.path for e in current_entries(case)}
    links, placeholders = [], []
    listing = walk_evidence(long_path(case.evidence, host), links, placeholders=placeholders)
    new = [path for rel in listing if (path := prefix + rel) not in known]
    if new or links or placeholders:
        raise RunError(_unhashed(spec, plan.host, new, [prefix + link for link in links],
                                 [prefix + path for path in placeholders]))


def _unhashed(spec: ToolSpec, host: str, new: list[str], links: list[str], placeholders: list[str]) -> str:
    """Why check_host_folder refused a run, with what the analyst can do about it."""
    text = f"{spec.name} wasn't run on {host}: it lists the host's folder itself, which holds what intake didn't hash."
    if new:
        files, them = ("1 file", "it") if len(new) == 1 else (f"{len(new):,} files", "them")
        text += (f" {files} the intake manifest doesn't list: {_paths(new)}. Hash {them} with Add new evidence, or "
                 "intake --add on the command line, then run the tool again.")
    if links:
        what = "1 link" if len(links) == 1 else f"{len(links):,} links"
        text += (f" {what}, which the tool may follow out of the evidence: {_paths(links)}. Remove each link, or "
                 "replace it with a copy of the files it points to and add those.")
    if placeholders:
        what = ("1 cloud placeholder, whose content isn't on this disk" if len(placeholders) == 1
                else f"{len(placeholders):,} cloud placeholders, whose content isn't on this disk")
        text += (f" {what}, which the tool would download by reading {'it' if len(placeholders) == 1 else 'them'}: "
                 f"{_paths(placeholders)}. Make the folder available on this disk and start a new case from it, or "
                 f"remove {'it' if len(placeholders) == 1 else 'them'}.")
    return text


def check_selected(plan: RunPlan) -> None:
    """Refuse a run whose every input the tool would leave out (RunPlan.left_out), which would read nothing."""
    if plan.left_out and len(plan.left_out) == len(plan.inputs):
        spec, count = plan.tool.spec, len(plan.inputs)
        raise RunError(f"{spec.name} wasn't run on {plan.host}: it reads only files named {' or '.join(spec.selects)}, and "
                       f"the {_files(count)} intake identified for it {'is' if count == 1 else 'are'} named otherwise: "
                       f"{_paths(list(plan.left_out))}.")


def _files(count: int) -> str:
    return "1 file" if count == 1 else f"{count:,} files"


def _paths(paths: list[str]) -> str:
    """The first SHOWN paths, and how many more."""
    more = f"; and {len(paths) - SHOWN:,} more" if len(paths) > SHOWN else ""
    return "; ".join(paths[:SHOWN]) + more


def run(case: Case, plan: RunPlan, options: dict[str, str] | None = None) -> RunRecord:
    """Run a tool on its plan's evidence, check its output and the evidence, load the output, and record it all in the
    run's folder. The evidence check covers the run's inputs and the files the tool reads beside them (read_beside).
    Refused before anything is made: RunError when the tool can't run here, would read none of its inputs, as its name
    patterns select files (check_selected), has arguments that can't be filled, or has a host folder that holds what
    intake didn't hash (check_host_folder); CaseError for a run folder that can't be made safely (_new_run_folder)."""
    spec = plan.tool.spec
    if plan.tool.missing:
        raise RunError(f"{spec.name} can't run here: {plan.tool.missing}.")
    check_selected(plan)
    run_id, folder = _new_run_folder(case, spec.id, plan.host)
    output_dir = folder / "output"
    copies_root = folder / "input" if spec.work_on_copies else None
    argv = build_argv(case, plan, output_dir, options or {}, copies_root)   # validate before creating anything
    check_host_folder(case, plan)
    output_dir.mkdir(parents=True)
    related, notes = [], []
    for rel in spec.related:
        if found := related_files(case, plan, rel["artifact"]):
            related += found
        else:
            notes.append(f"Ran without {rel['args'][0]}: no {rel['artifact']} file is in a folder above "
                         f"{_input_of(plan)}, where its volume's would be.")
    for entry in spec.without_related:
        if lacking := inputs_without(case, plan, entry["artifact"]):
            one = len(lacking) == 1
            notes.append(f"Ran with {' '.join(entry.get('args', []))}, so {spec.name} skipped the transaction logs of every "
                         f"hive on this host: {_paths(lacking)} {'has' if one else 'have'} none beside "
                         f"{'it' if one else 'them'}.")
    if plan.left_out:
        one = len(plan.left_out) == 1
        notes.append(f"{_files(len(plan.left_out))} that intake identified for {spec.name} {'was' if one else 'were'} not "
                     f"read: it reads only files named {' or '.join(spec.selects)} in a folder, and "
                     f"{'this one is' if one else 'these are'} named otherwise: {_paths(list(plan.left_out))}.")
    record = RunRecord(run_id=run_id, tool=spec.id, tool_version=plan.tool.version,
                       executable=str(plan.tool.executable), host=plan.host, argv=argv,
                       cwd=str(folder if spec.run_in_run_folder else plan.tool.executable.parent),
                       inputs=[*plan.inputs, *related], notes=notes,
                       started_utc=_utc_now(), parser=spec.parser or "", dotnet_root=plan.tool.dotnet_root,
                       rules=plan.tool.rules, evidence_root=str(case.evidence), input_root=str(copies_root or ""))
    if copies_root is not None:
        try:
            record.working_copies = _make_copies(case, plan, copies_root)
        except (OSError, RunError) as exc:
            record.reason = f"could not make working copies: {exc}"
    _write_record(folder, record)   # before the input list, so a run that fails to write it still has its record
    if not record.reason and any("{input_list}" in a for a in spec.args):   # exactly the files the evidence check covers
        base = copies_root or case.evidence
        listing = "".join(f"{base / p}\n" for p in plan.inputs)
        try:   # surrogatepass: a file name may hold a lone surrogate, which strict UTF-8 can't write
            (folder / INPUT_LIST).write_text(listing, encoding="utf-8", errors="surrogatepass")
        except OSError as exc:
            record.reason = f"could not write the input list: {exc}"

    t0 = time.perf_counter()
    with (folder / "stdout.txt").open("wb") as out, (folder / "stderr.txt").open("wb") as err:
        try:
            if not record.reason:
                proc = subprocess.run(argv, cwd=record.cwd, stdout=out, stderr=err, stdin=subprocess.DEVNULL,
                                      timeout=spec.timeout_minutes * 60, env=tool_env(plan.tool))
                record.exit_code = proc.returncode
        except subprocess.TimeoutExpired:
            record.timed_out = True
        except OSError as exc:
            record.reason = f"could not start: {exc}"
    record.seconds = round(time.perf_counter() - t0, 2)
    record.finished_utc = _utc_now()
    if record.working_copies:
        record.working_copy_changes = _changed_copies(case, copies_root, record.working_copies)

    _check_outputs(spec, output_dir, record)
    problems = verify(case, [*record.inputs, *read_beside(case, plan)], reason=f"after run {run_id}")
    record.evidence_check = check_result(problems)
    record.evidence_problems = problems
    record.status, record.reason = _status(record, spec.empty_result)
    if spec.empty_ok and record.status == "failed" and record.reason == spec.empty_result:
        record.status, record.reason = "ok", ""   # nothing to report is a result, such as an empty Timeline
        record.notes = [*record.notes, spec.empty_result]

    if record.status == "ok" and spec.parser:
        try:
            load_output(case, record, folder)
        except OSError as exc:
            record.status = "failed"
            record.reason = (f"output became unreadable while loading: {exc}. "
                             "Antivirus may have quarantined it; check the case folder's exclusion.")
        except Exception as exc:   # noqa: BLE001  (recorded failed with its reason, never left "running")
            record.status, record.reason = "failed", f"could not load the output: {type(exc).__name__}: {exc}"
    _write_record(folder, record)
    return record


def load_output(case: Case, record: RunRecord, folder: Path, layout: dict[str, dict[str, str]] | None = None) -> None:
    """Parse a successful run's output and replace its rows in the events table. `layout` is the journal's host
    splits (journal.host_layout), read here when not given: a run on a split host loads into the split's lanes, so a
    rerun or a rebuild keeps the split. An import is never split."""
    if record.parser == IMPORT:   # imported here: imports.py loads this module for its run records
        from .imports import load_import

        return load_import(case, record, folder)
    parser = PARSERS.get(record.parser)
    if parser is None:
        record.reason = f"no parser '{record.parser}' yet; output kept, not loaded"
        return
    t0 = time.perf_counter()
    ctx = parse_context(case, record, folder)
    routes = (host_layout(case) if layout is None else layout).get(record.host)
    result = load(case.db_path, parser(ctx), host=record.host, tool=record.tool, tool_version=record.tool_version,
                  run_id=record.run_id, replaces_sources=record.inputs, staging_dir=folder,
                  replace_seen_sources=record.from_output, routes=routes)
    record.loaded_rows = result.rows
    record.replaced_rows = result.replaced
    record.rows_without_time = result.without_time
    record.load_seconds = round(time.perf_counter() - t0, 2)
    # Replaced on each load, so a rebuild doesn't repeat them: the parser's own, such as the offset Autoruns' local
    # times were read at, which it notes only when it read one, and the count of events without a
    # time, since nothing on the page shows one: Autoruns entries without one mustn't vanish silently. Also the count
    # of lines or rows a parser made no event of (SKIPPED_NOTE).
    record.notes = [n for n in record.notes
                    if not (n.startswith((LOCAL_TIME_NOTE, SKIPPED_NOTE)) or n.endswith(NO_TIME_NOTE))]
    record.notes += ctx.notes
    if result.without_time:
        n = result.without_time
        record.notes.append(f"{n:,} {'event has' if n == 1 else 'events have'} {NO_TIME_NOTE}")


NO_TIME_NOTE = "no time: off the timeline, and out of search and exports."


def parse_context(case: Case, record: RunRecord, folder: Path, former: int = 0) -> ParseContext:
    """What a run's parser reads, as a load reads it; with `former`, a case format whose key rule the parser gives too
    (parsers.FORMER_RULES), for that format's upgrade (rekey.py), which parses each run as its load did."""
    # Output found in the evidence is read where it lies, by the extended-length path intake hashed it by, so a name
    # that ends in a dot or runs past 260 characters opens its own file. Its events name the files the tool read, which
    # they replace. Its evidence root is the resolved one the files are opened under, since the case may keep the
    # evidence by a junction, a substituted drive, or a mapped one, which a resolved file path doesn't start with;
    # evidence_relative reads a found file's path and the root each in its plain form.
    files = ()
    evidence = Path(record.evidence_root) if record.evidence_root else case.evidence   # as the output names it
    if record.from_output:
        evidence = long_path(case.evidence)
        files = tuple(long_path(evidence, p) for p in record.inputs)
    return ParseContext(folder / "output", evidence, tuple(record.inputs), files, record.zone, record.input_root,
                        former=former)


def read_runs(case: Case) -> list[RunRecord]:
    """Every run's record, oldest first. A run.json that isn't a JSON object, lacks a key every record has, or has a key
    RunRecord doesn't declare (written by a newer build) is refused by name, as open_case refuses a setting, rather than
    failing as a TypeError."""
    records = []
    for path in sorted(case.runs_folder.glob(f"*/{RUN_FILE}")):
        data = json.loads(path.read_text(encoding="utf-8"))
        run = path.parent.name
        if not isinstance(data, dict):
            raise CaseError(f"{path} isn't a JSON object, so run {run} can't be read. "
                            "Restore the file from a copy of the case.")
        if unknown := sorted(set(data) - RECORD_KEYS):
            raise CaseError(f"{path} has keys this build of glessner ({build_id()}) doesn't read: {', '.join(unknown)}. "
                            "A newer build may have written them; open the case with that build.")
        if missing := sorted(REQUIRED_KEYS - set(data)):
            raise CaseError(f"{path} lacks the {'key' if len(missing) == 1 else 'keys'} {', '.join(missing)} that every "
                            f"run's record has, so run {run} can't be read. Restore the file from a copy of the case.")
        records.append(RunRecord(**data))
    return records


def rebuild(case: Case, progress=None, report=None) -> list[RunRecord]:
    """Recreate events.duckdb from the latest successful run for each tool, host, and input set.

    An import's latest run of a file stands for that file, whatever host lane it chose. A host the journal splits by
    recorded computer loads into the split's lanes, with the same event IDs. report(record, text), when given, gets each
    note this rebuild adds to a run's record, for the command line to print.

    The runs load into a new database beside events.duckdb, which takes its place only once every run has loaded, and
    the runs' records are written after that. A load that raises, or a stop such as Ctrl-C, leaves the events and the
    records as they were, and the error is raised. A case with no database yet, or an empty one, such as a copy, is then
    left with no events (an open makes an empty database where there is none), so before the loads each run's record is
    written with no rows and a note that no database holds them (UNFINISHED_NOTE); the records written once the
    rebuild ends replace them."""
    loaded = latest_runs(read_runs(case))
    _refuse_held(case)
    if not _holds_events(case):
        for record in loaded:
            _write_record(case.runs_folder / record.run_id, _unfinished(record))
    built = replace(case, db_file=case.db_file + REBUILT)
    try:
        _delete_database(built.db_path)   # one a rebuild that was killed left
        connect(built.db_path).close()   # an empty events table, even when nothing loads
        layout = host_layout(case)   # the journal's host splits, read once for every load
        for i, record in enumerate(loaded, 1):
            if progress:
                progress(i, len(loaded))   # progress(done, total), for the start page's case copies
            _reload(built, record, layout, report)
        _refuse_held(case)   # another program may have opened it during the loads
        _wal(case.db_path).unlink(missing_ok=True)   # one left by a crash would be replayed into the new database
        os.replace(built.db_path, case.db_path)
    except BaseException:
        with suppress(OSError):
            _delete_database(built.db_path)
        raise
    for record in loaded:
        _write_record(case.runs_folder / record.run_id, record)
    return loaded


REBUILT = ".rebuild"   # added to the events database's name for the one a rebuild loads


def _holds_events(case: Case) -> bool:
    """Whether the case's events database exists and holds an event."""
    if not case.db_path.exists():
        return False
    with closing(connect(case.db_path)) as con:
        return con.execute("SELECT EXISTS (SELECT 1 FROM events)").fetchone()[0]


def _unfinished(record: RunRecord) -> RunRecord:
    """A run's record as a rebuild of a case whose events database is missing or empty leaves it until the rebuild ends:
    no rows, and a note saying why, which the Tools page and the overview's Gaps show as its reason."""
    notes = [n for n in record.notes if not n.endswith(UNFINISHED_NOTE)]
    return replace(record, loaded_rows=0, notes=[*notes, f"Rebuild at {_utc_now()}{LEFT_OUT}{UNFINISHED_NOTE}"])


def _refuse_held(case: Case) -> None:
    """Refuse a rebuild while another program has the events database open, such as glessner serving the case. Opening
    it read-write fails then; closed again, DuckDB writes the database's .wal file into it and deletes the .wal. A copy
    with no database yet has nothing to refuse."""
    if not case.db_path.exists():
        return
    try:
        connect(case.db_path).close()
    except duckdb.Error as exc:   # IOException from another process; ConnectionException from a connection in this one
        raise CaseError(f"{case.settings.name} can't be rebuilt now: another program has its events database open, such as "
                        f"glessner serving the case. Close it, then try again. ({exc})") from exc


def _wal(db_path: Path) -> Path:
    """DuckDB's write-ahead log beside a database, which holds the changes not yet written into it."""
    return db_path.with_name(db_path.name + ".wal")


def _delete_database(db_path: Path) -> None:
    db_path.unlink(missing_ok=True)
    _wal(db_path).unlink(missing_ok=True)


def latest_runs(runs: list[RunRecord], specs: dict[str, ToolSpec] | None = None) -> list[RunRecord]:
    """The runs a rebuild loads, in its order: the latest successful run for each tool, host, and input set
    (own_inputs). `runs` are read_runs', oldest first; `specs` are the registry's tools, read from it when not given."""
    specs = load_registry() if specs is None else specs
    latest: dict[tuple, RunRecord] = {}
    for record in runs:   # oldest first, so later runs overwrite earlier ones
        if record.status == "ok" and (record.parser in PARSERS or record.parser == IMPORT):
            host = "" if record.parser == IMPORT else record.host
            latest[(record.tool, host, own_inputs(record, specs))] = record
    return sorted(latest.values(), key=lambda r: r.run_id)


def own_inputs(record: RunRecord, specs: dict[str, ToolSpec]) -> tuple[str, ...]:
    """The evidence a run was made for, which its reruns share: its inputs, sorted, except for a run of a tool that runs
    once per file, whose own input is its first. The files such a run lists after it are the ones its tool reads
    alongside (ToolSpec.related), such as the $MFT beside a $J, and a rerun can take another: an $MFT added since."""
    spec = specs.get(record.tool)
    if spec is not None and spec.input == "each_file" and not record.from_output and record.inputs:
        return (record.inputs[0],)
    return tuple(sorted(record.inputs))


def run_problems(case: Case, record: RunRecord, reason: str) -> tuple[list[str], list[str]]:
    """What a run's load would read that differs from its record: its evidence files' hashes for an import or a load of
    output found in the evidence, which read evidence files again rather than the run's own output, and for found output
    the files its parser reads beside its inputs that the manifest lists (companions); otherwise its output folder
    against the hashes its run recorded. Also the files the load would read that have no hash: a run's output files it
    never hashed, and the companions the manifest doesn't list. `reason` goes to the verification record."""
    if record.parser == IMPORT or record.from_output:
        listed, unlisted = companions(case, record)
        return verify(case, [*record.inputs, *listed], reason=reason), unlisted
    return output_problems(record, case.runs_folder / record.run_id / "output")


def reload_run(case: Case, record: RunRecord, layout: dict[str, dict[str, str]], report=None) -> None:
    """Load one run's output again as a rebuild does (_reload), and write its record. The case format upgrade's reload
    (rekey.py) calls it."""
    _reload(case, record, layout, report)
    _write_record(case.runs_folder / record.run_id, record)


def _reload(case: Case, record: RunRecord, layout: dict[str, dict[str, str]], report=None) -> None:
    """Load one run's output again into the case's database, after checking it (run_problems), and add a note to its
    record on what the check found, without writing the record."""
    folder = case.runs_folder / record.run_id
    problems, unhashed = run_problems(case, record, f"rebuild reads {record.run_id}")
    record.notes = [n for n in record.notes if not n.endswith((UNHASHED_NOTE, UNFINISHED_NOTE))]
    if problems:
        record.loaded_rows = 0
        note = f"Rebuild at {_utc_now()}{LEFT_OUT}{'; '.join(problems)}"
    else:
        load_output(case, record, folder, layout)
        note = (f"Rebuild at {_utc_now()}: {len(unhashed):,} output {'file was' if len(unhashed) == 1 else 'files were'}"
                f" loaded unchecked ({', '.join(unhashed[:10])}{', and more' if len(unhashed) > 10 else ''}): "
                f"{UNHASHED_NOTE}") if unhashed else ""
    if note:
        record.notes = [*record.notes, note]
        if report:
            report(record, note)


# The end of a rebuild's note on the output files an older run never hashed
UNHASHED_NOTE = "the run recorded no hash for them."
# The end of the note a rebuild of a case with no events database, such as a copy's first, gives each run it loads
# until it finishes
UNFINISHED_NOTE = "the case has no events database until a rebuild finishes. Rebuild the case to load this run."
# What a rebuild's note on a run it left out says before the problems, which the commands and the Tools page look for
LEFT_OUT = " left it out: "


FOUND_OUTPUT = "found output"   # the tool version of a load of output found in the evidence; the CSV doesn't say
# The files a parser reads beside a found output's inputs, by parser: SBECmd's messages file names each CSV's hive
COMPANIONS = {"sbecmd_csv": (MESSAGES,)}


def companions(case: Case, record: RunRecord) -> tuple[list[str], list[str]]:
    """The files a load of found output reads beside its inputs (COMPANIONS): each one in an input's folder that the
    manifest lists, and each that is on disk but not in the manifest (named as given), as two lists of evidence-relative
    paths, sorted and without repeats. Both are empty for any other run."""
    names = COMPANIONS.get(record.parser, ()) if record.from_output else ()
    listed = {e.path.lower(): e.path for e in current_entries(case)} if names else {}
    base = long_path(case.evidence)
    found, unlisted = set(), set()
    for folder in {rel.rpartition("/")[0] for rel in record.inputs}:
        for name in names:
            rel = f"{folder}/{name}" if folder else name
            if rel.lower() in listed:
                found.add(listed[rel.lower()])
            elif long_path(base, rel).is_file():
                unlisted.add(rel)
    return sorted(found), sorted(unlisted)


NOT_CHECKED = "not checked"   # the evidence_check of a run refused before it read anything
NOT_READ = "not read"   # how a run that recorded no evidence check is shown, such as a load that failed while it read


def _unlisted_reason(paths: list[str]) -> str:
    """Why a load of found output stopped before it read anything: files its parser reads beside the output, which the
    manifest doesn't list, so no evidence check can cover them."""
    one = len(paths) == 1
    return (f"the load reads {'a file' if one else 'files'} beside the output that the manifest doesn't list, so no check "
            f"covers {'it' if one else 'them'}: {_paths([f'{path}: {NOT_IN_MANIFEST}' for path in paths])}. Add the files "
            "the manifest doesn't list with Add new evidence, then load it again")


def load_found_output(case: Case, tool: str, parser: str, host: str, inputs: list[str]) -> RunRecord:
    """Load a tool's output found in the evidence, such as KAPE's module output, as a run: the files' hashes
    are checked before and after reading, run.json records them, and a rebuild reads them again. The check covers the
    files the parser reads beside the output too (companions), though the run's inputs are the output alone. A companion
    the manifest doesn't list fails the load before it reads, as NOT_CHECKED, since nothing changed; one that appears
    while the load reads fails its check."""
    zone = host_zone(case, host) if parser in LOCAL_TIME else None   # local time, such as Autoruns'
    record, folder = start_run(case, tool, host, tool_version=FOUND_OUTPUT, host=host, inputs=sorted(inputs),
                               parser=parser, from_output=True, zone=zone)
    (folder / "output").mkdir()
    t0 = time.perf_counter()
    listed, unlisted = companions(case, record)
    before = verify(case, [*record.inputs, *listed], reason=f"before loading {record.run_id}")
    if before:
        record.evidence_check, record.evidence_problems = check_result(before), before
        record.status = "failed"
        record.reason = (not_reread("the check before loading", before, "load it again")
                         if record.evidence_check == UNREADABLE
                         else f"the output doesn't match its intake hash: {'; '.join(before)}")
    elif unlisted:
        record.status, record.evidence_check, record.reason = "failed", NOT_CHECKED, _unlisted_reason(unlisted)
    else:
        try:
            load_output(case, record, folder)
        except (OSError, ValueError, csv.Error) as exc:
            record.status, record.reason = "failed", f"could not load: {exc}"
        except Exception as exc:   # noqa: BLE001  (recorded failed with its reason, never left "running")
            record.status, record.reason = "failed", f"could not load: {type(exc).__name__}: {exc}"
        else:
            listed, unlisted = companions(case, record)   # one that appeared during the load is evidence that changed
            after = verify(case, [*record.inputs, *listed, *unlisted], reason=f"after loading {record.run_id}")
            record.evidence_check, record.evidence_problems = check_result(after), after
            record.status = "ok" if not after else "failed"
            if record.evidence_check == UNREADABLE:
                record.reason = not_reread("the check after loading", after, "load it again")
            elif after:
                record.reason = "evidence changed while it was read"
    record.seconds = round(time.perf_counter() - t0, 2)
    finish_run(folder, record)
    return record


def start_run(case: Case, tool: str, name: str, **fields) -> tuple[RunRecord, Path]:
    """Start a run for which no tool is started, an import (imports.run_import) or a load of output found in the
    evidence: a new run ID from the tool and `name`, a host or a file's name; the run's folder; and its record, started
    now and written to run.json. `fields` are the record's own. A run folder that can't be made safely is refused, as
    CaseError (_new_run_folder)."""
    run_id, folder = _new_run_folder(case, tool, name)
    folder.mkdir(parents=True)
    record = RunRecord(run_id=run_id, tool=tool, executable="", argv=[], cwd="", started_utc=_utc_now(), **fields)
    _write_record(folder, record)
    return record, folder


def finish_run(folder: Path, record: RunRecord) -> None:
    """Note when a run finished, and write its record."""
    record.finished_utc = _utc_now()
    _write_record(folder, record)


def host_zone(case: Case, host: str) -> dict | None:
    """The zone a load reads the host's local times in (parsers.LOCAL_TIME), from its SYSTEM hive, or None when the
    case has none for it yet. Autoruns writes every time at the one offset in force when it ran, not each date's own:
    on the Szechuan dataset, December dates read with Pacific standard time fell an hour after the MFT's and RECmd's
    records of the same writes. So the hive's ActiveTimeBias, the offset when the hive was last written, comes first,
    as a fixed offset. Without it, the host's zone, resolved as the import resolves "host:<host>", whose
    offset the parser takes at the output's own latest time, such as Autoruns' newest location row. The connection is a
    read-write one: in the server, which holds the database open, a read-only one can't open it (imports.host_zones)."""
    if not case.db_path.exists():
        return None
    con = connect(case.db_path)
    try:
        zones = host_timezones(con)
    finally:
        con.close()
    active = (zones.get(host) or {}).get("active_bias_minutes")
    if active is not None:
        minutes = -active   # Windows: UTC = local time + bias
        return {"kind": "offset", "minutes": minutes, "host": host,
                "label": f"UTC{fmt_offset(minutes)}, {host}'s offset when its SYSTEM hive was last written "
                         "(ActiveTimeBias)"}
    try:
        return resolve_zone(f"host:{host}", zones)
    except ZoneError:
        return None


def _make_copies(case: Case, plan: RunPlan, root: Path) -> list[str]:
    """Copy the run's inputs, and the host's files named by copy_also, to root in the evidence layout. Each copy
    must match its intake hash, so the tool reads the evidence as it was taken in."""
    spec = plan.tool.spec
    wanted = list(plan.inputs)
    for e in current_entries(case):
        if (case.host_of(e.path) == plan.host and _matches(spec.copy_also, e.artifact, e.detail)
                and e.path not in wanted):
            wanted.append(e.path)
    hashes = {e.path: e.sha256 for e in current_entries(case)}
    for rel in wanted:
        dst = long_path(root, rel)   # the evidence's names as they are, under the run folder
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(long_path(case.evidence, rel), dst)
        if sha256_file(dst) != hashes.get(rel):
            raise RunError(f"{rel} doesn't match its intake hash")
    return wanted


def _changed_copies(case: Case, root: Path, copies: list[str]) -> list[str]:
    hashes = {e.path: e.sha256 for e in current_entries(case)}
    return [rel for rel in copies
            if not long_path(root, rel).is_file() or sha256_file(long_path(root, rel)) != hashes.get(rel)]


def _check_outputs(spec: ToolSpec, output_dir: Path, record: RunRecord) -> None:
    """Note each expected output that is missing, and hash every file under the output folder, which a rebuild checks
    the folder against (output_problems). The registry's patterns name only some of a tool's files, so most CSVs
    that AmcacheParser, SrumECmd, and SBECmd write, which their parsers read, would have no hash. A file
    that can't be read fails the run, as an expected output always has."""
    named = set()
    for pattern in spec.outputs:
        matches = sorted(output_dir.glob(pattern))
        if not matches:
            record.missing_outputs.append(pattern)
        named.update(matches)
    for path in sorted(named | {p for p in output_dir.rglob("*") if p.is_file()}):
        rel = path.relative_to(output_dir).as_posix()
        try:
            record.outputs.append({"path": rel, "size": path.stat().st_size, "sha256": sha256_file(path)})
        except OSError as exc:   # antivirus can lock or remove a file while it is being read
            record.missing_outputs.append(f"{rel} (unreadable: {exc.strerror or exc})")
    record.outputs_all = True


def output_problems(record: RunRecord, output_dir: Path) -> tuple[list[str], list[str]]:
    """How a run's output folder differs from what run.json recorded when the tool ran: each recorded file missing,
    unreadable, or changed, and for a run that recorded every file, each file added since. Also, for a run that didn't
    record every file, the files it never hashed, which a rebuild loads with a note."""
    present = ({p.relative_to(output_dir).as_posix(): p for p in output_dir.rglob("*") if p.is_file()}
               if output_dir.is_dir() else {})
    recorded = {o["path"]: o["sha256"] for o in record.outputs}
    problems = []
    for rel, digest in sorted(recorded.items()):
        if rel not in present:
            problems.append(f"{rel}: missing")
            continue
        try:
            if sha256_file(present[rel]) != digest:
                problems.append(f"{rel}: SHA-256 changed")
        except OSError as exc:
            problems.append(f"{rel}: unreadable ({exc.strerror or exc})")
    unhashed = sorted(rel for rel in present if rel not in recorded)
    if record.outputs_all:
        problems += [f"{rel}: not there when the tool ran" for rel in unhashed]
        unhashed = []
    return problems, unhashed


UNREADABLE = "unreadable"   # an evidence check's result when it couldn't read a file and found none changed


def check_result(problems: list[str]) -> str:
    """An evidence check's result from its problems (intake.check_files), as RunRecord.evidence_check records it: "ok"
    for none; UNREADABLE when each says only that a file couldn't be read, such as one another program holds open, so
    no hash was compared; "mismatch" when one says a file changed, is missing, or isn't in the manifest."""
    if not problems:
        return "ok"
    return UNREADABLE if all(_unreadable(p) for p in problems) else "mismatch"


def _unreadable(problem: str) -> bool:
    """Whether an evidence check's problem says only that its file couldn't be read: check_files writes
    "<path>: unreadable (<reason>)"."""
    return problem.rpartition(": ")[2].startswith("unreadable (")


def not_reread(check: str, problems: list[str], again: str) -> str:
    """Why a run, a load of found output, or an import (imports.run_import) failed when its evidence check could not
    re-read its files (UNREADABLE). `check` names the check, and `again` says what to do."""
    one = len(problems) == 1
    files = "1 file" if one else f"{len(problems):,} files"
    return (f"{check} could not re-read {files}, so it compared no hash with intake's: {'; '.join(problems)}. Another "
            f"program, such as antivirus, may have held {'it' if one else 'them'} open; {again}.")


def _status(record: RunRecord, empty_result: str = "") -> tuple[str, str]:
    """A run's status and the reason it failed. empty_result explains output that is simply absent, for a tool
    that finishes quietly when it finds none of its inputs."""
    if record.reason:
        return "failed", record.reason
    if record.timed_out:
        return "failed", "timed out"
    if record.evidence_check == "mismatch":
        return "failed", "evidence changed during the run; further runs should stop"
    if record.exit_code != 0:
        return "failed", f"exit code {record.exit_code}"
    if record.evidence_check == UNREADABLE:
        return "failed", not_reread("the evidence check after the run", record.evidence_problems, "run the tool again")
    if record.missing_outputs and empty_result and not any("(unreadable:" in m for m in record.missing_outputs):
        return "failed", empty_result
    if record.missing_outputs:
        return "failed", (f"expected output missing or unreadable: {', '.join(record.missing_outputs)}. "
                          "Antivirus may have quarantined it; check the case folder's exclusion.")
    return "ok", ""


def _fill(arg: str, values: dict[str, str], spec: ToolSpec) -> str:
    for key, value in values.items():
        arg = arg.replace(key, value)
    leftover = [p for p in PLACEHOLDERS if p in arg]
    if leftover:
        raise RunError(f"{spec.id}: placeholder {leftover[0]} has no value in this run")
    return arg


def _new_run_folder(case: Case, tool_id: str, name: str) -> tuple[str, Path]:
    """A new run's ID and its folder, not made yet. Refused, as CaseError, when the case folder and the evidence folder
    overlap (check_outside_evidence), or when the folder wouldn't be directly in the runs folder, where read_runs finds
    it, and outside the evidence. The name is part of the folder's, so a single_host in case.yaml edited by hand to
    hold a slash or a backslash, such as CORP\\DC01 or one with ..\\, would put it deeper, or elsewhere."""
    check_outside_evidence(case.folder.resolve(), case.evidence)
    run_id = _new_run_id(case, tool_id, name)
    folder = case.runs_folder / run_id
    resolved = folder.resolve()
    if resolved.parent != case.runs_folder.resolve():
        raise CaseError(f"No run folder can be made at {resolved}: it isn't directly in the case's runs folder, "
                        f"{case.runs_folder}. The name {name!r} has a slash or a backslash; if it is single_host in "
                        f"{CASE_FILE}, set that to the host's name alone.")
    if resolved.is_relative_to(case.evidence):   # a runs folder that links into the evidence
        raise CaseError(f"Refusing to write a run inside the evidence folder: {resolved}")
    return run_id, folder


def _new_run_id(case: Case, tool_id: str, host: str) -> str:
    base = f"{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}_{tool_id}_{host}"
    run_id, n = base, 1
    while (case.runs_folder / run_id).exists():
        n += 1
        run_id = f"{base}_{n}"
    return run_id


def _write_record(folder: Path, record: RunRecord) -> None:
    """Write run.json. `outputs_all` is left out while it's false, so a run recorded without it, which a rebuild or a
    copy writes again, keeps the shape older builds read: their read_runs takes each key as a field, and an unknown
    one fails their Case overview and Tools page with a TypeError. A tool run this build makes keeps the key, and
    only the case format number makes an older build refuse such a case cleanly."""
    data = asdict(record)
    if not data["outputs_all"]:
        del data["outputs_all"]
    write_atomically(folder / RUN_FILE, json.dumps(data, indent=2))


def _utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
