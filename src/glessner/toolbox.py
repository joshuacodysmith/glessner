"""The Tools page: which tools are installed, what each would read in this case, whether it
ran, what's missing, which evidence no installed tool reads, and other known tools in the tools folder. Also runs a
tool from the page, one at a time, in the background, so the page can show its progress.

Tools' output found in the evidence, such as KAPE's module output, is listed too, by tool and host, and loaded from the
page the same way. Raw evidence comes first: output for a host whose raw files
an installed tool reads is listed as not loaded, with Load anyway.

Detection runs each tool's version check, which takes seconds for the whole registry, so the server keeps the result
until the analyst scans again.
"""

from __future__ import annotations

import fnmatch
import json
import threading
from collections import Counter, defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .case import Case, CaseError
from .identify import IMPORTABLE
from .imports import MappingError, listed_as, loaded_as_output, run_import
from .intake import current_entries
from .parsers import LOCAL_TIME
from .runner import (
    IMPORT,
    LEFT_OUT,
    NOT_CHECKED,
    NOT_READ,
    RUN_FILE,
    UNREADABLE,
    RunError,
    RunPlan,
    RunRecord,
    finish_run,
    handles,
    load_found_output,
    own_inputs,
    plan_runs,
    read_runs,
    run,
)
from .tool_outputs import BY_KIND, CAPTURES
from .tools import REGISTRY_DIR, DetectedTool, ToolSpec, _executables_under

KNOWN_FILE = REGISTRY_DIR / "known" / "known_tools.yaml"
NOUNS = {   # what an artifact is called on the page, singular
    "evtx": "event log", "prefetch": "prefetch file", "lnk": "LNK file", "mft": "$MFT file", "mft_mirror": "$MFTMirr file",
    "registry": "registry hive", "registry_log": "hive transaction log", "registry:AMCACHE": "Amcache hive",
    "registry:NTUSER": "NTUSER.DAT hive", "registry:USRCLASS": "UsrClass.dat hive", "registry:SOFTWARE": "SOFTWARE hive",
    "jumplist": "jump list", "recycle_bin": "Recycle Bin file", "srum": "SRUM database", "event_xml": "event XML file",
    "pcap": "capture file", "usnjrnl": "USN journal", "sqlite": "SQLite database", "sqlite_log": "SQLite log file",
    "sqlite:ActivitiesCache": "Windows Timeline database",
}


@dataclass(frozen=True)
class KnownTool:
    name: str
    executables: tuple[str, ...]
    reads: str
    status: str
    url: str


def load_known(path: Path = KNOWN_FILE) -> list[KnownTool]:
    if not path.is_file():
        return []
    return [KnownTool(t["name"], tuple(t["executables"]), t.get("reads", ""), t.get("status", ""), t.get("url", ""))
            for t in yaml.safe_load(path.read_text(encoding="utf-8")) or []]


def find_known(tools_folder: Path | None, known: list[KnownTool]) -> list[dict]:
    """Known tools whose executables are in the tools folder."""
    if not tools_folder or not tools_folder.is_dir():
        return []
    exes = _executables_under(tools_folder)
    out = []
    for k in known:
        hit = next((p for p in exes for pat in k.executables if fnmatch.fnmatch(p.name.lower(), pat.lower())), None)
        if hit is not None:
            out.append({"name": k.name, "path": str(hit), "reads": k.reads, "status": k.status, "url": k.url})
    return out


def run_gaps(runs: list[RunRecord], specs: dict[str, ToolSpec]) -> list[dict]:
    """Runs that failed or loaded nothing, which the Case overview's Gaps and the Tools page list. Only
    the latest run of each tool and host counts, and for a tool that runs once per file, of each file; an import's,
    of each file; a load of found output, of each host's group: a later run that loaded events replaced the gap. A run
    still marked running is left out, since a job may be running it."""
    latest: dict[tuple, RunRecord] = {}
    for r in runs:   # oldest first, so the later run wins
        each = r.tool == IMPORT or (r.tool in specs and specs[r.tool].input == "each_file")
        key = (r.tool, "" if r.tool == IMPORT else r.host, r.from_output, own_inputs(r, specs) if each else ())
        latest[key] = r
    # A run a rebuild left out, because its output or evidence changed since it ran, says why from its newest note
    # saying so
    left_out = lambda r: next((n for n in reversed(r.notes) if LEFT_OUT in n), "")
    return [{"run_id": r.run_id, "tool": r.tool, "name": specs[r.tool].name if r.tool in specs else r.tool,
             "host": r.host, "status": r.status, "reason": r.reason or left_out(r), "rows": r.loaded_rows or 0,
             "inputs": len(r.inputs), "from_output": r.from_output, "at": r.finished_utc or r.started_utc}
            for r in sorted(latest.values(), key=lambda r: r.run_id)
            if r.status == "failed" or (r.status == "ok" and not r.loaded_rows)]


INTERRUPTED = ("interrupted: the run was still marked running when the case was next opened for work, so it stopped "
               "before it finished, such as at Ctrl+C, a closed window, or a crash. Run it again.")


def close_interrupted(case: Case) -> list[RunRecord]:
    """Mark each run still recorded as running as failed, with INTERRUPTED as its reason, and return the records it
    marked. A run's record says running from before its tool starts until the run ends, so one found so when the case is
    opened for work was stopped before it ended; run_gaps leaves a running run out, since a job may be running it, so
    without this it would never show in the Gaps. A run that another command line process is still running at that
    moment is marked too, and its own final write replaces the mark. A run's record is read again just before its mark
    is written, and a run that has ended since is left as it is; one that ends in the instant between that read and the
    write can still have its final record replaced. Never raises: a record this build can't read (CaseError for one that
    isn't an object, lacks a key, or has a key it doesn't know; ValueError for text that isn't JSON; TypeError for a
    value of the wrong type, such as a run ID that isn't text), or one that can't be read or written (OSError), ends the
    pass with the runs marked so far."""
    closed = []
    try:
        for record in read_runs(case):
            folder = case.runs_folder / record.run_id
            if record.status == "running" and _still_running(folder):
                record.status, record.reason = "failed", INTERRUPTED
                finish_run(folder, record)
                closed.append(record)
    except (CaseError, OSError, TypeError, ValueError):
        pass
    return closed


def _still_running(folder: Path) -> bool:
    """Whether the run's record, read now, still says running."""
    data = json.loads((folder / RUN_FILE).read_text(encoding="utf-8"))
    return isinstance(data, dict) and data.get("status") == "running"


def _noun(key: str, n: int) -> str:
    word = NOUNS.get(key) or (f"{key.split(':', 1)[1]} hive" if key.startswith("registry:") else key.replace("_", " "))
    if n == 1:
        return f"1 {word}"
    return f"{n:,} {word if word.endswith('s') else word + 's'}"


def overview(case: Case, specs: dict[str, ToolSpec], detected: dict[str, DetectedTool]) -> dict:
    entries = current_entries(case) if case.manifest_path.exists() else []
    runs = read_runs(case)
    tools = []
    for spec in specs.values():
        matched = [e for e in entries if handles(spec, e.artifact, e.detail)]
        by_kind = Counter(next(h for h in spec.handles if h in (e.artifact, f"{e.artifact}:{e.detail}")) for e in matched)
        hosts = sorted({h for e in matched if (h := case.host_of(e.path))})
        # The latest successful run of each host, and for a tool that runs once per file, of each file: the events the
        # case holds. WxTCmd's runs on a host's Timeline databases each hold their own, so the host's last run alone
        # doesn't count them. A tool that reads the host's folder replaces its earlier run's events, even
        # when Add new evidence gave the later run more files, so that run counts alone.
        latest: dict[tuple, object] = {}
        for r in runs:   # oldest first, so the later run wins
            if r.tool == spec.id and r.status == "ok":
                latest[(r.host, own_inputs(r, specs) if spec.input == "each_file" else ())] = r
        last = max((r.finished_utc for r in latest.values()), default="")
        tool = detected.get(spec.id)
        if tool and tool.missing and hosts:
            status = "blocked"   # installed, but can't run here, such as Suricata without Npcap
        elif tool and hosts:
            status = "ran" if latest else "ready"
        elif tool:
            status = "nothing"
        else:
            status = "missing" if hosts else "missing_unneeded"
        tools.append({
            "id": spec.id, "name": spec.name, "publisher": spec.publisher, "license": spec.license,
            "download_url": spec.download_url, "notes": spec.notes, "work_on_copies": spec.work_on_copies,
            "found": tool is not None, "version": tool.version if tool else "", "path": str(tool.executable) if tool else "",
            "dotnet": spec.dotnet, "dotnet_root": tool.dotnet_root if tool else "", "builtin": spec.builtin,
            "missing": tool.missing if tool else "", "rules": tool.rules if tool else "", "has_rules": bool(spec.rules),
            "reads": ", ".join(_noun(k, n) for k, n in by_kind.most_common()), "hosts": hosts, "status": status,
            "last_run": {"at": last, "rows": sum(r.loaded_rows or 0 for r in latest.values()),
                         "hosts": sorted({host for host, _ in latest})} if latest else None,
            "hits": spec.id == "hayabusa",   # its rows are hits, not events
        })
    # A file a tool copies along with its input, such as a SQLite database's logs, is read too.
    handled = lambda e: any(handles(t.spec, e.artifact, e.detail) or e.artifact in t.spec.copy_also
                            for t in detected.values())
    unread = Counter(f"{e.artifact}:{e.detail}" if e.artifact == "registry" else e.artifact
                     for e in entries if e.artifact and e.artifact not in IMPORTABLE and e.artifact not in ("tool_output", "pcap")
                     and not e.error and not handled(e))
    # The files the Import page offers, so both pages count the same ones: text logs, and output in
    # local time, such as an Autoruns CSV, that no load from this page has read.
    loaded = loaded_as_output(case, runs)
    offered = Counter()
    for e in entries:
        artifact, detail = listed_as(e)
        if artifact in IMPORTABLE and e.path not in loaded:
            offered["text_log" if e.artifact in IMPORTABLE else detail] += 1
    # Each with intake's reason, where it gave one, such as a prefetch name without its signature
    unidentified = [{"path": e.path, "reason": e.detail} for e in entries if e.artifact is None and not e.error]
    folder = Path(case.settings.tools_folder) if case.settings.tools_folder else None
    return {"tools_folder": str(folder or ""), "found": len(detected), "total": len(specs), "tools": tools,
            "outputs": found_outputs(case, specs, detected, entries, runs),
            "unread": [{"what": _noun(k, n)} for k, n in unread.most_common()],
            "to_import": [_noun(k, n) for k, n in offered.most_common()],
            "unidentified": len(unidentified), "unidentified_sample": unidentified[:50],
            "others": find_known(folder, load_known()), "gaps": run_gaps(runs, specs)}


def found_outputs(case: Case, specs: dict[str, ToolSpec], detected: dict[str, DetectedTool],
                  entries: list | None = None, runs: list | None = None) -> list[dict]:
    """Tools' output found in the evidence, one group per tool and host, each with its status: loaded, ready, raw
    (the host's raw files are run instead), no_parser, or no_host (a file in the evidence folder's top level)."""
    entries = entries if entries is not None else current_entries(case)
    runs = runs if runs is not None else read_runs(case)
    groups: dict[tuple[str, str], list] = defaultdict(list)
    # Captures are listed here only while no installed tool that can run reads them; with Suricata ready, its row on
    # the Tools page covers them.
    reads = lambda e: any(handles(t.spec, e.artifact, e.detail) and not t.missing for t in detected.values())
    for e in entries:
        if e.error:
            continue
        kind = (BY_KIND.get(e.detail) if e.artifact == "tool_output"
                else CAPTURES if e.artifact == "pcap" and not reads(e) else None)
        if kind:
            groups[(group_key(kind), case.host_of(e.path) or "")].append((e, kind))
    loaded, imported = {}, {}
    for r in runs:   # oldest first, so the latest load of each file set wins
        if r.from_output and r.status == "ok":
            loaded[(r.tool, r.host, tuple(r.inputs))] = r
        elif r.tool == "import" and r.status == "ok":
            imported[r.inputs[0]] = r
    out = []
    for (key, host), items in sorted(groups.items()):
        kind = items[0][1]
        spec = specs.get(kind.tool)
        paths = sorted(e.path for e, _ in items)
        runnable = kind.tool in detected and not detected[kind.tool].missing
        raw = spec is not None and runnable and any(
            handles(spec, e.artifact, e.detail) and case.host_of(e.path) == host for e in entries)
        done = loaded.get((kind.tool, host, tuple(paths)))
        # Loaded through the import, one run per file: a preset's way, and an Autoruns CSV's when the analyst imported
        # it on the Import page, which a load by its parser would put in a second time.
        runs_of = [imported[p] for p in paths if p in imported]
        if not done and len(runs_of) == len(paths):
            done = runs_of[-1].__class__(**{**runs_of[-1].__dict__,
                                            "loaded_rows": sum(r.loaded_rows or 0 for r in runs_of),
                                            "rows_without_time": sum(r.rows_without_time or 0 for r in runs_of),
                                            "finished_utc": max(r.finished_utc for r in runs_of)})
        if kind.preset:   # the app doesn't run these tools itself
            raw = False
        if not host:
            status = "no_host"
        elif not (kind.parser or kind.preset):
            status = "no_parser"
        elif done:
            status = "loaded"
        elif raw:
            status = "raw"
        else:
            status = "ready"
        out.append({"key": key, "tool": kind.tool, "tool_name": spec.name if spec else (kind.maker or kind.tool),
                    "label": kind.label, "parser": kind.parser, "preset": kind.preset, "host": host, "files": len(paths),
                    "paths": paths[:20], "status": status, "note": kind.note,
                    # Events without a time, which nothing else on the page shows
                    "loaded": {"at": done.finished_utc, "rows": done.loaded_rows,
                               "without_time": done.rows_without_time or 0} if done else None})
    return out


def group_key(kind) -> str:
    """Found output loads by group: one per parser or import preset, so JLECmd's two CSV kinds go together."""
    return kind.preset or kind.parser or kind.kind


def start_load_job(case: Case, specs: dict[str, ToolSpec], detected: dict[str, DetectedTool], key: str,
                   hosts: list[str] | None, anyway: bool, after: Callable[[ToolJob], None]) -> ToolJob:
    """Load a tool's output found in the evidence, host by host, in the background. Without anyway, only
    hosts without raw files the tool reads; with it, those too."""
    wanted = {"ready", "raw"} if anyway else {"ready"}
    groups = [g for g in found_outputs(case, specs, detected) if g["key"] == key and g["status"] in wanted
              and (not hosts or g["host"] in hosts)]
    if not groups:
        raise RunError("Nothing to load: the output is loaded already, or its hosts have raw evidence to run instead.")
    return _start(ToolJob(groups[0]["label"], len(groups), "load"), f"load-{key}", case, [], groups, _step_host, after)


def everything_ready(case: Case, specs: dict[str, ToolSpec], detected: dict[str, DetectedTool],
                     view: dict | None = None) -> tuple[list, list]:
    """What Run and load everything ready does: the installed tools that have evidence here and haven't run,
    and the found output ready to load. `view` is the overview when the caller has it, as the Tools page does."""
    view = view or overview(case, specs, detected)
    tools = [detected[t["id"]] for t in view["tools"] if t["status"] == "ready"]
    # Output written in a host's local time, such as Autoruns', loads last, after any RECmd output found beside it,
    # which gives the host's zone. The sort keeps the order otherwise.
    groups = [g for g in view["outputs"] if g["status"] == "ready"]
    return tools, sorted(groups, key=lambda g: g["parser"] in LOCAL_TIME)


def start_all_job(case: Case, specs: dict[str, ToolSpec], detected: dict[str, DetectedTool],
                  after: Callable[[ToolJob], None]) -> ToolJob:
    """Run every ready tool on its hosts, then load every ready group of found output, in one background job: the
    one-folder-in path. Raw evidence comes first, so the tools run before any output loads."""
    tools, groups = everything_ready(case, specs, detected)
    plans = [plan for tool in tools for plan in plan_runs(case, tool)]
    if not plans and not groups:
        raise RunError("Nothing is ready: every tool with evidence here has run, and found output is loaded.")
    return _start(ToolJob("Everything ready", len(plans) + len(groups), "all"), "everything-ready", case, plans, groups,
                  _step_name, after)


def load_group(case: Case, g: dict, entries: list | None = None) -> list:
    """Load one group of found output: its CSVs as one run with the tool's parser, or each network monitor's log as an
    import with its ready-made mapping. Returns the runs' records."""
    entries = entries if entries is not None else current_entries(case)
    paths = sorted(e.path for e in entries if e.artifact == "tool_output" and case.host_of(e.path) == g["host"]
                   and (k := BY_KIND.get(e.detail)) and group_key(k) == g["key"])
    if g["preset"]:
        return [_import_found(case, path, g["preset"]) for path in paths]
    return [load_found_output(case, g["tool"], g["parser"], g["host"], paths)]


def _import_found(case: Case, path: str, preset: str):
    """Import one network monitor's log by its ready-made mapping; a mapping problem fails it with the reason."""
    try:
        return run_import(case, path, {"preset": preset}, zones={})
    except MappingError as exc:
        return RunRecord(run_id="", tool="import", tool_version="", executable="", host="", argv=[], cwd="",
                         inputs=[path], started_utc="", status="failed", reason=f"{path}: {exc}")


STOP_RUN = "Stopped: evidence changed during a run. Check the case's verification record."
STOP_LOAD = "Stopped: evidence changed while it was read. Check the case's verification record."


def run_and_load(case: Case, plans: list[RunPlan], groups: list[dict], started: Callable, finished: Callable,
                 options: dict[str, str] | None = None) -> str:
    """Run each plan, then load each group of found output (found_outputs): the steps of the Tools page's jobs and of
    the command line's run and load-output, so they stop by one rule. started(step) comes before
    each step, and finished(step, records) after it, a step being a plan or a group. A run refused before it started,
    such as one whose host's folder holds files intake didn't hash, is a failed step with the refusal as its reason, and
    the next step goes on. Stops after the first step that finds the evidence changed, and returns why, or "" when
    every step ran. A step whose check only couldn't re-read a file (runner.UNREADABLE) fails without stopping the
    others, since it compared no hash."""
    for plan in plans:
        started(plan)
        try:
            record = run(case, plan, options)
        except RunError as exc:
            record = _refused(plan, str(exc))
        finished(plan, [record])
        if record.evidence_check == "mismatch":
            return STOP_RUN
    entries = current_entries(case) if groups else []
    for g in groups:
        started(g)
        records = load_group(case, g, entries)
        finished(g, records)
        if any(r.evidence_check == "mismatch" for r in records):
            return STOP_LOAD
    return ""


def _refused(plan: RunPlan, reason: str) -> RunRecord:
    """A run refused before it started, as its job reports it: failed, with the reason, and its evidence not checked.
    It has no run ID or folder, and nothing is written."""
    return RunRecord(run_id="", tool=plan.tool.spec.id, tool_version=plan.tool.version,
                     executable=str(plan.tool.executable), host=plan.host, argv=[], cwd="", inputs=list(plan.inputs),
                     started_utc="", status="failed", reason=reason, evidence_check=NOT_CHECKED)


def _step_input(step: RunPlan | dict) -> str:
    """The file a tool that runs once per file reads, within its host's folder, so the tool's runs on one host are told
    apart: WxTCmd's four runs on one host would each read "WxTCmd on DESKTOP" without it."""
    if not isinstance(step, RunPlan) or not step.input_file:
        return ""
    return f", {step.input_file.removeprefix(f'{step.host}/')}"


def _step_host(step: RunPlan | dict) -> str:
    return (step.host if isinstance(step, RunPlan) else step["host"]) + _step_input(step)


def _step_name(step: RunPlan | dict) -> str:
    """A step as a job names it: the tool and its host, or the found output and its host."""
    if isinstance(step, RunPlan):
        return f"{step.tool.spec.name} on {step.host}{_step_input(step)}"
    return f"{step['label']} on {step['host']}"


def _step_result(label: str, step: RunPlan | dict, records: list[RunRecord]) -> dict:
    """A finished step as the page lists it: a run's own record, or a group's runs together. A group's `evidence` is the
    most serious check of its runs: mismatch, then unreadable, then not checked, then not read (a load that failed
    while it read, which records no check), then ok. `hits` says its rows are Hayabusa's hits, which the page counts
    apart from events. `loaded` says a load committed, which a run records with its rows once events.load has committed
    them: a run can fail after that, when the evidence changed while it was read, and a group fails when any of its runs
    does, so a step's status doesn't say whether the events changed."""
    hits = (step.tool.spec.id if isinstance(step, RunPlan) else step["tool"]) == "hayabusa"
    loaded = any(r.loaded_rows is not None for r in records)
    if isinstance(step, RunPlan):
        (record,) = records
        return {"host": label, "status": record.status, "reason": record.reason, "rows": record.loaded_rows,
                "hits": hits, "seconds": record.seconds, "evidence": record.evidence_check,
                "working_copy_changes": len(record.working_copy_changes), "loaded": loaded}
    bad = [r for r in records if r.status != "ok"]
    checks = {r.evidence_check for r in records}
    if "mismatch" in checks:
        evidence = "mismatch"
    elif UNREADABLE in checks:
        evidence = UNREADABLE
    elif NOT_CHECKED in checks:
        evidence = NOT_CHECKED
    elif "" in checks:
        evidence = NOT_READ
    else:
        evidence = "ok"
    return {"host": label, "status": "failed" if bad else "ok", "reason": "; ".join(r.reason for r in bad),
            "rows": sum(r.loaded_rows or 0 for r in records), "hits": hits,
            "seconds": round(sum(r.seconds for r in records), 2), "evidence": evidence,
            "working_copy_changes": 0, "loaded": loaded}


def _start(job: ToolJob, name: str, case: Case, plans: list[RunPlan], groups: list[dict],
           label: Callable[[RunPlan | dict], str], after: Callable[[ToolJob], None]) -> ToolJob:
    """Run a job's steps (run_and_load) in a background thread, for the page to follow; `after` runs once they're done,
    also when a fault stops the job partway (_finish)."""
    def started(step):
        job.current = label(step)

    def finished(step, records):
        job.results.append(_step_result(job.current, step, records))
        job.done += 1

    def work():
        try:
            job.error = run_and_load(case, plans, groups, started, finished)
        except Exception as exc:   # noqa: BLE001  (report any failure on the page rather than losing it in a thread)
            job.error = f"{type(exc).__name__}: {exc}"
        finally:
            _finish(job, after)

    threading.Thread(target=work, name=name, daemon=True).start()
    return job


def _finish(job: ToolJob, after: Callable[[ToolJob], None]) -> None:
    """End a job: `after` brings the derived tables up to date with the loads that committed, also when a fault
    stopped the job partway, and the page sees it finished."""
    try:
        after(job)
    except Exception as exc:   # noqa: BLE001  (report any failure on the page rather than losing it in a thread)
        job.error = job.error or f"{type(exc).__name__}: {exc}"
    finally:
        job.current = ""
        job.finished = True


@dataclass
class ToolJob:
    """One tool running on its hosts, in a background thread, for the page to follow. `kind` is what its steps are:
    a tool's runs ("run"), loads of found output ("load"), or both, for Run and load everything ready ("all")."""
    tool: str
    total: int
    kind: str = "run"
    done: int = 0
    current: str = ""
    results: list[dict] = field(default_factory=list)
    finished: bool = False
    error: str = ""

    def state(self) -> dict:
        return {"tool": self.tool, "total": self.total, "kind": self.kind, "done": self.done, "current": self.current,
                "results": list(self.results), "finished": self.finished, "error": self.error}


def start_job(case: Case, tool: DetectedTool, hosts: list[str] | None, after: Callable[[ToolJob], None]) -> ToolJob:
    """Plan and start a tool's runs; `after` runs once they're done, such as rebuilding derived tables."""
    plans = plan_runs(case, tool, hosts)
    if not plans:
        raise RunError(f"{tool.spec.name} has nothing to read in this case.")
    return _start(ToolJob(tool.spec.name, len(plans)), f"tool-{tool.spec.id}", case, plans, [], _step_host, after)
