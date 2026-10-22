"""The start page: what Glessner shows when no case is open. Recent cases, opening a
case folder, a new case with a check of the folders as they're chosen, and copying a case for a clean pass.

Recent cases live in the user's settings folder (APPDATA\\glessner\\recent.json on Windows, or the folder
GLESSNER_CONFIG_DIR names), never in a case. Creating, taking in, and copying run as one background job at a time,
which the page follows.
"""

from __future__ import annotations

import contextlib
import ctypes
import json
import os
import re
import string
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from .case import Case, CaseError, copy_case, create_case, open_case, tools_folder_problem, write_atomically
from .events import connect
from .intake import entry_kind, intake, walk
from .long_paths import long_path
from .queries import timeline_count
from .rekey import upgraded_copy
from .runner import LEFT_OUT, rebuild
from .tools import _executables_under, _match, load_registry

MAX_RECENT = 20
CHECK_SECONDS = 5      # an evidence folder check stops counting after this long and says so
MAX_FOLDERS = 500      # folders listed at once by the folder browser
# GetDriveTypeW's answers for a drive letter with no root folder and for a mapped network drive
DRIVE_NO_ROOT_DIR = 1
DRIVE_REMOTE = 4
# Several copies of one collection in the evidence folder. A dataset folder whose collection, triage, and triage_more
# folders each hold WIN-L0ZZQ76PMUF's folder brings the one host in three times, once per top-level folder. A subfolder
# is a host's when it holds a volume's Windows
# or Users folder, or a drive letter that does, as KAPE's target output does (HOST\C\Windows); a name that two or more
# top-level folders hold that way is one host in several copies. A folder per host never matches, since there the
# shared names are the volume's own folders; nor do KAPE's HOST\tout\C or HOST\Modules\EventLogs.
VOLUME_FOLDERS = ("Windows", "Users")
VOLUME_NAMES = {v.lower() for v in VOLUME_FOLDERS}
DRIVE_LETTER = re.compile(r"^[a-z]$", re.IGNORECASE)
# A computer name's characters, with any DNS labels after it, so names no computer has, such as [root] or C%3A, are
# left out.
COMPUTER_NAME = re.compile(r"^[a-z0-9_-]+(?:\.[a-z0-9_-]+)*$", re.IGNORECASE)
# Names that hold a volume's Windows or Users without being a host: a drive letter, KAPE's target output folder,
# Windows.old, a shadow copy's folder such as VSS1, and the usual names of a mounted volume or partition. A folder per
# host with DC01\vol1\Windows and WS01\vol1\Windows would otherwise warn of vol1 as a host.
NOT_A_HOST = re.compile(r"^(?:[a-z]|[a-z]_drive|drive_[a-z]|tout|windows\.old|vss\d+|vol(?:ume)?\d*|p\d+"
                        r"|part(?:ition)?\d+|root|mnt|mount)$", re.IGNORECASE)
# The copies warning gives up after this long, inside the check's CHECK_SECONDS, so a folder of thousands of top-level
# folders still gets its check in time: without a limit, C:\Windows\WinSxS's 27,184 took 3.4 to 5.8 s on their own.
COPIES_SECONDS = 1


def config_dir() -> Path:
    # TW_CONFIG_DIR is the variable's former name, still honored so a scratch run never lands in the analyst's own list.
    for name in ("GLESSNER_CONFIG_DIR", "TW_CONFIG_DIR"):
        if os.environ.get(name):
            return Path(os.environ[name])
    return _settings_root("glessner")


def _settings_root(name: str) -> Path:
    base = os.environ.get("APPDATA")
    return Path(base) / name if base else Path.home() / f".{name}"


def adopt_old_recent(new: Path, old: Path) -> bool:
    """Copy the recent-cases list from the settings folder of the app's former name, once, when the
    new folder has none. A copy, so a build under the former name still finds its own. The copy is linked into place
    only while no recent.json exists, so a list remember() writes meanwhile is never replaced."""
    target = new / "recent.json"
    if target.exists() or not (old / "recent.json").is_file():
        return False
    tmp = new / f"recent.json.adopt-{os.getpid()}-{threading.get_ident()}"
    try:
        data = (old / "recent.json").read_bytes()
        new.mkdir(parents=True, exist_ok=True)
        tmp.write_bytes(data)
        os.link(tmp, target)
    except OSError:   # FileExistsError among them: a list is there now
        return False
    finally:
        with contextlib.suppress(OSError):
            tmp.unlink()
    return True


def load_recent(strict: bool = False) -> list[dict]:
    """The recent cases, newest first; none when the list is missing or unreadable. On Windows a read is refused while
    another process replaces the file (PermissionError), which the start page takes as no list. With `strict` the
    refusal is raised instead, for remember, which writes the list back: an empty list read in its place would be
    written over the whole list."""
    if not (os.environ.get("GLESSNER_CONFIG_DIR") or os.environ.get("TW_CONFIG_DIR")):
        adopt_old_recent(config_dir(), _settings_root("triage-workbench"))
    try:
        data = json.loads((config_dir() / "recent.json").read_text(encoding="utf-8"))
    except PermissionError:
        if strict:
            raise
        return []
    except (OSError, ValueError):
        return []
    out = [{**r, "exists": (Path(r["folder"]) / "case.yaml").is_file()}
           for r in (data if isinstance(data, list) else []) if isinstance(r, dict) and r.get("folder")]
    return out[:MAX_RECENT]


def remember(case: Case, events: int) -> None:
    """Put the case first in the recent list. The list is bookkeeping with several writers, and a lost update is
    accepted; a list another process holds is not written over as empty: the PermissionError of that read, or of the
    replace, is raised and the old list stays, for the caller to report (App.remember, start_copy)."""
    folder = config_dir()
    folder.mkdir(parents=True, exist_ok=True)
    items = [r for r in load_recent(strict=True) if Path(r["folder"]) != case.folder]
    items.insert(0, {"folder": str(case.folder), "name": case.settings.name, "events": events,
                     "evidence": case.settings.evidence_path, "tools_folder": case.settings.tools_folder,
                     "opened_utc": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")})
    for r in items:
        r.pop("exists", None)
    write_atomically(folder / "recent.json", json.dumps(items[:MAX_RECENT], indent=2), shared=True)   # several writers


def forget_missing(folder: str = "") -> tuple[int, list[dict]]:
    """Take cases whose folder is gone off the recent list: the one at `folder`, or every one
    when no folder is named. A case whose case.yaml is there stays, so a page drawn before its drive came back can't take
    it off. Only recent.json changes; no case folder is written. Returns how many came off and the list as it is now,
    as load_recent gives it, so the page needs no second read, which Windows can refuse. A list another process holds
    raises PermissionError, as remember's read does, so the old list stays."""
    items = load_recent(strict=True)
    keep = [r for r in items if r["exists"] or (folder and Path(r["folder"]) != Path(folder))]
    if len(keep) < len(items):
        written = [{k: v for k, v in r.items() if k != "exists"} for r in keep]
        write_atomically(config_dir() / "recent.json", json.dumps(written, indent=2), shared=True)   # several writers
    return len(items) - len(keep), keep


def _drive_letters() -> list[str]:
    """The letters of the drives Windows has set, read from the bitmask GetLogicalDrives returns (bit 0 is A:)."""
    mask = ctypes.windll.kernel32.GetLogicalDrives()
    return [letter for bit, letter in enumerate(string.ascii_uppercase) if (mask >> bit) & 1]


def _drive_type(root: str) -> int:
    """GetDriveTypeW's answer for a drive root such as "C:\\". It reads the drive's type and opens no folder on it."""
    return ctypes.windll.kernel32.GetDriveTypeW(root)


def local_drives() -> list[str]:
    """The roots of the drives in this computer, such as "C:\\", each one a folder that opens. A mapped network drive and
    a letter with no root folder are skipped by their drive type before any folder is opened, so no share is touched."""
    roots = [f"{letter}:\\" for letter in _drive_letters()]
    local = [root for root in roots if _drive_type(root) not in (DRIVE_NO_ROOT_DIR, DRIVE_REMOTE)]
    return [root for root in local if os.path.isdir(root)]


def _network_path(text: str) -> bool:
    r"""Whether a path, on Windows, is on a network share. It reads the text and the drive's type and opens nothing.

    Forward slashes are read as backslashes. A path that starts with two backslashes is on a share: a UNC path
    (\\server\share), or a \\?\UNC\ or \\.\ device path. So is a path that starts with \??\, the NT object-namespace
    prefix, which Windows passes through as it is (\??\UNC\server\share, \??\GLOBALROOT\Device\Mup\server\share). The
    \\?\C:\ and \??\C:\ forms of a local drive are refused along with them, since Browse never produces them. A path
    with a drive letter is on a share when that drive is a mapped network drive, and a path with none is on the
    working directory's drive. On other platforms no path is."""
    if sys.platform != "win32":
        return False
    text = text.replace("/", "\\")
    if text.startswith(("\\\\", "\\??\\")):
        return True
    drive = os.path.splitdrive(text)[0] or os.path.splitdrive(os.getcwd())[0]
    if drive.startswith("\\\\"):  # a working directory on a share
        return True
    return len(drive) == 2 and drive[1] == ":" and _drive_type(f"{drive[0].upper()}:\\") == DRIVE_REMOTE


def _through_link(path: Path) -> bool:
    """Whether a folder on the way to `path`, from its drive's root down, is a symbolic link. Windows follows a link on
    a local drive to a share, so a link can lead off this computer. Each folder is asked about in turn and the walk
    stops at the first link, so nothing past a link is touched; asking about a link reads the link itself, on its own
    volume. `path` must already be known to be on a local drive, since asking about a folder on a share would reach it.
    On other platforms no path is."""
    if sys.platform != "win32":
        return False
    absolute = Path(os.path.abspath(path))
    return any(os.path.islink(folder) for folder in (*reversed(absolute.parents), absolute))


def _unlisted(path: Path, message: str) -> dict:
    return {"path": str(path), "parent": None, "folders": [], "message": message}


def browse(path: str) -> dict:
    """The folders inside a folder, for picking one; with no path, the drives in this computer. Browse opens only
    folders on this computer. A UNC or device path, a path on a mapped drive, and a path that passes through a symbolic
    link, which can point at a share, list nothing and say so. check() still opens the paths typed into the start
    page's folder fields, a share included."""
    if not path:
        if sys.platform == "win32":
            return {"path": "", "parent": None, "folders": local_drives(), "message": ""}
        path = "/"
    p = Path(path).expanduser()  # the checks below run on the expanded path, since a home folder can sit on a share
    if _network_path(str(p)):
        return _unlisted(p, "Browse doesn't open network folders. Type the folder's path instead.")
    if _through_link(p):
        return _unlisted(p, "Browse doesn't open folders through a link. Type the folder's path instead.")
    if not p.is_dir():
        return _unlisted(p, "Folder not found.")
    try:
        folders = sorted((e.name for e in os.scandir(p) if e.is_dir(follow_symlinks=False)), key=str.lower)
        message = ""
    except PermissionError:
        folders, message = [], "This folder can't be read."
    parent = str(p.parent) if p.parent != p else ""
    return {"path": str(p), "parent": parent, "folders": folders[:MAX_FOLDERS],
            "message": message or (f"Showing the first {MAX_FOLDERS}." if len(folders) > MAX_FOLDERS else "")}


def check(evidence: str = "", case_folder: str = "", tools: str = "") -> dict:
    """What the chosen folders hold, in words the start page shows beside them."""
    out = {}
    ev = Path(evidence).expanduser() if evidence else None
    if ev is not None:
        if not ev.is_dir():
            out["evidence"] = {"ok": False, "message": "Folder not found."}
        else:
            hosts, root_files = [], 0
            for e in sorted(os.scandir(ev), key=lambda e: e.name.lower()):
                kind = entry_kind(e)   # a link is neither: intake skips it
                if kind == "folder":
                    hosts.append(e.name)
                elif kind == "file":
                    root_files += 1
            # The copies warning first, with a time limit of its own, so the count's CHECK_SECONDS covers both.
            t0 = time.monotonic()
            warning = copies_warning(ev, hosts, t0 + COPIES_SECONDS)
            files, size, partial, links = 0, 0, False, []
            base, deadline = long_path(ev), t0 + CHECK_SECONDS
            # The time is checked before each file and after each folder, so a run of folders with no files stops too
            for dirpath, filenames in walk(ev, links):   # as intake walks it, links skipped and listed
                folder = Path(dirpath).relative_to(ev)
                for name in filenames:
                    if time.monotonic() > deadline:
                        break
                    files += 1
                    with contextlib.suppress(OSError):
                        size += long_path(base, (folder / name).as_posix()).stat().st_size
                if time.monotonic() > deadline:
                    partial = True
                    break
            if files:
                message = ""
            elif partial:
                message = "The count stopped at its time limit before it reached a file, so the folder may still hold files."
            else:
                message = "The folder holds no files."
            out["evidence"] = {"ok": files > 0, "files": files, "bytes": size, "partial": partial, "hosts": hosts,
                               "root_files": root_files, "message": message, "warning": warning, "links": links}
    if case_folder:
        cf = Path(case_folder).expanduser()
        problem = ""
        if cf.exists() and (not cf.is_dir() or any(cf.iterdir())):
            problem = "It already exists and isn't empty. Choose a new folder."
        elif ev is not None and ev.is_dir():
            a, b = cf.resolve(), ev.resolve()
            if a == b or a.is_relative_to(b) or b.is_relative_to(a):
                problem = "The case folder and the evidence folder can't contain each other."
        out["case_folder"] = {"ok": not problem,
                              "message": problem or ("A new folder." if not cf.exists() else "An empty folder.")}
    if tools:
        tf = Path(tools).expanduser()
        # Refused before it's opened: a network folder, or one that holds the evidence or the case
        problem = tools_folder_problem(tf, ev, Path(case_folder).expanduser() if case_folder else None)
        if problem or not tf.is_dir():
            out["tools"] = {"ok": False, "message": problem or "Folder not found."}
        else:
            specs = load_registry()
            candidates = _executables_under(tf)
            # Each tool's executable as detection would choose it, so the analyst sees which file would run.
            paths = {s.name: path for s in specs.values() if not s.builtin and (path := _match(s, candidates))}
            # A built-in reader is always there; the Tools page counts it as found too.
            found = len(paths) + sum(1 for s in specs.values() if s.builtin)
            out["tools"] = {"ok": True, "found": found, "total": len(specs),
                            "message": f"{found} of {len(specs)} registry tools found.",
                            "executables": [{"tool": name, "path": str(path)} for name, path in paths.items()]}
    return out


def copies_warning(ev: Path, tops: list[str], deadline: float = float("inf")) -> str:
    """A warning, shown under the evidence check but not blocking the case, when top-level folders hold copies of one
    host's folder; '' otherwise, or when time.monotonic() passes `deadline` first. Folder names only: no
    file is opened."""
    if _holds_volume(ev, tops):
        return ""   # the evidence folder is one host's own, such as a mounted image: its folders aren't hosts
    holders: dict[str, list[tuple[str, str]]] = {}   # a subfolder's name in lower case: (top-level folder, name)
    for top in tops:
        if time.monotonic() > deadline:
            return ""
        names = _folders(ev / top)
        if _holds_volume(ev / top, names):
            continue   # a host's own folder, as in a folder per host: what it holds are its volume's folders
        for name in names:
            if COMPUTER_NAME.match(name) and not NOT_A_HOST.match(name):
                holders.setdefault(name.lower(), []).append((top, name))
    copies = []
    for places in holders.values():
        if len(places) < 2:
            continue
        if time.monotonic() > deadline:
            return ""
        hosts = [(top, name) for top, name in places if _holds_volume(ev / top / name, _folders(ev / top / name))]
        if len(hosts) >= 2:
            copies.append(hosts)
    if not copies:
        return ""
    # The host with the most copies, then the first by name, as the example; its folders in the check's own order.
    places = min(copies, key=lambda p: (-len(p), p[0][1].lower()))
    folders = [top for top, _ in places]
    if len(folders) > 3:
        more = len(folders) - 3
        folders = folders[:3] + [f"{more} more folder{'s' if more > 1 else ''}"]
    listed = " and ".join(folders) if len(folders) == 2 else f"{', '.join(folders[:-1])}, and {folders[-1]}"
    return (f"{listed} each hold a host folder of their own, such as {places[0][1]}. "
            "Choose the folder that holds one copy of each host.")


def _folders(path: Path) -> list[str]:
    try:
        return [e.name for e in os.scandir(path) if e.is_dir(follow_symlinks=False)]
    except OSError:
        return []


def _holds_volume(path: Path, names: list[str]) -> bool:
    """Whether a folder, given its subfolders' names, holds a volume's Windows or Users folder, or a drive letter that
    does, as KAPE's target output does (HOST\\C\\Windows). Counting the drive letter, not only a host's own
    Windows and Users, lets two copies of a KAPE collection draw the warning."""
    if any(n.lower() in VOLUME_NAMES for n in names):
        return True
    return any(DRIVE_LETTER.match(n) and os.path.isdir(path / n / v) for n in names for v in VOLUME_FOLDERS)


@dataclass
class StartJob:
    """A case being created and taken in, or copied, in a background thread."""
    kind: str             # "new", "copy", or "open"
    case_folder: str
    name: str
    stage: str = ""
    done: int = 0
    total: int = 0
    finished: bool = False
    error: str = ""
    opened: bool = False
    result: dict = field(default_factory=dict)

    def state(self) -> dict:
        return {k: getattr(self, k) for k in ("kind", "case_folder", "name", "stage", "done", "total", "finished",
                                              "error", "opened", "result")}

    def progress(self, done: int, total: int) -> None:
        """For intake and rebuild to report how far they are."""
        self.done, self.total = done, total

    def report(self, stage: str, done: int = 0, total: int = 0) -> None:
        """For a case open: the stage it is in, with how far it is when it counts (case.upgrade's report)."""
        self.stage = stage
        self.done, self.total = done, total


def _run(job: StartJob, work: Callable[[], None]) -> StartJob:
    def target():
        try:
            work()
        except Exception as exc:   # noqa: BLE001  (report any failure on the page rather than losing it in a thread)
            job.error = str(exc) if isinstance(exc, (CaseError, ValueError, OSError)) else f"{type(exc).__name__}: {exc}"
        finally:
            job.finished = True
    threading.Thread(target=target, name=f"start-{job.kind}", daemon=True).start()
    return job


def start_new_case(body: dict, analyst: str, open_case_fn: Callable[[Case], None]) -> StartJob:
    """Create the case now, so its errors come back at once; take the evidence in, and open the case, in the background."""
    name = str(body.get("name") or "").strip()
    if not name:
        raise ValueError("Name the case.")
    evidence = Path(str(body.get("evidence") or "")).expanduser()
    folder = Path(str(body.get("case_folder") or "")).expanduser()
    tools = str(body.get("tools") or "").strip()
    case = create_case(folder, name, evidence, analyst, Path(tools) if tools else None,
                       str(body.get("host") or "").strip(), client="server")
    job = StartJob("new", str(case.folder), name, stage="Taking in the evidence")

    def work():
        summary = intake(case, job.progress)
        job.result = {"files": summary.files, "bytes": summary.total_bytes, "by_artifact": summary.by_artifact,
                      "unidentified": len(summary.unidentified), "errors": summary.errors, "links": summary.links}
        job.stage = "Opening the case"
        open_case_fn(case)
        job.opened = True
    return _run(job, work)


def start_open_case(case: Case, open_case_fn: Callable[..., Case]) -> StartJob:
    """Open a case as a job, so the page can follow a long open: the format upgrade of a case from an older
    build takes about 20 s on a million events, and runs inside the open. The caller has read the case's folder, so its
    errors come back at once (server.start_open). The job's stage is "Opening", then each stage the upgrade reports
    (case.report_stage), then "Opening" again, and it ends with `opened` true and the case's name in result["opened"].
    A case with nothing to upgrade reports "Opening" alone."""
    job = StartJob("open", str(case.folder), case.settings.name, stage="Opening")

    def work():
        open_case_fn(case, job.report)
        job.result = {"opened": case.settings.name}
        job.opened = True
    return _run(job, work)


def start_copy(body: dict, analyst: str) -> StartJob:
    source = open_case(Path(str(body.get("source") or "")))
    folder = Path(str(body.get("case_folder") or "")).expanduser()
    name = str(body.get("name") or "").strip() or f"{source.settings.name} (copy)"
    problem = check(evidence=source.settings.evidence_path, case_folder=str(folder))["case_folder"]
    target = folder.resolve()
    if not problem["ok"] or target == source.folder or target.is_relative_to(source.folder):
        raise CaseError(problem["message"] if not problem["ok"] else "The copy can't go inside the case it copies.")
    job = StartJob("copy", str(folder), name, stage="Copying the case")

    def work():
        case = copy_case(source, folder, name, analyst, client="server")
        job.case_folder = str(case.folder)
        # A copy of an older case keeps its format, with no events and an empty journal, so its upgrade records what
        # changed and seals the journal before its rebuild loads under this build's rules, and case_created follows.
        case = upgraded_copy(case, source, "server")
        job.stage = "Loading the events from the copied runs"
        left_out = []

        def note(record, text: str) -> None:   # a run whose output or evidence changed since it ran
            if LEFT_OUT in text:
                left_out.append(f"{record.run_id}: {text}")

        loaded = rebuild(case, job.progress, report=note)
        # The page names the runs left out
        job.result = {"runs": len(loaded), "left_out": left_out}
        with contextlib.closing(connect(case.db_path, read_only=True)) as con:
            events = timeline_count(con)   # the timeline's events, not every row loaded
        try:
            remember(case, events)
        except OSError as exc:   # the list is the start page's bookkeeping: a finished copy is no failure
            print(f"Recent cases not updated: {exc}", file=sys.stderr)   # for the console `serve` runs in, as App.remember
    return _run(job, work)
