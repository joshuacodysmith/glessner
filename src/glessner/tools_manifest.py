"""The tools manifest: tools_manifest.json at the top of a tools folder, in which an analyst pins the SHA-256 of the files
each tool reads from its own folder, so that a later run can say whether the tool's files are the ones that were pinned.

A pin is the analyst's statement of what was in the folder when they made it; it doesn't say where the files came from. The
check of a run (check_tool) compares the files the run hashed with the tool's pin and never refuses a run. The Tools page's
states (pin_states) compare the files as last hashed (PinCache) with the pin."""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import time
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager, suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, NamedTuple

from . import tools
from .case import write_atomically
from .tools import DetectedTool, ToolListing, ToolSpec, in_folder
from .version import build_id

if TYPE_CHECKING:
    from .runner import RunRecord

try:
    import msvcrt
except ImportError:   # off Windows, which the app doesn't target: fcntl locks the same byte
    msvcrt = None
    import fcntl

MANIFEST_FILE = "tools_manifest.json"
LOCK_FILE = "tools_manifest.lock"
FORMAT = 1
LOCK_WAIT = 10.0   # seconds a pin waits for another pin of the folder, in this process or another
LOCK_RETRY = 0.05
MAX_NAMED = 20     # the differing paths a run's check, and the Tools page's fold of a folder, name
BUSY = "Another Glessner window is pinning tools in this folder. Try again."
NO_FOLDER = "Pinning needs a tools folder, and this case has none set."
ENTRY_KEYS = ("executable", "files", "folders", "links", "pinned_by", "pinned_utc", "rules", "version")
HEX64 = re.compile(r"[0-9a-f]{64}")
STATE_WORDS = ("changed", "missing", "added")
LABELS = {   # the Tools page's badge for each state: its words and its tone (ok, warn, or muted)
    "matches": ("Matches pin", "ok"), "differs": ("Differs from pin", "warn"), "not_pinned": ("Not pinned", "muted"),
    "unreadable": ("Pins unreadable", "warn"), "cant_check": ("Can't check", "warn"),
    "no_folder": ("No tools folder", "muted"), "outside": ("Outside the tools folder", "muted")}
# The words for each result check_tool records, as a cell of the report's Method table: the Tools page's badge words where
# it has them, and plain words for a tools folder with no manifest
RESULT_WORDS = {"matches": LABELS["matches"][0], "differs": LABELS["differs"][0], "not pinned": LABELS["not_pinned"][0],
                "unreadable": LABELS["unreadable"][0], "no manifest": "No manifest"}
UNKNOWN_RESULT = "Unknown"
# The part of the Tool check line, in the report and the Case overview, that says what a run's record keeps of a difference
RECORD_PATHS = f"Each run's record names up to {MAX_NAMED} of the paths that differed."


class ManifestError(ValueError):
    """A manifest that can't be read, with the SHA-256 of its bytes when they were read (`sha256`, "" when not)."""

    def __init__(self, message: str, sha256: str = ""):
        super().__init__(message)
        self.sha256 = sha256


class Manifest(NamedTuple):
    path: Path
    sha256: str            # of the file's bytes
    tools: dict[str, dict]  # the entries, by registry tool ID


class Pin(NamedTuple):
    """A tool's files as they were read, to be pinned: `links` as tools.tool_listing collects them."""
    tool: DetectedTool
    listing: ToolListing
    links: tuple[str, ...]


def manifest_file(folder: Path) -> Path:
    return folder / MANIFEST_FILE


def utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------- Reading ----------

def read_manifest(path: Path) -> Manifest | None:
    """The manifest at `path`, or None when there is no file. ManifestError, naming what is wrong, when the file can't be
    opened, isn't JSON, names a format this build doesn't read, holds a key it doesn't know or lacks one, or holds a hash
    that isn't 64 lowercase hex digits."""
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ManifestError(f"{path} can't be opened: {exc.strerror or exc}") from exc
    digest = hashlib.sha256(data).hexdigest()
    try:
        found = json.loads(data.decode("utf-8"))
    except ValueError as exc:   # a UnicodeDecodeError and a JSONDecodeError both
        raise ManifestError(f"it isn't JSON ({exc})", digest) from exc
    except RecursionError as exc:
        raise ManifestError("it is nested too deeply to read", digest) from exc
    if not isinstance(found, dict):
        raise ManifestError("it isn't a JSON object", digest)
    if "format" not in found:
        raise ManifestError("it has no format", digest)
    if type(found["format"]) is not int or found["format"] != FORMAT:   # not true or 1.0, which equal 1
        raise ManifestError(f"its format is {found['format']!r}, which this build doesn't read (it reads {FORMAT})", digest)
    if unknown := sorted(set(found) - {"format", "tools"}):
        raise ManifestError(f"it has a key it doesn't know: {unknown[0]!r}", digest)
    if not isinstance(found.get("tools"), dict):
        raise ManifestError("its 'tools' isn't an object", digest)
    for tool_id, entry in found["tools"].items():
        try:
            _check_entry(tool_id, entry)
        except ManifestError as exc:
            raise ManifestError(str(exc), digest) from exc
    return Manifest(path, digest, found["tools"])


def _check_entry(tool_id: str, entry: object) -> None:
    if not isinstance(entry, dict):
        raise ManifestError(f"{tool_id}'s entry isn't an object")
    if unknown := sorted(set(entry) - set(ENTRY_KEYS)):
        raise ManifestError(f"{tool_id} has a key it doesn't know: {unknown[0]!r}")
    if missing := [key for key in ENTRY_KEYS if key not in entry]:
        raise ManifestError(f"{tool_id} has no {missing[0]!r}")
    for key in ("executable", "pinned_by", "pinned_utc", "rules", "version"):
        if not isinstance(entry[key], str):
            raise ManifestError(f"{tool_id}'s {key} isn't text")
    if not isinstance(entry["files"], dict):
        raise ManifestError(f"{tool_id}'s files isn't an object of hashes")
    _check_hashes(tool_id, "files", entry["files"])
    if not isinstance(entry["folders"], dict) or not all(isinstance(v, dict) for v in entry["folders"].values()):
        raise ManifestError(f"{tool_id}'s folders isn't an object of listings")
    for listing in entry["folders"].values():
        _check_hashes(tool_id, "folders", listing)
    if not isinstance(entry["links"], list) or not all(isinstance(link, str) for link in entry["links"]):
        raise ManifestError(f"{tool_id}'s links isn't a list of text")


def _check_hashes(tool_id: str, where: str, hashes: dict) -> None:
    for name, value in hashes.items():
        if not (isinstance(value, str) and HEX64.fullmatch(value)):
            raise ManifestError(f"the hash for {name!r} in {tool_id} isn't 64 lowercase hex digits")


def refusal(path: Path, reason: object) -> str:
    """What a pin says of a manifest it can't read, with what to do."""
    return f"The tools manifest at {path} can't be read: {str(reason).rstrip('.')}. Restore it, or delete it and pin again."


# ---------- The check of a run ----------

def check_tool(folder: Path | None, tool: DetectedTool, listing: ToolListing, links: list[str]) -> dict:
    """What a run records as its tool_check: the files it hashed (`listing`, with `links` as tool_listing collected them)
    against the tool's entry in the manifest of the tools folder `folder`, which is None when the case has none.
    Never raises. `result` is matches; differs, with up to MAX_NAMED differing paths in `files` (each path, its state,
    and the pinned and present hashes) and how many more in `more`; not pinned; no manifest; or unreadable. The
    others are the SHA-256 of the manifest's bytes when they were read, the pin's time, version, and build for matches
    and differs, and `reason` where one says why."""
    if folder is None:
        return {"result": "no manifest", "reason": "no tools folder is set"}
    path = manifest_file(folder)
    try:
        manifest = read_manifest(path)
    except ManifestError as exc:
        check = {"result": "unreadable"}
        if exc.sha256:
            check["manifest_sha256"] = exc.sha256
        return {**check, "reason": str(exc)}
    except OSError as exc:
        return {"result": "unreadable", "reason": f"{path} can't be opened: {exc.strerror or exc}"}
    if manifest is None:
        return {"result": "no manifest", "reason": f"the tools folder has no {MANIFEST_FILE}"}
    entry = manifest.tools.get(tool.spec.id)
    if entry is None:
        check = {"result": "not pinned", "manifest_sha256": manifest.sha256}
        if not in_folder(tool.executable, folder):
            check["reason"] = "the tool runs from outside the tools folder"
        return check
    named = {"manifest_sha256": manifest.sha256, "pinned_utc": entry["pinned_utc"], "pinned_version": entry["version"],
             "pinned_by": entry["pinned_by"]}
    differing = differences(entry, listing, links)
    if not differing:
        return {"result": "matches", **named}
    check = {"result": "differs", **named, "files": differing[:MAX_NAMED]}
    if len(differing) > MAX_NAMED:
        check["more"] = len(differing) - MAX_NAMED
    return check


def differences(entry: dict, listing: ToolListing, links: list[str]) -> list[dict]:
    """Each path whose file, folder, or link isn't as the entry pinned it, in path order: its `state` (changed, missing, or
    added), the `pinned` and `now` hashes it has (a link's targets, with "link" true). A folder that differs is named by
    each of its files that differs, and one that is gone or new by its own path."""
    found = []
    for key in sorted(entry["files"].keys() | listing.hashes.keys()):
        pinned, now = entry["files"].get(key), listing.hashes.get(key)
        if pinned == now:
            continue
        if pinned is not None and now is not None and key.endswith("/") and key in entry["folders"] and key in listing.folders:
            found += _folder_differences(key, entry["folders"][key], listing.folders[key])
        else:
            found.append(_difference(key, pinned, now))
    found += [{**change, "link": True} for change in link_states(entry["links"], links) if change["state"] != "same"]
    return found


def _difference(path: str, pinned: str | None, now: str | None) -> dict:
    state = "added" if pinned is None else "missing" if now is None else "changed"
    return {"path": path, "state": state, **({"pinned": pinned} if pinned is not None else {}),
            **({"now": now} if now is not None else {})}


def _folder_differences(folder: str, pinned: dict[str, str], now: dict[str, str]) -> list[dict]:
    return [_difference(folder + rel, pinned.get(rel), now.get(rel))
            for rel in sorted(pinned.keys() | now.keys()) if pinned.get(rel) != now.get(rel)]


def link_states(pinned: list[str], now: list[str]) -> list[dict]:
    """Each link of the pin and of the tool now, "path -> target", in path order, with its state: same, changed (the
    target differs), missing, or added, and the targets in `pinned` and `now`."""
    before, after = _targets(pinned), _targets(now)
    states = []
    for path in sorted(before.keys() | after.keys()):
        old, new = before.get(path), after.get(path)
        state = "same" if old == new else "added" if old is None else "missing" if new is None else "changed"
        states.append({"path": path, "state": state, **({"pinned": old} if old is not None else {}),
                       **({"now": new} if new is not None else {})})
    return states


def _targets(links: list[str]) -> dict[str, str]:
    return {path: target for path, _, target in (link.partition(" -> ") for link in links)}


def summary(files: list[dict], more: int = 0) -> str:
    """The differing paths of a check in a sentence: each path of the tool's own folder by its state, such as
    "EvtxECmd.exe changed", then each folder's count of paths by state, such as "1 changed, 1 missing, and 25 added in
    Maps/", and how many more the check didn't name."""
    loose, folders = [], {}
    for item in files:
        path = item["path"]
        if "/" not in path.rstrip("/"):
            loose.append(f"{path} {item['state']}")
        else:
            folders.setdefault(path.partition("/")[0] + "/", []).append(item["state"])
    parts = [*loose, *(f"{counts_text(states)} in {folder}" for folder, states in folders.items())]
    text = "; ".join(parts)
    return f"{text}; {more:,} more not listed" if more else text


def counts_text(states: list[str]) -> str:
    """How many of each state, such as "1 changed, 1 missing, and 25 added"."""
    return and_list([f"{states.count(state):,} {state}" for state in STATE_WORDS if state in states])


def and_list(items: list[str]) -> str:
    """Items in a sentence: "A", "A and B", or "A, B, and C"."""
    return " and ".join(items) if len(items) < 3 else f"{', '.join(items[:-1])}, and {items[-1]}"


def check_text(check: dict | None) -> str:
    """A run's tool check in words for the Tools page: its result, and for differs the paths that differ. A result this
    build doesn't know is shown as written, and a differs whose `files` or `more` aren't shaped as check_tool writes them
    (a list of dicts with a text path and a known state, and a whole number) is shown by its result alone."""
    if check is None:
        return "tool check not recorded"
    result = check.get("result", "unknown")
    files, more = check.get("files"), check.get("more", 0)
    if result == "differs" and _is_named(files, more):
        return f"tool check differs, {summary(files, more)}"
    return f"tool check {result}"


def _is_named(files: object, more: object) -> bool:
    """Whether `files` and `more` of a differs check can be put in words: at least one dict with a text path and a state
    of STATE_WORDS, and a whole number of others."""
    return (isinstance(files, list) and bool(files) and isinstance(more, int)
            and all(isinstance(f, dict) and isinstance(f.get("path"), str) and f.get("state") in STATE_WORDS for f in files))


def check_words(check: dict | None) -> str:
    """A run's tool check as a cell of the report's Method table: its result in RESULT_WORDS' words. A result this build
    doesn't know shows as written, and a check with no result, or one that isn't text, says Unknown. A run with no check
    (None) gives an empty cell."""
    if check is None:
        return ""
    result = check.get("result")
    if not isinstance(result, str) or not result:
        return UNKNOWN_RESULT
    return RESULT_WORDS.get(result, result)


def differing_tools(runs: Iterable[RunRecord], name_of: Callable[[str], str]) -> tuple[int, list[str]]:
    """How many run records say their tool's files differed from the pin, and the tools of those runs, each once, as
    `name_of` names a tool ID for the reader (escaped for where the name goes), sorted by name. Every such record counts,
    so a later run that matched doesn't hide an earlier one."""
    differing = [run.tool for run in runs if (run.tool_check or {}).get("result") == "differs"]
    return len(differing), sorted({name_of(tool) for tool in differing}, key=lambda name: (name.casefold(), name))


def differs_sentence(count: int, names: list[str], where: str) -> str:
    """Integrity's line about runs whose tools differed from their pins, from differing_tools' count and names, ending in
    `where`, the sentence that says where the reader sees the checks. "" when no run differed."""
    if not count:
        return ""
    return (f"{count:,} {'run' if count == 1 else 'runs'} used tool files that differed from the pin: "
            f"{and_list(names)}. {where}")


# ---------- Pinning ----------

def take_pin(tool: DetectedTool) -> Pin:
    """The tool's files as they are now (tools.pin_files). OSError when one can't be read."""
    links: list[str] = []
    listing = tools.pin_files(tool, links)
    return Pin(tool, listing, tuple(sorted(links)))


def pin_group(found: dict[str, DetectedTool], names: list[str]) -> list[str]:
    """The tool IDs that pinning `names` pins: each name, and each other tool that runs the same executable, such as
    MFTECmd under two IDs. Sorted."""
    executables = {found[name].executable for name in names}
    return sorted({tool_id for tool_id, tool in found.items() if tool.executable in executables} | set(names))


def pinnable(folder: Path | None, specs: dict[str, ToolSpec], found: dict[str, DetectedTool], names: list[str]) -> list[str]:
    """The tool IDs that pinning `names` pins (pin_group), or ValueError saying why a name can't be pinned: it names no
    registry tool, the case has no tools folder, the tool is built in or isn't installed, or it runs from outside the
    tools folder."""
    for name in names:
        if name not in specs:
            raise ValueError(f"No tool {name!r} in the registry.")
    if folder is None:
        raise ValueError(NO_FOLDER)
    for name in names:
        spec = specs[name]
        if spec.builtin:
            raise ValueError(f"{spec.name} is built in; it has no files in a tools folder to pin.")
        if name not in found:
            raise ValueError(f"{spec.name} isn't installed, so there is nothing to pin.")
        _check_inside(folder, found[name])
    return pin_group(found, names)


def unpinned(folder: Path | None, found: dict[str, DetectedTool]) -> list[str]:
    """The IDs of the tools in the tools folder that the manifest has no entry for, sorted. ValueError when there is no
    tools folder or the manifest can't be read."""
    if folder is None:
        raise ValueError(NO_FOLDER)
    manifest = readable_manifest(folder)
    have = manifest.tools if manifest else {}
    return sorted(i for i, tool in found.items() if not tool.spec.builtin and in_folder(tool.executable, folder)
                  and i not in have)


def _check_inside(folder: Path, tool: DetectedTool) -> None:
    if not in_folder(tool.executable, folder):
        raise ValueError(f"{tool.spec.name} runs from {tool.executable.parent}, outside the tools folder {folder}. "
                         "Move it into the tools folder to pin it.")


def readable_manifest(folder: Path) -> Manifest | None:
    """The manifest of the tools folder, or None when it has none. ValueError, saying what to do (refusal), when it can't
    be read: a pin doesn't replace what it can't read."""
    path = manifest_file(folder)
    try:
        return read_manifest(path)
    except ManifestError as exc:
        raise ValueError(refusal(path, exc)) from exc


def pin_tools(folder: Path, pins: dict[str, Pin]) -> Path:
    """Pin each tool of `pins`, by registry ID, in the manifest of the tools folder, and the path of the manifest. Under
    the manifest's lock (held), it reads the manifest, replaces the entries of these tools, and replaces the file whole
    (write_atomically), so a reader sees the old file or the new one and a pin made at the same time is kept.
    ValueError when a tool runs from outside the folder, when the manifest can't be read (it is not replaced), when
    another pin holds the lock for LOCK_WAIT seconds, or when the folder can't be written (the lock file can't be opened
    or the manifest can't be replaced), in which case the old manifest is as it was."""
    for pin in pins.values():
        _check_inside(folder, pin.tool)
    path = manifest_file(folder)
    try:
        with held(folder):
            manifest = readable_manifest(folder)
            pinned = dict(manifest.tools) if manifest else {}
            stamp = utc_now()
            for tool_id, pin in pins.items():
                pinned[tool_id] = _entry(folder, pin, stamp)
            text = json.dumps({"format": FORMAT, "tools": pinned}, indent=2, sort_keys=True) + "\n"
            write_atomically(path, text.encode("utf-8"), shared=True)
    except OSError as exc:
        raise ValueError(f"The tools manifest at {path} can't be written: {exc.strerror or exc}. Pinning needs a tools "
                         "folder this account can write to.") from exc
    return path


def _entry(folder: Path, pin: Pin, stamp: str) -> dict:
    tool, (hashes, folders), links = pin
    return {"executable": in_folder(tool.executable, folder), "files": dict(hashes),
            "folders": {key: dict(listing) for key, listing in folders.items()}, "links": list(links),
            "pinned_by": build_id(), "pinned_utc": stamp,
            "rules": tools.rules_label(tool.spec, tool.executable, hashes), "version": tool.version}


# The lock: one per process, for threads, and a byte of tools_manifest.lock beside the manifest, for other processes. The
# lock file is left in the folder.
_THREADS = threading.Lock()


@contextmanager
def held(folder: Path) -> Iterator[None]:
    """The manifest of the tools folder held for writing: the process's lock, then byte 0 of tools_manifest.lock, each
    waited for up to LOCK_WAIT seconds, then ValueError with BUSY."""
    if not _THREADS.acquire(timeout=LOCK_WAIT):
        raise ValueError(BUSY)
    try:
        fd = _take_os_lock(folder / LOCK_FILE)
        try:
            yield
        finally:
            _unlock(fd)
            os.close(fd)
    finally:
        _THREADS.release()


def _take_os_lock(path: Path) -> int:
    fd = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_BINARY", 0))
    deadline = time.monotonic() + LOCK_WAIT
    while not _try_lock(fd):
        if time.monotonic() >= deadline:
            os.close(fd)
            raise ValueError(BUSY)
        time.sleep(LOCK_RETRY)
    return fd


def _try_lock(fd: int) -> bool:
    """Whether one try locked byte 0. msvcrt.locking locks from the file's position, so the try seeks to it first."""
    os.lseek(fd, 0, os.SEEK_SET)
    try:
        if msvcrt is not None:
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        else:
            fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB, 1, 0)
    except OSError:
        return False
    return True


def _unlock(fd: int) -> None:
    with suppress(OSError):
        os.lseek(fd, 0, os.SEEK_SET)
        if msvcrt is not None:
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        else:
            fcntl.lockf(fd, fcntl.LOCK_UN, 1, 0)


# ---------- What the Tools page shows ----------

class Taken(NamedTuple):
    """A tool's files as hashed for the page: its executable, when, and either the listing and links or the error."""
    executable: str
    taken: str
    listing: ToolListing
    links: tuple[str, ...]
    error: str


def _take(tool: DetectedTool) -> Taken:
    try:
        pin = take_pin(tool)
    except OSError as exc:
        return Taken(str(tool.executable), utc_now(), ToolListing({}, {}), (), str(exc))
    return Taken(str(tool.executable), utc_now(), pin.listing, pin.links, "")


class PinCache:
    """The files of each found tool as last hashed for the Tools page, by tool ID, so the page compares them with the
    manifest without hashing each time it is drawn. Filled by the page alone (get); dropped for the tools a job ran, since
    its run may have changed what the tool reads, and cleared by a scan. A hash taken while an entry was dropped is not
    kept, so it can't bring back what the drop removed."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._items: dict[str, Taken] = {}
        self._generation = 0

    def __len__(self) -> int:
        return len(self._items)

    def get(self, tool: DetectedTool) -> Taken:
        """The tool's files as hashed for the page: the kept ones, or hashed now (and kept) when it has none or a different
        executable."""
        tool_id = tool.spec.id
        with self._lock:
            kept = self._items.get(tool_id)
            if kept is not None and kept.executable == str(tool.executable):
                return kept
            generation = self._generation
        taken = _take(tool)   # outside the lock: a folder of thousands of files takes seconds
        with self._lock:
            if generation == self._generation:
                self._items[tool_id] = taken
        return taken

    def put(self, tool: DetectedTool, pin: Pin) -> None:
        """Keep the files of a pin just made as the tool's."""
        taken = Taken(str(tool.executable), utc_now(), pin.listing, pin.links, "")
        with self._lock:
            self._items[tool.spec.id] = taken

    def drop(self, tool_ids: list[str]) -> None:
        with self._lock:
            self._generation += 1
            for tool_id in tool_ids:
                self._items.pop(tool_id, None)

    def clear(self) -> None:
        with self._lock:
            self._generation += 1
            self._items.clear()


def pin_states(folder: Path | None, found: dict[str, DetectedTool], cache: PinCache) -> tuple[dict[str, dict], dict]:
    """The pin state of each found tool that has files in a tools folder, by registry ID (a builtin tool has none), and
    the manifest's own: its path, state (absent, read, unreadable, or no_folder), the SHA-256 of its bytes, why it can't
    be read, how many tools are in each state, a sentence of those counts, when the oldest of the files were hashed, and
    the tools a bare pin would pin (`unpinned`). Each tool's state holds its `state` (matches, differs, not_pinned,
    unreadable, cant_check, no_folder, or outside), the badge's `label` and `tone`, a `hint` for its hover, what a pin
    would take (`executable`, `files`, `links`, and the tools pinned together, `group`), and for a tool that has a pin the
    pin's time, build, version, and rules (`pinned`), `changes` (a sentence, for differs), and the fold's `rows` and
    `link_rows`. The files are hashed through `cache`; one that can't be read gives that tool cant_check, with
    the reason."""
    candidates = {i: t for i, t in found.items() if not t.spec.builtin}
    if folder is None:
        states = {i: _plain("no_folder", t, NO_FOLDER) for i, t in candidates.items()}
        return states, {"path": "", "state": "no_folder", "sha256": "", "reason": "", "text": "", "checked": utc_now(),
                        "counts": _counts([]), "unpinned": []}
    path = manifest_file(folder)
    manifest, reason, digest, status = None, "", "", "absent"
    try:
        manifest = read_manifest(path)
        status = "read" if manifest else "absent"
        digest = manifest.sha256 if manifest else ""
    except ManifestError as exc:
        status, reason, digest = "unreadable", str(exc), exc.sha256
    except OSError as exc:
        status, reason = "unreadable", f"{path} can't be opened: {exc.strerror or exc}"
    pinned = manifest.tools if manifest else {}
    states, taken = {}, []
    for tool_id, tool in candidates.items():
        if not in_folder(tool.executable, folder):
            states[tool_id] = _plain("outside", tool)
        elif status == "unreadable":
            states[tool_id] = _plain("unreadable", tool, refusal(path, reason))
        else:
            one = cache.get(tool)
            taken.append(one.taken)
            states[tool_id] = _for_tool(tool, pinned.get(tool_id), one, candidates)
    counts = _counts([s["state"] for i, s in states.items() if in_folder(candidates[i].executable, folder)])
    waiting = [i for i, s in states.items() if s["state"] == "not_pinned"]
    unpinned_ids = pin_group(candidates, waiting) if waiting else []
    text = (f"can't be read: {reason.rstrip('.')}. Restore it, or delete it and pin again" if status == "unreadable"
            else _counts_sentence(counts))
    return states, {"path": str(path), "state": status, "sha256": digest, "reason": reason, "text": text,
                    "checked": min(taken, default=utc_now()), "counts": counts, "unpinned": unpinned_ids}


def _counts(states: list[str]) -> dict[str, int]:
    return {"matches": states.count("matches"), "differs": states.count("differs"),
            "not_pinned": states.count("not_pinned"), "cant_check": states.count("cant_check"),
            "total": len([s for s in states if s != "unreadable"])}


def _counts_sentence(counts: dict[str, int]) -> str:
    if not counts["total"]:
        return "No tool in this tools folder has files to pin"
    parts = [f"{counts['matches']} of {counts['total']} tools match their pins"]
    if counts["differs"]:
        parts.append(f"{counts['differs']} {'differs' if counts['differs'] == 1 else 'differ'}")
    if counts["not_pinned"]:
        parts.append(f"{counts['not_pinned']} {'is' if counts['not_pinned'] == 1 else 'are'} not pinned")
    if counts["cant_check"]:
        parts.append(f"{counts['cant_check']} can't be checked")
    return ", ".join(parts)


def _plain(state: str, tool: DetectedTool, hint: str = "") -> dict:
    label, tone = LABELS[state]
    hints = {"outside": "Pins cover the tools folder. Move the tool into it to pin it.",
             "no_folder": "Pinning needs a tools folder."}
    return {"state": state, "label": label, "tone": tone, "hint": hint or hints.get(state, ""),
            "executable": str(tool.executable), "files": {}, "links": [], "group": [], "changes": "", "reason": "",
            "pinned": None, "rows": [], "link_rows": []}


def _for_tool(tool: DetectedTool, entry: dict | None, taken: Taken, candidates: dict[str, DetectedTool]) -> dict:
    name = tool.spec.name
    group = pin_group(candidates, [tool.spec.id])
    if taken.error:
        state = _plain("cant_check", tool, f"{name}'s files can't all be read now: {taken.error}")
        return {**state, "reason": taken.error, "group": group}
    links = list(taken.links)
    base = {**_plain("not_pinned", tool, "Pin a tool after you install it, so later runs can tell when its files change."),
            "files": dict(taken.listing.hashes), "links": links, "group": group}
    if entry is None:
        return base
    pinned = {"utc": entry["pinned_utc"], "by": entry["pinned_by"], "version": entry["version"], "rules": entry["rules"],
              "executable": entry["executable"]}
    diffs = differences(entry, taken.listing, links)
    date = entry["pinned_utc"][:10]
    if not diffs:
        label, tone = LABELS["matches"]
        hint = (f"{name}'s files match your pin of {date}. A pin records what was in the folder; it doesn't vouch for "
                "where the files came from.")
        state = "matches"
    else:
        label, tone = LABELS["differs"]
        hint = (f"{name}'s files changed since you pinned them on {date}. If you updated its rules, pin it again. If you "
                "didn't, look in its folder: antivirus may have removed rule files.")
        state = "differs"
    return {**base, "state": state, "label": label, "tone": tone, "hint": hint, "pinned": pinned,
            "changes": summary(diffs) if diffs else "", "rows": _rows(entry, taken.listing, diffs),
            "link_rows": link_states(entry["links"], links)}


def _rows(entry: dict, listing: ToolListing, diffs: list[dict]) -> list[dict]:
    """The fold's rows: each pinned or present path of the tool's folder with its pinned hash, its hash now, and its state
    (same, changed, missing, or added). A folder that differs is followed by the files in it that differ, up to
    MAX_NAMED, with how many more, and says how many of each in `detail`."""
    rows = []
    for key in sorted(entry["files"].keys() | listing.hashes.keys()):
        pinned, now = entry["files"].get(key), listing.hashes.get(key)
        state = "same" if pinned == now else "added" if pinned is None else "missing" if now is None else "changed"
        row = {"path": key, "pinned": pinned or "", "now": now or "", "state": state, "depth": 0}
        inside = [d for d in diffs if d["path"].startswith(key) and not d.get("link")] if key.endswith("/") else []
        if state == "changed" and inside:
            rows.append({**row, "detail": counts_text([d["state"] for d in inside])})
            rows += [{"path": d["path"], "pinned": d.get("pinned", ""), "now": d.get("now", ""), "state": d["state"],
                      "depth": 1} for d in inside[:MAX_NAMED]]
            if len(inside) > MAX_NAMED:
                rows.append({"path": "", "pinned": "", "now": "", "state": "more", "depth": 1,
                             "more": len(inside) - MAX_NAMED})
        else:
            rows.append(row)
    return rows
