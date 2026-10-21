"""Hashes and identifies every evidence file, and re-checks hashes later.

The evidence folder is only ever opened for reading. The manifest is written to the
case folder once; a second intake is refused so the hash baseline cannot be replaced.
Files copied into the evidence folder later, such as firewall logs to import, are added with add_new: it hashes only
files the manifest doesn't
list, and appends them with the time they were added, leaving earlier entries as
they were.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from collections import Counter
from collections.abc import Callable, Iterable, Iterator
from dataclasses import asdict, dataclass, field, replace
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path

from .case import Case, CaseError, ends_open, write_atomically
from .events import well_formed
from .identify import IMPORTABLE, NEWER_SIGNATURE_NAMES, Identification, identify_file
from .long_paths import long_path

CHUNK = 4 * 1024 * 1024
TEXT_SUFFIXES = {".log", ".txt", ".csv", ".tsv", ".json", ".jsonl", ".ndjson", ".old", ""}   # names a text log may have
UNLISTED = "folder can't be opened, so its files aren't in the manifest"   # how the error of a folder's entry begins


@dataclass(frozen=True)
class ManifestEntry:
    path: str              # relative to the evidence root, with forward slashes
    size: int
    sha256: str
    artifact: str | None
    method: str
    detail: str = ""
    error: str = ""        # set when the file could not be read
    added_utc: str = ""    # set when Add new evidence added the file after the first intake

    @property
    def is_folder(self) -> bool:
        """Whether this is the entry of a folder walk couldn't list (_unlisted), not a file's."""
        return self.error.startswith(UNLISTED)


@dataclass(frozen=True)
class IntakeSummary:
    files: int
    total_bytes: int
    by_artifact: dict[str, int]
    unidentified: list[str]
    errors: list[str]
    missing: list[str] = field(default_factory=list)   # manifest files no longer in the evidence folder (add_new)
    links: list[str] = field(default_factory=list)     # links skipped, not followed, as "path -> target" (walk)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def walk(root: Path, links: list[str] | None = None,
         unreadable: list[tuple[str, str]] | None = None) -> Iterator[tuple[str, list[str]]]:
    """os.walk without following links, for the evidence and the tools folder: each folder under root, as (path, its
    files' names), depth first in name order, as os.walk with sorted names gives them.

    os.walk follows directory junctions even with followlinks=False, and lists a symbolic link to a file among the
    files, so a plain os.walk would make intake hash files outside the evidence, and a junction pointing back up
    would never end. Here a symbolic link, a junction, or a folder that is any other reparse point is skipped, and
    added to `links` as "path -> target", the path relative to root. A volume mounted in a folder is a junction here,
    since both carry the mount point tag. A folder that is another reparse point is mostly a cloud-sync placeholder,
    such as a OneDrive folder: its files are the user's own, but it is skipped. A file that is a reparse point but not a
    link, such as a deduplicated or cloud file, is read like any other file.

    Each folder is listed through its extended-length path (long_paths.long_path), so one past 260 characters, or
    whose name ends in a dot or a space, is listed as it is. The path it gives for a folder is root joined with the
    names scandir gave, which a plain open may not reach, so a caller opens a file through long_path. A folder that
    still can't be listed is skipped, as os.walk skips one, and added to `unreadable` as (its path relative to root, "."
    for root itself, and the error)."""
    base = long_path(root)
    stack = [(os.fspath(root), "")]
    while stack:
        top, rel = stack.pop()
        try:
            with os.scandir(long_path(base, rel)) as it:
                entries = sorted(it, key=lambda e: e.name)
        except OSError as exc:
            if unreadable is not None:
                unreadable.append((rel or ".", f"{type(exc).__name__}: {exc}"))
            continue
        files, folders = [], []
        for entry in entries:
            path = f"{rel}/{entry.name}" if rel else entry.name
            kind = entry_kind(entry)
            if kind == "link":
                if links is not None:
                    links.append(f"{path} -> {_target(entry.path)}")
            elif kind == "folder":
                folders.append((os.path.join(top, entry.name), path))
            else:
                files.append(entry.name)
        yield top, files
        stack.extend(reversed(folders))


def entry_kind(entry: os.DirEntry) -> str:
    """The entry's kind: "link" for a symbolic link, a junction, or on Windows a folder that is any other reparse
    point; else "folder" or "file". On Windows the scan has already read all of this, so it costs no more file system
    calls."""
    try:
        if entry.is_symlink() or entry.is_junction():
            return "link"
        if not entry.is_dir(follow_symlinks=False):
            return "file"
        attributes = entry.stat(follow_symlinks=False).st_file_attributes if os.name == "nt" else 0
        return "link" if attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT else "folder"
    except OSError:
        return "file"   # as os.walk takes an entry it can't check


def _target(path: str) -> str:
    """Where a link points, written as Windows shows it: readlink gives a junction's target as \\\\?\\D:\\..."""
    try:
        target = os.readlink(path)
    except (OSError, ValueError):
        return "a reparse point that isn't a link"
    return target[4:] if target.startswith("\\\\?\\") and target[5:6] == ":" else target


def walk_evidence(root: Path, links: list[str] | None = None,
                  unreadable: list[tuple[str, str]] | None = None) -> Iterator[str]:
    """Yield every file under root, by its path relative to root with forward slashes, in a stable order, without
    following links (walk)."""
    for dirpath, filenames in walk(root, links, unreadable):
        folder = Path(dirpath).relative_to(root)
        for name in filenames:
            yield (folder / name).as_posix()


def intake(case: Case, progress: Callable[[int, int], None] | None = None) -> IntakeSummary:
    """Hash and identify every evidence file, then write manifest.jsonl. progress(done, total) follows the hashing,
    for the start page. A folder that can't be listed has an entry of its own, with its error."""
    if case.manifest_path.exists():
        raise CaseError(f"Intake already done for this case: {case.manifest_path}")
    root, links, folders = case.evidence, [], []
    paths = list(walk_evidence(root, links, folders))
    base = long_path(root)
    entries = []
    for i, rel in enumerate(paths, 1):
        entries.append(_entry(base, rel))
        if progress:
            progress(i, len(paths))
    entries += [_unlisted(rel, error) for rel, error in folders]
    _write_manifest(case, b"", entries)
    return replace(summarize(entries), links=links)


def add_new(case: Case) -> IntakeSummary:
    """Hash and identify the evidence files the manifest doesn't list yet, and add them to it.

    Listed files aren't hashed again (verify does that), and their entries stay byte for byte as they were, so
    the intake baseline is never replaced. The summary also names listed files that are gone from the folder, one that
    a folder of its name replaced among them. The entry of a folder that couldn't be listed isn't one of them once the
    folder opens, and its files are added.

    A folder that can't be listed gets an entry only when the manifest lists nothing under it. Otherwise the files it
    lists there keep their entries and aren't called gone, since they can't be looked for, and the summary's errors
    name the folder and how many they are.
    """
    if not case.manifest_path.exists():
        raise CaseError("No intake manifest yet; run intake first.")
    old = case.manifest_path.read_bytes()
    listed = read_manifest(case)
    known = {e.path for e in listed}
    folder_entries = {e.path for e in listed if e.is_folder}
    root, seen, new, not_looked_for, links, folders = case.evidence, set(), [], [], [], []
    base = long_path(root)
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    for rel in walk_evidence(root, links, folders):
        seen.add(rel)
        if rel not in known:
            new.append(replace(_entry(base, rel), added_utc=now))
    for rel, error in folders:
        inside = {path for path in known if _under(path, rel)}
        if rel not in known and not inside:
            new.append(replace(_unlisted(rel, error), added_utc=now))
        if rel in folder_entries:
            seen.add(rel)
        seen |= inside
        if files := len(inside - folder_entries):
            not_looked_for.append(f"{rel}: folder can't be opened, so its {files:,} {'file' if files == 1 else 'files'} "
                                  f"in the manifest can't be looked for: {error}")
    if new:
        _write_manifest(case, old if old.endswith(b"\n") or not old else old + b"\n", new)
    missing = sorted(rel for rel in known - seen if not (rel in folder_entries and long_path(base, rel).is_dir()))
    summary = summarize(new)
    return replace(summary, errors=summary.errors + not_looked_for, missing=missing, links=links)


def _under(path: str, folder: str) -> bool:
    """Whether a manifest path lies under `folder`, a folder's path relative to the evidence root, "." for the root."""
    return path != folder and (folder == "." or path.startswith(f"{folder}/"))


def _write_manifest(case: Case, before: bytes, entries: list[ManifestEntry]) -> None:
    """Write the manifest as `before` plus one line per entry, replacing the file in one step. As bytes, so the lines
    end in LF and `before` stays byte for byte."""
    lines = []
    for entry in entries:
        line = asdict(entry)
        if not line["added_utc"]:
            del line["added_utc"]   # first-intake lines keep their original form
        lines.append((json.dumps(line) + "\n").encode("utf-8"))
    write_atomically(case.manifest_path, before + b"".join(lines))


def read_manifest(case: Case) -> list[ManifestEntry]:
    with case.manifest_path.open(encoding="utf-8") as f:
        return [ManifestEntry(**json.loads(line)) for line in f if line.strip()]


def manifest_hashes(case: Case) -> dict[str, str]:
    """Each file's hash by its path as the events table holds it, with a lone surrogate in a name as U+FFFD
    (events.well_formed), which is how an event names its source file; the raw path would miss it."""
    return {well_formed(e.path): e.sha256 for e in read_manifest(case)}


def current_entries(case: Case) -> list[ManifestEntry]:
    """The manifest with identification brought up to date: each entry an earlier intake may have identified by older
    rules (_read_again) is read again, and takes the new identification when it names an artifact. The Tools page,
    runs, and the Import page all read the evidence this way. The manifest itself never changes."""
    return list(_current_entries(case, *file_stamp(case.manifest_path)))


@lru_cache(maxsize=2)
def _current_entries(case: Case, size: int, mtime_ns: int) -> tuple[ManifestEntry, ...]:
    """current_entries for one version of the manifest, known by its size and time: only add_new changes the manifest,
    and it adds lines. The Tools page calls current_entries on every load, and a run several times. Without this, a
    case with more files to read again than _identify_cached holds read all of them on every call: 70,000 took 10 s a
    call. With it, only the first call for a version of the manifest reads them."""
    evidence = str(long_path(case.evidence))
    out = []
    for e in read_manifest(case):
        if _read_again(e) and (ident := _reidentify(evidence, e)) and ident.artifact:
            e = replace(e, artifact=ident.artifact, method=ident.method, detail=ident.detail)
        out.append(e)
    return tuple(out)


def _read_again(e: ManifestEntry) -> bool:
    """Whether an entry's identification may predate a rule added since: a file left unidentified whose name fits a
    newer signature, such as a jump list, a $I file, or SRUDB.dat, so a case taken in by a build that didn't identify them
    still plans runs for them, or whose name a text log may have; and a text log, which may be a tool's output, such as
    Zeek's, or a format added since, such as syslog that intake took for key=value lines."""
    if e.error:
        return False
    if e.artifact is not None:
        return e.artifact in IMPORTABLE
    name = e.path.rsplit("/", 1)[-1].lower()
    return name.endswith(NEWER_SIGNATURE_NAMES) or name.startswith("$i") or Path(name).suffix in TEXT_SUFFIXES


def file_stamp(path: Path) -> tuple[int, int]:
    """A file's size and modification time, the key of the caches that read a file once until it changes."""
    st = path.stat()
    return st.st_size, st.st_mtime_ns


def _reidentify(evidence: str, e: ManifestEntry) -> Identification | None:
    """A file's identification by today's rules; None when it can't be read. It is read once per process for the size
    and hash the manifest records, which verify checks before any run reads the file, so no evidence file is statted
    to look it up, and a manifest that add_new changed reads only the files it added."""
    try:
        return _identify_cached(evidence, e.path, e.size, e.sha256)
    except OSError:
        return None


@lru_cache(maxsize=65536)
def _identify_cached(evidence: str, path: str, size: int, sha256: str) -> Identification:
    """identify_file for a manifest path under `evidence`, the evidence root in extended-length form."""
    return identify_file(long_path(Path(evidence), path))


def summarize(entries: Iterable[ManifestEntry]) -> IntakeSummary:
    """The counts of manifest entries. The entry of a folder walk couldn't list counts as no file, since its files
    aren't known, and is named among the errors."""
    entries = list(entries)
    return IntakeSummary(
        files=sum(not e.is_folder for e in entries),
        total_bytes=sum(e.size for e in entries),
        by_artifact=dict(Counter(e.artifact or "unidentified" for e in entries if not e.error).most_common()),
        unidentified=[f"{e.path} ({e.detail})" if e.detail else e.path
                      for e in entries if e.artifact is None and not e.error],
        errors=[f"{e.path}: {e.error}" for e in entries if e.error],
    )


@dataclass(frozen=True)
class Check:
    """What one re-hash found (check_files): its problems, how many files it checked, and what it skipped as
    unverified: the files intake couldn't read, and the folders walk couldn't list, each named with a trailing slash.
    Such a file has no intake hash, so no check can say it matches, also once it can be read."""
    problems: list[str]
    checked: int
    unverified: list[str]

    @property
    def folders(self) -> int:
        """How many of the unverified are folders walk couldn't list, not files."""
        return sum(p.endswith("/") for p in self.unverified)


def verify(case: Case, paths: Iterable[str] | None = None, reason: str = "") -> list[str]:
    """Re-hash manifest files (all of them, or the given relative paths) and record the result.

    Returns a list of problems, empty when every file it could check matches. Each call appends one line to
    verification.jsonl.
    """
    return check_files(case, paths, reason).problems


def check_files(case: Case, paths: Iterable[str] | None = None, reason: str = "") -> Check:
    """verify's re-hash, with the counts a full check's outputs state: the report, close, and the verify
    command. A file intake couldn't read is skipped and not counted as checked, so no output says every file
    matched, and so is a folder walk couldn't list. A file that can't be read now, such as one another process holds
    open, is a problem. The record counts only the files checked, and names those skipped as unverified, a folder with
    a trailing slash."""
    manifest = {e.path: e for e in read_manifest(case)}
    wanted = list(manifest) if paths is None else list(paths)
    base = long_path(case.evidence)
    problems, unverified = [], []
    for rel in wanted:
        entry = manifest.get(rel)
        if entry is None:
            problems.append(f"{rel}: not in the manifest")
            continue
        if entry.error:
            unverified.append(f"{rel}/" if entry.is_folder else rel)
            continue
        full = long_path(base, rel)
        try:
            if not full.is_file():
                problems.append(f"{rel}: missing")
            elif sha256_file(full) != entry.sha256:
                problems.append(f"{rel}: SHA-256 changed")
        except OSError as exc:
            # strerror alone: str(exc) ends in ": <path>", and evidence_checks takes the file's name from before the
            # last ": "
            problems.append(f"{rel}: unreadable ({exc.strerror or type(exc).__name__})")
    record = {
        "at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "reason": reason,
        "files_checked": len(wanted) - len(unverified),
        "result": "ok" if not problems else "mismatch",
        "problems": problems,
        "unverified": unverified,
    }
    # A last line without its LF is ended first, so this one doesn't join it: a hand edit's, or a run of 0x00 a crash
    # left, which then stays as a line evidence_checks counts as unreadable
    lead = "\n" if case.verification_path.exists() and ends_open(case.verification_path) else ""
    with case.verification_path.open("a", encoding="utf-8", newline="\n") as f:
        f.write(lead + json.dumps(record) + "\n")
    return Check(problems, len(wanted) - len(unverified), unverified)


def matched_text(checked: int) -> str:
    """What a full check that found no problem says of the files it checked, when intake couldn't read others: never
    "all"."""
    if not checked:
        return "No evidence file has an intake hash to check."
    return ("The 1 evidence file intake hashed matches the intake manifest." if checked == 1
            else f"The {checked:,} evidence files intake hashed match the intake manifest.")


def unverified_text(paths: list[str], escape: Callable[[str], str] = str, shown: int = 10) -> str:
    """What a full check's outputs add for what it skipped as unverified (Check.unverified): a sentence for the files
    intake couldn't read, then one for the folders walk couldn't list (unlisted_text), each naming its first `shown`;
    '' for none."""
    files = [p for p in paths if not p.endswith("/")]
    folders = ["the evidence folder" if p == "./" else p.removesuffix("/") for p in paths if p.endswith("/")]
    sentences = []
    if files:
        one = len(files) == 1
        sentences.append(f"{len(files):,} evidence {'file' if one else 'files'} could not be read at intake, so "
                         f"{'it has' if one else 'they have'} no hash to check and {'is' if one else 'are'} unverified: "
                         f"{escape(_first(files, shown))}.")
    if folders:
        sentences.append(f"{unlisted_text(len(folders))}: {escape(_first(folders, shown))}.")
    return " ".join(sentences)


def unlisted_text(folders: int) -> str:
    """What the outputs say of a number of folders walk couldn't list at intake, without their names or a closing
    period. Intake hashed none of the files such a folder held, so none can be checked against intake. Add new evidence
    may list them later, once the folder opens, so the sentence doesn't say the manifest leaves them out."""
    one = folders == 1
    return (f"{folders:,} {'folder' if one else 'folders'} could not be listed at intake, so no check can show that "
            f"the files {'it' if one else 'they'} held then are unchanged since intake")


def _first(items: list[str], shown: int) -> str:
    """The first `shown` of items, and how many more there are."""
    return "; ".join(items[:shown]) + (f"; and {len(items) - shown:,} more" if len(items) > shown else "")


# The reasons verify is given for a re-hash of the whole manifest: the close command's, the report's (and the findings
# summary's, which older cases record), and the verify command's (cli.cmd_close, export.report_text, cli.cmd_verify).
# Every other check re-hashes the files one run or import read.
FULL_CHECKS = ("case close", "full check when writing the report", "full check when writing the findings summary",
               "manual full verification")


def evidence_checks(case: Case) -> dict:
    """What verification.jsonl records since intake: the newest check, the newest full re-hash, and the
    problems found since the newest full re-hash that matched, with the files they name. A run's check that matched
    clears no earlier problem, since its line counts the files it read without naming them; a full re-hash that matches
    does. The header's state line and the overview's Integrity both read this, so neither can say the evidence matched
    while the case records a mismatch.

    `unreadable_lines` counts the whole lines that aren't a check and come after the newest full re-hash that matched: a
    run of 0x00, which a crash during an append leaves and the next check's line end makes a whole line, or a hand
    edit's line that isn't a JSON object. Such a line may have held a mismatch, so it is counted rather than dropped,
    and the checks around it still read. A full re-hash that matches checks every file again, so it clears the lines
    before it as it clears the problems before it."""
    # unreadable: for each line that isn't a check, how many checks come before it, which is more than i when the line
    # comes after checks[i]
    checks, unreadable = [], []
    if case.verification_path.exists():
        with case.verification_path.open("rb") as f:
            for line in f:
                if not line.endswith(b"\n"):
                    break   # a line verify is still writing
                if line.strip():
                    check = _check_line(line)
                    if check is None:
                        unreadable.append(len(checks))
                    else:
                        checks.append(check)
    full = [i for i, c in enumerate(checks) if c.get("reason") in FULL_CHECKS]
    clean = max((i for i in full if _matched(checks[i])), default=-1)
    problems = list(dict.fromkeys(p for c in checks[clean + 1:] for p in c.get("problems") or []))
    found = [c for c in checks[clean + 1:] if c.get("problems")]
    return {"checks": len(checks), "newest": _brief(checks[-1]) if checks else None,
            "last_full": _brief(checks[full[-1]]) if full else None, "problems": problems,
            "files": len({p.rsplit(": ", 1)[0] for p in problems}), "found_at": found[-1].get("at", "") if found else "",
            "unreadable_lines": sum(before > clean for before in unreadable)}


def _check_line(line: bytes) -> dict | None:
    """A line of verification.jsonl as a check, or None for one holding 0x00, which json.dumps never writes, or one that
    isn't a JSON object in UTF-8, nested too deep to read among them."""
    if b"\0" in line:
        return None
    try:
        check = json.loads(line.decode("utf-8"))
    except (ValueError, RecursionError):   # UnicodeDecodeError is a ValueError
        return None
    return check if isinstance(check, dict) else None


def _matched(check: dict) -> bool:
    return check.get("result") == "ok" and not check.get("problems")


def _brief(check: dict) -> dict:
    return {"at": check.get("at", ""), "reason": check.get("reason", ""), "files_checked": check.get("files_checked", 0),
            "result": check.get("result", ""), "problems": len(check.get("problems") or [])}


def _entry(base: Path, rel: str) -> ManifestEntry:
    """The manifest entry of the file at `rel`, read under `base`, the evidence root in extended-length form
    (long_path)."""
    path = long_path(base, rel)
    try:
        size = path.stat().st_size
        ident = identify_file(path)
        return ManifestEntry(rel, size, sha256_file(path), ident.artifact, ident.method, ident.detail)
    except OSError as exc:
        return ManifestEntry(rel, 0, "", None, "unreadable", error=f"{type(exc).__name__}: {exc}")


def _unlisted(rel: str, error: str) -> ManifestEntry:
    """The manifest entry of a folder walk couldn't list: none of its files has an entry, so this one keeps the
    folder in the manifest, with its error and no hash, as an unreadable file's entry is kept."""
    return ManifestEntry(rel, 0, "", None, "unreadable", error=f"{UNLISTED}: {error}")
