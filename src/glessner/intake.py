"""Hashes and identifies every evidence file, and re-checks hashes later.

The evidence folder is only ever opened for reading. The manifest is written to the
case folder once; a second intake is refused so the hash baseline cannot be replaced.
Files copied into the evidence folder later, such as firewall logs to import, are added with add_new: it hashes only
files the manifest doesn't
list, and appends them with the time they were added, leaving earlier entries as
they were.

From case format 4 the journal records manifest.jsonl's SHA-256, bytes, and lines each time intake or Add new evidence
writes it (manifest_recorded), and the full checks compare the file with the record that counts (manifest_state).
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

from . import heads
from .case import JOURNAL_FILE, Case, CaseError, ends_open, write_atomically
from .events import well_formed
from .identify import IMPORTABLE, NEWER_SIGNATURE_NAMES, Identification, identify_file
from .journal import Check as JournalCheck
from .journal import Journal, JournalError, check, unvouched_sentences, unvouched_warns
from .long_paths import long_path

CHUNK = 4 * 1024 * 1024
TEXT_SUFFIXES = {".log", ".txt", ".csv", ".tsv", ".json", ".jsonl", ".ndjson", ".old", ""}   # names a text log may have
UNLISTED = "folder can't be opened, so its files aren't in the manifest"   # how the error of a folder's entry begins
NOT_IN_MANIFEST = "not in the manifest"   # what check_files says of a path the manifest doesn't list
LISTED_TWICE = "listed more than once in the manifest"   # and of one it lists on more than one line
# Windows file attributes of a cloud file whose content isn't on the disk, which opening it downloads: stat has no
# constants for the first two
RECALL_ON_OPEN = 0x40000
RECALL_ON_DATA_ACCESS = 0x400000
PLACEHOLDER_ATTRIBUTES = RECALL_ON_DATA_ACCESS | RECALL_ON_OPEN | stat.FILE_ATTRIBUTE_OFFLINE
# The error of the manifest entry of a placeholder intake didn't read, and what a later check says of one. Neither holds
# ": ", since the reader of a problem takes the file's name from before the last one.
PLACEHOLDER = "a cloud placeholder whose content isn't on this disk, so intake didn't read it, since reading would download it"
PLACEHOLDER_NOW = "a cloud placeholder whose content isn't on this disk"
MANIFEST_FORMAT = 4   # the case format from which the journal records manifest.jsonl (manifest_recorded)
FAILED_STATES = ("grew", "differs")   # what manifest_state answers for a manifest its record doesn't vouch for
HEAD_WORDS = "the head this app recorded"   # the head recorded outside the case, as close and Add new evidence name it


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


def walk(root: Path, links: list[str] | None = None, unreadable: list[tuple[str, str]] | None = None,
         placeholders: list[str] | None = None) -> Iterator[tuple[str, list[str]]]:
    """os.walk without following links, for the evidence and the tools folder: each folder under root, as (path, its
    files' names), depth first in name order, as os.walk with sorted names gives them.

    os.walk follows directory junctions even with followlinks=False, and lists a symbolic link to a file among the
    files, so a plain os.walk would make intake hash files outside the evidence, and a junction pointing back up
    would never end. Here a symbolic link, a junction, or a folder that is any other reparse point is skipped, and
    added to `links` as "path -> target", the path relative to root. A volume mounted in a folder is a junction here,
    since both carry the mount point tag. A folder that is another reparse point is mostly a cloud-sync placeholder,
    such as a OneDrive folder: its files are the user's own, but it is skipped. A file that is a reparse point but not a
    link, such as a deduplicated file, is read like any other file.

    Each folder is listed through its extended-length path (long_paths.long_path), so one past 260 characters, or
    whose name ends in a dot or a space, is listed as it is. The path it gives for a folder is root joined with the
    names scandir gave, which a plain open may not reach, so a caller opens a file through long_path. A folder that
    still can't be listed is skipped, as os.walk skips one, and added to `unreadable` as (its path relative to root, "."
    for root itself, and the error). A file that is a cloud placeholder (is_placeholder) is still listed, and added to
    `placeholders` as its path relative to root, so that a caller can leave it unread."""
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
                if placeholders is not None and is_placeholder(entry):
                    placeholders.append(path)
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


def is_placeholder(entry: os.DirEntry) -> bool:
    """Whether a file is a cloud placeholder, such as a OneDrive file whose content isn't on the disk, by the attributes
    the folder listing carries, so nothing is opened. False where files have no such attributes, and for an entry that
    can't be statted."""
    try:
        return _has_placeholder_attributes(entry.stat(follow_symlinks=False))
    except OSError:
        return False


def file_attributes(path: Path) -> int:
    """A file's Windows attributes from one stat, which opens nothing; 0 where files have none, and for a file that
    can't be statted."""
    try:
        return getattr(os.stat(path, follow_symlinks=False), "st_file_attributes", 0)
    except OSError:
        return 0


def _has_placeholder_attributes(result: os.stat_result) -> bool:
    return bool(getattr(result, "st_file_attributes", 0) & PLACEHOLDER_ATTRIBUTES)


def placeholders_among(case: Case, paths: Iterable[str]) -> list[str]:
    """The evidence files among `paths` (relative to the evidence root) that are cloud placeholders now, in the order
    given, by one stat each, so nothing is opened. A file that became one after intake still has its hash in the
    manifest; a caller asks before it reads such a file, since reading a placeholder downloads it."""
    base = long_path(case.evidence)
    return [rel for rel in paths if file_attributes(long_path(base, rel)) & PLACEHOLDER_ATTRIBUTES]


def _target(path: str) -> str:
    """Where a link points, written as Windows shows it: readlink gives a junction's target as \\\\?\\D:\\..."""
    try:
        target = os.readlink(path)
    except (OSError, ValueError):
        return "a reparse point that isn't a link"
    return target[4:] if target.startswith("\\\\?\\") and target[5:6] == ":" else target


def walk_evidence(root: Path, links: list[str] | None = None, unreadable: list[tuple[str, str]] | None = None,
                  placeholders: list[str] | None = None) -> Iterator[str]:
    """Yield every file under root, by its path relative to root with forward slashes, in a stable order, without
    following links (walk), which also fills `links`, `unreadable`, and `placeholders`."""
    for dirpath, filenames in walk(root, links, unreadable, placeholders):
        folder = Path(dirpath).relative_to(root)
        for name in filenames:
            yield (folder / name).as_posix()


def intake(case: Case, progress: Callable[[int, int], None] | None = None,
           journal: Journal | None = None) -> IntakeSummary:
    """Hash and identify every evidence file, then write manifest.jsonl. progress(done, total) follows the hashing,
    for the start page. A folder that can't be listed has an entry of its own, with its error, and so does a cloud
    placeholder, which is not read, since reading would download it (is_placeholder). With `journal`, on a case that
    records the manifest (records_manifest), the journal records the file written (_write_recorded); before any file is
    hashed, a break refuses, and so does a journal that records a manifest already, since this one would be a new
    baseline written over evidence that may have changed (manifest_missing)."""
    if case.manifest_path.exists():
        raise CaseError(f"Intake already done for this case: {case.manifest_path}")
    journal = journal if records_manifest(case) else None
    if journal is not None:
        with journal.held():
            _checked(journal)
            if journal.state.manifests:
                raise CaseError(manifest_missing(journal.state.manifests))
    root, links, folders, placeholders = case.evidence, [], [], []
    paths = list(walk_evidence(root, links, folders, placeholders))
    base, held = long_path(root), set(placeholders)
    entries = []
    for i, rel in enumerate(paths, 1):
        entries.append(_entry(base, rel, rel in held))
        if progress:
            progress(i, len(paths))
    entries += [_unlisted(rel, error) for rel, error in folders]
    _write_recorded(case, journal, None, entries, "intake")
    return replace(summarize(entries), links=links)


def add_new(case: Case, journal: Journal | None = None, *, at_open: bool = False) -> IntakeSummary:
    """Hash and identify the evidence files the manifest doesn't list yet, and add them to it.

    Listed files aren't hashed again (verify does that), and their entries stay byte for byte as they were, so
    the intake baseline is never replaced. The summary also names listed files that are gone from the folder, one that
    a folder of its name replaced among them. The entry of a folder that couldn't be listed isn't one of them once the
    folder opens, and its files are added.

    A folder that can't be listed gets an entry only when the manifest lists nothing under it. Otherwise the files it
    lists there keep their entries and aren't called gone, since they can't be looked for, and the summary's errors
    name the folder and how many they are. A cloud placeholder is added without being read, as intake adds one.

    With `journal`, on a case that records the manifest (records_manifest), the journal records the file written, and
    also a file that grew past its record with nothing new, which a stop between an earlier add's replace and its record
    leaves (_write_recorded). Before any file is hashed, a break refuses, and so does a manifest that differs from its
    record that counts (_head_seq, with `at_open` for a command that opened the case for work just now), or that is
    missing while the journal records one (manifest_missing).
    """
    journal = journal if records_manifest(case) else None
    if not case.manifest_path.exists():
        if journal is not None:
            journal.refresh()
            if journal.state.manifests:
                raise CaseError(manifest_missing(journal.state.manifests))
        raise CaseError("No intake manifest yet; run intake first.")
    old = case.manifest_path.read_bytes()
    if journal is not None:
        with journal.held():
            _checked(journal)
            _refuse_differs(old, journal, at_open)
    listed = read_manifest(case)
    known = {e.path for e in listed}
    folder_entries = {e.path for e in listed if e.is_folder}
    root, not_looked_for, links, folders, placeholders = case.evidence, [], [], [], []
    paths = list(walk_evidence(root, links, folders, placeholders))
    base, held, seen = long_path(root), set(placeholders), set(paths)
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    new = [replace(_entry(base, rel, rel in held), added_utc=now) for rel in paths if rel not in known]
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
    _write_recorded(case, journal, old, new, "add", at_open)
    missing = sorted(rel for rel in known - seen if not (rel in folder_entries and long_path(base, rel).is_dir()))
    summary = summarize(new)
    return replace(summary, errors=summary.errors + not_looked_for, missing=missing, links=links)


def _under(path: str, folder: str) -> bool:
    """Whether a manifest path lies under `folder`, a folder's path relative to the evidence root, "." for the root."""
    return path != folder and (folder == "." or path.startswith(f"{folder}/"))


def _manifest_bytes(old: bytes | None, entries: list[ManifestEntry]) -> bytes:
    """The manifest as `old`, the file's bytes or None for a new one, plus one line per entry; `old` itself with none.
    As bytes, so the lines end in LF and `old` stays byte for byte, with a line end added to its last line when it
    lacks one and an entry follows."""
    before = old or b""
    if not entries:
        return before
    lines = []
    for entry in entries:
        line = asdict(entry)
        if not line["added_utc"]:
            del line["added_utc"]   # first-intake lines keep their original form
        lines.append((json.dumps(line) + "\n").encode("utf-8"))
    return (before if not before or before.endswith(b"\n") else before + b"\n") + b"".join(lines)


def _write_recorded(case: Case, journal: Journal | None, old: bytes | None, entries: list[ManifestEntry],
                    via: str, at_open: bool = False) -> None:
    """Write the manifest as `old`, the bytes read before the hashing or None for intake's new file, plus one line per
    entry, replacing the file in one step; and with `journal`, record it. The hashing came first, outside any lock.
    Then, under the journal's held context: the append's own checks (Journal.check_for_append), refused on a break; the
    manifest still absent, or still `old`'s bytes, refused when another writer changed it meanwhile; for intake, still
    no record of a manifest in the journal (manifest_missing); for Add new evidence, the refusal of a manifest that
    differs from its record that counts (_refuse_differs); the replace, for intake or a new entry; and the record, also
    of a file that grew past its record with nothing new. After those checks no other writer can make the append
    refuse, so no replace goes unrecorded, and a replace Windows refuses raises before the record."""
    data = _manifest_bytes(old, entries)
    write = old is None or bool(entries)
    if journal is None:
        if write:
            write_atomically(case.manifest_path, data)
        return
    with journal.held():
        _checked(journal)
        now = case.manifest_path.read_bytes() if case.manifest_path.exists() else None
        if now != old:
            if old is None:
                raise CaseError(f"Intake already done for this case: {case.manifest_path}")
            raise CaseError("manifest.jsonl changed while Add new evidence was hashing, so nothing was added. Run Add "
                            "new evidence again.")
        if old is None and journal.state.manifests:
            raise CaseError(manifest_missing(journal.state.manifests))
        state = "none" if old is None else _refuse_differs(old, journal, at_open)
        if not (write or state == "grew"):
            return
        if write:
            write_atomically(case.manifest_path, data)
        journal.append("manifest_recorded", **manifest_record(data), via=via)


def _checked(journal: Journal) -> None:
    """The append's own checks, after a catch-up with the journal (Journal.check_for_append): a JournalError on a break,
    since the journal would refuse the record."""
    if reason := journal.check_for_append():
        raise JournalError(reason)


def _refuse_differs(old: bytes, journal: Journal, at_open: bool) -> str:
    """The manifest's state, for Add new evidence, against its record that counts, as the journal last read it: the
    newest at or before the head _head_seq gives. A CaseError when it differs, since the add would append to a manifest
    no record vouches for; it names a record after that head, and with `at_open`, that the command's open moved the
    head past it (_later_text)."""
    record, later = counted_record(journal.state.manifests, _head_seq(journal, at_open))
    state = _state_of(old, record)
    if state == "differs":
        raise CaseError(f"manifest.jsonl differs from its record in the journal, entry #{record['seq']}, so Add new "
                        "evidence adds nothing to it. Restore manifest.jsonl from a copy of the case, then add the "
                        f"evidence again.{_later_text(later, HEAD_WORDS, at_open)}")
    return state


def _head_seq(journal: Journal, at_open: bool) -> int | None:
    """The entry number of the head recorded outside the case that a manifest record must come at or before to count;
    None without one, when the newest counts. With `at_open`, the head as the journal's open for work found it, for a
    command whose open has just moved it to the newest line, past any line appended after it (Journal.recorded);
    otherwise the head as this app records it now, which its own appends and those of other Glessner programs on this
    computer move."""
    head = journal.recorded if at_open else heads.read(journal.path.parent)
    return head["seq"] if head else None


def manifest_missing(records: list[dict]) -> str:
    """What a command says of a missing manifest.jsonl whose journal holds manifest `records`: intake would write a new
    baseline over evidence that may have changed since, so the file is restored instead."""
    return (f"manifest.jsonl is missing, but the journal records it, entry #{records[-1]['seq']}. Restore it from a copy "
            "of the case.")


def records_manifest(case: Case) -> bool:
    """Whether the case's journal records manifest.jsonl (manifest_recorded): from MANIFEST_FORMAT on, and at any format
    once the journal holds a chained record of it. case.yaml, which names the format, sits outside the chain, so setting
    it back by hand must not turn the comparison off. A case below that format whose journal holds no record, such as
    one kept at format 3, doesn't record the manifest."""
    if case.settings.case_format >= MANIFEST_FORMAT:
        return True
    path = case.folder / JOURNAL_FILE
    # A journal without the action's name holds no record, so the full check is skipped for it
    return path.is_file() and b'"manifest_recorded"' in path.read_bytes() and bool(check(path).manifests)


def manifest_record(data: bytes) -> dict:
    """A manifest_recorded payload, without its via, for manifest.jsonl's bytes: their SHA-256, how many there are, and
    the lines among them that aren't blank, as read_manifest counts entries."""
    return {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data),
            "lines": sum(1 for line in data.split(b"\n") if line.strip())}


def _state_of(data: bytes | None, record: dict | None) -> str:
    """manifest.jsonl's bytes, None when it is missing, against a record (manifest_state)."""
    if record is None:
        return "none"
    size = record["bytes"]
    if data is None or len(data) < size or hashlib.sha256(memoryview(data)[:size]).hexdigest() != record["sha256"]:
        return "differs"
    if len(data) == size:
        return "matches"
    return "grew" if _added_lines(data[:size], data[size:]) else "differs"


def _added_lines(recorded: bytes, rest: bytes) -> bool:
    """Whether `rest`, the bytes after those a record names, is what Add new evidence's replace adds, which is all a stop
    between that replace and its record can leave: the line end the recorded bytes lacked, if any, then one or more
    whole lines, each an entry as _manifest_bytes writes it, with the time it was added, for a path no other line lists.
    Any other bytes, such as a line that lists an evidence file again with a new hash, are a change."""
    if recorded and not recorded.endswith(b"\n"):
        if not rest.startswith(b"\n"):
            return False
        rest = rest[1:]
    if not rest.endswith(b"\n"):
        return False
    try:
        listed = {json.loads(line)["path"] for line in recorded.splitlines() if line.strip()}
    except (ValueError, TypeError, KeyError):
        return False
    for line in rest[:-1].split(b"\n"):
        entry = _added_entry(line)
        if entry is None or entry.path in listed:
            return False
        listed.add(entry.path)
    return True


def _added_entry(line: bytes) -> ManifestEntry | None:
    """The entry a manifest line holds when the line is byte for byte as Add new evidence writes one, with the time it
    was added; None for any other line."""
    try:
        entry = ManifestEntry(**json.loads(line))
    except (ValueError, TypeError):
        return None
    if not (isinstance(entry.path, str) and isinstance(entry.added_utc, str) and entry.added_utc):
        return None
    return entry if line == json.dumps(asdict(entry)).encode("utf-8") else None


def manifest_state(case: Case, record: dict | None) -> str:
    """manifest.jsonl against a manifest_recorded record: "matches" when it holds exactly the bytes the record names;
    "grew" when those bytes start it and only lines Add new evidence writes follow (_added_lines), as a stop between its
    replace of the file and its record leaves; "differs" otherwise, a missing file included; and "none" without a
    record."""
    path = case.manifest_path
    return _state_of(path.read_bytes() if path.exists() else None, record)


@dataclass(frozen=True)
class ManifestCheck:
    """manifest.jsonl against the journal's record that counts, as a full check states it (manifest_text): its state
    (manifest_state); the record's entry number; the newest record after the head it was counted at or before, which
    vouches for nothing; that head, in words, or None when there was none, so the newest record counted; whether the
    head is an entry of the journal, without which no record counts; whether the file is missing, which fails the
    check whatever the state; whether the command's own open moved that head to the newest entry, past the later
    record, as close's does; and the reasons the journal's first record names, when it is a copy's, for why its source
    could not vouch for it (journal.UNVOUCHED_WORDS), which every check of the copy repeats."""
    state: str
    seq: int | None = None
    later: int | None = None
    head: str | None = None
    head_found: bool = True
    missing: bool = False
    moved: bool = False
    unvouched: tuple[str, ...] = ()

    @property
    def key(self) -> dict:
        """What a full check's line in verification.jsonl and the close's entry record: the state, the record's entry
        number, and the reasons when there are any."""
        key = {"state": self.state, "seq": self.seq}
        return {**key, "unvouched": list(self.unvouched)} if self.unvouched else key

    @property
    def warns(self) -> bool:
        """Whether a reason is a warning (journal.UNVOUCHED_WARNS), as opposed to a note. It fails nothing."""
        return unvouched_warns(self.unvouched)

    @property
    def failed(self) -> bool:
        return self.missing or self.state in FAILED_STATES


def counted_record(records: list[dict], limit: int | None, by: str = "seq",
                   written: tuple[int, int] | None = None) -> tuple[dict | None, int | None]:
    """The record that counts among a journal's manifest records, in journal order: the newest whose `by` is at or
    before `limit`, the head compared, or within `written`, a range (after, through) of entry numbers that a Glessner
    program on this computer appended after that head was read, as the head it records shows; the newest of all with no
    limit. And the number of the newest record that doesn't count, or None: anyone who can write the case folder can
    append one after the head, so it vouches for nothing."""
    if limit is None:
        return (records[-1] if records else None), None
    counted, later = [], []
    for record in records:
        if record[by] <= limit or (written is not None and written[0] < record[by] <= written[1]):
            counted.append(record)
        else:
            later.append(record)
    return (counted[-1] if counted else None), (later[-1]["seq"] if later else None)


def record_at_head(found: JournalCheck, compared: bool) -> tuple[dict | None, int | None]:
    """The manifest record a full check of the journal counts, and the newest after it (counted_record), by line: at or
    before the head the check compared, when it compared one (`compared`), and none when that head is no line of the
    journal; the newest with no head."""
    limit = (found.expected[0] if found.expected else 0) if compared else None
    return counted_record(found.manifests, limit, "line")


def first_unvouched(records: list[dict]) -> tuple[str, ...]:
    """The reasons the first of a journal's manifest records names, which only a copy's does (journal.manifest_of); none
    for a journal without a record. A later record, such as Add new evidence's, names none: the lines before the first
    are the ones the source could not vouch for."""
    return tuple(records[0].get("unvouched", ())) if records else ()


def recorded_manifest(case: Case, journal: Journal, *, at_open: bool = False) -> ManifestCheck | None:
    """close's and the report's ManifestCheck, or None for a case that doesn't record the manifest: under one short
    hold of the journal, after its catch-up, so a record another process appended counts, the record at or before the
    head recorded outside the case (_head_seq: with `at_open`, as close's open found it before moving it), and the
    file's state against it. With `at_open`, a record past the entries `journal` had read before this catch-up, at or
    before the head this app records now, counts too: a Glessner program on this computer, such as the server's Add new
    evidence, appended it after the open and moved the head to it. The evidence re-hash comes after, outside the hold,
    since an append waits for the hold only LOCK_WAIT."""
    if not records_manifest(case):
        return None
    with journal.held():
        read = journal.chain.seq
        journal.refresh()
        limit, now = _head_seq(journal, at_open), _head_seq(journal, False)
        written = (read, now) if at_open and isinstance(read, int) and now is not None else None
        record, later = counted_record(journal.state.manifests, limit, written=written)
        return ManifestCheck(manifest_state(case, record), record["seq"] if record else None, later,
                             None if limit is None else HEAD_WORDS, moved=at_open,
                             unvouched=first_unvouched(journal.state.manifests))


def _later_text(later: int | None, head: str | None, moved: bool) -> str:
    """The sentences that name a record after the head compared, which vouches for nothing, with a space before them,
    and when the command's own open moved that head past it, that later commands count it; "" without one."""
    if later is None:
        return ""
    text = f" Entry #{later} records manifest.jsonl after {head}, so it vouches for nothing."
    if moved:
        text += (" This command moved that head to the newest entry, so later commands count that record; verify "
                 "--expect-head with a head recorded before it, such as one a close printed, still names it.")
    return text


def manifest_text(found: ManifestCheck) -> str:
    """What verify, close, and the report say of manifest.jsonl against its record. When the journal's first record is a
    copy's, the sentences for the reasons it names follow (unvouched_sentences), except for a missing file and a head that
    is no line of the journal, where no record is in question."""
    if found.missing:
        recorded = f", but the journal records it, entry #{found.seq}" if found.seq is not None else ""
        text = f"manifest.jsonl is missing{recorded}. Restore it from a copy of the case."
    elif not found.head_found:
        return f"No record of manifest.jsonl counts, since {found.head} is no entry of the journal."
    else:
        text = {
            "matches": f"manifest.jsonl matches its record in the journal, entry #{found.seq}.",
            "grew": (f"manifest.jsonl grew past its record in the journal, entry #{found.seq}: lines follow the bytes "
                     "it records. A stop between Add new evidence's write and its record leaves this, and the next Add "
                     "new evidence records the file as it stands."),
            "differs": (f"manifest.jsonl differs from its record in the journal, entry #{found.seq}: it changed after it "
                        "was recorded. Restore it from a copy of the case."),
            "none": ("No journal entry records manifest.jsonl's hash, so nothing shows it holds what intake and Add new "
                     "evidence wrote."),
        }[found.state]
    if found.later is not None:
        text += _later_text(found.later, found.head, found.moved)
    elif found.head is None and found.seq is not None:
        text += " No head recorded outside the case was given, so nothing shows the record wasn't added later."
    if found.unvouched and not found.missing:
        text += f" {unvouched_sentences(found.unvouched)}."
    return text


def read_manifest(case: Case) -> list[ManifestEntry]:
    with case.manifest_path.open(encoding="utf-8") as f:
        return [ManifestEntry(**json.loads(line)) for line in f if line.strip()]


def manifest_hashes(case: Case) -> dict[str, str]:
    """Each file's hash by its path as the events table holds it, with a lone surrogate in a name as U+FFFD
    (events.well_formed), which is how an event names its source file; the raw path would miss it."""
    return {well_formed(e.path): e.sha256 for e in read_manifest(case)}


def current_entries(case: Case) -> list[ManifestEntry]:
    """The manifest with identification brought up to date: each entry an earlier intake may have identified by older
    rules (_read_again) is read again, and takes the new identification when it names an artifact; one that is a cloud
    placeholder now is not read, and keeps its entry. The Tools page, runs, and the Import page all read the evidence
    this way. The manifest itself never changes."""
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
    """A file's identification by today's rules; None when it can't be read, and when it is a cloud placeholder now,
    which reading would download. It is read once per process for the size and hash the manifest records, which verify
    checks before any run reads the file, so no evidence file is statted to look it up, and a manifest that add_new
    changed reads only the files it added."""
    try:
        return _identify_cached(evidence, e.path, e.size, e.sha256)
    except OSError:
        return None


@lru_cache(maxsize=65536)
def _identify_cached(evidence: str, path: str, size: int, sha256: str) -> Identification:
    """identify_file for a manifest path under `evidence`, the evidence root in extended-length form. A file that is a
    cloud placeholder (PLACEHOLDER_ATTRIBUTES) raises OSError, which the cache doesn't keep, instead of being read; only
    a file about to be read is statted for that."""
    full = long_path(Path(evidence), path)
    if file_attributes(full) & PLACEHOLDER_ATTRIBUTES:
        raise OSError(f"{path}: {PLACEHOLDER_NOW}")
    return identify_file(full)


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
    manifest: ManifestCheck | None = None   # manifest.jsonl against its record, which the caller found

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


def check_files(case: Case, paths: Iterable[str] | None = None, reason: str = "",
                manifest: ManifestCheck | None = None) -> Check:
    """verify's re-hash, with the counts a full check's outputs state: the report, close, and the verify
    command. A file intake couldn't read is skipped and not counted as checked, so no output says every file
    matched, and so is a folder walk couldn't list. A file that can't be read now, such as one another process holds
    open, is a problem. The record counts only the files checked, and names those skipped as unverified, a folder with
    a trailing slash. `manifest`, the full check's ManifestCheck, which its caller found, is recorded under its own key,
    outside the problems, which name evidence files; a manifest that grew past or differs from its record makes the
    result a mismatch. On a case whose journal records the manifest (records_manifest), a path the manifest lists on
    more than one line is a problem of that file, compared with neither line, since intake and Add new evidence list
    each path once."""
    entries = read_manifest(case)
    listed = {e.path: e for e in entries}
    twice = {path for path, n in Counter(e.path for e in entries).items() if n > 1}
    if twice and not records_manifest(case):
        twice = set()
    wanted = list(listed) if paths is None else list(paths)
    base = long_path(case.evidence)
    problems, unverified = [], []
    for rel in wanted:
        entry = listed.get(rel)
        if entry is None:
            problems.append(f"{rel}: {NOT_IN_MANIFEST}")
            continue
        if rel in twice:
            problems.append(f"{rel}: {LISTED_TWICE}")
            continue
        if entry.error:
            unverified.append(f"{rel}/" if entry.is_folder else rel)
            continue
        full = long_path(base, rel)
        if file_attributes(full) & PLACEHOLDER_ATTRIBUTES:   # reading it would download it
            problems.append(f"{rel}: unreadable ({PLACEHOLDER_NOW})")
            continue
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
        "result": "ok" if not problems and not (manifest and manifest.failed) else "mismatch",
        "problems": problems,
        "unverified": unverified,
    }
    if manifest is not None:
        record["manifest"] = manifest.key
    # A last line without its LF is ended first, so this one doesn't join it: a hand edit's, or a run of 0x00 a crash
    # left, which then stays as a line evidence_checks counts as unreadable
    lead = "\n" if case.verification_path.exists() and ends_open(case.verification_path) else ""
    with case.verification_path.open("a", encoding="utf-8", newline="\n") as f:
        f.write(lead + json.dumps(record) + "\n")
    return Check(problems, len(wanted) - len(unverified), unverified, manifest)


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
    """What verification.jsonl records since intake: the newest check, the newest full re-hash, with manifest.jsonl's
    state against its record when that check compared one, and the problems found since the newest full re-hash that
    matched, with the files they name. A run's check that matched
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
    brief = {"at": check.get("at", ""), "reason": check.get("reason", ""), "files_checked": check.get("files_checked", 0),
             "result": check.get("result", ""), "problems": len(check.get("problems") or [])}
    if isinstance(found := check.get("manifest"), dict):
        brief["manifest"] = {"state": found.get("state"), "seq": found.get("seq")}
    return brief


def _entry(base: Path, rel: str, placeholder: bool = False) -> ManifestEntry:
    """The manifest entry of the file at `rel`, read under `base`, the evidence root in extended-length form
    (long_path). A cloud placeholder (is_placeholder) is not read: its entry is unreadable, with PLACEHOLDER as its
    error."""
    if placeholder:
        return ManifestEntry(rel, 0, "", None, "unreadable", error=PLACEHOLDER)
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
