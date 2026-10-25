"""The append-only analyst journal and its replay into current analysis state.

Every analyst action is one JSON line, written and flushed to disk before the app shows the
change. The journal is the only part of a case that cannot be rebuilt, so lines are never
edited or removed.

From case format 3 each line names, in `prev`, the SHA-256 of the line before it, and in `build` and
`client` what wrote it, so a change to an earlier line shows as a break. A change to the newest lines shows only against
a head kept outside the case, such as the one heads.py records. Every append holds one lock per case folder per
process, re-entrant in its thread, and an OS lock on journal.lock across processes.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import time
from collections import Counter
from collections.abc import Callable, Collection, Iterable, Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import NamedTuple

import yaml

from . import heads
from .case import CASE_FILE, CASE_FORMAT, FIRST_CHAINED, JOURNAL_FILE, Case, KeptAtFormat, ends_open
from .parsers.common import normalize_ip
from .tags import TagError, normalize_tag
from .version import build_id

try:
    import msvcrt
except ImportError:   # off Windows, which the app doesn't target: fcntl locks the same byte
    msvcrt = None
    import fcntl

MARK_VALUES = ("unreviewed", "authorized", "suspicious", "malicious")
# case_open and case_upgrade are the app's record of the builds that opened the case for work and of the format upgrades
# they made; replay applies nothing from them. The app's other records of the chain are case_created, which
# starts it, case_yaml, which records case.yaml's bytes, journal_recovered, a line end added or a torn line moved aside,
# and chain_break, the analyst's choice to continue past a break. manifest_recorded records manifest.jsonl's bytes as
# intake, Add new evidence, or a copy of the case wrote them.
ACTIONS = {"mark", "note", "host_role", "host_identity", "host_offset", "case_setting",
           "rule_add", "rule_change", "rule_remove", "suggestion_decision", "tag", "tag_suggestion",
           "undo", "note_retract", "host_split", "case_open", "case_upgrade",
           "case_created", "case_yaml", "journal_recovered", "chain_break",
           "followup", "finding", "file_written", "manifest_recorded"}
# What an undo can reverse: the analysis entries. An undo is one entry holding its reversing
# changes, each in the form of one of these actions, so a replay applies them as it would the originals. A host split
# is undone from the Hosts panel instead, as an entry of its own, and a finding from the Findings page.
UNDOABLE = ("mark", "tag", "suggestion_decision", "tag_suggestion", "followup")
DECISIONS = ("rejected", "restored")
# A finding's severity: the scale the app uses for Hayabusa's levels, with Informational
# for a stated negative. Its ops, and an ATT&CK technique's form, such as T1543.003.
SEVERITIES = ("Critical", "High", "Medium", "Low", "Informational")
FINDING_OPS = ("add", "edit", "link", "unlink", "retire", "restore")
FINDING_FIELDS = ("title", "severity", "narrative", "techniques")   # what an edit can change, in this order
TECHNIQUE = re.compile(r"T\d{4}(\.\d{3})?")
TITLE_MAX = 200
# The files a file_written entry records: what wrote them, in which format, and the timeline's marks
FILE_KINDS = ("timeline", "findings_summary", "report", "audit_trail", "indicators")
FILE_FORMATS = ("csv", "jsonl", "md")
FILE_MARKS = ("all", "marked", "flagged")
MANIFEST_VIA = ("intake", "add", "copy")   # what wrote the manifest a manifest_recorded entry records
# Why a copy's record of manifest.jsonl comes with a warning, in the order the outputs word them: its source's journal
# had a break, its head wasn't recorded on this computer, or its first record came with Add new evidence. Each is a
# sentence with no final period, since the outputs join them to their own.
UNVOUCHED_WORDS = {
    "break": "The source's journal had a break, so it could not vouch for this record",
    "no_head": "No head of the source's journal was recorded on this computer, so nothing showed that this record was "
               "not added later",
    "add": "The source's first record came with Add new evidence, so nothing shows that the lines before it are as intake "
           "wrote them"}
# The reasons whose record the source couldn't vouch for, which outputs warn of; a source's first record that came with
# Add new evidence is a note
UNVOUCHED_WARNS = ("break", "no_head")
TAG_DECISIONS = ("dismissed", "restored")
SYSTEM = "glessner"   # the 'who' for entries the app writes itself, such as built-in rules
# Every name the app has written as its own 'who': journals from before the rename say triage-workbench and
# stay as written, so a comparison with SYSTEM accepts either.
APP_NAMES = frozenset({SYSTEM, "triage-workbench"})
# A lane a split makes: a computer name's characters, upper case, as the
# events table, filters, and page show a host name. splits.py cleans recorded names into this form.
SPLIT_OPS = ("split", "undo", "keep")
LANE = re.compile(r"[A-Z0-9][A-Z0-9_-]{0,62}")
# The fields of each action that name events by ID, which a case format upgrade's rekey reads through (translate). An
# undo's changes name theirs by their own actions. Every action has an entry, so a new one can't be left out
# (tests/test_rekey_journal.py).
ID_FIELDS: dict[str, tuple[str, ...]] = {
    "mark": ("targets",), "tag": ("targets",), "tag_suggestion": ("targets",), "suggestion_decision": ("targets",),
    "note": ("target",), "note_retract": ("target",), "undo": ("changes",),
    "host_role": (), "host_identity": (), "host_offset": (), "case_setting": (), "rule_add": (), "rule_change": (),
    "rule_remove": (), "host_split": (), "case_open": (), "case_upgrade": (),
    "case_created": (), "case_yaml": (), "journal_recovered": (), "chain_break": (),
    # A finding's `finding` is an entry number, not an event ID, so only its targets are read through a rekey
    "followup": ("targets",), "finding": ("targets",), "file_written": (), "manifest_recorded": (),
}
EVENT_ID = re.compile(r"[0-9a-f]{32}")   # events.event_uid's form; a repeat's ordinal is inside the hash
REKEYED = "ids_changed_at"   # what translate adds to an entry whose IDs it changed: the rekeys' entry numbers
# What _apply raises on a payload it can't read, such as a changed line's, or an unchained line's Infinity, which json
# reads and int() refuses with OverflowError; and what check(keep=True) adds to such an entry, naming the error, so the
# trail can show it
REPLAY_ERRORS = (KeyError, TypeError, ValueError, AttributeError, IndexError, OverflowError)
DAMAGED = "damaged"
SKIPPED = "it fails against the entries before it"   # why a line the state left out is marked, when _damage found nothing

# A chained line's envelope, its first keys in this order, before the action's payload
ENVELOPE = ("seq", "prev", "at", "who", "build", "client", "action")
CLIENTS = ("server", "cli")   # the kind of process that wrote a chained line
ZERO = "0" * 64   # the prev of the chain's first line
SHA256 = re.compile(r"[0-9a-f]{64}")
LOCK_FILE = "journal.lock"   # byte 0 is locked by the process writing the journal
LOCK_GATE = 1   # journal.lock's byte a writer takes on its way to byte 0, and holds while it waits for it
LOCK_WAIT = 10.0   # seconds an append waits for another writer of the case, in this process or another
LOCK_RETRY = 0.01   # seconds between a writer's tries of the gate
# Seconds between tries of byte 0 by the writer that holds the gate, whose turn is next. The lock stays idle from a
# release to that writer's next try, so this is short; only the one writer at the gate tries this often.
LOCK_TURN_RETRY = 0.001
SIDE_GLOB = "journal_torn_*.bin"   # a torn last line's bytes, kept byte for byte
SIDE_FILE = re.compile(r"journal_torn_[^\\/]+\.bin")
BUSY = ("Another Glessner process is writing this case's journal and didn't finish within 10 seconds. Try again; if it "
        "keeps happening, close the other Glessner window or command that has the case open.")
# A general append on a journal with no chained line: only the upgrade's record writes there
NO_CHAIN = ("The case's journal has no hash chain yet, so this build adds nothing to it until the case is upgraded to "
            "format 3. Opening the case for work, or any command that writes to it, upgrades it first.")


class JournalError(Exception):
    """Raised for an action the journal does not accept."""


@dataclass
class Mark:
    value: str
    note: str
    seq: int
    at: str
    who: str


@dataclass
class HostEdits:
    role: str = ""
    role_who: str = ""         # who set the role, and when, from the journal entry
    role_at: str = ""
    add_names: set[str] = field(default_factory=set)
    remove_names: set[str] = field(default_factory=set)
    add_ips: set[str] = field(default_factory=set)
    remove_ips: set[str] = field(default_factory=set)
    offset_seconds: float = 0.0
    offset_align: str = ""     # the latest offset entry's `align` from the Case panel's switch; "" when typed


@dataclass
class State:
    """Analysis state after replaying the journal."""
    marks: dict[str, Mark] = field(default_factory=dict)        # event_uid -> latest non-default mark
    notes: dict[str, list[dict]] = field(default_factory=dict)   # event_uid -> notes in order
    hosts: dict[str, HostEdits] = field(default_factory=dict)
    settings: dict[str, object] = field(default_factory=dict)
    rules: dict[str, dict] = field(default_factory=dict)          # rule id -> {"text", "builtin", "seq", "who"}
    removed_rules: set[str] = field(default_factory=set)          # so a removed built-in rule stays removed
    rejected: set[tuple[str, str]] = field(default_factory=set)   # (event_uid, suggestion source) the analyst rejected
    tags: dict[str, dict[str, dict]] = field(default_factory=dict)   # event_uid -> tag key -> {seq, at, who, via}
    dismissed_tags: set[tuple[str, str]] = field(default_factory=set)   # (event_uid, tag key) suggestions dismissed
    # Host splits by recorded computer: host -> computer key -> lane, the splits in force on each host
    # ({seq, at, who, lanes}), host -> the computer keys that raise no notice (kept as one host, or left on the host by
    # a split on purpose), and host -> the Keep as one host entry in force ({seq, at, who})
    splits: dict[str, dict[str, str]] = field(default_factory=dict)
    split_info: dict[str, list[dict]] = field(default_factory=dict)
    kept: dict[str, set[str]] = field(default_factory=dict)
    kept_info: dict[str, dict] = field(default_factory=dict)
    # The rekeys of case format upgrades in journal order, each case_upgrade entry's `rekey` with its number: for an
    # old ID's event (renamed) and the events an unplaced ID may have meant (unplaced)
    rekeys: list[dict] = field(default_factory=list)
    # The analyst's records: the events ticked Followed up, event_uid -> {seq, at, who}; the findings
    # by the number of their add; the files the case wrote, in journal order; and a rejection's note, by (event_uid,
    # suggestion source) -> {text, seq, at, who}
    followed: dict[str, dict] = field(default_factory=dict)
    findings: dict[int, dict] = field(default_factory=dict)
    files: list[dict] = field(default_factory=list)
    decision_notes: dict[tuple[str, str], dict] = field(default_factory=dict)
    # The chained records of manifest.jsonl in journal order, each {seq, at, who, sha256, bytes, lines, via},
    # and a copy's unvouched reasons when it names any
    manifests: list[dict] = field(default_factory=list)
    last_seq: int = 0


@dataclass
class Chain:
    """Where a read of the journal stands and what it found of the hash chain."""
    offset: int = 0          # bytes of the lines read, each ended by its LF
    lines: int = 0
    nonblank: int = 0        # lines read that aren't blank, which a seal counts
    last: int = 0            # where the last line read starts
    chained: bool = False    # whether the chain's first line has been read
    # Whether a chained line has been read that closes the place of REKEY_STEP's rekey for the lines after it (_past_step)
    past_step: bool = False
    head: str = ZERO         # SHA-256 of the last chained line read, whatever it holds: the journal's head
    seq: int | None = None   # the number the chain is at; an unreadable line takes one
    entries: int = 0         # chained lines read
    start: dict | None = None   # the chain's first line: {line, seq, action}
    crlf: int = 0            # lines read that end in CR, as a conversion of line endings leaves every one
    # Each break, {line, seq, kind, text}, since the last chain_break whose seal matches, which puts those before it on
    # record: each such entry as {line, seq, breaks}
    breaks: list[dict] = field(default_factory=list)
    on_record: list[dict] = field(default_factory=list)


def _break(line: int | None, seq, kind: str, text: str) -> dict:
    return {"line": line, "seq": seq, "kind": kind, "text": text}


# The line, its bytes, and how every reader parses it

def line_bytes(entry: dict) -> bytes:
    """An entry's line as the journal stores it: UTF-8 with no byte order mark, json's default separators, every
    character but those json escapes as its own bytes, so a line's one LF ends it, and no NaN or infinity. A lone
    surrogate, which a request body's "\\ud800" decodes to, can't be written in UTF-8, so it is refused here, before the
    file is opened."""
    try:
        return json.dumps(entry, ensure_ascii=False, allow_nan=False).encode("utf-8") + b"\n"
    except UnicodeEncodeError as exc:
        raise JournalError("The entry holds text that UTF-8 can't write, such as half of a surrogate pair") from exc
    except ValueError as exc:   # allow_nan=False
        raise JournalError(f"The entry holds a number the journal doesn't write: {exc}") from exc


def _unique(pairs: list[tuple[str, object]]) -> dict:
    if len({k for k, _ in pairs}) != len(pairs):
        raise ValueError("a key appears twice")
    return dict(pairs)


def _finite(name: str):
    raise ValueError(f"{name} isn't a number the journal writes")


def _float(text: str) -> float:
    """A number with a fraction or exponent, which json reads as inf when it overflows, such as 1e999: not finite either."""
    value = float(text)
    if value in (float("inf"), float("-inf")):
        _finite(text)
    return value


def strict(raw: bytes) -> dict | None:
    """A chained line's entry: one JSON object of unique keys and finite numbers in strict UTF-8, or None. json.loads
    keeps the last of two repeated keys where other tools keep the first, so one hashed line could mean two things."""
    try:
        entry = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique, parse_constant=_finite, parse_float=_float)
    except (ValueError, RecursionError):   # UnicodeDecodeError and JSONDecodeError are ValueErrors
        return None
    return entry if isinstance(entry, dict) else None


def parse_line(raw: bytes) -> dict | None:
    """A line's entry by the rule every reader shares: strictly for a line that names `prev`, by any JSON spelling, and as
    format 2's reader parses an unchained line otherwise. None for a line its rule refuses, or that isn't a JSON
    object."""
    entry = strict(raw)
    if entry is not None or b'"prev"' in raw:
        return entry
    entry = _format2(raw)
    return None if entry is not None and "prev" in entry else entry   # prev spelled with an escape, which strict refused


def _format2(raw: bytes) -> dict | None:
    """An unchained line's entry as format 2's reader parsed it, or None for one that isn't a JSON object."""
    try:
        entry = json.loads(raw)
    except (ValueError, RecursionError):
        return None
    return entry if isinstance(entry, dict) else None


def _chained(raw: bytes) -> bool:
    """Whether a line is a chained one: an entry that names `prev`, by any JSON spelling, as the checker reads the parsed
    keys. A key spelled other than by its plain letters has a \\u escape, so only a line holding `"prev"` or `\\u` is
    parsed."""
    return (b'"prev"' in raw or b"\\u" in raw) and (entry := strict(raw)) is not None and "prev" in entry


def _number(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def lacks(entry: dict) -> str | None:
    """What a chained line's envelope lacks, or None. Its prev is checked against the line before it."""
    if not _number(entry.get("seq")):
        return f"seq {entry.get('seq')!r} isn't an integer"
    missing = [k for k in ("at", "who", "build", "action") if not (isinstance(entry.get(k), str) and entry[k])]
    missing += [] if entry.get("client") in CLIENTS else ["client"]
    return f"no {', '.join(missing)} in the envelope" if missing else None


def _replayable(entry: dict) -> bool:
    """Whether replay can apply an entry: it reads seq, at, who, and the action."""
    return _number(entry.get("seq")) and all(isinstance(entry.get(k), str) for k in ("at", "who", "action"))


# The one upgrade up to this build's format that carries a rekey of event IDs after the chain starts: the step from
# format 3 to 4, which gives found output the IDs its path under the evidence folder makes (rekey.upgrade_format_4)
REKEY_STEP = (3, 4)
# The action words of the lines that close that step's place (_past_step), which the readers that scan a journal for its
# rekeys or for that place parse a line for (_may_close)
STEP_WORDS = (b'"case_created"', b'"case_upgrade"', b'"manifest_recorded"')


def _may_close(raw: bytes) -> bool:
    """Whether a line's bytes may be one that closes the step's place (_past_step), and so are parsed: they name one of
    STEP_WORDS, or hold a backslash-u escape, which can spell any of them another way."""
    return b"\\u" in raw or any(word in raw for word in STEP_WORDS)


def _past_step(entry: dict | None) -> bool:
    """Whether a chained line closes the place of REKEY_STEP's rekey for the lines after it: the step's own entry,
    whatever it holds; a case_created that says the case began at format 4 or later (`case_format`); or a
    manifest_recorded, which only a case at format 4 or later holds. `entry` is the line as every reader parses a chained
    line (strict), None when it isn't one JSON object. A rekey that follows such a line can't be the step's."""
    if entry is None:
        return False
    action = entry.get("action")
    if action == "case_upgrade":
        old, new = entry.get("from_format"), entry.get("to_format")
        return _number(old) and _number(new) and (old, new) == REKEY_STEP
    if action == "case_created":
        return _number(entry.get("case_format")) and entry["case_format"] >= REKEY_STEP[1]
    return action == "manifest_recorded"


def _past_before(path: Path, at: int) -> bool:
    """_past_step for the chained lines of the journal before byte `at`, read from the file's start as _read reads them."""
    chained = past = False
    with path.open("rb") as f:
        while f.tell() < at and (line := f.readline()):
            raw = line[:-1]
            chained = chained or _chained(raw)
            if chained and not past and _may_close(raw):
                past = _past_step(strict(raw))
    return past


def _described(rekey: dict) -> bool:
    """Whether a rekey describes its map as the step in REKEY_STEP writes it: the runs it read, its pairs as a map, and the
    size and SHA-256 of the whole map, which holds at least its pairs."""
    runs, pairs, size, digest = rekey.get("runs"), rekey.get("pairs"), rekey.get("map_size"), rekey.get("map_sha256")
    return (isinstance(runs, dict) and bool(runs) and isinstance(pairs, dict) and _number(size) and size >= len(pairs)
            and isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest) is not None)


def _rekey_ok(entry: dict, chained: bool, past: bool = False) -> bool:
    """Whether a rekey entry (is_rekey) is one a build of this format can have written. A rekey re-points every earlier
    entry's event IDs, so it is the one append that must not come from anyone. Before the chain starts, an unchained line
    is format 2's step. Once it has, no unchained line is, and a chained one is the step in REKEY_STEP with its map
    described (_described) and before any line that closes its place (`past`, _past_step), or a later format's upgrade,
    from a format that has the chain to one above CASE_FORMAT: no other step this build runs after the chain starts
    carries one. `chained` is whether a chained line came before."""
    if "prev" not in entry:
        return not chained
    old, new = entry.get("from_format"), entry.get("to_format")
    if not (_number(old) and _number(new) and old >= FIRST_CHAINED):
        return False
    return new > max(old, CASE_FORMAT) or ((old, new) == REKEY_STEP and not past and _described(entry["rekey"]))


def _rekey_break(entry: dict, past: bool = False) -> tuple[str, str]:
    """The (kind, text) of a chained rekey that _rekey_ok refuses, or ("", "") for any other entry."""
    if not is_rekey(entry) or _rekey_ok(entry, False, past):
        return "", ""
    return "rekey", (f"a rekey of event IDs, from format {entry.get('from_format')!r} to {entry.get('to_format')!r}, "
                     "which no build of this format writes: after the chain starts, only a later format's upgrade carries "
                     "one, and the step from format 3 to 4 when it describes its map and comes before the case's "
                     "format 4 entries and before any other step from 3 to 4")


def _follows(entry: dict, chain: Chain, path: Path | None = None) -> bool:
    """Whether a chained entry is the chain's next: a whole envelope, prev naming the head, the next number, and not a
    rekey of event IDs no build of this format writes (_rekey_break), which would be a break once its line end is added.
    Before the chain's first line it is the entry that starts the chain (_starts, which reads the seal's bytes from
    `path`), so a first line missing only its LF is the chain's start as it would be with it."""
    if "prev" not in entry or lacks(entry) or entry["prev"] != chain.head or _rekey_break(entry, chain.past_step)[0]:
        return False
    if chain.chained:
        return _number(chain.seq) and entry["seq"] == chain.seq + 1
    return path is not None and _starts(path, entry, chain)


def _prefix_sha256(path: Path, size: int) -> str:
    """The SHA-256 of the file's first `size` bytes, which a seal covers."""
    digest = hashlib.sha256()
    with path.open("rb") as f:
        while size > 0 and (block := f.read(min(size, 1 << 20))):
            digest.update(block)
            size -= len(block)
    return digest.hexdigest()


def _seal_matches(path: Path, sealed, size: int, lines: int) -> bool:
    """Whether a seal names every byte before its line: their count, the lines among them that aren't blank, and their
    SHA-256."""
    return (isinstance(sealed, dict) and sealed.get("bytes") == size and sealed.get("lines") == lines
            and sealed.get("sha256") == _prefix_sha256(path, size))


def _starts(path: Path, entry: dict, chain: Chain) -> bool:
    """Whether the first chained line starts the chain: prev of 64 zeros, and case_created at byte 0 or a seal that
    matches every byte before it."""
    if entry.get("prev") != ZERO:
        return False
    if entry.get("action") == "case_created":
        return chain.offset == 0 and entry.get("seq") == 1
    return entry.get("action") == "case_upgrade" and _seal_matches(path, entry.get("sealed"), chain.offset,
                                                                    chain.nonblank)


def _link(path: Path, raw: bytes, chain: Chain, n: int) -> tuple[dict | None, str, str]:
    """A chained line's entry, None when it isn't one JSON object, and its break as (kind, text), "" for none, in the
    words of scripts/check_journal.py."""
    entry = strict(raw)
    if not chain.chained:   # the first chained line: its envelope, then where the chain starts
        if problem := lacks(entry):
            return entry, "envelope", problem
        if _starts(path, entry, chain):
            return entry, *_rekey_break(entry, chain.past_step)
        return entry, "chain_missing", (f"the chain must start with case_created at the top, or with a seal that matches "
                                        f"the {chain.offset:,} bytes before it")
    if not raw.strip():
        return None, "blank", "a blank line inside the chain"
    if entry is None:
        return None, "unreadable", "not one JSON object of unique keys and finite numbers in UTF-8"
    if "prev" not in entry:
        return entry, "no_prev", ("no prev, so a build from before format 3 wrote it, such as one still running from "
                                  "before the upgrade")
    # The envelope before prev: replay is given no line whose envelope is incomplete, whatever its prev, and _rekeys
    # lists no such rekey
    if problem := lacks(entry):
        return entry, "envelope", problem
    if entry["prev"] != chain.head:
        return entry, "prev", (f"prev doesn't match line {n - 1}, which changed, or a line was removed, inserted, or "
                               "moved here")
    if _number(chain.seq) and entry["seq"] != chain.seq + 1:
        return entry, "seq", f"seq {entry['seq']} doesn't follow {chain.seq}"
    return entry, *_rekey_break(entry, chain.past_step)


def _unchained(path: Path, raw: bytes, n: int, f, *, stop: bool) -> dict | None:
    """A whole unchained line's entry, parsed as format 2's reader parsed it; None for a blank one. A line that isn't a
    JSON object stops the read with its number when `stop`, as format 2's reader stopped, unless a chained line follows
    it: the seal over it can't match then, and that is the break."""
    if not raw.strip():
        return None
    try:
        entry = json.loads(raw)
    except (ValueError, RecursionError) as exc:
        problem = str(exc)
    else:
        if isinstance(entry, dict):
            return entry
        problem = "not a JSON object"
    if stop and not _chain_follows(f):
        raise JournalError(f"{path} line {n} is not valid JSON: {problem}")
    return None


def _chain_follows(f) -> bool:
    """Whether a chained line follows the file's position, which is kept."""
    at = f.tell()
    try:
        return any(_chained(line.rstrip(b"\n")) for line in iter(f.readline, b""))
    finally:
        f.seek(at)


def _at_end(f) -> bool:
    at = f.tell()
    more = f.read(1)
    f.seek(at)
    return not more


# The shared reader

def _read(path: Path, chain: Chain, *, format2: bool = True, skip: set[int] | None = None,
          restarted: set[int] | None = None) -> Iterator[tuple[dict, str | None]]:
    """The journal's entries from where `chain` stands, each read through the rekeys that follow it in the file
    (translate), with its line's SHA-256, or None for an unchained line. `chain` moves past a line only when the next
    entry is asked for, so an entry is applied once, also when a later line stops the read. The lines
    numbered in `skip` are hashed and chained like any other but not given: replay couldn't apply them.

    Lines before the chain's first are format 1's and 2's, parsed as format 2 read them. From the first chained line on,
    each line's bytes are hashed, parsed strictly, and checked: the envelope, prev, seq, and the chain's start. A break
    goes on chain.breaks and the read goes on, so a broken journal can still be viewed; a line that isn't a whole entry
    is not given for replay. Translation comes after the hash and the checks, so the chain never depends on a rekey.

    The read stops at the last LF, and before a last line holding 0x00, which json.dumps never writes: either is a write
    in progress, or a crash's. An unchained journal's is too, so a torn format 2 journal reaches the upgrade's mend
    instead of stopping the read. With `format2`, a whole unchained line that doesn't parse stops the read with its
    number, as format 2's reader stopped, unless a chained line follows it. A rekey that the first pass didn't see,
    appended between the two, raises _Reread when entries before it have been given, since they weren't read through
    it, and its line goes in `restarted`, the lines the caller started its read again for. A rekey the first pass
    misses on a line already there, or for a caller that passes none, is a break and is not given, so a reader starts
    again at most once for each line. A rekey _apply can't take, which the first pass leaves out, is given as it is,
    for the state to leave out, and translates nothing."""
    rekeys = _rekeys(path, chain.offset, chain.lines, chain.chained, chain.past_step)
    given = False
    with path.open("rb") as f:
        f.seek(chain.offset)
        while line := f.readline():
            whole = line.endswith(b"\n")
            raw = line[:-1] if whole else line
            if not whole or (b"\0" in raw and _at_end(f)):
                return
            chained = chain.chained or _chained(raw)
            n = chain.lines + 1
            h, kind, text, sealed = None, "", "", None
            if chained:
                h = hashlib.sha256(raw).hexdigest()
                parsed, kind, text = _link(path, raw, chain, n)
                entry = parsed if parsed is not None and kind != "envelope" and _replayable(parsed) else None
                if parsed is not None and parsed.get("action") == "chain_break":
                    sealed = _seal_matches(path, parsed.get("sealed"), chain.offset, chain.nonblank)
            else:
                parsed = entry = _unchained(path, raw, n, f, stop=format2)
            if entry is not None and is_rekey(entry) and not _rekey_ok(entry, chain.chained, chain.past_step):
                entry = None   # a rekey no build of this format wrote translates nothing; the case shows it as a break
            if skip and n in skip:
                entry = None
            if (entry is not None and given and is_rekey(entry) and _applies(entry)
                    and not (rekeys and rekeys[0][0] == n)):
                if restarted is not None and n not in restarted:
                    restarted.add(n)
                    raise _Reread
                entry = None
                if not kind:
                    chain.breaks.append(_break(n, parsed.get("seq"), "rekey", (
                        "a rekey of event IDs that the reader's pass for rekeys doesn't find, also when read again, so "
                        "it translates nothing")))
            if entry is not None:
                while rekeys and rekeys[0][0] <= n:   # the rekeys still ahead of this line
                    rekeys.pop(0)
                yield (translate(entry, [r for _, r in rekeys]) if rekeys else entry), h
                given = True
            chain.offset, chain.last, chain.lines = chain.offset + len(line), chain.offset, n
            chain.nonblank += bool(raw.strip())
            chain.crlf += raw.endswith(b"\r")
            if h is None:
                continue
            seq = parsed.get("seq") if parsed is not None else None
            if not chain.chained:
                chain.chained = True
                chain.start = {"line": n, "seq": seq, "action": parsed.get("action")}
            chain.head = h
            chain.entries += 1
            chain.past_step = chain.past_step or _past_step(parsed)
            if _number(seq):
                chain.seq = seq
            elif _number(chain.seq):
                chain.seq += 1   # an unreadable line takes one number
            if sealed:   # the breaks before it are on record now
                chain.on_record.append({"line": n, "seq": seq, "breaks": chain.breaks})
                chain.breaks = []
            elif sealed is False:
                chain.breaks.append(_break(n, seq, "seal", "a chain_break whose seal of the lines before it doesn't "
                                                           "match: lines it put on record changed after it"))
            if kind:
                chain.breaks.append(_break(n, seq, kind, text))


class _Reread(Exception):
    """A rekey reached after entries before it were read without it: _read's first pass for rekeys ran before another
    writer appended it. The reader starts again from the first line, once for each such line."""


def _rekeys(path: Path, start: int, lines: int, chained: bool, past: bool = False) -> list[tuple[int, dict]]:
    """The rekey entries from byte `start` on, which follows line `lines`, each with its line's number; `chained` is
    whether a chained line came before, and `past` whether one that closes the place of REKEY_STEP's rekey did
    (_past_step), which the scan keeps up as it reads. They must be the lines _read gives as rekeys, or the read starts again
    (_Reread) and then reports the rekey as a break, so each whole line is parsed as the read parses it: strictly once
    the chain has started or for a chained line, as format 2's reader parsed it otherwise, and the scan stops where the
    read stops. Only lines that name both words are parsed, lines with a \\u escape, which can spell either another
    way, and lines holding 0x00: json also reads UTF-16 and UTF-32, which spell each ASCII character with 0x00 bytes.
    A chained rekey line whose envelope is incomplete is never applied, whatever its prev, as the read gives no such
    line for replay; an unchained one is, as format 2 read it, whatever its envelope holds. Nor is one _rekey_ok
    refuses, such as an unchained line after the chain started, or one _apply can't take, which the state leaves out,
    so it re-points no event ID for any reader. A line that isn't JSON is left to the read itself."""
    found = []
    with path.open("rb") as f:
        f.seek(start)
        while line := f.readline():
            raw = line[:-1]
            if not line.endswith(b"\n") or (b"\0" in raw and _at_end(f)):
                break   # the read stops at the last LF, and before a last line holding 0x00
            lines += 1
            now = chained or _chained(raw)   # whatever its spelling of prev, as _read decides
            if (b"\\u" in raw or b"\0" in raw or (b'"rekey"' in raw and b'"case_upgrade"' in raw)
                    or (now and not past and _may_close(raw))):
                entry = strict(raw) if now else _format2(raw)
                if (entry is not None and is_rekey(entry) and not (now and lacks(entry)) and _rekey_ok(entry, chained, past)
                        and _applies(entry)):
                    found.append((lines, entry))
                past = past or (now and _past_step(entry))
            chained = now
    return found


# The held context: one lock per case folder per process, and the OS lock across processes

@dataclass
class _Hold:
    lock: threading.RLock = field(default_factory=threading.RLock)
    depth: int = 0           # holds by the thread that has the lock; the OS lock is taken at the first
    fd: int | None = None    # journal.lock, its byte 0 locked while depth > 0


_HOLDS: dict[str, _Hold] = {}
_HOLDS_LOCK = threading.Lock()


def _hold_of(path: Path) -> _Hold:
    key = os.path.normcase(str(path.resolve()))
    with _HOLDS_LOCK:
        return _HOLDS.setdefault(key, _Hold())


@contextmanager
def held(path: Path) -> Iterator[None]:
    """The journal at `path` held for writing, by this thread: every Journal of the case folder in this process shares
    one re-entrant lock, so code that holds it can append, such as the upgrade's record inside its step, and two Journal
    objects of one case take turns. The first hold of the process also takes the OS lock, byte 0 of
    journal.lock, which keeps another process's writer out: Windows' byte-range locks are mandatory, so a lock on
    the journal's own bytes would block its readers. A process that lets go of the OS lock and comes back for it can't
    take it ahead of a process holding the gate (_take_os_lock). Each waits up to LOCK_WAIT seconds, then raises
    JournalError."""
    hold = _hold_of(path)
    if not hold.lock.acquire(timeout=LOCK_WAIT):
        raise JournalError(BUSY)
    try:
        if not hold.depth:
            hold.fd = _take_os_lock(path.parent / LOCK_FILE)
        hold.depth += 1
        try:
            yield
        finally:
            hold.depth -= 1
            if not hold.depth:
                fd, hold.fd = hold.fd, None
                _release_os_lock(fd)
    finally:
        hold.lock.release()


def _take_os_lock(path: Path) -> int:
    """journal.lock opened, and its byte 0 locked, through the gate at LOCK_GATE: the writer takes the gate, waits for
    byte 0 holding it, then lets go of it. A holder that lets go of byte 0 and comes back meets the gate, so the writer
    waiting there takes byte 0 first, at its next try; writers still waiting for the gate pass it in no set order. The
    gate is tried every LOCK_RETRY seconds and byte 0 every LOCK_TURN_RETRY, and the wait for both together lasts at
    most LOCK_WAIT; then JournalError is raised and the file closed, holding nothing. Windows lets go of a killed
    process's locks, but a process stopped while it waits keeps the gate, so it blocks other writers as a stopped
    writer does."""
    fd = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_BINARY", 0))
    deadline = time.monotonic() + LOCK_WAIT
    try:
        _wait_for(fd, LOCK_GATE, deadline, LOCK_RETRY)
        try:
            _wait_for(fd, 0, deadline, LOCK_TURN_RETRY)
        finally:
            _unlock(fd, LOCK_GATE)
    except BaseException:
        os.close(fd)
        raise
    return fd


def _wait_for(fd: int, byte: int, deadline: float, retry: float) -> None:
    """The byte locked, tried every `retry` seconds until the deadline, then JournalError."""
    while not _try_lock(fd, byte):
        if time.monotonic() >= deadline:
            raise JournalError(BUSY)
        time.sleep(retry)


def _try_lock(fd: int, byte: int = 0, shared: bool = False) -> bool:
    """Whether one try locked the byte. msvcrt.locking locks from the file's position, so the try seeks to it first."""
    os.lseek(fd, byte, os.SEEK_SET)
    try:
        if msvcrt is not None:
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        else:   # a shared lock for check's read-only handle, which can't take an exclusive one there
            fcntl.lockf(fd, (fcntl.LOCK_SH if shared else fcntl.LOCK_EX) | fcntl.LOCK_NB, 1, byte)
    except OSError:
        return False
    return True


def _unlock(fd: int, byte: int) -> None:
    with suppress(OSError):
        os.lseek(fd, byte, os.SEEK_SET)
        if msvcrt is not None:
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        else:
            fcntl.lockf(fd, fcntl.LOCK_UN, 1, byte)


def _release_os_lock(fd: int | None) -> None:
    if fd is None:
        return
    _unlock(fd, 0)
    os.close(fd)


def _writing(path: Path) -> bool:
    """Whether a writer holds the journal's lock now, so bytes after its last LF are a write in progress: a thread of
    this process, or another process, whose lock check tries once from journal.lock opened read-only, and only when it
    exists, so a check creates no file in the folder it checks."""
    hold = _HOLDS.get(os.path.normcase(str(path.resolve())))
    if hold is not None and hold.depth:
        return True
    # Off Windows, closing any descriptor of journal.lock lets go of every lock this process holds on it, so a check
    # from another thread while this process takes the lock drops what it took: the gate, or byte 0 before held()
    # counts the hold.
    try:
        fd = os.open(path.parent / LOCK_FILE, os.O_RDONLY | getattr(os, "O_BINARY", 0))
    except OSError:
        return False
    try:
        if _try_lock(fd, shared=True):
            _unlock(fd, 0)
            return False
        return True
    finally:
        os.close(fd)


def _write_all(f, data: bytes) -> None:
    """All of `data` through an unbuffered file, which may take fewer bytes in one write."""
    view = memoryview(data)
    while view:
        view = view[f.write(view):]


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class Journal:
    """A case's journal: its state, read once and followed as the file grows. Every Journal of a case folder in this
    process shares one held context, so two of them, such as the retiring and the new App of a reopened case, take turns
    and number their entries in order. `client` is the kind of process, server or cli, which each
    chained line names."""

    def __init__(self, case: Case, client: str = "cli"):
        if client not in CLIENTS:
            raise ValueError(f"client is one of {CLIENTS}")
        self.path = case.folder / JOURNAL_FILE
        self.who = case.settings.analyst
        self.client = client
        self.path.touch(exist_ok=True)
        self.state = State()
        self.build = ""   # the build the newest case_open entry names; kept outside the state, which replay builds
        self.chain = Chain()
        # Breaks found outside the read, under the lock: the newest line changed, the bytes after the last LF, and the
        # head recorded outside the case
        self.problems: list[dict] = []
        # What this object's first check found of the head recorded outside the case: {seq, at, after}, `after` counting
        # the entries that follow it by action; None without a record. An upgrade step's entry moves the record before
        # the open checks it again, so the open keeps the first check's count
        self.recorded: dict | None = None
        self._record_checked = False   # whether this object has run that first check
        self.recovered: list[dict] = []   # the journal_recovered entries this object wrote
        self._opened = False   # whether this object has run the checks of an open for work
        self._case_yaml: str | None = None   # case.yaml's SHA-256 as the journal last recorded it
        # The record is read before the first read, which keeps the hash of each chained line from its number on, so the
        # check under the lock finds a record that moved forward meanwhile
        self._record = heads.read(self.path.parent)
        self._kept: list[tuple[str, int, str]] = []   # (hash, seq, action)
        # The lines replay couldn't apply, by number: kept across _reset, so a rebuilt state leaves them out too
        self._skip: set[int] = set()
        self._catch_up()

    @property
    def _read(self) -> tuple[int, int]:
        """The bytes and lines of the file the state holds."""
        return self.chain.offset, self.chain.lines

    @property
    def skipped_lines(self) -> frozenset[int]:
        """The numbers of the lines replay couldn't apply, which the state leaves out, as a copy."""
        return frozenset(self._skip)

    @property
    def breaks(self) -> list[dict]:
        """The chain's breaks not on record, those of the read first."""
        return self.chain.breaks + self.problems

    @property
    def read_only(self) -> str:
        """Why the journal refuses writes, or "": a break in its chain."""
        if not (found := self.breaks):
            return ""
        first = found[0]
        where = f"line {first['line']}: " if first["line"] else ""
        if first["kind"] == "chain_missing":   # nothing to put on record: Continue needs a chain, and record_break refuses
            return (f"The journal was changed after it was written: {where}{first['text']}. Copy the case folder and "
                    "investigate first: Continue with the break on record is offered once the journal has a chained line.")
        text = (f"The journal was changed after it was written: {where}{first['text']}. Continue with the break on record "
                "from the Case overview, or copy the case folder and investigate first.")
        if first["kind"] == "no_prev":
            text += " An older Glessner build may still be running, or was started before this case was upgraded."
        return text

    def held(self):
        return held(self.path)

    def refresh(self) -> None:
        """Apply the entries other writers added since this object last read the file, under the held context, so a
        check of the state that decides an entry, such as whether a finding is retired, reads what the append will
        follow (lock order: the caller takes app.lock first)."""
        with self.held():
            self._catch_up()

    def note_breaks(self, found: Check) -> list[dict]:
        """The breaks a full check found (the audit trail, an undo, a report, close, Check now), which this
        object's read can't have seen when an older line changed after it: they put the journal in read-only mode, as a
        break found at the open does. The breaks found, the chain's missing start included."""
        breaks = list(found.chain.breaks) + [p for p in found.problems if p["kind"] == "chain_missing"]
        known = {(b["line"], b["kind"]) for b in self.breaks}
        self.problems += [b for b in breaks if (b["line"], b["kind"]) not in known]
        return breaks

    def full_check(self, keep: bool = False) -> tuple[Check, dict | None]:
        """The full check with the head this app recorded outside the case (the audit trail, an undo, a report,
        close, Check now), and the record it compared. The record is read first: it only moves forward, after its line
        is written, so the read that follows holds the line it names. A record naming no line is the open's "recorded
        head missing". What it finds puts the journal in read-only mode, as a break found at the open does. With `keep`,
        the entries the state left out (self._skip) are marked with those _apply can't take, so the trail and the state
        agree on them."""
        record = heads.read(self.path.parent)
        found = check(self.path, record["head"] if record else None, keep=keep, skip=self._skip)
        self.note_breaks(found)
        started = found.chain.chained or found.tail == "missing_lf"   # a first line missing only its LF starts it
        if record and started and not found.expected and not any(
                p["kind"] == "record_missing" for p in self.problems):
            self.problems.append(_break(None, record["seq"], "record_missing",
                                        f"the head this app recorded at {record.get('at', '')}, entry #{record['seq']}, "
                                        "is no line of the journal: its newest entries were removed or changed, or the "
                                        "journal was replaced"))
        return found, record

    def append(self, action: str, who: str | None = None, **payload) -> dict:
        """Validate, write, and flush one action, then apply it to the in-memory state. Entries
        another writer added since this one last read the file, such as the close command's beside a running server,
        are applied first, so the action takes the next number."""
        if action == "chain_break":
            raise JournalError("A chain_break is written by Continue with the break on record (Journal.record_break)")
        _validate(action, payload)
        if repeated := [k for k in payload if k in ENVELOPE and not (action == "case_open" and k == "build")]:
            raise JournalError(f"The entry's payload repeats the envelope's {', '.join(repeated)}")
        line_bytes({"action": action, **payload})   # a lone surrogate or NaN is refused before the file is opened
        with self.held():
            return self._append_locked(action, who, payload)

    def record_build(self, build: str) -> dict | None:
        """Journal the build that opened the case for work, unless the journal's newest build entry names it already, so
        repeated opens by one build add nothing. A chained case_open has no payload: its envelope's
        build names the build, and an unchained one's payload does, under the same key. None when nothing was
        written."""
        with self.held():
            self._catch_up()
            if self.build == build:
                return None
            return self._append_locked("case_open", SYSTEM, {}, build=build)

    def open_for_work(self, then: Callable[[], object] | None = None, *, record_build: bool | None = None) -> None:
        """The open for work, which comes after the case upgrade and the read when this object was made. Under the held
        context: the lines added since, the newest line, the bytes after the last LF,
        and the head recorded outside the case. With no break, the recoveries, a journal_recovered entry for each side
        file no entry names, case_yaml when case.yaml changed, case_open when `record_build` (the server's open for
        work, by default a server's), `then`, such as the built-in rules, and the head record. On a break nothing is
        written, and read_only says why. A journal with no chained line is "chain missing": the open comes after the
        upgrade, which starts the chain, so its chained lines were removed. A first line cut just before its LF is the
        chain (started): _prepare ends it and records that."""
        with self.held():
            self._catch_up()
            if not self.started():
                if not any(p["kind"] == "chain_missing" for p in self.problems):
                    self.problems.append(_break(None, None, "chain_missing", "the journal has no chained line, so its "
                                                                             "hash chain is missing"))
                return
            self._prepare(first=True)
            if self.read_only:
                return
            if self.client == "server" if record_build is None else record_build:
                self.record_build(build_id())
            if then is not None:
                then()
            self._record_head()

    def check_for_upgrade(self) -> bool:
        """The checks an upgrade step from a format with the chain runs before its entry, or before its number when an
        earlier run journaled the entry, under the held context: the lines added since this object's read, then an
        append's checks (_prepare), which at this object's first are an open's, with what they write. KeptAtFormat when
        the journal has no chain or a break puts it in read-only mode: the case stays at its format and opens read-only.
        A lock that isn't free within LOCK_WAIT raises JournalError. Returns whether a line before the check closes the
        place of REKEY_STEP's rekey (_past_step), after which the step's entry may not carry one."""
        with self.held():
            self._catch_up()
            if not self.started():
                raise KeptAtFormat(self.read_only or "The journal has no hash chain")
            self._prepare()
            if reason := self.read_only:
                raise KeptAtFormat(reason)
            return self.chain.past_step

    def check_for_append(self) -> str:
        """An append's checks, run ahead of it by a writer that must not change a file the append would then refuse to
        record, such as Add new evidence's replace of manifest.jsonl: the lines added since this object's read, then
        _prepare, which at this object's first are an open's, with what they write. Returns why the append would be
        refused, or "". The caller holds the held context from here through its append, so no other writer can change
        the answer."""
        with self.held():
            self._catch_up()
            if not self.started():
                return self.read_only or NO_CHAIN
            self._prepare()
            return self.read_only

    def record_break(self, reason: str, who: str | None = None) -> dict:
        """Continue with the break on record: a chain_break entry with the reason, the breaks, and a seal of
        every byte before it, chained to the line just before it, whatever that line holds. Nothing is repaired. Bytes
        after the last LF get one, so the entry starts its own line and its seal covers them. A seal that matches, with
        no break after it, ends read-only mode, and a full check reports it for the life of the case."""
        if not (isinstance(reason, str) and reason.strip()):
            raise JournalError("Continuing with the break on record needs a reason")
        with self.held():
            self._catch_up()
            if not self.started():
                raise JournalError("The journal has no hash chain yet, so it has no break to put on record")
            self._prepare()
            if not self.read_only:
                raise JournalError("The journal's chain is consistent, so it has no break to put on record")
            if ends_open(self.path):
                self._write(b"\n")
            fresh = Chain()
            for _ in _read(self.path, fresh, format2=False):
                pass
            sealed, prev = _seal_of(self.path)
            seq = fresh.seq if _number(fresh.seq) else self.state.last_seq
            # A last line holding 0x00, at which the read stopped, is sealed too, and takes a number as unreadable
            tail = fresh.offset < sealed["bytes"]
            found = fresh.breaks + self.problems + ([_break(fresh.lines + 1, None, "unreadable", "")] if tail else [])
            entry = {"seq": seq + 1 + tail, "prev": prev, "at": _now(), "who": who or self.who, "build": build_id(),
                     "client": self.client, "action": "chain_break",
                     "breaks": [{"line": b["line"], "kind": b["kind"]} for b in found], "sealed": sealed,
                     "reason": reason.strip()}
            _validate("chain_break", {k: v for k, v in entry.items() if k not in ENVELOPE})
            self._write(line_bytes(entry))
            self._reset()
            self._catch_up()
            self._record_head()
            return entry

    def _append_locked(self, action: str, who: str | None, payload: dict, build: str | None = None) -> dict:
        """The write of one entry, inside the held context, which append and the open's own writers re-enter. A
        journal with no chained line is refused: only the upgrade's record writes there. A first line missing
        only its LF is the chain, and _prepare ends it first (started)."""
        self._catch_up()
        if not self.started():
            raise JournalError(self.read_only or NO_CHAIN)
        self._prepare()
        if reason := self.read_only:
            raise JournalError(reason)
        if action == "case_open" and payload:
            raise JournalError("A chained case_open has no payload: its envelope's build names the build")
        seq = self.chain.seq + 1 if _number(self.chain.seq) else self.state.last_seq + 1
        entry = {"seq": seq, "prev": self.chain.head, "at": _now(), "who": who or self.who,
                 "build": build or build_id(), "client": self.client, "action": action, **payload}
        self._write(line_bytes(entry))
        self._catch_up()
        self._record_head()
        return entry

    def append_unchained(self, action: str, who: str | None = None, **payload) -> dict:
        """Format 2's append, with no prev, build, or client, into a journal with no chained line: the upgrade's record
        of format 2's step, the one line a build of format 3 or later writes there. That step mends the bytes after
        the last LF first (mend_unchained), so a journal that still ends without one is refused here: this line would
        join or follow bytes the seal must cover whole."""
        _validate(action, payload)
        entry = {"seq": 0, "at": "", "who": "", "action": action, **payload}
        line_bytes(entry)   # a lone surrogate or NaN is refused before the file is opened
        with self.held():
            self._catch_up()
            if self.chain.chained:
                raise JournalError("The journal's hash chain has started, so an unchained line can't follow it")
            if _unended(self.path)[1]:
                raise JournalError(f"{self.path} ends in bytes without a line end, which the upgrade must mend first")
            entry = {"seq": self.state.last_seq + 1, "at": _now(), "who": who or self.who, "action": action, **payload}
            self._write(line_bytes(entry))
            self._catch_up()   # this entry, as a replay reads it
            return entry

    def seal(self, fields: dict) -> dict:
        """The upgrade's record of the 2 to 3 step: the seal, a case_upgrade entry with prev of 64
        zeros and the number after the highest unchained one, as the journal's first chained line. Its `sealed` names
        every byte before it, which the step read under the held context it still holds, so it is checked again here
        and a journal another writer changed meanwhile is refused. The head is then recorded outside the case."""
        _validate("case_upgrade", fields)
        with self.held():
            self._catch_up()
            if self.chain.chained:
                raise JournalError("The journal's hash chain has started already, so it can't be sealed again")
            if fields.get("sealed") != _seal_of(self.path)[0] or _unended(self.path)[1]:
                raise JournalError(f"{self.path} changed while the case was upgraded, so the seal doesn't name its "
                                   "bytes. Close any other Glessner program that has the case open, then try again.")
            entry = {"seq": self.state.last_seq + 1, "prev": ZERO, "at": _now(), "who": SYSTEM, "build": build_id(),
                     "client": self.client, "action": "case_upgrade", **fields}
            self._write(line_bytes(entry))
            self._catch_up()
            self._record_head()
            return entry

    def _write(self, data: bytes) -> None:
        """The bytes appended, through a file without buffering, then flushed to disk."""
        with self.path.open("ab", buffering=0) as f:
            _write_all(f, data)
            os.fsync(f.fileno())

    def _prepare(self, first: bool = False) -> None:
        """Before a chained append, under the held context, after its catch-up: the check of the newest line and of the
        bytes after the last LF, with a line end added or a torn line moved aside; and at this object's first append or
        an open for work, also the check of the head recorded outside the case, an entry for each side file no entry
        names, and case.yaml's record. A break goes on self.problems, and with any, nothing is written. The head recorded
        outside the case is checked before a line end is added or a torn line moved aside, at an append after the first
        too: a running app's next append must not take a line another process wrote, and that was then changed, for a
        crash's torn line."""
        first = first or not self._opened
        self._opened = True
        self._check_newest()
        tail, kind = self._tail()
        if first or kind in ("missing_lf", "torn"):
            self._check_record(tail if kind == "missing_lf" else b"", first)
        if self.read_only:
            return
        if kind == "missing_lf":
            entry = strict(tail)
            self._write(b"\n")
            self._catch_up()   # the entry applies as written
            self._recover({"completed": True, "entry": {"action": entry["action"], "seq": entry["seq"]}})
        elif kind == "torn":
            self._recover(_aside(self.path, self.chain.offset, tail))
        if first:
            for payload in _found(self.path):
                self._recover(payload)
            self._record_case_yaml()

    def _recover(self, payload: dict) -> None:
        self.recovered.append(self._append_locked("journal_recovered", SYSTEM, payload))

    def _check_newest(self) -> None:
        """The newest line read still hashes to the head held in memory, and the file is no shorter.
        The chain alone can't show a change to its newest lines; this shows one made while the app runs."""
        if not self.chain.chained or any(p["kind"] == "newest_changed" for p in self.problems):
            return   # before the chain's first line, which an unended one is, there is no newest line to compare
        with self.path.open("rb") as f:
            size = f.seek(0, os.SEEK_END)
            f.seek(self.chain.last)
            line = f.read(self.chain.offset - self.chain.last) if size >= self.chain.offset else b""
        if line[-1:] != b"\n" or _sha256(line[:-1]) != self.chain.head:
            self.problems.append(_break(self.chain.lines, self.chain.seq, "newest_changed",
                                        f"the newest line, entry #{self.chain.seq}, changed or was removed after this "
                                        "app read it"))

    def started(self) -> bool:
        """Whether the journal has a chain: its first chained line is read, or it is the unended last line and starts
        the chain (_follows), such as a seal or a case_created cut just before its LF, which the next open or append ends
        with the LF (_prepare). A line that fails the start rule is no chain. Writes nothing and changes no state, so
        callers that decide whether Continue applies can ask."""
        if self.chain.chained:
            return True
        try:
            with self.path.open("rb") as f:
                f.seek(self.chain.offset)
                tail = f.read()
        except OSError:
            return False   # a journal deleted while the case is open has no chain to continue
        entry = None if b"\0" in tail or b"\n" in tail else strict(tail)
        return entry is not None and _follows(entry, self.chain, self.path)

    def _tail(self) -> tuple[bytes, str]:
        """The bytes after the last LF the read reached, and what they are: "" for none; missing_lf,
        a whole entry that chains but lacks its LF; not_entry, one JSON object that doesn't chain, which a cut can't
        leave, so a break; torn, anything else, NUL bytes included. Whole lines another writer added after the catch-up,
        as an older build's could be, are read first."""
        for _ in range(3):
            with self.path.open("rb") as f:
                f.seek(self.chain.offset)
                tail = f.read()
            if b"\n" not in tail[:-1] and (b"\0" in tail or not tail.endswith(b"\n")):
                break
            self._catch_up()
        if not tail:
            return tail, ""
        entry = None if b"\0" in tail else strict(tail)
        if entry is not None and _follows(entry, self.chain, self.path):
            return tail, "missing_lf"
        if entry is not None:
            if not any(p["kind"] == "tail" for p in self.problems):
                self.problems.append(_break(self.chain.lines + 1, entry.get("seq"), "tail",
                                            "the last line has no line end, and its entry doesn't follow the line "
                                            "before it"))
            return tail, "not_entry"
        return tail, "torn"

    def _check_record(self, tail: bytes, first: bool = True) -> None:
        """The check that the head this app recorded outside the case is a line of the chain, or the whole entry
        missing its LF. Lines after it are no break, since a failed write of the record leaves the same; they are
        counted by action for Integrity, a whole last entry missing its LF (`tail`) among them when the record's head
        is an earlier line: a forged entry left without its LF looks like a crash's, and must be counted like one with
        it. A record that names no line is a break: the newest entries were removed or changed, or the journal
        replaced, while the app was closed. `first` is the open's check; a later one, before a line end is
        added or a torn line moved aside, only looks for that break and leaves what the open found. Integrity's count,
        self.recorded, is this object's first such check's: an upgrade step's entry, written between that check and the
        open's, moves the record past the entries the first one counted."""
        counting = first and not self._record_checked
        if counting:
            self.recorded = None
            self._record_checked = True
        record = heads.read(self.path.parent)
        if record is None:
            return
        head, after = record["head"], None
        # With a skipped line, _kept lacks it, so the entries after the head are counted from the file
        for i, (h, _, _) in enumerate(() if self._skip else self._kept):
            if h == head:
                after = Counter(action for _, _, action in self._kept[i + 1:])
                break
        if after is None and tail and _sha256(tail) == head:
            after = Counter()
            tail = b""
        if after is None:
            after = _after_head(self.path, head, self.chain.offset)
        if first:
            self._kept = []
        if after is None:
            if not any(p["kind"] == "record_missing" for p in self.problems):
                self.problems.append(_break(None, record["seq"], "record_missing",
                                            f"the head this app recorded at {record.get('at', '')}, entry #{record['seq']}, "
                                            "is no line of the journal: its newest entries were removed or changed, or the "
                                            "journal was replaced" + (", while the app was closed" if first else "")))
            return
        if tail and (entry := strict(tail)) is not None:
            after[entry["action"]] += 1
        if counting:
            self.recorded = {"seq": record["seq"], "at": record.get("at", ""), "after": dict(after)}

    def _record_case_yaml(self) -> None:
        """case.yaml sits outside the chain, and its analyst becomes each later entry's who. When its bytes differ from
        those the journal last recorded, a case_yaml entry records the new SHA-256 and settings."""
        try:
            data = (self.path.parent / CASE_FILE).read_bytes()
        except OSError:
            return
        if (sha := _sha256(data)) == self._case_yaml:
            return
        try:
            settings = yaml.safe_load(data)
            settings = json.loads(json.dumps(settings if isinstance(settings, dict) else {}, default=str,
                                             allow_nan=False))
        except (yaml.YAMLError, ValueError):
            settings = {}
        self._append_locked("case_yaml", SYSTEM, {"sha256": sha, "settings": settings})

    def _record_head(self) -> None:
        """The head recorded outside the case moved to the newest line. A failed write fails no append: it leaves an
        older head, which the next open finds in the chain, never a false break."""
        if self.chain.chained and _number(self.chain.seq) and not self.read_only:
            with suppress(OSError):
                heads.write(self.path.parent, self.chain.seq, self.chain.head, build_id())

    def _reset(self) -> None:
        self.state, self.build, self.chain, self.problems = State(), "", Chain(), []
        self._case_yaml, self._kept = None, []

    def _catch_up(self) -> None:
        """Apply the entries added to the file since the state last read it. Where it has read to moves with each
        entry, so an entry is applied once, also when a later line stops the read. A new rekey changes IDs that entries
        applied before it name, so the state is built again from the first line, each entry read through the rekeys
        that follow it. Only a case format upgrade writes one, at the open. A line whose payload _apply
        can't apply, such as a changed one, goes in self._skip and the state is built again without it (_applied), also
        a line before the chain, which replay() still refuses. The rebuilds are a loop, not a call within a call: a
        journal of a thousand changed lines is rebuilt twice, not a thousand times."""
        restarted: set[int] = set()
        while True:
            applied = self._read != (0, 0)
            try:
                for entry, h in _read(self.path, self.chain, skip=self._skip, restarted=restarted):
                    if applied and is_rekey(entry):
                        raise _Reread
                    if not _applied(self.state, entry, self.chain.lines + 1, self._skip):
                        continue
                    action = entry.get("action")
                    if action == "case_open":
                        self.build = str(entry.get("build", ""))
                    elif action == "case_created":
                        self._case_yaml = entry.get("case_yaml")
                    elif action == "case_yaml":
                        self._case_yaml = entry.get("sha256")
                    if h is not None and self._record and not self._opened and entry["seq"] >= self._record["seq"]:
                        self._kept.append((h, entry["seq"], action))
                return
            except _Reread:
                problems = self.problems
                self._reset()
                self.problems = problems


def head_of(entry: dict) -> str:
    """The head after a chained entry: the SHA-256 of its line, which line_bytes writes the same way every time."""
    return _sha256(line_bytes(entry)[:-1])


def seal_of(path: Path) -> dict:
    """A seal's `sealed` over the whole journal, which ends in LF: its lines that aren't blank, its bytes, and their
    SHA-256."""
    return _seal_of(path)[0]


def has_chain(path: Path) -> bool:
    """Whether the journal holds a chained line, by any JSON spelling of prev: the upgrade sealed it, or a build of
    format 3 or later made it. A last line missing its LF counts, so a seal cut just before its LF isn't sealed again;
    whether that line starts the chain is the open's question (Journal.started)."""
    with path.open("rb") as f:
        return any(_chained(line.rstrip(b"\n")) for line in f)


def _seal_of(path: Path) -> tuple[dict, str]:
    """The seal of every byte of the journal, which ends in LF, and the SHA-256 of its last line, for a chain_break."""
    digest, lines, size, last = hashlib.sha256(), 0, 0, b""
    with path.open("rb") as f:
        for line in f:
            digest.update(line)
            size += len(line)
            lines += bool(line.strip())
            last = line
    return {"lines": lines, "bytes": size, "sha256": digest.hexdigest()}, _sha256(last.rstrip(b"\n")) if last else ZERO


def _after_head(path: Path, head: str, end: int) -> Counter | None:
    """The entries after the line whose SHA-256 is `head`, by action, reading whole lines up to byte `end`; None when no
    line has it."""
    after = None
    with path.open("rb") as f:
        read = 0
        for line in f:
            read += len(line)
            if read > end:
                break
            raw = line.rstrip(b"\n")
            if after is not None:
                entry = parse_line(raw)
                after[entry.get("action") if entry else "unreadable"] += 1
            elif _sha256(raw) == head:
                after = Counter()
    return after


def _recoveries(entry: dict) -> list[dict]:
    """What an entry says it recovered: a journal_recovered's own payload, and each in a case_upgrade's `recovered`."""
    action = entry.get("action")
    found = [entry] if action == "journal_recovered" else entry.get("recovered") if action == "case_upgrade" else []
    return [p for p in found if isinstance(p, dict)] if isinstance(found, list) else []


def _named(path: Path) -> set[str]:
    """The side files the journal's entries name: each journal_recovered's, and each in a case_upgrade's recovered."""
    names = set()
    with path.open("rb") as f:
        for line in f:
            if b"journal_torn_" not in line or (entry := parse_line(line.rstrip(b"\n"))) is None:
                continue
            names.update(p["saved_as"] for p in _recoveries(entry) if isinstance(p.get("saved_as"), str))
    return names


def _found(path: Path) -> list[dict]:
    """A journal_recovered payload for each side file in the case folder that no entry names: a crash between cutting
    the journal and recording it leaves one, and so does anyone who copies one in, so the trail says "found,
    unexplained"."""
    files = [f for f in sorted(path.parent.glob(SIDE_GLOB)) if f.is_file() and SIDE_FILE.fullmatch(f.name)]
    if not files:
        return []
    named = _named(path)
    out = []
    for file in files:
        if file.name not in named:
            data = file.read_bytes()
            out.append({"saved_as": file.name, "bytes": len(data), "sha256": _sha256(data), "found": True})
    return out


def _side_file(path: Path, data: bytes) -> str:
    """The side file in the journal's folder that holds `data`: one no entry names yet that holds the same bytes, as a
    crash between saving and cutting leaves, or a new journal_torn_<UTC>.bin, written and flushed to disk."""
    named = _named(path)
    for old in sorted(path.parent.glob(SIDE_GLOB)):
        if old.name not in named and old.is_file() and old.stat().st_size == len(data) and old.read_bytes() == data:
            return old.name
    while True:
        name = f"journal_torn_{datetime.now(UTC):%Y%m%dT%H%M%S%fZ}.bin"
        try:
            f = (path.parent / name).open("xb")
        except FileExistsError:
            continue
        try:
            with f:
                _write_all(f, data)
                f.flush()
                os.fsync(f.fileno())
        except BaseException:
            with suppress(OSError):
                (path.parent / name).unlink()
            raise
        return name


def _aside(path: Path, start: int, tail: bytes) -> dict:
    """A torn last line moved aside: its bytes, from `start` to the end, saved to a side file and flushed to disk, then
    the journal cut back to `start` and flushed. The one place the file gets shorter.
    Its journal_recovered payload, with the action and number of the entry it held when the bytes parse as one."""
    name = _side_file(path, tail)
    with path.open("r+b") as f:
        f.truncate(start)
        f.flush()
        os.fsync(f.fileno())
    payload = {"saved_as": name, "bytes": len(tail), "sha256": _sha256(tail)}
    parsed = strict(tail.rstrip(b"\0\r\n\t "))   # a whole entry whose line end a crash left as NUL bytes
    if parsed is not None and "action" in parsed:
        payload["held"] = {"action": parsed.get("action"), "seq": parsed.get("seq")}
    return payload


def _last_lf(f, before: int) -> int:
    """Where the file's last LF before byte `before` is, or -1."""
    at = before
    while at > 0:
        size = min(at, 1 << 16)
        f.seek(at - size)
        block = f.read(size)
        if (i := block.rfind(b"\n")) >= 0:
            return at - size + i
        at -= size
    return -1


def _unended(path: Path) -> tuple[int, bytes]:
    """Where the bytes after the last LF start, and those bytes; or, when there are none and the last line holds 0x00,
    where that line starts, and the line with its LF."""
    with path.open("rb") as f:
        size = f.seek(0, os.SEEK_END)
        end = _last_lf(f, size) + 1
        if end < size:
            f.seek(end)
            return end, f.read()
        start = _last_lf(f, end - 1) + 1 if end else 0
        f.seek(start)
        line = f.read(end - start)
        return (start, line) if b"\0" in line else (size, b"")


def _damage(entry: dict) -> str:
    """Why _apply can't take an entry, as the error's type and text, or "" when it can: tried on an empty state, so
    nothing real is half applied. A payload that fails only against what came before, such as a finding edit whose
    techniques aren't a list, passes here and fails in _applied."""
    try:
        _apply(State(), entry)
    except REPLAY_ERRORS as exc:
        return f"{type(exc).__name__}: {exc}"
    return ""


def _applies(entry: dict) -> bool:
    """Whether format 2's reader applies an entry: _apply takes it without an error."""
    return not _damage(entry)


def _applied(state: State, entry: dict, line: int, skip: set[int]) -> bool:
    """Apply an entry to `state`, or, when _apply can't (a changed line's payload), add its line to `skip` and raise
    _Reread: _apply changes the state step by step, so the state is built again from the first line without the entry,
    not repaired in place. Once a line is in `skip`, each entry is first tried on an empty state (_damage), and
    one it can't take is skipped on the spot, so the rebuild is one pass whatever the number of changed lines; only a
    line that fails against the state before it costs another rebuild. False for an entry skipped so."""
    if skip and _damage(entry):
        skip.add(line)
        return False
    try:
        _apply(state, entry)
    except REPLAY_ERRORS:
        skip.add(line)
        raise _Reread from None
    return True


def unchained_tail(path: Path) -> tuple[int, bytes, bool, dict | None]:
    """What mend_unchained would do with the bytes after the last LF, and a last line holding 0x00, without writing:
    where they start, the bytes ("" for none), whether they are torn and so go to a side file, and otherwise the
    action and seq of the entry that gets its LF (None for a line of only whitespace). Raises JournalError as
    mend_unchained does, so both upgrade steps can refuse before their first write. By format 2's reader:
    - bytes it applies get their LF, and so do bytes of only whitespace, which it skips;
    - bytes that parse as JSON but that it fails on raise JournalError naming the line, and nothing is written: a cut
      can't leave them, since every unchained line starts with { and a cut drops the closing };
    - anything else is torn."""
    start, tail = _unended(path)
    torn, done = bool(tail), None
    if tail and b"\0" not in tail and not tail.endswith(b"\n"):
        torn = False
        if tail.strip():
            try:
                entry = json.loads(tail)
            except (ValueError, RecursionError):
                torn = True
            else:
                if not (isinstance(entry, dict) and _applies(entry)):
                    with path.open("rb") as f:
                        n = sum(block.count(b"\n") for block in iter(lambda: f.read(1 << 20), b"")) + 1
                    raise JournalError(f"{path} line {n} is JSON that the journal's reader can't apply, so it isn't "
                                       "a line a crash cut short. Nothing was changed; restore the journal from a "
                                       "copy of the case folder, or remove that line by hand.")
                done = {"action": entry.get("action"), "seq": entry.get("seq")}
    return start, tail, torn, done


def mend_unchained(path: Path) -> list[dict]:
    """The mend that both upgrade steps run on a journal with no chained line, so the seal covers whole lines
    only and the replayed state stays the same. The bytes after the last LF, and a last line holding 0x00, by the rule
    of unchained_tail: an LF added, or the bytes moved to a side file as a chained journal's are, and
    JournalError, with nothing written, for bytes it refuses. Runs inside the held context. The journal_recovered
    payloads of what it did, for the step's `recovered`."""
    with held(path):
        start, tail, torn, done = unchained_tail(path)
        if not tail:
            return []
        if torn:
            return [_aside(path, start, tail)]
        with path.open("ab", buffering=0) as f:
            _write_all(f, b"\n")
            os.fsync(f.fileno())
        return [{"completed": True, "entry": done}]


def start_chain(case: Case, client: str = "cli", **payload) -> dict:
    """A case's case_created entry, naming the case, the case format it has now (`case_format`), and case.yaml's SHA-256,
    and the head recorded outside the case. In an empty journal it starts the chain: line 1 at byte 0, prev of 64 zeros,
    as create_case and the copy_case of a source with the chain write it. A copy of an older source is sealed by its
    upgrade first (upgraded_copy in rekey.py), and the entry then follows the seal, with no case_yaml before it, since
    it records case.yaml's SHA-256 itself. In both, the entries of the upgrade steps from a format with the chain
    follow it, and a case that began at format 4 has none from 3 to 4 (_past_step). `payload` adds copied_from for a
    copy."""
    journal = Journal(case, client)
    s = case.settings
    with journal.held():
        journal._catch_up()
        fields = {"name": s.name, "created_utc": s.created_utc, "analyst": s.analyst, "evidence_path": s.evidence_path,
                  "case_yaml": _sha256((case.folder / CASE_FILE).read_bytes()), "case_format": s.case_format, **payload}
        _validate("case_created", fields)
        if journal.path.stat().st_size:
            if not journal.started():   # a seal cut just before its LF is the chain: the append ends it first
                raise JournalError(f"{journal.path} isn't empty and has no hash chain, so the chain can't start in it")
            journal._case_yaml = fields["case_yaml"]   # recorded by this entry, so the open's check adds no case_yaml
            return journal._append_locked("case_created", SYSTEM, fields)
        entry = {"seq": 1, "prev": ZERO, "at": _now(), "who": SYSTEM, "build": build_id(), "client": client,
                 "action": "case_created", **fields}
        journal._write(line_bytes(entry))
        journal._catch_up()
        journal._opened = True
        journal._record_head()
    return entry


def copied_from(source: Case) -> dict:
    """What a copy's case_created says of its source: the source's folder and, when its journal has a chain, the hash
    and number of its last whole chained line, read through the shared reader whether or not the chain is broken;
    otherwise the length and SHA-256 of its journal through its last LF."""
    path = source.folder / JOURNAL_FILE
    out: dict = {"folder": str(source.folder)}
    if not path.is_file():
        return {**out, "bytes": 0, "sha256": _sha256(b"")}
    chain = Chain()
    restarted: set[int] = set()
    while True:
        try:
            for _ in _read(path, chain, format2=False, restarted=restarted):
                pass
            break
        except _Reread:
            chain = Chain()
    if chain.chained:
        return {**out, "head": chain.head, "seq": chain.seq}
    with path.open("rb") as f:
        size = _last_lf(f, f.seek(0, os.SEEK_END)) + 1
    return {**out, "bytes": size, "sha256": _prefix_sha256(path, size)}


@dataclass
class Check:
    """A full check of a journal, read from byte 0 without writing anything."""
    chain: Chain
    # With keep: every entry replay reads, translated; one it can't apply carries DAMAGED, naming the error
    entries: list[dict] = field(default_factory=list)
    head: str = ZERO          # the newest chained line's SHA-256, a whole entry missing its LF included
    seq: int | None = None
    tail: str = ""            # after the last LF: "", missing_lf, torn, not_entry, or writing (another holds the lock)
    tail_bytes: int = 0
    problems: list[dict] = field(default_factory=list)   # each reason the result isn't "consistent", as _break gives
    files: list[tuple[int, int, str]] = field(default_factory=list)   # each file_written entry's (line, seq, sha256)
    # Each chained manifest_recorded entry whose payload is whole, in journal order, as State.manifests holds it, with
    # its line
    manifests: list[dict] = field(default_factory=list)
    recovered: list[dict] = field(default_factory=list)   # the journal_recovered entries
    expected: tuple[int, int] | None = None   # the expected head's (line, seq), when it is a chained line
    after: dict[str, int] = field(default_factory=dict)   # entries after the expected head, by action
    # Each side file an entry names, by name, with its size and modification time (side_stamp) as the check found them
    # before it read the file; what a kept result depends on, besides the journal itself
    sides: dict[str, tuple[int, int] | None] = field(default_factory=dict)

    @property
    def breaks(self) -> list[dict]:
        return self.chain.breaks

    @property
    def consistent(self) -> bool:
        """Every check passed: the chain starts right, each line follows the one before, nothing follows the last LF but
        a write in progress, no chain_break is on record, and an expected head, when given, is a line."""
        return not self.problems and not self.chain.on_record


def check(path: Path, expect: str | None = None, *, keep: bool = False, skip: Collection[int] = ()) -> Check:
    """The full check: every line from byte 0 through the shared reader, the bytes after the last LF, and,
    when `expect` is given, where that head is and the entries after it, by action. Writes nothing and creates nothing:
    the lock is tried once, from journal.lock opened read-only when it exists, so bytes after the last LF while another
    writer holds it are a write in progress, not a torn line. `keep` keeps the entries, for the audit trail and undo,
    and marks (DAMAGED) each that _apply can't take, tried on an empty state, and each on a line in `skip`, the lines
    a Journal's state left out because they failed against what came before them."""
    expect = expect.lower() if expect else None
    restarted: set[int] = set()
    while True:
        result = Check(Chain())
        after: Counter = Counter()
        sides: list[tuple[int, dict]] = []   # the side files the entries name, with the entry's number
        try:
            for entry, h in _read(path, result.chain, format2=False, restarted=restarted):
                if keep:   # an entry replay can't apply stays in the list, marked, for the trail
                    why = _damage(entry) or (SKIPPED if result.chain.lines + 1 in skip else "")
                    result.entries.append({**entry, DAMAGED: why} if why else entry)
                # Also an unchained line's: a seal covers the side file format 2's step named, and only a check of the
                # file shows it changed
                sides.extend((entry.get("seq"), one) for one in _recoveries(entry))
                if h is None:
                    continue
                line, action = result.chain.lines + 1, entry["action"]
                if action == "file_written":
                    result.files.append((line, entry["seq"], entry.get("sha256")))
                elif action == "manifest_recorded" and manifest_ok(entry):
                    result.manifests.append({"line": line, **manifest_of(entry)})
                elif action == "journal_recovered":
                    result.recovered.append(entry)
                if result.expected:
                    after[action] += 1
                elif h == expect:
                    result.expected = (line, entry["seq"])
            break
        except _Reread:
            continue
    chain = result.chain
    result.head, result.seq = chain.head, chain.seq
    with path.open("rb") as f:
        f.seek(chain.offset)
        tail = f.read()
    result.tail_bytes = len(tail)
    entry = None if b"\0" in tail else strict(tail)
    follows = entry is not None and _follows(entry, chain, path)   # a whole entry that is the chain's next, or its start
    problems = list(chain.breaks)
    if not chain.chained and not follows:
        problems.append(_break(None, None, "chain_missing", "no chained line: the chain is missing, or this is a "
                                                             "journal of format 1 or 2, which has none"))
    if chain.crlf and chain.crlf == chain.lines:
        problems.insert(0, _break(None, None, "line_endings", "every line ends in CR LF: the line endings were "
                                                              "converted, such as by a copy through a tool that "
                                                              "changes them"))
    problems += _side_problems(path.parent, sides, result.sides)
    if tail and _writing(path):
        result.tail = "writing"
    elif tail:
        if follows:
            result.tail, result.head, result.seq = "missing_lf", _sha256(tail), entry["seq"]
            line = chain.lines + 1
            if entry["action"] == "file_written":
                result.files.append((line, entry["seq"], entry.get("sha256")))
            elif entry["action"] == "manifest_recorded" and manifest_ok(entry):
                result.manifests.append({"line": line, **manifest_of(entry)})
            if result.expected:
                after[entry["action"]] += 1
            elif result.head == expect:
                result.expected = (line, entry["seq"])
            problems.append(_break(line, entry["seq"], "missing_lf",
                                   f"the last line, entry #{entry['seq']}, has no line end. The entry is whole and "
                                   "follows the line before it; the app adds the line end at its next write"))
        elif entry is not None:
            result.tail = "not_entry"
            problems.append(_break(chain.lines + 1, entry.get("seq"), "tail", "the last line has no line end, and its "
                                                                              "entry doesn't follow the line before it"))
        else:
            result.tail = "torn"
            problems.append(_break(chain.lines + 1, None, "torn",
                                   f"{len(tail):,} bytes after the last whole line, most likely a write a crash cut "
                                   "short; the app moves them to a side file at its next write"))
    if expect and not result.expected:
        problems.append(_break(None, None, "expected_missing", "the expected head is no entry of this journal"))
    result.problems, result.after = problems, dict(after)
    return result


def side_stamp(folder: Path, name: str) -> tuple[int, int] | None:
    """A side file's size and modification time, or None when it can't be read or isn't there."""
    try:
        stat = (folder / name).stat()
    except OSError:
        return None
    return stat.st_size, stat.st_mtime_ns


def _side_problems(folder: Path, sides: list[tuple[int, dict]], stamps: dict | None = None) -> list[dict]:
    """Each side file an entry names (a journal_recovered's, a seal's `recovered`) that is missing from the case folder or
    doesn't hold the length and SHA-256 the entry recorded, which the chain covers, so replacing one would otherwise go
    unnoticed. Only a name of the side files' form is read, never a path from the journal. Each file's side_stamp, taken
    before it is read, goes into `stamps` by name."""
    out = []
    for seq, one in sides:
        name = one.get("saved_as")
        if not (isinstance(name, str) and SIDE_FILE.fullmatch(name)):
            continue
        if stamps is not None:
            stamps[name] = side_stamp(folder, name)
        try:
            data = (folder / name).read_bytes()
        except OSError:
            out.append(_break(None, seq, "side_file", f"the side file {name}, which entry #{seq} names, is missing from the "
                                                      "case folder"))
            continue
        if len(data) != one.get("bytes") or _sha256(data) != one.get("sha256"):
            out.append(_break(None, seq, "side_file", f"the side file {name} doesn't hold the {one.get('bytes')} bytes "
                                                      f"entry #{seq} recorded for it: its length or SHA-256 differs"))
    return out


def entries(path: Path) -> list[dict]:
    """The journal's entries in file order, each read through the rekeys that follow it, as replay applies them."""
    restarted: set[int] = set()
    while True:
        try:
            return [entry for entry, _ in _read(path, Chain(), restarted=restarted)]
        except _Reread:
            continue


def analyst(entry: dict) -> str:
    """Who made an entry, as the trail, the report, and the overview list it: its `who` as written when that is a string,
    "" when it has none, else the JSON text of what it holds. Format 2's reader gives a line as written, so a line under the
    seal can hold a list, an object, a number, or null there."""
    who = entry.get("who", "")
    return who if isinstance(who, str) else json.dumps(who)


def last_action(path: Path) -> dict | None:
    """The journal's newest entry by someone, as entries() gives it, read from the file's end rather than by parsing every
    line. The app's own entries, such as the build each new build journals when it opens the case, are left to the audit
    trail and Integrity: they answer no "where was I". The case format upgrades' rekeys it passes on the way are exactly
    those that follow the entry, so it is read through them, in file order, as every other reader reads it: through each
    rekey the shared reader gives that _apply can take (_applies). A `who` that is not a string is someone's, as the audit
    trail reads it."""
    start = None   # where the chain starts (_chain_start), found the first time a line that names no prev needs it
    with path.open("rb") as f:
        size = f.seek(0, 2)
        back = min(size, 65_536)
        while True:
            f.seek(size - back)
            # As the shared reader reads: up to the last LF, and before a last line holding 0x00. Either is a write in
            # progress, or a crash's
            *lines, torn = f.read(back).split(b"\n")
            end = size - len(torn) - 1   # where the newest whole line ends, at its LF
            if lines and not torn and b"\0" in lines[-1]:
                end -= len(lines.pop()) + 1
            if back < size:
                lines = lines[1:]   # the first may start mid-line
            rekeys = []   # the rekeys passed that the shared reader applies, newest first
            for line in reversed(lines):
                at = end - len(line)   # where the line starts
                end = at - 1           # where the line before it ends, at its LF
                if not line.strip():
                    continue
                # A line is chained when it names prev, or when a chained line comes before it, as _read decides; an
                # unchained line is parsed as format 2 read it
                entry = strict(line)
                chained = entry is not None and "prev" in entry
                if not chained:
                    start = _chain_start(path) if start is None else start
                    chained = at > start
                    entry = entry if chained else _format2(line)
                # The step's rekey stands only before the lines that close its place, which only a read from the file's
                # start knows
                step = chained and entry is not None and is_rekey(entry) and (
                    entry.get("from_format"), entry.get("to_format")) == REKEY_STEP
                if not _given(entry, chained, step and _past_before(path, at)):
                    continue
                who = entry.get("who")
                if not (isinstance(who, str) and who in APP_NAMES):
                    return translate(entry, rekeys[::-1]) if rekeys else entry
                if is_rekey(entry) and _applies(entry):
                    rekeys.append(entry)
            if back == size:
                return None
            back = min(size, back * 4)   # long lines, such as a mark of many events, or several build entries


def _given(entry: dict | None, chained: bool, past: bool = False) -> bool:
    """Whether the shared reader (_read) gives a line's entry, parsed as it parses the line, or None when that parse
    failed. A chained line's entry must have an envelope replay can read, complete when it names prev (lacks), and no
    entry may be a rekey that no build of this format writes (_rekey_ok). `chained` is whether the line is chained: it
    names prev, or a chained line comes before it. _rekey_ok reads that only for an entry that names no prev, which is
    chained only when a chained line comes before it. `past` is whether a line before it closes the place of the step's
    rekey (_past_step)."""
    if entry is None:
        return False
    if chained and (not _replayable(entry) or ("prev" in entry and lacks(entry))):
        return False
    return not is_rekey(entry) or _rekey_ok(entry, chained, past)


def _chain_start(path: Path) -> int:
    """Where the journal's first chained line starts (_chained), or its size when no line is chained: a line that starts
    after it is chained, as the shared reader reads it."""
    at = 0
    with path.open("rb") as f:
        for line in f:
            if _chained(line.removesuffix(b"\n")):
                break
            at += len(line)
    return at


def replay(path: Path) -> State:
    """The state the journal's entries build. A chained line `_apply` can't apply, such as a changed one, is left out and
    the state built again without it (_applied); an unchained line it can't apply still refuses, as format 2's reader
    did, with a JournalError naming the line, which the upgrade's checks rely on."""
    skip: set[int] = set()
    restarted: set[int] = set()
    while True:
        state, chain = State(), Chain()
        if not path.exists():
            return state
        try:
            for entry, h in _read(path, chain, skip=skip, restarted=restarted):
                if h is None:
                    try:
                        _apply(state, entry)
                    except REPLAY_ERRORS as exc:
                        raise JournalError(f"{path} line {chain.lines + 1} is JSON that the journal's reader can't apply "
                                           f"({type(exc).__name__}: {exc}). Nothing was changed; restore the journal from a "
                                           "copy of the case folder, or remove that line by hand.") from exc
                else:
                    _applied(state, entry, chain.lines + 1, skip)
            return state
        except _Reread:
            continue


def rekey_map(rekey: dict, name: str) -> dict:
    """A rekey's `pairs`, `unplaced`, or `candidates_unplaced`, or an empty map when a changed line holds something else
    there, so a reader of a rekey never fails on one the checks accept. The writer's _validate_rekey keeps the maps
    maps."""
    found = rekey.get(name)
    return found if isinstance(found, dict) else {}


def is_rekey(entry: dict) -> bool:
    """Whether an entry is a case format upgrade that changed event IDs, with the map in its `rekey`."""
    return entry.get("action") == "case_upgrade" and isinstance(entry.get("rekey"), dict)


def translate(entry: dict, rekeys: list[dict]) -> dict:
    """The entry with each event ID its ID_FIELDS name read through each of `rekeys`, the rekey entries that follow it
    in the journal, in file order. An entry written after a rekey names the IDs of its time, so a rekey
    reads only the entries before it: translation is by the line's place in the file, not its number, which a format 1
    journal may repeat or leave out. Each rekey is one lookup in its pairs, never repeated within it, so a swap or a
    chain within one map reads as written; one rekey after another composes. An ID a rekey left unplaced, or doesn't
    name, stays as written. The entry itself is returned when no ID changed, and otherwise a copy naming the rekeys'
    entry numbers in REKEYED, so the trail can say why an ID differs from the line."""
    changed = []
    for rekey in rekeys:
        renamed = _renamed(entry, rekey_map(rekey["rekey"], "pairs"))
        if renamed is not entry:
            entry = renamed
            changed.append(rekey.get("seq"))
    return {**entry, REKEYED: [*entry.get(REKEYED, []), *changed]} if changed else entry


def _renamed(entry: dict, pairs: dict[str, str]) -> dict:
    """The entry with its IDs looked up once in `pairs`; the entry itself when none is there."""
    out = None
    for name in ID_FIELDS.get(entry.get("action"), ()):
        value = entry.get(name)
        if name == "changes" and isinstance(value, list):
            new = [_renamed(c, pairs) if isinstance(c, dict) else c for c in value]
            same = all(n is c for n, c in zip(new, value, strict=True))
        elif isinstance(value, list):
            new = [pairs.get(v, v) if isinstance(v, str) else v for v in value]
            same = new == value
        elif isinstance(value, str):
            new = pairs.get(value, value)
            same = new == value
        else:
            continue
        if not same:
            out = out if out is not None else dict(entry)
            out[name] = new
    return entry if out is None else out


def translated(entries: list[dict]) -> list[dict]:
    """A whole journal's entries, in file order, each read through the rekeys that follow it."""
    if not any(is_rekey(e) for e in entries):
        return entries
    after: list[dict] = []   # the rekeys after the entry, in file order
    out = []
    for entry in reversed(entries):
        out.append(translate(entry, after) if after else entry)
        if is_rekey(entry):
            after.insert(0, entry)
    return out[::-1]


def event_ids(entry: dict) -> Iterator[str]:
    """The event IDs an entry's ID_FIELDS name, an undo's changes' included."""
    for name in ID_FIELDS.get(entry.get("action"), ()):
        value = entry.get(name)
        if name == "changes" and isinstance(value, list):
            for change in value:
                if isinstance(change, dict):
                    yield from event_ids(change)
        elif isinstance(value, list):
            yield from (v for v in value if isinstance(v, str))
        elif isinstance(value, str):
            yield value


class References(NamedTuple):
    """The event IDs a case format upgrade's map places (referenced_ids). An ID can be in both."""
    named: set[str]        # the IDs the journal's entries name, the analyst's references
    candidates: set[str]   # the events earlier rekeys' unplaced IDs may have meant, by the IDs they have now


def referenced_ids(path: Path) -> References:
    """The event IDs a case format upgrade's map places (rekey.py), apart: each ID the journal's entries name, read
    through the rekeys that follow it; and each event an earlier rekey's unplaced ID may have meant (unplaced), by the ID
    the event has now, which the map places too, since the Event page looks those events up by it. Only the first are
    references the analyst made."""
    if not path.exists():
        return References(set(), set())
    read = entries(path)
    rekeys = [{**entry["rekey"], "seq": entry.get("seq")} for entry in read if is_rekey(entry)]   # as State.rekeys
    return References({uid for entry in read for uid in event_ids(entry)}, set(unplaced(State(rekeys=rekeys))))


def upgrade_recorder(journal: Journal):
    """case.upgrade's record: each step's case_upgrade entry, the app's own, with the fields the step gives,
    picked by the format it brings the case to: to format 2 or below, an unchained line,
    as format 2's step wrote it; to format 3, the seal, the chain's first line; later, an ordinary chained entry, after
    the checks of Journal.check_for_upgrade, so a journal with no chain or with a break raises KeptAtFormat and keeps the
    case at its format. A later step whose entry is journaled already (fields None) gets the same checks and no entry,
    so they run on `journal`, which at the server's open is the open's own: it keeps the first count of the entries
    after the recorded head, and what the checks write names its client. An earlier step journaled already gets
    nothing. Each runs inside the step, in the held context the seal step still holds, which is re-entrant in its
    thread. The record's `check` runs the same checks on their own, for a step that changes the case before its entry
    (case.check_journal)."""
    def record(old: int, new: int, fields: dict | None) -> dict | None:
        if new > FIRST_CHAINED:
            with journal.held():
                journal.check_for_upgrade()
                if fields is None:
                    return None
                return journal.append("case_upgrade", who=SYSTEM, from_format=old, to_format=new, **fields)
        if fields is None:
            return None
        payload = {"from_format": old, "to_format": new, **fields}
        if new <= 2:
            return journal.append_unchained("case_upgrade", who=SYSTEM, **payload)
        return journal.seal(payload)
    record.check = journal.check_for_upgrade
    return record


def renamed(state: State, uid: str) -> tuple[str, list[int]] | None:
    """The ID an earlier event ID names now, read through every rekey from the first, and the rekeys' entry numbers
    that changed it, for an old ID pasted from an export or a findings summary. Only the IDs the journal named, and the
    events an earlier rekey's unplaced ID may have meant, are in a rekey; None for any other."""
    seqs = []
    for rekey in state.rekeys:
        new = rekey_map(rekey, "pairs").get(uid)
        if isinstance(new, str):
            uid = new
            seqs.append(rekey["seq"])
    return (uid, seqs) if seqs else None


def _successors(uid: str, rekey: dict) -> list[str]:
    """The IDs the event ID `uid` has after one rekey: the one its pairs give, the several its unplaced map or its
    candidates_unplaced lists, or `uid` itself when the rekey names it in none."""
    new = rekey_map(rekey, "pairs").get(uid)
    if isinstance(new, str):
        return [new]
    for name in ("unplaced", "candidates_unplaced"):
        several = rekey_map(rekey, name).get(uid)
        if isinstance(several, list) and (ids := [each for each in several if isinstance(each, str)]):
            return ids
    return [uid]


def _read_through(uid: str, rekeys: list[dict]) -> list[str]:
    """The IDs the event ID `uid` has after `rekeys`, the rekeys that follow the record naming it: one lookup in each,
    in file order (_successors), and an ID that several lookups reach once."""
    ids = [uid]
    for rekey in rekeys:
        ids = list(dict.fromkeys(new for each in ids for new in _successors(each, rekey)))
    return ids


def unplaced(state: State) -> dict[str, list[dict]]:
    """Each event a rekey's unplaced ID may have meant -> those IDs: an ID that named different records in different
    runs stays as written, with its candidates listed. Each is {seq, id, candidates}. A rekey lists its candidates by the
    IDs of its own format, so each is read through the rekeys after that one, as translate reads an entry's IDs, and an
    event is keyed by the ID it has now. A candidate a later rekey leaves unplaced becomes that rekey's candidates, and
    candidates that read as one ID are listed once. `id`, the ID the entries named, stays as written. A later rekey
    places the candidates as it places the IDs the entries name (referenced_ids). One it leaves unplaced that no entry
    names is in its `candidates_unplaced`, which is read through as `unplaced` is, but gets no listing of its own, since
    no entry was made under it: the earlier listing names its events. A rekey's `merged` and `dropped_runs` need no
    translation, since nothing looks them up by event ID."""
    out: dict[str, list[dict]] = {}
    for i, rekey in enumerate(state.rekeys):
        for old, candidates in rekey_map(rekey, "unplaced").items():
            if not isinstance(candidates, list):
                continue
            now = list(dict.fromkeys(uid for candidate in candidates if isinstance(candidate, str)
                                     for uid in _read_through(candidate, state.rekeys[i + 1:])))
            for uid in now:
                out.setdefault(uid, []).append({"seq": rekey["seq"], "id": old, "candidates": list(now)})
    return out


def unplaced_count(state: State) -> int:
    """The IDs the journal named that a rekey left unplaced, counted apart from orphans: one may still name a loaded
    event, as one of its own candidates, so the orphan count can't see it."""
    return len({old for rekey in state.rekeys for old in rekey_map(rekey, "unplaced")})


def host_layout(case: Case) -> dict[str, dict[str, str]]:
    """The splits in force, host -> computer key -> lane, for a load or rebuild outside the server. Only the
    lines that can hold a split are parsed, by the rule every reader shares (parse_line), and only lines ended by their
    LF, so a write in progress isn't read. It checks no chain: it runs at every load, and the chain is checked where
    state is replayed for an open or a report."""
    state = State()
    path = case.folder / JOURNAL_FILE
    if path.exists():
        with path.open("rb") as f:
            for line in f:
                if b'"host_split"' in line and line.endswith(b"\n"):
                    entry = parse_line(line[:-1])
                    # not a note that quotes the word, and not a split a changed line left unreadable
                    if entry is not None and entry.get("action") == "host_split" and _applies(entry):
                        _apply(state, entry)
    return state.splits


def _validate(action: str, payload: dict) -> None:
    if action not in ACTIONS:
        raise JournalError(f"Unknown journal action {action!r}")
    if "rekey" in payload:
        if action != "case_upgrade":
            raise JournalError("only a case_upgrade carries a 'rekey'")
        _validate_rekey(payload["rekey"])
    if "confirmed" in payload and action != "host_role":   # a role's confirmed is its own: the analyst confirmed it
        _validate_confirmed(action, payload)
    if action == "mark":
        if payload.get("value") not in MARK_VALUES:
            raise JournalError(f"Mark value must be one of {MARK_VALUES}")
        targets = payload.get("targets")
        if not targets or not all(isinstance(t, str) and t for t in targets):
            raise JournalError("A mark needs a non-empty list of event IDs in 'targets'")
    elif action == "note":
        if not payload.get("target") or not str(payload.get("text", "")).strip():
            raise JournalError("A note needs 'target' and non-empty 'text'")
    elif action in ("host_role", "host_identity", "host_offset") and not payload.get("host"):
        raise JournalError(f"{action} needs 'host'")
    elif action == "host_identity" and payload.get("op") not in ("add_name", "remove_name", "add_ip", "remove_ip"):
        raise JournalError("host_identity needs op: add_name, remove_name, add_ip, or remove_ip")
    elif action == "case_setting" and not payload.get("name"):
        raise JournalError("case_setting needs 'name'")
    elif action == "case_open" and payload and not (set(payload) == {"build"} and isinstance(payload["build"], str)
                                                    and payload["build"]):
        # A chained one has no payload: its envelope's build names the build. An unchained one's payload names it.
        raise JournalError("case_open needs the 'build' that opened the case, in its envelope or, unchained, its payload")
    elif action == "case_upgrade":
        if not (isinstance(payload.get("from_format"), int) and isinstance(payload.get("to_format"), int)
                and isinstance(payload.get("text"), str)):
            raise JournalError("case_upgrade needs 'from_format', 'to_format', and the 'text' saying what it changed")
        if payload["from_format"] >= payload["to_format"]:
            raise JournalError("a case_upgrade goes up: its 'to_format' is above its 'from_format'")
        if "sealed" in payload and not _sealed(payload["sealed"]):
            raise JournalError("a seal's 'sealed' gives the 'lines', 'bytes', and 'sha256' of every byte before it")
        recovered = payload.get("recovered", [])
        if not isinstance(recovered, list):
            raise JournalError("a case_upgrade's 'recovered' lists what it recovered")
        for one in recovered:
            _validate_recovered(one)
    elif action in ("rule_add", "rule_change") and not (payload.get("id") and str(payload.get("text", "")).strip()):
        raise JournalError(f"{action} needs 'id' and the rule's YAML in 'text'")
    elif action == "rule_remove" and not payload.get("id"):
        raise JournalError("rule_remove needs 'id'")
    elif action == "suggestion_decision":
        if payload.get("decision") not in DECISIONS or not payload.get("source") or not payload.get("targets"):
            raise JournalError(f"suggestion_decision needs 'targets', 'source', and a decision from {DECISIONS}")
        if "note" in payload and not isinstance(payload["note"], str):   # a Reject's note
            raise JournalError("a suggestion decision's 'note' is text")
    elif action == "followup":
        _validate_targets(action, payload.get("targets"))
        if not isinstance(payload.get("done"), bool):
            raise JournalError("followup needs 'done': true to tick Followed up, or false to clear it")
    elif action == "finding":
        _validate_finding(payload)
    elif action == "file_written":
        _validate_file(payload)
    elif action == "manifest_recorded" and not manifest_ok(payload):
        raise JournalError(f"manifest_recorded needs manifest.jsonl's 'sha256', its 'bytes' and 'lines', each an "
                           f"integer from 0, and 'via', one of {MANIFEST_VIA}; a copy's may add 'unvouched', a list of "
                           f"reasons from {tuple(UNVOUCHED_WORDS)}")
    elif action == "undo":
        if not isinstance(payload.get("undoes"), int) or payload.get("correction") != "accident":
            raise JournalError("undo needs the 'undoes' entry number and correction: accident")
        changes = payload.get("changes")
        if not isinstance(changes, list) or not changes:
            raise JournalError("undo needs a non-empty list of 'changes'")
        for change in changes:
            if not isinstance(change, dict) or change.get("action") not in UNDOABLE:
                raise JournalError(f"an undo's changes are {UNDOABLE} actions")
            _validate(change["action"], {k: v for k, v in change.items() if k != "action"})
    elif action == "note_retract":
        if not payload.get("target") or not isinstance(payload.get("note_seq"), int):
            raise JournalError("note_retract needs 'target' and the note's 'note_seq'")
    elif action in ("tag", "tag_suggestion"):
        targets = payload.get("targets")
        if not targets or not all(isinstance(t, str) and t for t in targets):
            raise JournalError(f"{action} needs a non-empty list of event IDs in 'targets'")
        keys = (payload.get("add") or []) + (payload.get("remove") or []) if action == "tag" else payload.get("tags") or []
        if not keys:
            raise JournalError("tag needs tags to 'add' or 'remove'" if action == "tag" else "tag_suggestion needs 'tags'")
        for key in keys:
            try:
                if normalize_tag(key, listed=False) != key:   # the form alone, as a finding's techniques
                    raise JournalError(f"{key!r} isn't a tag key")
            except TagError as exc:
                raise JournalError(str(exc)) from exc
        if action == "tag_suggestion" and payload.get("decision") not in TAG_DECISIONS:
            raise JournalError(f"tag_suggestion needs a decision from {TAG_DECISIONS}")
    elif action == "host_split":
        op, host = payload.get("op"), payload.get("host")
        if op not in SPLIT_OPS or not isinstance(host, str) or not host:
            raise JournalError(f"host_split needs 'host' and op: {', '.join(SPLIT_OPS)}")
        if op == "split":
            routes = payload.get("routes")
            if not isinstance(routes, dict) or not routes or not all(
                    isinstance(k, str) and k and isinstance(v, str) and LANE.fullmatch(v) for k, v in routes.items()):
                raise JournalError("a split needs 'routes' from computer names to lanes of A-Z, 0-9, _ and -")
            if host in routes.values():
                raise JournalError("a split can't route a computer to the host it splits")
            stays = payload.get("stays", [])
            if not isinstance(stays, list) or not all(isinstance(n, str) for n in stays):
                raise JournalError("a split's 'stays' lists the computer names it leaves on the host")
        elif op == "undo" and not (isinstance(payload.get("undoes"), list) and payload["undoes"]
                                   and all(isinstance(s, int) for s in payload["undoes"])):
            raise JournalError("undoing a split needs the split entries' numbers in 'undoes'")
        elif op == "keep" and not (isinstance(payload.get("computers"), list) and payload["computers"]
                                   and all(isinstance(c, str) for c in payload["computers"])):
            raise JournalError("keeping a host needs its computer names in 'computers'")
    elif action == "case_created":
        if not (all(isinstance(payload.get(k), str) for k in ("name", "created_utc", "analyst", "evidence_path"))
                and _hex(payload.get("case_yaml"))):
            raise JournalError("case_created needs 'name', 'created_utc', 'analyst', 'evidence_path', and case.yaml's "
                               "SHA-256 in 'case_yaml'")
        if "case_format" in payload and not (_number(payload["case_format"]) and payload["case_format"] >= 1):
            raise JournalError("case_created's 'case_format' is the case format, an integer from 1")
        source = payload.get("copied_from", {})
        if not (isinstance(source, dict) and isinstance(source.get("folder", ""), str)):
            raise JournalError("a copy's 'copied_from' names its source 'folder'")
    elif action == "case_yaml":
        if not (_hex(payload.get("sha256")) and isinstance(payload.get("settings"), dict)):
            raise JournalError("case_yaml needs case.yaml's 'sha256' and its 'settings'")
    elif action == "journal_recovered":
        _validate_recovered(payload)
    elif action == "chain_break":
        found = payload.get("breaks")
        if not (isinstance(found, list) and found and all(
                isinstance(b, dict) and (b.get("line") is None or _number(b.get("line"))) and isinstance(b.get("kind"), str)
                for b in found)):
            raise JournalError("a chain_break lists its 'breaks', each with its 'line' and 'kind'")
        if not _sealed(payload.get("sealed")):
            raise JournalError("a chain_break's 'sealed' gives the 'lines', 'bytes', and 'sha256' of every byte before it")
        if not (isinstance(payload.get("reason"), str) and payload["reason"].strip()):
            raise JournalError("a chain_break needs the analyst's 'reason'")


def _hex(value) -> bool:
    return isinstance(value, str) and SHA256.fullmatch(value) is not None


def _validate_targets(action: str, targets, *, empty: bool = False) -> None:
    if not (isinstance(targets, list) and (targets or empty) and all(isinstance(t, str) and t for t in targets)):
        raise JournalError(f"{action} needs a {'' if empty else 'non-empty '}list of event IDs in 'targets'")


def _validate_confirmed(action: str, payload: dict) -> None:
    """A record of consent: the count the dialog stated, and how many of those were no longer pending at the click.
    Only the actions a confirm asks about carry it: a mark, a tag, a follow-up, a suggestion decision, and a finding's
    link or unlink."""
    confirmed = payload["confirmed"]
    if action not in ("mark", "tag", "followup", "suggestion_decision") and not (
            action == "finding" and payload.get("op") in ("link", "unlink")):
        raise JournalError(f"{action} doesn't carry 'confirmed'")
    if not (isinstance(confirmed, dict) and set(confirmed) == {"count", "skipped"}
            and all(_number(v) and v >= 0 for v in confirmed.values())):
        raise JournalError("'confirmed' gives the 'count' the dialog stated and how many were 'skipped'")


def _validate_finding(payload: dict) -> None:
    """A finding's op and its fields. A finding is named by the number of its add, as note_retract
    names its note; whether that finding exists, or is retired, is the server's to refuse, since replay applies what
    the journal holds."""
    op = payload.get("op")
    if op not in FINDING_OPS:
        raise JournalError(f"finding needs op: {', '.join(FINDING_OPS)}")
    if op != "add" and not (_number(payload.get("finding")) and payload["finding"] > 0):
        raise JournalError(f"a finding's {op} names the finding by the number of its add, in 'finding'")
    if op == "add" and any(k not in payload for k in ("title", "severity")):
        raise JournalError("a finding's add needs its 'title' and 'severity'")
    if op == "edit" and not any(k in payload for k in FINDING_FIELDS):
        raise JournalError(f"a finding's edit changes one or more of {', '.join(FINDING_FIELDS)}")
    if "title" in payload and not (isinstance(payload["title"], str) and payload["title"].strip()
                                   and len(payload["title"]) <= TITLE_MAX):
        raise JournalError(f"a finding's title is 1 to {TITLE_MAX} characters")
    if "severity" in payload and payload["severity"] not in SEVERITIES:
        raise JournalError(f"a finding's severity is one of {', '.join(SEVERITIES)}")
    if "narrative" in payload and not isinstance(payload["narrative"], str):
        raise JournalError("a finding's narrative is text, which may be empty")
    if "techniques" in payload and not (isinstance(payload["techniques"], list) and all(
            isinstance(t, str) and TECHNIQUE.fullmatch(t) for t in payload["techniques"])):
        raise JournalError("a finding's techniques are ATT&CK IDs such as T1543.003")
    if op in ("add", "link", "unlink"):
        _validate_targets(f"a finding's {op}", payload.get("targets", []), empty=op == "add")
    if "reason" in payload and not (op == "retire" and isinstance(payload["reason"], str)):
        raise JournalError("only a finding's retire carries a 'reason', as text")


def _validate_file(payload: dict) -> None:
    """A file the case wrote: where, relative to the case folder with / separators; what wrote it; its
    scope and filters; its rows, length, and SHA-256; and for a file that prints one, the head it printed."""
    path = payload.get("path")
    if not (isinstance(path, str) and path and "\\" not in path and not path.startswith("/") and ":" not in path
            and ".." not in path.split("/")):
        raise JournalError("file_written names the file by its 'path' inside the case folder, with / separators")
    if payload.get("kind") not in FILE_KINDS or payload.get("format") not in FILE_FORMATS:
        raise JournalError(f"file_written needs a 'kind' from {FILE_KINDS} and a 'format' from {FILE_FORMATS}")
    scope = payload.get("scope", {"marks": "all"})
    if not (isinstance(scope, dict) and scope.get("marks") in FILE_MARKS and set(scope) <= {"marks", "start", "end"}
            and all(_number(scope[k]) for k in ("start", "end") if k in scope)):
        raise JournalError(f"a file's 'scope' gives its marks, one of {FILE_MARKS}, and its 'start' and 'end' in "
                           "microseconds, absent for the whole case")
    filters = payload.get("filters")
    if not (filters is None or (isinstance(filters, dict) and set(filters) == {"text", "spec"}
                                and isinstance(filters["text"], str))):
        raise JournalError("a file's 'filters' are the applied Sources and View as {text, spec}, or null")
    if not (_number(payload.get("rows")) and _number(payload.get("bytes")) and _hex(payload.get("sha256"))):
        raise JournalError("file_written needs the file's 'rows', 'bytes', and 'sha256'")
    if ("journal_head" in payload) != ("head_seq" in payload) or (
            "journal_head" in payload and not (_hex(payload["journal_head"]) and _number(payload["head_seq"]))):
        raise JournalError("a file that prints a head records it in 'journal_head' with its entry's 'head_seq'")


def manifest_ok(payload: dict) -> bool:
    """Whether a manifest_recorded payload is whole: a SHA-256, the bytes and the lines that aren't blank, each an
    integer from 0, what wrote the manifest, and, for a copy's record, if it has `unvouched`, a list of the reasons in
    UNVOUCHED_WORDS, each once."""
    return (_hex(payload.get("sha256")) and all(_number(payload.get(k)) and payload[k] >= 0 for k in ("bytes", "lines"))
            and payload.get("via") in MANIFEST_VIA and ("unvouched" not in payload or _reasons(payload)))


def _reasons(payload: dict) -> bool:
    reasons = payload["unvouched"]
    return (payload.get("via") == "copy" and isinstance(reasons, list) and bool(reasons)
            and all(isinstance(r, str) and r in UNVOUCHED_WORDS for r in reasons) and len(set(reasons)) == len(reasons))


def manifest_of(entry: dict) -> dict:
    """A manifest_recorded entry as State.manifests and Check.manifests keep it."""
    kept = {k: entry[k] for k in ("seq", "at", "who", "sha256", "bytes", "lines", "via")}
    return {**kept, "unvouched": list(entry["unvouched"])} if "unvouched" in entry else kept


def unvouched_sentences(reasons: Iterable[str]) -> str:
    """The sentences for `reasons` (UNVOUCHED_WORDS), in their order and joined by '. ', with no final period; '' for
    none."""
    return ". ".join(words for reason, words in UNVOUCHED_WORDS.items() if reason in reasons)


def unvouched_words(record: dict) -> str:
    """The sentences for the reasons a copy's record names, or a check's line records for it (unvouched_sentences); ''
    for a record that names none, or whose `unvouched` is not a list."""
    reasons = record.get("unvouched")
    return unvouched_sentences(reasons) if isinstance(reasons, list) else ""


def unvouched_warns(reasons: Iterable[str]) -> bool:
    """Whether one of `reasons` is a warning (UNVOUCHED_WARNS): the source's journal had a break, or no head of it was
    recorded on this computer. Add new evidence's note is not."""
    return any(reason in UNVOUCHED_WARNS for reason in reasons)


def _sealed(sealed) -> bool:
    return (isinstance(sealed, dict) and _number(sealed.get("lines")) and _number(sealed.get("bytes"))
            and _hex(sealed.get("sha256")))


def _validate_recovered(payload) -> None:
    """A journal_recovered payload, or one in a case_upgrade's recovered: a side file, by its name, length,
    and SHA-256, with the entry it held or `found`; or an added line end, with the entry it ended, or null for a line of
    only whitespace."""
    entry_ok = lambda e: isinstance(e, dict) and set(e) == {"action", "seq"}
    if not isinstance(payload, dict):
        raise JournalError("a recovery is an object")
    if payload.get("completed") is True:
        if not (payload.get("entry") is None or entry_ok(payload["entry"])):
            raise JournalError("an added line end names the 'entry' it ended, its action and seq, or null")
        return
    if not (isinstance(payload.get("saved_as"), str) and SIDE_FILE.fullmatch(payload["saved_as"])
            and _number(payload.get("bytes")) and _hex(payload.get("sha256"))):
        raise JournalError("journal_recovered names a side file by 'saved_as', 'bytes', and 'sha256', or an added line "
                           "end by 'completed': true")
    if "held" in payload and not entry_ok(payload["held"]):
        raise JournalError("a side file's 'held' names the entry it held, its action and seq")
    if payload.get("found", True) is not True:
        raise JournalError("a found side file says 'found': true")


def _validate_rekey(rekey) -> None:
    """A case format upgrade's map of the event IDs the journal names. Each ID is exactly 32 lowercase hex characters,
    as event_uid makes it; the readers rely on the ID fields, and the counts and runs are the upgrade's to describe."""
    if not isinstance(rekey, dict) or not isinstance(rekey.get("pairs"), dict):
        raise JournalError("a rekey needs 'pairs', a map of old event IDs to new ones")
    is_id = lambda v: isinstance(v, str) and EVENT_ID.fullmatch(v) is not None
    if not all(is_id(old) and is_id(new) for old, new in rekey["pairs"].items()):
        raise JournalError("a rekey's 'pairs' maps event IDs of 32 lowercase hex characters to event IDs")
    for name in ("unplaced", "candidates_unplaced", "merged"):
        found = rekey.get(name, {})
        if not isinstance(found, dict) or not all(
                is_id(k) and isinstance(v, list) and v and all(is_id(x) for x in v) for k, v in found.items()):
            raise JournalError(f"a rekey's '{name}' maps event IDs to non-empty lists of event IDs")
    dropped = rekey.get("dropped_runs", {})
    if not isinstance(dropped, dict) or not all(
            isinstance(v, dict) and all(is_id(x) for x in v.get("references", [])) for v in dropped.values()):
        raise JournalError("a rekey's 'dropped_runs' names each run's rows and the event IDs referenced in them")
    for name in ("skipped_runs", "unpinned_runs"):
        if not isinstance(rekey.get(name, {}), dict):
            raise JournalError(f"a rekey's '{name}' maps run IDs to why")
    if "map_sha256" in rekey and not (isinstance(rekey["map_sha256"], str)
                                      and re.fullmatch(r"[0-9a-f]{64}", rekey["map_sha256"])):
        raise JournalError("a rekey's 'map_sha256' is a SHA-256 in lowercase hex")


def _apply(state: State, entry: dict) -> None:
    state.last_seq = max(state.last_seq, int(entry.get("seq", 0)))
    action = entry.get("action")
    if action == "mark":
        if entry["value"] not in MARK_VALUES:   # the analysis tables are built from it, so a case with one wouldn't open
            raise ValueError(f"a mark's value is one of {MARK_VALUES}")
        for uid in entry["targets"]:
            if entry["value"] == "unreviewed":
                state.marks.pop(uid, None)
            else:
                state.marks[uid] = Mark(entry["value"], entry.get("note", ""), entry["seq"], entry["at"], entry["who"])
    elif action == "note":
        state.notes.setdefault(entry["target"], []).append(
            {"text": entry["text"], "seq": entry["seq"], "at": entry["at"], "who": entry["who"]})
    elif action in ("host_role", "host_identity", "host_offset"):
        edits = state.hosts.setdefault(entry["host"], HostEdits())
        if action == "host_role":
            edits.role = entry.get("role", "")
            edits.role_who, edits.role_at = entry.get("who", ""), entry.get("at", "")
        elif action == "host_offset":
            edits.offset_seconds = float(entry.get("seconds", 0))
            edits.offset_align = str(entry.get("align", ""))
        else:
            # In the form the host lookup reads: a name's first label in upper case, as build_identity
            # takes names from the evidence, and an address as the parsers store it. Text that isn't an address, from
            # an entry made before the server checked, stays in upper case as it was.
            value, op = str(entry.get("value", "")).strip(), entry["op"]
            value = value.split(".")[0].upper() if op.endswith("name") else normalize_ip(value) or value.upper()
            add, remove = (edits.add_names, edits.remove_names) if op.endswith("name") else (edits.add_ips, edits.remove_ips)
            (add if op.startswith("add") else remove).add(value)
            (remove if op.startswith("add") else add).discard(value)
    elif action == "case_setting":
        state.settings[entry["name"]] = entry.get("value")
    elif action in ("rule_add", "rule_change"):
        state.rules[entry["id"]] = {"text": entry["text"], "builtin": bool(entry.get("builtin")),
                                    "seq": entry["seq"], "who": entry["who"]}
        state.removed_rules.discard(entry["id"])
    elif action == "rule_remove":
        state.rules.pop(entry["id"], None)
        state.removed_rules.add(entry["id"])
    elif action == "suggestion_decision":
        pairs = {(uid, entry["source"]) for uid in entry["targets"]}
        if entry["decision"] == "rejected":
            state.rejected |= pairs
        else:
            state.rejected -= pairs
        # A rejection's note stays with each event's rejection until a restore, or a rejection without one, replaces it.
        # One an undo brings back takes the undo's number, as an undone mark's note does.
        note = str(entry.get("note") or "").strip() if entry["decision"] == "rejected" else ""
        for pair in pairs:
            if note:
                state.decision_notes[pair] = {"text": note, "seq": entry["seq"], "at": entry["at"], "who": entry["who"]}
            else:
                state.decision_notes.pop(pair, None)
    elif action == "followup":   # a later mark leaves the tick
        for uid in entry["targets"]:
            if entry["done"]:
                state.followed[uid] = {"seq": entry["seq"], "at": entry["at"], "who": entry["who"]}
            else:
                state.followed.pop(uid, None)
    elif action == "finding":
        _apply_finding(state, entry)
    elif action == "file_written":
        # the scope and filters stay, so the Findings page words a file as the trail does (audit.file_words)
        state.files.append({k: entry.get(k) for k in ("seq", "at", "who", "path", "kind", "rows", "sha256", "scope", "filters")})
    elif action == "manifest_recorded":
        if not manifest_ok(entry):
            raise ValueError("a manifest record names the manifest's SHA-256, bytes, lines, and what wrote it")
        if "prev" in entry:   # only the chain records the manifest
            state.manifests.append(manifest_of(entry))
    elif action == "undo":   # each reversing change applies as its own action would, under the undo's number
        for change in entry["changes"]:
            if isinstance(change, dict) and change.get("action") == "undo":   # the writer never nests one; a forged
                raise ValueError("an undo's change is not an undo")           # chain of them would end in RecursionError
            _apply(state, {**change, "seq": entry["seq"], "at": entry["at"], "who": entry["who"]})
    elif action == "note_retract":   # the note stays on record, marked retracted
        for note in state.notes.get(entry["target"], []):
            if note["seq"] == entry["note_seq"]:
                note["retracted"] = {"seq": entry["seq"], "at": entry["at"], "who": entry["who"]}
    elif action == "tag":
        info = {"seq": entry["seq"], "at": entry["at"], "who": entry["who"], "via": entry.get("via", "")}
        for uid in entry["targets"]:
            tags = state.tags.setdefault(uid, {})
            for key in entry.get("add") or []:
                tags[key] = dict(info)
            for key in entry.get("remove") or []:
                tags.pop(key, None)
            if not tags:
                state.tags.pop(uid, None)
    elif action == "tag_suggestion":
        pairs = {(uid, key) for uid in entry["targets"] for key in entry["tags"]}
        if entry["decision"] == "dismissed":
            state.dismissed_tags |= pairs
        else:
            state.dismissed_tags -= pairs
    elif action == "host_split":
        # A second split of a host adds its routes to the first's, for computers that appeared since; an undo takes
        # every route of the host away, so the host is whole again.
        host, op = entry["host"], entry["op"]
        info = {"seq": entry["seq"], "at": entry.get("at", ""), "who": entry.get("who", "")}
        if op == "split":
            state.splits.setdefault(host, {}).update(entry["routes"])
            state.split_info.setdefault(host, []).append({**info, "lanes": sorted(set(entry["routes"].values()))})
            # The computers the split left on the host on purpose, such as a bare name two domains share, raise no
            # notice: the preview said why they stay. Keys as splits.computer_key makes them.
            state.kept.setdefault(host, set()).update(n.strip().lower() for n in entry.get("stays", []))
            state.kept_info.pop(host, None)   # the analyst split it after all
        elif op == "undo":
            # Back to before any choice: the notice returns while the host's logs record several computers.
            for found in (state.splits, state.split_info, state.kept, state.kept_info):
                found.pop(host, None)
        else:
            state.kept.setdefault(host, set()).update(entry["computers"])
            state.kept_info[host] = info
    elif is_rekey(entry):   # the entries before it were read through it already (_read)
        state.rekeys.append({**entry["rekey"], "seq": entry.get("seq")})


def _apply_finding(state: State, entry: dict) -> None:
    """A finding's op. Its ID is the number of its add. An op naming no finding is ignored, and an
    edit, link, or unlink of a retired one applies as written, since the entry is on record; the server refuses both."""
    info = {"seq": entry["seq"], "at": entry["at"], "who": entry["who"]}
    op = entry["op"]
    if op == "add":
        state.findings[entry["seq"]] = {
            "title": entry["title"], "severity": entry["severity"], "narrative": entry.get("narrative", ""),
            "techniques": list(entry.get("techniques") or []), "targets": list(dict.fromkeys(entry.get("targets") or [])),
            "added": info, "edited": None, "retired": None}
        return
    found = state.findings.get(entry["finding"])
    if found is None:
        return
    if op == "edit":
        for name in FINDING_FIELDS:
            if name in entry:
                found[name] = list(entry[name]) if name == "techniques" else entry[name]
        found["edited"] = info
    elif op == "link":
        found["targets"] = list(dict.fromkeys([*found["targets"], *entry["targets"]]))
    elif op == "unlink":
        gone = set(entry["targets"])
        found["targets"] = [t for t in found["targets"] if t not in gone]
    elif op == "retire":
        found["retired"] = {**info, "reason": entry.get("reason", "")}
    else:   # restore
        found["retired"] = None
