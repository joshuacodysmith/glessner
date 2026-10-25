"""Synthetic chained journals for the journal chain tests: lines that name the line before them, written as the
journal writes them, so a test can change one byte and see the break. Also cases set back to an older format, as an
older build made or left them."""

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from glessner import case as case_module
from glessner import journal as journal_module
from glessner.case import Case, open_case
from glessner.journal import ZERO, Journal, line_bytes, start_chain
from glessner.server import App

AT = "2026-10-17T02:14:09.118204Z"
BUILD = "0.2.0+1a2b3c4"
UID = "0123456789abcdef0123456789abcdef"
OTHER = "fedcba9876543210fedcba9876543210"
CHECKER = Path(__file__).resolve().parent.parent / "scripts" / "check_journal.py"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def envelope(seq, prev, action, *, who="cody", client="cli", build=BUILD, at=AT, **payload) -> dict:
    """A chained entry: the envelope in its order, then the payload."""
    return {"seq": seq, "prev": prev, "at": at, "who": who, "build": build, "client": client, "action": action,
            **payload}


def unchained(*entries: dict) -> bytes:
    """Format 1 or 2 lines, as format 2's append wrote them."""
    return b"".join(json.dumps(e, ensure_ascii=False).encode("utf-8") + b"\n" for e in entries)


def note(seq, uid=UID, text="looked at it", **more) -> dict:
    """An unchained note."""
    return {"seq": seq, "at": AT, "who": "cody", "action": "note", "target": uid, "text": text, **more}


def created(**more) -> dict:
    return {"name": "Synthetic", "created_utc": "2026-10-17T02:00:00Z", "analyst": "cody",
            "evidence_path": "D:\\evidence", "case_yaml": sha(b"case.yaml"), **more}


def seal(before: bytes, **more) -> dict:
    """A seal's payload over `before`, the unchained bytes."""
    lines = sum(1 for line in before.split(b"\n")[:-1] if line.strip())
    return {"from_format": 2, "to_format": 3, "text": "Sealed the earlier journal entries.",
            "sealed": {"lines": lines, "bytes": len(before), "sha256": sha(before)}, **more}


def lines(data: bytes) -> list[bytes]:
    """The whole lines, without their LF."""
    return data.split(b"\n")[:-1]


def join(found: list[bytes]) -> bytes:
    return b"".join(line + b"\n" for line in found)


def last_seq(data: bytes) -> int:
    seqs = []
    for line in lines(data):
        try:
            seqs.append(int(json.loads(line)["seq"]))
        except (ValueError, KeyError, TypeError, OverflowError):   # int() of Infinity raises OverflowError
            continue
    return max(seqs, default=0)


def add(data: bytes, action: str, *, who="cody", client="cli", seq=None, **payload) -> bytes:
    """`data` with a line that names its last line, as the app writes it, or as a forger who knows the format would."""
    prev = sha(lines(data)[-1]) if data else ZERO
    return data + line_bytes(envelope(last_seq(data) + 1 if seq is None else seq, prev, action, who=who, client=client,
                                      **payload))


def chained(items=(), before: bytes = b"") -> bytes:
    """`before`, unchained bytes, then the chain: a seal over `before` when it holds anything, else case_created at byte
    0, then a line for each (action, payload) of `items`, each naming the line before it."""
    if before:
        first = envelope(last_seq(before) + 1, ZERO, "case_upgrade", who="glessner", **seal(before))
    else:
        first = envelope(1, ZERO, "case_created", who="glessner", **created())
    data = before + line_bytes(first)
    for action, payload in items:
        data = add(data, action, **payload)
    return data


MARKS = [("mark", {"targets": [UID], "value": "suspicious"}), ("note", {"target": UID, "text": "first look"}),
         ("mark", {"targets": [OTHER], "value": "malicious"}), ("note", {"target": OTHER, "text": "second"})]


def head(data: bytes) -> str:
    return sha(lines(data)[-1])


def as_format(folder: Path, value: int, journal: bytes = b"") -> None:
    """A case this build made, set back to an older format as an older build would have made it: case.yaml's
    case_format, an unchained journal of `journal`'s bytes, and no head recorded outside the case."""
    from glessner.heads import forget

    data = yaml.safe_load((folder / "case.yaml").read_text(encoding="utf-8"))
    data["case_format"] = value
    (folder / "case.yaml").write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    (folder / "journal.jsonl").write_bytes(journal)
    forget(folder)


def format3_case(case: Case) -> Case:
    """`case`, a new case with nothing after case_created, as a format 3 build made it: case.yaml at format 3, and a
    chain that starts with case_created naming that case.yaml, whose head is recorded outside the case. Its evidence and
    events database stay as they are."""
    as_format(case.folder, 3)
    case = open_case(case.folder)
    start_chain(case, "cli")
    return case


def worked_at_format_3(case: Case, marks: int = 4) -> bytes:
    """The case opened for work by a format 3 build, which journals its case_open, as BUILD, and the built-in rules,
    then `marks` marks with a note; the journal's bytes."""
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(case_module, "CASE_FORMAT", 3)
        patch.setattr(journal_module, "build_id", lambda: BUILD)
        App(open_case(case.folder), for_work=True).con.close()
        journal = Journal(open_case(case.folder))
        for i in range(marks):
            journal.append("mark", targets=[f"{i:032x}"], value="suspicious", note="first look")
    return (case.folder / "journal.jsonl").read_bytes()


def append_unchained(folder: Path, action: str, *, who="cody", **payload) -> dict:
    """An entry appended as a format 1 or 2 build appended it, with no prev, build, or client."""
    path = folder / "journal.jsonl"
    entry = {"seq": last_seq(path.read_bytes()) + 1, "at": AT, "who": who, "action": action, **payload}
    with path.open("ab") as f:
        f.write(unchained(entry))
    return entry


def run_checker(path: Path, *args: str) -> tuple[int, str]:
    """scripts/check_journal.py's exit and output, run as a reviewer runs it, with -I."""
    done = subprocess.run([sys.executable, "-I", str(CHECKER), str(path), *args], capture_output=True, text=True,
                          encoding="utf-8", check=False)
    return done.returncode, done.stdout + done.stderr
