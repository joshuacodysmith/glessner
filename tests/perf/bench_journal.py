"""Journal performance check: time opening a case whose journal holds about 300 MB of bulk marks, and one mark of
200,000 events, on this build or an older one.

Usage: uv run python tests/perf/bench_journal.py SCRATCH [runs] [megabytes]
SCRATCH is an empty folder; the script makes a synthetic case there, with no evidence. To time an older build, put its
src first on PYTHONPATH (git archive of the build, unpacked outside the repository); the script prints which glessner
it ran. The open is what an open for work reads of the journal: format 2's replay, or this build's read, the checks
under the lock, and the head record's write. The append is Journal.append, its fsync and, on this build, the head
record's write included. Prints the median and the range of `runs` (5) runs, in seconds; no event text.
"""

from __future__ import annotations

import hashlib
import statistics
import sys
import time
from pathlib import Path

import glessner
from glessner.case import create_case, open_case
from glessner.journal import Journal

BULK = 10_000   # events in each mark that fills the journal: about 360 KB a line


def uids(start: int, n: int) -> list[str]:
    return [hashlib.sha256(str(i).encode()).hexdigest()[:32] for i in range(start, start + n)]


def opened(case) -> Journal:
    journal = Journal(case)
    if hasattr(journal, "open_for_work"):   # this build: the checks of an open for work and the head record
        journal.open_for_work()
    return journal


def main(scratch: str, runs: int = 5, megabytes: int = 300) -> None:
    print(f"glessner from {glessner.__file__}")
    root = Path(scratch)
    evidence = root / "evidence"
    evidence.mkdir(parents=True, exist_ok=True)
    case = create_case(root / "case", "Journal bench", evidence, "bench")
    path = case.folder / "journal.jsonl"
    journal = Journal(case)
    n = 0
    t0 = time.perf_counter()
    while path.stat().st_size < megabytes * 1_000_000:
        journal.append("mark", targets=uids(n * BULK, BULK), value="suspicious" if n % 2 else "malicious")
        n += 1
    print(f"filled {path.stat().st_size / 1e6:,.0f} MB in {n:,} marks of {BULK:,} events in "
          f"{time.perf_counter() - t0:,.1f} s")
    case = open_case(case.folder)
    opens = []
    for _ in range(runs):
        t0 = time.perf_counter()
        journal = opened(case)
        opens.append(time.perf_counter() - t0)
    print(f"open: median {statistics.median(opens):.2f} s, {min(opens):.2f} to {max(opens):.2f} s, "
          f"{len(journal.state.marks):,} marked events")
    appends = []
    for i in range(runs):
        targets = uids(10_000_000 + i * 200_000, 200_000)
        t0 = time.perf_counter()
        journal.append("mark", targets=targets, value="suspicious")
        appends.append(time.perf_counter() - t0)
    print(f"append of a 200,000-event mark: median {statistics.median(appends):.2f} s, "
          f"{min(appends):.2f} to {max(appends):.2f} s")


if __name__ == "__main__":
    main(sys.argv[1], *(int(a) for a in sys.argv[2:]))
