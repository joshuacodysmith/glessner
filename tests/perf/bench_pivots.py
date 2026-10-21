"""Performance check: time the counts the Event page asks for after it draws, at the case's size.

Usage: uv run python tests/perf/bench_pivots.py D:\\path\\to\\case-copy [runs]
It opens the case as the server does, which writes its derived tables, so give it a copy. For each seed, an event of one kind
in the pivot guidance table found by a condition below, it asks for what the page asks for: each counted row's count, one query
per row, with the window's breakdown by source, the event read once as the server keeps it. Then the second pass, the breakdown
of each other row whose count passed the list's limit. The aim is 300 ms for a seed's counts at 10 million events. Prints counts
and milliseconds, the median of `runs` (3) runs; no event text.
"""

from __future__ import annotations

import statistics
import sys
import time
from pathlib import Path

from glessner.case import open_case
from glessner.pivots import count_pivot, guidance
from glessner.queries import RELATED_LIMIT, anchor_of, event_details
from glessner.server import App

SEEDS = {
    "service install": "event_code = '7045' AND log_channel = 'System'",
    "network logon": "event_code = '4624' AND logon_type = '3' AND source_port <> ''",
    "RDP logon": "event_code = '4624' AND logon_type = '10'",
    "process creation": "event_code = '4688'",
    "failed logon": "event_code = '4625' AND source_workstation <> ''",
    "NTLM validation": "event_code = '4776'",
    "IDS alert": "tool = 'suricata' AND log_channel = 'alert'",
    "DNS record": "tool = 'suricata' AND log_channel = 'dns'",
    "scheduled task": "log_channel LIKE '%TaskScheduler%' AND event_code = '140'",
    "prefetch": "artifact = 'prefetch'",
    "RECmd service": "artifact = 'registry' AND message LIKE 'Services:%'",
    "Autoruns service": "artifact = 'autoruns' AND log_channel = 'Services'",
    "group change": "event_code = '4732'",
    "SRUM": "artifact = 'srum'",
}


def main(folder: str, runs: int = 3) -> None:
    t0 = time.perf_counter()
    app = App(open_case(Path(folder)))
    print(f"open {time.perf_counter() - t0:.1f} s, {app.con.execute('SELECT count(*) FROM events').fetchone()[0]:,} events")
    con = app.reader()
    worst = 0.0
    for name, where in SEEDS.items():
        row = con.execute(f"SELECT event_uid FROM events WHERE {where} LIMIT 1").fetchone()
        if row is None:
            print(f"{name:18} no event")
            continue
        uid = row[0]
        ev = event_details(con, uid, app.identity)
        g = guidance(ev, app.identity, {}, app.time_window_seconds)
        anchor = anchor_of(con, uid, app.identity, ev["adjusted_ts_us"])
        first, second = [], []
        for _ in range(runs):
            t0 = time.perf_counter()
            counts = []
            for r in g["rows"]:
                if r["count"]:
                    res = count_pivot(con, app.identity, uid, ev["adjusted_ts_us"], r["pivot"], ip=r.get("ip", ""),
                                      seconds=r.get("seconds", 60), term=r.get("term", ""),
                                      breakdown=r["breakdown"] == "always", anchor=anchor)
                    counts.append((r, res["count"]))
            first.append((time.perf_counter() - t0) * 1000)
            t0 = time.perf_counter()
            for r, n in counts:
                if r["breakdown"] != "always" and n > RELATED_LIMIT:
                    count_pivot(con, app.identity, uid, ev["adjusted_ts_us"], r["pivot"], ip=r.get("ip", ""),
                                seconds=r.get("seconds", 60), term=r.get("term", ""), breakdown=True, anchor=anchor)
            second.append((time.perf_counter() - t0) * 1000)
        worst = max(worst, statistics.median(first))
        print(f"{name:18} {len(counts)} counted rows  counts {statistics.median(first):6.0f} ms   sources pass "
              f"{statistics.median(second):6.0f} ms   " + ", ".join(f"{r['pivot']} {n:,}" for r, n in counts))
    print(f"slowest seed's counts: {worst:.0f} ms (aim 300 ms at 10 million events)")


if __name__ == "__main__":
    main(sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 3)
