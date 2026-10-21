"""Performance check: time case open, lanes, views at each zoom level, and an export.

Usage: uv run python tests/perf/bench_views.py D:\\DFIR-Lab\\cases\\perf-10-hosts
Measures the server side only (what /api/view does). Drawing in the browser took
about 0.6 ms per 1,000 events on the canvas when measured. The pass mark is under 1 second per view.
"""

from __future__ import annotations

import json
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

from glessner.case import open_case
from glessner.events import connect
from glessner.export import export_timeline
from glessner.queries import lanes, parse_groupby, view
from glessner.server import App
from glessner.splits import apply_layout, machines


def us(text: str) -> int:
    return int(datetime.fromisoformat(text).replace(tzinfo=UTC).timestamp() * 1_000_000)


def main(folder: str) -> None:
    case = open_case(Path(folder))
    t0 = time.perf_counter()
    connect(case.db_path).close()   # adds a column an older database lacks, such as origin_host
    migrate_s = time.perf_counter() - t0
    t0 = time.perf_counter()
    app = App(case)
    open_s = time.perf_counter() - t0
    # The host split's check at every open and load: the lanes against the journal, with nothing to change on
    # a case that isn't split, and the computers in each host's event logs, before the server caches them.
    t0 = time.perf_counter()
    apply_layout(app.con, app.journal.state)
    layout_ms = (time.perf_counter() - t0) * 1000
    t0 = time.perf_counter()
    machines(app.con)
    machines_ms = (time.perf_counter() - t0) * 1000
    con = app.reader()
    rows = con.execute("SELECT count(*) FROM events").fetchone()[0]
    hosts = len(app.identity.hosts)
    keys = parse_groupby("mark,role,host")
    t0 = time.perf_counter()
    lane_list = lanes(con, keys)
    lanes_ms = (time.perf_counter() - t0) * 1000
    first, last = con.execute("SELECT min(ts_us), max(ts_us) FROM events WHERE ts_us IS NOT NULL").fetchone()
    windows = [("full range", first, last + 1),
               ("case week", us("2020-09-15T00:00:00"), us("2020-09-22T00:00:00")),
               ("attack day", us("2020-09-19T00:00:00"), us("2020-09-20T00:00:00")),
               ("attack hour", us("2020-09-19T03:00:00"), us("2020-09-19T04:00:00")),
               ("10 minutes", us("2020-09-19T03:30:00"), us("2020-09-19T03:40:00")),
               ("1 minute", us("2020-09-19T03:36:00"), us("2020-09-19T03:37:00"))]
    hour = windows[3][2] - windows[3][1]
    windows += [(f"pan {i}", windows[3][1] + i * hour // 4, windows[3][2] + i * hour // 4) for i in range(1, 5)]
    results = []
    for name, start, end in windows:
        t0 = time.perf_counter()
        v = view(con, app.identity, keys, start, end, 300, app.event_threshold, True)
        payload = len(json.dumps(v, default=str))
        ms = (time.perf_counter() - t0) * 1000
        results.append({"window": name, "mode": v["mode"], "events": v["count"], "links": len(v["links"]["items"]),
                        "ms": round(ms), "payload_kb": round(payload / 1024)})
    t0 = time.perf_counter()
    path, exported = export_timeline(app.con, case, app.identity, windows[3][1], windows[3][2], "csv", "all")
    export_s = time.perf_counter() - t0
    app.con.close()
    print(f"{rows:,} events, {hosts} hosts, {len(lane_list)} lanes")
    print(f"case open (derived tables, identity, suggestions): {open_s:.1f} s; lanes: {lanes_ms:.0f} ms")
    print(f"migration {migrate_s:.2f} s; host split check {layout_ms:.0f} ms; computers per host {machines_ms:.0f} ms")
    print(f"{'window':<12} {'mode':<8} {'events':>10} {'links':>6} {'ms':>6} {'payload KB':>11}")
    for r in results:
        print(f"{r['window']:<12} {r['mode']:<8} {r['events']:>10,} {r['links']:>6} {r['ms']:>6} {r['payload_kb']:>11,}")
    print(f"export of the attack hour: {exported:,} events in {export_s:.1f} s to {path.name}")
    print(f"worst view: {max(r['ms'] for r in results)} ms")
    out = Path(folder) / "bench_views.json"
    out.write_text(json.dumps({"rows": rows, "hosts": hosts, "open_s": open_s, "lanes_ms": lanes_ms, "views": results,
                               "export_s": export_s, "exported": exported, "migrate_s": migrate_s,
                               "layout_ms": layout_ms, "machines_ms": machines_ms}, indent=2))


if __name__ == "__main__":
    main(sys.argv[1])
