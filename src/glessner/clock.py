"""Each host's clock against the network capture.

A host's logs and a packet capture record some of the same moments: an RDP connection accepted (RdpCoreTS 131), a logon
or Kerberos request from a client port, and a download written to the browser's cache. Pairing them measures how far
the host's clock ran from the sensor's, and when the pairs agree, the host gets a suggested offset. Nothing changes
until the analyst applies it, as an ordinary host_offset journal entry. On the Szechuan case both hosts ran 3,599.5 s
ahead of the capture: an hour less half a second, not an hour.

Everything is measured on recorded times (ts_us), never adjusted ones, so applying a suggestion doesn't move the
measurement. The reference is a sensor lane, one whose events all come from Suricata or Zeek, which the capture's own
packet times place. Firewall logs and imported IDS alerts carry the device's clock and are no reference. The skew S is
the host's time minus the sensor's; offset_seconds is added to a host's times (identity.HostIdentity), so the
suggestion is the sensor lane's own offset minus S.

Pitfalls of the pairing, and what handles each:
- An RDP brute force reuses each client port every 27 to 31 s, so each 131 matches 3 flows. The median of every
  candidate is 30 s wrong, and the nearest flow in absolute time is right only for a host ahead of the sensor. The
  center is the 2 s window of offsets holding the most distinct host events, and each host event keeps its candidate
  nearest that center.
- Windows hands out the same ephemeral ports after each boot, which builds false clusters across a gap in the capture.
  Each sensor record keeps only its nearest host event, and a host event with no candidate near the center counts
  against it, even when its sensor records went to other host events: a false cluster can tie the true one and win.
- A logon follows its flow's start by about 0.26 s, after Kerberos and LDAP. Latency only adds, so the estimate is the
  smallest per-kind median among kinds with 3 or more pairs that agree.
- Suricata writes IPv6 in full and Windows compresses it, so the sensor's addresses are normalized first.
- w32time can step a clock by an hour, which splits a host's evidence: one offset fits only the span its pairs cover.
  Clock changes (System 1 from Kernel-General, Security 4616) are listed with every result, in the order they happened.
  A change that sets the clock back repeats host times, so pairs among them can't be placed on either side of it.
"""

from __future__ import annotations

import itertools
import statistics
from collections import Counter
from dataclasses import dataclass
from typing import NamedTuple

import duckdb

from .events import from_us, insert_columns, sql_literal, to_us
from .identity import HostIdentity, Identity
from .parsers.common import normalize_ip

SEC = 1_000_000
SENSOR_ARTIFACTS = ("suricata", "zeek")   # a capture's own output; analysis.NETWORK_DEVICE_ARTIFACTS names them too
RDP_CHANNEL = "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational"
MAX_OFFSET_US = 86_400 * SEC   # server.MAX_OFFSET_SECONDS: no pair can need more than the largest offset allowed
# Candidate pairs per host and kind. A brute force can log millions of 131s, each matching a flow on every reuse of its
# port, so past this one host event in k is kept, with all its candidates.
MAX_PAIRS = 20_000
WINDOW_US = 2 * SEC            # the densest window's width, and the band around its center that pairs must fall in
MIN_AGREEING = 3               # pairs that must agree before anything is suggested
KIND_MIN = 3                   # agreeing pairs a kind needs to count for the estimate
ONE_KIND = 10                  # agreeing pairs of one kind that suggest an offset without a second kind
KINDS_AGREE_US = SEC           # two kinds agree when their medians are this close
AGREE_US = SEC // 2            # an applied offset this close to the suggestion agrees
STEP_US = 2 * SEC              # a clock change worth listing
WAKE = "2"                     # Kernel-General 1's Reason 2: the clock reread from the RTC on wake, not a skew change
ZONE_US = 900 * SEC            # time zones and daylight saving move clocks by multiples of 15 minutes
CLUSTERS = 3                   # groups of pairs listed when the pairs disagree
KIND_WORDS = {"rdp": ("RDP connection", "RDP connections"), "logon": ("logon", "logons"),
              "download": ("download", "downloads")}
MEASURED = ("suggest", "agrees")   # the states with a skew the pairs agree on
# The agreeing pairs of each measured host, for the event page and the report. gap_us is the host's time
# minus the sensor's, as recorded.
PAIRS_DDL = ("CREATE OR REPLACE TABLE clock_pairs (host_event_uid VARCHAR, sensor_event_uid VARCHAR, host VARCHAR, "
             "kind VARCHAR, gap_us BIGINT)")

# Candidate pairs for one sensor lane, from one query over recorded times. Host events are filtered by code, port, and
# time before any JSON is read. A logon or Kerberos event names the client's ip:port; so does a 131, as ClientIP. A
# download pairs an HTTP GET answered 200 with the first USN journal FileCreate of the browser cache's copy, name[n].ext:
# the Downloads copy is the user's later save, and a fileinfo record is logged when Suricata closes the file, which can
# be hours later. Kerberos must go to port 88 and a logon to a TCP flow, which drops DNS and RPC cross-matches.
# Sampling follows the pairing, so a host's logons from clients the sensor never saw don't crowd out the ones it did,
# and it takes host events whole, by their ID's hash, so no window sorts every host event.
CANDIDATES_SQL = r"""
WITH he AS (
  SELECT e.host, e.event_uid, e.ts_us, e.event_code, e.source_ip AS client, e.source_port AS port,
         CASE WHEN e.event_code = '131' THEN 'rdp' ELSE 'logon' END AS kind
  FROM events e
  WHERE e.artifact = 'evtx' AND e.source_port NOT IN ('', '0') AND e.source_ip <> ''
    AND ((e.event_code = '131' AND e.log_channel = $rdp)
         OR (e.event_code IN ('4624', '4625', '4776', '4768', '4769', '4771') AND e.log_channel = 'Security'))
    AND e.ts_us BETWEEN $lo - $max AND $hi + $max
    -- loopback, link-local, and the host's own addresses never cross the sensor
    AND NOT (e.source_ip IN ('::', '::1', '0.0.0.0') OR e.source_ip LIKE '127.%' OR e.source_ip LIKE '169.254.%'
             OR regexp_matches(e.source_ip, '^fe[89ab]'))
    AND NOT EXISTS (SELECT 1 FROM clock_host_ips o WHERE o.host = e.host AND o.ip = e.source_ip)),
fl AS (   -- Suricata's flow records and Zeek's conn.log, with the sensor's addresses written as Windows writes them
  SELECT f.event_uid, f.ts_us, COALESCE(a.ip, f.source_ip) AS src, f.source_port AS sport,
         COALESCE(b.ip, f.dest_ip) AS dst, f.dest_port AS dport, NULLIF(f.extra, '') AS extra
  FROM events f LEFT JOIN clock_ip_forms a ON a.raw = f.source_ip LEFT JOIN clock_ip_forms b ON b.raw = f.dest_ip
  WHERE f.host = $sensor AND f.log_channel IN ('flow', 'conn')),
web AS (   -- GET requests answered 200, by the URL's last part; Suricata's field names, then Zeek's
  SELECT event_uid, ts_us, client,
         lower(regexp_extract(COALESCE(json_extract_string(extra, '$."http.url"'), json_extract_string(extra, '$.uri')),
                              '([^/?]+)([?].*)?$', 1)) AS name
  FROM (SELECT f.event_uid, f.ts_us, COALESCE(a.ip, f.source_ip) AS client, NULLIF(f.extra, '') AS extra
        FROM events f LEFT JOIN clock_ip_forms a ON a.raw = f.source_ip
        WHERE f.host = $sensor AND f.log_channel = 'http')
  WHERE COALESCE(json_extract_string(extra, '$."http.http_method"'), json_extract_string(extra, '$.method')) = 'GET'
    AND COALESCE(json_extract_string(extra, '$."http.status"'), json_extract_string(extra, '$.status_code')) = '200'),
cache AS (   -- each cached copy's first creation; a file gets several FileCreate records, so files count, not records
  SELECT host, event_uid, ts_us,
         regexp_replace(lower(regexp_extract(file_path, '[^\x5c]+$')), '\[\d+\](\.[^.]*)?$', '\1') AS name
  FROM events
  WHERE artifact = 'usnjrnl' AND host IN (SELECT host FROM clock_host_ips)
    AND split_part(message, ':', 1) LIKE '%FileCreate%'
    AND regexp_matches(file_path, '\[\d+\](\.[^.\x5c]*)?$') AND ts_us BETWEEN $lo - $max AND $hi + $max
  QUALIFY row_number() OVER (PARTITION BY host, file_path ORDER BY ts_us, event_uid) = 1),
pairs AS MATERIALIZED (
  SELECT he.host, he.kind, he.event_uid, he.ts_us, fl.event_uid AS record, fl.ts_us AS record_ts
  FROM he JOIN clock_host_ips h ON h.host = he.host
  JOIN fl ON fl.src = he.client AND fl.sport = he.port AND fl.dst = h.ip
  WHERE abs(he.ts_us - fl.ts_us) <= $max
    AND CASE WHEN he.event_code = '131' THEN fl.dport = '3389'
             WHEN he.event_code IN ('4768', '4769', '4771') THEN fl.dport = '88'
             ELSE upper(json_extract_string(fl.extra, '$.proto')) = 'TCP' END
  UNION ALL
  SELECT h.host, 'download', c.event_uid, c.ts_us, w.event_uid, w.ts_us
  FROM web w JOIN clock_host_ips h ON h.ip = w.client
  JOIN cache c ON c.host = h.host AND c.name = w.name
  WHERE w.name LIKE '%.%' AND abs(c.ts_us - w.ts_us) <= $max),
rate AS (SELECT host, kind, CAST(ceil(count(*) / $budget) AS UBIGINT) AS k FROM pairs GROUP BY ALL)
SELECT p.* FROM pairs p JOIN rate r USING (host, kind) WHERE hash(p.event_uid) % r.k = 0
"""

# Clock changes: Kernel-General's System 1 gives OldTime, NewTime, and Reason; Security 4616 gives PreviousTime and
# NewTime. Both log the same change, so they're merged on the two times.
STEPS_SQL = """
    SELECT host, event_code, record_id, json_extract_string(NULLIF(extra, ''), '$.OldTime'),
           json_extract_string(NULLIF(extra, ''), '$.PreviousTime'), json_extract_string(NULLIF(extra, ''), '$.NewTime'),
           json_extract_string(NULLIF(extra, ''), '$.Reason')
    FROM events
    WHERE artifact = 'evtx' AND ((event_code = '1' AND event_provider = 'Microsoft-Windows-Kernel-General')
                                 OR (event_code = '4616' AND log_channel = 'Security'))"""
STEP_SOURCES = ("System 1", "Security 4616")   # each log numbers its records in order; System's is tried first


class Pair(NamedTuple):
    """A host event and a sensor record that may record the same moment."""
    off: int              # host time minus sensor time, both as recorded, in microseconds
    kind: str             # rdp, logon, or download
    uid: str              # the host event
    host_us: int
    record: str           # the sensor's flow or HTTP request
    sensor_us: int


@dataclass
class Measure:
    """One host's pairs with one sensor lane, resolved."""
    pairs: int                          # the inliers, and each host event with candidates but none near the center
    inliers: list[Pair]                 # within 2 s of the center, one per host event and per sensor record
    skew_us: float                      # the estimate S: host minus sensor
    medians: dict[str, float]           # kind -> median offset of its agreeing pairs
    clusters: list[tuple[float, int]]   # the densest groups of all pairs: center offset and size
    problem: str                        # why the pairs support no suggestion; empty when they do


def check_clocks(con: duckdb.DuckDBPyConnection, identity: Identity, cache: dict | None = None) -> dict[str, dict]:
    """Check every host's clock against the sensor lanes and record the result on its HostIdentity as `clock`. A host
    with an offset to suggest also gets a review reason, which the Hosts badge counts. Returns the results by host.

    The measurement reads only the events and the hosts' addresses. Given a `cache`, it's kept there and reused while
    the addresses stay the same, so an offset, role, or confirm edit doesn't rerun the queries; the caller empties the
    cache when events load. On a 30-million-event case the queries took about 4 s of every host edit.
    Each measurement also rewrites the table clock_pairs, which an offset can't change either.
    """
    cache = {} if cache is None else cache
    if "sensors" not in cache:
        cache.update(sensors=sensor_lanes(con), steps=clock_steps(con))
    sensors, steps = cache["sensors"], cache["steps"]
    # Normalized as the events' addresses are; the journal and the registry reader give this form already.
    own = sorted({(h.host, ip) for h in identity.hosts.values() if h.host not in sensors
                  for ip in (normalize_ip(i) for i in h.ips) if ip})
    if cache.get("own") != own:
        cache.update(own=own, measured=_measure_all(con, own, sensors))
        _write_pairs(con, cache["measured"], sensors)
    measured: dict[str, list[tuple[str, Measure]]] = cache["measured"]
    sensor_us = {s: round(identity.hosts[s].offset_seconds * SEC) for s in sensors if s in identity.hosts}
    results = {}
    for h in identity.hosts.values():
        options = measured.get(h.host, [])
        if h.host in sensors:
            result = _result(h, h.host, 0, None, steps.get(h.host, []))
            result["reason"] = "This lane is the capture the other hosts' clocks are checked against."
        elif options:   # the sensor lane with the most agreeing pairs; any other that disagrees is named
            sensor, m = _chosen(options, sensors)
            result = _result(h, sensor, sensor_us.get(sensor, 0), m, steps.get(h.host, []))
            result["sensors_note"] = _sensors_note(sensor, m, options, sensor_us)
        else:
            result = _result(h, sensors[0] if sensors else "", 0, None, steps.get(h.host, []))
            if sensors and not any(normalize_ip(ip) for ip in h.ips):   # pairs need the host's own addresses
                result["reason"] = (f"Its addresses aren't known, so none of its events can pair with the capture's "
                                    f"({sensors[0]}). Adding them in the Hosts table lets its clock be checked.")
        h.clock = results[h.host] = result
        if result["state"] == "suggest":
            h.review.append(result["reason"])
    return results


def _chosen(options: list[tuple[str, Measure]], sensors: list[str]) -> tuple[str, Measure]:
    """The sensor lane with the most agreeing pairs, the first one listed on a tie."""
    return max(options, key=lambda o: (len(o[1].inliers), -sensors.index(o[0])))


def _write_pairs(con: duckdb.DuckDBPyConnection, measured: dict[str, list[tuple[str, Measure]]],
                 sensors: list[str]) -> None:
    """Each host's agreeing pairs with its chosen sensor lane, as the table clock_pairs. A host whose pairs disagree
    gets none: which of them record the same moment isn't known."""
    con.execute(PAIRS_DDL)
    rows = []
    for host, options in sorted(measured.items()):
        m = _chosen(options, sensors)[1]
        if not m.problem:
            rows += [(p.uid, p.record, host, p.kind, p.off) for p in m.inliers]
    insert_columns(con, "clock_pairs", *zip(*rows))


def in_segment(result: dict, ts_us: int | None) -> bool:
    """Whether a host's measured offset fits its event recorded at `ts_us`: the event is on the clock the pairs were
    on, at a time no clock with another offset ran over (_segment). Without clock changes every event is; when it
    isn't known which clock the pairs were on, none is."""
    if result.get("state") not in MEASURED or ts_us is None:
        return False
    segment = result.get("segment")
    if segment is None:
        return True
    start, end = segment["start"], segment["end"]
    if start is None and end is None:   # _segment couldn't place the pairs; with steps, a known clock has a bound
        return False
    return (start is None or start <= ts_us) and (end is None or ts_us < end)


def alignment(hosts: list[HostIdentity]) -> str:
    """Whether the case shows its times as recorded or aligned to the capture, for the Case panel's switch: "none" with
    no measured host, "aligned" when each one agrees with the capture, "recorded" when none has an offset, "partly"
    when some agree and others don't, and "neither" when none agrees and one has an offset that isn't its suggestion,
    as a typed one can be. A host that agrees with no offset fits both, so it doesn't decide; with only such hosts,
    it's aligned.

    An offset the switch set counts after its host's measurement changes, so the switch stays to set it back: as
    aligned when the clock can no longer be measured, and as neither when it now suggests another offset.

    A host's clock is read with get(): an identity has none until build_tables checks it."""
    counted = [h for h in hosts if h.clock.get("state") in MEASURED or h.offset_aligned]
    if not counted:
        return "none"
    deciding = [h for h in counted if h.offset_seconds or h.clock.get("state") != "agrees"]
    aligned = [h for h in deciding if h.clock.get("state") != "suggest"]
    if len(aligned) == len(deciding):
        return "aligned"
    if aligned:
        return "partly"
    return "recorded" if not any(h.offset_seconds for h in deciding) else "neither"


def sensor_lanes(con: duckdb.DuckDBPyConnection) -> list[str]:
    """Lanes whose events all come from a packet sensor, as analysis.role_evidence finds the network devices."""
    artifacts = ", ".join(sql_literal(a) for a in SENSOR_ARTIFACTS)
    return [r[0] for r in con.execute(f"SELECT host FROM events GROUP BY host HAVING bool_and(artifact IN ({artifacts})) "
                                      "ORDER BY host").fetchall()]


def clock_steps(con: duckdb.DuckDBPyConnection) -> dict[str, list[dict]]:
    """Each host's clock changes of more than 2 s, in the order they happened, leaving out the RTC reread on wake
    (Reason 2). `at` is the host time after the change, `was` the time before it, and `seconds` the change's size.

    Host time can't order them: after a change that sets the clock back, the clock runs over the same times again. So
    they're ordered by the System log's record numbers when every change has one, else by the Security log's, and by
    `at` only when neither log holds them all."""
    found: dict[tuple, dict] = {}
    numbers: dict[tuple, dict[str, int]] = {}
    for host, code, record, old, previous, new, reason in con.execute(STEPS_SQL).fetchall():
        was, at = to_us(old or previous), to_us(new)
        if was is None or at is None:
            continue
        step = found.setdefault((host, was, at), {"at": at, "was": was, "seconds": round((at - was) / SEC, 3),
                                                  "reason": "", "sources": []})
        source = STEP_SOURCES[0] if code == "1" else STEP_SOURCES[1]
        if source not in step["sources"]:
            step["sources"] = sorted([*step["sources"], source])
        if record is not None:
            numbers.setdefault((host, was, at), {}).setdefault(source, record)
        if code == "1":
            step["reason"] = reason or ""
    kept: dict[str, list[tuple]] = {}
    for key, step in found.items():
        if step["reason"] != WAKE and abs(step["at"] - step["was"]) > STEP_US:
            kept.setdefault(key[0], []).append(key)
    steps: dict[str, list[dict]] = {}
    for host, keys in sorted(kept.items()):
        log = next((s for s in STEP_SOURCES if all(s in numbers.get(k, {}) for k in keys)), None)
        keys.sort(key=lambda k: (numbers[k][log], k[2]) if log else (k[2], k[1]))
        steps[host] = [found[k] for k in keys]
    return steps


def _measure_all(con: duckdb.DuckDBPyConnection, own: list[tuple[str, str]],
                 sensors: list[str]) -> dict[str, list[tuple[str, Measure]]]:
    """Each host's measures, one per sensor lane its events pair with."""
    measured: dict[str, list[tuple[str, Measure]]] = {}
    if sensors:
        _prepare(con, own, sensors)
        for sensor in sensors:
            for host, candidates in _candidates(con, sensor).items():
                m = measure(candidates)
                if m is not None:
                    measured.setdefault(host, []).append((sensor, m))
    return measured


def _prepare(con: duckdb.DuckDBPyConnection, own: list[tuple[str, str]], sensors: list[str]) -> None:
    """The hosts' own addresses, and the sensor's addresses as Windows writes them, as temp tables for the query."""
    con.execute("CREATE OR REPLACE TEMP TABLE clock_host_ips (host VARCHAR, ip VARCHAR)")
    insert_columns(con, "clock_host_ips", *zip(*own))
    con.execute("CREATE OR REPLACE TEMP TABLE clock_ip_forms (raw VARCHAR, ip VARCHAR)")
    lanes = ", ".join(sql_literal(s) for s in sensors)
    raw = con.execute(f"SELECT DISTINCT v FROM (SELECT unnest([source_ip, dest_ip]) AS v FROM events "
                      f"WHERE host IN ({lanes}) AND log_channel IN ('flow', 'conn', 'http')) WHERE v LIKE '%:%'").fetchall()
    forms = [(r, normalize_ip(r)) for (r,) in raw]
    insert_columns(con, "clock_ip_forms", *zip(*[(r, ip) for r, ip in forms if ip and ip != r]))


def _candidates(con: duckdb.DuckDBPyConnection, sensor: str) -> dict[str, list[Pair]]:
    lo, hi = con.execute("SELECT min(ts_us), max(ts_us) FROM events WHERE host = ? "
                         "AND log_channel IN ('flow', 'conn', 'http')", [sensor]).fetchone()
    if lo is None:
        return {}
    rows = con.execute(CANDIDATES_SQL, {"sensor": sensor, "lo": lo, "hi": hi, "max": MAX_OFFSET_US, "rdp": RDP_CHANNEL,
                                        "budget": MAX_PAIRS}).fetchall()
    by_host: dict[str, list[Pair]] = {}
    for host, kind, uid, host_us, record, sensor_us in rows:
        by_host.setdefault(host, []).append(Pair(host_us - sensor_us, kind, uid, host_us, record, sensor_us))
    return by_host


def measure(candidates: list[Pair]) -> Measure | None:
    """Find the center, resolve the pairs one to one, and judge whether they agree. None without candidates."""
    if not candidates:
        return None
    _, center = _densest(candidates)
    nearest: dict[str, Pair] = {}
    for p in sorted(candidates, key=lambda p: (p.uid, p.record)):   # each host event: its candidate nearest the center
        if p.uid not in nearest or abs(p.off - center) < abs(nearest[p.uid].off - center):
            nearest[p.uid] = p
    resolved: dict[str, Pair] = {}
    for p in sorted(nearest.values(), key=lambda p: (p.record, p.uid)):   # each sensor record: its nearest host event
        if p.record not in resolved or abs(p.off - center) < abs(resolved[p.record].off - center):
            resolved[p.record] = p
    inliers = [p for p in resolved.values() if abs(p.off - center) <= WINDOW_US]
    # A host event with no candidate near the center disagrees with it, with all its candidates, even when the step
    # above gave its sensor records to other host events. An earlier boot's logons that the capture missed, from the
    # same ephemeral ports, pair with the captured boot's flows as a group that can tie the true one and take its flows.
    near = {p.uid for p in candidates if abs(p.off - center) <= WINDOW_US}
    dissent = [p for p in candidates if p.uid not in near]
    runner_up = _densest(dissent)[0]
    dissenters = sorted({p.uid for p in dissent})
    offsets: dict[str, list[int]] = {}
    for p in inliers:
        offsets.setdefault(p.kind, []).append(p.off)
    medians = {kind: statistics.median(values) for kind, values in offsets.items()}
    counted = [medians[kind] for kind, values in offsets.items() if len(values) >= KIND_MIN]
    skew = min(counted) if counted else statistics.median(p.off for p in inliers) if inliers else center
    n, total = len(inliers), len(inliers) + len(dissenters)
    kinds_agree = any(abs(a - b) <= KINDS_AGREE_US for a, b in itertools.combinations(medians.values(), 2))
    problem = ""
    if n < MIN_AGREEING:
        problem = f"only {n} of its {total} pairs agree, and it takes {MIN_AGREEING}"
    elif 2 * n < total:
        problem = f"only {n} of its {total} pairs agree"
    elif n < 3 * runner_up:
        problem = f"a second group of {runner_up} pairs competes with the {n} that agree"
    elif not (kinds_agree or max(len(v) for v in offsets.values()) >= ONE_KIND):
        problem = (f"its kinds of pairs differ by more than {KINDS_AGREE_US // SEC} s" if len(offsets) > 1 else
                   f"the {n} pairs that agree are all {KIND_WORDS[next(iter(offsets))][1]}, and it takes {ONE_KIND} "
                   "of one kind or a second kind that agrees")
    return Measure(total, inliers, skew, medians, _clusters(inliers + [nearest[uid] for uid in dissenters]), problem)


def _densest(pairs: list[Pair]) -> tuple[int, float]:
    """The 2 s window of offsets holding the most distinct host events: their count and the window's median offset."""
    points = sorted((p.off, p.uid) for p in pairs)
    inside: Counter[str] = Counter()
    best, span, j = 0, (0, 0), 0
    for i, (off, uid) in enumerate(points):
        inside[uid] += 1
        while off - points[j][0] > WINDOW_US:
            inside[points[j][1]] -= 1
            if not inside[points[j][1]]:
                del inside[points[j][1]]
            j += 1
        if len(inside) > best:
            best, span = len(inside), (j, i + 1)
    return best, statistics.median(p[0] for p in points[span[0]:span[1]]) if best else 0.0


def _clusters(pairs: list[Pair]) -> list[tuple[float, int]]:
    """Up to 3 groups of pairs, densest first, to show when the pairs disagree."""
    left, out = list(pairs), []
    while left and len(out) < CLUSTERS:
        count, center = _densest(left)
        out.append((center, count))
        left = [p for p in left if abs(p.off - center) > WINDOW_US]
    return out


def _result(h: HostIdentity, sensor: str, sensor_us: int, m: Measure | None, steps: list[dict]) -> dict:
    """The page's and the report's view of one host's clock. `state` is suggest, agrees, disagree, or none.
    `seconds` is the offset_seconds to apply; skew and medians are host minus sensor, as recorded."""
    result = {"state": "none", "reference": sensor, "seconds": None, "display": "", "current_seconds": h.offset_seconds,
              "residual_seconds": None, "skew_seconds": None, "skew_text": "", "kind_seconds": {}, "basis": {},
              "basis_text": "", "inliers": 0, "pairs": 0, "spread_seconds": None, "span": None, "segment": None,
              "zone_note": "", "clusters": [], "reason": "", "steps": steps, "steps_text": _steps_text(steps),
              "span_note": "", "sensors_note": ""}
    if not sensor:
        result["reason"] = "No lane holds only Suricata or Zeek records, so there's no capture to compare with."
        return result
    if m is None:
        result["reason"] = f"None of its events pair with the capture's ({sensor})."
        return result
    result.update(pairs=m.pairs, inliers=len(m.inliers), skew_seconds=round(m.skew_us / SEC, 3),
                  skew_text=span_text(m.skew_us / SEC),
                  kind_seconds={k: round(v / SEC, 3) for k, v in sorted(m.medians.items())})
    if m.problem:
        result.update(state="disagree", reason=f"Its events pair with the capture's ({sensor}), but {m.problem}, "
                                               "so no offset is suggested.",
                      clusters=[{"seconds": round((sensor_us - c) / SEC, 1), "pairs": n} for c, n in m.clusters])
        return result
    suggested = sensor_us - m.skew_us
    residual = h.offset_seconds * SEC - suggested   # how far the adjusted times still run ahead of the capture's
    seconds = round(suggested / SEC, 1)
    counts = Counter(p.kind for p in m.inliers)
    basis = {kind: counts[kind] for kind in KIND_WORDS if counts[kind]}
    start, end = min(p.host_us for p in m.inliers), max(p.host_us for p in m.inliers)
    words = ", ".join(f"{n:,} {KIND_WORDS[kind][n != 1]}" for kind, n in basis.items())
    whole = round(abs(suggested) / ZONE_US)
    result.update(seconds=seconds, display=offset_text(seconds), residual_seconds=round(residual / SEC, 3), basis=basis,
                  basis_text=f"from {words}; {len(m.inliers):,} of {m.pairs:,} pairs within {WINDOW_US // SEC} s",
                  spread_seconds=round((max(m.medians.values()) - min(m.medians.values())) / SEC, 3),
                  span={"start": start, "end": end},
                  zone_note="Consistent with a clock set to the wrong hour or zone."
                  if whole and abs(abs(suggested) - whole * ZONE_US) <= 2 * SEC else "")
    if steps:
        result["segment"], result["span_note"] = _segment(start, end, steps)
    if abs(residual) <= AGREE_US:
        result.update(state="agrees", reason=f"{'With its applied offset, its' if h.offset_seconds else 'Its'} clock "
                                             f"agrees with the capture's (residual {residual / SEC:+.2f} s).")
    else:
        direction = "ahead of" if residual > 0 else "behind"
        result.update(state="suggest", reason=f"Clock looks {_rough(abs(residual) / SEC)} {direction} the capture"
                                              f"{' even with its offset applied' if h.offset_seconds else ''}")
    return result


def _sensors_note(chosen: str, m: Measure, options: list[tuple[str, Measure]], sensor_us: dict[str, int]) -> str:
    """Names the other sensor lanes whose agreeing pairs suggest an offset more than 1 s from the chosen one's."""
    mine = sensor_us.get(chosen, 0) - m.skew_us
    others = [(s, o) for s, o in options
              if s != chosen and not o.problem and abs(sensor_us.get(s, 0) - o.skew_us - mine) > KINDS_AGREE_US]
    if not others:
        return ""
    said = [f"{s} suggests {offset_text(round((sensor_us.get(s, 0) - o.skew_us) / SEC, 1))} from {len(o.inliers):,} "
            f"pairs" for s, o in others]
    return (f"The sensors disagree: {chosen} suggests {offset_text(round(mine / SEC, 1))} from {len(m.inliers):,} "
            f"pairs, and {_join(said)}. The one with the most pairs is used.")


def _segment(start: int, end: int, steps: list[dict]) -> tuple[dict, str]:
    """Which clock the pairs were on, as the host times it ran over, and a sentence saying which events one offset fits.

    The steps are in the order they happened, so each clock runs from one change's `at` to the next one's `was`. A
    change that sets the clock back repeats the times between its `at` and `was`, and pairs among them could be on the
    clock before it or after it. The offset also fits each other clock within the agreement band of the pairs' own: on
    the Szechuan dataset, DESKTOP's changes of -3,599.6 s and +3,599.2 s left it 0.4 s from where it began.

    The segment is the pairs' clock less the host times another clock also ran over, unless that clock's offset
    agrees, since an event recorded there may be on either. When w32time sets back a clock that ran ahead, the segment
    before the clock change ends at its `at`, not its `was`."""
    covered = f"The pairs cover {_when(start)} to {_when(end)} host time"
    lows, highs = [None, *(s["at"] for s in steps)], [*(s["was"] for s in steps), None]   # None: no change bounds it
    shifts = list(itertools.accumulate((s["at"] - s["was"] for s in steps), initial=0))   # each clock against the first
    holding = [i for i, (lo, hi) in enumerate(zip(lows, highs))
               if (lo is None or lo <= start) and (hi is None or end < hi)]
    if not holding:
        change = next((s for s in steps if min(s["at"], s["was"]) <= end and start < max(s["at"], s["was"])), steps[0])
        return {"start": None, "end": None}, f"{covered}, across the clock change at {_when(change['at'])}, " \
                                             "so one offset can't fit them all."
    if max(shifts[i] for i in holding) - min(shifts[i] for i in holding) > AGREE_US:
        change = next((s for s in steps[holding[0]:holding[-1]] if s["at"] < s["was"]), steps[holding[0]])
        return {"start": None, "end": None}, (f"{covered}, which the clock change at {_when(change['at'])} repeated "
                                              "when it set the clock back, so they may be from before it or after it, "
                                              "and it isn't known which of its events one offset fits.")
    mine = holding[0]
    first, last = lows[mine], highs[mine]
    for lo, hi, shift in zip(lows, highs, shifts):
        if abs(shift - shifts[mine]) <= AGREE_US:
            continue
        if lo is not None and lo > start:   # it ran over times after the pairs' first
            last = lo if last is None else min(last, lo)
        else:   # it began before the pairs, so it ended before their last, or it would hold them
            first = hi if first is None else max(first, hi)
    fits = [f"before the clock change at {_when(steps[0]['at'])}" if i == 0 else
            f"after the clock change at {_when(steps[-1]['at'])}" if i == len(steps) else
            f"between the clock changes at {_when(steps[i - 1]['at'])} and {_when(steps[i]['at'])}"
            for i, shift in enumerate(shifts) if abs(shift - shifts[mine]) <= AGREE_US]
    return {"start": first, "end": last}, f"{covered}, so one offset fits only its events {_join(fits)}."


def _steps_text(steps: list[dict]) -> str:
    if not steps:
        return ""
    changes = [f"by {s['seconds']:+,.1f} s at {_when(s['at'])}" for s in steps]
    return f"Its clock was changed {_join(changes)} host time."


def offset_text(seconds: float) -> str:
    """An offset for display: -3599.5 as '-3,599.5 s (1 h less 0.5 s)'."""
    spoken = _spoken(abs(seconds))
    return f"{seconds:+,.1f} s" + (f" ({spoken})" if spoken else "")


def _spoken(seconds: float) -> str:
    """How a person would say a span of a minute or more: 3599.5 as '1 h less 0.5 s', 91 as '1 min and 31.0 s'."""
    if seconds < 60:
        return ""
    minutes = round(seconds / 60)
    if abs(seconds - minutes * 60) > 5:   # far from a whole minute: count up from the one below
        minutes = int(seconds // 60)
    rest = round(seconds - minutes * 60, 1)
    whole = _hours_minutes(minutes)
    if not rest:
        return whole
    return f"{whole} less {-rest:.1f} s" if rest < 0 else f"{whole} and {rest:.1f} s"


def span_text(seconds: float) -> str:
    """A span's size to a tenth of a second, as the clock flags give it: 3599.5 as '59 m 59.5 s', 3600 as '1 h'."""
    minutes, tenths = divmod(round(abs(seconds) * 10), 600)
    hours, minutes = divmod(minutes, 60)
    parts = [f"{hours} h" if hours else "", f"{minutes} m" if minutes else "",
             f"{tenths / 10:g} s" if tenths or not (hours or minutes) else ""]
    return " ".join(part for part in parts if part)


def _rough(seconds: float) -> str:
    """A span in round words for a review reason: 3599.5 as '1 h', 125 as '2 min'; under 90 s, in seconds."""
    return _hours_minutes(round(seconds / 60)) if seconds >= 90 else f"{seconds:.1f} s"


def _hours_minutes(minutes: int) -> str:
    hours, minutes = divmod(minutes, 60)
    return " ".join(part for part in (f"{hours} h" if hours else "", f"{minutes} min" if minutes else "") if part)


def _when(us: int) -> str:
    return f"{from_us(us):%Y-%m-%d %H:%M:%S}"


def _join(items: list[str]) -> str:
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " and " + items[-1]
