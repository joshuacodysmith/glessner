"""Each host's clock against the network capture, on synthetic pairs.

The cases here load lanes of their own, never into synthetic_case, whose rows other tests count. Times follow the
Szechuan case: both hosts ran 3,599.5 s ahead of the capture.
"""

import ipaddress
import itertools
import statistics
import threading
import time
from collections import Counter
from datetime import UTC, datetime

import pytest
from conftest import SEC, T0, registry

from glessner import analysis, clock, export, server
from glessner.analysis import build_identity, build_tables
from glessner.audit import describe, read_entries
from glessner.case import create_case
from glessner.events import Event, connect, event_uid, load, to_us
from glessner.export import write_report
from glessner.identity import HostIdentity
from glessner.journal import Journal, State
from glessner.queries import QueryError
from glessner.server import (
    App,
    api_counts,
    api_event,
    api_event_keys,
    api_filter,
    api_host,
    api_mark,
    api_meta,
    api_rule,
    api_suggestion,
    api_tag,
    api_tag_suggestion,
    api_undo,
)

CAPTURE = "network/case001.pcap"
DC_IP, WS_IP, ATTACKER = "10.42.85.10", "10.42.85.115", "194.61.24.102"
AHEAD = 3_599_500_000   # microseconds
RUNS = itertools.count(1)
RECORDS = itertools.count(1)


def iso(us):
    """A time as Suricata's EVE writes it."""
    return datetime.fromtimestamp(us // SEC, UTC).strftime("%Y-%m-%dT%H:%M:%S") + f".{us % SEC:06d}+0000"


def evtx_time(us):
    """A time as EvtxECmd writes it, with seven fraction digits."""
    return datetime.fromtimestamp(us // SEC, UTC).strftime("%Y-%m-%d %H:%M:%S") + f".{us % SEC:06d}0"


def when(us):
    return datetime.fromtimestamp(us // SEC, UTC).strftime("%Y-%m-%d %H:%M:%S")


def flow(ts, src, dst, proto="TCP", seconds=1.0, artifact="suricata", channel="flow"):
    """A sensor's flow record from ip:port to ip:port, at its start. Zeek's conn.log gives a duration, not an end."""
    (src_ip, src_port), (dest_ip, dest_port) = src.rsplit(":", 1), dst.rsplit(":", 1)
    if artifact == "zeek":
        extra = {"proto": proto.lower(), "duration": str(seconds)}
    else:
        extra = {"proto": proto, **({"flow.end": iso(ts + int(seconds * SEC))} if seconds is not None else {})}
    return Event(ts_us=ts, ts_desc="Suricata flow started", artifact=artifact, source_file=CAPTURE,
                 source_record=f"{channel}|{ts}|{src}|{dst}", message=f"Flow {src} -> {dst}", log_channel=channel,
                 source_ip=src_ip, source_port=src_port, dest_ip=dest_ip, dest_port=dest_port, extra=extra)


def accepted(ts, client, host="DC01"):
    """RdpCoreTS 131: the host accepted a TCP connection from client, before any logon."""
    ip, port = client.rsplit(":", 1)
    record = next(RECORDS)
    return Event(ts_us=ts, ts_desc="Event Recorded", artifact="evtx", source_file=f"{host}/RdpCoreTS.evtx",
                 source_record=str(record), record_id=record, message="131 connection accepted", event_code="131",
                 log_channel=clock.RDP_CHANNEL, source_ip=ip, source_port=port)


def security(ts, code, client, host="DC01"):
    ip, port = client.rsplit(":", 1)
    record = next(RECORDS)
    return Event(ts_us=ts, ts_desc="Event Recorded", artifact="evtx", source_file=f"{host}/Security.evtx",
                 source_record=str(record), record_id=record, message=f"{code} logon", event_code=code,
                 log_channel="Security", logon_type="3" if code == "4624" else "", source_ip=ip, source_port=port)


def brute_force(n, skew, host="DC01", host_ip=DC_IP, start=T0, first_port=40000):
    """n accepted RDP connections, each on a client port the attacker used twice before, 27 to 31 s apart, as in the
    Szechuan case's brute force. Returns the sensor's flows and the host's 131s, `skew` ahead of the sensor."""
    flows, events = [], []
    for i in range(n):
        client = f"{ATTACKER}:{first_port + i}"
        first = start + i * 3 * SEC
        second = first + (27 + i % 5) * SEC + 500_000
        third = second + (27 + 2 * i % 5) * SEC + 700_000
        flows += [flow(t, client, f"{host_ip}:3389") for t in (first, second, third)]
        events.append(accepted(third + skew + (i % 3 - 1) * 8_000, client, host))   # the host's 15.6 ms timer
    return flows, events


def logons(n, skew, code="4624", dport="445", host="DC01", host_ip=DC_IP, start=T0 + 600 * SEC, first_port=50000):
    """n logons from DESKTOP's address, each logged 0.26 s after its flow began, as the Szechuan case's were."""
    flows, events = [], []
    for i in range(n):
        t, client = start + i * 7 * SEC, f"{WS_IP}:{first_port + i}"
        flows.append(flow(t, client, f"{host_ip}:{dport}"))
        events.append(security(t + 260_000 + skew, code, client, host))
    return flows, events


def usn(ts, path, reasons="FileCreate"):
    return Event(ts_us=ts, ts_desc="USN journal change", artifact="usnjrnl", source_file="DESKTOP/$Extend/$J",
                 source_record=str(next(RECORDS)), message=f"{reasons}: {path}", event_code="FileCreate",
                 file_path=path)


def request(ts, name, status="200", client_ip=WS_IP):
    return Event(ts_us=ts, ts_desc="Suricata http", artifact="suricata", source_file=CAPTURE,
                 source_record=f"http|{ts}|{name}", message=f"HTTP GET /{name} {status}", log_channel="http",
                 source_ip=client_ip, source_port="49800", dest_ip=ATTACKER, dest_port="80",
                 extra={"http.url": f"/{name}", "http.http_method": "GET", "http.status": status})


def time_changed(old, new, reason="1", provider="Microsoft-Windows-Kernel-General", host="DESKTOP"):
    """System event 1 as EvtxECmd gives it, in UTC with seven fraction digits."""
    record = next(RECORDS)
    return Event(ts_us=to_us(new), ts_desc="Event Recorded", artifact="evtx", source_file=f"{host}/System.evtx",
                 source_record=str(record), record_id=record, message="1 The system time was changed", event_code="1",
                 event_provider=provider, log_channel="System", extra={"OldTime": old, "NewTime": new, "Reason": reason})


def time_changed_4616(old, new, host="DESKTOP"):
    record = next(RECORDS)
    return Event(ts_us=to_us(new), ts_desc="Event Recorded", artifact="evtx", source_file=f"{host}/Security.evtx",
                 source_record=str(record), record_id=record, message="4616 The system time was changed",
                 event_code="4616", event_provider="Microsoft-Windows-Security-Auditing", log_channel="Security",
                 extra={"PreviousTime": old, "NewTime": new})


# DESKTOP's clock changes in the Szechuan case: w32time set it back an hour, then forward an hour.
BACK = ("2020-09-18 05:58:01.9239364", "2020-09-18 04:58:02.3055654")
FORWARD = ("2020-09-18 21:43:05.9283863", "2020-09-18 22:43:05.1440626")


@pytest.fixture
def case(tmp_path):
    """DC01 at 10.42.85.10 and DESKTOP at 10.42.85.115, from their SYSTEM hives, and nothing else yet."""
    for host in ("DC01", "DESKTOP"):
        (tmp_path / "evidence" / host).mkdir(parents=True)
    c = create_case(tmp_path / "case", "Clock", tmp_path / "evidence", "cody")
    tcpip = "ROOT\\ControlSet001\\Services\\Tcpip\\Parameters\\Interfaces\\{1}"
    for host, ip in (("DC01", DC_IP), ("DESKTOP", WS_IP)):
        add(c, host, "recmd", [registry(f"{host}/Windows/System32/config/SYSTEM", tcpip, "IPAddress", ip)])
    return c


def add(case, host, tool, events):
    load(case.db_path, events, host=host, tool=tool, tool_version="t", run_id=f"run{next(RUNS)}", replaces_sources=[],
         staging_dir=case.folder)


def checked(case):
    """Each host's identity, with its clock result, as a case open builds them."""
    con = connect(case.db_path)
    try:
        journal = Journal(case)
        identity = build_identity(con, journal.state)
        build_tables(con, journal.state, identity)
        return identity.hosts
    finally:
        con.close()


def test_port_reuse_doesnt_pull_the_estimate_off(case):
    """Each 131 matches the 3 flows on its port. The median of every candidate is 30 s off; the densest window isn't."""
    flows, events = brute_force(30, AHEAD)
    add(case, "network", "suricata", flows)
    add(case, "DC01", "evtxecmd", events)
    every = [e.ts_us - f.ts_us for e in events for f in flows if (f.source_ip, f.source_port) == (e.source_ip, e.source_port)]
    assert statistics.median(every) / SEC > 3625
    dc = checked(case)["DC01"]
    c = dc.clock
    assert (c["state"], c["seconds"], c["basis"], c["inliers"], c["pairs"]) == ("suggest", -3599.5, {"rdp": 30}, 30, 30)
    assert (c["display"], c["reference"], c["skew_seconds"]) == ("-3,599.5 s (1 h less 0.5 s)", "network", 3599.5)
    assert c["basis_text"] == "from 30 RDP connections; 30 of 30 pairs within 2 s"
    assert c["zone_note"] == "Consistent with a clock set to the wrong hour or zone."
    assert c["span"] == {"start": min(e.ts_us for e in events), "end": max(e.ts_us for e in events)}
    assert dc.review == ["Role not confirmed", "Clock looks 1 h ahead of the capture"]


def test_a_host_behind_the_sensor(case):
    """The nearest flow in absolute time would be a stale one here; the densest window still finds the skew."""
    flows, events = brute_force(30, -125_300_000, host="DESKTOP", host_ip=WS_IP)
    add(case, "network", "suricata", flows)
    add(case, "DESKTOP", "evtxecmd", events)
    nearest = min((events[0].ts_us - f.ts_us for f in flows if f.source_port == events[0].source_port), key=abs)
    assert nearest / SEC > -100
    ws = checked(case)["DESKTOP"]
    assert (ws.clock["state"], ws.clock["seconds"], ws.clock["display"]) == ("suggest", 125.3, "+125.3 s (2 min and 5.3 s)")
    assert ws.clock["zone_note"] == "" and ws.review[-1] == "Clock looks 2 min behind the capture"


def test_logons_lag_their_flows_so_the_earliest_kind_sets_the_estimate(case):
    rdp_flows, rdp = brute_force(12, AHEAD)
    smb_flows, smb = logons(8, AHEAD)
    krb_flows, krb = logons(6, AHEAD, code="4769", dport="88", start=T0 + 900 * SEC, first_port=51000)
    # Not pairs: Kerberos to a port other than 88, a loopback client, the host's own address, and link-local clients,
    # whose addresses repeat on every segment.
    Journal(case).append("host_identity", host="DC01", op="add_ip", value="fe80::10")
    stray_flows = [flow(T0 + 1000 * SEC, f"{WS_IP}:52000", f"{DC_IP}:389"),
                   flow(T0 + 1001 * SEC, "127.0.0.1:52001", f"{DC_IP}:445"),
                   flow(T0 + 1002 * SEC, f"{DC_IP}:52002", f"{DC_IP}:445"),
                   flow(T0 + 1003 * SEC, "169.254.7.7:52003", f"{DC_IP}:445"),
                   flow(T0 + 1004 * SEC, "fe80::7:52004", "fe80::10:445")]
    stray = [security(T0 + 1000 * SEC + AHEAD, "4769", f"{WS_IP}:52000"),
             security(T0 + 1001 * SEC + AHEAD, "4624", "127.0.0.1:52001"),
             security(T0 + 1002 * SEC + AHEAD, "4624", f"{DC_IP}:52002"),
             security(T0 + 1003 * SEC + AHEAD, "4624", "169.254.7.7:52003"),
             security(T0 + 1004 * SEC + AHEAD, "4624", "fe80::7:52004")]
    add(case, "network", "suricata", rdp_flows + smb_flows + krb_flows + stray_flows)
    add(case, "DC01", "evtxecmd", rdp + smb + krb + stray)
    c = checked(case)["DC01"].clock
    assert (c["basis"], c["pairs"]) == ({"rdp": 12, "logon": 14}, 26)
    assert c["kind_seconds"] == {"logon": 3599.76, "rdp": 3599.5} and c["spread_seconds"] == 0.26
    assert c["seconds"] == -3599.5   # the logons alone would say -3,599.8 and place every event 0.3 s early


def test_a_download_pairs_with_the_first_record_of_its_cache_copy(case):
    """A cache copy gets FileCreate records until it's closed, and the user's save to Downloads is another file of the
    same name. Paired, the later records would outnumber the first ones and move the center 3 s, and the Downloads
    copies would compete with it."""
    flows, events = brute_force(3, AHEAD, host="DESKTOP", host_ip=WS_IP)
    requests, journal = [request(T0 + 1500 * SEC, "coreupdater.exe", "404")], []
    for k, name in enumerate(("coreupdater.exe", "tools.zip", "notes.pdf")):
        t, (stem, ext) = T0 + (1200 + 60 * k) * SEC, name.rsplit(".", 1)
        cache = f"\\Users\\Administrator\\AppData\\Local\\Microsoft\\Windows\\INetCache\\IE\\X1\\{stem}[1].{ext}"
        requests.append(request(t, name))
        journal += [usn(t + AHEAD - 4_000, cache),
                    *(usn(t + AHEAD + ms * 1000, cache, "DataExtend|FileCreate") for ms in (2_600, 3_000, 3_400)),
                    usn(t + AHEAD + 3_200_000, f"\\Users\\Administrator\\Downloads\\{name}")]
    add(case, "network", "suricata", flows + requests)
    add(case, "DESKTOP", "evtxecmd", events)
    add(case, "DESKTOP", "mftecmd_j", journal)
    c = checked(case)["DESKTOP"].clock
    assert (c["state"], c["seconds"], c["basis"]) == ("suggest", -3599.5, {"rdp": 3, "download": 3})
    assert c["kind_seconds"]["download"] == 3599.496
    assert c["basis_text"] == "from 3 RDP connections, 3 downloads; 6 of 6 pairs within 2 s"


def test_pairs_that_disagree_suggest_nothing(case):
    near_flows, near = brute_force(5, AHEAD)
    far_flows, far = brute_force(5, 1_800_000_000, start=T0 + 3000 * SEC, first_port=41000)
    few_flows, few = brute_force(2, AHEAD, host="DESKTOP", host_ip=WS_IP, first_port=42000)
    add(case, "network", "suricata", near_flows + far_flows + few_flows)
    add(case, "DC01", "evtxecmd", near + far)
    add(case, "DESKTOP", "evtxecmd", few)
    hosts = checked(case)
    dc, ws = hosts["DC01"].clock, hosts["DESKTOP"].clock
    assert (dc["state"], dc["seconds"], dc["pairs"]) == ("disagree", None, 10)
    assert sorted((c["seconds"], c["pairs"]) for c in dc["clusters"]) == [(-3599.5, 5), (-1800.0, 5)]
    assert dc["reason"] == ("Its events pair with the capture's (network), but a second group of 5 pairs competes with "
                            "the 5 that agree, so no offset is suggested.")
    assert ws["state"] == "disagree" and "only 2 of its 2 pairs agree, and it takes 3" in ws["reason"]
    assert not any(r.startswith("Clock") for h in hosts.values() for r in h.review)


@pytest.mark.parametrize("gap,captured,state", [(-3, 10, "disagree"), (3, 10, "disagree"), (-3, 40, "suggest")])
def test_logons_after_a_boot_the_capture_missed_count_against_the_center(case, gap, captured, state):
    """Windows hands out the same ephemeral ports after each boot. DESKTOP logs on to DC01 after two boots `gap` hours
    apart, the capture holds only the boot at T0, and the other boot's 10 logons pair with its flows as a false group.
    With 10 true logons the groups tie, and the false one, an earlier boot's, would win the tie and take every flow."""
    flows, events = logons(captured, AHEAD, start=T0, first_port=49671)
    _, missed = logons(10, AHEAD, start=T0 + gap * 3600 * SEC, first_port=49671)
    add(case, "network", "suricata", flows)
    add(case, "DC01", "evtxecmd", events + missed)
    c = checked(case)["DC01"].clock
    assert (c["state"], c["inliers"], c["pairs"]) == (state, captured, captured + 10)
    if state == "suggest":
        assert c["seconds"] == -3599.8 and c["basis_text"] == "from 40 logons; 40 of 50 pairs within 2 s"
    else:
        false = round(-(AHEAD + 260_000 + gap * 3600 * SEC) / SEC, 1)
        assert sorted((x["seconds"], x["pairs"]) for x in c["clusters"]) == sorted([(-3599.8, 10), (false, 10)])
        assert "a second group of 10 pairs competes with the 10 that agree" in c["reason"]


def test_a_flow_pairs_with_one_host_event(case):
    """An RDP logon logs a 4625 or 4624 on the 131's client port, so both pair with the same flow. The flow keeps the
    one nearer the center; the other is a duplicate, neither counted nor held against the center."""
    flows, events = brute_force(12, AHEAD)
    failed = [security(e.ts_us + 1_500_000, "4625", f"{e.source_ip}:{e.source_port}") for e in events[:6]]
    add(case, "network", "suricata", flows)
    add(case, "DC01", "evtxecmd", events + failed)
    c = checked(case)["DC01"].clock
    assert (c["state"], c["basis"], c["pairs"], c["kind_seconds"]) == ("suggest", {"rdp": 12}, 12, {"rdp": 3599.5})


def test_the_sensors_own_offset_carries_into_the_suggestion(case):
    """The capture's lane runs 5 s slow and the analyst set its offset, so the host's suggestion is that offset minus
    the skew, which is measured on recorded times and doesn't change."""
    flows, events = brute_force(12, AHEAD)
    add(case, "network", "suricata", flows)
    add(case, "DC01", "evtxecmd", events)
    Journal(case).append("host_offset", host="network", seconds=5.0)
    c = checked(case)["DC01"].clock
    assert (c["state"], c["seconds"], c["skew_seconds"]) == ("suggest", -3594.5, 3599.5)


@pytest.mark.parametrize("n,state", [(9, "disagree"), (10, "suggest")])
def test_one_kind_alone_takes_ten_pairs(case, n, state):
    flows, events = brute_force(n, AHEAD)
    add(case, "network", "suricata", flows)
    add(case, "DC01", "evtxecmd", events)
    c = checked(case)["DC01"].clock
    assert c["state"] == state
    if state == "disagree":
        assert "the 9 pairs that agree are all RDP connections, and it takes 10 of one kind" in c["reason"]


def test_applying_the_suggestion_through_the_hosts_api(case):
    flows, events = brute_force(12, AHEAD)
    add(case, "network", "suricata", flows)
    add(case, "DC01", "evtxecmd", events)
    app = App(case)
    try:
        api_host(app, {"confirm_hosts": ["DC01", "DESKTOP", "network"]})   # the clock is DC01's only reason
        dc = next(h for h in api_meta(app, {})["hosts"] if h["host"] == "DC01")
        assert (dc["clock"]["state"], dc["review"]) == ("suggest", ["Clock looks 1 h ahead of the capture"])
        assert api_counts(app, {})["hosts_review"] == 1
        dc = next(h for h in api_host(app, {"host": "DC01", "offset_seconds": -3500})["hosts"] if h["host"] == "DC01")
        assert dc["clock"]["state"] == "suggest"
        assert dc["review"] == ["Clock looks 2 min ahead of the capture even with its offset applied"]
        payload = api_host(app, {"host": "DC01", "offset_seconds": dc["clock"]["seconds"]})
        dc = next(h for h in payload["hosts"] if h["host"] == "DC01")
        assert (dc["clock"]["state"], dc["clock"]["residual_seconds"], dc["review"]) == ("agrees", 0.0, [])
        assert dc["clock"]["skew_seconds"] == 3599.5   # measured on recorded times, so applying it moves nothing
        assert dc["clock"]["reason"] == "With its applied offset, its clock agrees with the capture's (residual +0.00 s)."
        assert api_counts(app, {})["hosts_review"] == 0
    finally:
        app.con.close()


def test_ipv6_pairs_match_the_sensors_full_form(case):
    """Suricata writes IPv6 in full; Windows and the analyst's added address (stored upper-case) don't."""
    host, client = "2001:db8:85::10", "2001:db8:99::5"
    Journal(case).append("host_identity", host="DC01", op="add_ip", value=host)
    full = {ip: ipaddress.ip_address(ip).exploded for ip in (host, client)}
    flows = [flow(T0 + i * 10 * SEC, f"{full[client]}:{45000 + i}", f"{full[host]}:3389", seconds=None)
             for i in range(12)]   # without flow.end, only the 2 s band applies
    add(case, "network", "suricata", flows)
    add(case, "DC01", "evtxecmd", [accepted(f.ts_us + AHEAD, f"{client}:{f.source_port}") for f in flows])
    c = checked(case)["DC01"].clock
    assert (c["state"], c["seconds"], c["basis"]) == ("suggest", -3599.5, {"rdp": 12})


def test_clock_changes_are_listed_and_bound_the_suggestion(case):
    flows, events = brute_force(10, AHEAD, host="DESKTOP", host_ip=WS_IP)
    changes = [
        time_changed(*BACK), time_changed_4616(*BACK),   # one change, logged twice
        time_changed("2020-09-18 04:58:02.3302659", "2020-09-18 04:58:02.3355217"),   # 5 ms
        time_changed("2020-09-18 05:46:47.6863892", "2020-09-18 05:46:47.6863892", reason="3"),
        time_changed(*FORWARD), time_changed_4616(*FORWARD),
        time_changed("2020-09-19 01:54:39.6645222", "2020-09-19 03:13:20.5000000", reason="2"),   # woke from sleep
        time_changed("2020-09-19 01:00:00.0000000", "2020-09-19 02:00:00.0000000", provider="Microsoft-Windows-FilterManager"),
    ]
    add(case, "network", "suricata", flows)
    add(case, "DESKTOP", "evtxecmd", events + changes)
    c = checked(case)["DESKTOP"].clock
    assert [(s["at"], s["seconds"], s["sources"]) for s in c["steps"]] == [
        (to_us(BACK[1]), -3599.618, ["Security 4616", "System 1"]),
        (to_us(FORWARD[1]), 3599.216, ["Security 4616", "System 1"])]
    assert c["steps_text"] == ("Its clock was changed by -3,599.6 s at 2020-09-18 04:58:02 and by +3,599.2 s at "
                               "2020-09-18 22:43:05 host time.")
    assert (c["state"], c["seconds"], c["segment"]) == ("suggest", -3599.5, {"start": to_us(FORWARD[1]), "end": None})
    first, last = min(e.ts_us for e in events), max(e.ts_us for e in events)
    # The two changes net -0.4 s, so the clock before the first is the pairs' own, within the agreement band
    assert c["span_note"] == (f"The pairs cover {when(first)} to {when(last)} host time, so one offset fits only its "
                              "events before the clock change at 2020-09-18 04:58:02 and after the clock change at "
                              "2020-09-18 22:43:05.")


def test_pairs_in_times_a_change_repeated_arent_placed(case):
    """w32time set the clock back an hour after the pairs, so the clock ran over their host times again after it."""
    flows, events = brute_force(12, AHEAD)
    first, last = min(e.ts_us for e in events), max(e.ts_us for e in events)
    was = last + 600 * SEC
    add(case, "network", "suricata", flows)
    add(case, "DC01", "evtxecmd", events + [time_changed(evtx_time(was), evtx_time(was - 3600 * SEC), host="DC01")])
    c = checked(case)["DC01"].clock
    assert (c["state"], c["seconds"], c["segment"]) == ("suggest", -3599.5, {"start": None, "end": None})
    assert c["span_note"] == (f"The pairs cover {when(first)} to {when(last)} host time, which the clock change at "
                              f"{when(was - 3600 * SEC)} repeated when it set the clock back, so they may be from "
                              "before it or after it, and it isn't known which of its events one offset fits.")


@pytest.mark.parametrize("logged", [time_changed, time_changed_4616], ids=["system", "security"])
def test_clock_changes_are_ordered_as_logged(case, logged):
    """Forward an hour, then back an hour 30 minutes later: by host time, the second change would come first, and the
    pairs would seem to be on the clock the first change set."""
    flows, events = brute_force(12, AHEAD, host="DESKTOP", host_ip=WS_IP)
    first, hour = min(e.ts_us for e in events), 3600 * SEC
    forward = (first - 3 * hour, first - 2 * hour)
    back = (first - 3 * hour // 2, first - 5 * hour // 2)
    add(case, "network", "suricata", flows)
    add(case, "DESKTOP", "evtxecmd", events + [logged(*map(evtx_time, forward)), logged(*map(evtx_time, back))])
    c = checked(case)["DESKTOP"].clock
    assert [(s["at"], s["seconds"]) for s in c["steps"]] == [(forward[1], 3600.0), (back[1], -3600.0)]
    assert c["steps_text"] == f"Its clock was changed by +3,600.0 s at {when(forward[1])} and by -3,600.0 s at " \
                              f"{when(back[1])} host time."
    assert c["segment"] == {"start": back[0], "end": None}   # the clock before the change also ran up to its `was`
    assert c["span_note"].endswith(f"so one offset fits only its events before the clock change at {when(forward[1])} "
                                   f"and after the clock change at {when(back[1])}.")


def test_a_change_inside_the_pairs_span_is_named(case):
    flows, events = brute_force(12, AHEAD)
    middle = (min(e.ts_us for e in events) + max(e.ts_us for e in events)) // 2
    add(case, "network", "suricata", flows)
    add(case, "DC01", "evtxecmd", events + [time_changed(evtx_time(middle - 10 * SEC), evtx_time(middle), host="DC01")])
    c = checked(case)["DC01"].clock
    assert c["segment"] == {"start": None, "end": None}
    assert c["span_note"].endswith(f"across the clock change at {when(middle)}, so one offset can't fit them all.")


def test_without_a_sensor_lane_nothing_is_suggested(case):
    """A firewall's own log keeps the firewall's clock, so it's no reference even when its records would pair."""
    flows, events = brute_force(12, AHEAD)
    for f in flows:
        f.artifact = "fortinet"
    add(case, "FORTIGATE", "import", flows)
    add(case, "DC01", "evtxecmd", events + [time_changed(*BACK, host="DC01")])
    hosts = checked(case)
    dc = hosts["DC01"].clock
    assert (dc["state"], dc["reference"]) == ("none", "")
    assert dc["reason"] == "No lane holds only Suricata or Zeek records, so there's no capture to compare with."
    assert dc["steps_text"] == "Its clock was changed by -3,599.6 s at 2020-09-18 04:58:02 host time."
    assert hosts["FORTIGATE"].clock["state"] == "none"
    assert not any(r.startswith("Clock") for h in hosts.values() for r in h.review)


def test_the_shared_fixtures_have_no_pairs(suricata_case):
    """synthetic_case's logons carry no ports; suricata_case's lane is a sensor with alerts but no flows."""
    hosts = checked(suricata_case)
    assert {h: (v.clock["state"], v.clock["reference"]) for h, v in hosts.items()} == {
        "DC01": ("none", "network"), "DESKTOP": ("none", "network"), "network": ("none", "network")}
    assert hosts["DC01"].clock["reason"] == "None of its events pair with the capture's (network)."
    assert clock.alignment(list(hosts.values())) == "none"


def test_a_host_without_addresses_says_so(case):
    """The analyst's address edits feed the check: with DC01's address removed, nothing can pair."""
    flows, events = brute_force(12, AHEAD)
    add(case, "network", "suricata", flows)
    add(case, "DC01", "evtxecmd", events)
    Journal(case).append("host_identity", host="DC01", op="remove_ip", value=DC_IP)
    c = checked(case)["DC01"].clock
    assert (c["state"], c["reason"]) == ("none", "Its addresses aren't known, so none of its events can pair with the "
                                                 "capture's (network). Adding them in the Hosts table lets its clock be "
                                                 "checked.")


def test_zeek_conn_logs_are_a_reference(case):
    flows, events = brute_force(12, AHEAD)
    add(case, "ZEEK", "zeek", [flow(f.ts_us, f"{f.source_ip}:{f.source_port}", f"{f.dest_ip}:{f.dest_port}",
                                    artifact="zeek", channel="conn") for f in flows])
    add(case, "DC01", "evtxecmd", events)
    c = checked(case)["DC01"].clock
    assert (c["state"], c["seconds"], c["reference"]) == ("suggest", -3599.5, "ZEEK")


def test_sensors_that_disagree_are_named(case):
    flows, events = brute_force(12, AHEAD)
    add(case, "network", "suricata", flows)
    # A second sensor whose clock runs 5 s ahead, and which saw the first 10 connections only
    add(case, "ZEEK", "zeek", [flow(f.ts_us + 5 * SEC, f"{f.source_ip}:{f.source_port}", f"{f.dest_ip}:{f.dest_port}",
                                    artifact="zeek", channel="conn") for f in flows[:30]])
    add(case, "DC01", "evtxecmd", events)
    c = checked(case)["DC01"].clock
    assert (c["reference"], c["seconds"], c["inliers"]) == ("network", -3599.5, 12)
    assert c["sensors_note"] == ("The sensors disagree: network suggests -3,599.5 s (1 h less 0.5 s) from 12 pairs, and "
                                 "ZEEK suggests -3,594.5 s (59 min and 54.5 s) from 10 pairs. The one with the most "
                                 "pairs is used.")


def test_huge_cases_are_sampled_by_host_event(case, monkeypatch):
    """Past MAX_PAIRS, one host event in k is kept by its ID's hash, with every one of its candidates."""
    flows, events = brute_force(30, AHEAD)   # each 131 matches the 3 flows on its port: 90 candidates
    add(case, "network", "suricata", flows)
    add(case, "DC01", "evtxecmd", events)
    monkeypatch.setattr(clock, "MAX_PAIRS", 30)
    con = connect(case.db_path)
    try:
        clock._prepare(con, [("DC01", DC_IP)], ["network"])
        kept = clock._candidates(con, "network")["DC01"]
        chosen = {uid for (uid,) in con.execute("SELECT event_uid FROM events WHERE event_code = '131' "
                                                "AND hash(event_uid) % 3 = 0").fetchall()}
    finally:
        con.close()
    assert 0 < len(chosen) < 30
    assert Counter(p.uid for p in kept) == dict.fromkeys(chosen, 3)
    assert checked(case)["DC01"].clock["pairs"] == len(chosen)


def test_logons_the_sensor_never_saw_leave_the_sample_alone(case, monkeypatch):
    """A DC logs Kerberos requests from a segment the sensor doesn't see. Sampling follows the pairing, so they don't
    thin out the 40 requests it did see."""
    flows, events = logons(40, AHEAD, code="4769", dport="88")
    unseen = [security(T0 + i * 9 * SEC + AHEAD, "4769", f"10.42.86.{20 + i % 200}:{50000 + i}") for i in range(400)]
    add(case, "network", "suricata", flows)
    add(case, "DC01", "evtxecmd", events + unseen)
    monkeypatch.setattr(clock, "MAX_PAIRS", 40)
    c = checked(case)["DC01"].clock
    assert (c["state"], c["seconds"], c["pairs"]) == ("suggest", -3599.8, 40)


def test_a_port_reused_all_attack_long_still_pairs(case):
    """An attacker cycling 2 client ports uses each one 12 times in an hour, so every 131 matches 12 flows. Only the
    true offset holds all 24; the others hold at most the events one cycle apart, spread by the attempts' jitter."""
    flows, events = [], []
    for i in range(24):
        client, t = f"{ATTACKER}:{47000 + i % 2}", T0 + i * 150 * SEC + (i % 7) * 900_000
        flows.append(flow(t, client, f"{DC_IP}:3389"))
        events.append(accepted(t + AHEAD, client))
    add(case, "network", "suricata", flows)
    add(case, "DC01", "evtxecmd", events)
    c = checked(case)["DC01"].clock
    assert (c["state"], c["seconds"], c["inliers"], c["pairs"]) == ("suggest", -3599.5, 24, 24)


def test_host_edits_reuse_the_clock_measurement(case, monkeypatch):
    """Offsets, roles, and confirmations leave the measurement alone; an address edit or a load measures again."""
    flows, events = brute_force(12, AHEAD)
    add(case, "network", "suricata", flows)
    add(case, "DC01", "evtxecmd", events)
    calls, real = [], clock._candidates
    monkeypatch.setattr(clock, "_candidates", lambda con, sensor: calls.append(sensor) or real(con, sensor))
    app = App(case)
    try:
        api_host(app, {"confirm_hosts": ["DC01", "DESKTOP", "network"]})
        api_host(app, {"host": "DC01", "role": "Servers"})
        dc = next(h for h in api_host(app, {"host": "DC01", "offset_seconds": -3599.5})["hosts"] if h["host"] == "DC01")
        assert (calls, dc["clock"]["state"]) == (["network"], "agrees")
        api_host(app, {"host": "DC01", "op": "add_ip", "value": "10.42.85.11"})
        assert calls == ["network"] * 2
        more_flows, more = brute_force(12, AHEAD, start=T0 + 2000 * SEC, first_port=41000)
        add(case, "network", "suricata", more_flows)
        add(case, "DC01", "evtxecmd", more)
        assert app.con.execute("SELECT count(*) FROM clock_pairs").fetchone()[0] == 12
        app.refresh_identity(events_changed=True)
        assert calls == ["network"] * 3 and app.identity.hosts["DC01"].clock["inliers"] == 24
        assert app.con.execute("SELECT count(*) FROM clock_pairs").fetchone()[0] == 24
    finally:
        app.con.close()


def test_findings_summary_says_a_suggestion_is_pending_and_lists_clock_changes(case):
    flows, events = brute_force(12, AHEAD)
    add(case, "network", "suricata", flows)
    add(case, "DC01", "evtxecmd", events + [time_changed(*FORWARD, host="DC01")])
    add(case, "DESKTOP", "evtxecmd", [time_changed(*BACK)])
    con = connect(case.db_path)
    try:
        journal = Journal(case)
        identity = build_identity(con, journal.state)
        build_tables(con, journal.state, identity)
        path, _ = write_report(con, case, identity, {}, State())
    finally:
        con.close()
    text = path.read_text(encoding="utf-8")
    assert "| 10.42.85.10 | none; -3,599.5 s suggested, not applied |" in text
    assert "| 10.42.85.115 | none |" in text
    first, last = min(e.ts_us for e in events), max(e.ts_us for e in events)
    assert ("- **DC01.** Its events pair with the capture's (network) and suggest a clock offset of -3,599.5 s (1 h less "
            "0.5 s), from 12 RDP connections; 12 of 12 pairs within 2 s. Consistent with a clock set to the wrong hour "
            "or zone. It isn't applied, so its times may not line up with the capture's. Its clock was changed by "
            f"+3,599.2 s at 2020-09-18 22:43:05 host time. The pairs cover {when(first)} to {when(last)} host time, so "
            "one offset fits only its events after the clock change at 2020-09-18 22:43:05.") in text
    assert ("- **DESKTOP.** Its clock was changed by -3,599.6 s at 2020-09-18 04:58:02 host time. Its events on either "
            "side of a change are on different clocks.") in text


# The page's view of the check: each event's pair, the switch between recorded and aligned times, and the findings
# summary's clock lines.

def uid(e, host):
    return event_uid(host, e.artifact, e.source_file, e.source_record, e.ts_desc)


@pytest.fixture
def paired(case):
    """DC01's 12 RDP connections, and DESKTOP's 3 with downloads of coreupdater.exe and 2 more files, all 3,599.5 s
    ahead of the capture. Returns the case and the events the tests name."""
    dc_flows, dc = brute_force(12, AHEAD)
    ws_flows, ws = brute_force(3, AHEAD, host="DESKTOP", host_ip=WS_IP, first_port=42000)
    requests, cached, saved = [request(T0 + 1500 * SEC, "coreupdater.exe", "404")], [], []
    for k, name in enumerate(("coreupdater.exe", "tools.zip", "notes.pdf")):
        t, (stem, ext) = T0 + (1200 + 60 * k) * SEC, name.rsplit(".", 1)
        requests.append(request(t, name))
        cached.append(usn(t + AHEAD - 4_000, f"\\Users\\Administrator\\AppData\\Local\\Microsoft\\Windows\\INetCache"
                                             f"\\IE\\X1\\{stem}[1].{ext}"))
        saved.append(usn(t + AHEAD + 3_200_000, f"\\Users\\Administrator\\Downloads\\{name}"))
    add(case, "network", "suricata", dc_flows + ws_flows + requests)
    add(case, "DC01", "evtxecmd", dc)
    add(case, "DESKTOP", "evtxecmd", ws)
    add(case, "DESKTOP", "mftecmd_j", cached + saved)
    return case, {"get": requests[1], "missing": requests[0], "cached": cached[0], "saved": saved[0]}


def test_the_agreeing_pairs_are_kept_for_the_event_page(case):
    """Each 131 pairs with the third flow on its port, the one it agrees with. DESKTOP's 2 pairs don't agree enough to
    say which of its events record the capture's moments, so none of them is kept."""
    flows, events = brute_force(12, AHEAD)
    ws_flows, ws = brute_force(2, AHEAD, host="DESKTOP", host_ip=WS_IP, first_port=42000)
    add(case, "network", "suricata", flows + ws_flows)
    add(case, "DC01", "evtxecmd", events)
    add(case, "DESKTOP", "evtxecmd", ws)
    assert checked(case)["DESKTOP"].clock["state"] == "disagree"
    third = {f.source_port: f for f in flows}   # each port's flows are in time order
    con = connect(case.db_path)
    try:
        rows = con.execute("SELECT host_event_uid, sensor_event_uid, host, kind, gap_us FROM clock_pairs").fetchall()
    finally:
        con.close()
    assert sorted(rows) == sorted((uid(e, "DC01"), uid(third[e.source_port], "network"), "DC01", "rdp",
                                   e.ts_us - third[e.source_port].ts_us) for e in events)


def test_the_event_page_names_each_events_pair(paired):
    case, named = paired
    get, cached = named["get"], named["cached"]
    app = App(case)
    try:
        def event(e, host):
            return api_event(app, {"uid": [uid(e, host)]})["event"]

        host_event = event(cached, "DESKTOP")
        assert host_event["pair"] == {"uid": uid(get, "network"), "host": "network", "ts_us": get.ts_us,
                                      "adjusted_ts_us": get.ts_us, "message": "HTTP GET /coreupdater.exe 200",
                                      "in_capture": True, "kind": "download", "gap_seconds": 3599.496}
        assert host_event["clock"] == {
            "host": "DESKTOP", "state": "suggest", "reference": "network", "seconds": -3599.5, "skew_seconds": 3599.496,
            "skew_text": "59 m 59.5 s", "display": "-3,599.5 s (1 h less 0.5 s)",
            "basis_text": "from 3 RDP connections, 3 downloads; 6 of 6 pairs within 2 s", "inliers": 6, "pairs": 6,
            "zone_note": "Consistent with a clock set to the wrong hour or zone.", "steps_text": "", "span_note": ""}
        record = event(get, "network")   # a capture record names its host event, and that host's clock
        assert record["pair"] == {"uid": uid(cached, "DESKTOP"), "host": "DESKTOP", "ts_us": cached.ts_us,
                                  "adjusted_ts_us": cached.ts_us, "message": cached.message, "in_capture": False,
                                  "kind": "download", "gap_seconds": 3599.496}
        assert record["clock"] == host_event["clock"]
        saved = event(named["saved"], "DESKTOP")   # no pair, but on the clock the pairs were on
        assert saved["pair"] is None and saved["clock"]["host"] == "DESKTOP"
        missing = event(named["missing"], "network")   # the 404 pairs with nothing, and the capture has no skew
        assert (missing["pair"], missing["clock"]) == (None, None)
        api_host(app, {"align": "capture"})
        host_event, record = event(cached, "DESKTOP"), event(get, "network")
        assert (host_event["clock"]["state"], host_event["pair"]["adjusted_ts_us"]) == ("agrees", get.ts_us)
        assert record["pair"]["adjusted_ts_us"] == cached.ts_us - 3_599_500_000
    finally:
        app.con.close()


def test_the_event_page_gives_the_clock_only_where_the_offset_fits(case):
    """DESKTOP's pairs are after the clock change that set it forward. The change that set it back an hour earlier
    repeated its own time, so the offset may not fit there."""
    flows, events = brute_force(10, AHEAD, host="DESKTOP", host_ip=WS_IP)
    back, forward = time_changed(*BACK), time_changed(*FORWARD)
    add(case, "network", "suricata", flows)
    add(case, "DESKTOP", "evtxecmd", events + [back, forward])
    app = App(case)
    try:
        clocks = [api_event(app, {"uid": [uid(e, "DESKTOP")]})["event"]["clock"] for e in (back, forward, events[0])]
    finally:
        app.con.close()
    assert clocks[0] is None
    assert clocks[1]["state"] == clocks[2]["state"] == "suggest"
    assert clocks[1]["span_note"].startswith("The pairs cover")


def test_times_a_change_repeated_get_no_clock(case):
    """w32time set DESKTOP's clock back an hour after its pairs, so host times from the change's `at` to its `was` were
    recorded on both clocks, and an event among them may be an hour off either way."""
    flows, events = brute_force(10, AHEAD, host="DESKTOP", host_ip=WS_IP)
    at = max(e.ts_us for e in events) + 3600 * SEC
    back = time_changed(evtx_time(at + 3_599_600_000), evtx_time(at))
    files = [usn(at + d * 60 * SEC, f"\\Users\\Administrator\\Documents\\{name}.txt")
             for d, name in ((-10, "before"), (30, "repeated"), (70, "after"))]
    add(case, "network", "suricata", flows)
    add(case, "DESKTOP", "evtxecmd", events + [back])
    add(case, "DESKTOP", "mftecmd_j", files)
    app = App(case)
    try:
        assert app.identity.hosts["DESKTOP"].clock["segment"] == {"start": None, "end": at}
        uids = [uid(f, "DESKTOP") for f in files]
        assert [api_event(app, {"uid": [u]})["event"]["clock"] is not None for u in uids] == [True, False, False]
        api_mark(app, {"uids": uids, "value": "malicious"})
        path, _ = write_report(app.con, app.case, app.identity, app.manifest, app.journal.state)
        text = path.read_text(encoding="utf-8")
    finally:
        app.con.close()
    assert text.count("Capture's clock") == 1
    assert "Capture's clock: about 04:13:17.2 UTC" in text   # the file before the change, at 05:13:16.7 host time


def test_times_a_later_change_repeated_are_left_out_of_the_segment():
    """Set forward 5 h, then back 7 h: the third clock runs over the first one's last hour, though no change next to
    the first clock repeated it."""
    hour = 3600 * SEC
    steps = [{"at": T0 + 7 * hour, "was": T0 + 2 * hour}, {"at": T0 + hour, "was": T0 + 8 * hour}]
    assert clock._segment(T0, T0 + hour // 2, steps)[0] == {"start": None, "end": T0 + hour}


def test_an_offset_fits_the_clock_the_pairs_were_on():
    result = {"state": "suggest", "segment": None}
    assert clock.in_segment(result, T0) and not clock.in_segment(result, None)
    assert not clock.in_segment({**result, "state": "disagree"}, T0)
    after = {**result, "segment": {"start": T0, "end": None}}
    assert clock.in_segment(after, T0) and not clock.in_segment(after, T0 - 1)
    assert not clock.in_segment({**result, "segment": {"start": None, "end": T0}}, T0)
    assert not clock.in_segment({**result, "segment": {"start": None, "end": None}}, T0)   # the pairs weren't placed


def test_the_switch_state_across_hosts():
    def host(state, offset=0.0, switch=False):
        return HostIdentity("H", "", "guess", offset_seconds=offset, offset_aligned=switch, clock={"state": state})

    assert clock.alignment([host("none"), host("disagree", 5.0)]) == "none"
    assert clock.alignment([host("suggest"), host("suggest"), host("agrees")]) == "recorded"
    assert clock.alignment([host("agrees", -3599.5), host("agrees")]) == "aligned"
    assert clock.alignment([host("agrees")]) == "aligned"   # its clock was right: recorded and aligned are the same
    assert clock.alignment([host("agrees", -3599.5), host("suggest")]) == "partly"
    # An offset set by hand that doesn't match aligns nothing, so neither half holds and nothing is partly aligned
    assert clock.alignment([host("suggest", -3500)]) == "neither"
    assert clock.alignment([host("suggest", 10.0), host("suggest")]) == "neither"
    assert clock.alignment([host("agrees", -3599.5), host("suggest", -3500)]) == "partly"
    # The switch's offsets after the measurement changed: its address removed, or new events moved the estimate
    assert clock.alignment([host("none", -3599.5, switch=True)]) == "aligned"
    assert clock.alignment([host("disagree", -3599.5, switch=True), host("suggest")]) == "partly"
    assert clock.alignment([host("suggest", -3599.5, switch=True)]) == "neither"
    # A rebuild's identity before build_tables checks the clocks
    assert clock.alignment([HostIdentity("H", "", "guess", offset_seconds=-3599.5, offset_aligned=True)]) == "aligned"


def test_aligning_to_the_capture_and_back(paired):
    case, _ = paired
    app = App(case)

    def states(payload):
        return {h["host"]: (h["offset_seconds"], h["clock"]["state"]) for h in payload["hosts"]}

    def offsets():
        return [e for e in read_entries(app.journal.path) if e["action"] == "host_offset"]

    try:
        assert api_meta(app, {})["clock_alignment"] == "recorded"
        assert api_host(app, {"align": "capture", "host": "DC01"})["clock_alignment"] == "partly"
        payload = api_host(app, {"align": "capture"})   # only DESKTOP changes: DC01 already agrees
        assert states(payload) == {"DC01": (-3599.5, "agrees"), "DESKTOP": (-3599.5, "agrees"),
                                   "network": (0.0, "none")}
        assert payload["clock_alignment"] == api_meta(app, {})["clock_alignment"] == "aligned"
        entries = offsets()
        assert [(e["host"], e["seconds"], e["align"], e["reference"]) for e in entries] == [
            ("DC01", -3599.5, "capture", "network"), ("DESKTOP", -3599.5, "capture", "network")]
        assert describe(entries[0]) == ("Set DC01's clock offset to -3599.5 s to align it with the capture (network), "
                                        "from 12 RDP connections; 12 of 12 pairs within 2 s")
        api_host(app, {"align": "capture"})
        assert len(offsets()) == 2   # nothing left to align
        api_host(app, {"host": "DC01", "offset_seconds": -3500})
        payload = api_host(app, {"align": "recorded"})   # an offset set by hand isn't the switch's to undo
        assert states(payload) == {"DC01": (-3500.0, "suggest"), "DESKTOP": (0.0, "suggest"), "network": (0.0, "none")}
        assert payload["clock_alignment"] == "neither"
        assert describe(offsets()[-1]) == "Set DESKTOP's clock offset to +0 s, back to its times as recorded"
        assert states(api_host(app, {"align": "capture"}))["DC01"] == (-3599.5, "agrees")
        with pytest.raises(QueryError, match="align must be capture or recorded"):
            api_host(app, {"align": "sideways"})
        with pytest.raises(QueryError, match="unknown host"):
            api_host(app, {"align": "capture", "host": "DC02"})
    finally:
        app.con.close()


def test_as_recorded_finds_the_switchs_offsets_in_the_journal(paired):
    """After aligning, 40 more connections move DC01's estimate 1.5 s, and DESKTOP's address is removed, so its clock
    can't be measured. Neither agrees now, but the switch set both offsets, so it still undoes them."""
    case, _ = paired
    app = App(case)

    def states(payload):
        return {h["host"]: (h["offset_seconds"], h["clock"]["state"]) for h in payload["hosts"]}

    try:
        api_host(app, {"align": "capture"})
        more_flows, more = brute_force(40, AHEAD + 1_500_000, start=T0 + 2000 * SEC, first_port=41000)
        add(case, "network", "suricata", more_flows)
        add(case, "DC01", "evtxecmd", more)
        app.refresh_identity(events_changed=True)
        payload = api_host(app, {"host": "DESKTOP", "op": "remove_ip", "value": WS_IP})
        assert states(payload) == {"DC01": (-3599.5, "suggest"), "DESKTOP": (-3599.5, "none"), "network": (0.0, "none")}
        assert payload["clock_alignment"] == "partly"
        payload = api_host(app, {"align": "recorded"})
        assert states(payload) == {"DC01": (0.0, "suggest"), "DESKTOP": (0.0, "none"), "network": (0.0, "none")}
        assert payload["clock_alignment"] == "recorded"
        # A typed offset isn't the switch's to undo, even one that agrees
        api_host(app, {"host": "DC01", "offset_seconds": -3600.9})
        entries = len(read_entries(app.journal.path))
        payload = api_host(app, {"align": "recorded"})
        assert states(payload)["DC01"] == (-3600.9, "agrees") and payload["clock_alignment"] == "aligned"
        assert len(read_entries(app.journal.path)) == entries
    finally:
        app.con.close()



def test_alignments_at_once_journal_each_change_once(paired, monkeypatch):
    """A double click on the switch sends two alignments before the first one's answer. The second
    waits for the first one's rebuild, finds nothing left to align, and journals nothing; /api/meta, read during the
    rebuild, never sees a host whose clock isn't checked yet."""
    case, _ = paired
    app = App(case)
    real, errors, done = server.build_tables, [], threading.Event()

    def slow(*args, **kwargs):   # a rebuild long enough for the second alignment and the reads to land inside it
        time.sleep(0.3)
        return real(*args, **kwargs)

    def align():
        try:
            api_host(app, {"align": "capture"})
        except Exception as exc:   # noqa: BLE001
            errors.append(exc)

    def read_meta():
        while not done.is_set():
            try:
                api_meta(app, {})
            except Exception as exc:   # noqa: BLE001
                errors.append(exc)
            time.sleep(0.02)

    monkeypatch.setattr(server, "build_tables", slow)
    try:
        threads = [threading.Thread(target=f) for f in (read_meta, align, align)]
        for t in threads:
            t.start()
        for t in threads[1:]:
            t.join()
        done.set()
        threads[0].join()
        assert errors == []
        assert [(e["host"], e["seconds"]) for e in read_entries(app.journal.path) if e["action"] == "host_offset"] == [
            ("DC01", -3599.5), ("DESKTOP", -3599.5)]
        assert api_meta(app, {})["clock_alignment"] == "aligned"
    finally:
        app.con.close()


# Every table refresh_identity and refresh_suggestions rebuild
DERIVED = ("hosts", "logon_links", "clock_pairs", "suggestions", "rejected", "suggested", "marks", "hits",
           "suricata_alerts", "fast_alerts", "tags", "tag_suggestions")


class Watched:
    """The writer's connection, which after each statement it runs calls `look`, as a request reading at that moment."""

    def __init__(self, con, look):
        self._con, self._look = con, look

    def execute(self, *args, **kwargs):
        result = self._con.execute(*args, **kwargs)
        self._look()
        return result

    def __getattr__(self, name):
        return getattr(self._con, name)


def rebuild_as_read(app, rebuild):
    """What a request's cursor reads of the derived tables before `rebuild`, after it, and after each of its
    statements: each table's row count and the sum of its rows' hashes."""
    cur, writer, looks = app.reader(), app.con, []

    def tables():
        return {t: cur.execute(f"SELECT count(*), COALESCE(sum(hash(t)), 0) FROM {t} t").fetchone() for t in DERIVED}

    before = tables()
    app.con = Watched(writer, lambda: looks.append(tables()))
    try:
        rebuild()
    finally:
        app.con = writer
    return before, tables(), looks


def assert_read_whole(app, steps):
    """Run each step in turn and check that at every statement a reader saw all the tables as before the step or all as
    after it, and that the step changed them. Returns the tables as read after the last step."""
    for name, step in steps.items():
        before, after, looks = rebuild_as_read(app, step)
        assert before != after, name
        torn = [{t: seen[t][0] for t in DERIVED if seen[t] != before[t]}
                for seen in looks if seen not in (before, after)]
        assert torn == [], f"{name}: tables a reader saw part written, with their row counts"
    return after


def test_a_request_reads_each_rebuild_whole(paired):
    """A request never reads the tables part rebuilt. If each statement of a rebuild committed alone, the hosts table
    would be empty between CREATE OR REPLACE TABLE hosts and its insert, and the Event page would show an offset
    host's events unadjusted (test_browser_smoke.py's test_local_time_on_the_host_stays_its_own_clock_after_an_offset
    hit it 2 times in 27). A host edit, a load's full rebuild, and a rule's rebuild of the suggestions each show a
    reader, at every statement, all the tables as before it or all as after. Reading after each statement sees every
    state between them; a reader in a loop would sample only some."""
    case, _ = paired
    flows, logged = logons(12, AHEAD)   # DESKTOP's logons to DC01: logon links, and more pairs
    alert = Event(ts_us=T0, ts_desc="Suricata alert", artifact="suricata", source_file=CAPTURE, source_record="alert|1",
                  message="ET TEST", log_channel="alert", source_ip=ATTACKER, source_port="443", dest_ip=DC_IP,
                  dest_port="51000", extra={"alert.signature": "ET TEST", "alert.severity": "1"})
    add(case, "network", "suricata", [*flows, alert])
    add(case, "DC01", "evtxecmd", logged)
    first = logged[0]
    add(case, "DC01", "hayabusa", [Event(
        ts_us=first.ts_us, ts_desc="Event Recorded", artifact="hayabusa", source_file=first.source_file,
        source_record=f"{first.record_id}:rule", record_id=first.record_id, message="Lateral movement [high]",
        log_channel="Security", rule_title="Lateral movement", rule_level="high",
        extra={"MitreTactics": "LatMov", "MitreTags": "T1021.002"})])
    uids = [event_uid("DC01", "evtx", e.source_file, e.source_record, e.ts_desc) for e in logged]
    app = App(case)
    try:
        def load():   # as a job's after() does, with the journal changed since the last build
            app.journal.append("mark", value="suspicious", targets=uids[1:3], note="")
            app.journal.append("tag", targets=uids[3:5], add=["tactic:TA0008"])
            app.journal.append("suggestion_decision", decision="rejected", source="hayabusa", targets=uids[:1])
            app.refresh_identity(events_changed=True)

        rule = "id: dc-logons\nsuggest: suspicious\nwhen: {field: event_code, equals: '4624'}\n"
        after = assert_read_whole(app, {
            "host edit": lambda: api_host(app, {"host": "DESKTOP", "offset_seconds": 60}),
            "load": load, "rule": lambda: api_rule(app, {"op": "add", "text": rule})})
        assert all(after[t][0] for t in DERIVED if t != "fast_alerts"), after   # every table checked has rows
    finally:
        app.con.close()


def test_a_rebuild_that_fails_partway_leaves_the_tables_as_they_were(paired, monkeypatch):
    """When a load's rebuild fails after the clock check, the rollback keeps every table as it was. The clock
    measurement the rebuild cached goes too, so the next host edit writes the new pairs; kept, it would name pairs the
    rollback has taken back, and clock_pairs would keep the 12 from before the load."""
    case, _ = paired
    app = App(case)
    cur = app.reader()

    def tables():
        return {t: cur.execute(f"SELECT count(*), COALESCE(sum(hash(t)), 0) FROM {t} t").fetchone() for t in DERIVED}

    def partway(*args, **kwargs):   # after hosts, the logon links, and the clock check
        raise RuntimeError("partway")

    try:
        before = tables()
        more_flows, more = brute_force(40, AHEAD, start=T0 + 2000 * SEC, first_port=41000)
        add(case, "network", "suricata", more_flows)
        add(case, "DC01", "evtxecmd", more)
        with monkeypatch.context() as m:
            m.setattr(analysis, "build_suggestions", partway)
            with pytest.raises(RuntimeError, match="partway"):
                app.refresh_identity(events_changed=True)
        assert tables() == before and app.clock_cache == {}
        api_host(app, {"host": "DESKTOP", "offset_seconds": 60})
        assert cur.execute("SELECT count(*) FROM clock_pairs WHERE host = 'DC01'").fetchone()[0] == 52
    finally:
        app.con.close()


def test_a_request_reads_each_mark_and_tag_whole(paired):
    """A mark, a tag, a tag decision, and an undo rewrite their events' rows in `marks`, or in `tags` and
    `tag_suggestions`, by a delete and then an insert that commit together, so a request between the two never reads
    the events unmarked or untagged. Each step here shows a reader, at every statement, all the tables as before it or
    all as after. Its events have rows already, which the delete takes away. An accept marks only unmarked events, so
    its delete takes none, and its step would pass without the shared commit too."""
    case, _ = paired
    flows, logged = logons(12, AHEAD)
    add(case, "network", "suricata", flows)
    add(case, "DC01", "evtxecmd", logged)
    add(case, "DC01", "hayabusa", [Event(   # suggests Suspicious, and a tactic and a technique, for the first 6
        ts_us=e.ts_us, ts_desc="Event Recorded", artifact="hayabusa", source_file=e.source_file,
        source_record=f"{e.record_id}:rule", record_id=e.record_id, message="Lateral movement [high]",
        log_channel="Security", rule_title="Lateral movement", rule_level="high",
        extra={"MitreTactics": "LatMov", "MitreTags": "T1021.002"}) for e in logged[:6]])
    uids = [event_uid("DC01", "evtx", e.source_file, e.source_record, e.ts_desc) for e in logged]
    app = App(case)

    def undo(action):   # the latest entry of that action
        return lambda: api_undo(app, {"seq": max(e["seq"] for e in read_entries(app.journal.path)
                                                 if e["action"] == action)})

    try:
        api_mark(app, {"uids": uids[6:10], "value": "authorized"})
        api_tag(app, {"uids": uids[6:9], "add": ["tactic:TA0001"]})
        assert_read_whole(app, {
            "mark": lambda: api_mark(app, {"uids": uids[6:10], "value": "suspicious"}),
            "tag": lambda: api_tag(app, {"uids": uids[6:9], "add": ["tactic:TA0002"]}),
            "tag decision": lambda: api_tag_suggestion(app, {"uids": uids[:2], "tags": ["tactic:TA0008"],
                                                             "decision": "dismissed"}),
            "rejection": lambda: api_suggestion(app, {"decision": "reject", "source": "hayabusa", "uids": uids[4:6]}),
            "undo of the mark": undo("mark"),
            "undo of the tag": undo("tag"),
            "undo of the tag decision": undo("tag_suggestion"),
            "undo of the rejection": undo("suggestion_decision"),
            "accept": lambda: api_suggestion(app, {"decision": "accept", "source": "hayabusa", "uids": uids[2:4]})})
        cur = app.reader()
        assert dict(cur.execute("SELECT event_uid, label FROM marks").fetchall()) == {
            **dict.fromkeys(uids[2:4], "Suspicious"), **dict.fromkeys(uids[6:10], "Authorized")}
        assert cur.execute("SELECT count(*) FILTER (WHERE tag = 'tactic:TA0001'), count(*) FROM tags").fetchone() == (3, 3)
        assert cur.execute("SELECT count(*) FROM tag_suggestions").fetchone()[0] == 12
    finally:
        app.con.close()


def test_a_pair_ends_lane_is_found_by_id(paired):
    """The link to a pair draws an end that isn't a tick in its lane. By time, a microsecond that more than 100 events
    share came back as density cells, with no lane; by ID it can't. An end the filter hides has
    none."""
    case, named = paired
    cached, get = named["cached"], named["get"]
    add(case, "DESKTOP", "evtxecmd", [Event(ts_us=cached.ts_us, ts_desc="Event Recorded", artifact="evtx",
                                            source_file="DESKTOP/System.evtx", source_record=f"crowd{i}",
                                            record_id=9000 + i, message="7036 service state", event_code="7036",
                                            log_channel="System") for i in range(110)])
    app = App(case)
    try:
        by_time = server.api_view(app, {"start": [str(cached.ts_us)], "end": [str(cached.ts_us + 1)], "buckets": ["1"],
                                        "limit": ["100"]})
        assert (by_time["mode"], by_time["count"]) == ("density", 111)
        ends = f"{uid(cached, 'DESKTOP')},{uid(get, 'network')}"
        keys = api_event_keys(app, {"uids": [ends], "groupby": ["host,mark"]})["keys"]
        assert keys == {uid(cached, "DESKTOP"): ["DESKTOP", "Unreviewed"],
                        uid(get, "network"): ["network", "Unreviewed"]}
        hidden = api_filter(app, {"hide": [{"host": "DESKTOP"}]})["id"]
        keys = api_event_keys(app, {"uids": [ends], "groupby": ["host,mark"], "filter": [hidden]})["keys"]
        assert keys == {uid(get, "network"): ["network", "Unreviewed"]}
    finally:
        app.con.close()

def test_findings_summary_gives_both_clocks_and_names_pairs(paired):
    case, named = paired
    app = App(case)

    def summary():
        path, _ = write_report(app.con, app.case, app.identity, app.manifest, app.journal.state)
        return path.read_text(encoding="utf-8")

    try:
        cached, get = uid(named["cached"], "DESKTOP"), uid(named["get"], "network")
        api_mark(app, {"uids": [cached, get, uid(named["saved"], "DESKTOP")], "value": "malicious"})
        text = summary()
        assert ("1. **2020-09-19 03:41:48.000000 UTC, network, Malicious.** HTTP GET /coreupdater.exe 200\n"
                f"   - Its pair on DESKTOP: {export._md(named['cached'].message)}, recorded at "
                f"2020-09-19 04:41:47.496000 on DESKTOP's clock (the same download; event ID `{cached}`).\n") in text
        assert ("   - Capture's clock: about 03:41:48.0 UTC; DESKTOP runs 59 m 59.5 s ahead, not aligned.\n"
                "   - Its pair in the capture: HTTP GET /coreupdater.exe 200, seen at 2020-09-19 03:41:48.000000 UTC "
                f"(the same download; event ID `{get}`).\n") in text
        assert "   - Capture's clock: about 03:41:51.2 UTC; DESKTOP runs 59 m 59.5 s ahead, not aligned.\n" in text
        assert text.count("Its pair") == 2
        api_host(app, {"align": "capture"})
        text = summary()
        assert "Capture's clock" not in text and text.count("Its pair") == 2
        assert "**2020-09-19 03:41:47.996000 UTC, DESKTOP, Malicious.**" in text
    finally:
        app.con.close()


def test_spans_and_times_as_the_clock_lines_give_them():
    assert [clock.span_text(s) for s in (3599.5, -3599.5, 3600.04, 3725.3, 61, 0.4, 0)] == [
        "59 m 59.5 s", "59 m 59.5 s", "1 h", "1 h 2 m 5.3 s", "1 m 1 s", "0.4 s", "0 s"]
    assert export._about(T0 + 120_000, T0) == "03:21:48.1 UTC"
    assert export._about(T0 - 4 * 3600 * SEC, T0) == "2020-09-18 23:21:48.0 UTC"   # the date when it isn't the event's
