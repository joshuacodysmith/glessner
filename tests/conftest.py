"""A small two-host case shaped like the Szechuan Sauce facts, built without running any tools."""

import ipaddress
import json
import os
import shutil
import socket
import subprocess
import sys
import threading

import pytest

from glessner.case import create_case
from glessner.events import Event, load
from glessner.parsers import PARSERS, ParseContext

T0 = 1600485708000000            # 2020-09-19 03:21:48 UTC
SEC = 1_000_000
DC_LOG = "DC01/Windows/System32/winevt/Logs/Security.evtx"
WS_LOG = "DESKTOP/Windows/System32/winevt/Logs/Security.evtx"


def logon(ts, record, source, *, user="Administrator", domain="C137", ltype="10", ip="", ws="", logon_id="0x1",
          computer="CITADEL-DC01.C137.local", code="4624", extra=None):
    return Event(ts_us=ts, ts_desc="Event Recorded", artifact="evtx", source_file=source, source_record=str(record),
                 record_id=record, message=f"{code} logon", host_name_recorded=computer, event_code=code,
                 log_channel="Security", user_name=user, user_domain=domain, logon_type=ltype if code == "4624" else "",
                 source_ip=ip, source_workstation=ws, logon_id=logon_id, extra=extra)


def links_in(con, start, end):
    """The logon links whose clock-adjusted time is in [start, end), in time order, as the table logon_links holds them
    (relations.build_logon_links), each with its time."""
    from types import SimpleNamespace

    from glessner.queries import TIME_FROM, TS

    cur = con.execute(f"SELECT l.event_uid AS uid, {TS} AS ts, l.source_host AS source, l.target_host AS target, "
                      f"l.outside, l.account, l.machine, l.kind, l.via FROM {TIME_FROM} "
                      f"JOIN logon_links l ON l.event_uid = e.event_uid WHERE {TS} >= ? AND {TS} < ? ORDER BY ts, uid",
                      [start, end])
    names = [d[0] for d in cur.description]
    return [SimpleNamespace(**dict(zip(names, row, strict=True))) for row in cur.fetchall()]


def junction(link, target):
    """A directory junction, as an attacker, a user, or a copy that keeps reparse points can leave in an evidence or
    tools folder. Junctions are Windows': elsewhere the test skips. They need no administrator rights."""
    if sys.platform != "win32":
        pytest.skip("directory junctions are made with mklink /J, on Windows")
    subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)], check=True, capture_output=True)


def nested_list(depth):
    """A list nested `depth` deep, built without json, so json.dumps can't write it back, wherever the stack lets
    json.loads read to."""
    value = []
    for _ in range(depth):
        value = [value]
    return value


def registry(source, path, name, value):
    return Event(ts_us=T0 - 3600 * SEC, ts_desc="Registry Key LastWrite", artifact="registry", source_file=source,
                 source_record=f"{path}|{name}", message=f"{name} = {value}", registry_path=path,
                 registry_value=name, extra={"ValueData": value})


def new_synthetic_case(root):
    """The synthetic case's folders under `root`, as create_case makes them: case.yaml, and a journal holding only
    case_created. Its events database comes from load_synthetic_events, or a copy of one."""
    for host in ("DC01", "DESKTOP"):
        (root / "evidence" / host).mkdir(parents=True)
    return create_case(root / "case", "Synthetic", root / "evidence", "cody")


def load_synthetic_events(case):
    """Load the synthetic case's events: five loads, each a run of its own. They write only events.duckdb, which holds no
    path and no time of the load, so a copy of it serves any new_synthetic_case."""
    dc = [
        # RDP from the internet; WorkstationName names the target itself, as Windows often records it.
        logon(T0, 101, DC_LOG, ip="194.61.24.102", ws="CITADEL-DC01", logon_id="0x510986"),
        logon(T0 + 60 * SEC, 102, DC_LOG, user="mortysmith", ltype="3", ip="10.42.85.115", logon_id="0x2"),
        logon(T0 + 61 * SEC, 103, DC_LOG, user="DESKTOP-SDN1RPT$", ltype="3", ip="10.42.85.115"),
        logon(T0 + 62 * SEC, 104, DC_LOG, ltype="3", ip="10.42.85.10"),                      # DC01 to itself
        logon(T0 + 63 * SEC, 105, DC_LOG, code="4672", logon_id="0x510986"),                  # same session as the RDP
    ]
    ws = [
        logon(T0 + 874 * SEC, 201, WS_LOG, ip="10.42.85.10", computer="DESKTOP-SDN1RPT.C137.local"),
        logon(T0 + 900 * SEC, 202, WS_LOG, code="4648", computer="DESKTOP-SDN1RPT.C137.local",
              extra={"TargetServerName": "CITADEL-DC01.C137.local"}),
        logon(T0 + 910 * SEC, 203, WS_LOG, ltype="3", ws="CITADEL-DC01", computer="DESKTOP-SDN1RPT.C137.local"),
    ]
    load(case.db_path, dc, host="DC01", tool="evtxecmd", tool_version="t", run_id="r1", replaces_sources=[DC_LOG],
         staging_dir=case.folder)
    load(case.db_path, ws, host="DESKTOP", tool="evtxecmd", tool_version="t", run_id="r2", replaces_sources=[WS_LOG],
         staging_dir=case.folder)
    sys_path = "ROOT\\ControlSet001\\Control\\ComputerName\\ComputerName"
    tcpip = "ROOT\\ControlSet001\\Services\\Tcpip\\Parameters\\Interfaces\\{1}"
    load(case.db_path, [registry("DC01/Windows/System32/config/SYSTEM", sys_path, "ComputerName", "CITADEL-DC01"),
                        registry("DC01/Windows/System32/config/SYSTEM", tcpip, "IPAddress", "10.42.85.10")],
         host="DC01", tool="recmd", tool_version="t", run_id="r3", replaces_sources=["DC01/Windows/System32/config/SYSTEM"],
         staging_dir=case.folder)
    load(case.db_path, [registry("DESKTOP/Windows/System32/config/SYSTEM", sys_path, "ComputerName", "DESKTOP-SDN1RPT"),
                        registry("DESKTOP/Windows/System32/config/SYSTEM", tcpip, "DhcpIPAddress", "10.42.85.115 0.0.0.0")],
         host="DESKTOP", tool="recmd", tool_version="t", run_id="r4",
         replaces_sources=["DESKTOP/Windows/System32/config/SYSTEM"], staging_dir=case.folder)
    hit = Event(ts_us=T0, ts_desc="Event Recorded", artifact="hayabusa", source_file=DC_LOG, source_record="101:rule",
                record_id=101, message="RDP from internet [high]", log_channel="Security", rule_title="RDP from internet",
                rule_level="high")
    load(case.db_path, [hit], host="DC01", tool="hayabusa", tool_version="t", run_id="r5", replaces_sources=[DC_LOG],
         staging_dir=case.folder)


@pytest.fixture(scope="session")
def synthetic_events(tmp_path_factory, settings_folder):
    """The synthetic case's events database, loaded once a session. The five loads took about 1 s against 12 ms for
    create_case, and about 500 tests ask for the case."""
    case = new_synthetic_case(tmp_path_factory.mktemp("synthetic_events"))
    load_synthetic_events(case)
    return case.db_path


@pytest.fixture
def synthetic_case(tmp_path, synthetic_events):
    """A new case of its own for each test, made by create_case in tmp_path, with a copy of the session's events
    database. A test may change any of it."""
    case = new_synthetic_case(tmp_path)
    shutil.copyfile(synthetic_events, case.db_path)
    return case


NETWORK_CAPTURE = "network/case001.pcap"


def eve_alert(when, sid, signature, severity, src, dest):
    """A Suricata EVE alert record at `when`, a UTC time of day on 2020-09-19, between two "ip:port" ends."""
    (src_ip, src_port), (dest_ip, dest_port) = src.split(":"), dest.split(":")
    return {"timestamp": f"2020-09-19T{when}.000000+0000", "event_type": "alert", "src_ip": src_ip,
            "src_port": int(src_port), "dest_ip": dest_ip, "dest_port": int(dest_port), "proto": "TCP",
            "alert": {"signature_id": sid, "signature": signature, "category": "Test", "severity": severity}}


# Alerts at severities 1, 2, 2, and 3, from 20 to 23 minutes after T0, for the Suricata suggestion source. They load in
# a network lane of their own, never in synthetic_case, whose lanes and counts other tests assert.
METASPLOIT = "ET MALWARE Possible Metasploit Payload Common Construct Bind_API (from server)"
DOTTED_QUAD = "ET INFO Executable Download from dotted-quad Host"
SURICATA_ALERTS = [
    eve_alert("03:41:48", 2025644, METASPLOIT, 1, "203.78.103.109:443", "10.42.85.10:62410"),
    eve_alert("03:42:48", 2016141, DOTTED_QUAD, 2, "194.61.24.102:80", "10.42.85.10:62411"),
    eve_alert("03:43:48", 2016141, DOTTED_QUAD, 2, "194.61.24.102:80", "10.42.85.115:50864"),
    eve_alert("03:44:48", 2023753, "ET INFO RDP - Response To External Host", 3, "10.42.85.10:3389",
              "194.61.24.102:51000"),
]


@pytest.fixture
def suricata_case(synthetic_case):
    """synthetic_case plus SURICATA_ALERTS, loaded through the EVE parser as Suricata's run on a capture."""
    out = synthetic_case.folder.parent / "suricata_run"
    out.mkdir()
    (out / "eve.json").write_text("".join(json.dumps(r) + "\n" for r in SURICATA_ALERTS), encoding="utf-8")
    events = PARSERS["suricata_eve"](ParseContext(out, synthetic_case.evidence, (NETWORK_CAPTURE,)))
    load(synthetic_case.db_path, events, host="network", tool="suricata", tool_version="8.0.7", run_id="r6",
         replaces_sources=[NETWORK_CAPTURE], staging_dir=out)
    return synthetic_case


def serving(case):
    """Serve a case on a free port for one pass of a for loop: yields the app, the port, and the launch link. A closure
    made in the loop's body runs within that pass, so ruff's B023 is silenced on it."""
    from glessner.server import serve

    server, app, url = serve(case, 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    yield app, port, url
    server.shutdown()
    server.server_close()
    app.con.close()


@pytest.fixture
def running(synthetic_case):
    yield from serving(synthetic_case)


@pytest.fixture
def running_alerts(suricata_case):
    yield from serving(suricata_case)


# Snort or Suricata fast alert lines at priorities 1, 2, 2, and 3, and one with no priority, at the same times as
# SURICATA_ALERTS plus a minute, for imported fast alerts as a suggestion source.
FAST_ALERTS = "".join(
    f"09/19/2020-{when}.000000  [**] [1:{sid}:1] {signature} [**] {extra}{{TCP}} {src} -> {dst}\n"
    for when, sid, signature, extra, src, dst in (
        ("03:41:48", 2025644, METASPLOIT, "[Classification: A Network Trojan was detected] [Priority: 1] ",
         "203.78.103.109:443", "10.42.85.10:62410"),
        ("03:42:48", 2016141, DOTTED_QUAD, "[Classification: Potentially Bad Traffic] [Priority: 2] ",
         "194.61.24.102:80", "10.42.85.10:62411"),
        ("03:43:48", 2016141, DOTTED_QUAD, "[Classification: Potentially Bad Traffic] [Priority: 2] ",
         "194.61.24.102:80", "10.42.85.115:50864"),
        ("03:44:48", 2023753, "ET INFO RDP - Response To External Host",
         "[Classification: Misc activity] [Priority: 3] ", "10.42.85.10:3389", "194.61.24.102:51000"),
        ("03:45:48", 2999999, "TEST alert with no priority", "", "198.51.100.7:80", "10.42.85.10:62420")))


@pytest.fixture
def fast_alerts_case(synthetic_case):
    """synthetic_case plus FAST_ALERTS in IDS/fast.log, taken in and imported with the ready-made fast alert mapping."""
    from glessner.imports import preview, run_import
    from glessner.intake import intake

    (synthetic_case.evidence / "IDS").mkdir()
    (synthetic_case.evidence / "IDS" / "fast.log").write_text(FAST_ALERTS, newline="\n")
    intake(synthetic_case)
    mapping = preview(synthetic_case, "IDS/fast.log")["mapping"]
    assert mapping["preset"] == "snort_fast"
    record = run_import(synthetic_case, "IDS/fast.log", {**mapping, "time": {**mapping["time"], "zone": "UTC"}},
                        zones={})
    assert (record.status, record.loaded_rows) == ("ok", 5), record.reason
    return synthetic_case


@pytest.fixture(autouse=True, scope="session")
def settings_folder(tmp_path_factory):
    """Recent cases and other user settings go to a temporary folder, never the analyst's own."""
    folder = tmp_path_factory.mktemp("settings")
    before = os.environ.get("GLESSNER_CONFIG_DIR")
    os.environ["GLESSNER_CONFIG_DIR"] = str(folder)
    yield folder
    if before is None:
        os.environ.pop("GLESSNER_CONFIG_DIR", None)
    else:
        os.environ["GLESSNER_CONFIG_DIR"] = before


def on_this_machine(address) -> bool:
    """Whether a socket address or host name stays on this machine: localhost or a loopback address. An empty host, as
    a bind to every interface takes, does not."""
    host = address[0] if isinstance(address, tuple) else address
    if isinstance(host, bytes):
        host = host.decode("ascii", "replace")
    if not isinstance(host, str):
        return False
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.split("%", 1)[0]).is_loopback
    except ValueError:
        return False


@pytest.fixture(autouse=True)
def network_guard(monkeypatch):
    """Every test runs with nothing reaching past this machine. A socket's connect, bind, or sendto to an address that
    isn't loopback, and a name lookup of anything but localhost or a loopback address, raises OSError and is listed
    here, and a test that made one fails. The server's 127.0.0.1 listener and the browser tests' loopback traffic pass.
    It sees Python's sockets only: native code, such as DuckDB's own HTTP client, is out of its sight, so
    test_no_network.py checks DuckDB's settings instead."""
    refused = []

    def guarded(name, real, target):   # `target` picks the address or host out of the call's arguments
        def call(*args, **kwargs):
            where = target(*args, **kwargs)
            if not on_this_machine(where):
                refused.append(f"{name}({where!r})")
                raise OSError(f"Refused in the tests: {name} to {where!r}, which is not this machine")
            return real(*args, **kwargs)
        return call

    for name in ("connect", "connect_ex", "bind"):
        monkeypatch.setattr(socket.socket, name, guarded(f"socket.{name}", getattr(socket.socket, name),
                                                         lambda sock, address: address))
    monkeypatch.setattr(socket.socket, "sendto", guarded("socket.sendto", socket.socket.sendto,
                                                         lambda sock, data, *rest: rest[-1]))
    for name in ("getaddrinfo", "gethostbyname", "gethostbyname_ex", "gethostbyaddr", "getnameinfo"):
        monkeypatch.setattr(socket, name, guarded(f"socket.{name}", getattr(socket, name),
                                                  lambda host, *rest, **options: host))
    yield refused
    assert not refused, f"The test reached past this machine: {refused}"


def pytest_xdist_auto_num_workers(config):
    """-n auto starts one worker per two logical CPUs. On 16 threads, 8 workers ran the suite in 5 min 54 s against 6 to
    6.5 min for 16, and two suites at once in 9 min 21 s each against 9 min 51 s, where 32 workers slowed a timed test
    past its limit. PYTEST_XDIST_AUTO_NUM_WORKERS, read by pytest-xdist's own hook, still sets the count."""
    if not os.environ.get("PYTEST_XDIST_AUTO_NUM_WORKERS"):
        return max(1, (os.cpu_count() or 2) // 2)


@pytest.hookimpl(tryfirst=True)   # before pytest-xdist's own hook, which reads the group into each test's ID
def pytest_collection_modifyitems(items):
    """With pytest-xdist's --dist loadgroup, a module's browser tests, and its lab tests, run on one worker in order: its
    Edge launches once, and test_lab_runs.py runs the tools once. Other tests go to whichever worker is free."""
    for item in items:
        if item.get_closest_marker("browser") or item.get_closest_marker("lab"):
            item.add_marker(pytest.mark.xdist_group(item.path.name))
