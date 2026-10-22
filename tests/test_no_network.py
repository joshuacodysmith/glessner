"""The app makes no network calls, checked across a case load, a search, and each export, driven through the server
over loopback as the page drives it. conftest.network_guard refuses Python's sockets past this machine in every test;
DuckDB fetches an extension through its own HTTP client, out of that guard's sight, so this test also checks that every
DuckDB connection the app opens has extension autoload and autoinstall off."""

import json
import re
import socket
import time
from pathlib import Path
from urllib.parse import quote

import duckdb
import pytest
from conftest import FAST_ALERTS, serving
from test_server import login, request
from test_tool_outputs import EVTX_COLUMNS, evtx_rows, write_rows

import glessner
from glessner.case import create_case
from glessner.intake import intake

SETTINGS = ("SELECT current_setting('autoinstall_known_extensions'), "
            "current_setting('autoload_known_extensions')")
DEFAULT_CONNECTION = re.compile(r"\bduckdb\.(?!connect\()[a-z_]+\(")   # duckdb.sql(...), duckdb.read_csv(...)


def call(port, session, method, path, body=None):
    res, payload = request(port, method, path, session=session, body=body)
    assert res.status == 200, (path, res.status, payload[:300])
    return json.loads(payload)


def test_a_load_a_search_and_every_export_stay_on_this_machine(tmp_path, network_guard, monkeypatch):
    opened = []
    connect = duckdb.connect

    def recorded(*args, **kwargs):
        con = connect(*args, **kwargs)
        opened.append(con.execute(SETTINGS).fetchone())
        return con

    monkeypatch.setattr(duckdb, "connect", recorded)
    evidence = tmp_path / "evidence"
    write_rows(evidence / "WS01" / "Modules" / "EventLogs" / "20240514_EvtxECmd_Output.csv", EVTX_COLUMNS,
               evtx_rows("WS01.corp.local"))
    (evidence / "IDS").mkdir()
    (evidence / "IDS" / "fast.log").write_text(FAST_ALERTS, newline="\n")
    case = create_case(tmp_path / "case", "No network", evidence, "cody")
    intake(case)
    for app, port, _ in serving(case):
        session = login(port, app)
        # A case load: found tool output, as a background job, and an imported text log
        job = call(port, session, "POST", "/api/load_output", {"key": "evtxecmd_csv"})["job"]
        deadline = time.monotonic() + 60
        while not job["finished"] and time.monotonic() < deadline:
            time.sleep(0.05)
            job = call(port, session, "GET", "/api/run_status")["job"]
        assert job["finished"] and not job["error"] and [r["rows"] for r in job["results"]] == [2], job
        mapping = call(port, session, "POST", "/api/import_preview", {"path": "IDS/fast.log"})["mapping"]
        mapping = {**mapping, "time": {**mapping["time"], "zone": "UTC"}}
        imported = call(port, session, "POST", "/api/import", {"paths": ["IDS/fast.log"], "mapping": mapping})
        assert [r["rows"] for r in imported["runs"]] == [5], imported
        # A search, then a mark for the marked exports and the indicators
        found = call(port, session, "GET", f"/api/search?q={quote('alice')}")
        assert found["total"] == 2, found["total"]
        call(port, session, "POST", "/api/mark", {"uids": [found["events"][0]["uid"]], "value": "malicious"})
        # Each export: the timeline in both formats and every scope, the indicators, the report, and the audit trail
        first, last = app.con.execute("SELECT min(ts_us), max(ts_us) + 1 FROM events").fetchone()
        scopes = ({"marks": "all", "start": first, "end": last}, {"marks": "marked"}, {"marks": "flagged"})
        written = [call(port, session, "POST", "/api/export", {"format": fmt, **scope})
                   for fmt in ("csv", "jsonl") for scope in scopes]
        written +=[call(port, session, "POST", path, {}) for path in ("/api/indicators", "/api/report", "/api/audit_export")]
        assert [w["rows"] for w in written[:6]] == [7, 1, 1] * 2 and all(w.get("path") for w in written), written
    assert network_guard == []
    assert opened and set(opened) == {(False, False)}, opened


def test_the_guard_refuses_what_leaves_this_machine(network_guard):
    """The guard itself: a connect to an address off this machine and a lookup of a public name raise and are listed,
    and a listener and a connect on loopback pass."""
    with socket.socket() as off:
        off.settimeout(1)
        with pytest.raises(OSError, match="Refused in the tests"):
            off.connect(("192.0.2.1", 9))
    with pytest.raises(OSError, match="Refused in the tests"):
        socket.getaddrinfo("example.invalid", 80)
    with socket.socket() as server, socket.socket() as client:
        server.bind(("127.0.0.1", 0))
        server.listen()
        client.connect(server.getsockname())
    assert network_guard == ["socket.connect(('192.0.2.1', 9))", "socket.getaddrinfo('example.invalid')"]
    network_guard.clear()


def test_every_duckdb_connection_in_the_code_turns_extension_fetching_off():
    """Each place the app's code opens DuckDB passes NO_EXTENSION_FETCH, the places the test above doesn't reach too,
    and no code queries DuckDB's default connection, which keeps autoload on, through a module function such as
    duckdb.sql."""
    lines = [f"{path.name}: {line.strip()}" for path in Path(glessner.__file__).parent.rglob("*.py")
             for line in path.read_text(encoding="utf-8").splitlines()]
    connects = [line for line in lines if "duckdb.connect(" in line]
    assert connects and all("config=dict(NO_EXTENSION_FETCH)" in line for line in connects), connects
    assert not [line for line in lines if DEFAULT_CONNECTION.search(line)]
