"""Server access controls and the API, against the synthetic case."""

import http.client
import json
import re
import secrets
import socket
import time
from pathlib import Path

import pytest
from conftest import DOTTED_QUAD, METASPLOIT, T0, serving

from glessner.server import CASE_HEADER, MAX_BODY, SESSION_HEADER, START_GET_ROUTES


def request(port, method, path, *, session=None, host=None, body=None, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    h = {"Host": host or f"127.0.0.1:{port}"}
    if session:
        h[SESSION_HEADER] = session
    if headers:
        h.update(headers)
    data = json.dumps(body).encode() if body is not None else None
    if data is not None:
        h.setdefault("Content-Type", "application/json")
    conn.request(method, path, body=data, headers=h)
    res = conn.getresponse()
    payload = res.read()
    conn.close()
    return res, payload


JSON_TYPE = "Content-Type: application/json"


def raw_post(port, session, path, headers, data=b"", pause=0.0):
    """POST over a raw socket, for requests http.client won't send. headers are "Name: value" lines, sent as given,
    and pause is waited after the headers and again after the body. Returns the status line and the answer's body."""
    lines = [f"POST {path} HTTP/1.1", f"Host: 127.0.0.1:{port}", f"{SESSION_HEADER}: {session}", *headers]
    with socket.create_connection(("127.0.0.1", port), timeout=10) as sock:
        sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())
        time.sleep(pause)
        sock.sendall(data)
        time.sleep(pause)
        status, _, body = read_answer(sock)
    return status, body


def read_answer(sock):
    """One answer from a socket, read by its Content-Length, as the server keeps the connection open after most: the
    status line, the headers by lowercase name, and the body."""
    answer = b""
    while b"\r\n\r\n" not in answer and (chunk := sock.recv(65_536)):
        answer += chunk
    head, _, body = answer.partition(b"\r\n\r\n")
    status, *lines = head.split(b"\r\n")
    headers = {name.lower(): value for name, _, value in (line.decode().partition(": ") for line in lines)}
    while len(body) < int(headers.get("content-length", 0)) and (chunk := sock.recv(65_536)):
        body += chunk
    return status, headers, body


def journaled(app):
    lines = (app.case.folder / "journal.jsonl").read_text(encoding="utf-8").splitlines()
    return [json.loads(line)["action"] for line in lines]


def login(port, app):
    """The session the page holds once it has traded the start link's token: the run's, which the requests send in
    SESSION_HEADER."""
    return app.session


def test_launch_link_binds_to_loopback_and_carries_token(running):
    """The start link names the loopback address and the port served, and its token is not the session the page gets for
    it."""
    app, port, url = running
    prefix = f"http://127.0.0.1:{port}/?token="
    assert url.startswith(prefix)
    token = url.removeprefix(prefix)
    assert len(token) >= 40 and len(app.session) >= 40 and token != app.session


def test_api_requests_without_the_session_or_with_a_foreign_host_are_refused(running):
    """An API request needs the run's session and a Host naming this server. The page's own files need no session: they
    hold no case data, and the page trades the start link's token for the session after it loads."""
    app, port, _ = running
    assert request(port, "GET", "/api/meta")[0].status == 403
    assert request(port, "GET", "/")[0].status == 200
    assert request(port, "GET", "/?token=wrong")[0].status == 200
    assert request(port, "GET", "/nothing")[0].status == 404
    session = login(port, app)
    assert request(port, "GET", "/api/meta", session=session, host="attacker.example:80")[0].status == 403
    assert request(port, "GET", "/", host="attacker.example:80")[0].status == 403
    assert request(port, "GET", "/api/meta", session="wrong")[0].status == 403
    assert request(port, "GET", "/api/meta", session=session)[0].status == 200


def test_a_get_sent_from_another_site_or_port_is_refused(running, monkeypatch):
    """A page on another 127.0.0.1 port is same-site, so a request it makes reaches this server. The browser's
    Sec-Fetch-Site says where a request came from, and a GET runs only for same-origin, none (a link typed or opened from
    the command line), or no header, as a client other than a browser sends. A refused browse lists nothing: a UNC path
    there would make Windows offer the analyst's credentials to that share."""
    app, port, _ = running
    session = login(port, app)
    browsed = []
    monkeypatch.setitem(START_GET_ROUTES, "/api/start/browse", lambda hub, query: browsed.append(query) or {})
    browse = "/api/start/browse?path=%5C%5Cshare.invalid%5Cx"
    for site in ("same-site", "cross-site"):
        sent = {"Sec-Fetch-Site": site}
        assert request(port, "GET", browse, session=session, headers=sent)[0].status == 403
        assert request(port, "GET", "/api/meta", session=session, headers=sent)[0].status == 403
        assert request(port, "GET", "/js/main.js", headers=sent)[0].status == 403
        assert request(port, "GET", "/?token=x", headers=sent)[0].status == 403
    assert browsed == []
    for sent in ({"Sec-Fetch-Site": "same-origin"}, {"Sec-Fetch-Site": "none"}, None):
        assert request(port, "GET", browse, session=session, headers=sent)[0].status == 200
        assert request(port, "GET", "/", headers=sent)[0].status == 200
    assert len(browsed) == 3
    assert request(port, "GET", "/?token=x", headers={"Sec-Fetch-Site": "none"})[0].status == 200


def test_the_launch_token_and_the_session_are_compared_with_compare_digest(running, monkeypatch):
    """The start link's token and the session both go through secrets.compare_digest. Either one with characters
    outside ASCII is answered 403, not with a dropped connection."""
    app, port, _ = running
    compared, real = [], secrets.compare_digest
    monkeypatch.setattr(secrets, "compare_digest", lambda a, b: compared.append(a) or real(a, b))
    res, _ = request(port, "GET", "/api/meta", session=f"\u00e9{app.session[1:]}")
    assert res.status == 403 and compared
    compared.clear()
    for token in (f"\u00e9{app.session[1:]}", "\u0100", "\ud800"):
        res, payload = request(port, "POST", "/api/session", body={"token": token})
        assert res.status == 403 and json.loads(payload)["link_used"] is True
    assert len(compared) == 3


def test_page_has_csp_and_api_works(running):
    app, port, _ = running
    session = login(port, app)
    res, body = request(port, "GET", "/", session=session)
    assert res.status == 200 and "default-src 'none'" in res.getheader("Content-Security-Policy")
    res, body = request(port, "GET", "/api/meta", session=session)
    meta = json.loads(body)
    assert meta["case"] == "Synthetic" and meta["outside_sources"] == ["194.61.24.102"]
    res, body = request(port, "GET", f"/api/view?start={T0 - 10**6}&end={T0 + 3600 * 10**6}&groupby=mark,role,host",
                        session=session)
    assert json.loads(body)["mode"] == "events"
    assert request(port, "GET", "/api/view?start=1&end=2&groupby=mark,nonsense", session=session)[0].status == 400


def test_mark_writes_journal_and_changes_lanes(running):
    app, port, _ = running
    session = login(port, app)
    uid = app.con.execute("SELECT event_uid FROM events WHERE tool = 'evtxecmd' AND ts_us = ?", [T0]).fetchone()[0]
    res, _ = request(port, "POST", "/api/mark", session=session, body={"uids": [uid], "value": "malicious", "note": "RDP"})
    assert res.status == 200
    line = json.loads((app.case.folder / "journal.jsonl").read_text().splitlines()[-1])
    assert (line["action"], line["value"], line["targets"], line["note"]) == ("mark", "malicious", [uid], "RDP")
    lanes = json.loads(request(port, "GET", "/api/lanes?groupby=mark,host", session=session)[1])["lanes"]
    assert {"keys": ["Malicious", "DC01"], "count": 1} in lanes
    details = json.loads(request(port, "GET", f"/api/event?uid={uid}", session=session)[1])["event"]
    assert details["mark"]["label"] == "Malicious" and details["hits"] == [{"title": "RDP from internet", "level": "high"}]
    # The Event page shows who set the mark and when, from the journal entry.
    assert details["mark"]["who"] == line["who"] and details["mark"]["at"] == line["at"]


def test_selected_lists_events_in_time_order_with_their_marks(running):
    """The verdict zone lists the selected events with their current marks, a pending suggestion
    among them, in time order whatever order the page sends them in."""
    app, port, _ = running
    session = login(port, app)
    uid = lambda ts: app.con.execute("SELECT event_uid FROM events WHERE tool = 'evtxecmd' AND ts_us = ?", [ts]).fetchone()[0]
    rdp, morty, desktop = uid(T0), uid(T0 + 60 * 1_000_000), uid(T0 + 874 * 1_000_000)
    # DC01's two registry values share a time, so they come in ID order
    hive = [u for (u,) in app.con.execute("SELECT event_uid FROM events WHERE tool = 'recmd' AND host = 'DC01' "
                                          "ORDER BY event_uid").fetchall()]
    request(port, "POST", "/api/mark", session=session, body={"uids": [morty], "value": "malicious"})
    query = "&".join(f"uid={u}" for u in [desktop, morty, rdp, *reversed(hive)])
    res, body = request(port, "GET", f"/api/selected?{query}", session=session)
    assert res.status == 200
    listed = json.loads(body)
    assert listed["total"] == 5
    assert [(e["uid"], e["host"], e["code"], e["mark"]) for e in listed["events"]] == [
        (hive[0], "DC01", "", "Unreviewed"), (hive[1], "DC01", "", "Unreviewed"),
        (rdp, "DC01", "4624", "Suggested: suspicious"), (morty, "DC01", "4624", "Malicious"),
        (desktop, "DESKTOP", "4624", "Unreviewed")]


def test_counts_and_role_confirm(running):
    app, port, _ = running
    session = login(port, app)
    def counts():
        body = json.loads(request(port, "GET", "/api/counts", session=session)[1])
        body.pop("server_ms")   # every API response carries its timing
        return body
    before = counts()
    assert (before["flagged"], before["hosts_review"], before["rule_errors"]) == (0, 2, 0) and before["pending"] >= 1
    res, body = request(port, "POST", "/api/host", session=session, body={"confirm_hosts": ["DC01"]})
    assert res.status == 200
    line = json.loads((app.case.folder / "journal.jsonl").read_text().splitlines()[-1])
    assert (line["action"], line["role"], line["confirmed"]) == ("host_role", "Domain controllers", True)
    dc = next(h for h in json.loads(body)["hosts"] if h["host"] == "DC01")
    assert dc["role_source"] == "analyst" and dc["review"] == [] and dc["role_by"] == line["who"]
    uid = app.con.execute("SELECT event_uid FROM events WHERE tool = 'evtxecmd' AND ts_us = ?", [T0]).fetchone()[0]
    request(port, "POST", "/api/mark", session=session, body={"uids": [uid], "value": "malicious"})
    after = counts()   # the marked event had Hayabusa's pending suggestion
    assert after == {"flagged": 1, "pending": before["pending"] - 1, "hosts_review": 1, "hosts_mixed": [],
                     "rule_errors": 0}


def test_pending_suggestions_grouped_and_decided_by_group(running):
    app, port, _ = running
    session = login(port, app)
    pending = lambda q: json.loads(request(port, "GET", f"/api/pending?{q}", session=session)[1])
    uid = app.con.execute("SELECT event_uid FROM events WHERE tool = 'evtxecmd' AND ts_us = ?", [T0]).fetchone()[0]
    hay = pending("source=hayabusa")   # Hayabusa's suggestions group by the rule behind them
    assert (hay["group_by"], hay["total"]) == ("rule", 1)
    assert [(g["key"], g["level"], g["count"]) for g in hay["groups"]] == [("RDP from internet", "high", 1)]
    assert hay["groups"][0]["events"][0]["uid"] == uid
    machine = pending("source=machine-accounts-authorized")   # rules group by account
    assert machine["group_by"] == "account" and [g["key"] for g in machine["groups"]] == ["C137\\DESKTOP-SDN1RPT$"]
    assert request(port, "GET", "/api/pending?source=hayabusa&group_by=nonsense", session=session)[0].status == 400
    res, body = request(port, "POST", "/api/suggestion", session=session,
                        body={"decision": "reject", "source": "hayabusa", "group_by": "rule", "group": "RDP from internet"})
    assert res.status == 200
    line = json.loads((app.case.folder / "journal.jsonl").read_text().splitlines()[-1])
    assert json.loads(body)["changed"] == 1 and (line["decision"], line["targets"]) == ("rejected", [uid])
    assert pending("source=hayabusa")["total"] == 0


def test_suricata_pending_groups_by_signature_most_severe_first(running_alerts):
    """Suricata's suggestions group by signature, severity 1 ahead of the larger severity 2 group, and each
    group names the alerts' own severity."""
    app, port, _ = running_alerts
    session = login(port, app)
    pending = lambda q: json.loads(request(port, "GET", f"/api/pending?{q}", session=session)[1])
    count = lambda: json.loads(request(port, "GET", "/api/counts", session=session)[1])["pending"]
    alerts = pending("source=suricata")
    assert (alerts["group_by"], alerts["total"]) == ("rule", 3)
    assert [(g["key"], g["level"], g["level_label"], g["count"]) for g in alerts["groups"]] == [
        (METASPLOIT, "high", "severity 1", 1), (DOTTED_QUAD, "medium", "severity 2", 2)]
    hay = pending("source=hayabusa")   # Hayabusa's groups name their level
    assert [(g["level"], g["level_label"]) for g in hay["groups"]] == [("high", "high")]
    assert pending("source=suricata&group_by=host")["groups"][0]["level_label"] is None
    before = count()
    uids = sorted(e["uid"] for e in alerts["groups"][1]["events"])
    res, body = request(port, "POST", "/api/suggestion", session=session,
                        body={"decision": "reject", "source": "suricata", "group_by": "rule", "group": DOTTED_QUAD})
    assert res.status == 200
    line = json.loads((app.case.folder / "journal.jsonl").read_text().splitlines()[-1])
    assert json.loads(body)["changed"] == 2
    assert (line["source"], line["decision"], sorted(line["targets"])) == ("suricata", "rejected", uids)
    assert [g["key"] for g in pending("source=suricata")["groups"]] == [METASPLOIT]
    assert count() == before - 2


def test_post_needs_json_and_same_origin(running):
    app, port, _ = running
    session = login(port, app)
    res, _ = request(port, "POST", "/api/mark", session=session, body={"uids": ["x"], "value": "malicious"},
                     headers={"Content-Type": "text/plain"})
    assert res.status == 415
    res, _ = request(port, "POST", "/api/mark", session=session, body={"uids": ["x"], "value": "malicious"},
                     headers={"Origin": "http://evil.example"})
    assert res.status == 403
    res, _ = request(port, "POST", "/api/mark", session=session, body={"uids": ["x"], "value": "evil"})
    assert res.status == 400 and "mark" not in journaled(app)   # only the built-in rule was journaled


def test_a_refused_post_is_answered_after_its_body_is_read(running):
    """A POST refused with 403, 415, or 404 is answered after its body is read. Closing the connection with the body
    unread makes Windows reset it, and the reset can reach the client before it reads the refusal (WinError 10053 in
    test_post_needs_json_and_same_origin). Sending the body after a pause, and reading after another, would lose the
    refusal every time otherwise."""
    app, port, _ = running
    session = login(port, app)
    body = json.dumps({"uids": ["x"], "value": "malicious"}).encode()
    length = f"Content-Length: {len(body)}"

    def post(path, *headers, data=body):
        # The first pause lets a refusal sent at once go out and the server close; the second lets the reset for the
        # unread body come back.
        return raw_post(port, session, path, headers, data, pause=0.1)[0]

    assert post("/api/mark", JSON_TYPE, "Origin: http://evil.example", length) == b"HTTP/1.1 403 Forbidden"
    assert post("/api/mark", "Content-Type: text/plain", length) == b"HTTP/1.1 415 Unsupported Media Type"
    assert post("/api/none", JSON_TYPE, length) == b"HTTP/1.1 404 Not Found"
    assert post("/api/none", JSON_TYPE, "Content-Length: many", data=b"") == b"HTTP/1.1 404 Not Found"
    assert "mark" not in journaled(app)


def test_a_post_length_must_be_one_number(running):
    """Content-Length is digits only (RFC 9110, 8.6). int() takes "1_000", "-5", and "+12", so the server would wait
    for a body that isn't coming; "many" raises ValueError, which would print a traceback and send no answer. A second
    Content-Length is refused too, not ignored."""
    app, port, _ = running
    session = login(port, app)
    for lengths in (["many"], ["1_000"], ["-5"], ["+12"], ["12", "13"]):
        status, body = raw_post(port, session, "/api/mark", [JSON_TYPE, *(f"Content-Length: {n}" for n in lengths)])
        assert (status, json.loads(body)) == (b"HTTP/1.1 400 Bad Request",
                                              {"error": "Content-Length must be a single number."}), lengths
    # Spaces around the number belong to the header, not the number. The body reaches the route, which refuses it.
    status, body = raw_post(port, session, "/api/mark", [JSON_TYPE, "Content-Length:  2  "], b"{}")
    assert status == b"HTTP/1.1 400 Bad Request" and json.loads(body)["error"].startswith("Mark value must be")
    assert "mark" not in journaled(app)


def test_a_post_with_transfer_encoding_is_refused(running):
    """The server reads a body by Content-Length only. A chunked body would be taken as empty, so the route would run
    on {} with the body left unread. Chunked gets 411, and codings that don't end with chunked get 400, since the body's
    end can't be found (RFC 9112, 6.3). A request with neither header has no body, and the route still runs."""
    app, port, _ = running
    session = login(port, app)
    for headers in (["Transfer-Encoding: chunked"], ["transfer-encoding: gzip, Chunked", "Content-Length: 2"]):
        status, body = raw_post(port, session, "/api/mark", [JSON_TYPE, *headers])
        assert (status, json.loads(body)) == (b"HTTP/1.1 411 Length Required",
                                              {"error": "Send the body with a Content-Length."}), headers
    for headers in (["Transfer-Encoding: gzip"], ["Transfer-Encoding: chunked", "Transfer-Encoding: gzip"]):
        status, body = raw_post(port, session, "/api/mark", [JSON_TYPE, *headers])
        assert (status, json.loads(body)) == (b"HTTP/1.1 400 Bad Request",
                                              {"error": "Transfer-Encoding must end with chunked."}), headers
    status, body = raw_post(port, session, "/api/mark", [JSON_TYPE])
    assert status == b"HTTP/1.1 400 Bad Request" and json.loads(body)["error"].startswith("Mark value must be")
    assert "mark" not in journaled(app)


def test_a_post_over_the_cap_is_refused_with_413(running):
    """A body has a limit. Over MAX_BODY the server answers without reading the body, so none is sent here: a client
    that sends one may get a reset in place of the 413. A length of 5,000 digits is over it too, though int() refuses
    a number that long."""
    app, port, _ = running
    session = login(port, app)
    for length in (str(MAX_BODY + 1), "9" * 5000):
        status, body = raw_post(port, session, "/api/mark", [JSON_TYPE, f"Content-Length: {length}"])
        assert (status, json.loads(body)) == (b"HTTP/1.1 413 Content Too Large",
                                              {"error": f"The body is over {MAX_BODY:,} bytes."}), length[:20]


def test_a_post_body_must_be_a_json_object(running):
    """Every route takes an object. A list or a string would reach the routes, whose body.get raises AttributeError;
    bytes that don't decode, such as a lone 0xff, raise UnicodeDecodeError, and deep nesting RecursionError. None of the
    three is a JSONDecodeError, so each would print a traceback and send no answer."""
    app, port, _ = running
    session = login(port, app)
    for data, error in ((b"[1, 2]", "Send a JSON object."), (b'"x"', "Send a JSON object."),
                        (b'{"a": "\xff"}', "invalid JSON"), (b"[" * 100_000, "invalid JSON"), (b"{", "invalid JSON")):
        status, body = raw_post(port, session, "/api/mark", [JSON_TYPE, f"Content-Length: {len(data)}"], data)
        assert (status, json.loads(body)) == (b"HTTP/1.1 400 Bad Request", {"error": error}), data[:20]
    assert "mark" not in journaled(app)


def test_a_canceled_request_ends_quietly():
    """The page cancels a view request when the analyst zooms on before it finishes. Writing the answer then fails, and
    the server must drop it without printing a traceback."""
    from glessner.server import make_handler

    class Gone:
        def write(self, data):
            raise ConnectionAbortedError(10053, "An established connection was aborted")

    handler_class = make_handler(None, [0])
    handler = handler_class.__new__(handler_class)
    handler.requestline, handler.request_version, handler.command = "GET /api/view HTTP/1.1", "HTTP/1.1", "GET"
    handler.close_connection = False   # as parse_request leaves it for an HTTP/1.1 request
    handler.wfile = Gone()
    handler._json(200, {"events": []})   # the write error must not escape
    assert handler.close_connection   # the connection is gone, so no further request is read from it


def test_the_server_queues_more_connections_than_a_browser_opens_at_once():
    """A page opens 6 connections at once to fetch its files. With socketserver's backlog of 5, Windows refuses the
    6th when the accept loop falls behind, about 2 s after the attempt. Nothing accepts here, so every
    connection waits in the backlog."""
    from glessner.server import serve_start

    server, _, _ = serve_start(0)
    connections = []
    try:
        # The 6th would be refused with the backlog of 5. extend keeps the ones made before it, to close.
        connections.extend(socket.create_connection(server.server_address, timeout=5) for _ in range(16))
    finally:
        for c in connections:
            c.close()
        server.server_close()


def kept(port, session):
    """An open http.client connection, and the headers its requests carry."""
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.connect()
    return conn, {"Host": f"127.0.0.1:{port}", SESSION_HEADER: session}


def ask(conn, method, path, headers, body=None):
    """A request on a kept connection: the answer's status, its Connection header, and whether the connection still
    has the socket it had before."""
    sock = conn.sock
    conn.request(method, path, body=body, headers=headers)
    res = conn.getresponse()
    res.read()
    return res.status, res.getheader("Connection"), conn.sock is sock


def test_a_page_s_requests_share_one_connection(running):
    """The server answers HTTP/1.1, and every answer has a Content-Length, so a page, a module, an API answer, and each
    refusal leave the connection open for the next one. A close after each answer makes each request open a new
    connection, which takes a local port that stays in TIME_WAIT after it closes. A page load makes about 37 requests
    and a run of the browser tests about 5,000, a large share of the dynamic port range the machine shares. When the
    range runs out, Windows refuses the browser a local port (net::ERR_NO_BUFFER_SPACE)."""
    app, port, _ = running
    conn, h = kept(port, app.session)
    json_h = {**h, "Content-Type": "application/json"}
    try:
        for method, path, headers, body, status in (
                ("GET", "/", h, None, 200), ("GET", "/js/main.js", h, None, 200), ("GET", "/api/meta", h, None, 200),
                ("GET", "/api/meta", {"Host": h["Host"]}, None, 403),
                ("GET", "/api/none", h, None, 404), ("POST", "/api/mark", json_h, b"{}", 400),
                ("POST", "/api/mark", json_h, b"[", 400), ("POST", "/api/none", json_h, b"{}", 404),
                ("GET", "/api/meta", {**h, CASE_HEADER: "an earlier open"}, None, 409),
                ("GET", "/api/meta", h, None, 200)):
            assert ask(conn, method, path, headers, body) == (status, None, True), (method, path)
    finally:
        conn.close()


def test_every_request_on_a_kept_connection_is_checked(running):
    """The Host, the session, and the Origin are checked on each request, not once per connection: a connection whose
    requests passed them is refused one without the session, naming another host, or from another origin."""
    app, port, _ = running
    conn, h = kept(port, app.session)
    uid = app.con.execute("SELECT event_uid FROM events WHERE tool = 'evtxecmd' AND ts_us = ?", [T0]).fetchone()[0]
    mark = json.dumps({"uids": [uid], "value": "malicious"}).encode()
    json_h = {**h, "Content-Type": "application/json"}
    try:
        assert ask(conn, "GET", "/api/meta", h) == (200, None, True)
        for headers in ({"Host": h["Host"]}, {**h, "Host": "attacker.example:80"}, {**h, SESSION_HEADER: "x"}):
            assert ask(conn, "GET", "/api/meta", headers) == (403, None, True), headers
        assert ask(conn, "GET", "/", {"Host": h["Host"]}) == (200, None, True)   # the page needs no session
        assert ask(conn, "GET", "/", {"Host": "attacker.example:80"}) == (403, None, True)
        for headers in ({**json_h, "Origin": "http://evil.example"}, {**json_h, SESSION_HEADER: "x"}):
            assert ask(conn, "POST", "/api/mark", headers, mark) == (403, None, True), headers
        assert "mark" not in journaled(app)
        assert ask(conn, "POST", "/api/mark", json_h, mark) == (200, None, True)
    finally:
        conn.close()


def test_the_standard_library_s_error_answers_carry_a_length_and_close(running):
    """A method the server doesn't route and a request line it can't parse are answered by BaseHTTPRequestHandler, not
    by _write. Each carries a Content-Length, so an HTTP/1.1 client knows where the answer ends, and closes the
    connection, so what follows the bad request isn't read as the next one."""
    _, port, _ = running
    for sent, status in ((f"PUT /api/meta HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n", b"501"),
                         (f"DELETE / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n", b"501"),
                         ("GET\r\n\r\n", b"400"), (f"GET /{'a' * 70_000} HTTP/1.1\r\n\r\n", b"414")):
        with socket.create_connection(("127.0.0.1", port), timeout=10) as sock:
            sock.sendall(sent.encode())
            answer, headers, body = read_answer(sock)
            assert answer.split(b" ")[1] == status, sent[:20]
            assert headers.get("connection") == "close" and int(headers["content-length"]) == len(body) > 0, sent[:20]
            assert sock.recv(65_536) == b"", sent[:20]


def test_a_body_left_unread_closes_the_connection(running):
    """A body the server won't read, by its length or its Transfer-Encoding, or a GET's, would be read as the next
    request on a kept connection. Its answer says Connection: close, and the server closes the connection. A refused
    POST whose body was read keeps the connection."""
    app, port, _ = running
    session = login(port, app)
    head = f"Host: 127.0.0.1:{port}\r\n{SESSION_HEADER}: {session}\r\n"
    post = f"POST /api/mark HTTP/1.1\r\n{head}Content-Type: application/json\r\n"
    for sent, status in ((f"{post}Content-Length: {MAX_BODY + 1}\r\n\r\n", b"413"),
                         (f"{post}Transfer-Encoding: chunked\r\n\r\n2\r\n{{}}\r\n0\r\n\r\n", b"411"),
                         (f"{post}Content-Length: many\r\n\r\n{{}}", b"400"),
                         (f"GET /api/meta HTTP/1.1\r\n{head}Content-Length: 2\r\n\r\n{{}}", b"200")):
        with socket.create_connection(("127.0.0.1", port), timeout=10) as sock:
            sock.sendall(sent.encode())
            answer, headers, _ = read_answer(sock)
            assert (answer.split(b" ")[1], headers.get("connection")) == (status, "close"), sent[:40]
            assert sock.recv(65_536) == b"", sent[:40]   # closed, with the body unread
    with socket.create_connection(("127.0.0.1", port), timeout=10) as sock:
        sock.sendall(f"{post}Origin: http://evil.example\r\nContent-Length: 2\r\n\r\n{{}}".encode())
        answer, headers, _ = read_answer(sock)
        assert (answer, headers.get("connection")) == (b"HTTP/1.1 403 Forbidden", None)
        sock.sendall(f"GET /api/meta HTTP/1.1\r\n{head}\r\n".encode())
        assert read_answer(sock)[0] == b"HTTP/1.1 200 OK"
    assert "mark" not in journaled(app)


def test_a_request_that_is_not_http_1_1_closes_even_when_it_asks_to_stay(running):
    """An HTTP/1.0 answer can't say it stays open without Connection: keep-alive, so a client that asked for it would
    wait for the end of a connection the server held. Such a request is answered and closed."""
    app, port, _ = running
    session = login(port, app)
    with socket.create_connection(("127.0.0.1", port), timeout=10) as sock:
        sock.sendall(f"GET /api/meta HTTP/1.0\r\nHost: 127.0.0.1:{port}\r\n{SESSION_HEADER}: {session}\r\n"
                     "Connection: keep-alive\r\n\r\n".encode())
        answer, headers, body = read_answer(sock)
        assert answer.split(b" ")[1] == b"200" and headers.get("connection") == "close"
        assert int(headers["content-length"]) == len(body)
        assert sock.recv(65_536) == b""


def test_100_continue_waits_for_the_checks(running):
    """A request that expects 100 Continue is invited to send its body only after the Host, session, and Origin checks, so
    a client the server will refuse isn't asked for a body of up to MAX_BODY bytes first. The trade of the start link's
    token for the session carries no session, and is invited."""
    app, port, _ = running
    session = login(port, app)
    head = f"POST /api/mark HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\n"
    expect = "Expect: 100-continue\r\nContent-Length: 2\r\n\r\n"
    trade = head.replace("/api/mark", "/api/session")
    for first_lines, extra, first in ((head, f"{SESSION_HEADER}: {session}\r\n", b"HTTP/1.1 100 Continue"),
                                      (head, f"{SESSION_HEADER}: {session}\r\nOrigin: http://evil.example\r\n",
                                       b"HTTP/1.1 403 Forbidden"),
                                      (head, "", b"HTTP/1.1 403 Forbidden"),
                                      (trade, "", b"HTTP/1.1 100 Continue"),
                                      (trade, "Origin: http://evil.example\r\n", b"HTTP/1.1 403 Forbidden")):
        with socket.create_connection(("127.0.0.1", port), timeout=10) as sock:
            sock.sendall((first_lines + extra + expect).encode())
            assert read_answer(sock)[0] == first, extra
            if first.endswith(b"Continue"):
                sock.sendall(b"{}")   # the invited body
                assert read_answer(sock)[0].startswith(b"HTTP/1.1 ")


def test_an_idle_connection_closes_and_ends_its_thread(synthetic_case, monkeypatch):
    """A kept connection holds a server thread while it waits for the next request. After KEEP_ALIVE_SECONDS without
    one, the server closes it, and the thread ends."""
    import threading

    from glessner import server

    monkeypatch.setattr(server, "KEEP_ALIVE_SECONDS", 0.5)
    for app, port, _ in serving(synthetic_case):
        before = set(threading.enumerate())
        conn, h = kept(port, app.session)
        try:
            assert ask(conn, "GET", "/api/meta", h) == (200, None, True)
            handlers = [t for t in threading.enumerate() if t not in before and "process_request_thread" in t.name]
            assert len(handlers) == 1   # the connection's
            handlers[0].join(10)
            assert not handlers[0].is_alive() and conn.sock.recv(1) == b""
        finally:
            conn.close()


def test_a_reset_while_a_connection_idles_ends_it_quietly(running, capsys):
    """A browser that drops a kept connection, as when its context closes, can reset it while the server waits for the
    next request. The reset ends the connection's thread without a traceback on the console."""
    import struct
    import threading

    app, port, _ = running
    before = set(threading.enumerate())
    conn, h = kept(port, app.session)
    assert ask(conn, "GET", "/api/meta", h) == (200, None, True)
    handler = next(t for t in threading.enumerate() if t not in before and "process_request_thread" in t.name)
    conn.sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("hh", 1, 0))   # close with a reset
    conn.close()
    handler.join(10)
    assert not handler.is_alive() and "Traceback" not in capsys.readouterr().err


def test_a_kept_connection_follows_a_switch_of_case(synthetic_case):
    """Hub.open makes another App the open one while the browser keeps its connections. A request on a connection made
    before the switch reads the open App, as a new connection's does: one naming the earlier open is refused 409,
    and one without it reads the open case."""
    import threading

    from glessner.server import Hub, serve_hub

    server, hub, _ = serve_hub(Hub(synthetic_case), 0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    conn, h = kept(server.server_address[1], hub.session)
    try:
        conn.request("GET", "/api/meta", headers=h)
        first = json.loads(conn.getresponse().read())["case_id"]
        assert ask(conn, "POST", "/api/start/open", {**h, "Content-Type": "application/json"},
                   json.dumps({"folder": str(synthetic_case.folder)}).encode()) == (200, None, True)
        for _ in range(200):   # the open is a job
            conn.request("GET", "/api/start/job", headers=h)
            job = json.loads(conn.getresponse().read())["job"]
            if job["finished"]:
                break
            time.sleep(0.05)
        else:
            pytest.fail("the open job didn't finish")
        assert job["opened"] and not job["error"]
        assert ask(conn, "GET", "/api/meta", {**h, CASE_HEADER: first}) == (409, None, True)
        sock = conn.sock
        conn.request("GET", "/api/meta", headers=h)
        assert json.loads(conn.getresponse().read())["case_id"] == hub.app.case_id != first and conn.sock is sock
    finally:
        conn.close()
        server.shutdown()
        server.server_close()
        hub.app.con.close()


def free_port():
    """A port nothing holds at the moment: bound to 0 and released."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def test_serve_prefers_its_fixed_port_and_falls_back_when_it_is_held(synthetic_case, monkeypatch):
    """Without --port, serve binds PREFERRED_PORT, so the browser's layout preferences, kept by origin, last across
    runs; held, it binds a free port. The port is below Windows' dynamic range. A second server can't share the port:
    with HTTPServer's SO_REUSEADDR, Windows lets a second bind to a held port succeed, and the two take turns at the
    connections (probed), so Server binds without it."""
    from glessner import server as mod
    from glessner.server import Hub, serve_hub

    assert mod.PREFERRED_PORT < 49152
    port = free_port()
    monkeypatch.setattr(mod, "PREFERRED_PORT", port)
    hub = Hub(synthetic_case)
    try:
        first, _, url = serve_hub(hub, None)
        try:
            assert first.server_address[1] == port and url == f"http://127.0.0.1:{port}/?token={hub.token}"
            second, _, _ = serve_hub(hub, None)   # one hub serves both: a second App would hold the same database
            try:
                assert second.server_address[1] not in (port, 0)
            finally:
                second.server_close()
            with pytest.raises(OSError):
                serve_hub(hub, port)   # named, the held port is an error, as before
        finally:
            first.server_close()
        with socket.socket() as holder:   # any program on the port, not only another serve
            holder.bind(("127.0.0.1", port))
            holder.listen(1)
            fallback, _, _ = serve_hub(hub, None)
            try:
                assert fallback.server_address[1] not in (port, 0)
            finally:
                fallback.server_close()
        again, _, _ = serve_hub(hub, None)   # released, the port binds at once
        try:
            assert again.server_address[1] == port
        finally:
            again.server_close()
    finally:
        hub.app.con.close()


def test_the_serve_command_says_when_it_fell_back_to_a_free_port(synthetic_case, monkeypatch, capsys):
    """The one line serve prints when the preferred port is held: this run's page won't see the saved layout. The
    server's loop is stubbed, so the command returns at once."""
    from glessner import server as mod
    from glessner.cli import main

    monkeypatch.setattr(mod.Server, "serve_forever", lambda self: None)
    port = free_port()
    monkeypatch.setattr(mod, "PREFERRED_PORT", port)
    folder = str(synthetic_case.folder)
    assert main(["serve", folder, "--no-browser"]) == 0
    out = capsys.readouterr().out
    assert f"  http://127.0.0.1:{port}/?token=" in out and "is in use" not in out
    with socket.socket() as holder:
        holder.bind(("127.0.0.1", port))
        holder.listen(1)
        assert main(["serve", folder, "--no-browser"]) == 0
    out = capsys.readouterr().out
    other = int(out.split("http://127.0.0.1:")[1].split("/")[0])
    assert other != port
    assert (f"Port {port} is in use, so this run is on port {other}. The browser keeps the page's layout per port, so "
            "this run's page won't see the layout saved in earlier runs.") in out
    assert main(["serve", folder, "--no-browser", "--port", "0"]) == 0   # 0 still picks a free port, with no line
    assert "is in use" not in capsys.readouterr().out


def test_the_serve_command_says_what_its_open_is_doing_before_the_link(synthetic_case, monkeypatch, capsys):
    """serve names the case it opens, and its open's stages, before the link. A case at the
    newest format has no upgrade, so no line says one runs. Each stage's line starts with the seconds since the open
    began, which depend on how busy the machine is, so any count of seconds matches. The server's loop is stubbed, so the
    command returns at once."""
    from glessner import server as mod
    from glessner.cli import OPENING, main

    monkeypatch.setattr(mod.Server, "serve_forever", lambda self: None)
    assert main(["serve", str(synthetic_case.folder), "--no-browser", "--port", "0"]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert lines[0] == f"Opening {synthetic_case.settings.name!r} from {synthetic_case.folder}."
    seconds = r" *\d+ s  "
    assert re.fullmatch(seconds + re.escape(OPENING), lines[1]), lines[1]
    assert re.fullmatch(seconds + r"Opened\.", lines[2]), lines[2]
    assert lines[3].startswith("Serving ") and not any("upgrade" in line for line in lines)


@pytest.mark.parametrize(("flags", "how"), [
    ([], "to open it in another browser, run serve with --no-browser"),
    (["--no-browser"], "open it in the browser you choose"),
], ids=["browser", "no browser"])
def test_the_serve_command_says_the_start_link_works_once(synthetic_case, monkeypatch, capsys, flags, how):
    """The line before the link says the link works once. A run that opens the browser names --no-browser as the way to
    open the link in another browser, and a run with --no-browser says to open it in the browser you choose. The link is
    on the next line, and only a run without --no-browser opens it. The browser and the server's loop are stubbed, so the
    command opens nothing and returns at once."""
    from glessner import server as mod
    from glessner.cli import main

    opened = []
    monkeypatch.setattr("webbrowser.open", opened.append)
    monkeypatch.setattr(mod.Server, "serve_forever", lambda self: None)
    assert main(["serve", str(synthetic_case.folder), *flags, "--port", "0"]) == 0
    lines = capsys.readouterr().out.splitlines()
    at = next(i for i, line in enumerate(lines) if line.startswith("Serving "))
    assert lines[at] == f"Serving {synthetic_case.settings.name!r} on 127.0.0.1 only. Start link (it works once; {how}):"
    assert lines[at + 1].startswith("  http://127.0.0.1:")
    assert opened == ([] if flags else [lines[at + 1].strip()])


def test_the_open_s_lines_name_each_stage_as_it_starts_and_say_when_it_is_still_working(capsys):
    """A line per stage when it starts, after the seconds since the open began, with its count where it has
    one. A stage quiet for QUIET seconds gets a still-working line, with how far it has got when its count moved since
    its last line. The open's last stage, "Opening", reads in the command line's own words."""
    from glessner.cli import OPENING, OpenProgress

    now = [100.0]
    progress = OpenProgress(clock=lambda: now[0])
    reading = "Upgrading the case format: reading the output of the runs"
    progress(reading, 1, 306)
    now[0] = 102.0
    progress(reading, 40, 306)   # the same stage again: no line
    progress.tick()   # 2 s quiet: no line
    now[0] = 105.4
    progress(reading, 141, 306)
    progress.tick()
    now[0] = 108.0
    progress.tick()   # 2.6 s since the last line: none
    now[0] = 110.6
    progress.tick()   # quiet again, and the count hasn't moved since the last line
    progress("Upgrading the case format: reloading 67,858 Suricata events", 2, 9)
    now[0] = 116.0
    progress.tick()   # 5.4 s into a stage whose count is the group it is on, which stays 2
    progress("Opening")
    progress.finish()
    now[0] = 130.0
    progress.tick()   # the open is done: nothing more
    assert capsys.readouterr().out.splitlines() == [
        f"   0 s  {reading}, 1 of 306",
        "   5 s    still working: 141 of 306",
        "  11 s    still working on this step",
        "  11 s  Upgrading the case format: reloading 67,858 Suricata events, 2 of 9",
        "  16 s    still working on this step",
        f"  16 s  {OPENING}",
        "  16 s  Opened.",
    ]


def test_the_open_s_thread_writes_the_still_working_lines_and_stops_with_the_open(capsys, monkeypatch):
    """The context's thread is what writes a still-working line during a step that reports nothing, and it
    ends when the open does."""
    from glessner.cli import OpenProgress

    monkeypatch.setattr(OpenProgress, "QUIET", 0.2)
    monkeypatch.setattr(OpenProgress, "TICK", 0.02)
    out = ""
    with OpenProgress() as progress:
        progress("Upgrading the case format: reloading 67,858 Suricata events", 2, 9)
        deadline = time.monotonic() + 10
        while "still working on this step" not in out and time.monotonic() < deadline:
            time.sleep(0.05)
            out += capsys.readouterr().out
    assert "still working on this step" in out
    assert not progress.thread.is_alive()
    time.sleep(0.3)
    assert capsys.readouterr().out == ""   # no line once the open is over


def test_each_run_has_a_session_of_its_own(running):
    """Two runs at once have sessions of their own, and each refuses the other's, as a tab left from an earlier run is
    refused by the run that took its port."""
    import threading

    from glessner.server import serve_start

    app, port, _ = running
    other, hub, _ = serve_start(0)   # a second run at once, on the start page
    threading.Thread(target=other.serve_forever, daemon=True).start()
    try:
        port2 = other.server_address[1]
        assert hub.session != app.session and port2 != port
        assert request(port, "GET", "/api/meta", session=hub.session)[0].status == 403
        assert request(port2, "GET", "/api/start", session=app.session)[0].status == 403
        assert request(port2, "GET", "/api/start", session=hub.session)[0].status == 200
    finally:
        other.shutdown()
        other.server_close()


def test_an_api_request_without_this_run_s_session_is_refused_as_json(running):
    """A tab left from an earlier run reaches the new run's server on the same port with the old run's session. Its API
    requests are answered 403 as JSON the page can show, saying to open the new link. Nothing of the case is in them, or
    in the page, which needs no session."""
    from glessner.server import STALE_SESSION

    app, port, _ = running
    old = "the-earlier-run-s-session"
    for method, path, body in (("GET", "/api/meta", None), ("POST", "/api/mark", {"uids": ["x"], "value": "malicious"})):
        for session in (old, None):
            res, payload = request(port, method, path, session=session, body=body)
            assert res.status == 403 and res.getheader("Content-Type") == "application/json", (method, path)
            assert json.loads(payload) == {"error": STALE_SESSION, "stale_session": True}
    res, payload = request(port, "GET", "/", session=old)
    assert res.status == 200 and app.case.settings.name.encode() not in payload


def test_two_requests_cannot_both_start_a_start_page_job():
    """Opening a case is the most frequent start page job, so the check for a running one and the start of the next are one
    step: two requests at once start one job, and the other is refused."""
    import threading

    from glessner.server import Hub, _start_job

    class Job:
        name, finished = "Case", False

        def state(self):
            return {}

    hub = Hub()
    results = []

    def make():
        time.sleep(0.2)   # long enough for the second request to pass an unguarded check
        return Job()

    def ask_for_a_job():
        try:
            results.append(_start_job(hub, make))
        except ValueError as e:
            results.append(e)

    threads = [threading.Thread(target=ask_for_a_job) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(type(r).__name__ for r in results) == ["ValueError", "dict"]


def test_view_api_marks_counts_and_pivot_fields(running):
    """Mark counts for the View flyout, a View registered as a filter, and pivot results
    that carry what the page needs to tell which ones the View hides."""
    app, port, _ = running
    session = login(port, app)
    rdp = app.con.execute("SELECT event_uid FROM events WHERE tool = 'evtxecmd' AND ts_us = ?", [T0]).fetchone()[0]
    request(port, "POST", "/api/mark", session=session, body={"uids": [rdp], "value": "malicious"})
    counts = json.loads(request(port, "GET", "/api/marks", session=session)[1])["counts"]
    assert counts["Malicious"] == 1 and counts["Suggested"] >= 1 and counts["Unreviewed"] > 0
    res, body = request(port, "POST", "/api/filter", session=session, body={"view": {"marks": ["Malicious"]}})
    assert res.status == 200
    fid = json.loads(body)["id"]
    events = json.loads(request(port, "GET", f"/api/view?start={T0 - 3600 * 10**6}&end={T0 + 3600 * 10**6}"
                                             f"&groupby=mark,host&filter={fid}", session=session)[1])["events"]
    assert [e["uid"] for e in events] == [rdp]
    rel = json.loads(request(port, "GET", f"/api/related?uid={rdp}&kind=account&filter={fid}", session=session)[1])
    assert rel["anchor"] == {"user_domain": "C137", "user_name": "Administrator"} and rel["total"] == len(rel["events"])
    # The server says which results the View shows: only the Malicious one here.
    assert {e["uid"] for e in rel["events"] if e["shown"]} == {rdp} and len(rel["events"]) > 1


def test_related_api_takes_only_an_address_the_event_has(synthetic_case, tmp_path):
    """/api/related?kind=addr pivots on one of the event's own addresses and says which
    end each result had it at; any other address is refused. A View at either end registers and shows the same events."""
    from test_analysis_relations import ATTACKER, load_inbound

    uids = load_inbound(synthetic_case, tmp_path)
    for app, port, _ in serving(synthetic_case):
        session = login(port, app)
        get = lambda path: request(port, "GET", path, session=session)   # noqa: B023
        res, body = get(f"/api/related?uid={uids['inbound']}&kind=addr&ip={ATTACKER}")
        rel = json.loads(body)
        assert res.status == 200 and rel["address"] == ATTACKER
        assert {e["uid"]: e["end"] for e in rel["events"]} == {uids["inbound"]: "destination", uids["rdp"]: "source",
                                                               uids["failed"]: "source"}
        for ip in ("10.42.85.115", ""):
            res, body = get(f"/api/related?uid={uids['inbound']}&kind=addr&ip={ip}")
            assert res.status == 400 and "one of this event's addresses: 10.42.85.10, 194.61.24.102" in json.loads(body)["error"]
        res, body = get(f"/api/related?uid={uids['inbound']}&kind=addr")   # no ip at all
        assert res.status == 400
        view = {"view": {"values": [{"addr": ATTACKER}]}}
        fid = json.loads(request(port, "POST", "/api/filter", session=session, body=view)[1])["id"]
        window = f"start={T0 - 3600 * 10**6}&end={T0 + 3600 * 10**6}"
        events = json.loads(get(f"/api/view?{window}&groupby=host&filter={fid}")[1])["events"]
        assert {e["uid"] for e in events} == {e["uid"] for e in rel["events"]}


def test_import_page_adds_previews_and_imports(running, synthetic_case):
    """Add new evidence, a preview that asks for a zone, then an import the timeline shows."""
    from glessner.intake import intake

    app, port, _ = running
    session = login(port, app)
    intake(synthetic_case)
    (synthetic_case.evidence / "DC01" / "pfirewall.log").write_bytes(
        b"#Version: 1.5\r\n#Software: Microsoft Windows Firewall\r\n#Time Format: Local\r\n"
        b"#Fields: date time action protocol src-ip dst-ip src-port dst-port size tcpflags tcpsyn tcpack tcpwin "
        b"icmptype icmpcode info path pid\r\n"
        b"2020-09-19 03:21:48 ALLOW TCP 194.61.24.102 10.42.85.10 51544 3389 0 - 0 0 0 - - - RECEIVE 1234\r\n")
    post = lambda path, body: json.loads(request(port, "POST", path, session=session, body=body)[1])
    get = lambda path: json.loads(request(port, "GET", path, session=session)[1])
    added = post("/api/evidence_add", {})
    assert (added["by_artifact"], added["links"]) == ({"w3c_log": 1}, [])   # links skipped
    files = get("/api/imports")["files"]
    assert [(f["path"], f["detail"], f["imported"]) for f in files] == [("DC01/pfirewall.log", "Windows Firewall", None)]
    first = post("/api/import_preview", {"path": "DC01/pfirewall.log"})
    assert first["mapping"]["preset"] == "windows_firewall" and "carry no zone" in first["problems"][0]
    mapping = {**first["mapping"], "time": {**first["mapping"]["time"], "zone": "UTC"}}
    ready = post("/api/import_preview", {"path": "DC01/pfirewall.log", "mapping": mapping})
    assert not ready["problems"] and ready["events"][0]["ts"] == T0
    out = post("/api/import", {"paths": ["DC01/pfirewall.log"], "mapping": mapping, "save_as": "dc-firewall"})
    assert out["runs"][0]["status"] == "ok" and out["runs"][0]["rows"] == 1 and out["saved_as"] == "dc-firewall"
    sources = get("/api/sources")
    assert "import" in json.dumps(sources) and "windows_firewall" in json.dumps(sources)
    assert get("/api/imports")["files"][0]["imported"]["rows"] == 1
    res, payload = request(port, "POST", "/api/import_preview", session=session, body={"path": "../case.yaml"})
    assert res.status == 400 and "Not an evidence file" in json.loads(payload)["error"]


def test_an_import_whose_save_as_name_is_refused_imports_nothing(running, synthetic_case):
    """The "Save mapping as" name is checked before any file is imported, with save_mapping's own message, so a refused
    name leaves no run and no events behind the error the page shows."""
    from glessner.imports import MappingError, save_mapping
    from glessner.intake import intake
    from glessner.runner import read_runs

    app, port, _ = running
    session = login(port, app)
    (synthetic_case.evidence / "DC01" / "fw.csv").write_text("time,src\n2020-09-19T03:21:48Z,194.61.24.102\n",
                                                             encoding="utf-8")
    intake(synthetic_case)
    post = lambda path, body: request(port, "POST", path, session=session, body=body)
    mapping = json.loads(post("/api/import_preview", {"path": "DC01/fw.csv"})[1])["mapping"]
    with pytest.raises(MappingError) as refused:
        save_mapping(synthetic_case, "Palo Alto traffic", mapping)
    res, body = post("/api/import", {"paths": ["DC01/fw.csv"], "mapping": mapping, "save_as": "Palo Alto traffic"})
    assert res.status == 400 and json.loads(body)["error"] == str(refused.value)
    assert read_runs(synthetic_case) == []
    files = json.loads(request(port, "GET", "/api/imports", session=session)[1])["files"]
    assert [(f["path"], f["imported"]) for f in files] == [("DC01/fw.csv", None)]


def fake_tool_case(case, tmp_path):
    """The synthetic case with an event log on disk, taken in, and a stand-in tool from test_runner."""
    from test_runner import fake_spec

    from glessner.intake import intake

    logs = case.evidence / "DC01" / "Windows" / "System32" / "winevt" / "Logs"
    logs.mkdir(parents=True)
    (logs / "Security.evtx").write_bytes(b"ElfFile\x00" + b"\x01" * 64)
    intake(case)
    tool = fake_spec(tmp_path)
    spec = tool.spec.__class__(**{**tool.spec.__dict__, "args": tool.spec.args[:-1] + ("ok",)})
    return {"fake": spec}, {"fake": tool.__class__(spec, tool.executable, tool.version)}


def test_tools_page_lists_and_runs_a_tool(running, synthetic_case, tmp_path):
    """The Tools page's data, and a run in the background that the page follows."""
    import time

    app, port, _ = running
    session = login(port, app)
    app.tool_cache = fake_tool_case(synthetic_case, tmp_path)
    get = lambda path: json.loads(request(port, "GET", path, session=session)[1])
    tools = get("/api/tools")
    (fake,) = tools["tools"]
    assert (fake["status"], fake["reads"], fake["hosts"]) == ("ready", "1 event log", ["DC01"])
    res, body = request(port, "POST", "/api/run_tool", session=session, body={"tool": "fake"})
    assert res.status == 200 and json.loads(body)["job"]["total"] == 1
    for _ in range(100):
        job = get("/api/run_status")["job"]
        if job["finished"]:
            break
        time.sleep(0.1)
    assert job["finished"] and job["results"][0]["status"] == "ok" and not job["error"]
    assert get("/api/tools")["tools"][0]["status"] == "ran"
    res, body = request(port, "POST", "/api/run_tool", session=session, body={"tool": "nope"})
    assert res.status == 400 and "No tool" in json.loads(body)["error"]


def test_a_tool_that_runs_per_file_counts_and_names_each_file(synthetic_case, tmp_path):
    """The Tools page counts the latest run of each file, as rebuild loads them, and names each run's file: counting a
    tool's latest run on each host would read WxTCmd's four runs on DESKTOP, one per Timeline database, as the last
    one's 28 events, and name all four jobs "WxTCmd on DESKTOP". A job's result says what its steps were, and
    Hayabusa's rows are hits."""
    from glessner.intake import add_new
    from glessner.runner import RunRecord, finish_run, plan_runs, start_run
    from glessner.toolbox import _step_name, _step_result, overview, start_job

    specs, detected = fake_tool_case(synthetic_case, tmp_path)
    logs = synthetic_case.evidence / "DC01" / "Windows" / "System32" / "winevt" / "Logs"
    (logs / "System.evtx").write_bytes(b"ElfFile\x00" + b"\x02" * 64)
    add_new(synthetic_case)
    spec = specs["fake"].__class__(**{**specs["fake"].__dict__, "input": "each_file"})
    tool = detected["fake"].__class__(spec, detected["fake"].executable, detected["fake"].version)
    plans = plan_runs(synthetic_case, tool)
    assert [_step_name(p) for p in plans] == ["Fake on DC01, Windows/System32/winevt/Logs/Security.evtx",
                                              "Fake on DC01, Windows/System32/winevt/Logs/System.evtx"]
    for plan, rows in ((plans[0], 10), (plans[1], 37), (plans[0], 34)):   # the first file ran twice
        record, folder = start_run(synthetic_case, "fake", "DC01", tool_version="1.0", host="DC01",
                                   inputs=list(plan.inputs), status="ok", loaded_rows=rows)
        finish_run(folder, record)
    (fake,) = overview(synthetic_case, {"fake": spec}, {"fake": tool})["tools"]
    assert (fake["last_run"]["rows"], fake["last_run"]["hosts"], fake["hits"]) == (71, ["DC01"], False)
    job = start_job(synthetic_case, tool, None, lambda job: None)
    for _ in range(100):
        if job.finished:
            break
        time.sleep(0.1)
    state = job.state()
    assert (state["kind"], state["done"], state["total"]) == ("run", 2, 2) and not state["error"]
    assert [r["host"] for r in state["results"]] == ["DC01, Windows/System32/winevt/Logs/Security.evtx",
                                                     "DC01, Windows/System32/winevt/Logs/System.evtx"]
    hits = RunRecord(run_id="h", tool="hayabusa", tool_version="", executable="", host="DC01", argv=[], cwd="",
                     inputs=[], started_utc="", status="ok", loaded_rows=3)
    assert _step_result("Hayabusa CSV on DC01", {"tool": "hayabusa"}, [hits])["hits"]


def test_a_tool_that_reads_the_host_s_folder_counts_its_run_after_new_evidence_alone(synthetic_case, tmp_path):
    """A tool that reads a host's whole folder, such as EvtxECmd, run again after Add new evidence, has a second input
    set. The later run's load replaces the first run's events, so the case holds 15, and the page counts the later run
    alone, not both runs, 10 + 15 events."""
    from glessner.intake import add_new
    from glessner.runner import finish_run, plan_runs, start_run
    from glessner.toolbox import overview

    specs, detected = fake_tool_case(synthetic_case, tmp_path)
    assert specs["fake"].input == "host_dir"

    def ran(rows):
        (plan,) = plan_runs(synthetic_case, detected["fake"])
        record, folder = start_run(synthetic_case, "fake", "DC01", tool_version="1.0", host="DC01",
                                   inputs=list(plan.inputs), status="ok", loaded_rows=rows)
        finish_run(folder, record)
        return record

    assert len(ran(10).inputs) == 1   # Security.evtx
    logs = synthetic_case.evidence / "DC01" / "Windows" / "System32" / "winevt" / "Logs"
    (logs / "System.evtx").write_bytes(b"ElfFile\x00" + b"\x02" * 64)
    add_new(synthetic_case)
    assert len(ran(15).inputs) == 2   # and System.evtx
    (fake,) = overview(synthetic_case, specs, detected)["tools"]
    assert (fake["last_run"]["rows"], fake["last_run"]["hosts"]) == (15, ["DC01"])


def test_the_meta_names_the_case_by_a_key_that_lasts_across_opens(synthetic_case, tmp_path):
    """The browser keeps the lane folds per case, and case_id changes with every open, so /api/meta adds
    case_key, a hash of the case folder's path, the same across opens and however the path's letters are cased, and
    different for a copy of the case."""
    from glessner.case import copy_case, open_case
    from glessner.server import App, api_meta, case_key

    keys = []
    for case in (synthetic_case, open_case(Path(str(synthetic_case.folder).upper())), synthetic_case):
        app = App(case)
        try:
            meta = api_meta(app, {})
            assert meta["case_key"] == case_key(case) and len(meta["case_key"]) == 16
            keys.append((meta["case_key"], meta["case_id"]))
        finally:
            app.con.close()
    assert len({k for k, _ in keys}) == 1 and len({i for _, i in keys}) == 3
    copy = copy_case(synthetic_case, tmp_path / "copy", "Copy", "cody")
    assert case_key(copy) != keys[0][0]


def test_host_split_routes(running):
    """The preview is a GET, and a host whose event logs record one computer has nothing to split; the meta
    and every Hosts panel answer carry the mixed hosts and the splits."""
    app, port, _ = running
    session = login(port, app)
    res, body = request(port, "GET", "/api/host_split?host=DC01", session=session)
    assert res.status == 400 and "nothing to split" in json.loads(body)["error"]
    meta = json.loads(request(port, "GET", "/api/meta", session=session)[1])
    assert (meta["mixed"], meta["splits"]) == ([], [])
    res, body = request(port, "POST", "/api/host", session=session, body={"keep_host": "DC01"})
    assert res.status == 400 and "don't record several computers" in json.loads(body)["error"]


def test_a_fault_in_a_route_is_answered_500_with_its_message(running, monkeypatch):
    """An exception the routes don't expect, such as OSError, is answered 500 with its message, since with no answer the
    page shows only "Failed to fetch"."""
    from glessner import server

    def broken(app, query):
        raise OSError(22, "Invalid argument")

    app, port, _ = running
    session = login(port, app)
    monkeypatch.setitem(server.GET_ROUTES, "/api/marks", broken)
    res, body = request(port, "GET", "/api/marks", session=session)
    assert res.status == 500 and json.loads(body) == {"error": "OSError: [Errno 22] Invalid argument"}
    assert request(port, "GET", "/api/counts", session=session)[0].status == 200   # the server still answers


def test_the_meta_names_every_tool_and_every_artifact_the_parsers_write():
    """The page keeps no lists of tool and artifact names of its own, which would fall behind. /api/meta sends them:
    every registry tool, every tool whose output is found in the evidence, and the import; every artifact a parser
    writes, and every import preset's."""
    import re
    from pathlib import Path

    from glessner import parsers
    from glessner.imports import PRESETS
    from glessner.server import page_names
    from glessner.tool_outputs import KINDS
    from glessner.tools import load_registry

    names = page_names()
    assert set(load_registry()) | {k.tool for k in KINDS} | {"import"} <= set(names["tool_names"])
    written = {artifact for path in Path(parsers.__file__).parent.glob("*.py")
               for artifact in re.findall(r'artifact="([a-z_]+)"', path.read_text(encoding="utf-8"))}
    assert len(written) > 15 and written | {p["artifact"] for p in PRESETS.values()} <= set(names["artifact_names"])


def test_a_number_field_that_isnt_one_is_answered_400(running):
    """int() and float() raise TypeError for a null, a list, or an object, which would be answered 500 with a traceback
    in the console, where bad text is answered 400. Each such field is a 400 naming the field, and nothing is
    journaled."""
    app, port, _ = running
    session = login(port, app)
    before = journaled(app)
    fields = [("/api/undo", {}, "seq"), ("/api/setting", {"name": "event_threshold"}, "value"),
              ("/api/host", {"host": "DC01"}, "offset_seconds"), ("/api/export", {"end": T0}, "start"),
              ("/api/export", {"start": T0}, "end")]
    for path, body, name in fields:
        for value in (None, [1], {"n": 1}, "many"):
            res, answer = request(port, "POST", path, session=session, body={**body, name: value})
            assert (res.status, json.loads(answer)) == (400, {"error": f"{name} must be a number"}), (path, value)
    # Infinity, which Python's JSON reader takes, isn't a whole number: int() raises OverflowError.
    res, answer = request(port, "POST", "/api/setting", session=session,
                          body={"name": "event_threshold", "value": float("inf")})
    assert (res.status, json.loads(answer)) == (400, {"error": "value must be a number"})
    assert journaled(app) == before
    res, answer = request(port, "POST", "/api/setting", session=session, body={"name": "event_threshold", "value": 20000})
    assert res.status == 200 and json.loads(answer)["value"] == 20000


class CursorsOnly:
    """An App's connection that refuses statements, for a route that must read through a cursor: app.con is for use
    under app.lock, and two threads on it can fetch each other's results with no error."""

    def __init__(self, con):
        self.con = con

    def cursor(self):
        return self.con.cursor()

    def __getattr__(self, name):
        raise AssertionError(f"app.con.{name} used outside app.lock")


def test_the_import_preview_and_a_case_open_read_through_cursors(synthetic_case, monkeypatch):
    """The Import page's preview reads the case's year, and a case open the event count once the new App is visible to
    requests, through a cursor and not on app.con without the lock."""
    from glessner import server
    from glessner.intake import intake

    (synthetic_case.evidence / "DC01" / "fw.csv").write_text("time,src\n2020-09-19T03:21:48Z,10.0.0.1\n")
    intake(synthetic_case)
    app = server.App(synthetic_case)
    con, app.con = app.con, CursorsOnly(app.con)
    try:
        assert server.api_import_preview(app, {"path": "DC01/fw.csv"})["events"]
    finally:
        con.close()

    class Opened(server.App):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.con = CursorsOnly(self.con)   # from here, request threads can reach the App
    monkeypatch.setattr(server, "App", Opened)
    hub = server.Hub(synthetic_case)
    hub.app.con.con.close()


def test_a_sources_listing_read_before_a_load_is_not_kept_after_it(synthetic_case, monkeypatch):
    """A Sources request that reads the events before a load's commit, and stores its listing after the load's refresh
    clears the cache, must not keep the old listing until the next load. Here the load and its refresh run while the
    request reads."""
    import threading

    from conftest import SEC, logon

    from glessner import server
    from glessner.events import load

    archive = "DC01/Windows/System32/winevt/Logs/Archive-Security.evtx"
    app = server.App(synthetic_case)
    real, loaders = server.sources, []

    def load_and_refresh():
        load(synthetic_case.db_path, [logon(T0 + SEC, 1, archive)], host="DC01", tool="evtxecmd", tool_version="t",
             run_id="r9", replaces_sources=[archive], staging_dir=synthetic_case.folder)
        app.refresh_identity(events_changed=True)   # as a job's after() does

    def read_during_a_load(cur):
        listing = real(cur)   # the events before the load
        loaders.append(threading.Thread(target=load_and_refresh))
        loaders[0].start()
        loaders[0].join(timeout=1.5)   # done by now, unless the request's lock holds the refresh back
        return listing
    monkeypatch.setattr(server, "sources", read_during_a_load)
    try:
        assert archive not in json.dumps(server.api_sources(app, {}))
        loaders[0].join()
        monkeypatch.setattr(server, "sources", real)
        assert archive in json.dumps(server.api_sources(app, {}))
    finally:
        app.con.close()


def paused(server, name, monkeypatch):
    """Patch a function of the server module to run, then signal `reached` and wait for `release`, the first time only;
    later calls, such as a preview's, run through."""
    import threading

    real, reached, release, calls = getattr(server, name), threading.Event(), threading.Event(), []

    def first_waits(*args, **kwargs):
        result = real(*args, **kwargs)
        calls.append(1)
        if len(calls) == 1:
            reached.set()
            release.wait(10)
        return result
    monkeypatch.setattr(server, name, first_waits)
    return reached, release


def in_thread(answers, name, fn, *args):
    import threading

    thread = threading.Thread(target=lambda: answers.update({name: fn(*args)}))
    thread.start()
    return thread


def test_an_undo_plans_under_the_lock_so_a_mark_made_meanwhile_stands(synthetic_case, monkeypatch):
    """api_undo holds app.lock from its plan through its rewrite, and a mark waits for it. Without the lock, a
    Malicious mark made while an undo of a Suspicious mark planned would be journaled, and the undo would then append
    its plan after it, changed 1 and kept 0, so the event would end Unreviewed. Requests that only read don't wait: an
    Event page and the undo's preview answer while the undo plans."""
    import time

    from glessner import server
    from glessner.journal import replay

    app = server.App(synthetic_case)
    uid = app.con.execute("SELECT event_uid FROM events WHERE tool = 'evtxecmd' AND ts_us = ?", [T0]).fetchone()[0]
    reached, release = paused(server, "plan_undo", monkeypatch)
    answers = {}
    try:
        seq = server.api_mark(app, {"uids": [uid], "value": "suspicious"})["seq"]
        undo = in_thread(answers, "undo", server.api_undo, app, {"seq": seq})
        assert reached.wait(10)
        mark = in_thread(answers, "mark", server.api_mark, app, {"uids": [uid], "value": "malicious"})
        mark.join(0.5)
        assert mark.is_alive() and journaled(app)[-1] == "mark" and app.journal.state.last_seq == seq
        t0 = time.perf_counter()
        assert server.api_event(app, {"uid": [uid]})["event"]["mark"]["label"] == "Suspicious"
        assert server.api_undo_plan(app, {"seq": [str(seq)]})["changed"] == 1
        assert time.perf_counter() - t0 < 2
        release.set()
        undo.join(10)
        mark.join(10)
        assert answers["undo"] == {"seq": seq + 1, "changed": 1, "kept": 0} and answers["mark"]["seq"] == seq + 2
        assert replay(app.journal.path).marks[uid].value == "malicious"
        assert app.con.execute("SELECT label FROM marks WHERE event_uid = ?", [uid]).fetchone() == ("Malicious",)
    finally:
        release.set()
        app.con.close()


def test_an_accept_reads_its_pending_suggestions_under_the_lock(synthetic_case, monkeypatch):
    """An accept holds the lock from its read of the pending suggestions, and a mark waits for it, so the analyst's
    later mark stands. Without the lock, a mark made before the accept journaled its own would be overwritten: the
    analyst's Authorized mark, then the accept's Suspicious one."""
    from glessner import server
    from glessner.journal import replay

    app = server.App(synthetic_case)
    uid = app.con.execute("SELECT event_uid FROM events WHERE tool = 'evtxecmd' AND ts_us = ?", [T0]).fetchone()[0]
    reached, release = paused(server, "pending_for_source", monkeypatch)
    answers = {}
    try:
        accept = in_thread(answers, "accept", server.api_suggestion, app,
                           {"decision": "accept", "source": "hayabusa", "uids": [uid]})
        assert reached.wait(10)
        mark = in_thread(answers, "mark", server.api_mark, app, {"uids": [uid], "value": "authorized"})
        mark.join(0.5)
        assert mark.is_alive() and "mark" not in journaled(app)
        release.set()
        accept.join(10)
        mark.join(10)
        assert answers["accept"]["changed"] == 1
        lines = (app.case.folder / "journal.jsonl").read_text(encoding="utf-8").splitlines()
        assert [(e["value"], e["note"]) for e in map(json.loads, lines) if e["action"] == "mark"] == [
            ("suspicious", "Accepted suggestion from hayabusa"), ("authorized", "")]
        assert replay(app.journal.path).marks[uid].value == "authorized"
    finally:
        release.set()
        app.con.close()


def test_every_route_that_journals_appends_under_the_lock(synthetic_case, monkeypatch):
    """Every route that journals appends under app.lock, not outside it and taking it only to rewrite the derived
    tables, so an undo's plan, an accept's pending suggestions, a host edit's rebuild, or a findings summary can't read
    the journal's state as another request changes it. Each append here is checked from a second thread, which can't
    take the lock while the route holds it."""
    import threading

    from glessner import server

    app = server.App(synthetic_case)
    real, unlocked = app.journal.append, []

    def append(action, **payload):
        def probe():
            if app.lock.acquire(blocking=False):
                app.lock.release()
                unlocked.append(action)
        thread = threading.Thread(target=probe)
        thread.start()
        thread.join()
        return real(action, **payload)

    monkeypatch.setattr(app.journal, "append", append)
    uids = [u for (u,) in app.con.execute("SELECT event_uid FROM events WHERE tool = 'evtxecmd' ORDER BY ts_us").fetchall()]
    rule = "id: test-rule\ndescription: A test\nsuggest: authorized\nwhen:\n  all:\n    - {field: host, in: [DC01]}\n"
    try:
        seq = server.api_mark(app, {"uids": uids[:1], "value": "suspicious"})["seq"]
        note = server.api_note(app, {"uid": uids[1], "text": "look"})["seq"]
        calls = [
            (server.api_note_retract, {"uid": uids[1], "note_seq": note}),
            (server.api_tag, {"uids": uids[:2], "add": ["lateral-movement"]}),
            (server.api_tag_suggestion, {"uids": uids[:1], "tags": ["tactic:TA0001"], "decision": "dismissed"}),
            (server.api_setting, {"name": "event_threshold", "value": 20000}),
            (server.api_setting, {"name": "time_zones", "value": [{"host": "DC01"}]}),
            (server.api_host, {"host": "DC01", "role": "Servers"}),
            (server.api_host, {"host": "DC01", "offset_seconds": 5}),
            (server.api_host, {"host": "DC01", "op": "add_name", "value": "DC-ONE"}),
            (server.api_host, {"confirm_hosts": ["DESKTOP"]}),
            (server.api_rule, {"op": "add", "text": rule}),
            (server.api_rule, {"op": "change", "text": rule.replace("A test", "Changed")}),
            (server.api_rule, {"op": "remove", "id": "test-rule"}),
            (server.api_suggestion, {"decision": "reject", "source": "hayabusa", "uids": uids[:1]}),
            (server.api_suggestion, {"decision": "restore", "source": "hayabusa", "uids": uids[:1]}),
            (server.api_suggestion, {"decision": "accept", "source": "machine-accounts-authorized"}),
            (server.api_undo, {"seq": seq}),
            # The journal's other writers: follow-up, each finding op, and the three file entries
            (server.api_followup, {"uids": uids[:2], "done": True}),
            (server.api_finding, {"op": "add", "title": "Lateral movement", "severity": "High", "targets": uids[:1]}),
        ]
        for route, body in calls:
            route(app, body)
        fid = app.journal.state.last_seq
        more = [(server.api_finding, {"op": "edit", "finding": fid, "severity": "Low"}),
                (server.api_finding, {"op": "link", "finding": fid, "targets": uids[1:2]}),
                (server.api_finding, {"op": "unlink", "finding": fid, "targets": uids[1:2]}),
                (server.api_finding, {"op": "retire", "finding": fid, "reason": "test"}),
                (server.api_finding, {"op": "restore", "finding": fid}),
                (server.api_export, {"start": 0, "end": 2**53, "format": "csv", "marks": "all"}),
                (server.api_report, {}), (server.api_indicators, {}), (server.api_audit_export, {})]
        for route, body in more:
            route(app, body)
        assert journaled(app)[-29:] == ["mark", "note", "note_retract", "tag", "tag_suggestion", "case_setting",
                                        "case_setting", "host_role", "host_offset", "host_identity", "host_role",
                                        "rule_add", "rule_change", "rule_remove", "suggestion_decision",
                                        "suggestion_decision", "mark", "undo", "followup", "finding", "finding",
                                        "finding", "finding", "finding", "finding", "file_written", "file_written",
                                        "file_written", "file_written"]
        assert unlocked == []
        # Every function of server.py that writes the journal is a route called here, a helper such a route calls
        # under its lock, or Continue with the break on record, which test_journal_actions.py checks the same way
        called = {route.__name__ for route, _ in [*calls, *more]} | {"api_mark", "api_note"}
        inside = {"_align": "api_host", "_host_split": "api_host", "_set_pivot_windows": "api_setting",
                  "_decide": "api_suggestion"}
        assert journal_writers(server) - called - set(inside) == {"api_chain_break"}
        assert set(inside.values()) <= called
    finally:
        app.con.close()


def journal_writers(module) -> set[str]:
    """The functions of `module` that write the journal: a call of journal.append or journal.record_break, or of
    export.record_file, which appends the file's entry."""
    import ast

    found = set()
    for fn in ast.walk(ast.parse(Path(module.__file__).read_text(encoding="utf-8"))):
        if not isinstance(fn, ast.FunctionDef):
            continue
        for node in ast.walk(fn):
            f = node.func if isinstance(node, ast.Call) else None
            if (isinstance(f, ast.Attribute) and f.attr in ("append", "record_break")
                    and isinstance(f.value, ast.Attribute) and f.value.attr == "journal") or (
                    isinstance(f, ast.Name) and f.id == "record_file"):
                found.add(fn.name)
    return found


def test_an_event_s_tags_are_read_from_a_copy_of_the_journal_s(synthetic_case, monkeypatch):
    """The Event page reads an event's tags without the lock, and loops over a copy of the journal's dict of them,
    which a tag journaled meanwhile changes: a loop over the original raises "dictionary changed size during
    iteration", and the page answers 500. Here the loop's own first step journals a tag on the event, as a request
    would."""
    from glessner import server

    app = server.App(synthetic_case)
    uid = app.con.execute("SELECT event_uid FROM events WHERE tool = 'evtxecmd' AND ts_us = ?", [T0]).fetchone()[0]
    real = server.tag_kind

    def tag_kind(key):   # a tag journaled while the loop reads
        if "tactic:TA0002" not in app.journal.state.tags[uid]:
            app.journal.append("tag", targets=[uid], add=["tactic:TA0002"], remove=[])
        return real(key)

    try:
        server.api_tag(app, {"uids": [uid], "add": ["lateral-movement"]})
        monkeypatch.setattr(server, "tag_kind", tag_kind)
        applied, _ = server._event_tags(app, uid)
        assert [t["key"] for t in applied] == ["tag:lateral-movement"]   # as the loop began
        assert set(app.journal.state.tags[uid]) == {"tag:lateral-movement", "tactic:TA0002"}
    finally:
        app.con.close()
