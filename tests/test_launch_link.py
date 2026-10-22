"""The session and the start link, over HTTP: the session travels in a header and not a cookie, the page's files need none,
and the start link's token is traded for the session once."""

import json

from test_server import request

from glessner.server import LINK_USED, SESSION_HEADER, STALE_SESSION, Hub


def token_of(url):
    return url.split("?token=", 1)[1]


def trade(port, token, **kwargs):
    """The page's request for the session with the start link's token."""
    return request(port, "POST", "/api/session", body={"token": token}, **kwargs)


def test_an_api_request_needs_the_session_in_its_header_and_not_a_cookie(running):
    """The session goes in X-Glessner-Session. A session sent in a cookie is not read: a browser sends a cookie to every
    server on the address, and the header only to a request the page makes."""
    app, port, _ = running
    res, payload = request(port, "GET", "/api/meta")
    assert res.status == 403 and json.loads(payload) == {"error": STALE_SESSION, "stale_session": True}
    cookie = {"Cookie": f"glessner_session_{port}={app.session}"}
    assert request(port, "GET", "/api/meta", headers=cookie)[0].status == 403
    assert request(port, "GET", "/api/meta", headers={SESSION_HEADER: app.session})[0].status == 200
    assert request(port, "GET", "/api/meta", headers={SESSION_HEADER: app.session, **cookie})[0].status == 200


def test_the_start_link_sets_no_cookie_and_leaves_its_token_for_the_page(running):
    """A GET of the start link answers the page, with no redirect and no Set-Cookie, and spends nothing: the page's own
    request trades the token."""
    _, port, url = running
    res, payload = request(port, "GET", f"/?token={token_of(url)}")
    assert res.status == 200 and res.getheader("Content-Type").startswith("text/html")
    assert res.getheader("Set-Cookie") is None and b"<script" in payload
    assert trade(port, token_of(url))[0].status == 200


def test_the_pages_files_need_no_session_and_are_refused_to_another_site(running):
    _, port, _ = running
    res, payload = request(port, "GET", "/js/core.js")
    assert res.status == 200 and res.getheader("Content-Type").startswith("text/javascript") and b"X-Glessner-Session" in payload
    assert request(port, "GET", "/js/core.js", headers={"Sec-Fetch-Site": "cross-site"})[0].status == 403
    assert request(port, "GET", "/js/core.js", host="attacker.example:80")[0].status == 403


def test_no_answer_allows_another_origin(running):
    """The server answers no preflight, and no answer carries a CORS header, so a page of another origin can neither
    send the session header nor read an answer."""
    app, port, _ = running
    for method, headers in (("OPTIONS", None), ("GET", {SESSION_HEADER: app.session}), ("GET", None)):
        res, _ = request(port, method, "/api/meta", headers=headers)
        assert res.getheader("Access-Control-Allow-Origin") is None
        assert res.getheader("Access-Control-Allow-Headers") is None
    assert request(port, "OPTIONS", "/api/meta")[0].status == 501


def test_the_start_links_token_is_traded_for_the_session_once(running):
    app, port, url = running
    token = token_of(url)
    res, payload = trade(port, token)
    assert res.status == 200 and json.loads(payload) == {"session": app.session}
    assert request(port, "GET", "/api/meta", headers={SESSION_HEADER: json.loads(payload)["session"]})[0].status == 200
    res, payload = trade(port, token)
    assert res.status == 403 and json.loads(payload) == {"error": LINK_USED, "link_used": True}


def test_a_wrong_token_leaves_the_start_link_unspent(running):
    app, port, url = running
    for token in ("wrong", "", token_of(url)[:-1], None, 7, ["x"]):
        res, payload = trade(port, token)
        assert res.status == 403 and json.loads(payload)["link_used"] is True, token
    assert request(port, "POST", "/api/session", body={})[0].status == 403
    assert json.loads(trade(port, token_of(url))[1]) == {"session": app.session}


def test_the_trade_refuses_a_request_from_another_origin_or_without_json(running):
    """A page on another 127.0.0.1 port can't spend the token: its POST names its own origin. A request that isn't JSON,
    as a form of another site would send, spends nothing either."""
    _, port, url = running
    other = {"Origin": f"http://127.0.0.1:{port + 1}"}
    assert trade(port, token_of(url), headers=other)[0].status == 403
    assert trade(port, token_of(url), headers={"Origin": "http://evil.example"})[0].status == 403
    assert request(port, "POST", "/api/session", headers={"Content-Type": "text/plain"})[0].status == 415
    assert trade(port, token_of(url), host="attacker.example:80")[0].status == 403
    assert trade(port, token_of(url), headers={"Origin": f"http://127.0.0.1:{port}"})[0].status == 200


def test_only_the_newest_start_link_works_and_it_works_once():
    hub = Hub()
    first, second = hub.new_token(), hub.new_token()
    assert first != second and len(second) >= 40
    assert not hub.spend(first) and not hub.spend(None) and not hub.spend("\ud800")
    assert hub.spend(second) and not hub.spend(second)
    assert hub.token is None and hub.session not in (first, second)
