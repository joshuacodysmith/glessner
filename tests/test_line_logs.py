"""Log lines in known layouts for the import: identification, fields, Cisco ASA directions, times without a year,
and imports."""

import json
import time

import pytest

from glessner.case import create_case
from glessner.events import connect
from glessner.identify import identify_bytes
from glessner.imports import (
    KV_PAIR,
    KV_PAIR_COMMA,
    PRESETS,
    guess_time_format,
    importable,
    preview,
    records,
    run_import,
)
from glessner.intake import intake
from glessner.line_logs import LAYOUTS
from glessner.runner import rebuild
from glessner.timezones import DATE_TIME

US = 1_000_000
APACHE = ('203.0.113.9 - alice [14/May/2024:12:04:22 -0700] "GET /login.php?u=a HTTP/1.1" 200 512 "-" "curl/8.0"\n'
          '10.0.0.5 - CORP\\bob [14/May/2024:12:04:24 +0000] "CONNECT example.com:443 HTTP/1.1" 200 - "-" "Edge" '
          '"cs_bytes=434 proxy_action=tunnel"\n'
          '198.51.100.7 - - [14/May/2024:12:05:00 +0000] "\\x16\\x03\\x01" 400 226\n')
APACHE_ERROR = ('[Sun Aug 23 14:43:47.578750 2015] [ssl:warn] [pid 3744:tid 236] AH01909: certificate mismatch\n'
                '[Sun Aug 23 14:44:02 2015] [error] [client 203.0.113.9] File does not exist: C:/xampp/htdocs/x\n'
                'a continuation line\n')
SYSLOG = ('<5>1 2024-05-14T12:00:15.781241Z WEB-01 kernel - - - [UFW BLOCK] IN=eth0 OUT= SRC=45.33.63.235 '
          'DST=10.44.30.10 PROTO=TCP SPT=63730 DPT=80 SYN\n'
          '2024-05-14T12:01:00.000000+00:00 WEB-01 sshd[812]: Accepted publickey for nina from 10.44.10.21 port 50122 ssh2\n'
          '<86>May 14 12:02:00 WEB-01 sudo:     nina : TTY=pts/0 ; PWD=/home/nina ; USER=root ; COMMAND=/usr/bin/id\n'
          'May 14 12:03:00 WEB-01 sshd[813]: pam_unix(sshd:session): session closed for user nina\n'
          'May 14 12:04:00 WEB-01 sshd[814]: Failed password for invalid user admin from 185.220.1.2 port 4444 ssh2\n')
# One file keeps one time format; this one is RFC 3164, without a year.
SYSLOG_BSD = "".join(line + "\n" for line in SYSLOG.splitlines()[2:]) + (
    "May 14 12:05:00 WEB-01 sshd[815]: Accepted password for nina from 10.44.10.21 port 50122 ssh2\n")
SNORT = ('05/14-12:55:09.776777 [**] [1:2002677:14] ET SCAN Nikto Web App Scan in Progress [**] '
         '[Classification: web-application-attack] [Priority: 2] {TCP} 185.199.110.42:51750 -> 45.83.220.5:80\n'
         '05/14/2024-12:56:00.000001  [**] [1:2100366:8] GPL ICMP_INFO PING *NIX [**] [Classification: Misc activity] '
         '[Priority: 3] {ICMP} 185.220.0.148 -> 45.83.220.5\n')
STAMPED = ('2015-08-23 14:45:39 3136 [Note] Plugin \'FEDERATED\' is disabled.\n'
           '2015-08-23 14:45:40,123 a74 InnoDB: Warning\n'
           '2015-08-23 14:45:40 3136 [Note] InnoDB: Using atomics\n'
           '[2015-08-23 14:45:41] 3136 [Note] Server hostname (bind-address): \'*\'; port: 3306\n'
           "Version: '5.6.25'  socket: ''  port: 3306\n"
           '2015-08-23T14:45:42Z 3136 [Note] Event Scheduler: Loaded 0 events\n'
           '2015-08-23 14:45:43 3136 [Note] mysqld: ready for connections.\n')
ASA_CISCO = (   # Cisco's own order: an outbound connection's outside responder first (Cisco TAC Q&A 116149)
    '<166>Dec 31 23:59:58 fw01 %ASA-6-302013: Built outbound TCP connection 9 for outside:93.184.216.34/443 '
    '(93.184.216.34/443) to inside:10.1.1.2/53496 (203.0.113.1/53496)\n'
    '<166>Jan 1 00:00:02 fw01 %ASA-6-302014: Teardown TCP connection 9 for outside:93.184.216.34/443 to '
    'inside:10.1.1.2/53496 duration 0:00:04 bytes 4321 TCP FINs\n'
    '<166>Jan 1 00:00:03 fw01 %ASA-6-302014: Teardown TCP connection 7 for outside:198.51.100.9/22 to '
    'inside:10.1.1.3/50000 duration 1:00:00 bytes 99 TCP Reset-O\n'
    '<164>Jan 1 00:00:04 fw01 %ASA-4-106023: Deny tcp src inside:10.1.1.2/50693 dst outside:167.71.156.88/5985 by '
    'access-group "inside_access_in" [0x0, 0x0]\n'
    '<166>Jan 1 00:00:05 fw01 %ASA-6-106100: access-list outside_in denied tcp outside/198.51.100.20(4444) -> '
    'inside/10.1.1.2(3389) hit-cnt 1 first hit [0x0, 0x0]\n'
    '<166>Jan 1 00:00:06 fw01 %ASA-6-605005: Login permitted from 10.1.1.50/51000 to inside:10.1.1.1/ssh for user '
    '"admin"\n'
    '<166>Jan 1 00:00:07 fw01 %ASA-6-305011: Built dynamic TCP translation from inside:10.1.1.2/53496 to '
    'outside:203.0.113.1/53496\n')
# EvidenceForge (https://github.com/Cisco-Talos/EvidenceForge) writes the initiator first; an inbound dmz -> inside shows
# dmz ranks lower.
ASA_EVIDENCEFORGE = (
    '<166>May 14 12:00:16 fw-bo-edge %ASA-6-302015: Built inbound UDP connection 1 for dmz:10.44.30.10/34959 '
    '(10.44.30.10/34959) to inside:10.44.20.10/53 (10.44.20.10/53)\n'
    '<166>May 14 12:00:17 fw-bo-edge %ASA-6-302015: Built outbound UDP connection 2 for dmz:10.44.30.10/58116 '
    '(45.83.220.5/58116) to outside:20.205.76.77/3478 (20.205.76.77/3478)\n'
    '<166>May 14 12:00:18 fw-bo-edge %ASA-6-302013: Built outbound TCP connection 3 for inside:10.44.20.30/58930 '
    '(45.83.220.1/42895) to dmz:10.44.30.10/443 (10.44.30.10/443)\n'
    '<166>May 14 12:36:55 fw-bo-edge %ASA-6-302020: Built outbound ICMP connection for faddr 10.44.30.10/8 gaddr '
    '10.44.20.20/0 laddr 10.44.20.20/0\n'
    '<166>May 14 12:36:55 fw-bo-edge %ASA-6-302021: Teardown ICMP connection for faddr 10.44.30.10/8 gaddr '
    '10.44.20.20/0 laddr 10.44.20.20/0\n')


def parse(layout, text):
    p = LAYOUTS[layout].parser()
    return [p(line) for line in text.splitlines()]


SLOW_S = 0.5   # a 64 KB line takes milliseconds; a backtracking pattern takes minutes to hours


def seconds(read, *args):
    """The thread's CPU time, which a backtracking pattern spends. Wall time also counts the waits for a CPU among the
    suite's parallel workers: a 64 KB line that takes 25 ms took 0.52 s with two suites running on 16 threads."""
    t0 = time.thread_time()
    read(*args)
    return time.thread_time() - t0


def hostile_lines(n):
    """Lines that make a backtracking pattern try each way to split a long run: each layout's sample line cut at each
    space and given a run of n spaces or letters, and a sudo line."""
    samples = [text.splitlines()[0] for text in (ASA_CISCO, SNORT, APACHE, APACHE_ERROR, SYSLOG, STAMPED)]
    for line in [*samples, SYSLOG.splitlines()[2]]:
        for i in (i for i, c in enumerate(line) if c == " "):
            for filler in " a":
                yield line[:i] + filler * n + "\x00"
    yield "May 14 12:02:00 WEB-01 sudo: nina : " + "; PWD=" * (n // 6) + "x"


def test_no_pattern_backtracks_for_long_on_a_crafted_line():
    """Overlapping quantifiers would make matching time grow with the cube of a run of spaces: a fast alert line of 8 KB
    would hold intake for 445 s, and a time value of 2 KB would take 21.9 s. A sudo line and a key=value word would grow
    with the square of their length. Every layout reads every hostile line, and the time patterns and
    key=value pairs read theirs, at up to 64 KB, the shorter lines first so that a slow pattern fails within seconds."""
    readers = {name: layout.parser() for name, layout in LAYOUTS.items()}
    for n in (1 << 10, 1 << 12, 1 << 14, 1 << 16):
        for line in hostile_lines(n):
            for name, read in readers.items():
                assert seconds(read, line) < SLOW_S, (name, n, line[:60])
        for text in (f"2020-01-01{' ' * n}x", f"2020-01-01 10:00:00{' ' * n}x", f"1/2/2020 10:00{' ' * n}PM x"):
            assert seconds(DATE_TIME.match, text) < SLOW_S, (n, text[:20])
            assert seconds(guess_time_format, [text]) < SLOW_S, (n, text[:20])
        for pattern in (KV_PAIR, KV_PAIR_COMMA):
            assert seconds(pattern.findall, "srcip=1.2.3.4 " + "a" * n) < SLOW_S, (pattern.pattern, n)
    # The fast alert file as intake reads it: its first 8 KB, tested against every layout
    alert = "01/01-00:00:00.000 [**] [1:1:1] " + " " * 8192
    assert seconds(identify_bytes, "notes.txt", alert.encode()) < SLOW_S


def test_possessive_patterns_read_lines_as_before(tmp_path):
    """The possessive patterns give the groups that backtracking ones give. A fast alert with an empty signature
    still fits; one whose signature itself holds [**], which no rule writes, does not."""
    kv = tmp_path / "kv.log"
    kv.write_text("<5>fw 12a=1 b=2\n", newline="\n")   # a key=value match can start at the digits before its key
    assert dict(records(kv, {"format": "kv"}))["1"] == {"syslog_header": "<5>fw 12", "a": "1", "b": "2"}
    sudo = parse("syslog", "May 14 12:02:00 WEB-01 sudo: nina : TTY=pts/0 ; PWD=/a;b ; USER=root ; ENV=A=1 ; "
                           "USER=root ; COMMAND=/bin/ls ; USER=x\n")[0]
    assert (sudo["user"], sudo["pwd"], sudo["as_user"], sudo["command"]) == (
        "nina", "/a;b ; USER=root ; ENV=A=1", "root", "/bin/ls ; USER=x")   # the first USER= that COMMAND= follows
    empty, inner = parse("snort_fast", "01/02-10:00:00.000 [**] [1:2:3]  [**] {TCP} 10.0.0.1:1 -> 10.0.0.2:2\n"
                                       "01/02-10:00:00.000 [**] [1:2:3] a [**] b [**] {TCP} 10.0.0.1:1 -> 10.0.0.2:2\n")
    assert (empty["signature"], empty["rule"], empty["dst"]) == ("", "1:2:3", "10.0.0.2:2") and inner is None
    assert DATE_TIME.match("2020-01-02  T 10:11:12,5 p.m.  +0130").groups() == (
        "2020", "01", "02", "10", "11", "12", "5", "p.m.", "+0130")
    assert [m.groups() for m in KV_PAIR.finditer('9ab=1 x.y-z="q \\" r" -k=')] == [
        ("ab", "1"), ("x.y-z", '"q \\" r"'), ("k", "")]


def test_each_layout_is_identified_by_its_first_lines():
    for name, text, layout in (("access.log", APACHE, "apache_access"), ("error.log", APACHE_ERROR, "apache_error"),
                               ("syslog", SYSLOG, "syslog"), ("alert", SNORT, "snort_fast"),
                               ("asa.log", ASA_CISCO, "cisco_asa"), ("mysql_error.log", STAMPED, "timestamped")):
        ident = identify_bytes(name, text.encode())
        assert (ident.artifact, ident.detail) == ("line_log", LAYOUTS[layout].label), name
    # UFW lines carry KEY=value pairs but are syslog; key=value logs and CSVs that start with a time stay as they were.
    ufw = SYSLOG.splitlines()[0] + "\n"
    assert identify_bytes("syslog.log", (ufw * 3).encode()).detail == "Syslog"
    forti = 'date=2023-05-25 time=00:45:16 devname="FGT" devid="F1" logid="0000000013" type="traffic"\n' * 3
    assert identify_bytes("forti.log", forti.encode()).artifact == "kv_log"
    assert identify_bytes("export.csv", b"2024-01-01 10:00:00,alice,logon\n2024-01-01 10:00:01,bob,logoff\n").artifact == "csv"


def test_every_layout_has_a_ready_made_mapping_of_the_same_name():
    # The Import page's Layout menu loads the ready-made mapping named after the layout.
    for name, layout in LAYOUTS.items():
        assert PRESETS[name]["layout"] == name and PRESETS[name]["match"]["detail"] == layout.label
        missing = {c for c in PRESETS[name]["fields"].values() if c not in layout.columns}
        assert not missing, (name, missing)


def test_apache_access_requests_users_and_proxy_extras():
    login, proxy, tls = parse("apache_access", APACHE)
    assert (login["method"], login["url"], login["protocol"], login["user"], login["status"]) == (
        "GET", "/login.php?u=a", "HTTP/1.1", "alice", "200")
    assert (proxy["method"], proxy["url"], proxy["cs_bytes"], proxy["proxy_action"]) == (
        "CONNECT", "example.com:443", "434", "tunnel")
    assert (tls["method"], tls["url"], tls["referer"]) == ("", "\\x16\\x03\\x01", "")
    first, second, continuation = parse("apache_error", APACHE_ERROR)
    assert (first["module"], first["level"], first["pid"]) == ("ssl", "warn", "3744")
    assert (second["level"], second["client"]) == ("error", "203.0.113.9") and continuation is None


def test_syslog_layouts_and_the_fields_read_from_messages():
    ufw, sshd, sudo, session, failed = parse("syslog", SYSLOG)
    assert (ufw["hostname"], ufw["app"], ufw["facility"], ufw["severity"], ufw["procid"]) == (
        "WEB-01", "kernel", "kern", "notice", "")
    assert (ufw["action"], ufw["src_ip"], ufw["src_port"], ufw["dst_ip"], ufw["dst_port"], ufw["proto"]) == (
        "BLOCK", "45.33.63.235", "63730", "10.44.30.10", "80", "TCP")
    assert (sshd["time"], sshd["action"], sshd["auth"], sshd["user"], sshd["src_ip"], sshd["src_port"]) == (
        "2024-05-14T12:01:00.000000+00:00", "Accepted", "publickey", "nina", "10.44.10.21", "50122")
    assert (sudo["user"], sudo["as_user"], sudo["command"], sudo["facility"]) == ("nina", "root", "/usr/bin/id", "authpriv")
    assert (session["time"], session["action"], session["user"]) == ("May 14 12:03:00", "session closed", "nina")
    assert (failed["action"], failed["user"], failed["src_ip"]) == ("Failed", "admin", "185.220.1.2")


def test_cisco_asa_sources_follow_the_direction_in_either_order():
    built, teardown, unknown, deny, acl, login, nat = parse("cisco_asa", ASA_CISCO)
    assert (built["hostname"], built["msgid"], built["direction"]) == ("fw01", "302013", "outbound")
    assert (built["src_ip"], built["src_port"], built["dst_ip"], built["dst_port"]) == ("10.1.1.2", "53496",
                                                                                       "93.184.216.34", "443")
    assert (teardown["src_ip"], teardown["dst_ip"], teardown["bytes"], teardown["reason"]) == (
        "10.1.1.2", "93.184.216.34", "4321", "TCP FINs")
    assert unknown["direction"].startswith("unknown") and unknown["src_ip"] == "198.51.100.9"   # as written
    assert (deny["action"], deny["src_ip"], deny["dst_port"], deny["acl"]) == ("Deny", "10.1.1.2", "5985",
                                                                               "inside_access_in")
    assert (acl["action"], acl["src_ip"], acl["dst_ip"], acl["dst_port"]) == ("denied", "198.51.100.20", "10.1.1.2",
                                                                              "3389")
    assert (login["src_ip"], login["dst_ip"], login["user"]) == ("10.1.1.50", "10.1.1.1", "admin")
    assert (nat["src_ip"], nat["nat_ip"], nat["nat_port"]) == ("10.1.1.2", "203.0.113.1", "53496")

    inbound, to_outside, to_dmz, icmp, icmp_down = parse("cisco_asa", ASA_EVIDENCEFORGE)
    assert (inbound["src_ip"], inbound["dst_ip"]) == ("10.44.30.10", "10.44.20.10")
    assert (to_outside["src_ip"], to_outside["dst_ip"]) == ("10.44.30.10", "20.205.76.77")
    assert (to_dmz["src_ip"], to_dmz["dst_ip"]) == ("10.44.20.30", "10.44.30.10")   # inside ranks above dmz
    assert (icmp["src_ip"], icmp["dst_ip"], icmp_down["direction"]) == ("10.44.20.20", "10.44.30.10", "outbound")


def test_snort_and_suricata_alerts():
    nikto, ping = parse("snort_fast", SNORT)
    assert (nikto["rule"], nikto["classification"], nikto["priority"], nikto["proto"]) == (
        "1:2002677:14", "web-application-attack", "2", "TCP")
    assert (nikto["src"], nikto["dst"], ping["time"]) == ("185.199.110.42:51750", "45.83.220.5:80",
                                                          "05/14/2024-12:56:00.000001")


def test_times_without_a_year_are_guessed_but_never_read_as_1900():
    assert guess_time_format(["May 14 12:00:16", "May  4 12:00:17"]).format == "%b %d %H:%M:%S"
    assert guess_time_format(["Feb 29 23:59:59"]).format == "%b %d %H:%M:%S"   # tried in a leap year
    assert guess_time_format(["05/14-12:37:59.652770"]).format == "%m/%d-%H:%M:%S.%f"
    assert guess_time_format(["05/14/2024-12:56:00.000001"]).format == "%m/%d/%Y-%H:%M:%S.%f"
    assert guess_time_format(["May 14 2024 12:00:16"]).format == "%b %d %Y %H:%M:%S"


@pytest.fixture
def case(tmp_path):
    ev = tmp_path / "evidence"
    error_24 = APACHE_ERROR.replace("14:44:02 2015] [error]", "14:44:02.000001 2015] [core:error]")   # one style
    for folder, name, text in (("WEB01", "access.log", APACHE), ("WEB01", "error.log", error_24),
                               ("WEB01", "syslog", SYSLOG_BSD),
                               ("IDS", "alert", SNORT.splitlines()[0] + "\n" + SNORT.splitlines()[0].replace(
                                   "12:55:09", "12:55:10") + "\n"),   # Snort's year-less times only
                               ("FW", "asa.log", ASA_CISCO), ("DB01", "mysql_error.log", STAMPED)):
        (ev / folder).mkdir(parents=True, exist_ok=True)
        (ev / folder / name).write_text(text, newline="\n")
    c = create_case(tmp_path / "case", "Lines", ev, "cody")
    intake(c)
    return c


def test_each_layout_imports_as_a_run_that_rebuild_repeats(case):
    listed = {f["path"]: f["detail"] for f in importable(case)}
    assert listed["FW/asa.log"] == "Cisco ASA" and listed["DB01/mysql_error.log"] == "Lines that start with a date and time"
    counts = {}
    for path in listed:
        p = preview(case, path, year_hint=2023)
        mapping = {**p["mapping"], "time": {**p["mapping"]["time"], "zone": p["mapping"]["time"]["zone"] or "UTC"}}
        record = run_import(case, path, mapping, zones={})
        assert record.status == "ok" and record.evidence_check == "ok", (path, record.reason)
        counts[path] = record.loaded_rows
    assert counts == {"WEB01/access.log": 3, "WEB01/error.log": 2, "WEB01/syslog": 4, "IDS/alert": 2, "FW/asa.log": 7,
                      "DB01/mysql_error.log": 6}
    con = connect(case.db_path)
    row = lambda where: con.execute(f"SELECT ts_us, source_ip, source_port, dest_ip, dest_port, user_name, user_domain, "
                                    f"event_code, message, artifact FROM events WHERE {where}").fetchone()
    login = row("source_file = 'WEB01/access.log' AND user_name = 'alice'")
    assert login[0] == 1715713462 * US and login[1] == "203.0.113.9" and login[7] == "200"   # -0700 to UTC
    assert login[8] == "GET /login.php?u=a 200 512 bytes user alice curl/8.0" and login[9] == "web_access"
    assert row("source_file = 'WEB01/access.log' AND user_name = 'bob'")[6] == "CORP"
    built = row("source_file = 'FW/asa.log' AND event_code = '302013'")
    assert built[1:5] == ("10.1.1.2", "53496", "93.184.216.34", "443")
    assert built[8].startswith("%ASA-6-302013: Built outbound TCP connection 9")
    # Year-less times: the first reads as the year given, and the next year begins at January.
    times = [t for (t,) in con.execute("SELECT ts_us FROM events WHERE source_file = 'FW/asa.log' ORDER BY ts_us").fetchall()]
    assert times[0] == 1704067198 * US and times[1] == 1704067202 * US   # 2023-12-31 23:59:58, 2024-01-01 00:00:02
    sshd = row("source_file = 'WEB01/syslog' AND event_code = 'Accepted'")
    assert sshd[1:3] == ("10.44.10.21", "50122") and sshd[5] == "nina" and sshd[8].startswith("sshd: Accepted")
    nikto = row("source_file = 'IDS/alert' AND event_code = '1:2002677:14'")
    assert nikto[1:5] == ("185.199.110.42", "51750", "45.83.220.5", "80") and nikto[9] == "ids_alert"
    total = con.execute("SELECT count(*) FROM events").fetchone()[0]
    con.close()
    assert total == sum(counts.values()) and len(rebuild(case)) == len(counts)
    con = connect(case.db_path)
    assert con.execute("SELECT count(*) FROM events").fetchone()[0] == total   # read again the same way, year and all
    con.close()


def test_a_missing_year_blocks_the_import_until_given(case):
    p = preview(case, "FW/asa.log")   # a case without events suggests no year
    assert p["needs_year"] and "year" not in p["mapping"]["time"]
    assert any("no year" in problem for problem in p["problems"])
    p = preview(case, "FW/asa.log", {**p["mapping"], "time": {**p["mapping"]["time"], "year": 2023, "zone": "UTC"}})
    assert not p["problems"] and any("first reads as 2023" in w for w in p["warnings"])


def test_text_logs_taken_in_as_key_value_lines_are_listed_by_layout(case):
    # Before line layouts, intake took UFW syslog for key=value lines; the Import page reads them again.
    manifest = case.manifest_path
    rows = [json.loads(line) for line in manifest.read_text(encoding="utf-8").splitlines()]
    for r in rows:
        if r["path"] == "WEB01/syslog":
            r["artifact"], r["detail"] = "kv_log", "key=value"
    manifest.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    assert {f["path"]: f["detail"] for f in importable(case)}["WEB01/syslog"] == "Syslog"
