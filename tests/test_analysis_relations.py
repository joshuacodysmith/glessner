import pytest
from conftest import SEC, T0, links_in, registry

from glessner.analysis import RoleEvidence, build_identity, build_tables, guess_role, host_os, role_evidence
from glessner.events import connect, load
from glessner.journal import Journal
from glessner.queries import lanes, parse_groupby, related, view
from glessner.relations import outside_sources

CURRENT_VERSION = "Microsoft\\Windows NT\\CurrentVersion"
CSI_ROOT = "CsiTool-CreateHive-{00000000-0000-0000-0000-000000000000}"   # the root key name RECmd gave DC01's hive
# The Szechuan hosts' values as RECmd's System Info (Current) rows hold them.
SERVER_2012_R2 = {"ProductName": "Windows Server 2012 R2 Standard Evaluation", "EditionID": "ServerStandardEval",
                  "InstallationType": "Server", "CurrentBuild": "9600", "CurrentBuildNumber": "9600",
                  "InstallDate": "2020-09-17 16:43:59.0000000"}
WINDOWS_10 = {"ProductName": "Windows 10 Enterprise Evaluation", "EditionID": "EnterpriseEval", "InstallationType": "Client",
              "CurrentBuild": "19041", "CurrentBuildNumber": "19041", "UBR": "264", "ReleaseId": "2004",
              "InstallDate": "2020-09-18 05:47:03.0000000"}


def open_case(case):
    journal = Journal(case)
    con = connect(case.db_path)
    identity = build_identity(con, journal.state)
    build_tables(con, journal.state, identity)
    return con, journal, identity


def add_os(case, host, root, values, hive="Windows/System32/config/SOFTWARE", key=CURRENT_VERSION):
    load(case.db_path, [registry(f"{host}/{hive}", f"{root}\\{key}", name, value) for name, value in values.items()],
         host=host, tool="recmd", tool_version="t", run_id=f"os-{host}", replaces_sources=[], staging_dir=case.folder)


def test_identity_from_registry_and_evtx(synthetic_case):
    _, _, identity = open_case(synthetic_case)
    dc, ws = identity.hosts["DC01"], identity.hosts["DESKTOP"]
    assert dc.names == ["CITADEL-DC01"] and dc.ips == ["10.42.85.10"] and dc.role == "Domain controllers"
    assert ws.names == ["DESKTOP-SDN1RPT"] and ws.ips == ["10.42.85.115"] and ws.role == "Workstations"
    assert identity.resolve_name("citadel-dc01.c137.local") == "DC01"
    assert identity.resolve_ip("10.42.85.115") == "DESKTOP"


def test_analyst_role_and_ip_edits_apply(synthetic_case):
    journal = Journal(synthetic_case)
    journal.append("host_role", host="DESKTOP", role="Servers")
    journal.append("host_identity", host="DESKTOP", op="add_ip", value="10.42.85.200")
    _, _, identity = open_case(synthetic_case)
    assert identity.hosts["DESKTOP"].role == "Servers" and identity.hosts["DESKTOP"].role_source == "analyst"
    assert identity.resolve_ip("10.42.85.200") == "DESKTOP"


def test_guess_role():
    assert guess_role(["DC01"]) == ("Domain controllers", "The name DC01 contains DC")
    assert guess_role(["X", "CITADEL-DC01"])[0] == "Domain controllers"
    assert guess_role(["FILESRV2"])[0] == "Servers"
    assert guess_role(["DESKTOP-SDN1RPT"]) == ("Workstations", "Nothing points to a server or domain controller")
    assert guess_role(["DCOMSERVICE"])[0] == "Workstations"   # "DC" inside a word is not a domain controller


def test_guess_role_prefers_evidence_over_names():
    # Windows' own record of the machine type beats a misleading name.
    assert guess_role(["DC-LOOKALIKE"], RoleEvidence(product_type="WinNT")) == (
        "Workstations", "The SYSTEM hive records its product type as WinNT")
    assert guess_role(["APP7"], RoleEvidence(product_type="LanmanNT"))[0] == "Domain controllers"
    role, reason = guess_role(["HOST7"], RoleEvidence(kerberos_tgt=62))
    assert role == "Domain controllers" and "62 Kerberos ticket requests" in reason
    assert guess_role(["HOST7"], RoleEvidence(product_name="Windows Server 2019 Standard"))[0] == "Servers"


def test_role_evidence_from_registry_and_security_log(synthetic_case):
    path = "ROOT\\ControlSet001\\Control\\ProductOptions"
    load(synthetic_case.db_path, [registry("DESKTOP/Windows/System32/config/SYSTEM", path, "ProductType", "ServerNT")],
         host="DESKTOP", tool="recmd", tool_version="t", run_id="r9", replaces_sources=[], staging_dir=synthetic_case.folder)
    _, _, identity = open_case(synthetic_case)
    ws = identity.hosts["DESKTOP"]
    assert (ws.role, ws.role_source, ws.guessed_role) == ("Servers", "guess", "Servers")
    assert ws.role_reason == "The SYSTEM hive records its product type as ServerNT"


def test_host_os_from_the_software_hive(synthetic_case):
    """Each host's release, under either root key name RECmd gives a hive, with and without UBR and ReleaseId."""
    add_os(synthetic_case, "DC01", CSI_ROOT, SERVER_2012_R2)
    add_os(synthetic_case, "DESKTOP", "ROOT", WINDOWS_10)
    # A RegBack copy and the 32-bit view hold other values; neither mixes into the host's own key.
    add_os(synthetic_case, "DESKTOP", "ROOT", {"ProductName": "Windows 10 Pro", "UBR": "1"},
           hive="Windows/System32/config/RegBack/SOFTWARE")
    add_os(synthetic_case, "DESKTOP", "ROOT", {"ProductName": "Windows 10 Pro", "DisplayVersion": "22H2"},
           key="Wow6432Node\\" + CURRENT_VERSION)
    con, _, identity = open_case(synthetic_case)
    systems = host_os(con)
    assert systems["DC01"] == {
        "product": "Windows Server 2012 R2 Standard Evaluation", "edition": "ServerStandardEval",
        "installation_type": "Server", "build": "9600", "version": "", "install_date": "2020-09-17 16:43:59.0000000",
        "source": "SOFTWARE hive DC01/Windows/System32/config/SOFTWARE, key Microsoft\\Windows NT\\CurrentVersion",
        "display": "Windows Server 2012 R2 Standard Evaluation, build 9600"}
    ws = systems["DESKTOP"]
    assert (ws["product"], ws["edition"], ws["build"], ws["version"]) == (
        "Windows 10 Enterprise Evaluation", "EnterpriseEval", "19041.264", "2004")
    assert ws["display"] == "Windows 10 Enterprise Evaluation, version 2004, build 19041.264"
    assert identity.hosts["DESKTOP"].os == ws and identity.hosts["DC01"].os == systems["DC01"]
    # The role's product name comes from the same reader.
    assert role_evidence(con)["DESKTOP"].product_name == "Windows 10 Enterprise Evaluation"
    assert identity.hosts["DC01"].role_reason == "Its product name is Windows Server 2012 R2 Standard Evaluation"


def test_host_os_reads_the_live_hive_over_a_windows_old_copy(synthetic_case):
    """RECmd reads every hive under a host's folder, Windows.old's too. The live hive wins where a copy's path sorts
    first and its root key name is the shorter, and where the live hive sits deeper than the copies."""
    win11 = {"ProductName": "Windows 10 Pro", "InstallationType": "Client", "CurrentBuildNumber": "22631", "UBR": "4317",
             "DisplayVersion": "23H2"}
    win10 = {"ProductName": "Windows 10 Pro", "InstallationType": "Client", "CurrentBuildNumber": "19045", "UBR": "3803",
             "DisplayVersion": "22H2"}
    add_os(synthetic_case, "DESKTOP", CSI_ROOT, win11)
    add_os(synthetic_case, "DESKTOP", "ROOT", win10, hive="Windows.old/Windows/System32/config/SOFTWARE")   # '.' before '/'
    add_os(synthetic_case, "DESKTOP", "ROOT", win10, hive="Backup/Windows/System32/config/SOFTWARE")   # 'B' before 'W'
    # Both copies' paths are shorter than the live hive's, so only the Windows.old check, for either name, sets them back.
    add_os(synthetic_case, "LAPTOP", "ROOT", win11, hive="image_export/volume_c/Windows/System32/config/SOFTWARE")
    add_os(synthetic_case, "LAPTOP", "ROOT", win10, hive="Windows.old/Windows/System32/config/SOFTWARE")
    add_os(synthetic_case, "LAPTOP", "ROOT", win10, hive="Windows.old.000/Windows/System32/config/SOFTWARE")
    con, _, _ = open_case(synthetic_case)
    systems = host_os(con)
    for host in ("DESKTOP", "LAPTOP"):
        assert systems[host]["display"] == "Windows 11 Pro, version 23H2, build 22631.4317"
    # The source names the hive file read, so the analyst can tell the live hive from a copy.
    assert systems["DESKTOP"]["source"] == (
        "SOFTWARE hive DESKTOP/Windows/System32/config/SOFTWARE, key Microsoft\\Windows NT\\CurrentVersion")
    assert systems["LAPTOP"]["source"].startswith("SOFTWARE hive LAPTOP/image_export/volume_c/Windows/System32/")


def test_host_os_display_for_windows_11_and_service_packs(synthetic_case):
    """Windows 11 still records ProductName as Windows 10. A client build of 22000 or later shows as Windows 11, and
    the product keeps the registry's name; a server's name is left alone. A service pack shows without "version"."""
    add_os(synthetic_case, "DESKTOP", "ROOT", {"ProductName": "Windows 10 Pro", "EditionID": "Professional",
                                               "InstallationType": "Client", "CurrentBuildNumber": "22631", "UBR": "4317",
                                               "DisplayVersion": "23H2", "ReleaseId": "2009"})
    add_os(synthetic_case, "DC01", "ROOT", {"ProductName": "Windows Server 2025 Standard", "InstallationType": "Server",
                                            "CurrentBuildNumber": "26100", "DisplayVersion": "24H2"})
    add_os(synthetic_case, "WIN7", "ROOT", {"ProductName": "Windows 7 Professional", "InstallationType": "Client",
                                            "CurrentBuildNumber": "7601", "CSDVersion": "Service Pack 1"})
    con, _, _ = open_case(synthetic_case)
    systems = host_os(con)
    ws = systems["DESKTOP"]
    assert ws["display"] == "Windows 11 Pro, version 23H2, build 22631.4317"
    assert (ws["product"], ws["version"]) == ("Windows 10 Pro", "23H2")
    assert systems["DC01"]["display"] == "Windows Server 2025 Standard, version 24H2, build 26100"
    assert (systems["WIN7"]["display"], systems["WIN7"]["version"]) == (
        "Windows 7 Professional, Service Pack 1, build 7601", "Service Pack 1")


@pytest.mark.parametrize("number", ["²", "2" * 5000], ids=["superscript", "5000 digits"])
def test_a_build_number_in_other_digits_is_shown_as_written(synthetic_case, number):
    """A client's CurrentBuildNumber written in digits int() refuses, such as "²" or more than 4,300 digits, doesn't
    stop the case opening, though every open reads the host's release."""
    add_os(synthetic_case, "DESKTOP", "ROOT", {"ProductName": "Windows 10 Pro", "InstallationType": "Client",
                                               "CurrentBuildNumber": number})
    _, _, identity = open_case(synthetic_case)
    assert identity.hosts["DESKTOP"].os["display"] == f"Windows 10 Pro, build {number}"


def test_review_until_confirmed_and_for_claimed_ips(synthetic_case):
    _, _, identity = open_case(synthetic_case)
    assert identity.hosts["DC01"].review == ["Role not confirmed"]
    journal = Journal(synthetic_case)
    journal.append("host_role", host="DC01", role="Domain controllers", confirmed=True)
    journal.append("host_identity", host="DESKTOP", op="add_ip", value="10.42.85.10")   # DC01's IP, claimed twice
    _, _, identity = open_case(synthetic_case)
    dc = identity.hosts["DC01"]
    assert (dc.role_source, dc.role_by) == ("analyst", "cody") and dc.role_at
    assert dc.review == ["10.42.85.10 is also claimed by DESKTOP"]
    assert identity.hosts["DESKTOP"].review == ["Role not confirmed", "10.42.85.10 is also claimed by DC01"]
    assert "10.42.85.10" in identity.conflicts and identity.resolve_ip("10.42.85.10") is None


def test_logon_links_resolve_by_ip_first(synthetic_case):
    con, _, _ = open_case(synthetic_case)
    links = links_in(con, T0 - SEC, T0 + 3600 * SEC)
    got = [(link.source, link.target, link.kind, link.via, link.outside, link.machine) for link in links]
    assert got == [
        ("194.61.24.102", "DC01", "4624 type 10", "ip", True, False),   # not "DC01 to itself" by WorkstationName
        ("DESKTOP", "DC01", "4624 type 3", "ip", False, False),
        ("DESKTOP", "DC01", "4624 type 3", "ip", False, True),
        ("DC01", "DESKTOP", "4624 type 10", "ip", False, False),
        ("DESKTOP", "DC01", "4648 explicit credentials", "recorded host", False, False),
        ("DC01", "DESKTOP", "4624 type 3", "name", False, False),
    ]
    assert outside_sources(con) == ["194.61.24.102"]


def test_links_over_the_limit_group_per_pair_and_bucket(synthetic_case, monkeypatch):
    """More links than LINK_LIMIT are grouped in SQL by source, target, and density bucket."""
    from conftest import logon

    from glessner import queries

    archive = "DC01/Windows/System32/winevt/Logs/Archive-Security.evtx"
    start = T0 + 1000 * SEC
    near = [logon(start + i * SEC, 300 + i, archive, user=f"user{5 - i}", ltype="3", ip="10.42.85.115") for i in range(6)]
    far = [logon(start + 19 * SEC, 320 + i, archive, user="a", ltype="3", ip="10.42.85.115") for i in range(3)]
    load(synthetic_case.db_path, [*near, *far, logon(start + 2 * SEC, 330, archive, ip="1.2.3.4")], host="DC01",
         tool="evtxecmd", tool_version="t", run_id="r8", replaces_sources=[archive], staging_dir=synthetic_case.folder)
    con, _, identity = open_case(synthetic_case)
    keys = parse_groupby("host")
    links = queries.view_links(con, identity, keys, start, start + 20 * SEC, 10 * SEC, False)
    assert links["mode"] == "individual" and len(links["items"]) == 10
    assert all(link["target_keys"] == ["DC01"] for link in links["items"])
    monkeypatch.setattr(queries, "LINK_LIMIT", 2)
    groups = queries.view_links(con, identity, keys, start, start + 20 * SEC, 10 * SEC, False)
    assert groups["mode"] == "grouped"
    got = [(g["source"], g["count"], g["ts"], g["kinds"], g["accounts"], g["target_keys"]) for g in groups["items"]]
    # Each group sits at its middle logon, not its bucket's center, so zooming in on the arrow keeps it in view; it
    # names up to five accounts, in order.
    assert got == [("1.2.3.4", 1, start + 2 * SEC, ["4624 type 10"], ["C137\\Administrator"], ["DC01"]),
                   ("DESKTOP", 6, start + 3 * SEC, ["4624 type 3"], [f"C137\\user{i}" for i in range(5)], ["DC01"]),
                   ("DESKTOP", 3, start + 19 * SEC, ["4624 type 3"], ["C137\\a"], ["DC01"])]
    assert view(con, identity, keys, start, start + 20 * SEC, 2, 1000, False, links=False)["links"]["items"] == []


def test_fit_range_leaves_out_only_far_strays(synthetic_case):
    """A few 1980 file times or a year-3850 time don't stretch Fit case."""
    from glessner.events import Event
    from glessner.queries import fit_range

    year = 365 * 86_400 * SEC
    def ev(i, ts):
        return Event(ts_us=ts, ts_desc="$SI M...", artifact="mft", source_file="DC01/$MFT", source_record=f"r{i}",
                     message="file")
    bulk = [ev(i, T0 + i * SEC) for i in range(4000)]
    strays = [ev(-1, T0 - 40 * year), ev(-2, T0 - 40 * year), ev(-3, T0 + 1800 * year)]
    load(synthetic_case.db_path, bulk + strays, host="DC01", tool="mftecmd", tool_version="t", run_id="r9",
         replaces_sources=[], staging_dir=synthetic_case.folder)
    con, _, _ = open_case(synthetic_case)
    fit = fit_range(con)
    assert (fit["start"], fit["before"], fit["after"]) == (T0 - 3600 * SEC, 2, 1)   # the registry rows sit at T0 - 1 h
    assert fit["end"] == T0 + 3999 * SEC
    assert (fit["first"], fit["last"]) == (T0 - 40 * year, T0 + 1800 * year)


def load_link_time_strays(case) -> list[int]:
    """Three Autoruns link times, which don't set Fit case's window, so each is a stray: one in 1937, one 40 s after the
    case's last event, inside the margin Fit case draws around its window, and one in 2037. Returns their times."""
    from datetime import UTC, datetime

    from glessner.events import Event
    from glessner.parsers.autoruns import BUILT

    times = [int(datetime(1937, 10, 23, tzinfo=UTC).timestamp()) * SEC, T0 + 950 * SEC,
             int(datetime(2037, 10, 21, tzinfo=UTC).timestamp()) * SEC]
    load(case.db_path, [Event(ts, BUILT, "autoruns", "DC01/autoruns.csv", str(i), f"entry {i}") for i, ts in enumerate(times)],
         host="DC01", tool="autoruns", tool_version="found output", run_id="r9", replaces_sources=[],
         staging_dir=case.folder)
    return times


def test_the_view_counts_what_lies_outside_the_window_drawn_under_its_filter(synthetic_case):
    """The status line's "Outside this view" can't take Fit case's strays: that counts the one inside the drawn margin
    twice, and names strays the filter hides. The view counts, on request, what lies before and after the window it
    draws, under its filter, so the three add up to what the filter shows."""
    from glessner.queries import case_range, fit_range

    first, _, last = load_link_time_strays(synthetic_case)
    con, _, identity = open_case(synthetic_case)
    fit = fit_range(con)
    assert (fit["before"], fit["after"], fit["first"], fit["last"]) == (1, 2, first, last)
    pad = (fit["end"] - fit["start"]) // 50   # the 2% margin the page's Fit case draws on each side
    start, end, keys = fit["start"] - pad, fit["end"] + pad, parse_groupby("mark,role,host")
    drawn = view(con, identity, keys, start, end, 100, 1000, False, links=False, outside=True)
    assert drawn["outside"] == {"before": 1, "after": 1, "first": first, "last": last}
    assert drawn["count"] + 2 == case_range(con)[2]
    no_autoruns = " AND e.artifact <> 'autoruns'"
    hidden = view(con, identity, keys, start, end, 100, 1000, False, no_autoruns, links=False, outside=True)
    assert hidden["outside"] == {"before": 0, "after": 0, "first": None, "last": None}
    assert "outside" not in view(con, identity, keys, start, end, 100, 1000, False, links=False)


def test_view_events_density_and_machine_filter(synthetic_case):
    con, _, identity = open_case(synthetic_case)
    keys = parse_groupby("mark,role,host")
    ev = view(con, identity, keys, T0 - SEC, T0 + 3600 * SEC, 100, 1000, hide_machine=True)
    assert ev["mode"] == "events"
    assert all(e["tool"] != "hayabusa" for e in ev["events"])            # hits mark events, not lanes
    rdp = next(e for e in ev["events"] if e["ts"] == T0)
    # A high-level Hayabusa hit suggests Suspicious, which decides the lane until the analyst marks it.
    assert rdp["hit"] == 4 and rdp["keys"] == ["Suggested: suspicious", "Domain controllers", "DC01"]
    assert all("$" not in link["account"] for link in ev["links"]["items"])
    with_machine = view(con, identity, keys, T0 - SEC, T0 + 3600 * SEC, 100, 1000, hide_machine=False)
    assert len(with_machine["links"]["items"]) == len(ev["links"]["items"]) + 1
    dens = view(con, identity, keys, T0 - SEC, T0 + 3600 * SEC, 100, 1, hide_machine=True)
    assert dens["mode"] == "density" and sum(c[4] for c in dens["cells"]) == dens["count"]


def test_lanes_follow_marks(synthetic_case):
    con, journal, identity = open_case(synthetic_case)
    rdp_uid = con.execute("SELECT event_uid FROM events WHERE tool = 'evtxecmd' AND ts_us = ?", [T0]).fetchone()[0]
    journal.append("mark", targets=[rdp_uid], value="malicious")
    build_tables(con, journal.state, identity)
    assert {"keys": ["Malicious", "Domain controllers", "DC01"], "count": 1} in lanes(con, parse_groupby("mark,role,host"))


def test_related_session_and_account(synthetic_case):
    con, _, _ = open_case(synthetic_case)
    rdp_uid = con.execute("SELECT event_uid FROM events WHERE tool = 'evtxecmd' AND ts_us = ?", [T0]).fetchone()[0]
    session = related(con, rdp_uid, "session")
    assert [e["code"] for e in session["events"]] == ["4624", "4672"]
    account = related(con, rdp_uid, "account")
    assert {e["host"] for e in account["events"]} == {"DC01", "DESKTOP"}


def test_connection_pivot_and_port_filter(synthetic_case):
    """Events from one network connection share the source IP and port, so the port can be
    viewed, pivoted on, and filtered on. Synthetic events; on Szechuan the pairs are Kerberos requests and logons."""
    from glessner.events import Event
    from glessner.filters import normalize, where_sql

    log = "DC01/Windows/System32/winevt/Logs/RdpCoreTS.evtx"
    def ev(record, code, ts, port):
        return Event(ts_us=ts, ts_desc="Event Recorded", artifact="evtx", source_file=log, source_record=str(record),
                     record_id=record, message=f"{code} rdp", event_code=code, log_channel="RdpCoreTS",
                     source_ip="194.61.24.102", source_port=port)
    load(synthetic_case.db_path, [ev(1, "131", T0 - 2 * SEC, "58132"), ev(2, "131", T0 - SEC, "58140"),
                                  ev(3, "4624", T0 + SEC, "58132")],
         host="DC01", tool="evtxecmd", tool_version="t", run_id="r8", replaces_sources=[log], staging_dir=synthetic_case.folder)
    con, _, _ = open_case(synthetic_case)
    first = con.execute("SELECT event_uid FROM events WHERE source_port = '58132'").fetchone()[0]
    connection = related(con, first, "connection")
    # both events from the connection on port 58132; the other connection's port differs
    assert [(e["code"], e["ts"]) for e in connection["events"]] == [("131", T0 - 2 * SEC), ("4624", T0 + SEC)]
    by_ip = related(con, first, "source_ip")
    assert {e["code"] for e in by_ip["events"]} == {"131", "4624"}
    only_port = where_sql(normalize({"only": [{"port": "58140"}]}))
    shown = con.execute(f"SELECT count(*) FROM events e WHERE true{only_port}").fetchone()[0]
    assert shown == 1


ATTACKER = "194.61.24.102"   # the synthetic case's RDP source, as on Szechuan
DC01_LOGS = "D:\\Evidence\\case\\DC01\\Windows\\System32\\winevt\\Logs\\"


def load_inbound(case, tmp_path) -> dict[str, str]:
    """The attacker's RDP connection to DC01 as older Sysmon records it, inbound, with DC01's own address as the source
    and the attacker's as the destination, a second before the synthetic case's 4624 from the attacker. Read through
    the EvtxECmd parser, so each address is stored in the parsers' form (normalize_ip): a 4625 from
    ::ffff:194.61.24.102 stores 194.61.24.102, and an IPv6 address written in full in one event and in capitals in
    another stores fe80::bad in both. Plus a loopback connection, one address at both ends. Returns the events' IDs by
    name, with the synthetic case's RDP 4624 as "rdp"."""
    from test_parsers import EVIDENCE, EVTX_COLUMNS, security_row, sysmon_row, write_csv

    from glessner.parsers import PARSERS, ParseContext

    sysmon = {"SourceFile": DC01_LOGS + "Microsoft-Windows-Sysmon%4Operational.evtx", "Computer": "CITADEL-DC01.C137.local"}
    security = {"SourceFile": DC01_LOGS + "Security-Archive.evtx", "Computer": "CITADEL-DC01.C137.local"}
    at = lambda clock: {"TimeCreated": f"2020-09-19 {clock}.0000000"}
    write_csv(tmp_path / "evtxecmd.csv", EVTX_COLUMNS, [
        sysmon_row(1, 3, "Network connection", {"Image": "C:\\Windows\\System32\\svchost.exe", "Initiated": "false",
                                                "SourceIp": "10.42.85.10", "SourcePort": "3389",
                                                "DestinationIp": ATTACKER, "DestinationPort": "58132"},
                   **sysmon, **at("03:21:47")),
        security_row(2, 4625, "Failed logon", {"TargetUserName": "admin", "LogonType": "3",
                                               "IpAddress": f"::ffff:{ATTACKER}", "IpPort": "58140"},
                     **security, **at("03:21:50")),
        sysmon_row(3, 3, "Network connection", {"Initiated": "true", "SourceIp": "127.0.0.1", "SourcePort": "49800",
                                                "DestinationIp": "127.0.0.1", "DestinationPort": "445"},
                   **sysmon, **at("03:22:00")),
        sysmon_row(4, 3, "Network connection", {"Initiated": "false", "SourceIp": "fe80::10", "SourcePort": "445",
                                                "DestinationIp": "fe80:0:0:0:0:0:0:bad", "DestinationPort": "52000"},
                   **sysmon, **at("03:22:10")),
        security_row(5, 4624, "Successful logon", {"TargetUserName": "admin", "TargetDomainName": "C137", "LogonType": "3",
                                                   "IpAddress": "FE80::BAD", "IpPort": "52000"}, **security, **at("03:22:11")),
    ])
    events = list(PARSERS["evtxecmd_csv"](ParseContext(tmp_path, EVIDENCE)))
    load(case.db_path, events, host="DC01", tool="evtxecmd", tool_version="t", run_id="inbound", replaces_sources=[],
         staging_dir=case.folder)
    con = connect(case.db_path, read_only=True)
    try:
        uids = {name: con.execute("SELECT event_uid FROM events WHERE source_file LIKE ? AND record_id = ?",
                                  [f"%{log}", record]).fetchone()[0]
                for name, log, record in (("inbound", "Sysmon%4Operational.evtx", 1), ("failed", "Security-Archive.evtx", 2),
                                          ("loopback", "Sysmon%4Operational.evtx", 3), ("ipv6_in", "Sysmon%4Operational.evtx", 4),
                                          ("ipv6_logon", "Security-Archive.evtx", 5))}
        uids["rdp"] = con.execute("SELECT event_uid FROM events WHERE tool = 'evtxecmd' AND ts_us = ?", [T0]).fetchone()[0]
    finally:
        con.close()
    return uids


def test_ip_pivot_at_either_end(synthetic_case, tmp_path, monkeypatch):
    """From the inbound Sysmon 3, Same source IP finds DC01's own address, and from the attacker's 4624 it
    never reaches the Sysmon 3. Same IP at either end joins them both ways, and says which end the address was on."""
    from glessner import queries
    from glessner.queries import QueryError

    uids = load_inbound(synthetic_case, tmp_path)
    con, _, _ = open_case(synthetic_case)
    ends = lambda res: {e["uid"]: e["end"] for e in res["events"]}
    inbound, rdp = uids["inbound"], uids["rdp"]
    # Unchanged: same source IP reads the recorded source.
    assert related(con, inbound, "source_ip")["anchor"] == {"source_ip": "10.42.85.10"}
    assert rdp not in {e["uid"] for e in related(con, inbound, "source_ip")["events"]}
    assert inbound not in {e["uid"] for e in related(con, rdp, "source_ip")["events"]}
    # Either end, from either event: the Sysmon 3 with the attacker as destination, the 4624 and the 4625 as source.
    expected = {inbound: "destination", rdp: "source", uids["failed"]: "source"}
    for anchor in (inbound, rdp):
        res = related(con, anchor, "addr", ip=ATTACKER)
        assert ends(res) == expected
        assert (res["label"], res["address"], res["total"], res["limited"]) == (
            f"IP {ATTACKER} at either end", ATTACKER, 3, False)
        assert [e["ts"] for e in res["events"]] == sorted(e["ts"] for e in res["events"])   # time order, with gaps
    assert related(con, inbound, "addr", ip=ATTACKER)["anchor"] == {"source_ip": "10.42.85.10", "dest_ip": ATTACKER}
    # DC01's own address from the same event: the Sysmon 3 as source, with the other events from DC01's address.
    own = ends(related(con, inbound, "addr", ip="10.42.85.10"))
    assert own[inbound] == "source" and rdp not in own and set(own.values()) == {"source"} and len(own) == 3
    # One address at both ends, and IPv6 in the parsers' form: written in full, and in capitals, they join.
    assert ends(related(con, uids["loopback"], "addr", ip="127.0.0.1")) == {uids["loopback"]: "both"}
    assert ends(related(con, uids["ipv6_logon"], "addr", ip="fe80::bad")) == {uids["ipv6_in"]: "destination",
                                                                              uids["ipv6_logon"]: "source"}
    # Only an address the event has: not another one, not none, and not another form of its own.
    for ip in ("10.42.85.115", "", f"::ffff:{ATTACKER}", "FE80::BAD"):
        with pytest.raises(QueryError, match="one of this event's addresses"):
            related(con, uids["ipv6_logon"] if ip == "FE80::BAD" else inbound, "addr", ip=ip)
    session = con.execute("SELECT event_uid FROM events WHERE event_code = '4672'").fetchone()[0]   # no address
    assert related(con, session, "addr", ip=ATTACKER) == {"label": "IP at either end", "events": [],
                                                          "note": "this event has no source_ip or dest_ip"}
    # The other pivots' results carry no end.
    assert all("end" not in e for e in related(con, inbound, "source_ip")["events"])
    # More events than the list holds: the nearest in time with their ends, and the count of all,
    # which runs the match with the address for both columns.
    monkeypatch.setattr(queries, "RELATED_LIMIT", 2)
    res = related(con, inbound, "addr", ip=ATTACKER)
    assert (res["limited"], res["total"]) == (True, 3)
    assert ends(res) == {inbound: "destination", rdp: "source"}


UNTIMED_NOTE = "this event has no time recorded, so the list has no gaps and starts at the earliest"


def load_untimed_pivots(case) -> tuple[str, str, list[str]]:
    """An untimed ShellBag on DESKTOP that shares its account, logon ID, address, port, and file with four timed 4624s,
    and a second one with none of them. The first 4624 by ID is the latest, two share a time, and they're loaded latest
    first, those two in the reverse of their IDs' order, so neither the load order, the time alone, nor the ID alone
    gives the order by time and ID. Returns the two ShellBags' IDs and the 4624s' in that order."""
    from glessner.events import Event, event_uid

    shared = {"user_name": "rick", "user_domain": "C137", "logon_id": "0x7777", "source_ip": "10.0.0.5",
              "source_port": "5000", "file_key": "c:/users/rick/loot"}
    bag = "DESKTOP/Users/rick/NTUSER.DAT"
    load(case.db_path, [Event(None, "ShellBag without a time", "shellbags", bag, "bag1", "ShellBag loot", **shared),
                        Event(None, "ShellBag without a time", "shellbags", bag, "bag2", "ShellBag other")],
         host="DESKTOP", tool="sbecmd", tool_version="t", run_id="r9", replaces_sources=[bag], staging_dir=case.folder)
    log = "DESKTOP/Windows/System32/winevt/Logs/Security.evtx"
    uid = lambda ev: event_uid("DESKTOP", ev.artifact, log, ev.source_record, ev.ts_desc)
    logons = sorted((Event(T0, "Event Recorded", "evtx", log, str(record), "4624 logon", event_code="4624", **shared)
                     for record in range(301, 305)), key=uid)
    for ev, ts in zip(logons, (T0 + 2 * SEC, T0 + SEC, T0, T0), strict=True):
        ev.ts_us = ts
    logons[2:] = reversed(logons[2:])
    load(case.db_path, logons, host="DESKTOP", tool="evtxecmd", tool_version="t", run_id="r10", replaces_sources=[],
         staging_dir=case.folder)
    by_time = [uid(ev) for ev in sorted(logons, key=lambda ev: (ev.ts_us, uid(ev)))]
    return (event_uid("DESKTOP", "shellbags", bag, "bag1", "ShellBag without a time"),
            event_uid("DESKTOP", "shellbags", bag, "bag2", "ShellBag without a time"), by_time)


def test_pivots_from_an_event_without_a_time_list_from_the_first_with_no_gap(synthetic_case, monkeypatch):
    """The pivots anchor on the event's time, but an event without one still pivots. Same IP at either end computes no
    gap for it, and the other pivots don't answer "this event has no host" and the like, since the check for an empty
    field leaves the time out. They list from the first in time order, ties by ID, with no gap; the time window, which
    needs a time, says so. From a timed event, ties at the list's limit go by ID too."""
    from glessner import queries

    untimed, bare, by_time = load_untimed_pivots(synthetic_case)
    con, _, _ = open_case(synthetic_case)
    monkeypatch.setattr(queries, "RELATED_LIMIT", 3)
    for kind, ip in (("session", ""), ("account", ""), ("source_ip", ""), ("connection", ""), ("file", ""),
                     ("addr", "10.0.0.5")):
        res = related(con, untimed, kind, ip=ip)
        assert [e["uid"] for e in res["events"]] == by_time[:3], kind
        assert [e["gap_s"] for e in res["events"]] == [None] * 3, kind
        assert (res["nearest"], res["limited"], res["total"], res["note"]) == (False, True, 4, UNTIMED_NOTE), kind
    assert related(con, untimed, "window", 60) == {"label": "same host within the time window", "events": [],
                                                   "note": "this event has no time recorded"}
    # An empty relation field is still named, with or without a time.
    assert related(con, bare, "file")["note"] == "this event has no file_key"
    assert related(con, bare, "addr", ip="10.0.0.5")["note"] == "this event has no source_ip or dest_ip"
    # From the latest 4624, the nearest three: itself, one 1 s before, and of the two 2 s before, the first by ID.
    res = related(con, by_time[3], "source_ip")
    assert [(e["uid"], e["gap_s"]) for e in res["events"]] == [(by_time[0], -2.0), (by_time[2], -1.0), (by_time[3], 0.0)]
    assert (res["nearest"], res["limited"], "note" in res) == (True, True, False)


def test_selected_events_at_one_time_and_without_one_list_in_id_order(synthetic_case):
    """The selection list, and an audit entry's, put events at one time, and events without one, last, in ID order.
    Each pair here loads in the reverse of its IDs' order, so the load order doesn't give it."""
    from glessner.events import Event, event_uid
    from glessner.server import App, api_selected

    log = "DESKTOP/Windows/System32/winevt/Logs/Security.evtx"
    uid = lambda ev: event_uid("DESKTOP", ev.artifact, log, ev.source_record, ev.ts_desc)
    pairs = [sorted((Event(ts, "Event Recorded", "evtx", log, f"{ts}-{n}", "4624 logon", event_code="4624")
                     for n in range(2)), key=uid, reverse=True) for ts in (None, T0 + 5 * SEC)]
    load(synthetic_case.db_path, [ev for pair in pairs for ev in pair], host="DESKTOP", tool="evtxecmd",
         tool_version="t", run_id="r11", replaces_sources=[], staging_dir=synthetic_case.folder)
    untimed, timed = ([uid(ev) for ev in pair] for pair in pairs)
    app = App(synthetic_case)
    try:
        res = api_selected(app, {"uid": [*untimed, *timed]})
        assert res["total"] == 4
        assert [e["uid"] for e in res["events"]] == [*sorted(timed), *sorted(untimed)]
    finally:
        app.con.close()


def test_typed_addresses_and_names_resolve_as_the_evidence_writes_them(synthetic_case):
    """An address the analyst types resolves in the form the parsers store, IPv6 and link-local ones
    too, whatever its letter case, and so does one journaled in upper case before; removing it as the Hosts panel shows
    it takes it away. A full name resolves by its first label. A 4648 whose TargetServerName is an IP links to the host
    with that IP."""
    from conftest import logon

    from glessner.analysis import _ips
    from glessner.server import App, QueryError, api_host

    archive = "DC01/Windows/System32/winevt/Logs/Archive-Security.evtx"
    load(synthetic_case.db_path, [logon(T0 + 300 * SEC, 1, archive, ltype="3", ip="2001:db8::10"),
                                  logon(T0 + 301 * SEC, 2, archive, ltype="3", ip="fe80::a1b2")],
         host="DC01", tool="evtxecmd", tool_version="t", run_id="r8", replaces_sources=[archive],
         staging_dir=synthetic_case.folder)
    archive = "DESKTOP/Windows/System32/winevt/Logs/Archive-Security.evtx"
    load(synthetic_case.db_path, [logon(T0 + 905 * SEC, 1, archive, code="4648", extra={"TargetServerName": "10.42.85.10"})],
         host="DESKTOP", tool="evtxecmd", tool_version="t", run_id="r9", replaces_sources=[archive],
         staging_dir=synthetic_case.folder)
    journal = Journal(synthetic_case)
    for op, value in (("add_ip", "2001:DB8::10"), ("add_ip", "fe80::A1B2"), ("add_name", "ws02.corp.local")):
        journal.append("host_identity", host="DESKTOP", op=op, value=value)
    con, _, identity = open_case(synthetic_case)
    desktop = identity.hosts["DESKTOP"]
    assert desktop.ips == ["10.42.85.115", "2001:db8::10", "fe80::a1b2"] and "WS02" in desktop.names
    assert identity.resolve_name("WS02.corp.local") == identity.resolve_name("10.42.85.115") == "DESKTOP"
    found = lambda start, end: [(link.source, link.target, link.kind, link.outside)   # the archive's events alone
                                for link in links_in(con, T0 + start * SEC, T0 + end * SEC)]
    assert found(300, 302) == [("DESKTOP", "DC01", "4624 type 3", False)] * 2
    assert found(905, 906) == [("DESKTOP", "DC01", "4648 explicit credentials", False)]
    con.close()
    journal.append("host_identity", host="DESKTOP", op="remove_ip", value="2001:db8::10")
    con, _, identity = open_case(synthetic_case)
    assert identity.resolve_ip("2001:db8::10") is None and "2001:db8::10" in outside_sources(con)
    con.close()
    assert _ips("::ffff:10.42.85.116 0.0.0.0 fe80::1") == ["10.42.85.116"]
    app = App(synthetic_case)
    try:
        with pytest.raises(QueryError, match="isn't an IP address"):
            api_host(app, {"host": "DESKTOP", "op": "add_ip", "value": "10.42.85"})
    finally:
        app.con.close()


FROM_DESKTOP = "id: from-desktop\nsuggest: suspicious\nwhen: {field: source_host, equals: DESKTOP}\n"


def suggested(app, source):
    return {u for (u,) in app.con.execute("SELECT event_uid FROM suggestions WHERE source = ?", [source]).fetchall()}


def test_a_host_edit_rebuilds_only_what_reads_host_identity(synthetic_case):
    """A host edit builds hosts, outside sources, and suggestions again, and an address edit the logon links too, and
    leaves the marks, hits, and tags as they are: with 200,000 marks, writing them again would take seconds on each
    edit."""
    from glessner.server import App, api_host, api_rule

    app = App(synthetic_case)
    try:
        api_rule(app, {"op": "add", "text": FROM_DESKTOP})
        rdp = app.con.execute("SELECT event_uid FROM events WHERE ts_us = ? AND event_code = '4624'", [T0]).fetchone()[0]
        assert app.outside == ["194.61.24.102"] and rdp not in suggested(app, "from-desktop")
        for table in ("marks", "hits", "tags"):   # a row no event or entry made, which a rebuild would drop
            app.con.execute(f"INSERT INTO {table} (event_uid) VALUES ('kept')")
        api_host(app, {"host": "DESKTOP", "op": "add_ip", "value": "194.61.24.102"})
        assert app.outside == [] and rdp in suggested(app, "from-desktop")
        assert [(link.source, link.outside) for link in links_in(app.con, T0, T0 + 1)] == [("DESKTOP", False)]
        for table in ("marks", "hits", "tags"):
            assert app.con.execute(f"SELECT count(*) FROM {table} WHERE event_uid = 'kept'").fetchone()[0] == 1, table
    finally:
        app.con.close()


def keep_link(con):
    """A logon link no logon made, which building logon_links again drops."""
    con.execute("INSERT INTO logon_links (event_uid) VALUES ('kept')")


def link_kept(con) -> bool:
    return con.execute("SELECT count(*) FROM logon_links WHERE event_uid = 'kept'").fetchone()[0] == 1


def test_only_a_name_or_ip_edit_builds_the_logon_links_again(synthetic_case):
    """The links read only the events and the identity's lookup, which an offset, role, or confirm edit, or an
    alignment, leaves as it was, so those keep the table, and the rule that reads source_host suggests the same
    events. Building it would take about two thirds of an offset edit's rebuild on a case of 1 million events. A
    name or IP edit builds it again: without the name CITADEL-DC01, DESKTOP's 4648 to it and DESKTOP's logon with it as
    the WorkstationName link nothing, and with the RDP source's address, DESKTOP is that logon's source."""
    from glessner.server import App, api_host, api_rule

    def links():
        return [(link.source, link.target, link.kind) for link in links_in(app.con, T0 - SEC, T0 + 3600 * SEC)]

    app = App(synthetic_case)
    try:
        api_rule(app, {"op": "add", "text": FROM_DESKTOP})
        from_desktop, before = suggested(app, "from-desktop"), links()
        assert len(from_desktop) == 3 and len(before) == 6
        keep_link(app.con)
        for edit in ({"host": "DESKTOP", "offset_seconds": 60}, {"host": "DESKTOP", "role": "Servers"},
                     {"confirm_hosts": ["DC01"]}, {"align": "capture"}):
            api_host(app, edit)
            assert link_kept(app.con) and links() == before, edit
            assert suggested(app, "from-desktop") == from_desktop, edit
        api_host(app, {"host": "DC01", "op": "remove_name", "value": "CITADEL-DC01"})
        assert not link_kept(app.con)
        assert [link for link in before if link not in links()] == [
            ("DESKTOP", "DC01", "4648 explicit credentials"), ("DC01", "DESKTOP", "4624 type 3")]
        assert len(suggested(app, "from-desktop")) == 2   # the 4648's source was DESKTOP
        keep_link(app.con)
        api_host(app, {"host": "DESKTOP", "op": "add_ip", "value": "194.61.24.102"})
        assert not link_kept(app.con) and links()[0] == ("DESKTOP", "DC01", "4624 type 10")
    finally:
        app.con.close()


def test_a_load_and_a_case_open_build_the_logon_links_again(synthetic_case):
    """A load and a case open build the logon links again, though the lookup is as it was, so a logon
    each adds, from DESKTOP's address to DC01, gets its link. A load empties the cache that holds the lookup the links
    were built from; a case open starts with an empty one, after a load the command line may have made while the case
    was closed."""
    from conftest import logon

    from glessner.server import App

    archive = "DC01/Windows/System32/winevt/Logs/Archive-Security.evtx"

    def add(record):
        load(synthetic_case.db_path, [logon(T0 + (1000 + record) * SEC, record, archive, ltype="3", ip="10.42.85.115")],
             host="DC01", tool="evtxecmd", tool_version="t", run_id=f"r-{record}", replaces_sources=[],
             staging_dir=synthetic_case.folder)

    def added(app):
        return [(link.source, link.target) for link in links_in(app.con, T0 + 1000 * SEC, T0 + 1010 * SEC)]

    app = App(synthetic_case)
    try:
        lookup = dict(app.identity.lookup)
        keep_link(app.con)
        add(1)
        app.refresh_identity(events_changed=True)   # as a job's after() and an import do
        assert app.identity.lookup == lookup
        assert not link_kept(app.con) and added(app) == [("DESKTOP", "DC01")]
        keep_link(app.con)
    finally:
        app.con.close()
    add(2)
    app = App(synthetic_case)
    try:
        assert app.identity.lookup == lookup
        assert not link_kept(app.con) and added(app) == [("DESKTOP", "DC01")] * 2
    finally:
        app.con.close()


def test_a_failed_rebuild_builds_the_logon_links_again_at_the_next_edit(synthetic_case, monkeypatch):
    """An IP edit's rebuild fails after the logon links, and the rollback takes them back. The cache that held the
    lookup they were built from is emptied with it, so the next offset edit builds them for the new address. Were it
    kept, the lookup would match the edit's, and the links would stay as they were before it."""
    from glessner import analysis
    from glessner.server import App, api_host

    def partway(*args, **kwargs):   # after hosts, the logon links, and the clock check
        raise RuntimeError("partway")

    def rdp():
        return [(link.source, link.outside) for link in links_in(app.con, T0, T0 + 1)]

    app = App(synthetic_case)
    try:
        with monkeypatch.context() as m:
            m.setattr(analysis, "build_suggestions", partway)
            with pytest.raises(RuntimeError, match="partway"):
                api_host(app, {"host": "DESKTOP", "op": "add_ip", "value": "194.61.24.102"})
        assert rdp() == [("194.61.24.102", True)]
        api_host(app, {"host": "DESKTOP", "offset_seconds": 60})
        assert rdp() == [("DESKTOP", False)]
    finally:
        app.con.close()


def test_every_logon_resolves_whatever_its_hosts_offset(synthetic_case):
    """A logon's source is resolved for the rules and the outside sources whatever its host's clock offset. They read
    the links from the case's first to its last recorded time, by clock-adjusted time, so an offset that moved a logon
    past either end lost it: DESKTOP's two logons from DC01, by IP and by name, end the case."""
    journal = Journal(synthetic_case)
    journal.append("host_offset", host="DESKTOP", seconds=60.0)
    journal.append("host_offset", host="DC01", seconds=-7200.0)   # its RDP from outside, before the registry's T0 - 1 h
    journal.append("rule_add", id="from-dc01", text=FROM_DESKTOP.replace("DESKTOP", "DC01"))
    con, _, _ = open_case(synthetic_case)
    from_dc01 = con.execute("SELECT list(event_uid ORDER BY event_uid) FROM events WHERE host = 'DESKTOP' "
                            "AND ts_us IN (?, ?)", [T0 + 874 * SEC, T0 + 910 * SEC]).fetchone()[0]
    assert con.execute("SELECT list(event_uid ORDER BY event_uid) FROM suggestions "
                       "WHERE source = 'from-dc01'").fetchone()[0] == from_dc01
    assert outside_sources(con) == ["194.61.24.102"]
    con.close()


def test_a_logon_from_an_address_that_is_not_remote_links_by_its_workstation_name(synthetic_case, tmp_path):
    """A 4624 whose source address isn't a real one (loopback, link-local, or unspecified, IPv4 or IPv6) and resolves
    to no host links from the host its WorkstationName names, an RDP logon as a network one, and a rule reads that host
    as its source_host. A real address never falls back to the name, so a name can't hide an outside source: a routable
    IPv6 address, which no host's Tcpip values give, stays an outside source, and so does an outside IPv4 address whose
    logon names the target, as RDP logons often do, or a collected host. Logons with no address, or one that resolves,
    link as before. Read through the EvtxECmd parser, so each address is stored in the parsers' form:
    ::ffff:10.42.85.115 as DESKTOP's own."""
    from test_parsers import EVIDENCE, EVTX_COLUMNS, security_row, write_csv

    from glessner.parsers import PARSERS, ParseContext

    sources = {   # record: (IpAddress, WorkstationName)
        1: ("fe80::1a2b:3c4d:5e6f:7a8b", "DESKTOP-SDN1RPT"),
        2: ("127.0.0.1", "DESKTOP-SDN1RPT"),
        3: ("::1", "desktop-sdn1rpt"),
        4: ("169.254.10.20", "DESKTOP-SDN1RPT"),
        5: ("0.0.0.0", "DESKTOP-SDN1RPT"),
        6: ("fd00::5", "DESKTOP-SDN1RPT"),
        7: ("203.0.113.7", "CITADEL-DC01"),
        8: ("203.0.113.8", "DESKTOP-SDN1RPT"),
        9: ("-", "DESKTOP-SDN1RPT.C137.local"),   # a name the other records don't write
        10: ("::ffff:10.42.85.115", "WS09"),
        11: ("fe80::99", "WS09"),           # a name no host has
        12: ("fe80::98", "CITADEL-DC01"),   # DC01's own name: a host logging on to itself draws nothing
        13: ("fe80::77", "CITADEL-DC01"),   # an address typed for DESKTOP resolves first
        14: ("127.0.0.1", "DESKTOP-SDN1RPT"),
        15: ("::1", "CITADEL-DC01"),
    }
    rdp = {14, 15}   # type 10; the others are type 3
    log = DC01_LOGS + "Security-Fallback.evtx"
    write_csv(tmp_path / "evtxecmd.csv", EVTX_COLUMNS, [
        security_row(record, 4624, "Successful logon", {"TargetUserName": "mortysmith", "TargetDomainName": "C137",
                                                        "LogonType": "10" if record in rdp else "3", "IpAddress": ip,
                                                        "WorkstationName": name},
                     SourceFile=log, Computer="CITADEL-DC01.C137.local", TimeCreated=f"2020-09-19 04:00:{record:02d}.0000000")
        for record, (ip, name) in sources.items()])
    events = list(PARSERS["evtxecmd_csv"](ParseContext(tmp_path, EVIDENCE)))
    load(synthetic_case.db_path, events, host="DC01", tool="evtxecmd", tool_version="t", run_id="fallback",
         replaces_sources=[], staging_dir=synthetic_case.folder)
    journal = Journal(synthetic_case)
    journal.append("rule_add", id="from-desktop", text=FROM_DESKTOP)
    journal.append("host_identity", host="DESKTOP", op="add_ip", value="fe80::77")
    con, _, _ = open_case(synthetic_case)
    fallback = "e.source_file LIKE '%Security-Fallback.evtx'"
    links = {record: (source, target, via, outside) for record, source, target, via, outside in con.execute(
        "SELECT e.record_id, l.source_host, l.target_host, l.via, l.outside FROM logon_links l "
        f"JOIN events e ON e.event_uid = l.event_uid WHERE {fallback}").fetchall()}
    by_name = ("DESKTOP", "DC01", "name", False)
    assert links == {1: by_name, 2: by_name, 3: by_name, 4: by_name, 5: by_name,
                     6: ("fd00::5", "DC01", "ip", True), 7: ("203.0.113.7", "DC01", "ip", True),
                     8: ("203.0.113.8", "DC01", "ip", True), 9: by_name, 10: ("DESKTOP", "DC01", "ip", False),
                     13: ("DESKTOP", "DC01", "ip", False), 14: by_name}
    assert outside_sources(con) == ["194.61.24.102", "203.0.113.7", "203.0.113.8", "fd00::5"]
    suggested_records = {record for (record,) in con.execute(
        f"SELECT e.record_id FROM suggestions s JOIN events e ON e.event_uid = s.event_uid "
        f"WHERE s.source = 'from-desktop' AND {fallback}").fetchall()}
    assert suggested_records == {1, 2, 3, 4, 5, 9, 10, 13, 14}
    con.close()


def test_a_host_whose_address_logs_on_under_another_machines_name_needs_review(synthetic_case):
    """A host owning an address that 4624 type 3 logons came from under another machine's WorkstationName, such as a
    laptop's old home lease that an uncollected machine held during the incident, gets a review note per address with
    the count and the names. The host's own names, in any letter case or as a full name, its address written as the
    name, the 15-character NetBIOS form of a longer name, a blank or "-" name, a type 10 logon, which can record the
    target's own name, and a failed logon don't count. The logons still link from the host that owns the address. An
    address two hosts claim resolves to neither, so it gets only the note that says so."""
    from dataclasses import replace

    from conftest import logon

    hive = "LAPTOP01/Windows/System32/config/SYSTEM"
    load(synthetic_case.db_path,
         [registry(hive, "ROOT\\ControlSet001\\Control\\ComputerName\\ComputerName", "ComputerName", "LAPTOP01"),
          registry(hive, "ROOT\\ControlSet001\\Services\\Tcpip\\Parameters\\Interfaces\\{2}", "DhcpIPAddress",
                   "192.168.1.23")],
         host="LAPTOP01", tool="recmd", tool_version="t", run_id="laptop", replaces_sources=[hive],
         staging_dir=synthetic_case.folder)
    fin_log = "FIN/Windows/System32/winevt/Logs/Security.evtx"   # its names come from its event logs alone
    load(synthetic_case.db_path, [logon(T0, 1, fin_log, code="4634", computer="FINANCE-WORKSTATION01.corp.local")],
         host="FIN", tool="evtxecmd", tool_version="t", run_id="fin", replaces_sources=[fin_log],
         staging_dir=synthetic_case.folder)
    journal = Journal(synthetic_case)
    for ip in ("10.42.85.116", "10.42.85.117"):
        journal.append("host_identity", host="DESKTOP", op="add_ip", value=ip)
    journal.append("host_identity", host="FIN", op="add_ip", value="10.42.85.200")
    at = lambda i: T0 + (2000 + i) * SEC
    archive = "DC01/Windows/System32/winevt/Logs/Archive-Security.evtx"
    sources = [
        *[("3", "192.168.1.23", "ATTACKER-PC")] * 3,
        ("3", "192.168.1.23", "laptop01.corp.local"),   # its own name
        ("3", "192.168.1.23", "192.168.1.23"),          # its own address
        ("3", "192.168.1.23", ""),
        ("3", "192.168.1.23", "-"),
        ("10", "192.168.1.23", "CITADEL-DC01"),          # RDP, naming the target
        ("3", "10.42.85.10", "CITADEL-DC01"),            # DC01 to itself, by its own name
        ("3", "10.42.85.115", "DESKTOP"),                # DESKTOP's lane name
        *[("3", "10.42.85.115", "WS07")] * 2,
        ("3", "10.42.85.115", "WS08"),
        ("3", "10.42.85.116", "WS09"),
        *[("3", "10.42.85.117", name) for name in ("WS10", "WS11", "WS12", "WS13", "WS13")],
        ("3", "10.42.85.200", "FINANCE-WORKSTA"),        # FIN's NetBIOS name
        ("3", "10.42.85.200", "FINANCE-WORKST2"),
    ]
    logons = [logon(at(i), 400 + i, archive, user="u", ltype=ltype, ip=ip, ws=ws)
              for i, (ltype, ip, ws) in enumerate(sources)]
    failed = logon(at(len(sources)), 400 + len(sources), archive, user="u", code="4625", ip="192.168.1.23",
                   ws="ATTACKER-PC")
    load(synthetic_case.db_path, [*logons, replace(failed, logon_type="3")],   # EvtxECmd gives a 4625 its logon type
         host="DC01", tool="evtxecmd", tool_version="t", run_id="names", replaces_sources=[archive],
         staging_dir=synthetic_case.folder)
    con, _, identity = open_case(synthetic_case)
    hosts = identity.hosts
    assert hosts["LAPTOP01"].review == ["Role not confirmed", "3 logons from 192.168.1.23 name ATTACKER-PC, not this host"]
    desktop_notes = ["3 logons from 10.42.85.115 name WS07 and WS08, not this host",
                     "1 logon from 10.42.85.116 names WS09, not this host",
                     "5 logons from 10.42.85.117 name WS13, WS10, WS11, and 1 other, not this host"]
    assert hosts["DESKTOP"].review == ["Role not confirmed", *desktop_notes]
    assert hosts["FIN"].review == ["Role not confirmed", "1 logon from 10.42.85.200 names FINANCE-WORKST2, not this host"]
    assert hosts["DC01"].review == ["Role not confirmed"]
    assert [(link.source, link.target, link.via) for link in links_in(con, at(0), at(3))] == [("LAPTOP01", "DC01", "ip")] * 3

    Journal(synthetic_case).append("host_identity", host="DESKTOP", op="add_ip", value="192.168.1.23")
    hosts = build_identity(con, Journal(synthetic_case).state).hosts
    assert hosts["LAPTOP01"].review == ["Role not confirmed", "192.168.1.23 is also claimed by DESKTOP"]
    assert hosts["DESKTOP"].review == ["Role not confirmed", "192.168.1.23 is also claimed by LAPTOP01", *desktop_notes]
    con.close()


@pytest.mark.parametrize("kind", ["untimed", "imported"])
def test_a_logon_that_draws_no_link_adds_no_name_to_the_review_note(synthetic_case, kind):
    """The note counts the logons that link from the host owning the address: EvtxECmd's 4624s with a time. A 4624
    with no time, or one imported from another log, such as a SIEM's export of the same logons, draws no link, so the
    names it records aren't counted, though its source address resolves to the host."""
    from dataclasses import replace

    from conftest import logon

    hive = "LAPTOP01/Windows/System32/config/SYSTEM"
    load(synthetic_case.db_path,
         [registry(hive, "ROOT\\ControlSet001\\Control\\ComputerName\\ComputerName", "ComputerName", "LAPTOP01"),
          registry(hive, "ROOT\\ControlSet001\\Services\\Tcpip\\Parameters\\Interfaces\\{2}", "DhcpIPAddress",
                   "192.168.1.23")],
         host="LAPTOP01", tool="recmd", tool_version="t", run_id="laptop", replaces_sources=[hive],
         staging_dir=synthetic_case.folder)
    at = lambda i: T0 + (2000 + i) * SEC
    archive = "DC01/Windows/System32/winevt/Logs/Archive-Security.evtx"
    linked = [logon(at(i), 400 + i, archive, user="u", ltype="3", ip="192.168.1.23", ws="ATTACKER-PC") for i in range(3)]
    load(synthetic_case.db_path, linked, host="DC01", tool="evtxecmd", tool_version="t", run_id="names",
         replaces_sources=[archive], staging_dir=synthetic_case.folder)
    if kind == "untimed":
        source, tool = "DC01/Windows/System32/winevt/Logs/Untimed-Security.evtx", "evtxecmd"
        unlinked = [logon(None, 500, source, user="u", ltype="3", ip="192.168.1.23", ws="OTHER-PC")]
    else:
        source, tool = "SIEM/logons.jsonl", "import"
        unlinked = [replace(logon(at(i), 500 + i, source, user="u", ltype="3", ip="192.168.1.23", ws="OTHER-PC"),
                            artifact="siem_logons") for i in range(2)]
    load(synthetic_case.db_path, unlinked, host="DC01", tool=tool, tool_version="t", run_id=kind,
         replaces_sources=[source], staging_dir=synthetic_case.folder)
    con, _, identity = open_case(synthetic_case)
    assert identity.hosts["LAPTOP01"].review == ["Role not confirmed",
                                                 "3 logons from 192.168.1.23 name ATTACKER-PC, not this host"]
    assert con.execute("SELECT count(*) FROM logon_links WHERE source_host = 'LAPTOP01'").fetchone()[0] == 3
    con.close()


def test_registry_paths_match_whatever_their_letter_case(synthetic_case):
    """Windows compares key names without case, and a hive can write them in lower case, such as `services`. Such a
    host still gets its name, address, role, release, and zone, and Same service name still reaches a Sysmon key
    under `services`."""
    from glessner.events import Event
    from glessner.timezones import host_timezones

    system, software = "WS03/Windows/System32/config/SYSTEM", "WS03/Windows/System32/config/SOFTWARE"
    zone = "ROOT\\ControlSet001\\control\\timezoneinformation"
    load(synthetic_case.db_path, [
        registry(system, "ROOT\\ControlSet001\\control\\computername\\computername", "ComputerName", "FILESRV03"),
        registry(system, "ROOT\\ControlSet001\\services\\Tcpip\\Parameters\\Interfaces\\{3}", "DhcpIPAddress",
                 "10.20.30.40"),
        registry(system, "ROOT\\ControlSet001\\control\\productoptions", "ProductType", "ServerNT"),
        registry(system, zone, "TimeZoneKeyName", "Pacific Standard Time"),
        registry(system, zone, "Bias", "480"),
        *[registry(software, "ROOT\\Microsoft\\windows nt\\currentversion", name, value)
          for name, value in WINDOWS_10.items()]],
         host="WS03", tool="recmd", tool_version="t", run_id="lower", replaces_sources=[], staging_dir=synthetic_case.folder)
    sysmon = [Event(ts_us=T0 + (3000 + i) * SEC, ts_desc="Event Recorded", artifact="evtx",
                    source_file="DC01/Sysmon.evtx", source_record=str(i), record_id=i, message="13", event_code="13",
                    event_provider="Microsoft-Windows-Sysmon", log_channel="Microsoft-Windows-Sysmon/Operational",
                    registry_path=f"HKLM\\System\\CurrentControlSet\\{services}\\WinUpdSvc\\ImagePath")
              for i, services in enumerate(("services", "Services"))]
    load(synthetic_case.db_path, sysmon, host="DC01", tool="evtxecmd", tool_version="t", run_id="sysmon",
         replaces_sources=[], staging_dir=synthetic_case.folder)
    con, _, identity = open_case(synthetic_case)
    ws = identity.hosts["WS03"]
    assert (ws.names, ws.ips) == (["FILESRV03"], ["10.20.30.40"])
    assert identity.resolve_ip("10.20.30.40") == identity.resolve_name("FILESRV03") == "WS03"
    assert (ws.guessed_role, ws.role_reason) == ("Servers", "The SYSTEM hive records its product type as ServerNT")
    assert ws.os["display"] == "Windows 10 Enterprise Evaluation, version 2004, build 19041.264"
    assert (host_timezones(con)["WS03"]["windows"], ws.timezone["bias_minutes"]) == ("Pacific Standard Time", 480)
    keys = [uid for (uid,) in con.execute("SELECT event_uid FROM events WHERE source_file = 'DC01/Sysmon.evtx' "
                                          "ORDER BY record_id").fetchall()]
    for key in keys:
        assert sorted(e["uid"] for e in related(con, key, "service_name")["events"]) == sorted(keys)
    con.close()


@pytest.mark.parametrize("written, windows, iana", [
    ("Eastern Standard Time ard Time", "Eastern Standard Time", "America/New_York"),
    ("Pacific Standard Time\x00me", "Pacific Standard Time", "America/Los_Angeles"),
    ("Central Standard Time (Mexico) xico)", "Central Standard Time (Mexico)", "America/Mexico_City"),
    ("Tokyo Standard Time", "Tokyo Standard Time", "Asia/Tokyo"),
    ("Central Standard Time (Mexico)", "Central Standard Time (Mexico)", "America/Mexico_City"),
    ("Mid-Atlantic Standard Time", "Mid-Atlantic Standard Time", ""),
], ids=["no null", "null", "parentheses", "as written", "as written, its leading words a zone", "no zone"])
def test_a_zone_name_written_with_bytes_after_its_null_reads_as_its_zone(synthetic_case, written, windows, iana):
    """RECmd can write TimeZoneKeyName with what followed the value's terminating null, as "Eastern Standard Time ard
    Time", which names no zone. The name is read up to the null, or, where the null isn't kept, as its longest run of
    leading words that names a Windows zone, so the host's zone keeps its daylight saving rules. A name that names a
    zone as written keeps all its words, and one that no run of words matches keeps its text, with the host's bias as
    a fixed offset."""
    import sys

    from glessner.timezones import host_timezones, resolve_zone

    if sys.platform != "win32" and "\x00" not in written:
        pytest.skip("the zone names are looked up in the ICU that ships with Windows")
    zone = "ROOT\\ControlSet001\\Control\\TimeZoneInformation"
    hive = "DESKTOP/Windows/System32/config/SYSTEM"
    load(synthetic_case.db_path, [registry(hive, zone, "TimeZoneKeyName", written), registry(hive, zone, "Bias", "300")],
         host="DESKTOP", tool="recmd", tool_version="t", run_id="zone", replaces_sources=[], staging_dir=synthetic_case.folder)
    con, _, _ = open_case(synthetic_case)
    zones = host_timezones(con)
    assert zones["DESKTOP"]["windows"] == windows
    if sys.platform == "win32":
        assert zones["DESKTOP"]["iana"] == iana
        label = (f"DESKTOP's zone, {windows} ({iana})" if iana
                 else "DESKTOP's fixed offset UTC-05:00, without daylight saving")
        assert resolve_zone("host:DESKTOP", zones)["label"] == label
    con.close()
