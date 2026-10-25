"""The parser fields the pivots read: each is filled on rebuild, and none changes an event's ID. And the IDs of each
case format, pinned, so an ID changes only with a case format step."""

import pytest
from parser_fix_fixtures import HOST, evtx_events, ids, suricata_events
from rekey_fixtures import FIXTURES, HOSTS

from glessner.case import CASE_FORMAT
from glessner.events import EventIds, connect, event_uid, load

# The IDs the records in parser_fix_fixtures get, pinned. An ID hashes the host, artifact, source file, source record,
# and time description, and none of the fields the pivots read is one of them.
GOLDEN_EVTX = {
    "4688 shared logon": "43587427ecffaaa1b619fe6a63d80738",
    "4688 own logon": "9fed2600831e5bc519535c5efe0e9205",
    "4688 empty target": "7b49f50f91cc425a78ad50ce670a22fb",
    "4625 no logon": "aef215c61db8bc588a1997cf19e9bad3",
    "4624 hex digits": "42c8afe7c54b8099414c60971a76a81a",
    "4778 reconnect": "1c3fbc7623df63350dd039f8d6a459ed",
    "4779 disconnect": "3bf60dd2f29ff2cc14f449aafd36a72d",
    "LSM 21": "f17dd848e730848cebad9df881860f8e",
    "LSM 24 local": "6c1e4cbfcec5d7d9f08af1486b41b983",
    "Defender 1116": "c07499aca832680e28a5203a8f7a5db3",
    "Defender 1117 container": "21802136ce8ce50f44bfd272cd9abe99",
    "4663 file": "c9bd9ef188a103b91c204b0677664cc7",
    "4663 key": "454a556adc13fba10923a74492163d5b",
    "4776 workstation": "3225fef36c9fa380054feb5776f2ad2e",
    "4732 group": "13eb690de8a2d9ca7b53736dd4e77c01",
    "4720 account": "d505352cdc12f772ab27b64570a205e7",
}
GOLDEN_SURICATA = ["decb33f9b5e78bb36c04ba94aff9755c", "93e076256c9825f5b2784fa840e78730",
                   "91a188015152a5a5f5735ee80e1b862e"]


def test_no_parser_fix_changes_an_event_id(tmp_path):
    """A mark in a journal names its event by ID, so a parser fix that changed one would orphan the marks on it."""
    events = evtx_events(tmp_path)
    assert dict(zip(events, ids(events.values()), strict=True)) == GOLDEN_EVTX
    assert ids(suricata_events(tmp_path)) == GOLDEN_SURICATA


# The IDs rekey_fixtures' records get as a load gives them, by case format. Format 1's are those the parsers give under
# format 1's key rules; format 2's are those under the current ones. An event's ID changes only with a case format
# step: keep the replaced rule as the parser's former rule for the format it upgrades from (parsers.FORMER_RULES), pin
# the IDs under the new format here, and add the new format's upgrade (rekey.py).
IDS_BY_FORMAT = {
    1: {
        "amcache_found": ["0fb567491477b0c18d110cc0ebc160b7", "c7cab1af34a0ec8b13c1e4169f10f697",
                          "e4dc45d3728f107951565b3f82dd0422", "f20176eceac2939d46c36e3d6c36cb42",
                          "d089e06ad71bda65267443448d985a6d", "3d5ee61ecc4924b3bbb121cecfc6cfb4"],
        "amcache_tool": ["642e23b3e752cae5ccec9f058fac2b48", "903f42a5efbd534e2e299fbcd50a9e8b",
                         "e1e52c280e4bdb4b90ae6efff0dcc3a1", "06f66b78431ea46d17db08f6a75aa5d0"],
        "srum_found": ["ddb078cc5901f158284a28a9b28b8c6b", "0e0cfd3851dc1c0b99de5ca3687de419",
                       "f29e6064f2970831c9dfbcc5ececdc24", "6a513f03cdcc94cb793aa462e8de1a0d"],
        "srum_tool": ["edf6d61908961bfb8fc25a49b4aff88b", "2c92e7676e207e7314082dbad9399fa3",
                      "6b007ff2ce6d646f2e9ff5837d88d2ae"],
        "eve": ["c049e3ae457bd9af292823865a2b4da2", "2522b6fb4ad68d90adfaacbbd3a07622", "6db8bae1c4ddc0c2545da2dce2435d59",
                "b15e933cb998683d6c9ba3e4430d6e20", "bf60d4bce10135ab821bde2afee36c4a", "89e9fbf5b9959f88f01694eda67aff49",
                "615618bbc5fb2a9070c857833de74e04"],
        "eve_found": ["839dd50ae3514b4fa9f0c6c1b9448d63", "f5919d9568064efa84aa7da2f94f8018",
                      "02f828103c513e605e75b2dc2dc84c5e", "3f601b81320e5c98cb57a0d96a0a4656",
                      "e7b48683416eecff81ec777677ecfd28", "898466926e62f64eb2608698ee49b290",
                      "c5495d3df991007dab102dfabc868436", "cff2b9220ef06900acded93351e6f38a",
                      "85c2bd5088ba91610a84b7afa4f2dfe1", "58ab99da8faa74ddd8824e9168d55be1",
                      "73e83f41d17ac80bee3d121ca343e03f", "c9fbcc722e81faa4d2f836771f01937d",
                      "dfec4e42b4ae79e660889cbc05f7b1c4", "9585d60b24ad224d7c219204fb308a21"],
        "sqlecmd": ["002faeec366d7bdd91fe9a91c1e22936", "aa4d4d9c12135a568e8214662a567683",
                    "a7ce0def7bed2c6ae5fdca45410e8f91", "d28df0035de7ebefde2ae2117fc16258",
                    "42004a4476fadf53ad50490e7a215f3b"],
    },
    2: {
        "amcache_found": ["fd169e35f5d69eda32e8dc7531d18253", "c7cab1af34a0ec8b13c1e4169f10f697",
                          "e4dc45d3728f107951565b3f82dd0422", "785c9aa8f3b609f2f701de80084e7adf",
                          "83c2af64456f457eada76ee7dcee3dfd", "f7297da2c5ceebea29d410b901ed50b5"],
        "amcache_tool": ["642e23b3e752cae5ccec9f058fac2b48", "903f42a5efbd534e2e299fbcd50a9e8b",
                         "e1e52c280e4bdb4b90ae6efff0dcc3a1", "06f66b78431ea46d17db08f6a75aa5d0"],
        "srum_found": ["c2cfbe6a638f52f0c549a82f50dd5cbe", "a3ba13344aeb6bb9df71d634e1d60686",
                       "17aa35cd2fa2ced1ce2a2eabbc2b9886", "d7a5457e632f59ceda5c00c550ff92b8"],
        "srum_tool": ["edf6d61908961bfb8fc25a49b4aff88b", "2c92e7676e207e7314082dbad9399fa3",
                      "6b007ff2ce6d646f2e9ff5837d88d2ae"],
        "eve": ["56f24db71f5bec83140778b19cb56ff3", "879a9207f6c0aa23896907dd9e9a8a16", "5dd075a71d4b52724c8cd098b6a3c091",
                "a0b3f3d794ce3673eac70fbfdb657d74", "bf60d4bce10135ab821bde2afee36c4a", "89e9fbf5b9959f88f01694eda67aff49",
                "3dcc9f3c8df948eaeef4bb68bfea6c54"],
        "eve_found": ["54f32fb50949732e520bf05f5a5c289c", "7b1c0c0e78de4dff58abe7db92ec9db5",
                      "837b489479bbb1011ee3c222d87d493e", "c88377dfa00389003b95a4b88cbba346",
                      "e7b48683416eecff81ec777677ecfd28", "898466926e62f64eb2608698ee49b290",
                      "0bf7e6d3ee0b69b0fa48641a59688c59", "744b731c50d297f7560f301653749bea",
                      "e151230b73a42df86f704473acb80998", "6c94baa2ee4d1ec05aa7789e014c19ed",
                      "915aa7dae7215598e78b90aadbb5cbf7", "c9fbcc722e81faa4d2f836771f01937d",
                      "dfec4e42b4ae79e660889cbc05f7b1c4", "23b08b8aaed1d45bd8393cddc0b25687"],
        "sqlecmd": ["a3cacc2a051423d38ffd18afcc04fc2a", "aa4d4d9c12135a568e8214662a567683",
                    "a7ce0def7bed2c6ae5fdca45410e8f91", "d28df0035de7ebefde2ae2117fc16258",
                    "8d0a3a0a408f4b7bb72817a9d21d2501"],
    },
}
IDS_BY_FORMAT[3] = IDS_BY_FORMAT[2]   # format 3 seals the journal and changes no event ID
IDS_BY_FORMAT[4] = IDS_BY_FORMAT[3]   # format 4 adds a journal entry and changes no event ID


def test_the_format_this_build_writes_has_its_ids_pinned():
    """Raising CASE_FORMAT without pinning the new format's IDs here fails."""
    assert max(IDS_BY_FORMAT) == CASE_FORMAT


def loaded_ids(folder, events, host) -> list[str]:
    """The events' IDs as events.load writes them, in the order it read them."""
    db = folder / "pinned.duckdb"
    load(db, events, host=host, tool="t", tool_version="1", run_id="r", replaces_sources=[], staging_dir=folder)
    con = connect(db, read_only=True)
    try:
        return [uid for (uid,) in con.execute("SELECT event_uid FROM events ORDER BY rowid").fetchall()]
    finally:
        con.close()


def test_a_load_gives_the_ids_it_gave_before(tmp_path):
    """load numbers repeats through events.EventIds, which the upgrade shares; the golden records load with their
    pinned IDs, and a repeat takes #2."""
    events = list(evtx_events(tmp_path).values())
    assert loaded_ids(tmp_path, events + events[:1], HOST) == [*GOLDEN_EVTX.values(), event_uid(
        HOST, events[0].artifact, events[0].source_file, f"{events[0].source_record}#2", events[0].ts_desc)]
    (tmp_path / "pinned.duckdb").unlink()
    assert loaded_ids(tmp_path, suricata_events(tmp_path), HOST) == GOLDEN_SURICATA


@pytest.mark.parametrize("name", FIXTURES)
def test_each_case_formats_ids_are_pinned(tmp_path, name):
    """A load gives the current format's IDs, and the former rule, asked for format 1, gives format 1's, repeats
    numbered as a load under that rule numbers them."""
    events = FIXTURES[name](tmp_path, former=1)
    assert loaded_ids(tmp_path, events, HOSTS[name]) == IDS_BY_FORMAT[CASE_FORMAT][name]
    pair = EventIds(former=True)
    assert [pair(HOSTS[name], e)[1] for e in events] == IDS_BY_FORMAT[1][name]


def test_a_4688_takes_the_subjects_logon_when_its_target_logon_is_0x0(tmp_path):
    """Windows 10 writes a TargetLogonId of 0x0 when the creator and target share a logon, so the Subject's logon is
    the process's session and the process joins the user's 4624 session. 0x0 is no session, so it is stored as none."""
    e = evtx_events(tmp_path)
    assert e["4688 shared logon"].logon_id == "0x3E7"          # the Subject's
    assert e["4688 own logon"].logon_id == "0x2222"            # a target of its own stays the target
    assert e["4688 empty target"].logon_id == "0x1111"         # an empty target, too
    assert e["4625 no logon"].logon_id == ""                   # 0x0 in both: no session at all
    assert e["4624 hex digits"].logon_id == "0x6c0b6d"         # a 4624's own logon, as written


def test_suricata_addresses_are_stored_as_event_logs_store_them(tmp_path):
    """Suricata writes IPv6 in full, so the stored address takes the shortened form host events use, and an IP pivot
    joins them. The raw text stays in extra, and the ID, whose record key reads it, doesn't change."""
    alert, dns, flow = suricata_events(tmp_path)
    assert (alert.source_ip, alert.dest_ip) == ("fe80::2dcf:e660:be73:d220", "ff02::1:2")
    assert (dns.source_ip, dns.dest_ip) == ("10.0.0.5", "2001:db8::1")   # a mapped v4 and a capitalized v6, as host events
    assert (flow.source_ip, flow.dest_ip) == ("10.0.0.5", "10.0.0.1")
    assert alert.extra["src_ip"] == "fe80:0000:0000:0000:2dcf:e660:be73:d220"
    assert dns.extra["src_ip"] == "::ffff:10.0.0.5" and dns.extra["dest_ip"] == "2001:0DB8:0000:0000:0000:0000:0000:0001"
    assert alert.message.endswith("fe80:0000:0000:0000:2dcf:e660:be73:d220:546 -> ff02:0000:0000:0000:0000:0000:0001:0002:547")


def test_rdp_session_events_fill_the_account_the_session_and_the_address(tmp_path):
    """4778 and 4779 name their account as AccountName, their session as LogonID, and the client
    as ClientAddress, and LocalSessionManager writes the client as Address, with LOCAL for none."""
    e = evtx_events(tmp_path)
    reconnect, disconnect = e["4778 reconnect"], e["4779 disconnect"]
    assert (reconnect.user_domain, reconnect.user_name, reconnect.logon_id) == ("C137", "Administrator", "0x510986")
    assert reconnect.source_ip == "194.61.24.102"
    assert (disconnect.user_name, disconnect.logon_id, disconnect.source_ip) == ("Administrator", "0x510986", "")   # LOCAL
    assert (e["LSM 21"].user_name, e["LSM 21"].source_ip) == ("Administrator", "194.61.24.102")
    assert e["LSM 24 local"].source_ip == ""


def test_defender_detections_name_their_file_process_and_user(tmp_path):
    """A detection's Path, Process Name, and Detection User are read, so Same file finds the detected file. The file:
    prefix goes, a file inside an archive gives the archive, and "Unknown" is no process."""
    e = evtx_events(tmp_path)
    found, container = e["Defender 1116"], e["Defender 1117 container"]
    assert (found.file_path, found.file_key) == ("C:\\Users\\Public\\coreupdater.exe", "\\users\\public\\coreupdater.exe")
    assert (found.process_executable, found.user_domain, found.user_name) == ("C:\\Windows\\Explorer.EXE", "C137",
                                                                              "Administrator")
    assert (container.file_path, container.process_executable) == ("C:\\x\\a.zip", "")
    assert (container.user_domain, container.user_name) == ("NT AUTHORITY", "SYSTEM")


def test_object_access_names_the_file_and_an_ntlm_validation_names_its_workstation(tmp_path):
    """A 4663's ObjectName is the file, not the process doing the access; a registry key's is no file. 4776 writes its
    client as Workstation, not WorkstationName."""
    e = evtx_events(tmp_path)
    assert (e["4663 file"].file_path, e["4663 file"].file_key) == ("C:\\Data\\secret.docx", "\\data\\secret.docx")
    assert e["4663 file"].process_executable == "C:\\Windows\\explorer.exe"
    assert (e["4663 key"].file_path, e["4663 key"].file_key) == ("", "\\windows\\regedit.exe")   # the process
    assert e["4776 workstation"].source_workstation == "KALI"


def test_a_group_change_takes_the_subject_who_made_it_as_its_account(tmp_path):
    """The Target of a 4732 is the group, so the event takes the Subject who made the change as its account, and Same
    account finds the person, not the group's other events. The group and the member stay in the event's data; an
    account change keeps the account it changed."""
    e = evtx_events(tmp_path)
    group = e["4732 group"]
    assert (group.user_domain, group.user_name) == ("C137", "Administrator")
    assert group.extra["TargetUserName"] == "Administrators" and group.extra["MemberSid"] == "S-1-5-21-1-2-3-1105"
    assert (e["4720 account"].user_domain, e["4720 account"].user_name) == ("C137", "newuser")


def test_a_sysmon_logon_id_of_0x0_is_no_session():
    """Sysmon's LogonId follows the rule that 0x0 is no logon session, as the Security events' do."""
    from glessner.parsers.evtxecmd import SYSMON, _user_session
    row = {"Provider": SYSMON}
    assert _user_session(row, {"LogonId": "0x0"}) == "" and _user_session(row, {"LogonId": "0x5a1"}) == "0x5a1"
