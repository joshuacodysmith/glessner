from glessner.identify import LNK_CLSID, Identification, identify_bytes


def pad(header: bytes) -> bytes:
    return header + b"\x00" * (32 - len(header))


def test_evtx():
    assert identify_bytes("Security.evtx", pad(b"ElfFile\x00")).artifact == "evtx"


def test_registry_hive_type_from_name():
    ident = identify_bytes("NTUSER.DAT", pad(b"regf"))
    assert (ident.artifact, ident.detail) == ("registry", "NTUSER")
    assert identify_bytes("SYSTEM", pad(b"regf")).detail == "SYSTEM"
    assert identify_bytes("odd_name", pad(b"regf")).detail == "unknown hive"


def test_registry_transaction_log_is_not_a_hive():
    ident = identify_bytes("NTUSER.DAT.LOG1", pad(b"regf"))
    assert (ident.artifact, ident.detail) == ("registry_log", "NTUSER")


def test_lnk_needs_header_size_and_clsid():
    assert identify_bytes("a.lnk", pad(b"\x4c\x00\x00\x00" + LNK_CLSID)).artifact == "lnk"
    assert identify_bytes("a.lnk", pad(b"\x4c\x00\x00\x00" + b"\x00" * 16)).artifact is None


def test_prefetch_both_formats():
    assert identify_bytes("CMD.EXE-1.pf", pad(b"\x1e\x00\x00\x00SCCA")).detail == "uncompressed"
    assert identify_bytes("CMD.EXE-1.pf", pad(b"MAM\x04")).detail == "compressed"


def test_mft_needs_name_and_record_magic():
    assert identify_bytes("_MFT", pad(b"FILE0")).artifact == "mft"
    assert identify_bytes("$MFT", pad(b"FILE0")).artifact == "mft"
    assert identify_bytes("_MFTMirr", pad(b"FILE0")).artifact == "mft_mirror"
    assert identify_bytes("random.bin", pad(b"FILE0")).artifact is None


def test_signature_wins_over_misleading_name():
    assert identify_bytes("Security.evtx", pad(b"PK\x03\x04")).artifact is None
    assert identify_bytes("notes.txt", pad(b"ElfFile\x00")).artifact == "evtx"


def test_unidentified_file_named_like_an_artifact_says_why():
    ident = identify_bytes("VSSVC.EXE-6C8F0C66.pf", b"\x00" * 32)
    assert ident.artifact is None
    assert ident.detail == "named like prefetch, but no prefetch signature; header is all zero bytes"
    assert identify_bytes("SYSTEM", pad(b"junk")).detail == "named like registry, but no registry signature"
    assert identify_bytes("notes.txt", pad(b"junk")).detail == ""


def test_empty_file():
    ident = identify_bytes("empty.evtx", b"")
    assert ident.artifact is None and ident.detail == "empty file"


FIREWALL_LOG = (b"#Version: 1.5\r\n#Software: Microsoft Windows Firewall\r\n#Time Format: Local\r\n"
                b"#Fields: date time action protocol src-ip dst-ip src-port dst-port size tcpflags tcpsyn tcpack tcpwin "
                b"icmptype icmpcode info path pid\r\n\r\n"
                b"2024-02-05 10:21:48 ALLOW TCP 10.0.0.5 10.0.0.9 49733 445 0 - 0 0 0 - - - SEND 4\r\n")


def test_text_logs_are_recognized_by_their_content():
    """The logs the import reads, recognized from their first lines."""
    assert identify_bytes("pfirewall.log", FIREWALL_LOG) == Identification("w3c_log", "content", "Windows Firewall")
    iis = (b"#Software: Microsoft Internet Information Services 10.0\r\n#Version: 1.0\r\n#Date: 2024-02-05 00:00:00\r\n"
           b"#Fields: date time s-ip cs-method cs-uri-stem\r\n")
    assert identify_bytes("u_ex240205.log", iis).detail == "IIS"
    forti = (b'<189>date=2023-05-25 time=07:45:16 devname="FGT60E" devid="FGT60E0000000001" eventtime=1685000716783695562 '
             b'tz="+0000" logid="0000000013" type="traffic" subtype="forward"\n')
    assert identify_bytes("fortigate.log", forti) == Identification("kv_log", "content", "Fortinet")
    sonic = (b'<134>id=firewall sn=0017C5000000 time="2024-02-05 10:21:48" fw=203.0.113.1 pri=6 c=1024 m=537 '
             b'msg="Connection Closed" src=10.0.0.12:49733:X0 dst=198.51.100.4:443:X1\n')
    assert identify_bytes("sonicwall.log", sonic).detail == "SonicWall"
    jsonl = b'{"@timestamp": "2024-02-05T10:21:48Z", "source": {"ip": "10.0.0.5"}}\n{"@timestamp": "2024-02-05T10:21:49Z"}\n'
    assert identify_bytes("alerts.json", jsonl).artifact == "jsonl"
    assert identify_bytes("traffic.csv", b"receive_time,src,dst\n2024/02/05 10:21:48,203.0.113.9,10.0.0.12\n") == \
        Identification("csv", "content", "comma-separated")
    assert identify_bytes("traffic.tsv", b"time\tsrc\tdst\n").detail == "tab-separated"
    assert identify_bytes("export.csv", "time,src\n2024-02-05 10:21:48,10.0.0.5\n".encode("utf-16")).artifact == "csv"


def test_other_text_and_binary_stay_unidentified():
    assert identify_bytes("setup.log", b"Setup started\r\nDone\r\n").artifact is None
    assert identify_bytes("Preferences.json", b'{"browser": {"theme": 1}}').artifact is None   # one object isn't JSON lines
    assert identify_bytes("notes.txt", b"time,src\n2024-02-05,10.0.0.5\n").artifact is None    # CSV needs .csv or .tsv
    assert identify_bytes("blob.bin", bytes(range(128, 256)) * 20).artifact is None


def test_item_41_artifacts_by_signature_and_name():
    """Jump lists, Recycle Bin $I files, and SRUM: a signature plus the name, as the tools look for them."""
    ole = bytes.fromhex("d0cf11e0a1b11ae1") + b"\x00" * 24
    assert identify_bytes("1bc392b8e104a00e.automaticDestinations-ms", ole) == Identification(
        "jumplist", "signature", "automatic")
    assert identify_bytes("28c8b86deab549a1.customDestinations-ms", pad(b"\x02\x00\x00\x00\x01\x00\x00\x00")).detail == "custom"
    assert identify_bytes("$IU2L112.txt", pad(b"\x01" + b"\x00" * 7 + b"\x1c")) == \
        Identification("recycle_bin", "signature", "$I version 1")
    assert identify_bytes("$IABC123.docx", pad(b"\x02" + b"\x00" * 7)).detail == "$I version 2"
    assert identify_bytes("SRUDB.dat", pad(bytes.fromhex("dad5f576efcdab89"))) == Identification("srum", "signature")
    # The signature alone, or the name alone, isn't enough.
    assert identify_bytes("report.doc", ole).artifact is None
    assert identify_bytes("$Iwhatever.txt", pad(b"hello")).artifact is None
    assert identify_bytes("other.dat", pad(bytes.fromhex("dad5f576efcdab89"))).artifact is None
