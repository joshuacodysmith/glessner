import os
import zlib

import pytest
from conftest import e01_digest, e01_hash, e01_segment

from glessner.identify import LNK_CLSID, Identification, identify_bytes, identify_file, image_note, stored_hashes


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


def test_an_eric_zimmerman_console_log_is_known_by_its_name():
    """Eric Zimmerman's tools write <stamp>_<Tool>_<version>_ConsoleLog.txt beside their output from release 2026.10. It
    holds no events, and its detail names the tool that wrote it."""
    log = b"[13:08:02.051 INF] EvtxECmd version 2026.10.2\r\n\r\nAuthor: Eric Zimmerman\r\n"
    assert identify_bytes("20261026060736_EvtxECmd_2026.10.2_ConsoleLog.txt", log) == Identification(
        "console_log", "name", "EvtxECmd")
    assert identify_bytes("20261026060736_MFTECmd_2026.10.6_ConsoleLog.TXT", log) == Identification(
        "console_log", "name", "MFTECmd")
    assert identify_bytes("my_ConsoleLog.txt", log) == Identification(None, "unidentified", "")


CONSOLE_LOG_TEXT = b"[13:08:02.051 INF] RECmd version 2.1.0.0\r\n"


@pytest.mark.parametrize(("name", "tool"), [
    ("20261026060736_RECmd_2.1.0.0_ConsoleLog.txt", "RECmd"),   # a version of four numbers
    ("20261026060736_SQLECmd_2026.10.1_consolelog.txt", "SQLECmd"),
])
def test_a_console_log_name_takes_any_tool_and_a_dotted_version(name, tool):
    assert identify_bytes(name, CONSOLE_LOG_TEXT) == Identification("console_log", "name", tool)


@pytest.mark.parametrize("name", [
    "2026102606073_EvtxECmd_2026.10.2_ConsoleLog.txt",   # a stamp of 13 digits
    "202610260607361_EvtxECmd_2026.10.2_ConsoleLog.txt",   # 15 digits
    "2026-10-26_EvtxECmd_2026.10.2_ConsoleLog.txt",   # a stamp that isn't all digits
    "x20261026060736_EvtxECmd_2026.10.2_ConsoleLog.txt",   # text before the stamp
    "20261026060736_2026.10.2_ConsoleLog.txt",   # no tool
    "20261026060736_EvtxECmd_2026_ConsoleLog.txt",   # a version without a dot
    "20261026060736_EvtxECmd_v2026.10.2_ConsoleLog.txt",   # a version that isn't numbers
    "20261026060736_EvtxECmd_ConsoleLog.txt",   # no version
    "20261026060736_EvtxECmd_2026.10.2_Console.txt",
    "20261026060736_EvtxECmd_2026.10.2_ConsoleLog.log",
    "20261026060736_EvtxECmd_2026.10.2_ConsoleLog.txt.bak",
])
def test_a_name_missing_a_console_log_part_is_no_console_log(name):
    assert identify_bytes(name, CONSOLE_LOG_TEXT).artifact != "console_log"


def sector(at: dict[int, bytes], size: int = 8192) -> bytes:
    """A file's first bytes, zeros but for the bytes given at their offsets."""
    data = bytearray(size)
    for offset, value in at.items():
        data[offset:offset + len(value)] = value
    return bytes(data)


EWF_HEADER = b"EVF\x09\x0d\x0a\xff\x00\x01"
BOOT = {510: b"\x55\xaa"}


@pytest.mark.parametrize(("name", "segment"), [("pc.E01", 1), ("pc.E04", 4), ("pc.E10", 10), ("pc.EAA", 100)])
def test_ewf_segment_is_a_disk_image_with_its_number(name, segment):
    """Each EWF segment holds its number at offset 9, so every segment is known by its signature, whatever its name."""
    header = sector({0: EWF_HEADER, 9: segment.to_bytes(2, "little"), 13: b"header"})
    assert identify_bytes(name, header) == Identification("disk_image", "signature", f"E01 segment {segment}")


@pytest.mark.parametrize(("name", "header", "detail"), [
    ("pc.Ex01", b"EVF2\x0d\x0a\x81\x00\x02\x01", "Ex01"),
    ("usb.Lx01", b"LEF2\x0d\x0a\x81\x00\x02\x01", "Lx01"),
    ("usb.L01", b"LVF\x09\x0d\x0a\xff\x00\x01\x02\x00", "L01 segment 2"),
    ("usb.s01", b"EVF\x09\x0d\x0a\xff\x00\x01\x01\x00", "E01 segment 1"),   # SMART writes E01's signature
    ("laptop.ad1", b"ADSEGMENTEDFILE\x00", "AD1 logical image"),
    ("disk.vhdx", b"vhdxfile", "VHDX"),
    ("disk.vhd", b"conectix\x00\x00\x00\x02", "VHD, dynamic"),
    ("disk-s001.vmdk", b"KDMV\x01\x00\x00\x00", "VMDK sparse extent"),
    ("disk.vmdk", b'# Disk DescriptorFile\nversion=1\nencoding="UTF-8"\nCID=fffffffe\nparentCID=ffffffff\n'
                  b'createType="monolithicSparse"\n\n# Extent description\nRW 16777216 SPARSE "disk-s001.vmdk"\n',
     "VMDK descriptor"),
    ("disk.qcow2", b"QFI\xfb\x00\x00\x00\x03", "QCOW"),
])
def test_image_formats_are_recognized(name, header, detail):
    """Containers are known by their signatures alone, so a renamed one is recognized too."""
    data = header if header.startswith(b"#") else pad(header)
    assert identify_bytes(name, data) == Identification("disk_image", "signature", detail)
    assert identify_bytes("renamed.bin", data).detail == detail


def test_fixed_vhd_is_recognized_by_its_footer(tmp_path):
    """A fixed VHD starts with the disk's own first sector and keeps its signature in the footer of its last 512 bytes,
    which identify_file reads for a .vhd file only."""
    disk = sector(BOOT) + b"\x00" * 8192 + b"conectix" + b"\x00" * 504
    (tmp_path / "fixed.vhd").write_bytes(disk)
    (tmp_path / "fixed.bin").write_bytes(disk)
    (tmp_path / "small.vhd").write_bytes(b"tiny")
    assert identify_file(tmp_path / "fixed.vhd") == Identification("disk_image", "signature", "VHD, fixed")
    assert identify_file(tmp_path / "fixed.bin").artifact is None
    assert identify_file(tmp_path / "small.vhd").artifact is None
    assert identify_bytes("fixed.vhd", disk[:8192], disk[-512:]).detail == "VHD, fixed"
    assert identify_bytes("fixed.vhd", disk[:8192]).artifact is None   # without the footer


@pytest.mark.parametrize(("at", "detail"), [
    ({**BOOT, 3: b"NTFS    "}, "raw image, NTFS volume"),
    ({**BOOT, 3: b"EXFAT   "}, "raw image, exFAT volume"),
    ({**BOOT, 3: b"MSDOS5.0", 54: b"FAT16   "}, "raw image, FAT volume"),
    ({**BOOT, 3: b"MSDOS5.0", 82: b"FAT32   "}, "raw image, FAT volume"),
    ({**BOOT, 450: b"\xee", 512: b"EFI PART"}, "raw image, GPT disk"),
    ({**BOOT, 450: b"\xee", 4096: b"EFI PART"}, "raw image, GPT disk"),   # a disk of 4,096-byte sectors
    ({**BOOT, 446: b"\x80"}, "raw image, MBR disk"),
    ({**BOOT, 446: b"\x7f"}, "raw image"),
    ({3: b"ReFS\x00\x00\x00\x00", 16: b"FSRS"}, "raw image, ReFS volume"),   # a ReFS boot sector has no 0x55AA
])
def test_raw_image_needs_the_boot_signature_and_an_image_name(at, detail):
    """A raw image has no signature of its own, so it needs both an image name and a boot sector, whose file system
    name or partition table says what it holds."""
    header = sector(at)
    for name in ("disk.dd", "disk.raw", "disk.IMG", "Winserpart.001"):
        assert identify_bytes(name, header) == Identification("disk_image", "signature", detail), name
    for name in ("disk.bin", "disk.002", "$Boot", "_Boot", "memory.dmp"):
        assert identify_bytes(name, header).artifact is None, name
    assert identify_bytes("disk.dd", sector({3: b"NTFS    "})).artifact is None   # no boot signature
    assert identify_bytes("disk.raw", b"\x01" * 8192).artifact is None


MD5 = bytes(range(1, 17))
SHA1 = bytes(range(101, 121))
CHAIN_START = 13   # the descriptor of a segment's first section
DESCRIPTOR = 76


def descriptor(kind: bytes, following: int) -> bytes:
    """A section's descriptor, checksummed, with its next offset as given."""
    covered = kind.ljust(16, b"\x00") + following.to_bytes(8, "little") + DESCRIPTOR.to_bytes(8, "little") + bytes(40)
    return covered + zlib.adler32(covered).to_bytes(4, "little")


def stored(tmp_path, data: bytes) -> tuple[str, str]:
    path = tmp_path / "image.E01"
    path.write_bytes(data)
    return stored_hashes(path)


def test_an_e01_stores_its_md5_and_sha1_in_its_digest_section(tmp_path):
    """The digest section holds both hashes, and a chain of other sections comes before it."""
    data = e01_segment((b"volume", bytes(94)), (b"sectors", bytes(512)), (b"table", bytes(64)),
                       e01_digest(MD5, SHA1), e01_hash(MD5), (b"done", b""), segment=4)
    assert stored(tmp_path, data) == (MD5.hex(), SHA1.hex())


def test_an_e01_with_a_hash_section_alone_has_its_md5_alone(tmp_path):
    assert stored(tmp_path, e01_segment(e01_hash(MD5), (b"done", b""))) == (MD5.hex(), "")


def test_a_digest_of_zeros_gives_way_to_the_hash_section(tmp_path):
    """A tool writes zeros for a hash it didn't compute, so they aren't a hash."""
    data = e01_segment(e01_digest(bytes(16), bytes(20)), e01_hash(MD5), (b"done", b""))
    assert stored(tmp_path, data) == (MD5.hex(), "")


def test_a_segment_before_the_last_stores_no_hash_and_its_chain_ends_at_next(tmp_path):
    """The walk stops at a next section, so a digest past it isn't read."""
    data = e01_segment((b"sectors", bytes(512)), (b"next", b""), e01_digest(MD5, SHA1), segment=2)
    assert stored(tmp_path, data) == ("", "")


def test_a_hash_section_that_fails_its_checksum_gives_nothing(tmp_path):
    kind, body = e01_digest(MD5, SHA1)
    assert stored(tmp_path, e01_segment((kind, b"\xff" + body[1:]), (b"done", b""))) == ("", "")


def test_a_descriptor_that_fails_its_checksum_ends_the_walk(tmp_path):
    data = bytearray(e01_segment((b"sectors", bytes(512)), e01_digest(MD5, SHA1), (b"done", b"")))
    data[CHAIN_START] ^= 0xff
    assert stored(tmp_path, bytes(data)) == ("", "")


@pytest.mark.parametrize("data", [b"", b"EVF\x09\x0d\x0a\xff\x00\x01\x01\x00\x00\x00", EWF_HEADER + bytes(64),
                                  e01_segment(e01_digest(MD5, SHA1))[:-20]])
def test_a_short_or_empty_segment_stores_no_hash(tmp_path, data):
    assert stored(tmp_path, data) == ("", "")


def test_a_section_pointing_back_ends_the_walk(tmp_path):
    """Each section's offset must move forward, so a digest that only a step back reaches isn't read."""
    kind, body = e01_digest(MD5, SHA1)
    digest_at = CHAIN_START + DESCRIPTOR
    back_at = digest_at + DESCRIPTOR + len(body)
    data = (EWF_HEADER + bytes(4) + descriptor(b"sectors", back_at) + descriptor(kind, back_at) + body
            + descriptor(b"sectors", digest_at) + bytes(16))
    assert stored(tmp_path, data) == ("", "")


@pytest.mark.parametrize("following", [2 ** 63, 2 ** 64 - 1, 10_000])
def test_a_next_offset_past_the_file_ends_the_walk(tmp_path, following):
    """An offset too large to seek to raises no error, and hashes read before it stay."""
    kind, body = e01_hash(MD5)
    data = EWF_HEADER + bytes(4) + descriptor(kind, following) + body
    assert stored(tmp_path, data) == (MD5.hex(), "")


def test_two_digest_sections_never_mix_their_hashes(tmp_path):
    """The first digest section with a hash gives it, so the MD5 and SHA-1 come from one section."""
    data = e01_segment(e01_digest(MD5, SHA1), e01_digest(bytes(range(16)), bytes(range(20))), (b"done", b""))
    assert stored(tmp_path, data) == (MD5.hex(), SHA1.hex())


def test_the_stored_hashes_follow_a_changed_file(tmp_path):
    """The cache goes by the file's size and time, so a file that changed either one is read again."""
    path = tmp_path / "image.E01"
    other_md5, other_sha1 = bytes(range(16)), bytes(range(20))
    path.write_bytes(e01_segment(e01_digest(MD5, SHA1), (b"done", b"")))
    assert stored_hashes(path) == (MD5.hex(), SHA1.hex())
    at = path.stat().st_mtime_ns
    path.write_bytes(e01_segment(e01_digest(other_md5, other_sha1), (b"done", b"")))
    os.utime(path, ns=(at + 1_000_000_000, at + 1_000_000_000))
    assert stored_hashes(path) == (other_md5.hex(), other_sha1.hex())
    path.write_bytes(e01_segment(e01_hash(MD5), e01_digest(MD5, SHA1), (b"done", b"")))
    os.utime(path, ns=(at + 1_000_000_000, at + 1_000_000_000))
    assert stored_hashes(path) == (MD5.hex(), SHA1.hex())


def test_a_collected_boot_file_is_no_disk_image():
    """A collection's $Boot holds the volume's boot sector, as an NTFS volume image starts. Its name keeps it out."""
    boot = sector({0: b"\xebR\x90", 3: b"NTFS    ", **BOOT})
    assert identify_bytes("$Boot", boot) == Identification(None, "unidentified", "")
    assert identify_bytes("volume.dd", boot).detail == "raw image, NTFS volume"


def test_existing_signatures_win_over_image_checks():
    """The image checks run after every other one, so a file with another signature keeps its identification,
    whatever its name. Each file has an image's name and the boot signature, so the image checks would take it for a raw
    image if they ran first."""
    assert identify_bytes("x.img", sector({0: b"regf", **BOOT})) == Identification("registry", "signature", "unknown hive")
    assert identify_bytes("Security.001", sector({0: b"ElfFile\x00", **BOOT})).artifact == "evtx"
    assert identify_bytes("History.dd", sector({0: b"SQLite format 3\x00", **BOOT})).artifact == "sqlite"
    assert identify_bytes("capture.raw", sector({0: b"\xd4\xc3\xb2\xa1", **BOOT})).artifact == "pcap"
    assert identify_bytes("$MFT", sector({0: b"FILE0", **BOOT})).artifact == "mft"


def test_an_image_note_for_the_formats_that_need_one():
    assert image_note("raw image, ReFS volume") == ("A ReFS volume's extracted files hold no $MFT or $J for the file "
                                                    "system tools.")
    assert image_note("AD1 logical image") == "An AD1 image holds files, not a volume: export its files first."
    assert image_note("L01 segment 2") == "An L01 image holds files, not a volume: export its files first."
    assert image_note("Lx01") == "An Lx01 image holds files, not a volume: export its files first."
    assert image_note("E01 segment 1") == image_note("Ex01") == image_note("raw image, NTFS volume") == ""
