"""One file's hashes as each source that records them writes them: Amcache, Autoruns, Sysmon, Suricata's fileinfo, and Zeek's
files log, each holding coreupdater.exe's SHA-1 with the other algorithms it records, plus an import hash and an
Authenticode hash that must join nothing. Built as tests/pivot_key_fixtures.py builds its tool output, through the parsers."""

import json
from pathlib import Path

from pivot_key_fixtures import AUTORUNS_COLUMNS, autoruns_row, csv_file, folder_of, run
from rekey_fixtures import AMCACHE_FILE, write_rows
from test_parsers import EVTX_COLUMNS, sysmon_row
from test_parsers import write_csv as write_evtx

from glessner.parsers import PARSERS, ParseContext

CORE = "C:\\Windows\\System32\\coreupdater.exe"
SHA1 = "fd153c66386ca93ec9993d66a84d6f0d129a3a5c"   # coreupdater.exe's, as Szechuan's Amcache records it
MD5 = "0dd3d3b8bc3d4ee0bb1d6a1b9f4e2c77"
SHA256 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
IMPHASH = "f34d5f2d4577ed6d9ceec516c1f5a744"   # the same imports: other programs share it
PESHA1 = "7c4a8d09ca3762af61e59520943dc26494f8941b"   # Authenticode's hash, which no other source records
OTHER256 = "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"   # another file: a DLL that shares the imphash
AUTORUNS_HASHES = ["MD5", "SHA-1", "PESHA-1", "SHA-256", "PESHA-256", "IMP"]


def amcache(parent: Path) -> list:
    """An Amcache file entry whose SHA1 is in Amcache's FileId form, 0000 and the SHA-1, as some versions write it."""
    out = folder_of(parent, "amcache")
    write_rows(out / "2024_Amcache_UnassociatedFileEntries.csv", AMCACHE_FILE, [
        {"FileKeyLastWriteTimestamp": "2020-09-19 03:40:45", "FullPath": CORE.lower(), "SHA1": "0000" + SHA1}])
    return list(PARSERS["amcache_csv"](ParseContext(out, parent, ("DESKTOP/Windows/appcompat/Programs/Amcache.hve",))))


def autoruns(parent: Path) -> list:
    """An Autoruns service entry with the hashes -h writes, in upper case, and its PESHA and import hash."""
    out = folder_of(parent, "autoruns")
    entry = {**autoruns_row("CoreUpdater", CORE.lower(), CORE), "Entry Location": "HKLM\\System\\CurrentControlSet\\Services",
             "Category": "Services", "MD5": MD5.upper(), "SHA-1": SHA1.upper(), "PESHA-1": PESHA1.upper(),
             "SHA-256": SHA256.upper(), "PESHA-256": "", "IMP": IMPHASH.upper()}
    csv_file(out / "autoruns.csv", AUTORUNS_COLUMNS + AUTORUNS_HASHES, [entry])
    return run("autoruns_csv", out, root=parent)


def sysmon(parent: Path) -> list:
    """Sysmon's 1, the program's start, with its SHA-1, MD5, SHA-256, and import hash; and a 7, a DLL that shares only
    the import hash."""
    out = folder_of(parent, "sysmon")
    write_evtx(out / "evtxecmd.csv", EVTX_COLUMNS, [
        sysmon_row(1, 1, "Process creation", {
            "Image": CORE, "CommandLine": CORE, "ProcessGuid": "{1}", "ProcessId": "4321", "User": "C137\\Administrator",
            "LogonId": "0x510986",
            "Hashes": f"SHA1={SHA1.upper()},MD5={MD5.upper()},SHA256={SHA256.upper()},IMPHASH={IMPHASH.upper()}"}),
        sysmon_row(2, 7, "Image loaded", {
            "Image": CORE, "ImageLoaded": "C:\\Windows\\System32\\other.dll", "ProcessGuid": "{1}", "ProcessId": "4321",
            "Hashes": f"SHA256={OTHER256.upper()},IMPHASH={IMPHASH.upper()}"}),
    ])
    return list(PARSERS["evtxecmd_csv"](ParseContext(out, parent)))


def suricata(parent: Path) -> list:
    """Suricata's fileinfo for the download, its file hashing on."""
    out = folder_of(parent, "suricata")
    record = {"timestamp": "2020-09-19T03:21:49.000000+0000", "event_type": "fileinfo", "flow_id": 31,
              "src_ip": "194.61.24.102", "src_port": 80, "dest_ip": "10.42.85.115", "dest_port": 49752, "proto": "TCP",
              "fileinfo": {"filename": "/coreupdater.exe", "size": 7168, "md5": MD5, "sha1": SHA1, "sha256": SHA256}}
    (out / "eve.json").write_text(json.dumps(record) + "\n", encoding="utf-8")
    return list(PARSERS["suricata_eve"](ParseContext(out, parent, ("SENSOR/capture.pcap",))))


# Zeek's files log: the download, and a file whose SHA-1 equals the Autoruns entry's PESHA-1
ZEEK_FILES = [{"ts": 1600485710.0, "fuid": "F1", "source": "HTTP", "filename": "coreupdater.exe", "md5": MD5,
               "sha1": SHA1},
              {"ts": 1600485711.0, "fuid": "F2", "source": "HTTP", "filename": "other.bin", "sha1": PESHA1}]


def zeek_files(evidence: Path, host: str = "SENSOR") -> str:
    """The files log in the evidence, for an import with the Zeek preset; its evidence path."""
    path = evidence / host / "files.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(r) + "\n" for r in ZEEK_FILES), encoding="utf-8")
    return f"{host}/files.json"


def hash_events(parent: Path) -> dict[str, tuple[str, list]]:
    """Each source's events by the host and the tool that load them."""
    parent.mkdir(parents=True, exist_ok=True)
    return {"amcache": ("DESKTOP", "amcacheparser", amcache(parent)),
            "autoruns": ("DESKTOP", "autoruns", autoruns(parent)),
            "sysmon": ("DESKTOP", "evtxecmd", sysmon(parent)),
            "suricata": ("SENSOR", "suricata", suricata(parent))}
