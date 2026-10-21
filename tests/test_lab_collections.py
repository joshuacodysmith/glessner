"""Checks identification against the real Szechuan Sauce collections.

Skipped when D:/DFIR-Lab is absent.
"""

from pathlib import Path

import pytest

from glessner.case import create_case
from glessner.intake import intake, read_manifest

COLLECTION = Path("D:/DFIR-Lab/datasets/szechuan-sauce/collection")
HIVE_NAMES = {"SYSTEM", "SOFTWARE", "SAM", "SECURITY", "DEFAULT", "NTUSER.DAT", "USRCLASS.DAT", "AMCACHE.HVE"}

pytestmark = [
    pytest.mark.lab,
    pytest.mark.skipif(not COLLECTION.is_dir(), reason="Szechuan Sauce collection not present"),
]


@pytest.fixture(scope="module")
def manifest(tmp_path_factory):
    case = create_case(tmp_path_factory.mktemp("lab") / "case", "Szechuan Sauce", COLLECTION, "test")
    summary = intake(case)
    return summary, read_manifest(case)


def by_artifact(entries, artifact):
    return {e.path for e in entries if e.artifact == artifact}


def test_every_evtx_file_is_identified(manifest):
    _, entries = manifest
    named = {e.path for e in entries if e.path.lower().endswith(".evtx") and e.size > 0}
    assert named and named == by_artifact(entries, "evtx")


def test_lnk_and_prefetch_match_their_extensions(manifest):
    _, entries = manifest
    assert by_artifact(entries, "lnk") == {e.path for e in entries if e.path.lower().endswith(".lnk")}
    assert by_artifact(entries, "lnk")
    assert by_artifact(entries, "prefetch")  # DESKTOP has prefetch; DC01 does not
    # One DESKTOP prefetch file has a zeroed header. PECmd also rejects it ("Invalid signature!
    # Should be 'SCCA'"), so it must be listed as unidentified with the reason.
    damaged = "DESKTOP/Windows/Prefetch/VSSVC.EXE-6C8F0C66.pf"
    named_pf = {e.path for e in entries if e.path.lower().endswith(".pf")}
    assert by_artifact(entries, "prefetch") == named_pf - {damaged}
    entry = next(e for e in entries if e.path == damaged)
    assert entry.artifact is None and "header is all zero bytes" in entry.detail


def test_both_os_mfts_found(manifest):
    _, entries = manifest
    assert by_artifact(entries, "mft") == {"DC01_mft/$MFT", "DESKTOP_mft/$MFT"}


def test_system_hives_found_for_both_hosts(manifest):
    _, entries = manifest
    # <HOST>_more folders beside the host folders hold more copies of the hives, and aren't hosts of their own.
    system = {e.path.split("/")[0] for e in entries if e.artifact == "registry" and e.detail == "SYSTEM"}
    assert {h for h in system if not h.endswith("_more")} == {"DC01", "DESKTOP"}
    for e in entries:
        if e.artifact == "registry":
            assert e.path.rsplit("/", 1)[-1].upper() in HIVE_NAMES


def test_nothing_unreadable(manifest):
    summary, _ = manifest
    assert summary.errors == []
