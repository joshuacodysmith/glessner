"""Browser tests for what the pages say of disk images, which no tool reads: the Case overview's gap, the Tools page's
list, and the start page's warning under the evidence check. They run as test_browser_smoke.py's do, on the installed
Edge, and are skipped without it."""

import pytest
from conftest import e01_digest, e01_hash, e01_segment, file_sha256
from test_browser_smoke import browser, served_page  # noqa: F401

from glessner.intake import intake
from glessner.tools import load_registry

pytestmark = pytest.mark.browser

REFS_NOTE = "A ReFS volume's extracted files hold no $MFT or $J for the file system tools."


def refs_volume() -> bytes:
    data = bytearray(4096)
    data[3:11] = b"ReFS\x00\x00\x00\x00"
    return bytes(data)


def test_overview_and_tools_list_disk_images_with_the_extraction_step(browser, synthetic_case):  # noqa: F811
    """The Case overview counts the disk image files apart from the unidentified ones and gives the step that comes
    first; See in Tools opens the Tools page's list of them, each with its format and any note on it."""
    ev = synthetic_case.evidence
    md5, sha1 = bytes(range(16)), bytes(range(20))
    (ev / "DC01" / "dc01.E01").write_bytes(e01_segment(e01_digest(md5, sha1), e01_hash(md5), (b"done", b"")))
    (ev / "DESKTOP" / "Winserpart.001").write_bytes(refs_volume())
    (ev / "DC01" / "unknown.bin").write_bytes(b"\x01\x02 nothing known")
    intake(synthetic_case)
    for p in served_page(browser, synthetic_case, tab="overview",
                         setup=lambda app: setattr(app, "tool_cache", (load_registry(), {}))):
        images = p.locator("#ovGaps #ovImages")
        images.wait_for()
        assert images.inner_text() == ("2 disk image files no tool reads, kept in the manifest and hashed. Mount or "
                                       "extract each image first, and point Glessner at the extracted folder. See in Tools")
        assert "1 file intake could not identify, kept in the manifest and hashed." in p.locator("#ovGaps").inner_text()
        images.get_by_role("button", name="See in Tools").click()
        listed = p.locator("#toolsImages:not([hidden])")
        listed.wait_for()
        e01_sha256, raw_sha256 = file_sha256(ev / "DC01" / "dc01.E01"), file_sha256(ev / "DESKTOP" / "Winserpart.001")
        assert listed.locator("li").all_inner_texts() == [
            f"DC01/dc01.E01 (E01 segment 1)\nSHA-256 of this file: {e01_sha256}\nMD5 stored for the disk: {md5.hex()}\n"
            f"SHA-1 stored for the disk: {sha1.hex()}\n"
            "The imaging tool stored these. Glessner doesn't check them against the image's data.",
            f"DESKTOP/Winserpart.001 (raw image, ReFS volume) {REFS_NOTE}\nSHA-256 of this file: {raw_sha256}"]
        unread = p.locator("#details .tools-unread").inner_text()
        assert ("2 disk image files: no tool reads them. Mount or extract each image first, and point Glessner at the "
                "extracted folder. Hide") in unread
        assert "1 unidentified file List" in unread
        assert "disk image: no installed tool reads" not in unread


def test_a_long_image_lists_its_hash_segment_first_and_says_the_list_stops(browser, synthetic_case):  # noqa: F811
    """Only an image's last segment holds its hashes, and the list stops at 50 rows, so that segment comes first."""
    ev = synthetic_case.evidence
    for number in range(1, 51):
        (ev / "DC01" / f"big.E{number:02}").write_bytes(e01_segment((b"next", b""), segment=number))
    md5, sha1 = bytes(range(16)), bytes(range(20))
    (ev / "DC01" / "big.E51").write_bytes(e01_segment(e01_digest(md5, sha1), (b"done", b""), segment=51))
    intake(synthetic_case)
    for p in served_page(browser, synthetic_case, tab="overview",
                         setup=lambda app: setattr(app, "tool_cache", (load_registry(), {}))):
        images = p.locator("#ovGaps #ovImages")
        images.wait_for()
        images.get_by_role("button", name="See in Tools").click()
        listed = p.locator("#toolsImages:not([hidden])")
        listed.wait_for()
        rows = listed.locator("li")
        assert rows.count() == 51
        assert rows.first.inner_text().startswith("DC01/big.E51 (E01 segment 51)")
        assert f"MD5 stored for the disk: {md5.hex()}" in rows.first.inner_text()
        assert rows.last.inner_text() == "The first 50 of 51, those that store hashes first."


def test_start_page_names_a_disk_image_under_the_evidence_check(browser, tmp_path):  # noqa: F811
    """A folder that holds a disk image passes the evidence check, with a warning under it that names the image and the
    step that comes first. The case can still be created."""
    ev = tmp_path / "winserpart"
    ev.mkdir()
    (ev / "Winserpart.001").write_bytes(refs_volume())
    for page in served_page(browser, None, ready="() => window.__start && window.__start.info !== null"):
        start = page.locator("#start")
        warning = start.locator("[data-check='evidence-images']")
        assert warning.is_hidden()
        start.get_by_label("Case name").fill("Image")
        start.get_by_label("Case folder", exact=True).fill(str(tmp_path / "cases" / "image"))
        start.get_by_label("Evidence folder").fill(str(ev))
        warning.wait_for()
        assert warning.inner_text() == ("Winserpart.001 (raw image, ReFS volume) is a disk image, which Glessner doesn't "
                                        f"read. Mount or extract it first, and choose the extracted folder. {REFS_NOTE}")
        page.wait_for_selector("#start [data-check='evidence'].ok")
        assert start.locator("[data-check='evidence-copies']").is_hidden()
        assert start.get_by_role("button", name="Create case and take in evidence").is_enabled()
