"""The report's evidence re-hash runs without the case lock, and its preview lists a bounded number of events."""

import re
import threading
from pathlib import Path

import pytest
from conftest import SEC, T0, flip_a_byte
from test_report import section, uid_at

from glessner import server
from glessner.intake import add_new, intake, sha256_file
from glessner.journal import JournalError
from glessner.server import App, api_mark, api_report, api_report_preview

ENTRY = re.compile(r"^\d+\. \*\*", re.MULTILINE)


@pytest.fixture
def app(synthetic_case):
    """An App on a case with an intake manifest, so the report re-hashes its evidence."""
    for name in ("Security.evtx", "System.evtx"):
        (synthetic_case.evidence / "DC01" / name).write_bytes(b"ElfFile\x00" + name.encode())
    intake(synthetic_case)
    app = App(synthetic_case)
    yield app
    app.con.close()


def test_the_report_re_hashes_the_evidence_without_holding_the_case_lock(app, monkeypatch):
    """The report hashes the evidence without holding the case lock, so a marking request, which takes the lock briefly,
    doesn't wait for the hashing."""
    free = []

    def hashing(path):
        def try_lock():
            got = app.lock.acquire(timeout=1)
            free.append(got)
            if got:
                app.lock.release()

        thread = threading.Thread(target=try_lock)
        thread.start()
        thread.join()
        return sha256_file(path)

    monkeypatch.setattr("glessner.intake.sha256_file", hashing)
    res = api_report(app, {})
    assert free and all(free)
    text = Path(res["path"]).read_text(encoding="utf-8")
    assert "Every evidence file (2) was re-hashed when this report was written, and all match the intake manifest." in text


def test_the_report_re_hashes_again_when_the_manifest_changes_while_it_hashes(app, monkeypatch):
    """Evidence added while the report hashes changes the manifest, so the report hashes again and states what the
    manifest then listed."""
    (app.case.evidence / "DC01" / "Added.evtx").write_bytes(b"ElfFile\x00added")
    first = True

    def hashing(path):
        nonlocal first
        if first:
            first = False
            add_new(app.case)
        return sha256_file(path)

    monkeypatch.setattr("glessner.intake.sha256_file", hashing)
    text = Path(api_report(app, {})["path"]).read_text(encoding="utf-8")
    assert "Every evidence file (3) was re-hashed when this report was written" in text


def test_a_journal_break_only_the_full_check_finds_refuses_the_report_before_the_evidence_is_hashed(app, monkeypatch):
    """A journal line changed after the case opened is found by the report's own full check. The report is refused before
    any evidence is hashed, so verification.jsonl gains no re-hash for a report that is never written."""
    api_mark(app, {"uids": [uid_at(app, T0)], "value": "suspicious", "note": "first"})
    path = app.journal.path
    flip_a_byte(path, path.read_bytes().index(b"first"))
    assert not app.journal.read_only

    def recorded():
        file = app.case.verification_path
        return file.read_bytes() if file.exists() else b""

    before = recorded()
    hashed = []
    monkeypatch.setattr("glessner.intake.sha256_file", lambda file: hashed.append(file) or sha256_file(file))
    with pytest.raises(JournalError):
        api_report(app, {})
    assert app.journal.read_only and hashed == [] and recorded() == before


def listed(text):
    return len(ENTRY.findall(section(text, 3)))


def test_the_preview_lists_the_first_events_and_says_how_many_it_leaves_out(app, monkeypatch):
    """The preview lists up to PREVIEW_EVENTS events and says how many it left out; the counts, and the report Write report
    writes, cover and list every marked event."""
    monkeypatch.setattr(server, "PREVIEW_EVENTS", 1)
    for seconds in (0, 60):
        api_mark(app, {"uids": [uid_at(app, T0 + seconds * SEC)], "value": "suspicious"})
    preview = api_report_preview(app, {})
    assert preview["events"] == 2 and listed(preview["text"]) == 1
    assert "The preview lists the first 1 of 2 events. Write report lists them all." in section(preview["text"], 3)
    assert "the 2 events the analyst marked malicious (0) or suspicious (2)" in preview["text"]
    written = Path(api_report(app, {})["path"]).read_text(encoding="utf-8")
    assert listed(written) == 2 and "The preview lists" not in written
    monkeypatch.setattr(server, "PREVIEW_EVENTS", 2)
    assert listed(api_report_preview(app, {})["text"]) == 2
    assert "The preview lists" not in api_report_preview(app, {})["text"]
