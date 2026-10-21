"""A folder intake couldn't list is counted and worded as a folder, never as an evidence file, since how many files it
holds is unknown: in the report's evidence check, the close's journal entry and its line in the audit trail, the
header's case state, the overview's Integrity and Gaps, and the Findings page's count of the files the report
re-hashes."""

import os

import pytest

from glessner import cli
from glessner import intake as intake_module
from glessner.audit import describe, read_entries
from glessner.case import create_case
from glessner.intake import intake
from glessner.server import App, api_case_state, api_exports_page, api_overview, api_report

FOLDER = ("1 folder could not be listed at intake, so no check can show that the files it held then are unchanged "
          "since intake")
LOCKED = "1 evidence file could not be read at intake"


@pytest.fixture(params=[False, True], ids=["folder", "folder and file"])
def shut_case(request, tmp_path, monkeypatch):
    """A case whose intake couldn't list HOST/shut, a folder of two files, beside HOST/open.txt, which it hashed. With
    the param true, intake couldn't read HOST/locked.bin either, as when another program holds it open."""
    ev = tmp_path / "evidence"
    for rel in ("HOST/open.txt", "HOST/locked.bin", "HOST/shut/a.txt", "HOST/shut/b.txt"):
        (ev / rel).parent.mkdir(parents=True, exist_ok=True)
        (ev / rel).write_bytes(rel.encode())
    if not request.param:
        (ev / "HOST" / "locked.bin").unlink()
    real_scandir, real_sha256 = os.scandir, intake_module.sha256_file

    def scandir(path="."):   # as a folder whose ACL denies listing it
        if os.fspath(path).endswith("shut"):
            raise PermissionError(13, "Access is denied")
        return real_scandir(path)

    def sha256_file(path):
        if path.name == "locked.bin":
            raise PermissionError(13, "The process cannot access the file")
        return real_sha256(path)

    case = create_case(tmp_path / "case", "Shut", ev, "cody")
    with monkeypatch.context() as m:
        m.setattr(os, "scandir", scandir)
        m.setattr(intake_module, "sha256_file", sha256_file)
        intake(case)
    return case, request.param


def test_the_report_counts_the_folder_apart_from_the_evidence_files(shut_case):
    case, locked = shut_case
    app = App(case)
    try:
        report = (case.folder / api_report(app, {})["path"]).read_text(encoding="utf-8")
    finally:
        app.con.close()
    if locked:
        assert ("1 of the 2 evidence files was re-hashed when this report was written, and none differs from the intake "
                f"manifest. {LOCKED}, so it has no hash to check and is unverified: HOST/locked.bin. {FOLDER}: "
                "HOST/shut.") in report
    else:
        assert ("1 evidence file was re-hashed when this report was written, and none differs from the intake manifest. "
                f"{FOLDER}: HOST/shut.") in report


def test_the_close_journals_the_folder_apart_and_the_trail_says_so(shut_case, capsys):
    case, locked = shut_case
    assert cli.cmd_close(case, None) == 0
    out = capsys.readouterr().out
    assert f"{FOLDER}: HOST/shut. Recorded in the journal." in out
    close = read_entries(case.folder / "journal.jsonl")[-1]
    value = close["value"]
    assert (value["evidence_files"], value["unverified"], value["unlisted_folders"]) == (1, int(locked), 1)
    assert describe(close).startswith(
        "Closed the case. The 1 evidence file intake hashed matches the intake manifest."
        + (f" {LOCKED} and is unverified." if locked else "") + f" {FOLDER}. The journal's ")


def test_a_close_without_unlisted_folders_reads_its_unverified_count_as_files():
    """A close entry without unlisted_folders reads its unverified count as files."""
    close = {"action": "case_setting", "name": "closed",
             "value": {"hash_check": "ok", "evidence_files": 1, "unverified": 2}}
    assert describe(close) == ("Closed the case. The 1 evidence file intake hashed matches the intake manifest. 2 "
                               "evidence files could not be read at intake and are unverified.")


def test_the_header_state_counts_the_folder_apart_from_the_files_intake_could_not_read(shut_case):
    case, locked = shut_case
    app = App(case)
    try:
        state = api_case_state(app, {})
    finally:
        app.con.close()
    assert (state["evidence_files"], state["unreadable"], state["unlisted"]) == (1, int(locked), 1)


def test_the_overview_counts_the_folder_apart_from_the_files_intake_could_not_read(shut_case):
    """The overview's Integrity counts the folder apart from the files intake couldn't read, and its Gaps list the
    folder on its own, with the error that kept it from being listed."""
    case, locked = shut_case
    app = App(case)
    try:
        ov = api_overview(app, {})
    finally:
        app.con.close()
    integrity, gaps = ov["integrity"], ov["gaps"]
    assert (integrity["evidence_files"], integrity["unreadable"], integrity["unlisted"]) == (1, int(locked), 1)
    assert [f["path"] for f in gaps["unreadable"]] == (["HOST/locked.bin"] if locked else [])
    assert gaps["unlisted"] == [{"path": "HOST/shut", "error": "PermissionError: [Errno 13] Access is denied", "added": ""}]


def test_the_findings_page_counts_only_the_files_the_report_re_hashes(shut_case):
    """The report's outline says how many files it re-hashes when written: neither the folder nor a file intake
    couldn't read is one."""
    case, _ = shut_case
    app = App(case)
    try:
        assert api_exports_page(app, {})["evidence_files"] == 1
    finally:
        app.con.close()
