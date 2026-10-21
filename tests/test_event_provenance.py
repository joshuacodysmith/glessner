"""The Event page's provenance line for a file intake couldn't read, and for a file whose checks follow a line of the
check log that can't be read."""

from conftest import DC_LOG
from test_overview import evidence_log, held_open

from glessner import intake as intake_module
from glessner.intake import intake, verify
from glessner.server import App, api_case_state, api_event


def provenance(app):
    """The provenance of one event read from the case's DC01 Security log."""
    uid = app.con.execute("SELECT event_uid FROM events WHERE source_file = ? LIMIT 1", [DC_LOG]).fetchone()[0]
    found = api_event(app, {"uid": [uid]})["event"]["provenance"]
    return found["state"], found["text"]


def test_a_file_intake_could_not_read_says_so_rather_than_that_the_manifest_leaves_it_out(synthetic_case, monkeypatch):
    evidence_log(synthetic_case)
    with monkeypatch.context() as m:
        m.setattr(intake_module, "sha256_file", held_open("Security.evtx"))
        intake(synthetic_case)
    app = App(synthetic_case)
    try:
        assert provenance(app) == ("unreadable", "intake could not read this file, so it has no hash to check")
    finally:
        app.con.close()


def test_a_full_re_hash_that_matches_clears_the_unreadable_check_log_line_before_it(synthetic_case):
    """A line of the check log that can't be read may have named the file, so the Event page doesn't say it matches.
    A full re-hash after it that matches checked every file, so the page says it matches again, and the header's state
    counts no such line."""
    evidence_log(synthetic_case)
    intake(synthetic_case)
    assert verify(synthetic_case, reason="manual full verification") == []
    with synthetic_case.verification_path.open("ab") as f:
        f.write(b"\0" * 64)
    assert verify(synthetic_case, [DC_LOG], reason="after a run") == []
    app = App(synthetic_case)
    try:
        assert provenance(app) == ("uncounted", "no readable check found it changed; 1 check-log line unreadable")
        assert verify(synthetic_case, reason="manual full verification") == []
        assert provenance(app) == ("matches", "matches intake")
        assert api_case_state(app, {})["checks"]["unreadable_lines"] == 0
    finally:
        app.con.close()
