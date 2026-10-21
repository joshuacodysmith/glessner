"""A count on the command line reads in its number, as the page's does."""

from __future__ import annotations

from conftest import SEC, T0

from glessner.cli import main, orphan_warning, plural
from glessner.events import from_us
from glessner.server import App, api_mark


def test_plural_follows_the_count():
    assert [plural(n, "file") for n in (0, 1, 2, 1234)] == ["0 files", "1 file", "2 files", "1,234 files"]
    assert plural(1, "malicious or suspicious event") == "1 malicious or suspicious event"
    assert plural(2, "copy", "copies") == "2 copies"


def test_the_case_open_warning_for_marks_without_events_reads_in_its_number():
    assert orphan_warning(1) == "Warning: 1 mark refers to an event that no longer exists."
    assert orphan_warning(2) == "Warning: 2 marks refer to events that no longer exist."
    assert orphan_warning(1200) == "Warning: 1,200 marks refer to events that no longer exist."


def test_a_command_with_one_of_something_says_so(synthetic_case, capsys):
    folder = str(synthetic_case.folder)
    (synthetic_case.evidence / "DC01" / "Security.evtx").write_bytes(b"ElfFile\x00x")
    assert main(["intake", folder]) == 0
    assert capsys.readouterr().out.startswith("1 file, ")
    (synthetic_case.evidence / "DESKTOP" / "Security.evtx").write_bytes(b"ElfFile\x00y")
    assert main(["intake", folder, "--add"]) == 0
    assert capsys.readouterr().out.startswith("1 new file, ")

    assert main(["close", folder]) == 0
    assert "Case closed. All 2 evidence files match the intake manifest." in capsys.readouterr().out
    (synthetic_case.evidence / "DESKTOP" / "Security.evtx").write_bytes(b"ElfFile\x00z")
    assert main(["close", folder]) == 1
    assert capsys.readouterr().out.startswith("Case closed with 1 evidence problem, ")
    assert main(["verify", folder]) == 1
    assert capsys.readouterr().out.startswith("1 problem:")

    # a window holding one event, and the findings summary of one marked event
    start = from_us(T0 + 60 * SEC).strftime("%Y-%m-%dT%H:%M:%SZ")
    end = from_us(T0 + 61 * SEC).strftime("%Y-%m-%dT%H:%M:%SZ")
    assert main(["export", folder, "--start", start, "--end", end]) == 0
    assert capsys.readouterr().out.startswith("Wrote 1 event to ")
    app = App(synthetic_case)
    try:
        uid = app.con.execute("SELECT event_uid FROM events WHERE tool = 'evtxecmd' AND ts_us = ?",
                              [T0 + 60 * SEC]).fetchone()[0]
        api_mark(app, {"uids": [uid], "value": "malicious"})
    finally:
        app.con.close()
    assert main(["findings", folder]) == 0
    assert "(1 malicious or suspicious event)" in capsys.readouterr().out


def test_the_close_command_says_the_one_evidence_file_matches(synthetic_case, capsys):
    (synthetic_case.evidence / "DC01" / "Security.evtx").write_bytes(b"ElfFile\x00x")
    assert main(["intake", str(synthetic_case.folder)]) == 0
    capsys.readouterr()
    assert main(["close", str(synthetic_case.folder)]) == 0
    assert "Case closed. The 1 evidence file matches the intake manifest." in capsys.readouterr().out


def test_serve_prints_the_warning_for_marks_without_events_in_its_number(synthetic_case, capsys, monkeypatch):
    """The serve command's startup line is its own call of orphan_warning, so the function's test alone doesn't cover
    the line's wording."""
    from glessner import server
    from glessner.events import event_uid
    from glessner.journal import Journal

    Journal(synthetic_case).append("mark", targets=[event_uid("DC01", "evtx", "DC01/gone.evtx", "1", "Event Recorded")],
                                   value="malicious")

    def stop(self, *args, **kwargs):   # the server's loop: Ctrl+C at once
        raise KeyboardInterrupt

    monkeypatch.setattr(server.ThreadingHTTPServer, "serve_forever", stop)
    assert main(["serve", str(synthetic_case.folder), "--no-browser", "--port", "0"]) == 0
    assert "Warning: 1 mark refers to an event that no longer exists.\n" in capsys.readouterr().out
