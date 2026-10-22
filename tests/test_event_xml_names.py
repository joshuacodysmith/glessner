"""The built-in event XML reader and its run with a file name that holds an unpaired surrogate, which Windows allows, or
characters a console code page can't write."""

import io
import subprocess
import sys
from pathlib import Path

import pytest
from test_event_xml import events_file, rdp_logon, rows

from glessner import event_xml
from glessner.case import create_case
from glessner.events import connect
from glessner.intake import intake
from glessner.runner import INPUT_LIST, plan_runs, read_runs, run
from glessner.tools import detect, load_registry

NAME = "Sec\udc80.xml"
SHOWN = "Sec\ufffd.xml"   # how the converter and the events table write the name
JAPANESE = "\u30a4\u30d9\u30f3\u30c8.xml"   # a name that is not a lone surrogate, which cp1252 can't write either
NAMES = pytest.mark.parametrize(("name", "shown"), [(NAME, SHOWN), (JAPANESE, JAPANESE)], ids=["surrogate", "japanese"])

SOURCE_FOLDER = Path(event_xml.__file__).resolve().parents[1]   # the folder that holds the package under test
# What `python -I -m glessner.event_xml` does, importing the package from SOURCE_FOLDER rather than from the environment
START = ("import sys; sys.path.insert(0, sys.argv[1]); from glessner import event_xml; "
         "sys.exit(event_xml.main(sys.argv[2:]))")
# Python's -I ignores PYTHONIOENCODING and PYTHONUTF8, and -X utf8=0 keeps the code page for a stream sent to a file
CHILD = ["-I", "-X", "utf8=0", "-c", START, str(SOURCE_FOLDER)]


def started_as_the_runner_starts_it(calls):
    """A stand-in for subprocess.run that starts the event XML reader as a child process, as the runner does with its
    streams sent to files, but imports the package under test."""
    real = subprocess.run

    def start(argv, **options):
        calls.append(argv)
        return real([argv[0], *CHILD, *argv[-2:]], **options)
    return start


def listed(tmp_path, name, text=None):
    """An event file called `name`, a listing of it as the runner writes one, and an empty output folder."""
    source = tmp_path / name
    source.write_text(events_file(rdp_logon(1, "SRV", "10.0.0.8")) if text is None else text, encoding="utf-8")
    listing = tmp_path / INPUT_LIST
    listing.write_bytes(f"{source}\n".encode("utf-8", "surrogatepass"))
    out = tmp_path / "out"
    out.mkdir()
    return source, listing, out


def case_with_named_file(tmp_path):
    evidence = tmp_path / "evidence"
    (evidence / "HOST").mkdir(parents=True)
    (evidence / "HOST" / NAME).write_text(events_file(rdp_logon(1, "HOST", "10.0.0.8")), encoding="utf-8")
    case = create_case(tmp_path / "case", "XML", evidence, "cody")
    intake(case)
    tool = detect([load_registry()["event_xml"]], None)["event_xml"]
    (plan,) = plan_runs(case, tool)
    assert plan.inputs == (f"HOST/{NAME}",)
    return case, plan


def test_the_reader_opens_a_name_with_a_surrogate_and_writes_it_as_a_replacement_character(tmp_path, capsys):
    source, listing, out = listed(tmp_path, NAME)
    assert event_xml.main([str(listing), str(out)]) == 0
    (row,) = rows(out)
    assert row["SourceFile"] == str(source).replace("\udc80", "\ufffd")
    assert f"{SHOWN}: 1 events" in capsys.readouterr().out


def test_an_unreadable_file_with_a_surrogate_in_its_name_is_named_in_the_error(tmp_path, capsys):
    absent = tmp_path / "absent\udc81.xml"
    _, listing, out = listed(tmp_path, NAME, events_file(rdp_logon(1, "SRV", "10.0.0.8"))[:-30])   # cut off mid-event
    assert event_xml.main([str(listing), str(out)]) == 3
    assert f"{SHOWN}: " in capsys.readouterr().err
    listing.write_bytes(f"{absent}\n".encode("utf-8", "surrogatepass"))
    assert event_xml.main([str(listing), str(out)]) == 3
    assert "absent" in capsys.readouterr().err


@NAMES
def test_the_reader_writes_utf8_to_streams_that_have_a_code_page(tmp_path, monkeypatch, name, shown):
    source, listing, out = listed(tmp_path, name)
    stdout, stderr = io.BytesIO(), io.BytesIO()
    monkeypatch.setattr(sys, "stdout", io.TextIOWrapper(stdout, encoding="cp1252"))
    monkeypatch.setattr(sys, "stderr", io.TextIOWrapper(stderr, encoding="cp1252", errors="backslashreplace"))
    assert event_xml.main([str(listing), str(out)]) == 0
    sys.stdout.flush()
    assert f"{shown}: 1 events" in stdout.getvalue().decode("utf-8")
    assert rows(out)[0]["SourceFile"] == str(source).replace("\udc80", "\ufffd")
    source.write_text(events_file(rdp_logon(1, "SRV", "10.0.0.8"))[:-30], encoding="utf-8")   # cut off mid-event
    assert event_xml.main([str(listing), str(out)]) == 3
    sys.stderr.flush()
    assert f"{shown}: " in stderr.getvalue().decode("utf-8")


@NAMES
def test_the_reader_started_as_a_child_with_its_output_in_files_reads_any_name(tmp_path, name, shown):
    source, listing, out = listed(tmp_path, name)
    with (tmp_path / "stdout.txt").open("wb") as stdout, (tmp_path / "stderr.txt").open("wb") as stderr:
        result = subprocess.run([sys.executable, *CHILD, str(listing), str(out)], stdout=stdout, stderr=stderr,
                                stdin=subprocess.DEVNULL, check=False)
    assert result.returncode == 0, (tmp_path / "stderr.txt").read_bytes().decode("utf-8", "replace")
    assert rows(out)[0]["SourceFile"] == str(source).replace("\udc80", "\ufffd")
    assert f"{shown}: 1 events" in (tmp_path / "stdout.txt").read_bytes().decode("utf-8")


def test_a_run_on_a_file_with_a_surrogate_in_its_name_is_recorded_and_loads(tmp_path, monkeypatch):
    case, plan = case_with_named_file(tmp_path)
    calls = []
    monkeypatch.setattr("glessner.runner.subprocess.run", started_as_the_runner_starts_it(calls))
    record = run(case, plan)
    assert (record.status, record.reason, record.loaded_rows, record.evidence_check) == ("ok", "", 1, "ok")
    assert [r.run_id for r in read_runs(case)] == [record.run_id]
    listed_inputs = (case.runs_folder / record.run_id / INPUT_LIST).read_text(encoding="utf-8", errors="surrogatepass")
    assert listed_inputs == f"{case.evidence / 'HOST' / NAME}\n"
    con = connect(case.db_path, read_only=True)
    try:
        assert con.execute("SELECT source_file FROM events").fetchall() == [(f"HOST/{SHOWN}",)]
    finally:
        con.close()


def test_a_run_whose_input_list_cannot_be_written_fails_with_its_record_and_starts_no_tool(tmp_path, monkeypatch):
    case, plan = case_with_named_file(tmp_path)
    calls = []
    monkeypatch.setattr("glessner.runner.subprocess.run", started_as_the_runner_starts_it(calls))
    write_text = Path.write_text

    def refuse(self, *args, **options):
        if self.name == INPUT_LIST:
            raise OSError("the disk is full")
        return write_text(self, *args, **options)

    monkeypatch.setattr(Path, "write_text", refuse)
    record = run(case, plan)
    assert (record.status, record.reason) == ("failed", "could not write the input list: the disk is full")
    assert calls == []
    (saved,) = read_runs(case)
    assert (saved.status, saved.reason) == (record.status, record.reason)
