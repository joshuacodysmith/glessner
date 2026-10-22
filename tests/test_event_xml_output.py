"""The built-in event XML reader started with `python -I`, as the runner starts it, with its output sent to a file, as the
runner sends it, or to a pipe. A stream takes the locale's code page unless the reader sets UTF-8, and the name of a file in
another script must not stop the run. test_event_xml_names.py covers stdout sent to a file. The tests skip on a host whose
code page can write the name, because they would pass without the reader setting UTF-8."""

import subprocess
import sys

import pytest
from test_event_xml import events_file, rdp_logon, rows
from test_event_xml_names import CHILD, JAPANESE, listed

TIMEOUT_SECONDS = 60
FLAGS = CHILD[:CHILD.index("-c")]   # the child's interpreter options before its script: the runner's -I, and -X utf8=0


def writes_japanese(encoding):
    try:
        JAPANESE.encode(encoding)
    except UnicodeEncodeError:
        return False
    return True


@pytest.fixture(scope="module", autouse=True)
def code_page_cannot_write_the_name():
    """Skips the module when a child's stdout or stderr can write JAPANESE, as on a UTF-8 locale or a Japanese code page."""
    probe = subprocess.run([sys.executable, *FLAGS, "-c", "import sys; print(sys.stdout.encoding, sys.stderr.encoding)"],
                           capture_output=True, stdin=subprocess.DEVNULL, timeout=TIMEOUT_SECONDS, check=True)
    writable = sorted({encoding for encoding in probe.stdout.decode("ascii").split() if writes_japanese(encoding)})
    if writable:
        pytest.skip(f"a child's stdout or stderr uses {' and '.join(writable)}, which can write the Japanese file name")


def into_files(argv, tmp_path):
    """The child's exit code, stdout, and stderr, with the two streams sent to files."""
    with (tmp_path / "stdout.txt").open("wb") as stdout, (tmp_path / "stderr.txt").open("wb") as stderr:
        result = subprocess.run(argv, stdout=stdout, stderr=stderr, stdin=subprocess.DEVNULL, timeout=TIMEOUT_SECONDS,
                                check=False)
    return result.returncode, (tmp_path / "stdout.txt").read_bytes(), (tmp_path / "stderr.txt").read_bytes()


def into_pipes(argv, tmp_path):
    """The child's exit code, stdout, and stderr, with the two streams sent to pipes. `tmp_path` is unused: it gives this
    function into_files's signature, so a test can run with either."""
    result = subprocess.run(argv, capture_output=True, stdin=subprocess.DEVNULL, timeout=TIMEOUT_SECONDS, check=False)
    return result.returncode, result.stdout, result.stderr


def test_a_file_name_in_another_script_is_written_as_utf8_to_stdout_sent_to_a_pipe(tmp_path):
    source, listing, out = listed(tmp_path, JAPANESE)
    code, stdout, stderr = into_pipes([sys.executable, *CHILD, str(listing), str(out)], tmp_path)
    assert code == 0, stderr.decode("utf-8", "replace")
    assert stdout.decode("utf-8").splitlines() == [f"{source}: 1 events", "1 events from 1 files"]
    assert rows(out)[0]["SourceFile"] == str(source)


@pytest.mark.parametrize("attach", [into_files, into_pipes], ids=["file", "pipe"])
def test_a_file_name_in_another_script_is_written_as_utf8_to_the_error_sent_to_a_file_or_a_pipe(tmp_path, attach):
    source, listing, out = listed(tmp_path, JAPANESE, events_file(rdp_logon(1, "SRV", "10.0.0.8"))[:-30])   # cut off mid-event
    code, _, stderr = attach([sys.executable, *CHILD, str(listing), str(out)], tmp_path)
    assert code == 3
    assert stderr.decode("utf-8").startswith(f"Could not read the event XML: {source}: ")
