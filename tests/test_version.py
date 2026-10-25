"""The three numbers: the release version, the build identifier, and the case format number."""

import contextlib
import dataclasses
import importlib.metadata
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import tomllib
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from conftest import serving
from test_server import login, request

import glessner
from glessner import case as case_module
from glessner import version
from glessner.audit import AuditError, describe, markdown, plan_undo, read_entries, rows
from glessner.case import CASE_FORMAT, CaseError, copy_case, open_case
from glessner.cli import main
from glessner.events import connect
from glessner.export import write_report
from glessner.journal import SYSTEM, Journal, replay
from glessner.server import App, Hub, serve_start
from glessner.tools import DetectedTool, detect, load_registry
from glessner.version import build_id

PROJECT = Path(__file__).resolve().parents[1]
GIT = shutil.which("git")
needs_git = pytest.mark.skipif(GIT is None, reason="git isn't installed")
FAKE = "9.9.9+test"   # a build no checkout gives, so a stamp shows where it came from


@pytest.fixture
def fresh_build():
    """build_id() worked out again for the test, and again after it, so no test keeps another's."""
    build_id.cache_clear()
    yield
    build_id.cache_clear()


@pytest.fixture
def fake_build(monkeypatch, fresh_build):
    monkeypatch.setattr(version, "BAKED_BUILD", FAKE)
    return FAKE


def as_build(monkeypatch, build):
    monkeypatch.setattr(version, "BAKED_BUILD", build)
    build_id.cache_clear()


# ---------- the release version ----------

def test_the_release_version_is_written_only_in_pyproject_and_read_from_the_metadata(monkeypatch):
    with (PROJECT / "pyproject.toml").open("rb") as f:
        written = tomllib.load(f)["project"]["version"]
    assert glessner.__version__ == written == importlib.metadata.version("glessner")
    assert not [p.name for p in (PROJECT / "src").rglob("*.py") if f'"{written}"' in p.read_text(encoding="utf-8")]
    monkeypatch.setattr(importlib.metadata, "version", lambda name: "7.7.7")
    assert glessner._release_version() == "7.7.7"

    def missing(name):
        raise importlib.metadata.PackageNotFoundError(name)

    monkeypatch.setattr(importlib.metadata, "version", missing)
    assert glessner._release_version() == "0+unknown"


# ---------- the build identifier ----------

def git(cwd, *args):
    subprocess.run([GIT, "-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false",
                    "-c", f"core.hooksPath={cwd / 'no-hooks'}", *args], cwd=cwd, check=True, capture_output=True)


@pytest.fixture
def checkout(tmp_path, monkeypatch, fresh_build):
    """A checkout of a workspace, with a package folder and a file outside it; the build reads the package folder. The
    build waits longer for git than the app does, since on a loaded machine git's three calls can together take longer
    than the app's wait, which gives the plain version whatever git would have said."""
    monkeypatch.setattr(version, "GIT_TIMEOUT_S", 60)
    repo = tmp_path / "repo"
    package = repo / "src" / "pkg"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("x = 1\n")
    (repo / "notes.md").write_text("workspace\n")
    git(repo, "init", "-q")
    git(repo, "add", ".")
    git(repo, "commit", "-q", "-m", "first")
    head = subprocess.run([GIT, "rev-parse", "--short=7", "HEAD"], cwd=repo, capture_output=True, text=True,
                          check=True).stdout.strip()
    monkeypatch.setattr(version, "PACKAGE_DIR", package)
    return repo, package, head


def again() -> str:
    build_id.cache_clear()
    return build_id()


@needs_git
def test_the_build_names_the_commit_and_is_dirty_only_for_changes_under_the_package(checkout):
    repo, package, head = checkout
    clean = f"{glessner.__version__}+{head}"
    assert build_id() == clean and len(head) >= 7
    (repo / "notes.md").write_text("another session's change\n")   # the workspace's other files don't count
    (package / "new_module.py").write_text("y = 2\n")             # nor does a file git doesn't track
    assert again() == clean
    (package / "__init__.py").write_text("x = 2\n")
    assert again() == f"{clean}.dirty"
    git(repo, "add", ".")   # staged but not committed still differs from the commit
    assert again() == f"{clean}.dirty"


@needs_git
def test_a_package_the_checkout_doesn_t_track_gets_the_plain_version(checkout, monkeypatch):
    """A copy installed in a folder of another checkout, such as a .venv in a repository, isn't that checkout's commit."""
    repo, _, _ = checkout
    installed = repo / ".venv" / "Lib" / "site-packages" / "pkg"
    installed.mkdir(parents=True)
    (installed / "__init__.py").write_text("x = 1\n")
    monkeypatch.setattr(version, "PACKAGE_DIR", installed)
    assert again() == glessner.__version__


@needs_git
def test_a_version_with_a_local_label_takes_the_commit_after_a_dot(checkout, monkeypatch):
    monkeypatch.setattr(version, "__version__", "0+unknown")
    assert again() == f"0+unknown.{checkout[2]}"


def fake_git(monkeypatch, answer):
    """git as `answer(args, timeout)` gives it: (exit code, stdout), or None for a git still running at the timeout.
    Returns each call: its arguments and Popen's keywords, the timeout, and whether it was killed."""
    calls = []

    class Popen:
        def __init__(self, args, **kw):
            self.call = {"args": args, **kw, "killed": False}
            calls.append(self.call)
            self.returncode = None

        def communicate(self, timeout=None):
            self.call["timeout"] = timeout
            if (answered := answer(self.call["args"], timeout)) is None:
                raise subprocess.TimeoutExpired(self.call["args"], timeout)
            self.returncode, out = answered
            return out, None

        def kill(self):
            self.call["killed"] = True

        def wait(self, timeout=None):
            self.returncode = 1
            return 1

    monkeypatch.setattr(version.shutil, "which", lambda name: "git")
    monkeypatch.setattr(version.subprocess, "Popen", Popen)
    return calls


def test_without_git_the_build_is_the_plain_version(monkeypatch, fresh_build):
    monkeypatch.setattr(version.shutil, "which", lambda name: None)
    monkeypatch.setattr(version.subprocess, "Popen", lambda *a, **k: pytest.fail("git ran"))
    assert build_id() == glessner.__version__


def test_a_failing_or_slow_git_gives_the_plain_version(monkeypatch, fresh_build):
    # As git answers in a repository with no commits yet: HEAD on stdout, and an error
    fake_git(monkeypatch, lambda args, timeout: (128, "HEAD\n"))
    assert build_id() == glessner.__version__
    calls = fake_git(monkeypatch, lambda args, timeout: None)
    assert again() == glessner.__version__
    [call] = calls
    assert call["killed"] and call["timeout"] == pytest.approx(version.GIT_TIMEOUT_S, abs=0.5)
    assert call["cwd"] == version.PACKAGE_DIR and "shell" not in call and call["stderr"] == subprocess.DEVNULL


def test_git_s_commands_share_the_timeout(monkeypatch, fresh_build):
    """GIT_TIMEOUT_S bounds the three commands together, not each one."""
    clock = [0.0]
    monkeypatch.setattr(version, "time", SimpleNamespace(monotonic=lambda: clock[0]))

    def answer(args, timeout):   # each command takes 1.5 s
        if timeout < 1.5:
            return None
        clock[0] += 1.5
        return 0, "abc1234\n" if "rev-parse" in args else ""

    calls = fake_git(monkeypatch, answer)
    assert build_id() == glessner.__version__
    assert [call["timeout"] for call in calls] == [3, 1.5, 0]


@pytest.mark.skipif(sys.platform != "win32", reason="runs a batch file")
def test_git_is_given_up_on_at_the_timeout_while_a_child_holds_its_output(tmp_path, monkeypatch, fresh_build):
    """Git for Windows' cmd\\git.exe runs the real git as a child, which holds git's output open. At the timeout the build
    stops waiting for both, where subprocess.run waits for the child however long it runs."""
    ping = Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "System32" / "PING.EXE"
    fake = tmp_path / "git.cmd"
    fake.write_text(f'@"{ping}" -n 6 127.0.0.1\n', encoding="ascii")   # about 5 s
    monkeypatch.setattr(version.shutil, "which", lambda name: str(fake))
    monkeypatch.setattr(version, "PACKAGE_DIR", tmp_path)
    monkeypatch.setattr(version, "GIT_TIMEOUT_S", 0.5)
    started = time.monotonic()
    assert build_id() == glessner.__version__
    assert time.monotonic() - started < 2.5


def test_git_and_tools_are_never_taken_from_the_folder_the_app_starts_in(tmp_path):
    """Windows looks for a program in the current folder before PATH unless NoDefaultCurrentDirectoryInExePath is set,
    so a git.exe planted in the folder the app started from, such as an evidence folder, would run. The package sets
    the variable when it's imported."""
    (tmp_path / "git.exe").write_bytes(b"")
    env = {k: v for k, v in os.environ.items() if k.upper() != "NODEFAULTCURRENTDIRECTORYINEXEPATH"}
    code = ("import shutil, types, glessner.tools as t; print(shutil.which('git')); "
            "print(t._on_path(types.SimpleNamespace(executables=['git.exe'])))")
    out = subprocess.run([sys.executable, "-I", "-c", code], cwd=tmp_path, env=env, capture_output=True, text=True,
                         check=True).stdout.splitlines()
    assert len(out) == 2
    for found in out:   # git from PATH, or None where it isn't installed
        assert found == "None" or (Path(found).is_absolute() and Path(found).parent != tmp_path), found


def test_git_runs_once_per_process_and_a_baked_build_skips_it(monkeypatch, fresh_build):
    calls = fake_git(monkeypatch, lambda args, timeout: (0, "abc1234\n" if "rev-parse" in args else ""))
    assert build_id() == build_id() == f"{glessner.__version__}+abc1234"
    assert len(calls) == 3 and all(call["args"][0] == "git" for call in calls)
    monkeypatch.setattr(version, "BAKED_BUILD", "1.2.3+baked")
    assert again() == "1.2.3+baked" and len(calls) == 3


def test_version_flag_prints_the_build(capsys, fake_build):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0 and capsys.readouterr().out == f"glessner {FAKE}\n"


def test_the_runs_and_tools_listings_line_up_with_a_build_as_the_version(synthetic_case, monkeypatch, capsys):
    """A build such as 0.1.0+abc1234.dirty is longer than 10 characters, and the version columns still line up."""
    from glessner import cli

    build = "0.1.0+abc1234.dirty"
    runs = [SimpleNamespace(run_id=run_id, status="ok", tool_version=v, seconds=1.0, loaded_rows=5, reason="")
            for run_id, v in (("r1", "1.2.0"), ("r2", build))]
    monkeypatch.setattr(cli, "read_runs", lambda case: runs)
    assert main(["runs", str(synthetic_case.folder)]) == 0
    assert len({line.index("1.0s") for line in capsys.readouterr().out.splitlines()}) == 1

    specs = load_registry()
    found = {spec: DetectedTool(specs[spec], Path(f"C:/tools/{spec}.exe"), v)
             for spec, v in zip(list(specs)[:2], ("1.2.0", build), strict=True)}
    monkeypatch.setattr(cli, "detect", lambda specs, folder: found)
    assert main(["tools", str(synthetic_case.folder)]) == 0
    lines = capsys.readouterr().out.splitlines()
    gaps = {line.index(f"{spec}.exe") - line.index(tool.version) for spec, tool in found.items() for line in lines
            if f"{spec}.exe" in line}
    assert len(gaps) == 1


def test_exports_imports_and_built_in_tools_carry_the_build(fake_build, fast_alerts_case):
    """The findings summary's header names the build that wrote it, and imported events, an import's run record, and the
    built-in event XML reader take it as their tool version."""
    case = fast_alerts_case
    con = connect(case.db_path, read_only=True)
    try:
        assert con.execute("SELECT DISTINCT tool_version FROM events WHERE tool = 'import'").fetchall() == [(FAKE,)]
    finally:
        con.close()
    records = [json.loads(p.read_text(encoding="utf-8")) for p in case.runs_folder.glob("*/run.json")]
    assert [r["tool_version"] for r in records] == [FAKE]
    assert detect([load_registry()["event_xml"]], None)["event_xml"].version == FAKE
    app = App(case)
    try:
        path, _ = write_report(app.con, case, app.identity, app.manifest, app.journal.state)
    finally:
        app.con.close()
    assert f"by glessner {FAKE} for cody." in path.read_text(encoding="utf-8")


# ---------- the journal's build entries ----------

def builds(case):
    return [e["build"] for e in read_entries(case.folder / "journal.jsonl") if e["action"] == "case_open"]


def test_the_server_s_case_open_journals_each_change_of_build_once(synthetic_case, monkeypatch, fresh_build):
    for build in ("0.1.0+aaaaaaa", "0.1.0+aaaaaaa", "0.1.0+aaaaaaa.dirty", "0.1.0+aaaaaaa.dirty", "0.1.0+aaaaaaa"):
        as_build(monkeypatch, build)
        Hub(synthetic_case).app.con.close()
    assert builds(synthetic_case) == ["0.1.0+aaaaaaa", "0.1.0+aaaaaaa.dirty", "0.1.0+aaaaaaa"]
    entries = read_entries(synthetic_case.folder / "journal.jsonl")
    # The first entry after case_created, ahead of the built-in rules that build added, and the app's own, as those are
    assert [e["action"] for e in entries[:3]] == ["case_created", "case_open", "rule_add"]
    assert {e["who"] for e in entries if e["action"] == "case_open"} == {SYSTEM}


def test_no_command_journals_a_build_and_each_entry_names_its_own(synthetic_case, fake_build, capsys):
    """No command writes case_open, and each entry a command writes, such as the built-in rules its App adds, names its
    build and the command line in its envelope."""
    folder = str(synthetic_case.folder)
    for argv in (["runs", folder], ["rule", folder, "list"], ["export", folder], ["findings", folder]):
        assert main(argv) == 0, argv
    App(synthetic_case, client="cli").con.close()   # the command line's App, without the server's open
    assert builds(synthetic_case) == []
    written = read_entries(synthetic_case.folder / "journal.jsonl")[1:]   # after the fixture's case_created
    assert written and all((e["build"], e["client"]) == (FAKE, "cli") for e in written)


def test_replay_ignores_the_build_entries_and_the_trail_shows_them(synthetic_case, tmp_path, fake_build):
    journal = Journal(synthetic_case)
    journal.append("mark", targets=["a", "b"], value="suspicious")
    assert journal.record_build(FAKE)["seq"] == 3   # after case_created and the mark
    assert journal.record_build(FAKE) is None
    journal.append("note", target="a", text="first look")
    journal.append("case_setting", name="event_threshold", value=1000)
    path = synthetic_case.folder / "journal.jsonl"
    without = tmp_path / "without.jsonl"
    without.write_text("".join(line for line in path.open(encoding="utf-8") if '"case_open"' not in line), encoding="utf-8")
    state, other = dataclasses.asdict(replay(path)), dataclasses.asdict(replay(without))
    assert state.pop("last_seq") == 5 and other.pop("last_seq") == 5 and state == other

    entries = read_entries(path)
    assert describe(entries[2]) == f"Opened with glessner {FAKE}"
    trail = rows(entries, {}, kind="Builds")["rows"]   # case_created is a build entry too
    assert [(r["seq"], r["action"], r["undoable"]) for r in trail] == [(3, "case_open", False), (1, "case_created", False)]
    assert trail[0]["who"] == SYSTEM
    with pytest.raises(AuditError, match="can't be undone"):
        plan_undo(entries, 3)
    text = markdown(entries, "Synthetic", {})
    assert f"by glessner {FAKE}." in text and f"{SYSTEM}: Opened with glessner {FAKE}" in text


def test_the_audit_trail_page_shows_the_build_that_opened_the_case(synthetic_case, fake_build):
    for app, port, _ in serving(synthetic_case):
        session = login(port, app)
        trail = json.loads(request(port, "GET", "/api/audit?kind=Builds", session=session)[1])
        assert [r["text"] for r in trail["rows"]] == [f"Opened with glessner {FAKE}", 'Created the case "Synthetic" for cody']
        body = request(port, "POST", "/api/audit_export", session=session, body={})[1]
        # then the head of the journal it lists
        assert f"by glessner {FAKE}, from the journal whose head is " in Path(json.loads(body)["path"]).read_text(
            encoding="utf-8")


# ---------- the case format number ----------

def settings_file(case):
    return yaml.safe_load((case.folder / "case.yaml").read_text(encoding="utf-8"))


def set_format(case, value):
    data = settings_file(case)
    if value is None:
        data.pop("case_format")
    else:
        data["case_format"] = value
    (case.folder / "case.yaml").write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


def test_new_cases_write_the_format_and_one_without_it_is_format_1(synthetic_case, tmp_path, monkeypatch):
    assert CASE_FORMAT == 4 and settings_file(synthetic_case)["case_format"] == CASE_FORMAT
    assert open_case(synthetic_case.folder).settings.case_format == CASE_FORMAT
    set_format(synthetic_case, None)   # as a case made before the format number was recorded
    assert open_case(synthetic_case.folder).settings.case_format == 1
    monkeypatch.setattr(case_module, "CASE_FORMAT", CASE_FORMAT + 1)   # a later build writes its own format
    later = case_module.create_case(tmp_path / "later", "Later", synthetic_case.evidence, "cody")
    assert later.settings.case_format == CASE_FORMAT + 1 and settings_file(later)["case_format"] == CASE_FORMAT + 1


def test_a_newer_format_is_refused_by_the_command_line_and_the_start_page(synthetic_case, fake_build, capsys):
    set_format(synthetic_case, CASE_FORMAT + 1)
    data = settings_file(synthetic_case)
    data["a_later_setting"] = "a newer build's"   # read only after the format check, which names the problem instead
    (synthetic_case.folder / "case.yaml").write_text(yaml.safe_dump(data), encoding="utf-8")
    said = (f"is a case of format {CASE_FORMAT + 1}, and this build of glessner ({FAKE}) reads formats up to "
            f"{CASE_FORMAT}. Open it with a build that reads format {CASE_FORMAT + 1}.")
    with pytest.raises(CaseError, match=rf"of format {CASE_FORMAT + 1}, and this build .* reads formats up to {CASE_FORMAT}\."):
        open_case(synthetic_case.folder)
    assert main(["runs", str(synthetic_case.folder)]) == 2
    assert said in capsys.readouterr().err
    assert main(["copy-case", str(synthetic_case.folder), str(synthetic_case.folder.parent / "copy"), "--name", "C"]) == 2
    server, hub, _ = serve_start(0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]
    try:
        session = login(port, hub)
        res, body = request(port, "POST", "/api/start/open", session=session, body={"folder": str(synthetic_case.folder)})
        assert res.status == 400 and said in json.loads(body)["error"] and hub.app is None
        assert json.loads(request(port, "GET", "/api/start", session=session)[1])["build"] == FAKE
    finally:
        server.shutdown()
        server.server_close()


def test_a_case_format_that_isn_t_a_whole_number_is_refused(synthetic_case):
    for value in ("2", 1.5, True, 0):
        set_format(synthetic_case, value)
        with pytest.raises(CaseError, match="case_format"):
            open_case(synthetic_case.folder)


def test_a_setting_this_build_doesn_t_read_is_refused_by_name(synthetic_case, fake_build, capsys):
    """A later build may add a setting to case.yaml without raising the format. This build refuses such a case, naming
    the setting, not failing with a TypeError."""
    data = settings_file(synthetic_case)
    data["closed_utc"] = "2026-10-20T10:00:00Z"
    (synthetic_case.folder / "case.yaml").write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    said = f"has settings this build of glessner ({FAKE}) doesn't read: closed_utc. A newer build"
    with pytest.raises(CaseError, match=re.escape(said)):
        open_case(synthetic_case.folder)
    assert main(["runs", str(synthetic_case.folder)]) == 2
    assert said in capsys.readouterr().err


def test_copy_case_carries_the_source_s_format(synthetic_case, tmp_path, monkeypatch):
    set_format(synthetic_case, 2)   # copy_case keeps it; the command line and the start page upgrade the copy after
    copy = copy_case(open_case(synthetic_case.folder), tmp_path / "copy", "Copy", "cody")
    assert copy.settings.case_format == 2 and settings_file(copy)["case_format"] == 2


def test_an_older_format_is_upgraded_at_the_server_s_open_and_journaled(synthetic_case, monkeypatch, fake_build):
    """The upgrade hook, with steps made up for the test: the server's case open runs each step from the case's format
    up, journals the fields it gives, then the build, and writes the new number; the next open runs none. A step can
    hold what it opened until the entry and the number are written. The made-up step runs from this build's format to
    the next, after the seal, so its entry is an ordinary chained one."""
    held = []
    later = CASE_FORMAT + 1

    @contextlib.contextmanager
    def step(case):
        held.append("open")
        (case.folder / "upgraded.txt").write_text("done")
        yield {"text": "Wrote upgraded.txt.", "extra": 1}
        held.append((settings_file(case)["case_format"], read_entries(case.folder / "journal.jsonl")[-1]["action"]))

    monkeypatch.setattr(case_module, "CASE_FORMAT", later)
    monkeypatch.setattr(case_module, "UPGRADES", {CASE_FORMAT: step})
    App(synthetic_case).con.close()   # the command line's App upgrades nothing
    assert settings_file(synthetic_case)["case_format"] == CASE_FORMAT
    for _ in range(2):
        hub = Hub(open_case(synthetic_case.folder))
        hub.app.con.close()
    assert held == ["open", (later, "case_upgrade")]   # released after the entry and the number
    assert settings_file(synthetic_case)["case_format"] == later and hub.app.case.settings.case_format == later
    entries = [e for e in read_entries(synthetic_case.folder / "journal.jsonl") if e["action"] in ("case_open", "case_upgrade")]
    assert [e["action"] for e in entries] == ["case_upgrade", "case_open"] and entries[0]["extra"] == 1
    assert "prev" in entries[0] and describe(entries[0]) == (
        f"Upgraded the case from format {CASE_FORMAT} to {later}: Wrote upgraded.txt.")
    monkeypatch.setattr(case_module, "CASE_FORMAT", later + 1)   # a format with no step to it
    with pytest.raises(CaseError, match=f"no upgrade from case format {later}"):
        Hub(open_case(synthetic_case.folder))
