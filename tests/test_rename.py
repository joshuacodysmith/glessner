"""The rename from triage-workbench to Glessner: the settings and browser preferences of the old name
are copied once, both names count as the app's own 'who', old journals stay as written, and a case made before the
rename opens, rebuilds, and exports under the new build."""

import json
import shutil
from pathlib import Path

import pytest
from conftest import serving
from test_browser_smoke import browser, page  # noqa: F401
from test_overview import api_overview, app_with_work, overview_case  # noqa: F401
from test_server import login, request
from test_version import FAKE, fake_build, fresh_build  # noqa: F401

from glessner import start
from glessner.audit import describe, read_entries
from glessner.case import open_case
from glessner.cli import main
from glessner.journal import APP_NAMES, SYSTEM

OLD = "triage-workbench"
# A small case made with the old build: 2,510 events, its journal's app entries by the old name
LAB_CASE = Path("D:/DFIR-Lab/cases/ops-samples-2026-10-16")


def recent(folder, *names):
    folder.mkdir(parents=True, exist_ok=True)
    data = json.dumps([{"folder": f"D:/cases/{n}", "name": n, "events": 1} for n in names], indent=2)
    (folder / "recent.json").write_text(data, encoding="utf-8")
    return data


def test_the_old_recent_cases_list_is_copied_when_the_new_folder_has_none(tmp_path):
    old, new = tmp_path / OLD, tmp_path / "glessner"
    data = recent(old, "A", "B")
    assert start.adopt_old_recent(new, old)
    assert (new / "recent.json").read_text(encoding="utf-8") == data
    assert (old / "recent.json").read_text(encoding="utf-8") == data   # copied, not moved: an old build still finds it
    assert not start.adopt_old_recent(new, old)                          # once


def test_a_new_recent_cases_list_is_left_alone(tmp_path):
    old, new = tmp_path / OLD, tmp_path / "glessner"
    recent(old, "A")
    mine = recent(new, "C")
    assert not start.adopt_old_recent(new, old)
    assert (new / "recent.json").read_text(encoding="utf-8") == mine
    assert not start.adopt_old_recent(tmp_path / "other", tmp_path / "missing")   # nothing to copy
    assert not (tmp_path / "other").exists()


def test_a_list_written_while_the_copy_runs_is_kept(tmp_path, monkeypatch):
    """Review of the rename: a remember() between the check and the copy had its new list replaced by the old one."""
    old, new = tmp_path / OLD, tmp_path / "glessner"
    recent(old, "A")
    write_bytes = Path.write_bytes

    def remember_meanwhile(self, data):
        if self.parent == new and self.name != "recent.json":
            recent(new, "C")   # the list another thread or command writes while the copy is made
        return write_bytes(self, data)

    monkeypatch.setattr(Path, "write_bytes", remember_meanwhile)
    assert not start.adopt_old_recent(new, old)
    assert [r["name"] for r in json.loads((new / "recent.json").read_text(encoding="utf-8"))] == ["C"]
    assert [f.name for f in new.iterdir()] == ["recent.json"]   # no copy left behind


def test_the_settings_folder_moves_and_its_first_read_copies_the_old_list(tmp_path, monkeypatch):
    monkeypatch.delenv("GLESSNER_CONFIG_DIR", raising=False)
    monkeypatch.delenv("TW_CONFIG_DIR", raising=False)
    monkeypatch.setenv("APPDATA", str(tmp_path))
    recent(tmp_path / OLD, "A")
    assert start.config_dir() == tmp_path / "glessner"
    assert [r["name"] for r in start.load_recent()] == ["A"]
    assert (tmp_path / "glessner" / "recent.json").is_file() and (tmp_path / OLD / "recent.json").is_file()


def test_a_settings_variable_of_either_name_is_honored_and_copies_nothing(tmp_path, monkeypatch):
    monkeypatch.delenv("GLESSNER_CONFIG_DIR", raising=False)
    monkeypatch.setenv("APPDATA", str(tmp_path))
    recent(tmp_path / OLD, "A")
    monkeypatch.setenv("TW_CONFIG_DIR", str(tmp_path / "scratch-old"))
    assert start.config_dir() == tmp_path / "scratch-old" and start.load_recent() == []
    monkeypatch.setenv("GLESSNER_CONFIG_DIR", str(tmp_path / "scratch-new"))
    assert start.config_dir() == tmp_path / "scratch-new" and start.load_recent() == []
    assert not (tmp_path / "glessner").exists()


@pytest.mark.parametrize("who", [SYSTEM, OLD])
def test_your_last_action_leaves_out_the_app_under_either_name(overview_case, who):  # noqa: F811
    assert {"glessner", OLD} == APP_NAMES
    app, _ = app_with_work(overview_case)
    try:
        app.journal.append("case_open", who=who)
        app.journal.append("rule_change", who=who, id="builtin-x", text="x", builtin=True)
        last = api_overview(app, {})["progress"]["last"]
        assert (last["who"], last["text"]) == ("cody", "Closed the case. Its 1 evidence file matches the intake manifest.")
    finally:
        app.con.close()


def test_an_old_case_open_shows_the_name_it_was_written_with():
    assert describe({"action": "case_open", "who": OLD, "build": "0.1.0+abc1234"}) == f"Opened with {OLD} 0.1.0+abc1234"
    assert describe({"action": "case_open", "who": SYSTEM, "build": FAKE}) == f"Opened with glessner {FAKE}"


@pytest.mark.lab
@pytest.mark.skipif(not LAB_CASE.is_dir(), reason="the lab case is not present")
def test_a_copy_of_a_case_from_before_the_rename_opens_rebuilds_and_exports(tmp_path, fake_build):  # noqa: F811
    """tmp_path is under D:/DFIR-Lab/scratch when the suite runs with --basetemp there, as the lab rules require. The
    lab case itself is only read."""
    folder = tmp_path / "case"
    shutil.copytree(LAB_CASE, folder)
    path = folder / "journal.jsonl"
    before = path.read_bytes()
    old_entries = read_entries(path)
    assert any(e.get("who") == OLD for e in old_entries)

    case = open_case(folder)
    for app, port, _ in serving(case):
        cookie = login(port, app)
        overview = json.loads(request(port, "GET", "/api/overview", cookie=cookie)[1])
        people = [e for e in old_entries if e.get("who") not in APP_NAMES]
        assert people   # the case has analyst entries, so the filter is tested
        assert overview["progress"]["last"]["seq"] == people[-1]["seq"]
        trail = json.loads(request(port, "GET", "/api/audit?kind=Builds", cookie=cookie)[1])
        texts = [r["text"] for r in trail["rows"]]   # newest first
        assert texts[0] == f"Opened with glessner {FAKE}"
        # The open upgrades the format 1 case first, where no event of this case changes its ID, and then seals its
        # journal
        assert texts[1].startswith("Upgraded the case from format 2 to 3: Sealed the ")
        assert texts[2].startswith("Upgraded the case from format 1 to 2: ") and "No journal reference changed" in texts[2]
        olds = [e for e in old_entries if e["action"] == "case_open"]
        assert texts[3:] == [f"Opened with {e['who']} {e['build']}" for e in reversed(olds)]
    after = path.read_bytes()
    assert after.startswith(before)   # every old line stays as written
    added = [json.loads(line) for line in after[len(before):].decode("utf-8").splitlines()]
    assert [(e["action"], e["who"], e.get("build")) for e in added] == [("case_upgrade", SYSTEM, None),
                                                                      ("case_upgrade", SYSTEM, FAKE),
                                                                      ("case_yaml", SYSTEM, FAKE),
                                                                      ("case_open", SYSTEM, FAKE)]

    assert main(["rebuild", str(folder)]) == 0
    assert path.read_bytes() == after   # a rebuild journals nothing
    assert main(["export", str(folder)]) == 0
    assert main(["findings", str(folder)]) == 0
    exports = sorted((folder / "exports").iterdir(), key=lambda p: p.stat().st_mtime)
    summary = next(p for p in reversed(exports) if p.suffix == ".md")
    assert f"by glessner {FAKE} for" in summary.read_text(encoding="utf-8")
    # Each written file is recorded by its file_written entry, by the current build
    added = read_entries(path)[-2:]
    assert [(e["action"], e["kind"], e["build"]) for e in added] == [("file_written", "timeline", FAKE),
                                                                     ("file_written", "report", FAKE)]
    assert path.read_bytes().startswith(after)


@pytest.mark.browser
def test_browser_preferences_from_before_the_rename_are_copied_once(page):  # noqa: F811
    page.evaluate(f"""() => {{
        localStorage.clear();
        localStorage.setItem('{OLD}.fadePivotResults', 'off');
        localStorage.setItem('{OLD}.quickActionsHidden', '["note"]');
        localStorage.setItem('{OLD}.legendOpen', 'open');
        localStorage.setItem('glessner.legendOpen', 'closed');
    }}""")
    page.reload()
    page.wait_for_function("() => window.__ready === true")
    got = page.evaluate(f"""() => ['fadePivotResults', 'quickActionsHidden', 'legendOpen', 'rawFieldsOpen'].map(
        (k) => [localStorage.getItem('glessner.' + k), localStorage.getItem('{OLD}.' + k)])""")
    assert got == [["off", "off"], ['["note"]', '["note"]'], ["closed", "open"], [None, None]]
