"""Where a case writes: a case folder outside its evidence folder, and each run's folder directly in the case's runs
folder, where read_runs finds it."""

import shutil
import sys
from dataclasses import replace
from pathlib import Path

import pytest
import yaml

from glessner.case import Case, CaseError, create_case, open_case
from glessner.intake import intake
from glessner.runner import load_found_output, plan_runs, read_runs, run, start_run
from glessner.tools import DetectedTool, ToolSpec

# Stands in for a tool that reads the event logs it is given and writes nothing
TOOL = ToolSpec(id="fake", name="Fake", publisher="", license="", download_url="https://example.invalid",
                executables=("python.exe",), version_args=(), version_regex="", handles=("evtx",), input="each_file",
                args=("-c", "pass", "{input_file}", "{output_dir}"), timeout_minutes=1.0, outputs=(), parser=None)


def evidence(root: Path) -> Path:
    logs = root / "evidence" / "Windows" / "System32" / "winevt" / "Logs"
    logs.mkdir(parents=True)
    (logs / "Security.evtx").write_bytes(b"ElfFile\x00one host")
    return root / "evidence"


def files_under(folder: Path) -> list[str]:
    return sorted(p.relative_to(folder).as_posix() for p in folder.rglob("*"))


@pytest.mark.parametrize("host", ["CORP\\DC01", "DC01/C", "/../../../evidence/sub", "DC01\x07", "DC01\n", "x" * 65])
def test_a_single_host_name_with_a_slash_or_a_control_character_is_refused(tmp_path, host):
    """The single host's name goes into each run folder's name, so a slash or a backslash would put the folder deeper
    than read_runs looks, or outside the case. create_case refuses such a name, as the Import page refuses one for a
    lane, and makes nothing."""
    ev = evidence(tmp_path)
    with pytest.raises(CaseError, match="host name"):
        create_case(tmp_path / "case", "One", ev, "cody", single_host=host)
    assert not (tmp_path / "case").exists()
    assert create_case(tmp_path / "case", "One", ev, "cody", single_host="DC01").settings.single_host == "DC01"


@pytest.mark.parametrize("host", ["C:", "DC01:x", "DC01?", "DC01*", 'DC"01', "DC<01>", "DC|01"])
def test_a_single_host_name_windows_refuses_in_a_folder_name_is_refused(tmp_path, host):
    """Windows refuses : and the other characters in < > " | ? * in a file's name, so a run folder named for such a
    host couldn't be made, and the run would fail at its first step. create_case refuses the name, saying so, and makes
    nothing."""
    ev = evidence(tmp_path)
    with pytest.raises(CaseError, match="host name") as refused:
        create_case(tmp_path / "case", "One", ev, "cody", single_host=host)
    assert "Windows refuses in a folder's name" in str(refused.value)
    assert not (tmp_path / "case").exists()


@pytest.mark.parametrize("host", ["DC01 ", "DC01.", "DC01 .", " "])
def test_a_single_host_name_ending_in_a_space_or_a_dot_is_refused(tmp_path, host):
    """Windows drops a space or a dot from the end of a folder's name, so a run folder named for such a host would be
    made under another name, and the run would fail at its first step. create_case refuses the name, saying so, and
    makes nothing."""
    ev = evidence(tmp_path)
    with pytest.raises(CaseError, match="host name") as refused:
        create_case(tmp_path / "case", "One", ev, "cody", single_host=host)
    assert "can't end in a space or a dot" in str(refused.value)
    assert not (tmp_path / "case").exists()
    assert create_case(tmp_path / "case", "One", ev, "cody", single_host="DC01.corp").settings.single_host == "DC01.corp"


@pytest.mark.parametrize("host", ["CORP\\DC01", "\\..\\..\\..\\evidence\\sub"])
def test_a_run_folder_outside_the_runs_folder_is_refused(tmp_path, host):
    """A case.yaml whose single_host was edited by hand still gets no run folder outside its runs folder: one deeper
    would be missing from every rebuild, copy, and Tools page, and one with ".." could land in the evidence. run, for
    tools, and start_run, for imports and found output, refuse it before they make anything."""
    ev = evidence(tmp_path)
    good = create_case(tmp_path / "case", "One", ev, "cody", single_host="DC01")
    intake(good)
    before = files_under(ev)
    case = Case(good.folder, replace(good.settings, single_host=host))
    (plan,) = plan_runs(case, DetectedTool(TOOL, Path(sys.executable), "1.0"))
    assert plan.host == host
    with pytest.raises(CaseError, match="isn't directly in the case's runs folder"):
        run(case, plan)
    with pytest.raises(CaseError, match="isn't directly in the case's runs folder"):
        start_run(case, "import", host, tool_version="1", host=host, inputs=[])
    with pytest.raises(CaseError, match="isn't directly in the case's runs folder"):
        load_found_output(case, "evtxecmd", "evtxecmd_csv", host, [])
    assert list(good.runs_folder.iterdir()) == [] and files_under(ev) == before
    assert read_runs(good) == []


def test_a_case_moved_into_its_evidence_folder_is_refused_on_open(tmp_path):
    """create_case refuses a case folder inside its evidence folder, and open_case refuses one moved there afterward,
    or whose evidence_path was edited to a folder that holds it: each write of the case would land in the evidence,
    and Add new evidence would hash the case's own files as evidence."""
    ev = evidence(tmp_path)
    case = create_case(tmp_path / "case", "One", ev, "cody")
    moved = ev / "case"
    shutil.move(case.folder, moved)
    with pytest.raises(CaseError, match="The case folder and the evidence folder must not contain each other") as refused:
        open_case(moved)
    assert "Move the case folder out of the evidence folder, or correct evidence_path" in str(refused.value)
    shutil.move(moved, tmp_path / "case")
    assert open_case(tmp_path / "case").evidence == ev.resolve()
    settings = yaml.safe_load((tmp_path / "case" / "case.yaml").read_text(encoding="utf-8"))
    settings["evidence_path"] = str(tmp_path)
    (tmp_path / "case" / "case.yaml").write_text(yaml.safe_dump(settings, sort_keys=False), encoding="utf-8")
    with pytest.raises(CaseError, match="must not contain each other"):
        open_case(tmp_path / "case")


def test_a_run_of_a_case_inside_its_evidence_folder_is_refused(tmp_path):
    """A case held open while its folder came to sit in the evidence folder makes no run folder there: start_run, for
    imports and found output, refuses it as open_case does, and so does run."""
    ev = evidence(tmp_path)
    case = create_case(tmp_path / "case", "One", ev, "cody", single_host="DC01")
    intake(case)
    (plan,) = plan_runs(case, DetectedTool(TOOL, Path(sys.executable), "1.0"))
    shutil.move(case.folder, ev / "case")
    inside = Case(ev / "case", case.settings)
    before = files_under(ev)
    with pytest.raises(CaseError, match="must not contain each other"):
        start_run(inside, "import", "Security.evtx", tool_version="1", host="DC01", inputs=[])
    with pytest.raises(CaseError, match="must not contain each other"):
        run(inside, plan)
    assert files_under(ev) == before
