"""import takes a file by its absolute path when the path lies in the evidence folder, however the case spells that
folder: as typed, in extended-length form, or through a junction."""

import dataclasses

import pytest
import yaml
from conftest import junction

from glessner import cli
from glessner.case import CASE_FILE, CaseError, create_case, open_case
from glessner.cli import main
from glessner.intake import intake


@pytest.fixture
def case(tmp_path):
    """A case on an evidence folder holding HOST/x.log."""
    (tmp_path / "evidence" / "HOST").mkdir(parents=True)
    (tmp_path / "evidence" / "HOST" / "x.log").write_text("time,src\n2020-09-19T03:21:48Z,10.0.0.1\n", encoding="utf-8")
    return create_case(tmp_path / "case", "Paths", tmp_path / "evidence", "cody")


def spelled(case, evidence_path):
    """The case with its evidence folder written as `evidence_path` in the settings."""
    return dataclasses.replace(case, settings=dataclasses.replace(case.settings, evidence_path=str(evidence_path)))


def test_an_absolute_path_in_an_evidence_folder_kept_in_extended_length_form_is_found(case, tmp_path):
    evidence = tmp_path / "evidence"
    extended = spelled(case, "\\\\?\\" + str(evidence))
    assert cli._evidence_relative(extended, str(evidence / "HOST" / "x.log")) == "HOST/x.log"
    assert cli._evidence_relative(extended, "\\\\?\\" + str(evidence / "HOST" / "x.log")) == "HOST/x.log"
    assert cli._evidence_relative(case, "\\\\?\\" + str(evidence / "HOST" / "x.log")) == "HOST/x.log"


def test_an_absolute_path_through_a_junction_to_the_evidence_folder_is_found(case, tmp_path):
    """The evidence folder written as a junction to it, and a path written through that junction, name one file."""
    link = tmp_path / "evidence_link"
    junction(link, tmp_path / "evidence")
    assert cli._evidence_relative(spelled(case, link), str(link / "HOST" / "x.log")) == "HOST/x.log"
    assert cli._evidence_relative(spelled(case, link), str(tmp_path / "evidence" / "HOST" / "x.log")) == "HOST/x.log"
    assert cli._evidence_relative(case, str(link / "HOST" / "x.log")) == "HOST/x.log"
    # The junction kept in extended-length form too
    extended = spelled(case, "\\\\?\\" + str(link))
    assert cli._evidence_relative(extended, str(link / "HOST" / "x.log")) == "HOST/x.log"
    assert cli._evidence_relative(extended, str(tmp_path / "evidence" / "HOST" / "x.log")) == "HOST/x.log"
    assert cli._evidence_relative(extended, "\\\\?\\" + str(link / "HOST" / "x.log")) == "HOST/x.log"


def test_an_absolute_path_outside_the_evidence_folder_is_refused(case, tmp_path):
    (tmp_path / "evidence_old").mkdir()
    for outside in (tmp_path / "elsewhere" / "x.log", tmp_path / "evidence_old" / "x.log", tmp_path / "case" / "x.log"):
        with pytest.raises(CaseError, match="isn't in the evidence folder"):
            cli._evidence_relative(case, str(outside))
        with pytest.raises(CaseError, match="isn't in the evidence folder"):
            cli._evidence_relative(spelled(case, "\\\\?\\" + str(tmp_path / "evidence")), str(outside))


def test_a_relative_path_is_returned_with_forward_slashes(case):
    assert cli._evidence_relative(case, "HOST\\x.log") == "HOST/x.log"
    assert cli._evidence_relative(case, "HOST/x.log") == "HOST/x.log"
    assert cli._evidence_relative(case, "HOST\\*.log") == "HOST/*.log"


def test_the_import_command_takes_an_absolute_path_in_an_evidence_folder_kept_in_extended_length_form(case, tmp_path, capsys):
    """case.yaml holds the evidence folder in extended-length form, as a case made from a path typed that way does."""
    settings = case.folder / CASE_FILE
    data = yaml.safe_load(settings.read_text(encoding="utf-8"))
    data["evidence_path"] = "\\\\?\\" + data["evidence_path"]
    settings.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    intake(open_case(case.folder))
    capsys.readouterr()
    assert main(["import", str(case.folder), str(tmp_path / "evidence" / "HOST" / "x.log"), "--preview"]) == 0
    assert capsys.readouterr().out.startswith("HOST/x.log: ")
    assert main(["import", str(case.folder), str(tmp_path / "elsewhere.log"), "--preview"]) == 2
    assert "isn't in the evidence folder" in capsys.readouterr().err
