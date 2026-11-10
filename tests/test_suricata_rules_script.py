"""scripts/suricata_rules.py builds the rule file for Suricata runs from an unpacked ET Open rule set. It checks the set
for everything it copies before it writes, and replaces the version file only after the rule file, so a set it can't use
leaves the old rules in force with the version file naming them. A version file it can't replace is named as out of date."""

import importlib.util
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parents[1] / "scripts" / "suricata_rules.py"
RULE_A = 'alert tcp any any -> any any (msg:"a"; sid:1;)'
RULE_B = 'drop udp any any -> any 53 (msg:"b"; sid:2;)'


def script():
    spec = importlib.util.spec_from_file_location("suricata_rules", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def et_open(tmp_path, classification=True, version="11310"):
    """An unpacked ET Open folder: two rule files and two withdrawn ones, with or without classification.config and
    version.txt."""
    rules = tmp_path / "et" / "rules"
    rules.mkdir(parents=True)
    (rules / "a.rules").write_text(f"{RULE_A}\n#alert disabled\n", encoding="utf-8")
    (rules / "b.rules").write_text(f"{RULE_B}\n", encoding="utf-8")
    (rules / "emerging-deleted.rules").write_text('alert tcp any any -> any any (msg:"gone"; sid:3;)\n', encoding="utf-8")
    (rules / "emerging-retired.rules").write_text('alert tcp any any -> any any (msg:"old"; sid:4;)\n', encoding="utf-8")
    if classification:
        (rules / "classification.config").write_text("config classification: trojan-activity,Trojan,1\n", encoding="utf-8")
    if version:
        (tmp_path / "et" / "version.txt").write_text(f"{version}\n", encoding="utf-8")
    return tmp_path / "et"


def suricata_with_old_rules(tmp_path):
    """A Suricata folder whose rules/ already holds a rule file, a classification.config, and a version file from an
    earlier build."""
    out = tmp_path / "suricata" / "rules"
    out.mkdir(parents=True)
    (out / "suricata.rules").write_text("old", encoding="utf-8")
    (out / "classification.config").write_text("old classes", encoding="utf-8")
    (out / "et-open-version.txt").write_text("ET Open 11000\n", encoding="utf-8")
    return tmp_path / "suricata"


def test_a_rule_set_without_classification_config_is_refused_before_anything_is_written(tmp_path, capsys):
    et = et_open(tmp_path, classification=False)
    suricata = suricata_with_old_rules(tmp_path)
    assert script().main(et, suricata) == 1
    assert capsys.readouterr().err == f"No classification.config in {et / 'rules'}\n"
    out = suricata / "rules"
    assert (out / "suricata.rules").read_text(encoding="utf-8") == "old"
    assert (out / "classification.config").read_text(encoding="utf-8") == "old classes"
    assert (out / "et-open-version.txt").read_text(encoding="utf-8") == "ET Open 11000\n"
    assert sorted(p.name for p in out.iterdir()) == ["classification.config", "et-open-version.txt", "suricata.rules"]


def test_a_refused_rule_set_creates_no_rules_folder(tmp_path):
    suricata = tmp_path / "suricata"
    suricata.mkdir()
    assert script().main(et_open(tmp_path, classification=False), suricata) == 1
    assert not (suricata / "rules").exists()


def test_a_rule_set_is_written_as_one_rule_file_with_its_classification_config_and_version(tmp_path, capsys):
    et = et_open(tmp_path)
    suricata = suricata_with_old_rules(tmp_path)
    assert script().main(et, suricata) == 0
    out = suricata / "rules"
    assert (out / "suricata.rules").read_text(encoding="utf-8") == (
        f"# --- a.rules\n{RULE_A}\n#alert disabled\n# --- b.rules\n{RULE_B}\n"
    )
    assert (out / "classification.config").read_text(encoding="utf-8") == ("config classification: trojan-activity,Trojan,1\n")
    assert (out / "et-open-version.txt").read_text(encoding="utf-8") == "ET Open 11310\n"
    assert sorted(p.name for p in out.iterdir()) == ["classification.config", "et-open-version.txt", "suricata.rules"]
    assert capsys.readouterr().out == f"{out / 'suricata.rules'}: 2 active rules from 2 files, ET Open 11310\n"


def test_a_rule_set_without_version_txt_is_versioned_unknown(tmp_path):
    suricata = tmp_path / "suricata"
    suricata.mkdir()
    assert script().main(et_open(tmp_path, version=None), suricata) == 0
    assert (suricata / "rules" / "et-open-version.txt").read_text(encoding="utf-8") == "ET Open unknown\n"


def test_a_folder_without_rule_files_is_refused(tmp_path, capsys):
    (tmp_path / "et" / "rules").mkdir(parents=True)
    suricata = tmp_path / "suricata"
    suricata.mkdir()
    assert script().main(tmp_path / "et", suricata) == 1
    assert capsys.readouterr().err == f"No .rules files in {tmp_path / 'et' / 'rules'}\n"
    assert not (suricata / "rules").exists()


def version_txt_is_a_folder(et, suricata):
    """The set's version.txt can't be read when a folder has its name, which stops the build after the new rules are
    written but before they replace the old ones."""
    (et / "version.txt").unlink()
    (et / "version.txt").mkdir()


def rule_file_is_a_folder(et, suricata):
    """A folder named like a rule file can't be read, which stops the build with the new rules half written."""
    (et / "rules" / "z.rules").mkdir()


def classification_config_is_a_folder(et, suricata):
    """The copy of classification.config can't replace a folder of that name, which stops the build with every
    temporary file written."""
    config = suricata / "rules" / "classification.config"
    config.unlink()
    config.mkdir()


@pytest.mark.parametrize("stop", [version_txt_is_a_folder, rule_file_is_a_folder, classification_config_is_a_folder])
def test_a_failure_partway_leaves_the_old_rule_file_in_force_and_no_temporary_file(tmp_path, stop):
    et = et_open(tmp_path)
    suricata = suricata_with_old_rules(tmp_path)
    stop(et, suricata)
    with pytest.raises(OSError):
        script().main(et, suricata)
    out = suricata / "rules"
    assert (out / "suricata.rules").read_text(encoding="utf-8") == "old"
    assert (out / "et-open-version.txt").read_text(encoding="utf-8") == "ET Open 11000\n"
    assert sorted(p.name for p in out.glob("*.tmp")) == []


def test_a_version_file_that_cant_be_replaced_is_named_as_out_of_date(tmp_path, monkeypatch, capsys):
    et = et_open(tmp_path)
    suricata = suricata_with_old_rules(tmp_path)
    replace = Path.replace

    def refuse_the_version_file(self, target):
        if Path(target).name == "et-open-version.txt":
            raise PermissionError(f"{target} is in use")
        return replace(self, target)

    monkeypatch.setattr(Path, "replace", refuse_the_version_file)
    assert script().main(et, suricata) == 1
    out = suricata / "rules"
    told = capsys.readouterr()
    assert told.out == ""
    assert f"The rules are now ET Open 11310, but {out / 'et-open-version.txt'} is out of date" in told.err
    assert (out / "suricata.rules").read_text(encoding="utf-8").startswith("# --- a.rules\n")
    assert (out / "et-open-version.txt").read_text(encoding="utf-8") == "ET Open 11000\n"
    assert sorted(p.name for p in out.glob("*.tmp")) == []


def test_a_folder_in_the_version_files_place_stops_the_build_with_the_new_rules_in_force(tmp_path, capsys):
    et = et_open(tmp_path)
    suricata = suricata_with_old_rules(tmp_path)
    out = suricata / "rules"
    (out / "et-open-version.txt").unlink()
    (out / "et-open-version.txt").mkdir()
    assert script().main(et, suricata) == 1
    assert f"{out / 'et-open-version.txt'} is out of date" in capsys.readouterr().err
    assert (out / "suricata.rules").read_text(encoding="utf-8").startswith("# --- a.rules\n")
    assert sorted(p.name for p in out.glob("*.tmp")) == []


def test_a_rule_file_that_cant_be_replaced_leaves_the_version_file_naming_the_old_rules(tmp_path, monkeypatch):
    et = et_open(tmp_path)
    suricata = suricata_with_old_rules(tmp_path)
    replace = Path.replace

    def refuse_the_rule_file(self, target):
        if Path(target).name == "suricata.rules":
            raise PermissionError(f"{target} is in use")
        return replace(self, target)

    monkeypatch.setattr(Path, "replace", refuse_the_rule_file)
    with pytest.raises(PermissionError):
        script().main(et, suricata)
    out = suricata / "rules"
    assert (out / "suricata.rules").read_text(encoding="utf-8") == "old"
    assert (out / "et-open-version.txt").read_text(encoding="utf-8") == "ET Open 11000\n"
    assert sorted(p.name for p in out.glob("*.tmp")) == []
