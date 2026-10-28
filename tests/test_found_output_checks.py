"""A tool's output found in the evidence: the source paths its events cite, and the files the load checks."""

import dataclasses
import json

from chain_fixtures import format3_case
from conftest import junction
from sbecmd_log_fixtures import CONSOLE_LOG_NAME, console_log_text
from test_runner import eve_lines
from test_tool_outputs import SBE_COLUMNS, write_rows

from glessner import runner as runner_module
from glessner.case import create_case, open_case
from glessner.events import connect
from glessner.intake import add_new, intake
from glessner.rekey import upgraded
from glessner.runner import LEFT_OUT, UNLISTED_NOTE, load_found_output, read_runs, rebuild, run_problems
from glessner.toolbox import run_and_load

CSV = "HOST/Modules/FileFolderAccess/alice_UsrClass.csv"
BAG = {"BagPath": "BagMRU\\0", "Slot": "1", "AbsolutePath": "Desktop\\This PC\\C:\\Tools", "ShellType": "Directory",
       "FirstInteracted": "2024-05-14 12:06:00"}


def found_case(tmp_path):
    """A case whose evidence holds one SBECmd CSV and no messages file, so the CSV's events cite the CSV itself."""
    evidence = tmp_path / "evidence"
    write_rows(evidence / CSV, SBE_COLUMNS, [BAG])
    case = create_case(tmp_path / "case", "Found", evidence, "cody")
    intake(case)
    return case


def source_files(case):
    con = connect(case.db_path, read_only=True)
    try:
        return [row[0] for row in con.execute("SELECT DISTINCT source_file FROM events ORDER BY 1").fetchall()]
    finally:
        con.close()


def test_found_output_cites_the_evidence_relative_path_when_the_case_keeps_the_evidence_as_resolved(tmp_path):
    case = found_case(tmp_path)
    record = load_found_output(case, "sbecmd", "sbecmd_csv", "HOST", [CSV])
    assert (record.status, record.loaded_rows) == ("ok", 1)
    assert source_files(case) == [CSV]


def test_found_output_cites_the_evidence_relative_path_when_the_case_keeps_the_evidence_by_a_junction(tmp_path):
    case = found_case(tmp_path)
    link = tmp_path / "link"
    junction(link, case.evidence)
    by_junction = dataclasses.replace(case, settings=dataclasses.replace(case.settings, evidence_path=str(link)))
    record = load_found_output(by_junction, "sbecmd", "sbecmd_csv", "HOST", [CSV])
    assert (record.status, record.loaded_rows) == ("ok", 1)
    assert source_files(case) == [CSV]


MESSAGES = "HOST/Modules/FileFolderAccess/!SBECmd_Messages.txt"
HIVE = r"D:\Evidence\HOST\Users\alice\AppData\Local\Microsoft\Windows\UsrClass.dat"


def write_messages(evidence, hive=HIVE, path=MESSAGES):
    exported = r"C:\out\alice_UsrClass.csv"
    (evidence / path).write_text(
        f"[03:17:41.800 INF] Finished processing {hive}\n[03:17:41.800 INF] Exported to: {exported}\n", encoding="utf-8")


def case_with_messages(tmp_path):
    """A case whose evidence holds an SBECmd CSV and the messages file that names its hive, hashed at intake."""
    evidence = tmp_path / "evidence"
    write_rows(evidence / CSV, SBE_COLUMNS, [BAG])
    write_messages(evidence)
    case = create_case(tmp_path / "case", "Found", evidence, "cody")
    intake(case)
    return case


def test_found_sbecmd_output_loads_when_the_messages_file_is_unchanged(tmp_path):
    case = case_with_messages(tmp_path)
    record = load_found_output(case, "sbecmd", "sbecmd_csv", "HOST", [CSV])
    assert (record.status, record.loaded_rows, record.evidence_check, record.inputs) == ("ok", 1, "ok", [CSV])
    assert source_files(case) == [HIVE.replace("\\", "/")]   # the hive the messages file names


def test_found_sbecmd_output_fails_when_the_messages_file_changed_after_intake(tmp_path):
    case = case_with_messages(tmp_path)
    write_messages(case.evidence, hive=HIVE.replace("alice", "bob"))
    record = load_found_output(case, "sbecmd", "sbecmd_csv", "HOST", [CSV])
    assert record.status == "failed" and record.loaded_rows is None and record.inputs == [CSV]
    assert record.evidence_check == "mismatch" and f"{MESSAGES}: SHA-256 changed" in record.reason


def test_found_sbecmd_output_fails_when_the_messages_file_is_gone(tmp_path):
    case = case_with_messages(tmp_path)
    (case.evidence / MESSAGES).unlink()
    record = load_found_output(case, "sbecmd", "sbecmd_csv", "HOST", [CSV])
    assert record.status == "failed" and f"{MESSAGES}: missing" in record.reason


def test_found_sbecmd_output_fails_for_a_messages_file_the_manifest_does_not_list_until_it_is_added(tmp_path):
    evidence = tmp_path / "evidence"
    write_rows(evidence / CSV, SBE_COLUMNS, [BAG])
    case = create_case(tmp_path / "case", "Found", evidence, "cody")
    intake(case)
    write_messages(evidence)   # put there after intake
    record = load_found_output(case, "sbecmd", "sbecmd_csv", "HOST", [CSV])
    assert record.status == "failed" and f"{MESSAGES}: not in the manifest" in record.reason
    assert "Add new evidence" in record.reason
    assert (record.loaded_rows, record.evidence_check, record.evidence_problems) == (None, "not checked", [])
    assert json.loads(case.verification_path.read_text(encoding="utf-8").splitlines()[-1])["result"] == "ok"
    add_new(case)
    again = load_found_output(case, "sbecmd", "sbecmd_csv", "HOST", [CSV])
    assert (again.status, again.loaded_rows) == ("ok", 1)


def sbecmd_group(host):
    return {"key": "sbecmd_csv", "host": host, "preset": "", "tool": "sbecmd", "parser": "sbecmd_csv"}


def test_a_job_goes_on_past_a_load_that_waits_for_its_messages_file_to_be_added(tmp_path):
    evidence = tmp_path / "evidence"
    other = "OTHER/Modules/FileFolderAccess/bob_UsrClass.csv"
    for path in (CSV, other):
        write_rows(evidence / path, SBE_COLUMNS, [BAG])
    case = create_case(tmp_path / "case", "Found", evidence, "cody")
    intake(case)
    write_messages(evidence)   # beside HOST's CSV only, after intake
    finished = []
    stopped = run_and_load(case, [], [sbecmd_group("HOST"), sbecmd_group("OTHER")], lambda step: None,
                           lambda step, records: finished.extend(records))
    assert stopped == ""
    assert [(r.host, r.status, r.evidence_check) for r in finished] == [("HOST", "failed", "not checked"), ("OTHER", "ok", "ok")]


def test_a_rebuild_loads_found_output_unchecked_when_its_messages_file_is_not_in_the_manifest(tmp_path):
    case = found_case(tmp_path)
    assert load_found_output(case, "sbecmd", "sbecmd_csv", "HOST", [CSV]).status == "ok"
    write_messages(case.evidence)   # after intake
    (record,) = read_runs(case)
    assert run_problems(case, record, "test") == ([], [MESSAGES])
    rebuild(case)
    (saved,) = read_runs(case)
    assert saved.loaded_rows == 1
    assert LEFT_OUT not in saved.notes[-1] and MESSAGES in saved.notes[-1] and UNLISTED_NOTE in saved.notes[-1]
    assert source_files(case) == [HIVE.replace("\\", "/")]


def changing_during_the_load(monkeypatch, change):
    """Make a load of found output call change(case) once it has read, as another program changing the evidence would."""
    real = runner_module.load_output

    def load(case, record, folder, *args, **options):
        real(case, record, folder, *args, **options)
        change(case)

    monkeypatch.setattr(runner_module, "load_output", load)


def test_found_sbecmd_output_fails_when_its_messages_file_changes_while_it_loads(tmp_path, monkeypatch):
    case = case_with_messages(tmp_path)
    changing_during_the_load(monkeypatch, lambda case: write_messages(case.evidence, hive=HIVE.replace("alice", "bob")))
    record = load_found_output(case, "sbecmd", "sbecmd_csv", "HOST", [CSV])
    assert (record.status, record.evidence_check, record.reason) == ("failed", "mismatch", "evidence changed while it was read")
    assert record.evidence_problems == [f"{MESSAGES}: SHA-256 changed"]


def test_found_sbecmd_output_fails_when_a_messages_file_appears_while_it_loads(tmp_path, monkeypatch):
    case = found_case(tmp_path)
    changing_during_the_load(monkeypatch, lambda case: write_messages(case.evidence))
    record = load_found_output(case, "sbecmd", "sbecmd_csv", "HOST", [CSV])
    assert (record.status, record.evidence_check) == ("failed", "mismatch")
    assert record.evidence_problems == [f"{MESSAGES}: not in the manifest"]


def test_a_messages_file_the_manifest_lists_in_other_letter_case_is_checked_as_listed(tmp_path):
    evidence = tmp_path / "evidence"
    write_rows(evidence / CSV, SBE_COLUMNS, [BAG])
    write_messages(evidence, path=MESSAGES.replace("!SBECmd_Messages", "!sbecmd_messages"))
    case = create_case(tmp_path / "case", "Found", evidence, "cody")
    intake(case)
    record = load_found_output(case, "sbecmd", "sbecmd_csv", "HOST", [CSV])
    assert (record.status, record.evidence_check, record.evidence_problems) == ("ok", "ok", [])
    assert source_files(case) == [HIVE.replace("\\", "/")]


def test_a_rebuild_leaves_out_found_sbecmd_output_whose_messages_file_changed_since_it_loaded(tmp_path):
    case = case_with_messages(tmp_path)
    assert load_found_output(case, "sbecmd", "sbecmd_csv", "HOST", [CSV]).status == "ok"
    write_messages(case.evidence, hive=HIVE.replace("alice", "bob"))
    rebuild(case)
    (saved,) = read_runs(case)
    assert saved.loaded_rows == 0
    assert LEFT_OUT in saved.notes[-1] and f"{MESSAGES}: SHA-256 changed" in saved.notes[-1]


LOG = f"HOST/Modules/FileFolderAccess/{CONSOLE_LOG_NAME}"
OLDER_LOG = "HOST/Modules/FileFolderAccess/20261024090000_SBECmd_2026.10.2_ConsoleLog.txt"


def write_console_log(evidence, hive=HIVE, path=LOG):
    """The console log of a 2026.10 build, which takes the messages file's place beside the CSV it names."""
    text = console_log_text(hive, r"C:\out\alice_UsrClass.csv", name=path.rpartition("/")[2])
    (evidence / path).write_text(text, encoding="utf-8", newline="")


def case_with_console_log(tmp_path):
    """A case whose evidence holds an SBECmd CSV and the console log that names its hive, hashed at intake."""
    evidence = tmp_path / "evidence"
    write_rows(evidence / CSV, SBE_COLUMNS, [BAG])
    write_console_log(evidence)
    case = create_case(tmp_path / "case", "Found", evidence, "cody")
    intake(case)
    return case


def test_found_sbecmd_output_loads_when_the_console_log_is_unchanged(tmp_path):
    """The log is read beside the CSV and checked with it, but the run's input is the CSV alone."""
    case = case_with_console_log(tmp_path)
    record = load_found_output(case, "sbecmd", "sbecmd_csv", "HOST", [CSV])
    assert (record.status, record.loaded_rows, record.evidence_check, record.inputs) == ("ok", 1, "ok", [CSV])
    assert source_files(case) == [HIVE.replace("\\", "/")]   # the hive the console log names


def test_found_sbecmd_output_fails_when_the_console_log_changed_after_intake(tmp_path):
    case = case_with_console_log(tmp_path)
    write_console_log(case.evidence, hive=HIVE.replace("alice", "bob"))
    record = load_found_output(case, "sbecmd", "sbecmd_csv", "HOST", [CSV])
    assert record.status == "failed" and record.loaded_rows is None and record.inputs == [CSV]
    assert record.evidence_check == "mismatch" and f"{LOG}: SHA-256 changed" in record.reason


def test_found_sbecmd_output_fails_when_the_console_log_is_gone(tmp_path):
    case = case_with_console_log(tmp_path)
    (case.evidence / LOG).unlink()
    record = load_found_output(case, "sbecmd", "sbecmd_csv", "HOST", [CSV])
    assert record.status == "failed" and f"{LOG}: missing" in record.reason


def test_found_sbecmd_output_fails_for_a_console_log_the_manifest_does_not_list_until_it_is_added(tmp_path):
    case = found_case(tmp_path)
    write_console_log(case.evidence)   # put there after intake
    record = load_found_output(case, "sbecmd", "sbecmd_csv", "HOST", [CSV])
    assert record.status == "failed" and f"{LOG}: not in the manifest" in record.reason
    assert (record.loaded_rows, record.evidence_check, record.evidence_problems) == (None, "not checked", [])
    add_new(case)
    again = load_found_output(case, "sbecmd", "sbecmd_csv", "HOST", [CSV])
    assert (again.status, again.loaded_rows) == ("ok", 1)


def test_found_sbecmd_output_fails_when_a_console_log_appears_while_it_loads(tmp_path, monkeypatch):
    case = found_case(tmp_path)
    changing_during_the_load(monkeypatch, lambda case: write_console_log(case.evidence))
    record = load_found_output(case, "sbecmd", "sbecmd_csv", "HOST", [CSV])
    assert (record.status, record.evidence_check) == ("failed", "mismatch")
    assert record.evidence_problems == [f"{LOG}: not in the manifest"]


def test_every_console_log_beside_found_sbecmd_output_is_checked(tmp_path):
    """A folder that holds the logs of two runs: the one that isn't named for a CSV is read all the same, so a change to
    it is caught. A log in another folder is none of the load's concern."""
    evidence = tmp_path / "evidence"
    write_rows(evidence / CSV, SBE_COLUMNS, [BAG])
    write_console_log(evidence)
    write_console_log(evidence, hive=HIVE.replace("alice", "bob"), path=OLDER_LOG)
    (evidence / "HOST" / "Modules" / "Other").mkdir()
    write_console_log(evidence, path="HOST/Modules/Other/" + CONSOLE_LOG_NAME)
    case = create_case(tmp_path / "case", "Found", evidence, "cody")
    intake(case)
    write_console_log(evidence, hive=HIVE.replace("alice", "carol"), path="HOST/Modules/Other/" + CONSOLE_LOG_NAME)
    ok = load_found_output(case, "sbecmd", "sbecmd_csv", "HOST", [CSV])
    assert (ok.status, ok.evidence_check) == ("ok", "ok")
    assert source_files(case) == [HIVE.replace("\\", "/")]   # the later run's log names the CSV
    write_console_log(evidence, hive=HIVE.replace("alice", "dave"), path=OLDER_LOG)
    changed = load_found_output(case, "sbecmd", "sbecmd_csv", "HOST", [CSV])
    assert changed.status == "failed" and f"{OLDER_LOG}: SHA-256 changed" in changed.reason


OTHER_TOOL_LOG = "HOST/Modules/FileFolderAccess/20261025181337_EvtxECmd_2026.10.2_ConsoleLog.txt"


def test_another_tool_s_console_log_beside_found_sbecmd_output_is_neither_read_nor_checked(tmp_path):
    """A KAPE module folder can hold the console log of a tool other than SBECmd. Its lines name no hive for the CSV, a
    change to it after intake doesn't fail the load, and a second one put there after intake isn't reported as a file
    the load needs."""
    evidence = tmp_path / "evidence"
    write_rows(evidence / CSV, SBE_COLUMNS, [BAG])
    write_console_log(evidence, path=OTHER_TOOL_LOG)   # lines that would name the hive, were it SBECmd's log
    case = create_case(tmp_path / "case", "Found", evidence, "cody")
    intake(case)
    write_console_log(evidence, hive=HIVE.replace("alice", "bob"), path=OTHER_TOOL_LOG)
    write_console_log(evidence, path=OTHER_TOOL_LOG.replace("20261025", "20261026"))
    record = load_found_output(case, "sbecmd", "sbecmd_csv", "HOST", [CSV])
    assert (record.status, record.evidence_check, record.evidence_problems) == ("ok", "ok", [])
    assert source_files(case) == [CSV]   # no SBECmd log names its hive, so the events cite the CSV
    assert run_problems(case, record, "test") == ([], [])


def test_a_folder_named_like_a_console_log_is_none_of_the_files_a_load_of_found_sbecmd_output_needs(tmp_path):
    case = found_case(tmp_path)
    (case.evidence / LOG).mkdir()   # put there after intake
    record = load_found_output(case, "sbecmd", "sbecmd_csv", "HOST", [CSV])
    assert (record.status, record.evidence_check, record.evidence_problems) == ("ok", "ok", [])
    assert run_problems(case, record, "test") == ([], [])


def test_a_rebuild_loads_found_output_unchecked_when_its_console_log_is_not_in_the_manifest(tmp_path):
    case = found_case(tmp_path)
    assert load_found_output(case, "sbecmd", "sbecmd_csv", "HOST", [CSV]).status == "ok"
    write_console_log(case.evidence)   # after intake
    (record,) = read_runs(case)
    assert run_problems(case, record, "test") == ([], [LOG])
    rebuild(case)
    (saved,) = read_runs(case)
    assert saved.loaded_rows == 1
    assert LEFT_OUT not in saved.notes[-1] and LOG in saved.notes[-1] and UNLISTED_NOTE in saved.notes[-1]
    assert source_files(case) == [HIVE.replace("\\", "/")]


def test_a_load_of_found_output_records_what_its_parser_skipped_once_the_case_is_at_format_4(tmp_path):
    """An EVE file found in the evidence, whose last line was cut short, and an SBECmd CSV, whose parser counts nothing.
    A case below format 4 keeps run.json in the shape the builds of its format read."""
    evidence = tmp_path / "evidence"
    (evidence / "SENSOR").mkdir(parents=True)
    (evidence / "SENSOR" / "eve.json").write_text(eve_lines([1000, 1001]) + '{"timestamp": "2024', encoding="utf-8")
    write_rows(evidence / CSV, SBE_COLUMNS, [BAG])
    case = create_case(tmp_path / "case", "Found", evidence, "cody")
    intake(case)
    saved = lambda record: json.loads((case.runs_folder / record.run_id / "run.json").read_text(encoding="utf-8"))
    below = format3_case(case)
    for record in (load_found_output(below, "suricata", "suricata_eve", "SENSOR", ["SENSOR/eve.json"]),
                   load_found_output(below, "sbecmd", "sbecmd_csv", "HOST", [CSV])):
        assert (record.status, record.rows_skipped) == ("ok", None)
        assert not {"tool_files", "rows_skipped", "tool_check"} & set(saved(record))
    at_4 = upgraded(open_case(case.folder))
    eve = load_found_output(at_4, "suricata", "suricata_eve", "SENSOR", ["SENSOR/eve.json"])
    assert (eve.status, eve.loaded_rows, eve.rows_skipped, saved(eve)["rows_skipped"]) == ("ok", 2, 1, 1)
    bags = load_found_output(at_4, "sbecmd", "sbecmd_csv", "HOST", [CSV])
    assert (bags.status, bags.rows_skipped) == ("ok", None) and "rows_skipped" not in saved(bags)
    assert "tool_files" not in saved(eve) and "tool_files" not in saved(bags)   # no tool ran


def test_a_load_of_several_found_files_records_the_sum_of_what_its_parser_skipped(tmp_path):
    """A found-output group loads all of a host's files in one run. Each EVE file here ends in a line cut short."""
    evidence = tmp_path / "evidence"
    for folder, ids in (("a", [1000, 1001]), ("b", [1002])):
        (evidence / "SENSOR" / folder).mkdir(parents=True)
        (evidence / "SENSOR" / folder / "eve.json").write_text(eve_lines(ids) + '{"timestamp": "2024', encoding="utf-8")
    case = create_case(tmp_path / "case", "Found", evidence, "cody")
    intake(case)
    eve = load_found_output(case, "suricata", "suricata_eve", "SENSOR", ["SENSOR/a/eve.json", "SENSOR/b/eve.json"])
    saved = json.loads((case.runs_folder / eve.run_id / "run.json").read_text(encoding="utf-8"))
    assert (eve.status, eve.loaded_rows, eve.rows_skipped, saved["rows_skipped"]) == ("ok", 3, 2, 2)
