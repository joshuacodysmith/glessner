"""Suggestion rules, Hayabusa, Suricata, and imported fast alert suggestions, accept and reject, the to-investigate
list, and exports."""

import csv
import json
import re
from pathlib import Path

import pytest
from conftest import DOTTED_QUAD, METASPLOIT, SEC, T0, eve_alert
from test_analysis_relations import WINDOWS_10, add_os

from glessner.events import Event, event_uid, load
from glessner.export import export_timeline, write_report
from glessner.parsers import PARSERS, ParseContext
from glessner.queries import QueryError, investigate, pending_for_source
from glessner.rules import RuleError, parse
from glessner.server import (
    App,
    api_counts,
    api_event,
    api_host,
    api_mark,
    api_meta,
    api_pending,
    api_rule,
    api_rules,
    api_suggestion,
)


def test_rule_compiles_to_parameters_not_sql():
    rule = parse("id: r1\nsuggest: suspicious\nwhen:\n  any:\n"
                 "    - {field: user_name, equals: \"x' OR 1=1 --\"}\n"
                 "    - {field: ts_us, between: ['2020-09-19T03:00:00Z', '2020-09-19T04:00:00Z']}\n"
                 "    - not: {field: host, in: [DC01, DESKTOP]}\n")
    assert "OR 1=1" not in rule.where and "x' or 1=1 --" in rule.params
    assert 1600484400000000 in rule.params   # 03:00 UTC as epoch microseconds


def test_rule_values_compare_as_written():
    """A rule's text values aren't read with YAML 1.1's types, so an unquoted 0x3e7, as EvtxECmd shows a logon ID, doesn't
    compare as '999', an event code with a leading zero isn't octal, and no isn't 'false'. Numbers and true or false are
    read only where a field takes them."""
    rule = parse("id: r\nsuggest: suspicious\nwhen:\n  all:\n    - {field: logon_id, equals: 0x3e7}\n"
                 "    - {field: event_code, in: [0400, 4624]}\n    - {field: user_name, equals: no}\n"
                 "    - {field: record_id, in: [7, '8']}\n"
                 "    - {field: ts_us, between: [1600484400000000, 2020-09-19T04:00:00Z]}\n"
                 "    - {field: source_host, collected: true}\n")
    assert rule.params == ("0x3e7", "0400", "4624", "no", 7, 8, 1600484400000000, 1600488000000000)
    for bad, message in (("{field: source_host, collected: maybe}", "true or false"),
                         ("{field: user_name, equals: [a, b]}", "takes text values"),
                         ("{field: record_id, equals: seven}", "needs a number")):
        with pytest.raises(RuleError, match=message):
            parse(f"id: r\nsuggest: suspicious\nwhen: {bad}\n")


def test_rule_numbers_and_true_or_false_read_as_before():
    """Values are kept as written for text fields only. Numbers, times, and collected are read as YAML 1.1 reads them,
    so a rule journaled earlier still compiles to what it meant."""
    rule = lambda cond: parse(f"id: r\nsuggest: suspicious\nwhen: {cond}\n")
    assert rule("{field: record_id, in: [0x10, 1_000, 010, +7]}").params == (16, 1000, 8, 7)
    assert rule("{field: ts_us, between: [2020-09-19 03:00:00, 1_600_488_000_000_000]}").params == (
        1600484400000000, 1600488000000000)
    for yes, no in (("yes", "no"), ("on", "off"), ("True", "FALSE")):
        assert rule(f"{{field: source_host, collected: {yes}}}").where == rule("{field: source_host, collected: true}").where
        assert rule(f"{{field: source_host, collected: {no}}}").where == rule("{field: source_host, collected: false}").where
    assert rule("{field: source_host, collected: true}").where != rule("{field: source_host, collected: false}").where


@pytest.mark.parametrize("text,message", [
    ("id: r\nsuggest: evil\nwhen: {field: host, equals: x}", "suggest must be"),
    ("id: r\nsuggest: suspicious\nwhen: {field: password, equals: x}", "unknown field"),
    ("id: r\nsuggest: suspicious\nwhen: {field: host, equals: x, regex: y}", "one operator"),
    ("id: r\nsuggest: suspicious\nwhen: {field: host, regex: '('}", "bad regex"),
    ("id: r\nsuggest: suspicious\nwhen: {field: host, regex: 'DC(?=01)'}", "bad regex .* for RE2"),   # a lookahead
    ("id: r\nsuggest: suspicious\nwhen: {field: host, regex: '(D)\\1'}", "bad regex .* for RE2"),
    ("id: 'bad id!'\nsuggest: suspicious\nwhen: {field: host, equals: x}", "id must be"),
    ("id: r\nsuggest: suspicious\nwhen: {field: host, collected: true}", "collected applies only"),
    ("{not yaml", "not valid YAML"),
])
def test_bad_rules_are_refused(text, message):
    with pytest.raises(RuleError, match=message):
        parse(text)


def test_a_journaled_rule_whose_regex_re2_cant_compile_says_why_and_the_rest_build(synthetic_case):
    """A journaled rule whose regex RE2 can't compile, here a lookahead, which Python's re reads, would fail only as it
    runs, and in the server's rebuild, one transaction, that failure would abort the rebuild and the case open with it.
    Parse refuses it, so the case opens, the rule says why, and the other sources build."""
    from glessner.journal import Journal

    Journal(synthetic_case).append("rule_add", id="lookahead",
                                   text="id: lookahead\nsuggest: suspicious\nwhen: {field: host, regex: 'DC(?=01)'}\n")
    app = App(synthetic_case)
    try:
        rules = {r["id"]: r for r in api_rules(app, {})["rules"]}
        assert "for RE2" in rules["lookahead"]["error"] and "invalid perl operator" in rules["lookahead"]["error"]
        assert rules["hayabusa"]["matched"] == 1 and rules["machine-accounts-authorized"]["matched"] == 1
        with pytest.raises(QueryError, match=r"rule not saved: bad regex .* for RE2"):
            api_rule(app, {"op": "add", "text": "id: other\nsuggest: suspicious\nwhen: {field: host, regex: '(D)\\1'}\n"})
    finally:
        app.con.close()


def test_rule_text_fields_are_event_columns():
    """A rule's text fields are the events table's columns, the parent process and registry data among them."""
    from glessner.events import COLUMNS
    from glessner.rules import TEXT_FIELDS

    assert TEXT_FIELDS.issubset(COLUMNS)
    rule = parse("id: r\nsuggest: suspicious\nwhen:\n  all:\n    - {field: process_parent_executable, regex: 'w3wp'}\n"
                 "    - {field: registry_data, equals: x}\n")
    assert "e.process_parent_executable" in rule.where and "e.registry_data" in rule.where


def test_a_rule_can_match_a_network_events_destination(app):
    """The list of rule fields includes dest_ip, dest_port, and source_port, so a rule for connections to an address,
    from Sysmon 3, 5156, or a firewall import, can be written."""
    from glessner.events import COLUMNS, Event
    from glessner.rules import NUMBER_FIELDS, TEXT_FIELDS

    connection = Event(ts_us=T0, ts_desc="Event Recorded", artifact="evtx", source_file="DC01/Sysmon.evtx",
                       source_record="1", message="3 Network connection", event_code="3", source_ip="10.42.85.10",
                       source_port="49712", dest_ip="203.78.103.109", dest_port="443")
    load(app.case.db_path, [connection], host="DC01", tool="evtxecmd", tool_version="t", run_id="r9",
         replaces_sources=["DC01/Sysmon.evtx"], staging_dir=app.case.folder)
    app.refresh_identity(events_changed=True)
    rule = ("id: to-c2\nsuggest: malicious\nwhen:\n  all:\n    - {field: dest_ip, equals: 203.78.103.109}\n"
            "    - {field: dest_port, in: ['443', '8443']}\n    - {field: source_port, regex: '^49'}\n")
    report = {r["id"]: r for r in api_rule(app, {"op": "add", "text": rule})["rules"]}
    assert report["to-c2"]["matched"] == 1
    uid = app.con.execute("SELECT event_uid FROM events WHERE source_file = 'DC01/Sysmon.evtx'").fetchone()[0]
    assert lane_mark(app, uid) == "Suggested: malicious"
    # Neither of case format 3's computed columns is a rule field
    assert set(COLUMNS) - {"event_uid", "extra", "origin_host", "account_key", "hashes"} == TEXT_FIELDS | NUMBER_FIELDS


@pytest.fixture
def app(synthetic_case):
    a = App(synthetic_case)
    yield a
    a.con.close()


def uid_at(app, ts, tool="evtxecmd"):
    return app.con.execute("SELECT event_uid FROM events WHERE tool = ? AND ts_us = ?", [tool, ts]).fetchone()[0]


def lane_mark(app, uid):
    from glessner.queries import BASE_FROM, MARK_EXPR
    return app.con.execute(f"SELECT {MARK_EXPR} FROM {BASE_FROM} WHERE e.event_uid = ?", [uid]).fetchone()[0]


def test_builtin_rule_and_hayabusa_suggest(app):
    rules = {r["id"]: r for r in api_rules(app, {})["rules"]}
    assert rules["machine-accounts-authorized"]["builtin"] and rules["machine-accounts-authorized"]["matched"] == 1
    assert rules["hayabusa"]["matched"] == 1
    assert lane_mark(app, uid_at(app, T0 + 61 * SEC)) == "Suggested: authorized"     # DESKTOP-SDN1RPT$ logon
    assert lane_mark(app, uid_at(app, T0)) == "Suggested: suspicious"                # RDP with a high Hayabusa hit
    assert lane_mark(app, uid_at(app, T0 + 60 * SEC)) == "Unreviewed"                # mortysmith


def test_removed_builtin_rule_stays_removed(synthetic_case):
    a = App(synthetic_case)
    api_rule(a, {"op": "remove", "id": "machine-accounts-authorized"})
    a.con.close()
    b = App(synthetic_case)
    try:
        assert "machine-accounts-authorized" not in b.journal.state.rules
        assert lane_mark(b, uid_at(b, T0 + 61 * SEC)) == "Unreviewed"
    finally:
        b.con.close()


def test_accept_reject_and_restore(app):
    morty = "id: morty-suspicious\nsuggest: suspicious\nwhen: {field: account, equals: 'c137\\mortysmith'}\n"
    report = {r["id"]: r for r in api_rule(app, {"op": "add", "text": morty})["rules"]}
    assert report["morty-suspicious"]["pending"] == 1
    morty_uid = uid_at(app, T0 + 60 * SEC)
    api_suggestion(app, {"decision": "reject", "source": "morty-suspicious"})
    assert lane_mark(app, morty_uid) == "Unreviewed"
    api_suggestion(app, {"decision": "restore", "source": "morty-suspicious", "uids": [morty_uid]})
    assert lane_mark(app, morty_uid) == "Suggested: suspicious"
    result = api_suggestion(app, {"decision": "accept", "source": "hayabusa"})
    assert result["changed"] == 1 and lane_mark(app, uid_at(app, T0)) == "Suspicious"
    last = json.loads((app.case.folder / "journal.jsonl").read_text().splitlines()[-1])
    assert last["action"] == "mark" and last["note"] == "Accepted suggestion from hayabusa"
    with pytest.raises(ValueError, match="already exists"):
        api_rule(app, {"op": "add", "text": morty})


def test_to_investigate_and_the_rules_page_count_pending_suggestions_after_a_manual_mark(app):
    """A mark made with the mark buttons, not Accept, takes the event out of the pending counts of To investigate and
    the Rules page at once, since they read the counts live, not from the last time the suggestions were built."""
    from glessner.server import api_investigate

    pending = lambda: {r["id"]: (r["matched"], r["pending"]) for r in api_investigate(app, {})["rules"]}["hayabusa"]
    assert pending() == (1, 1)
    api_mark(app, {"uids": [uid_at(app, T0)], "value": "suspicious"})
    assert pending() == (1, 0)
    assert {r["id"]: r["pending"] for r in api_rules(app, {})["rules"]}["hayabusa"] == 0


def test_accept_journals_the_analyst_s_note_after_the_fixed_text(app):
    """A note typed before Accept is journaled after the fixed text "Accepted suggestion from ..."."""
    rdp = uid_at(app, T0)
    api_suggestion(app, {"decision": "accept", "source": "hayabusa", "uids": [rdp], "note": "  RDP from the internet  "})
    last = json.loads((app.case.folder / "journal.jsonl").read_text().splitlines()[-1])
    assert (last["action"], last["note"]) == ("mark", "Accepted suggestion from hayabusa: RDP from the internet")
    assert lane_mark(app, rdp) == "Suspicious"


def test_accept_all_is_capped_as_a_mark_is(app, monkeypatch):
    """Accepting is marking, so it takes at most MAX_MARK_TARGETS events, as a mark or a tag does."""
    from glessner import server

    every = "id: every-logon\nsuggest: suspicious\nwhen: {field: event_code, in: ['4624', '4648']}\n"
    api_rule(app, {"op": "add", "text": every})
    uids = pending_for_source(app.reader(), "every-logon")["suspicious"]
    pending = len(uids)
    monkeypatch.setattr(server, "MAX_MARK_TARGETS", pending - 1)
    lines = (app.case.folder / "journal.jsonl").read_text().count("\n")
    # The refusal says what to do for the request it got: Accept all, chosen events, or one group
    for more, advice in (({}, "a group at a time from the source's Suggestions page"), ({"uids": uids}, "fewer at a time")):
        with pytest.raises(QueryError, match=f"would mark {pending} events, more than the {pending - 1} .*{advice}"):
            api_suggestion(app, {"decision": "accept", "source": "every-logon", **more})
    big = max(api_pending(app, {"source": ["every-logon"], "group_by": ["host"]})["groups"], key=lambda g: g["count"])
    monkeypatch.setattr(server, "MAX_MARK_TARGETS", big["count"] - 1)
    with pytest.raises(QueryError, match=f"would mark {big['count']} events.* Group the suggestions another way"):
        api_suggestion(app, {"decision": "accept", "source": "every-logon", "group_by": "host", "group": big["key"]})
    assert (app.case.folder / "journal.jsonl").read_text().count("\n") == lines   # nothing journaled
    monkeypatch.setattr(server, "MAX_MARK_TARGETS", pending)
    assert api_suggestion(app, {"decision": "accept", "source": "every-logon"})["changed"] == pending


@pytest.fixture
def alerts_app(suricata_case):
    a = App(suricata_case)
    yield a
    a.con.close()


def alert_uids(app):
    """The fixture's alerts in time order: severity 1, two at severity 2, and severity 3."""
    return [uid_at(app, T0 + s * SEC, "suricata") for s in (1200, 1260, 1320, 1380)]


def test_suricata_alerts_at_severity_1_and_2_suggest(alerts_app):
    """Suricata alerts at severity 1 or 2 are a built-in source like Hayabusa's; severity 3 stays searchable
    only. The counts are exact, so a severity read as NULL from the dotted key can't pass as no alerts."""
    from glessner.queries import event_details
    app = alerts_app
    rules = {r["id"]: r for r in api_rules(app, {})["rules"]}
    entry = rules["suricata"]
    assert (entry["suggest"], entry["description"], entry["builtin"], entry["editable"]) == (
        "suspicious", "Suricata alerts at severity 1 or 2", True, False)
    assert (entry["matched"], entry["pending"], rules["hayabusa"]["matched"]) == (3, 3, 1)
    severities = app.con.execute("SELECT severity, count(*) FROM suricata_alerts GROUP BY 1").fetchall()
    assert dict(severities) == {1: 1, 2: 2, 3: 1}
    first, second, third, low = alert_uids(app)
    assert [lane_mark(app, u) for u in (first, second, third)] == ["Suggested: suspicious"] * 3
    assert lane_mark(app, low) == "Unreviewed"
    details = event_details(app.con, first)
    assert details["suggestions"] == [{"value": "suspicious", "source": "suricata", "rejected": False}]


def test_suricata_suggestions_accept_reject_and_restore(alerts_app):
    app = alerts_app
    first, second, third, _ = alert_uids(app)
    api_suggestion(app, {"decision": "reject", "source": "suricata", "uids": [second, third]})
    last = json.loads((app.case.folder / "journal.jsonl").read_text().splitlines()[-1])
    assert (last["action"], last["source"], last["decision"]) == ("suggestion_decision", "suricata", "rejected")
    assert lane_mark(app, second) == lane_mark(app, third) == "Unreviewed"
    api_suggestion(app, {"decision": "restore", "source": "suricata", "uids": [second]})
    assert lane_mark(app, second) == "Suggested: suspicious" and lane_mark(app, third) == "Unreviewed"
    result = api_suggestion(app, {"decision": "accept", "source": "suricata"})   # all pending; the rejected stays out
    assert result["changed"] == 2 and lane_mark(app, first) == lane_mark(app, second) == "Suspicious"
    last = json.loads((app.case.folder / "journal.jsonl").read_text().splitlines()[-1])
    assert (last["action"], last["value"], last["note"]) == ("mark", "suspicious", "Accepted suggestion from suricata")
    assert sorted(last["targets"]) == sorted([first, second])
    rules = {r["id"]: r for r in result["rules"]}
    assert (rules["suricata"]["matched"], rules["suricata"]["pending"]) == (3, 0)


@pytest.mark.parametrize("rule_id", ["hayabusa", "suricata", "ids_alert"])
def test_rules_cannot_take_a_builtin_source_id(app, rule_id):
    """A rule with a built-in source's ID would merge with that source's suggestions, and one reject would
    cover both."""
    text = f"id: {rule_id}\nsuggest: suspicious\nwhen: {{field: host, equals: DC01}}\n"
    for op in ("add", "change"):
        with pytest.raises(ValueError, match=f"{rule_id} is a built-in suggestion source"):
            api_rule(app, {"op": op, "text": text})
    assert rule_id not in app.journal.state.rules
    rules = {r["id"]: r for r in api_rules(app, {})["rules"]}
    assert rules[rule_id]["builtin"] and not rules[rule_id]["editable"]


def test_a_rule_saved_under_a_builtin_source_id_is_not_run(alerts_app):
    """A journal can hold a rule named suricata, written when that was a legal ID. Run, it would share the source key
    and double every alert's suggestion; it waits instead, with an error telling the analyst to rename."""
    app = alerts_app
    app.journal.append("rule_add", id="suricata", text="id: suricata\nsuggest: suspicious\n"
                                                        "when: {field: log_channel, equals: alert}\n")
    app.refresh_suggestions()
    entry = {r["id"]: r for r in api_rules(app, {})["rules"]}["suricata"]
    assert (entry["matched"], entry["pending"], entry["editable"]) == (3, 3, True)   # the built-in's 3, not 3 + 4
    assert entry["error"].startswith("The rule suricata was not run")
    assert api_counts(app, {})["rule_errors"] == 1
    api_rule(app, {"op": "remove", "id": "suricata"})
    entry = {r["id"]: r for r in api_rules(app, {})["rules"]}["suricata"]
    assert "error" not in entry and entry["matched"] == 3 and not entry["editable"]


def test_an_alert_without_a_severity_is_never_suggested(suricata_case):
    """TRY_CAST leaves a missing severity NULL, so the alert stays searchable and unsuggested."""
    out = suricata_case.folder.parent / "no_severity"
    out.mkdir()
    record = eve_alert("03:45:48", 2999999, "TEST alert with no severity", 1, "198.51.100.7:80", "10.42.85.10:62420")
    del record["alert"]["severity"]
    (out / "eve.json").write_text(json.dumps(record) + "\n", encoding="utf-8")
    events = PARSERS["suricata_eve"](ParseContext(out, suricata_case.evidence, ("network/other.pcap",)))
    load(suricata_case.db_path, events, host="network", tool="suricata", tool_version="8.0.7", run_id="r7",
         replaces_sources=["network/other.pcap"], staging_dir=out)
    app = App(suricata_case)
    try:
        assert app.con.execute("SELECT severity FROM suricata_alerts WHERE signature = 'TEST alert with no severity'"
                               ).fetchall() == [(None,)]
        assert {r["id"]: r for r in api_rules(app, {})["rules"]}["suricata"]["matched"] == 3
        assert lane_mark(app, uid_at(app, T0 + 1440 * SEC, "suricata")) == "Unreviewed"
    finally:
        app.con.close()


@pytest.fixture
def fast_app(fast_alerts_case):
    a = App(fast_alerts_case)
    yield a
    a.con.close()


def fast_uids(app):
    """The imported fast alerts in time order: priority 1, two at priority 2, priority 3, and one with no priority."""
    return [uid_at(app, T0 + s * SEC, "import") for s in (1200, 1260, 1320, 1380, 1440)]


def test_fast_alerts_at_priority_1_and_2_suggest(fast_app):
    """Imported fast alerts at priority 1 or 2 are a built-in source like Suricata's EVE alerts;
    priority 3, and a line with no priority, stay searchable only. The counts are exact, so a priority read as NULL
    can't pass as no alerts."""
    from glessner.queries import event_details
    app = fast_app
    rules = {r["id"]: r for r in api_rules(app, {})["rules"]}
    entry = rules["ids_alert"]
    assert (entry["suggest"], entry["description"], entry["builtin"], entry["editable"]) == (
        "suspicious", "Imported Snort or Suricata fast alerts at priority 1 or 2", True, False)
    assert (entry["matched"], entry["pending"], rules["suricata"]["matched"]) == (3, 3, 0)
    priorities = app.con.execute("SELECT priority, count(*) FROM fast_alerts GROUP BY 1").fetchall()
    assert dict(priorities) == {1: 1, 2: 2, 3: 1, None: 1}
    first, second, third, low, none = fast_uids(app)
    assert [lane_mark(app, u) for u in (first, second, third)] == ["Suggested: suspicious"] * 3
    assert lane_mark(app, low) == lane_mark(app, none) == "Unreviewed"
    assert event_details(app.con, first)["suggestions"] == [
        {"value": "suspicious", "source": "ids_alert", "rejected": False}]


def test_fast_alerts_group_by_signature_and_take_decisions(fast_app):
    """Grouped by signature by default, priority 1 ahead of the larger priority 2 group, each named in the line's own
    words; a group's reject and an accept of the rest journal under the source's ID."""
    app = fast_app
    first, second, third, _, _ = fast_uids(app)
    pending = api_pending(app, {"source": ["ids_alert"]})
    assert (pending["group_by"], pending["total"]) == ("rule", 3)
    assert [(g["key"], g["level"], g["level_label"], g["count"]) for g in pending["groups"]] == [
        (METASPLOIT, "high", "priority 1", 1), (DOTTED_QUAD, "medium", "priority 2", 2)]
    result = api_suggestion(app, {"decision": "reject", "source": "ids_alert", "group_by": "rule",
                                  "group": DOTTED_QUAD})
    last = json.loads((app.case.folder / "journal.jsonl").read_text().splitlines()[-1])
    assert result["changed"] == 2 and (last["source"], last["decision"]) == ("ids_alert", "rejected")
    assert sorted(last["targets"]) == sorted([second, third])
    api_suggestion(app, {"decision": "accept", "source": "ids_alert"})
    last = json.loads((app.case.folder / "journal.jsonl").read_text().splitlines()[-1])
    assert (last["action"], last["targets"], last["note"]) == ("mark", [first], "Accepted suggestion from ids_alert")
    assert lane_mark(app, first) == "Suspicious" and lane_mark(app, second) == "Unreviewed"


def test_builtin_rules_flag_remote_execution_pipes_and_admin_share_tool_writes(synthetic_case, tmp_path):
    """5145 opens of remote execution pipes and writes of runnable files over admin shares
    suggest Suspicious. The rows go through the EvtxECmd parser, so a change to its message can't silently break the
    rules that read it."""
    from test_parsers import EVTX_COLUMNS, security_row, write_csv

    def share(record, name, local, target, access, codes, minute):
        row = security_row(record, 5145, "Network share object access",
                           {"SubjectUserName": "jlee", "IpAddress": "10.20.4.15", "ShareName": f"\\\\*\\{name}",
                            "ShareLocalPath": local, "RelativeTargetName": target, "AccessList": codes},
                           PayloadData1=f"Share: \\\\*\\{name} ({local})", PayloadData2=f"Object: {target}",
                           PayloadData3=f"AccessList: {access}")
        row["TimeCreated"] = f"2020-09-19 03:{minute:02d}:00.0000000"
        row["SourceFile"] = "D:\\Evidence\\case\\DC01\\Security5145.evtx"
        return row

    out = tmp_path / "run"
    out.mkdir()
    write_csv(out / "evtxecmd.csv", EVTX_COLUMNS, [
        share(1, "IPC$", "", "svcctl", "ReadData (or ListDirectory)", "%%4416, ", 30),
        share(2, "IPC$", "", "RemCom_stdin_1234", "Unknown code (%%4416 | %%4417)", "%%4416, %%4417, ", 31),
        share(3, "IPC$", "", "PSEXESVC-WS01-4242-stdin", "Unknown code (%%4416 | %%4417)", "%%4416, %%4417, ", 32),
        share(4, "ADMIN$", "\\??\\C:\\Windows", "PSEXESVC.exe", "Unknown code (%%4417 | %%4418)", "%%4417, %%4418, ", 33),
        share(5, "IPC$", "", "winreg", "ReadData (or ListDirectory)", "%%4416, ", 34),        # remote registry: not these
        share(6, "C$", "\\??\\C:\\", "Tools\\tool.exe", "ReadData (or ListDirectory)", "%%4416, ", 35),   # a read
        share(7, "C$", "\\??\\C:\\", "notes.txt", "WriteData (or AddFile)", "%%4417, ", 36),           # not runnable
        share(8, "IPC$", "", "spoolss", "ReadData (or ListDirectory)", "%%4416, ", 37),       # its own rule
        share(9, "IPC$", "", "RemCom_stdoutWS-01-4242", "ReadData (or ListDirectory)", "%%4416, ", 38),   # a hyphen
    ])
    events = list(PARSERS["evtxecmd_csv"](ParseContext(out, synthetic_case.evidence)))
    load(synthetic_case.db_path, events, host="DC01", tool="evtxecmd", tool_version="t", run_id="r8",
         replaces_sources=["DC01/Security5145.evtx"], staging_dir=out)
    a = App(synthetic_case)
    try:
        rules = {r["id"]: r for r in api_rules(a, {})["rules"]}
        assert rules["remote-execution-pipes"]["builtin"] and rules["admin-share-executable-writes"]["builtin"]
        assert share_suggestions(a) == {"remote-execution-pipes": ["1", "2", "3", "9"], "print-spooler-pipe": ["8"],
                                        "admin-share-executable-writes": ["4"]}
    finally:
        a.con.close()


def share_suggestions(app):
    return dict(app.con.execute(
        "SELECT source, list(e.source_record ORDER BY e.source_record) FROM suggestions s "
        "JOIN events e ON e.event_uid = s.event_uid WHERE source IN "
        "('remote-execution-pipes', 'print-spooler-pipe', 'admin-share-executable-writes') GROUP BY source").fetchall())


def test_builtin_share_rules_read_the_event_xml_readers_rows(synthetic_case, tmp_path):
    """The XML reader writes its own message parts, so the share rules have to match those too."""
    from test_event_xml import event, events_file

    from glessner.event_xml import convert

    def share(record, name, local, target, access):
        return event("5145", record, "DC01.corp.local",
                     {"SubjectUserName": "jlee", "SubjectDomainName": "CORP", "IpAddress": "10.20.4.15",
                      "IpPort": "51846", "ShareName": f"\\\\*\\{name}", "ShareLocalPath": local,
                      "RelativeTargetName": target, "AccessList": access},
                     time=f"2020-09-19T03:{30 + record:02d}:00.0000000Z")

    source = tmp_path / "Security5145.xml"
    source.write_text(events_file(
        share(1, "IPC$", "", "svcctl", "%%4416\n\t\t\t\t"),
        share(2, "ADMIN$", "\\??\\C:\\Windows", "PSEXESVC.exe", "%%4417\n\t\t\t\t%%4418\n\t\t\t\t"),
        share(3, "IPC$", "", "winreg", "%%4416\n\t\t\t\t"),
    ), encoding="utf-8")
    out = tmp_path / "run"
    out.mkdir()
    assert convert([source], out) == 3
    events = list(PARSERS["event_xml_csv"](ParseContext(out, synthetic_case.evidence)))
    assert events[0].message.endswith("Share: \\\\*\\IPC$ | Object: svcctl | Access: ReadData")   # no "()" after the address
    assert "Share: \\\\*\\ADMIN$ (\\??\\C:\\Windows) | Object: PSEXESVC.exe" in events[1].message
    # A reader's stored output may have "IPC$ () | Object" after the address, and a rebuild or a case copy parses it
    # again without the reader, so the parser words the share again.
    stored = out / "event_xml.csv"
    old = stored.read_bytes().replace(b"IPC$ | Object", b"IPC$ () | Object")
    assert old.count(b"IPC$ () | Object") == 2
    stored.write_bytes(old)
    assert [e.message for e in PARSERS["event_xml_csv"](ParseContext(out, synthetic_case.evidence))] == \
        [e.message for e in events]
    load(synthetic_case.db_path, events, host="DC01", tool="event_xml", tool_version="t", run_id="r9",
         replaces_sources=["DC01/Security5145.xml"], staging_dir=out)
    a = App(synthetic_case)
    try:
        assert share_suggestions(a) == {"remote-execution-pipes": ["1"], "admin-share-executable-writes": ["2"]}
    finally:
        a.con.close()


def test_builtin_share_rules_match_messages_in_the_older_share_form(synthetic_case):
    """Events loaded with "Share: \\\\*\\IPC$ () | Object: ..." keep that text until a rebuild, and the two IPC$ rules
    still suggest them."""
    log = "DC01/Security5145.evtx"
    old = [Event(T0 + i * SEC, "Event Recorded", "evtx", log, str(i + 1),
                 f"5145 Network share object access | Share: \\\\*\\IPC$ () | Object: {pipe} | Access: ReadData",
                 event_code="5145", log_channel="Security") for i, pipe in enumerate(("svcctl", "spoolss"))]
    load(synthetic_case.db_path, old, host="DC01", tool="evtxecmd", tool_version="t", run_id="r8",
         replaces_sources=[log], staging_dir=synthetic_case.folder)
    a = App(synthetic_case)
    try:
        assert share_suggestions(a) == {"remote-execution-pipes": ["1"], "print-spooler-pipe": ["2"]}
    finally:
        a.con.close()


def test_builtin_rules_take_the_apps_current_text_unless_the_analyst_changed_or_removed_them(synthetic_case):
    """A case made before a built-in rule changed gets the new text when opened. A rule the analyst
    changed is the analyst's, and a removed one stays removed."""
    from glessner.journal import Journal
    from glessner.rules import BUILTIN_RULES

    old = BUILTIN_RULES["remote-execution-pipes"].replace("svcctl|", "")
    mine = BUILTIN_RULES["admin-share-executable-writes"].replace("|sys)", "|sys|msi)")
    journal = Journal(synthetic_case)
    journal.append("rule_add", who="system", id="remote-execution-pipes", text=old, builtin=True)
    journal.append("rule_add", who="system", id="admin-share-executable-writes",
                   text=BUILTIN_RULES["admin-share-executable-writes"], builtin=True)
    journal.append("rule_change", id="admin-share-executable-writes", text=mine)
    journal.append("rule_remove", id="print-spooler-pipe")
    a = App(synthetic_case)
    try:
        rules = a.journal.state.rules
        assert rules["remote-execution-pipes"]["text"] == BUILTIN_RULES["remote-execution-pipes"]
        assert rules["remote-execution-pipes"]["builtin"]
        assert rules["admin-share-executable-writes"]["text"] == mine
        assert not rules["admin-share-executable-writes"]["builtin"]
        assert "print-spooler-pipe" not in rules
        assert rule_changes(a) == ["admin-share-executable-writes", "remote-execution-pipes"]
    finally:
        a.con.close()
    b = App(synthetic_case)   # opening again appends nothing
    try:
        assert rule_changes(b) == ["admin-share-executable-writes", "remote-execution-pipes"]
    finally:
        b.con.close()


def rule_changes(app):
    lines = app.journal.path.read_text(encoding="utf-8").splitlines()
    return [e["id"] for e in map(json.loads, lines) if e["action"] == "rule_change"]


def test_system_userid_exports_as_user_id_and_sessions_join_without_case(synthetic_case, tmp_path):
    """An account known only by its SID is ECS's user.id, not user.name. Sysmon's LogonId joins a 4624's session
    whichever case each reader wrote the hex in."""
    from test_parsers import EVTX_COLUMNS, security_row, sysmon_row, system_row, write_csv

    from glessner.queries import related

    sid = "S-1-5-21-3623811015-3361044348-30300820-1013"
    rows = [system_row(1, 7045, "Service installed", {"ServiceName": "PSEXESVC"}, UserId=sid),
            sysmon_row(2, 1, "Process creation", {"Image": "C:\\Windows\\System32\\cmd.exe", "LogonId": "0x5C1D2"}),
            security_row(3, 4624, "Successful logon", {"TargetUserName": "alice", "TargetLogonId": "0x5c1d2"})]
    for second, row in enumerate(rows):
        row["TimeCreated"] = f"2020-09-19 03:40:0{second}.0000000"
    out = tmp_path / "run"
    out.mkdir()
    write_csv(out / "evtxecmd.csv", EVTX_COLUMNS, rows)
    events = list(PARSERS["evtxecmd_csv"](ParseContext(out, synthetic_case.evidence)))
    load(synthetic_case.db_path, events, host="DC01", tool="evtxecmd", tool_version="t", run_id="r10",
         replaces_sources=["LAB/System.evtx", "LAB/Sysmon.evtx", "LAB/Security.evtx"], staging_dir=out)
    a = App(synthetic_case)
    try:
        shell = a.con.execute("SELECT event_uid FROM events WHERE run_id = 'r10' AND event_code = '1'").fetchone()[0]
        assert [e["code"] for e in related(a.con, shell, "session")["events"]] == ["1", "4624"]   # itself, then the logon
        path, _ = export_timeline(a.con, a.case, a.identity, 0, 2**62, "csv", "all")
        with path.open(encoding="utf-8", newline="") as f:
            service = next(r for r in csv.DictReader(f) if r["event.code"] == "7045" and r["run_id"] == "r10")
        assert (service["user.name"], service["user.id"]) == ("", sid)
    finally:
        a.con.close()


def test_investigate_and_exports(app):
    rdp = uid_at(app, T0)
    api_mark(app, {"uids": [rdp], "value": "malicious", "note": "RDP from the internet"})
    items = investigate(app.con)
    # The worklist's item, with the event's own columns for the ranking; its unreviewed counts are the page's
    assert [(i["uid"], i["mark"], i["note"], i["event"]["logon_id"]) for i in items] == [
        (rdp, "Malicious", "RDP from the internet", "0x510986")]

    path, rows = export_timeline(app.con, app.case, app.identity, T0 - SEC, T0 + 3600 * SEC, "csv", "all")
    with path.open(encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        header, data = reader.fieldnames, list(reader)
    assert header[:3] == ["datetime", "timestamp_desc", "message"] and "winlog.event_data.LogonType" in header
    assert rows == len(data) == 8
    first = data[0]
    assert first["datetime"] == "2020-09-19T03:21:48.000000Z" and first["mark"] == "Malicious"
    assert first["source.ip"] == "194.61.24.102" and first["rule.name"] == "RDP from internet"
    assert "source.port" in header
    jpath, jrows = export_timeline(app.con, app.case, app.identity, T0 - SEC, T0 + 3600 * SEC, "jsonl", "flagged")
    lines = jpath.read_text(encoding="utf-8").splitlines()
    assert jrows == len(lines) == 1 and json.loads(lines[0])["mark_note"] == "RDP from the internet"


def test_export_from_the_command_line_says_when_no_event_has_a_time(tmp_path, capsys):
    """The bounds default to the case's first and last times, so on a case whose only event has no time, `export` with
    either bound left out says the case has no events with a time to export."""
    from glessner.case import create_case
    from glessner.cli import main
    from glessner.events import Event

    (tmp_path / "evidence").mkdir()
    case = create_case(tmp_path / "case", "Untimed", tmp_path / "evidence", "cody")
    bag = Event(ts_us=None, ts_desc="ShellBag", artifact="shellbag", source_file="UsrClass.dat", source_record="1",
                message="Folder C:\\Temp")
    load(case.db_path, [bag], host="DESKTOP", tool="sbecmd", tool_version="t", run_id="r1",
         replaces_sources=["UsrClass.dat"], staging_dir=case.folder)
    folder = str(case.folder)
    start, end = ["--start", "2020-09-19T00:00:00Z"], ["--end", "2020-09-20T00:00:00Z"]
    for bounds in ([], start, end):
        assert main(["export", folder, *bounds]) == 2
        assert capsys.readouterr().err == "Error: The case has no events with a time to export.\n"
    assert main(["export", folder, *start, *end]) == 0
    assert "Wrote 0 events to " in capsys.readouterr().out
    # A marked or flagged export covers the whole case and takes no bounds, so it needs no event with a time
    for marks in ("marked", "flagged"):
        assert main(["export", folder, "--marks", marks]) == 0
        assert "Wrote 0 events to " in capsys.readouterr().out


def test_the_report_escapes_evidence_text(app):
    rdp = uid_at(app, T0)
    app.con.execute("UPDATE events SET message = '4624 [click](http://evil.example) <script>' WHERE event_uid = ?", [rdp])
    api_mark(app, {"uids": [rdp], "value": "malicious", "note": "seen | piped"})
    path, count = write_report(app.con, app.case, app.identity, app.manifest, app.journal.state)
    text = path.read_text(encoding="utf-8")
    assert count == 1
    assert "\\[click\\](http://evil.example) \\<script\\>" in text and "[click](" not in text
    assert "seen \\| piped" in text and "**2020-09-19 03:21:48.000000 UTC, DC01, Malicious.**" in text
    assert "| DC01 | Domain controllers (guessed) | Not recorded | CITADEL\\-DC01 |" not in text   # '-' is not escaped
    assert "| DC01 | Domain controllers (guessed) | Not recorded | CITADEL-DC01 | 10.42.85.10 |" in text


def test_the_report_says_which_host_roles_were_guessed(app):
    """The Hosts table marks a role the app guessed, apart from one the analyst confirmed."""
    summary = lambda: write_report(app.con, app.case, app.identity, app.manifest, app.journal.state)[0].read_text(
        encoding="utf-8")
    text = summary()
    assert "| DC01 | Domain controllers (guessed) |" in text and "| DESKTOP | Workstations (guessed) |" in text
    assert "A role marked (guessed) is the app's guess from the host's names and evidence" in text
    api_host(app, {"confirm_hosts": ["DC01", "DESKTOP"]})
    text = summary()
    assert "| DC01 | Domain controllers |" in text and "| DESKTOP | Workstations |" in text
    assert "(guessed)" not in text


def test_the_report_keeps_a_source_path_in_its_code_span(app):
    """Found output takes source_file from a CSV's own SourceFile column, so the report keeps a crafted path inside the
    Source line's code span: a backtick can't end the span, nor a line break its paragraph, to add markup after it."""
    rdp = uid_at(app, T0)
    app.con.execute("UPDATE events SET source_file = ? WHERE event_uid = ?", ["DC01/a`b\n\n<img src=x>.evtx", rdp])
    api_mark(app, {"uids": [rdp], "value": "malicious"})
    text = write_report(app.con, app.case, app.identity, app.manifest, app.journal.state)[0].read_text(
        encoding="utf-8")
    assert "evtx `DC01/a'b  <img src=x>.evtx` record" in text and "\n<img" not in text


def test_the_report_and_hosts_payload_carry_the_os(synthetic_case):
    """The Hosts table names each host's release, or says Not recorded where no SOFTWARE hive gave one."""
    add_os(synthetic_case, "DESKTOP", "ROOT", WINDOWS_10)
    a = App(synthetic_case)
    try:
        path, _ = write_report(a.con, a.case, a.identity, a.manifest, a.journal.state)
        text = path.read_text(encoding="utf-8")
        assert "| Host | Role | OS | Names | IPs | Clock offset |" in text
        assert ("| DESKTOP | Workstations (guessed) | Windows 10 Enterprise Evaluation, version 2004, build 19041.264 | "
                "DESKTOP-SDN1RPT | 10.42.85.115 | none |") in text
        assert "| DC01 | Domain controllers (guessed) | Not recorded | CITADEL-DC01 | 10.42.85.10 | none |" in text
        # The page's hosts payload sends every HostIdentity field, so the OS reaches it with no server change.
        hosts = {h["host"]: h["os"] for h in api_meta(a, {})["hosts"]}
        assert hosts["DESKTOP"]["display"] == "Windows 10 Enterprise Evaluation, version 2004, build 19041.264"
        assert hosts["DC01"] == {}
    finally:
        a.con.close()


BEFORE_1970 = -315_619_200 * SEC   # 1960-01-01 00:00 UTC, a PE link time Autoruns loads as an event time


def test_the_report_takes_a_marked_event_from_before_1970(synthetic_case):
    """On Windows datetime.fromtimestamp refuses times before 1970, but the summary takes a marked Autoruns entry whose
    image was built then. Through the server, any other fault is answered 500 with its message."""
    from conftest import serving
    from test_server import login, request

    from glessner.events import Event
    from glessner.parsers.autoruns import BUILT

    entry = Event(BEFORE_1970, BUILT, "autoruns", "DESKTOP/autoruns.csv", "2", "Logon | Updater | rundll32.exe")
    load(synthetic_case.db_path, [entry], host="DESKTOP", tool="autoruns", tool_version="t", run_id="r9",
         replaces_sources=["DESKTOP/autoruns.csv"], staging_dir=synthetic_case.folder)
    for a, port, _ in serving(synthetic_case):
        session = login(port, a)
        old = uid_at(a, BEFORE_1970, "autoruns")
        api_mark(a, {"uids": [old], "value": "suspicious"})
        res, body = request(port, "POST", "/api/report", session=session, body={})
        assert res.status == 200, body
        text = Path(json.loads(body)["path"]).read_text(encoding="utf-8")
        assert "**1960-01-01 00:00:00.000000 UTC, DESKTOP, Suspicious.**" in text


@pytest.mark.parametrize("us,text", [(BEFORE_1970, "1960-01-01 00:00:00"), (-2_145_916_800 * SEC + 5, "1902-01-01 00:00:00"),
                                     (T0 + 123_456, "2020-09-19 03:21:48")])
def test_every_time_formatter_takes_times_before_1970(us, text):
    """The five helpers that write a time as text share events.from_us."""
    from glessner.cli import _fmt_us
    from glessner.clock import _when
    from glessner.export import _about, _time
    from glessner.parsers.autoruns import _iso

    fraction, tenth = f"{us % SEC:06d}", round(us / 100_000) % 10
    assert _time(us) == f"{text}.{fraction} UTC" and _fmt_us(us) == f"{text}.{fraction} UTC"
    assert _when(us) == text and _iso(us) == text[:16]
    assert _about(us, us) == f"{text[11:]}.{tenth} UTC"   # the date only when it isn't the shown time's
    assert _about(us, us + 86_400 * SEC) == f"{text}.{tenth} UTC"


def summary_events(text):
    """The numbered events of a report, one string each."""
    section = text.split("## 3. Timeline of marked events\n\n")[1].split("\n\n### ")[0]
    return re.split(r"\n(?=\d+\. )", section)


def test_the_report_lists_a_flagged_event_without_a_time_last(synthetic_case):
    """Rules match events without a time too, so accepting a rule's suggestions can flag one. The summary lists it after
    the timed events, without clock lines, though its host has an offset."""
    bag = "DESKTOP/Users/rick/NTUSER.DAT"
    load(synthetic_case.db_path, [Event(None, "ShellBag without a time", "shellbags", bag, "bag1", "ShellBag loot")],
         host="DESKTOP", tool="sbecmd", tool_version="t", run_id="r9", replaces_sources=[bag],
         staging_dir=synthetic_case.folder)
    a = App(synthetic_case)
    try:
        api_host(a, {"host": "DESKTOP", "offset_seconds": 90})
        api_rule(a, {"op": "add", "text": "id: loot\nsuggest: malicious\nwhen: {field: artifact, equals: shellbags}\n"})
        assert api_suggestion(a, {"decision": "accept", "source": "loot"})["changed"] == 1
        api_mark(a, {"uids": [uid_at(a, T0 + 874 * SEC)], "value": "suspicious"})
        path, count = write_report(a.con, a.case, a.identity, a.manifest, a.journal.state)
        text = path.read_text(encoding="utf-8")
        assert count == 2 and "in time order, with those that have no time recorded (1) last." in text
        timed, untimed = summary_events(text)
        assert timed.startswith("1. **2020-09-19 03:37:52.000000 UTC, DESKTOP, Suspicious.**")
        assert "   - Clock: DESKTOP's offset of +90 s is applied" in timed
        assert untimed.startswith("2. **No time recorded, DESKTOP, Malicious.** ShellBag loot") and "Clock" not in untimed
    finally:
        a.con.close()


def test_the_report_numbers_events_at_one_time_by_id(synthetic_case):
    """Events at one time are numbered by ID, not in the order the database reads them, so two summaries of a case
    number them the same; on the Szechuan case 30 flagged events share 20 times. Here the events load in the reverse of
    their IDs' order, which the database keeps."""
    log = "DESKTOP/Windows/System32/winevt/Logs/System.evtx"
    tied = sorted((Event(T0, "Event Recorded", "evtx", log, str(record), "7045 service installed", event_code="7045")
                   for record in range(300, 310)),
                  key=lambda ev: event_uid("DESKTOP", ev.artifact, log, ev.source_record, ev.ts_desc), reverse=True)
    load(synthetic_case.db_path, tied, host="DESKTOP", tool="evtxecmd", tool_version="t", run_id="r9",
         replaces_sources=[log], staging_dir=synthetic_case.folder)
    a = App(synthetic_case)
    try:
        uids = [uid for (uid,) in a.con.execute("SELECT event_uid FROM events WHERE source_file = ?", [log]).fetchall()]
        api_mark(a, {"uids": uids, "value": "malicious"})
        text = write_report(a.con, a.case, a.identity, a.manifest, a.journal.state)[0].read_text(encoding="utf-8")
        assert re.findall(r"Event ID: `(\w+)`", text) == sorted(uids) and len(uids) == 10
    finally:
        a.con.close()


def test_the_report_lists_an_imports_hosts_in_order(synthetic_case):
    """An import whose events name their hosts loads several in one run, and the run table lists them in sorted order."""
    hosts = ["WS05", "WS03", "WS01", "WS04", "WS02", "WS06"]
    log = "FIREWALL/pfirewall.log"
    load(synthetic_case.db_path, [Event(T0, "Logged", "text_log", log, str(i), "ALLOW TCP", lane=host)
                                  for i, host in enumerate(hosts)],
         host=None, tool="import", tool_version="t", run_id="r9", replaces_sources=[log], staging_dir=synthetic_case.folder)
    a = App(synthetic_case)
    try:
        text = write_report(a.con, a.case, a.identity, a.manifest, a.journal.state)[0].read_text(encoding="utf-8")
        assert re.findall(r"\| `r9` \| import \| t \| (\w+) \| 1 \|", text) == sorted(hosts)
    finally:
        a.con.close()


def test_to_investigate_lists_a_flagged_event_without_a_time_last_and_ties_by_id(synthetic_case):
    """To investigate orders by time and then ID, so events at one time come in a fixed order, and an event without a
    time comes last whatever DuckDB's default null order is. The Event page finds the untimed event by its ID, with or
    without a time from the page."""
    bag = "DESKTOP/Users/rick/NTUSER.DAT"
    load(synthetic_case.db_path, [Event(None, "ShellBag without a time", "shellbags", bag, "bag1", "ShellBag loot")],
         host="DESKTOP", tool="sbecmd", tool_version="t", run_id="r9", replaces_sources=[bag],
         staging_dir=synthetic_case.folder)
    log = "DESKTOP/Windows/System32/winevt/Logs/System.evtx"
    tied = sorted((Event(T0, "Event Recorded", "evtx", log, str(record), "7045 service installed", event_code="7045")
                   for record in range(300, 310)),
                  key=lambda ev: event_uid("DESKTOP", ev.artifact, log, ev.source_record, ev.ts_desc), reverse=True)
    load(synthetic_case.db_path, tied, host="DESKTOP", tool="evtxecmd", tool_version="t", run_id="r10",
         replaces_sources=[log], staging_dir=synthetic_case.folder)
    a = App(synthetic_case)
    try:
        api_host(a, {"host": "DESKTOP", "offset_seconds": 90})
        api_rule(a, {"op": "add", "text": "id: loot\nsuggest: malicious\nwhen: {field: artifact, equals: shellbags}\n"})
        assert api_suggestion(a, {"decision": "accept", "source": "loot"})["changed"] == 1
        uids = [uid for (uid,) in a.con.execute("SELECT event_uid FROM events WHERE source_file = ?", [log]).fetchall()]
        api_mark(a, {"uids": uids, "value": "suspicious"})
        a.con.execute("SET default_null_order = 'nulls_first'")
        *timed, untimed = investigate(a.con)
        assert [i["uid"] for i in timed] == sorted(uids) and len(uids) == 10
        assert (untimed["ts"], untimed["mark"], untimed["msg"]) == (None, "Malicious", "ShellBag loot")
        for shown in ({}, {"ts": [str(T0)]}):
            event = api_event(a, {"uid": [untimed["uid"]], **shown})["event"]
            assert (event["event_uid"], event["ts_us"], event["adjusted_ts_us"]) == (untimed["uid"], None, None)
    finally:
        a.con.close()


def test_an_export_runs_outside_the_lock(app, monkeypatch):
    """A timeline export only reads, on a reader, without the server's lock, so a mark sent while it runs doesn't wait
    for it."""
    import threading

    from glessner import server

    writing, go = threading.Event(), threading.Event()
    write = server.export_timeline

    def held(*args):
        writing.set()
        assert go.wait(10)
        return write(*args)

    monkeypatch.setattr(server, "export_timeline", held)
    worker = threading.Thread(target=lambda: server.api_export(app, {"start": T0 - SEC, "end": T0 + SEC}))
    worker.start()
    try:
        assert writing.wait(10)
        mark = threading.Thread(target=lambda: api_mark(app, {"uids": [uid_at(app, T0)], "value": "malicious"}))
        mark.start()
        mark.join(5)
        assert not mark.is_alive()
    finally:
        go.set()
        worker.join(10)


def test_an_exports_row_count_is_its_files(app, monkeypatch):
    """On a reader without the lock, a mark can commit while an export runs. The row count the export reports is the
    COPY's own, so it is the file's, not a count taken before the COPY."""
    import threading

    from glessner import server

    uids = [u for (u,) in app.con.execute("SELECT event_uid FROM events WHERE tool <> 'hayabusa' AND ts_us IS NOT NULL "
                                          "ORDER BY ts_us, event_uid LIMIT 5").fetchall()]
    api_mark(app, {"uids": uids[:2], "value": "malicious"})
    write = server.export_timeline

    class MarkBeforeCopy:   # the export's reader, which lets a mark of three more events commit just before the COPY
        def __init__(self, con):
            self.con = con

        def execute(self, sql, *args):
            if sql.startswith("COPY"):
                mark = threading.Thread(target=lambda: api_mark(app, {"uids": uids[2:], "value": "suspicious"}))
                mark.start()
                mark.join(10)
            return self.con.execute(sql, *args)

    monkeypatch.setattr(server, "export_timeline", lambda con, *args: write(MarkBeforeCopy(con), *args))
    first, last = app.con.execute("SELECT min(ts_us), max(ts_us) + 1 FROM events").fetchone()
    result = server.api_export(app, {"start": first, "end": last, "marks": "marked"})
    with Path(result["path"]).open(encoding="utf-8", newline="") as f:
        assert result["rows"] == len(list(csv.DictReader(f))) == 5


def test_timeline_export_writes_each_events_tags(app):
    """One grouped join gives each event its tactics in kill-chain order, its techniques, and the analyst's own tags in
    order; an event without tags has none."""
    from glessner.server import api_tag

    rdp, other = uid_at(app, T0), uid_at(app, T0 + 60 * SEC)
    api_tag(app, {"uids": [rdp], "add": ["Lateral Movement", "Initial Access", "T1078", "T1021.001", "staging", "Beta"]})
    path, _ = export_timeline(app.reader(), app.case, app.identity, T0 - SEC, T0 + 3600 * SEC, "csv", "all")
    with path.open(encoding="utf-8", newline="") as f:
        rows = {r["event_uid"]: r for r in csv.DictReader(f)}
    fields = ("threat.tactic.name", "threat.tactic.id", "threat.technique.id", "tags")
    assert [rows[rdp][k] for k in fields] == ["Initial Access; Lateral Movement", "TA0001; TA0008", "T1021.001; T1078",
                                              "beta; staging"]
    assert [rows[other][k] for k in fields] == ["", "", "", ""]
