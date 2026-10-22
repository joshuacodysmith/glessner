"""A finding's ATT&CK field, on the server side: the bundled Enterprise ATT&CK list and its record of where it came
from; the flags for an ID that isn't listed; the generator, on a small STIX bundle of its own; and over HTTP, a
finding's add or edit taking only listed IDs, while a finding that already holds unlisted IDs keeps them, flagged on
the Findings page and in the report."""

import importlib.util
import json
from pathlib import Path

import pytest
from conftest import SEC, T0
from test_server import login, request

from glessner import attack
from glessner.journal import JOURNAL_FILE, JournalError
from glessner.server import api_findings_page, api_report_preview
from glessner.tags import TACTICS

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "scripts" / "attack_list.py"


def entries(case):
    return [json.loads(line) for line in (case.folder / JOURNAL_FILE).read_text(encoding="utf-8").splitlines()]


def uid_at(app, ts):
    return app.con.execute("SELECT event_uid FROM events WHERE tool = 'evtxecmd' AND ts_us = ?", [ts]).fetchone()[0]


def generator():
    spec = importlib.util.spec_from_file_location("attack_list", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_bundled_list_is_enterprise_attack_20_with_its_source_and_mitres_terms():
    """ATT&CK v20.0's 706 current techniques (227 techniques, 479 sub-techniques), each once, in ID order, each with a name
    and its tactics; a sub-technique's name starts with its technique's; the tactics are tags.py's, in its order, so a
    release that changes them shows here; the file names its source and the SHA-256 of what it was made from; and it
    carries MITRE's copyright line and license, as the terms of use ask of every copy."""
    data = json.loads(attack.LIST_FILE.read_text(encoding="utf-8"))
    assert (data["attack"]["name"], data["attack"]["version"]) == ("Enterprise ATT&CK", "20.0")
    assert data["attack"]["source"] == ("https://github.com/mitre-attack/attack-stix-data/releases/download/v20.0/"
                                        "enterprise-attack.json")
    assert data["attack"]["sha256"] == "81113ba98afa2928f3dcff62022539f7ce30c315c32e14422f11ff95ce534352"
    assert data["copyright"] == ("© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission "
                                 "of The MITRE Corporation.")
    assert data["license"].startswith("The MITRE Corporation (MITRE) hereby grants you a non-exclusive, royalty-free license")
    assert [(t[0], t[1]) for t in data["tactics"]] == [(tid, name) for tid, name, _ in TACTICS]
    rows = data["techniques"]
    ids = [r[0] for r in rows]
    assert len(rows) == 706 and len(set(ids)) == 706 and ids == sorted(ids)
    assert sum("." not in i for i in ids) == 227
    names = {r[0]: r[1] for r in rows}
    known = {tid for tid, _, _ in TACTICS}
    for tid, name, tactics in rows:
        assert name and tactics and set(tactics) <= known, tid
        if "." in tid:
            assert name.startswith(f"{names[tid.split('.')[0]]}: "), tid
    assert names["T1059.001"] == "Command and Scripting Interpreter: PowerShell"
    assert names["T1543.003"] == "Create or Modify System Process: Windows Service"
    assert data["revoked"]["T1086"] == "T1059.001" and all(new in names for new in data["revoked"].values())
    assert not set(data["revoked"]) & set(names)


def test_an_id_that_isnt_listed_is_flagged_and_refused():
    """A listed ID has no flag; a revoked one names the technique MITRE revoked it in favor of; a deprecated one (T1064,
    Scripting) and one that never existed are "not in ATT&CK v20.0". The refusal names each unlisted ID, in one sentence
    for one or several, and leaves anything but a list of text to the journal's check of the form."""
    assert attack.flag("T1059.001") == "" and attack.flag("T1078") == ""
    assert attack.flag("T1086") == "revoked; now T1059.001"
    assert attack.flag("T1064") == attack.flag("T9999") == "not in ATT&CK v20.0"
    assert attack.flags(["T1078", "T1086", "T9999"]) == {"T1086": "revoked; now T1059.001", "T9999": "not in ATT&CK v20.0"}
    assert attack.worded(["T1078", "T1086", "T9999"]) == "T1078, T1086 (revoked; now T1059.001), T9999 (not in ATT&CK v20.0)"
    assert attack.refusal(["T1078", "T1059.001"]) == ""
    assert attack.refusal(["T1078", "T9999"]) == "T9999 isn't in ATT&CK v20.0. Remove it to save the ATT&CK field."
    assert attack.refusal(["T1086", "t1078"]) == "T1086, t1078 aren't in ATT&CK v20.0. Remove them to save the ATT&CK field."
    assert attack.refusal("T1078") == attack.refusal([1078]) == ""
    picker = attack.picker()
    assert picker["version"] == "20.0" and len(picker["techniques"]) == 706 and len(picker["tactics"]) == 15
    assert picker["copyright"].startswith("© 2026 The MITRE Corporation.")


def _bundle():
    """A small Enterprise ATT&CK bundle: two tactics in the matrix's order, a technique with a sub-technique, a technique
    revoked by one that is itself revoked by the sub-technique, and a deprecated technique."""
    def ref(tid):
        return [{"source_name": "mitre-attack", "external_id": tid}]

    def pattern(sid, tid, name, phases=("persistence",), **extra):
        return {"type": "attack-pattern", "id": sid, "name": name, "external_references": ref(tid),
                "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": p} for p in phases], **extra}

    return {"type": "bundle", "objects": [
        {"type": "x-mitre-collection", "name": "Enterprise ATT&CK", "x_mitre_version": "99.1", "modified": "2026-01-02"},
        {"type": "x-mitre-matrix", "id": "m", "tactic_refs": ["t-pe", "t-p"]},
        {"type": "x-mitre-tactic", "id": "t-p", "name": "Persistence", "x_mitre_shortname": "persistence",
         "external_references": ref("TA0003")},
        {"type": "x-mitre-tactic", "id": "t-pe", "name": "Privilege Escalation", "x_mitre_shortname": "privilege-escalation",
         "external_references": ref("TA0004")},
        pattern("a", "T1543", "Create or Modify System Process", ("persistence", "privilege-escalation")),
        pattern("b", "T1543.003", "Windows Service", x_mitre_is_subtechnique=True),
        pattern("c", "T1050", "New Service", revoked=True),
        pattern("d", "T1999", "Middle Step", revoked=True),
        pattern("e", "T1064", "Scripting", x_mitre_deprecated=True),
        {"type": "relationship", "relationship_type": "revoked-by", "source_ref": "c", "target_ref": "d"},
        {"type": "relationship", "relationship_type": "revoked-by", "source_ref": "d", "target_ref": "b"}]}


def test_the_generator_keeps_current_techniques_and_follows_revocations(tmp_path):
    """scripts/attack_list.py on a bundle of its own: the current techniques in ID order, a sub-technique named after its
    technique, each technique's tactics in the matrix's order; deprecated and revoked ones left out; a revoked ID followed
    through a chain of revocations to the current technique it ends at; and the version, the release's URL, and the
    input's hash recorded. The written file, one row per line, reads back as built."""
    gen = generator()
    data = gen.build(_bundle(), "ab" * 32)
    assert data["tactics"] == [["TA0004", "Privilege Escalation"], ["TA0003", "Persistence"]]
    assert data["techniques"] == [["T1543", "Create or Modify System Process", ["TA0004", "TA0003"]],
                                  ["T1543.003", "Create or Modify System Process: Windows Service", ["TA0003"]]]
    assert data["revoked"] == {"T1050": "T1543.003", "T1999": "T1543.003"}
    assert (data["attack"]["version"], data["attack"]["sha256"]) == ("99.1", "ab" * 32)
    assert data["attack"]["source"].endswith("/download/v99.1/enterprise-attack.json")
    assert data["copyright"].startswith("© 2026 The MITRE Corporation.") and "royalty-free" in data["license"]
    out = tmp_path / "list.json"
    gen.write(data, out)
    text = out.read_text(encoding="utf-8")
    assert json.loads(text) == data
    assert '\n    ["T1543.003", "Create or Modify System Process: Windows Service", ["TA0003"]]\n' in text


def test_the_generator_refuses_a_bundle_it_cant_trust_and_drops_a_revocation_cycle():
    """A current technique whose sub-technique flag disagrees with its ID, a sub-technique whose technique isn't current,
    an ID twice, a technique with no tactic, and one naming a tactic the matrix doesn't are each refused, so a changed
    release stops the script rather than shipping a wrong list. A revoked ID whose revocations go round in a circle is
    left out."""
    gen = generator()

    def changed(edit):
        bundle = _bundle()
        edit({o.get("id"): o for o in bundle["objects"]}, bundle["objects"])
        return bundle

    bad = [lambda by, objs: by["b"].pop("x_mitre_is_subtechnique"),
           lambda by, objs: by["a"].update(x_mitre_deprecated=True),
           lambda by, objs: by["e"].update(x_mitre_deprecated=False, external_references=by["a"]["external_references"]),
           lambda by, objs: by["a"].update(kill_chain_phases=[]),
           lambda by, objs: by["a"]["kill_chain_phases"].append({"kill_chain_name": "mitre-attack", "phase_name": "impact"})]
    for edit in bad:
        with pytest.raises(ValueError):
            gen.build(changed(edit), "00")
    # c -> d -> c: neither ends at a current technique
    circle = changed(lambda by, objs: next(o for o in objs if o.get("source_ref") == "d").update(target_ref="c"))
    assert gen.build(circle, "00")["revoked"] == {}


def test_a_finding_takes_only_listed_ids_and_an_old_one_is_flagged(running):
    """Over HTTP: an add or an edit naming an unlisted ID is refused with the form's words and writes nothing, and /api/attack
    gives the page its list. A finding that already holds unlisted IDs (written to the journal as an older case holds
    it) keeps its IDs: the Findings page flags each unlisted one, the report writes the flag beside it, an edit that leaves the
    techniques alone is taken, and an edit of the techniques is refused until the unlisted IDs are gone."""
    app, port, _ = running
    session = login(port, app)

    def finding(body):
        res, payload = request(port, "POST", "/api/finding", session=session, body=body)
        return res.status, json.loads(payload)

    res, payload = request(port, "GET", "/api/attack", session=session)
    listed = json.loads(payload)
    assert res.status == 200 and listed["version"] == "20.0" and len(listed["techniques"]) == 706
    before = len(entries(app.case))
    status, answer = finding({"op": "add", "title": "Made up", "severity": "Low", "techniques": ["T1078", "T9999"]})
    assert status == 400 and answer["error"] == "T9999 isn't in ATT&CK v20.0. Remove it to save the ATT&CK field."
    # A confirmed add, which writes its add and then a link, is refused before either
    many = [uid_at(app, T0), uid_at(app, T0 + 60 * SEC)]
    status, answer = finding({"op": "add", "title": "Made up", "severity": "Low", "techniques": ["T9999"], "targets": many,
                              "confirmed": {"count": 2}})
    assert status == 400 and answer["error"].startswith("T9999 isn't in ATT&CK v20.0.")
    assert len(entries(app.case)) == before
    # The journal's own check still refuses an ID of the wrong form, as replay of an old case relies on
    with app.lock, pytest.raises(JournalError, match="ATT&CK IDs such as T1543"):
        app.journal.append("finding", op="add", title="x", severity="Low", techniques=["T15"], targets=[])
    assert len(entries(app.case)) == before
    with app.lock:
        old = app.journal.append("finding", op="add", title="From before the list", severity="High",
                                 techniques=["T1059.001", "T1086", "T9999"], targets=[uid_at(app, T0 + 60 * SEC)])["seq"]
    one = api_findings_page(app, {})["findings"][0]
    assert one["techniques"] == ["T1059.001", "T1086", "T9999"]
    assert one["technique_flags"] == {"T1086": "revoked; now T1059.001", "T9999": "not in ATT&CK v20.0"}
    report = api_report_preview(app, {})["text"]
    assert ("High. ATT&CK: T1059.001, T1086 (revoked; now T1059.001), T9999 (not in ATT&CK v20.0). 1 supporting event; "
            in report)
    status, _ = finding({"op": "edit", "finding": old, "title": "Kept as it was"})
    assert status == 200 and entries(app.case)[-1]["title"] == "Kept as it was"
    before = len(entries(app.case))
    status, answer = finding({"op": "edit", "finding": old, "techniques": ["T1059.001", "T1086", "T9999", "T1078"]})
    assert status == 400 and answer["error"] == ("T1086, T9999 aren't in ATT&CK v20.0. Remove them to save the ATT&CK "
                                                 "field.")
    assert len(entries(app.case)) == before
    status, _ = finding({"op": "edit", "finding": old, "techniques": ["T1059.001", "T1078"]})
    assert status == 200 and entries(app.case)[-1]["techniques"] == ["T1059.001", "T1078"]
    assert api_findings_page(app, {})["findings"][0]["technique_flags"] == {}
