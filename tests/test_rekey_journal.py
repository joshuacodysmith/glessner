"""Reading the journal through a case format upgrade's rekey: every reader translates an entry's event IDs through the
rekeys that follow it in the file, and no line changes. The upgrade itself is rekey.py's; here a test writes the rekey
entry and changes the events' IDs in the database as the upgrade's reload would."""

import copy
import hashlib
import json
import random
from pathlib import Path

import pytest

from glessner.audit import read_entries
from glessner.events import connect
from glessner.journal import (
    ACTIONS,
    ID_FIELDS,
    REKEYED,
    SYSTEM,
    Journal,
    JournalError,
    _validate,
    replay,
)
from glessner.overview import _last_action


def new_id(name: str) -> str:
    return hashlib.sha256(name.encode()).hexdigest()[:32]


def evtx_uids(case, n=3):
    con = connect(case.db_path, read_only=True)
    try:
        return [u for (u,) in con.execute("SELECT event_uid FROM events WHERE tool = 'evtxecmd' ORDER BY ts_us LIMIT ?",
                                          [n]).fetchall()]
    finally:
        con.close()


def rekey(case, journal, pairs, formats=(4, 5), **fields):
    """What the upgrade leaves: the events under their new IDs, and the entry that maps the old ones, an upgrade from
    and to `formats`."""
    con = connect(case.db_path)
    try:
        for old, new in pairs.items():
            con.execute("UPDATE events SET event_uid = ? WHERE event_uid = ?", [new, old])
    finally:
        con.close()
    # After the chain starts, only a later format's upgrade carries a rekey, to a format above this build's format 4
    from_format, to_format = formats
    return journal.append("case_upgrade", who=SYSTEM, from_format=from_format, to_format=to_format,
                          text="Event IDs changed.", rekey={"pairs": pairs, **fields})


def test_every_action_says_which_of_its_fields_name_events():
    """A reader translates only the fields ID_FIELDS names, so an action left out, such as followup or finding, would
    keep its old IDs after an upgrade."""
    assert set(ID_FIELDS) == ACTIONS
    assert ID_FIELDS["undo"] == ("changes",) and all(ID_FIELDS[a] for a in ("mark", "note", "tag", "note_retract"))


def test_only_a_case_upgrade_carries_a_rekey_of_well_formed_ids():
    a, b = new_id("a"), new_id("b")
    upgrade = {"from_format": 1, "to_format": 2, "text": "x"}
    _validate("case_upgrade", {**upgrade, "rekey": {"pairs": {a: b}, "unplaced": {b: [a, b]}, "merged": {b: [a, b]},
                                                    "map_size": 1, "map_sha256": "0" * 64}})
    with pytest.raises(JournalError, match="only a case_upgrade"):
        _validate("mark", {"targets": [a], "value": "malicious", "rekey": {"pairs": {}}})
    for bad in ({"pairs": {a: b.upper()}}, {"pairs": {a: b + "#2"}}, {"pairs": {a[:31]: b}}, {"pairs": [[a, b]]}, {},
                {"pairs": {}, "unplaced": {a: []}}, {"pairs": {}, "merged": {a: ["x"]}},
                {"pairs": {}, "dropped_runs": {"r": {"rows": 1, "references": ["x"]}}}, {"pairs": {}, "map_sha256": "x"}):
        with pytest.raises(JournalError):
            _validate("case_upgrade", {**upgrade, "rekey": bad})


# Replay through rekeys equals replay of the journal translated by hand.

def random_journal(rng: random.Random, ids: list[str]) -> list[dict]:
    """Entries of every action that names events, with undos, retractions, and rekeys that swap and chain IDs."""
    entries = []
    pick = lambda: rng.sample(ids, rng.randint(1, 3))
    tags = ["tactic:TA0001", "tactic:TA0008", "technique:T1059"]
    for seq in range(1, rng.randint(10, 40)):
        kind = rng.choice(["mark", "mark", "note", "retract", "tag", "tag_suggestion", "decision", "undo", "rekey"])
        if kind == "mark":
            e = {"action": "mark", "targets": pick(), "value": rng.choice(["malicious", "authorized", "unreviewed"]),
                 "note": ""}
        elif kind == "note":
            e = {"action": "note", "target": rng.choice(ids), "text": f"note {seq}"}
        elif kind == "retract":
            notes = [x for x in entries if x["action"] == "note"]
            if not notes:
                continue
            note = rng.choice(notes)
            e = {"action": "note_retract", "target": rng.choice([note["target"], rng.choice(ids)]),
                 "note_seq": note["seq"]}
        elif kind == "tag":
            e = {"action": "tag", "targets": pick(), "add": [rng.choice(tags)]}
            if rng.random() < 0.3:
                e["remove"] = [rng.choice(tags)]
        elif kind == "tag_suggestion":
            e = {"action": "tag_suggestion", "targets": pick(), "tags": [rng.choice(tags)],
                 "decision": rng.choice(["dismissed", "restored"])}
        elif kind == "decision":
            e = {"action": "suggestion_decision", "targets": pick(), "source": "hayabusa",
                 "decision": rng.choice(["rejected", "restored"])}
        elif kind == "undo":
            e = {"action": "undo", "undoes": max(1, seq - 1), "correction": "accident", "kept": 0, "changes": [
                {"action": "mark", "targets": pick(), "value": "unreviewed", "note": ""},
                {"action": "tag", "targets": pick(), "remove": [rng.choice(tags)]}]}
        else:
            a, b, c = rng.sample(ids, 3)
            pairs = rng.choice([{a: b, b: a}, {a: b, b: c}, {a: b}, {a: c, c: b, b: a}])
            e = {"action": "case_upgrade", "from_format": 1, "to_format": 2, "text": "rekey", "rekey": {"pairs": pairs}}
        _validate(e["action"], {k: v for k, v in e.items() if k != "action"})
        entries.append({"seq": seq, "at": f"2026-10-18T09:00:{seq:02d}.000000Z", "who": "cody", **e})
    return entries


def by_hand(entries: list[dict]) -> list[dict]:
    """The journal as it would read had each entry been written with the IDs of the end: every field holding an
    event ID, by name, mapped through each later rekey in turn, and the rekeys left out."""
    out = []
    for i, entry in enumerate(entries):
        if entry["action"] == "case_upgrade":
            continue
        maps = [e["rekey"]["pairs"] for e in entries[i + 1:] if e["action"] == "case_upgrade"]

        def through(uid, maps=maps):
            for pairs in maps:
                uid = pairs.get(uid, uid)
            return uid

        e = copy.deepcopy(entry)
        for holder in [e, *e.get("changes", [])]:
            if "targets" in holder:
                holder["targets"] = [through(t) for t in holder["targets"]]
            if "target" in holder:
                holder["target"] = through(holder["target"])
        out.append(e)
    return out


def write(path: Path, entries: list[dict]) -> Path:
    path.write_text("".join(json.dumps(e) + "\n" for e in entries), encoding="utf-8")
    return path


def analysis(state) -> tuple:
    return (state.marks, state.notes, state.tags, state.rejected, state.dismissed_tags)


def test_replay_through_rekeys_equals_the_journal_translated_by_hand(tmp_path):
    """Over 300 generated journals: swaps (A to B with B to A), chains (A to B with B to C), and several rekeys,
    with every action that names events, undos and retractions included. The trail's entries match too, and say which
    rekeys changed them."""
    ids = [new_id(str(n)) for n in range(6)]
    rekeyed = 0
    for n in range(300):
        rng = random.Random(n)
        entries = random_journal(rng, ids)
        path, hand = write(tmp_path / "journal.jsonl", entries), by_hand(entries)
        assert analysis(replay(path)) == analysis(replay(write(tmp_path / "by_hand.jsonl", hand))), n
        trail = [{k: v for k, v in e.items() if k != REKEYED} for e in read_entries(path) if e["action"] != "case_upgrade"]
        assert trail == hand, n
        rekeyed += sum(1 for e in read_entries(path) if e.get(REKEYED))
    assert rekeyed > 300   # the generated journals did change IDs


def test_a_journal_open_across_a_rekey_reads_every_entry_again(synthetic_case):
    """Journal._catch_up applies only the lines after those it has applied, which follow every rekey it knew. A new
    rekey changes IDs that the applied entries name, so the state is built again from the first line, in this
    writer and in another one open on the same case, as a server is beside the command line."""
    a, z, _ = evtx_uids(synthetic_case)
    b = new_id("b")
    journal, other = Journal(synthetic_case), Journal(synthetic_case)
    journal.append("mark", targets=[a, z], value="malicious", note="")
    other.append("note", target=a, text="seen")   # each has applied entries before the rekey
    rekey(synthetic_case, journal, {a: b})
    assert set(journal.state.marks) == {b, z} and set(journal.state.notes) == {b}
    other.append("tag", targets=[b], add=["tactic:TA0001"])   # it catches up on the rekey first
    assert set(other.state.marks) == {b, z} and set(other.state.notes) == {b} and set(other.state.tags) == {b}
    assert analysis(other.state) == analysis(replay(journal.path))
    assert [r["seq"] for r in other.state.rekeys] == [4]   # after case_created, the mark, and the note


def test_a_rekey_appended_between_a_reader_s_two_passes_is_read_through(synthetic_case, monkeypatch):
    """_entries finds the rekeys in a first pass and reads the entries in a second. A rekey another writer appends
    between the two would leave the entries before it read without it in a journal opened then, so the reader starts
    again from the first line."""
    import glessner.journal as journal_module

    a, z, _ = evtx_uids(synthetic_case)
    b = new_id("b")
    writer = Journal(synthetic_case)
    writer.append("mark", targets=[a, z], value="malicious", note="")
    first_pass, raced = journal_module._rekeys, []

    def racing(path, start, lines, chained, *place):
        found = first_pass(path, start, lines, chained, *place)
        if not raced:
            raced.append(True)
            rekey(synthetic_case, writer, {a: b})   # another writer's, between the two passes
        return found

    monkeypatch.setattr(journal_module, "_rekeys", racing)
    fresh = Journal(synthetic_case)
    assert raced and set(fresh.state.marks) == {b, z}
    assert analysis(fresh.state) == analysis(replay(writer.path)) == analysis(writer.state)


def test_translation_is_by_place_in_the_file_and_rekeys_compose(synthetic_case):
    """An entry before a rekey reads through it; one after it that names an old ID was written in the new ID space,
    stays as written, and counts as an orphan. A second rekey composes with the first. The journal's bytes don't
    change."""
    from glessner.server import App

    a, z, _ = evtx_uids(synthetic_case)
    b, c = new_id("b"), new_id("c")
    journal = Journal(synthetic_case)
    journal.append("mark", targets=[a], value="malicious", note="")       # 2
    rekey(synthetic_case, journal, {a: b})                                 # 3
    journal.append("mark", targets=[a], value="suspicious", note="")      # 4: an old ID after the rekey
    journal.append("mark", targets=[z], value="authorized", note="")      # 5
    written = journal.path.read_bytes()

    def opened(check):
        app = App(synthetic_case)
        try:
            check(app)
        finally:
            app.con.close()

    def first(app):
        assert {u: m.value for u, m in app.journal.state.marks.items()} == {b: "malicious", a: "suspicious",
                                                                          z: "authorized"}
        assert app.orphans == 1   # #4's a, which no event has since #3

    opened(first)
    later = rekey(synthetic_case, journal, {b: c, z: a}, (5, 6))["seq"]   # a is z's new ID here; the open added rules
    state = replay(journal.path)
    assert {u: m.value for u, m in state.marks.items()} == {c: "malicious", a: "authorized"}   # #5 after #4
    entries = read_entries(journal.path)
    assert [(e["targets"], e.get(REKEYED)) for e in entries if e["action"] == "mark"] == [
        ([c], [3, later]), ([a], None), ([a], [later])]

    def second(app):
        assert app.orphans == 0 and app.journal.state.marks[a].value == "authorized"
        app.journal.append("mark", targets=[b], value="suspicious", note="")   # b, renamed by the later rekey
        app.refresh_identity(events_changed=True)
        assert app.orphans == 1 and b in app.journal.state.marks

    opened(second)
    assert journal.path.read_bytes().startswith(written)   # only appended to


def test_every_reader_sees_one_id_space(synthetic_case):
    """Mark X and another event, note X, then an upgrade that gives X the ID Y. The trail filtered to Y lists both
    entries and names Y's event, its "events" list gives Y, the export names Y's message and marks both entries "IDs
    as changed at" the upgrade's number, the overview's last action names Y, and an undo of the mark writes Y, keeping
    a later mark on Y."""
    from glessner.server import App, api_audit, api_audit_events, api_audit_export, api_mark, api_overview, api_undo

    x, z, _ = evtx_uids(synthetic_case)
    y = new_id("y")
    journal = Journal(synthetic_case)
    journal.append("mark", targets=[x, z], value="malicious", note="")   # 2
    journal.append("note", target=x, text="first look")                 # 3
    rekey(synthetic_case, journal, {x: y})                               # 4
    app = App(synthetic_case)
    try:
        name = app.con.execute("SELECT host || ' ' || event_code FROM events WHERE event_uid = ?", [y]).fetchone()[0]
        trail = api_audit(app, {"event": [y]})
        assert [(r["seq"], r["rekeyed"]) for r in trail["rows"]] == [(3, "IDs as changed at #4"),
                                                                     (2, "IDs as changed at #4")]
        assert trail["rows"][0]["text"].startswith(f"Note on {name}: ")
        assert {e["uid"] for e in api_audit_events(app, {"seq": ["2"]})["events"]} == {y, z}
        # Before the export, whose file entry is then the newest action
        assert api_overview(app, {})["progress"]["last"]["text"].startswith(f"Note on {name}: ")
        lines = Path(api_audit_export(app, {})["path"]).read_text(encoding="utf-8").splitlines()
        entry_line = lambda seq: next(line for line in lines if line.startswith(f"- **#{seq}**"))
        assert [line for line in lines if "*(IDs as changed at #4)*" in line] == [entry_line(2), entry_line(3)]
        assert any(f"Note on {name}: " in line for line in lines) and any(f"ID `{y}`" in line for line in lines)
        assert app.journal.state.marks[y].value == "malicious" and x not in app.journal.state.marks
        api_mark(app, {"uids": [y], "value": "suspicious"})                # 5
        api_undo(app, {"seq": 2})                                         # 6
        undo = read_entries(journal.path)[-1]
        assert (undo["changes"], undo["kept"]) == ([{"action": "mark", "targets": [z], "value": "unreviewed",
                                                     "note": ""}], 1)
        assert app.journal.state.marks[y].value == "suspicious" and z not in app.journal.state.marks
    finally:
        app.con.close()


def test_the_upgrade_entry_says_how_many_events_merged():
    """References under two earlier IDs that reach one event after the upgrade are a merge; the later mark stands, and the
    trail's text for the upgrade says how many."""
    from glessner.audit import describe

    a, b, c = new_id("a"), new_id("b"), new_id("c")
    entry = {"action": "case_upgrade", "from_format": 1, "to_format": 2, "text": "IDs changed.",
             "rekey": {"pairs": {a: c}, "merged": {c: [a, c]}}}
    assert describe(entry) == ("Upgraded the case from format 1 to 2: IDs changed. 1 event now holds references made "
                               "under more than one earlier ID; the later mark stands, and each event's trail shows "
                               "them all.")
    entry["rekey"]["merged"][b] = [a, b]
    assert "2 events now hold" in describe(entry)
    assert describe({**entry, "rekey": {"pairs": {}}}) == "Upgraded the case from format 1 to 2: IDs changed."


def test_the_last_action_reads_through_the_rekeys_after_it(tmp_path):
    """overview._last_action reads back from the end; the rekeys it passes are those after the entry, in file order."""
    a, b, c = new_id("a"), new_id("b"), new_id("c")
    up = lambda pairs: {"action": "case_upgrade", "who": SYSTEM, "from_format": 1, "to_format": 2, "text": "",
                        "rekey": {"pairs": pairs}}
    path = write(tmp_path / "journal.jsonl", [{"seq": 1, "who": "cody", "action": "note", "target": a, "text": "x"},
                                              {"seq": 2, **up({a: b})}, {"seq": 3, **up({b: c, a: b})},
                                              {"seq": 4, "who": SYSTEM, "action": "case_open", "build": "x"}])
    assert _last_action(path) == {"seq": 1, "who": "cody", "action": "note", "target": c, "text": "x", REKEYED: [2, 3]}


def test_an_unplaced_id_says_why_and_the_trail_finds_an_old_id(synthetic_case):
    """Beyond the Event page's own ID: an unplaced ID that names no loaded event says on the Event page that
    the upgrade left it so, rather than "unknown event", and the trail filtered by an old ID the journal named lists its
    entries, as the Event page opens its event."""
    from glessner.server import App, QueryError, api_audit, api_event

    x, u, v = evtx_uids(synthetic_case)
    y, w = new_id("y"), new_id("w")
    journal = Journal(synthetic_case)
    journal.append("mark", targets=[x], value="malicious", note="")
    journal.append("note", target=w, text="the record that moved")
    up = rekey(synthetic_case, journal, {x: y}, unplaced={w: [u, v]})
    app = App(synthetic_case)
    try:
        with pytest.raises(QueryError, match=f"more than one event before the case format upgrade at #{up['seq']}.*the 2 "):
            api_event(app, {"uid": [w]})
        seqs = lambda uid: [r["seq"] for r in api_audit(app, {"event": [uid]})["rows"]]
        assert seqs(x) == seqs(y) == [2]
    finally:
        app.con.close()


def test_an_old_id_opens_its_event_and_an_unplaced_one_is_counted_apart(synthetic_case):
    """An ID the journal named before an upgrade opens the event it names after the upgrade, which says when it changed.
    An ID that named different records stays as written; the overview counts it apart from orphans, since it may still
    name a loaded event, and each candidate's Event page says an entry may have meant it."""
    from glessner.server import App, QueryError, api_event, api_overview

    x, u, v = evtx_uids(synthetic_case)
    y = new_id("y")
    journal = Journal(synthetic_case)
    journal.append("mark", targets=[x, u], value="malicious", note="")
    up = rekey(synthetic_case, journal, {x: y}, unplaced={u: [u, v]})
    app = App(synthetic_case)
    try:
        moved = api_event(app, {"uid": [x]})["event"]
        assert moved["event_uid"] == y and moved["id_changed"] == {"from": x, "seqs": [up["seq"]]}
        assert moved["mark"]["label"] == "Malicious" and not moved["unplaced"]
        assert "id_changed" not in api_event(app, {"uid": [y]})["event"]
        for candidate in (u, v):
            assert api_event(app, {"uid": [candidate]})["event"]["unplaced"] == [{"seq": up["seq"], "id": u, "others": 1}]
        with pytest.raises(QueryError, match="unknown event"):
            api_event(app, {"uid": [new_id("never")]})
        progress = api_overview(app, {})["progress"]
        assert (progress["unplaced"], progress["orphans"]) == (1, 0)
    finally:
        app.con.close()
