"""A later rekey places the events an earlier rekey's unplaced ID may have meant, so that list reads through it
(journal.unplaced). They are no reference of the analyst's: the entry's text, its merged list, and its dropped runs'
references leave them out, and one it leaves unplaced goes in its `candidates_unplaced`, apart from the IDs the journal
names, so the overview's count and the Event page leave it out too."""

import pytest
from chain_fixtures import append_unchained
from rekey_cases import Format1
from rekey_fixtures import srum_row, srum_tables
from test_rekey_unplaced import first_rekey, new_case, new_id, next_rekey, rekey, state_of

from glessner.audit import describe
from glessner.case import CASE_FORMAT, JOURNAL_FILE
from glessner.journal import SYSTEM, Journal, JournalError, replay, unplaced, unplaced_count
from glessner.queries import QueryError
from glessner.rekey import _parse, upgraded
from glessner.server import App, api_event, api_overview

NO_EVENT = "Event IDs no longer depend on where or in which time zone a tool ran; no event here took a new ID."
LEFT_ONE = ("1 was left unplaced, each naming more than one event; the Case overview counts them, and each event they may "
            "mean says so.")
# The fields of a format 1 case's upgrade entry's rekey, in the order the step writes them
FORMAT_2_FIELDS = ["reasons", "pairs", "unplaced", "merged", "skipped_runs", "dropped_runs", "unpinned_runs", "runs",
                   "map_size", "map_sha256"]


def ids(*names: str) -> list[str]:
    return [new_id(name) for name in names]


def mark(journal: Journal, uid: str) -> None:
    journal.append("mark", targets=[uid], value="suspicious", note="")


def after(entry: dict) -> tuple[int, int]:
    """The from and to formats of the rekey that follows the upgrade `entry`."""
    return entry["to_format"], entry["to_format"] + 1


def test_a_candidate_moved_onto_the_analyst_s_event_is_no_reference_and_merges_nothing(tmp_path):
    """A mark on x, a rekey leaving old1 unplaced on b1 and b2, then a rekey that gives x and b1 one event: only x moved,
    and no event holds references made under two IDs."""
    case = new_case(tmp_path)
    old, x, b1, b2, c1, c2 = ids("old1", "x", "b1", "b2", "c1", "c2")
    journal = Journal(case)
    mark(journal, x)
    first = first_rekey(journal, old, [b1, b2])
    second = next_rekey(journal, case, after(first), {x: c1, b1: c1, b2: c2})
    assert second["rekey"] == {"pairs": {x: c1, b1: c1, b2: c2}, "unplaced": {}, "merged": {}}
    assert second["text"] == f"{NO_EVENT} 1 journal reference now names its event's new ID. None was left unplaced."
    assert "references made under more than one earlier ID" not in describe(second)


def test_the_analyst_s_references_that_reach_one_event_merge_without_the_candidate_beside_them(tmp_path):
    case = new_case(tmp_path)
    old, x, y, b1, b2, c1, c2 = ids("old1", "x", "y", "b1", "b2", "c1", "c2")
    journal = Journal(case)
    mark(journal, x)
    mark(journal, y)
    first = first_rekey(journal, old, [b1, b2])
    second = next_rekey(journal, case, after(first), {x: c1, y: c1, b1: c1, b2: c2})
    assert second["rekey"]["merged"] == {c1: sorted([x, y])}
    assert second["text"] == f"{NO_EVENT} 2 journal references now name their events' new IDs. None was left unplaced."
    assert "1 event now holds references made under more than one earlier ID" in describe(second)


def test_a_candidate_left_unplaced_adds_nothing_to_the_count_after_each_later_rekey(tmp_path):
    """The analyst named one ID, old1. A second rekey leaves its candidate b1 unplaced, and a third leaves b1's candidate
    c1 unplaced: the count stays 1, and each event old1 may mean now carries old1's note alone."""
    case = new_case(tmp_path)
    old, b1, b2, c1, c2, d1, d2 = ids("old1", "b1", "b2", "c1", "c2", "d1", "d2")
    journal = Journal(case)
    first = first_rekey(journal, old, [b1, b2])
    second = next_rekey(journal, case, after(first), {b1: c1, b2: b2}, {b1: c2})
    assert second["rekey"] == {"pairs": {}, "unplaced": {}, "merged": {}, "candidates_unplaced": {b1: sorted([c1, c2])}}
    assert second["text"] == f"{NO_EVENT} No journal reference changed."
    assert unplaced_count(Journal(case).state) == 1
    third = next_rekey(journal, case, after(second), {c1: d1}, {c1: d2})
    assert third["rekey"] == {"pairs": {}, "unplaced": {}, "merged": {}, "candidates_unplaced": {c1: sorted([d1, d2])}}
    assert third["text"] == f"{NO_EVENT} No journal reference changed."
    for state in (journal.state, Journal(case).state):
        assert unplaced_count(state) == 1
        found = unplaced(state)
        assert sorted(found) == sorted([d1, d2, c2, b2])
        for notes in found.values():
            (note,) = notes
            assert (note["seq"], note["id"], sorted(note["candidates"])) == (first["seq"], old, sorted([d1, d2, c2, b2]))


def test_candidates_a_later_rekey_gives_one_event_merge_nothing(tmp_path):
    case = new_case(tmp_path)
    old, b1, b2, c1, c2, d1, e2 = ids("old1", "b1", "b2", "c1", "c2", "d1", "e2")
    journal = Journal(case)
    first = first_rekey(journal, old, [b1, b2])
    second = next_rekey(journal, case, after(first), {b1: c1}, {b1: c2})
    third = next_rekey(journal, case, after(second), {c1: d1, c2: d1, b2: e2})
    assert third["rekey"] == {"pairs": {c1: d1, c2: d1, b2: e2}, "unplaced": {}, "merged": {}}
    assert third["text"] == f"{NO_EVENT} No journal reference changed."
    state = Journal(case).state
    note = {"seq": first["seq"], "id": old, "candidates": [d1, e2]}
    assert unplaced(state) == {d1: [note], e2: [note]} and unplaced_count(state) == 1


def test_a_candidate_an_entry_named_between_the_rekeys_stays_the_analyst_s_reference(tmp_path):
    """A mark on b1 after the first rekey makes b1 a reference of the analyst's: the second rekey leaves it unplaced as
    one, its text counts it, and its events carry its own note beside old1's."""
    case = new_case(tmp_path)
    old, b1, b2, c1, c2 = ids("old1", "b1", "b2", "c1", "c2")
    journal = Journal(case)
    first = first_rekey(journal, old, [b1, b2])
    mark(journal, b1)
    second = next_rekey(journal, case, after(first), {b1: c1}, {b1: c2})
    assert second["rekey"] == {"pairs": {}, "unplaced": {b1: sorted([c1, c2])}, "merged": {}}
    assert second["text"] == f"{NO_EVENT} No journal reference was placed on a new ID. {LEFT_ONE}"
    c1, c2 = sorted([c1, c2])
    of_old = {"seq": first["seq"], "id": old, "candidates": [c1, c2, b2]}
    of_b1 = {"seq": second["seq"], "id": b1, "candidates": [c1, c2]}
    state = Journal(case).state
    assert unplaced(state) == {c1: [of_old, of_b1], c2: [of_old, of_b1], b2: [of_old]} and unplaced_count(state) == 2


B1, C1 = ids("b1", "c1")


@pytest.mark.parametrize("value", [[B1], {B1: []}, {B1: C1}, {B1: [7]}, {B1.upper(): [C1]}],
                         ids=["a list", "an empty list", "an ID for a list", "a number", "an uppercase ID"])
def test_a_rekey_whose_candidates_unplaced_is_not_a_map_of_ids_to_lists_of_ids_is_refused(tmp_path, value):
    case = new_case(tmp_path)
    journal = Journal(case)
    before = (case.folder / JOURNAL_FILE).read_bytes()
    with pytest.raises(JournalError, match="candidates_unplaced"):
        journal.append("case_upgrade", who=SYSTEM, from_format=CASE_FORMAT + 1, to_format=CASE_FORMAT + 2,
                       text="Event IDs changed.", rekey={"pairs": {}, "candidates_unplaced": value})
    assert (case.folder / JOURNAL_FILE).read_bytes() == before


@pytest.mark.parametrize("value", [["b1"], "b1", 7, None, {"b1": "c1"}, {"b1": [7]}], ids=repr)
def test_a_later_rekey_whose_candidates_unplaced_holds_no_list_of_ids_leaves_the_candidate_as_it_is(value):
    """A changed line can hold something else where the candidates left unplaced are; a reader of a rekey never fails on
    one."""
    state = state_of(rekey(5, unplaced={"old1": ["b1", "b2"]}), rekey(9, candidates_unplaced=value))
    first = {"seq": 5, "id": "old1", "candidates": ["b1", "b2"]}
    assert unplaced(state) == {"b1": [first], "b2": [first]} and unplaced_count(state) == 1


def changed(found: dict[str, str]) -> list[str]:
    """The IDs a run's parse changes, sorted."""
    return sorted(old for old, new in found.items() if old != new)


def test_the_upgrade_step_places_the_candidates_and_counts_only_the_analyst_s_references(tmp_path):
    """Format 2's step after a rekey written by hand before it, which left an ID unplaced on an event of each of two
    runs: Suricata's run, and EVE found in the evidence that loaded and then failed its check, whose rows drop. The step
    places both candidates, so the earlier list reads through it. Its text counts the two marked events it moved, and
    the dropped run's references name the marked one alone."""
    f = Format1(tmp_path, hosts=("SENSOR",))
    run = f.eve_run(7)
    f.eve_file("SENSOR/found/eve.json", 7)
    f.take_in()
    failed = f.found_run("suricata", "suricata_eve", "SENSOR", ["SENSOR/found/eve.json"], status="failed")
    loaded, dropped = (_parse(f.case, r).ids for r in (run, failed))
    (x, b1, *_), (fx, fb, *_) = changed(loaded), changed(dropped)
    (old,) = ids("old1")
    f.mark([x, fx, old])
    earlier = append_unchained(f.case.folder, "case_upgrade", who=SYSTEM, from_format=0, to_format=1,
                               text="Event IDs changed.", rekey={"pairs": {}, "unplaced": {old: [b1, fb]}})
    upgraded(f.case)
    (entry,) = f.upgrades()
    rekeyed = entry["rekey"]
    assert rekeyed["pairs"] == {x: loaded[x], b1: loaded[b1], fx: dropped[fx], fb: dropped[fb]}
    assert (rekeyed["unplaced"], rekeyed["merged"]) == ({}, {}) and "candidates_unplaced" not in rekeyed
    assert rekeyed["dropped_runs"] == {failed.run_id: {"rows": failed.loaded_rows, "references": [fx]}}
    n = rekeyed["runs"][run.run_id]["changed"]
    assert entry["text"] == ("Event IDs no longer depend on where or in which time zone a tool ran: "
                             f"{n} Suricata events took new IDs. 2 journal references now name their events' new IDs. "
                             "None was left unplaced.")
    state = replay(f.case.folder / JOURNAL_FILE)
    note = {"seq": earlier["seq"], "id": old, "candidates": [loaded[b1], dropped[fb]]}
    assert unplaced(state) == {loaded[b1]: [note], dropped[fb]: [note]} and unplaced_count(state) == 1


def two_collections(f: Format1) -> tuple[str, str]:
    """Found SRUM of one collection, then of another with one more record: format 1 gave the second collection's Id 5
    record, b.exe's, the ID the first's, a.exe's, had, so the two runs name different records by it, and format 2's
    step can place it on neither. Returns that ID, and the format 1 ID of the second collection's other record,
    c.exe's."""
    f.take_in()
    srum_tables(f.evidence / "DESKTOP" / "K1", [srum_row("5", "a.exe")])
    f.take_in()
    f.found_run("srumecmd", "srumecmd_csv", "DESKTOP", ["DESKTOP/K1/2024_SrumECmd_NetworkUsages_Output.csv"])
    (shared,) = f.uids("srumecmd")
    srum_tables(f.evidence / "DESKTOP" / "K2", [srum_row("5", "b.exe"), srum_row("6", "c.exe")])
    f.take_in()
    f.found_run("srumecmd", "srumecmd_csv", "DESKTOP", ["DESKTOP/K2/2024_SrumECmd_NetworkUsages_Output.csv"])
    (other,) = set(f.uids("srumecmd")) - {shared}
    return shared, other


def new_ids(app: App) -> dict[str, str]:
    """The loaded SRUM records' IDs after the upgrade, by program."""
    return dict(app.con.execute("SELECT process_executable, event_uid FROM events WHERE tool = 'srumecmd'").fetchall())


def test_the_upgrade_of_a_format_1_case_writes_the_fields_it_always_has(tmp_path):
    """With no earlier rekey nothing is a candidate: the entry holds the fields the step has always written, in their
    order, and the ID the analyst marked is unplaced, which the Event page and the overview count."""
    f = Format1(tmp_path)
    uid, _ = two_collections(f)
    f.mark([uid])
    app = App(f.case, for_work=True)
    try:
        (entry,) = f.upgrades()
        assert list(entry["rekey"]) == FORMAT_2_FIELDS
        assert list(entry["rekey"]["unplaced"]) == [uid]
        with pytest.raises(QueryError, match="the Case overview counts it"):
            api_event(app, {"uid": [uid]})
        assert api_overview(app, {})["progress"]["unplaced"] == 1
    finally:
        app.con.close()


def test_the_upgrade_step_leaves_a_candidate_unplaced_apart_from_the_ids_the_journal_names(tmp_path):
    """A rekey written by hand before format 2's step left old1 unplaced on two SRUM IDs: one that two records share,
    and c.exe's. No entry names either. The step places c.exe's on its record, and the shared one on neither record,
    so it lists that one among its candidates left unplaced. Its text counts no reference, each record carries old1's
    note, the overview counts old1 alone, and the Event page knows the shared ID as no unplaced ID of the journal's."""
    f = Format1(tmp_path)
    uid, other = two_collections(f)
    (old,) = ids("old1")
    f.mark([old])
    earlier = append_unchained(f.case.folder, "case_upgrade", who=SYSTEM, from_format=0, to_format=1,
                               text="Event IDs changed.", rekey={"pairs": {}, "unplaced": {old: [uid, other]}})
    app = App(f.case, for_work=True)
    try:
        (entry,) = f.upgrades()
        now = new_ids(app)
        assert sorted(entry["rekey"]) == sorted([*FORMAT_2_FIELDS, "candidates_unplaced"])
        assert entry["rekey"]["pairs"] == {other: now["c.exe"]}
        assert (entry["rekey"]["unplaced"], entry["rekey"]["merged"]) == ({}, {})
        assert entry["rekey"]["candidates_unplaced"] == {uid: sorted([now["a.exe"], now["b.exe"]])}
        assert entry["text"].endswith(" took new IDs. No journal reference changed.")
        for candidate in now.values():
            notes = api_event(app, {"uid": [candidate]})["event"]["unplaced"]
            assert notes == [{"seq": earlier["seq"], "id": old, "others": 2}]
        with pytest.raises(QueryError) as refused:
            api_event(app, {"uid": [uid]})
        assert str(refused.value) == "unknown event"
        assert api_overview(app, {})["progress"]["unplaced"] == 1
    finally:
        app.con.close()
