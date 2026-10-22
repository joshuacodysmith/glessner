"""The events an unplaced ID may have meant (journal.unplaced), read through the rekeys that come after the one that
listed them: a later rekey renames events, and the Event page looks the candidates up by the IDs the events have now. The
later rekey's map comes from the upgrade's own placing (referenced_ids and rekey._place), which has to name the
candidates for the reading to find them."""

import hashlib
from types import SimpleNamespace

import pytest

from glessner.case import JOURNAL_FILE, create_case
from glessner.journal import SYSTEM, Journal, State, referenced_ids, renamed, unplaced, unplaced_count
from glessner.rekey import _place, _sentence


def new_id(name: str) -> str:
    return hashlib.sha256(name.encode()).hexdigest()[:32]


def rekey(seq, pairs=None, **maps) -> dict:
    """A rekey as State.rekeys holds it: the case_upgrade entry's rekey map with the entry's number."""
    return {"seq": seq, "pairs": pairs or {}, **maps}


def state_of(*rekeys) -> State:
    state = State()
    state.rekeys = list(rekeys)
    return state


def test_a_later_rekey_renames_the_candidates_it_changed():
    state = state_of(rekey(5, unplaced={"old1": ["b1", "b2"]}), rekey(9, {"b1": "c1"}))
    assert unplaced(state) == {
        "c1": [{"seq": 5, "id": "old1", "candidates": ["c1", "b2"]}],
        "b2": [{"seq": 5, "id": "old1", "candidates": ["c1", "b2"]}],
    }


def test_the_rekey_that_listed_the_candidates_alone_leaves_them_as_written():
    state = state_of(rekey(5, {"b1": "b9"}, unplaced={"old1": ["b1", "b2"]}))
    assert unplaced(state) == {
        "b1": [{"seq": 5, "id": "old1", "candidates": ["b1", "b2"]}],
        "b2": [{"seq": 5, "id": "old1", "candidates": ["b1", "b2"]}],
    }


def test_a_rekey_before_the_one_that_listed_the_candidates_doesnt_rename_them():
    state = state_of(rekey(3, {"b1": "c1"}), rekey(5, unplaced={"old1": ["b1", "b2"]}))
    assert sorted(unplaced(state)) == ["b1", "b2"]


def test_each_later_rekey_is_one_lookup_in_file_order():
    """One rekey after another composes; within one rekey a swap reads as written."""
    state = state_of(rekey(5, unplaced={"old1": ["b1", "b2"]}), rekey(7, {"b1": "c1"}), rekey(9, {"c1": "d1", "b2": "b1"}))
    assert unplaced(state)["d1"] == [{"seq": 5, "id": "old1", "candidates": ["d1", "b1"]}]
    assert sorted(unplaced(state)) == ["b1", "d1"]
    swapped = state_of(rekey(5, unplaced={"old1": ["b1", "b2"]}), rekey(7, {"b1": "b2", "b2": "b1"}))
    assert unplaced(swapped)["b2"][0]["candidates"] == ["b2", "b1"]


def test_each_rekey_that_listed_candidates_reads_through_the_ones_after_it():
    state = state_of(
        rekey(5, unplaced={"old1": ["b1", "b2"]}),
        rekey(7, {"b1": "c1"}, unplaced={"old2": ["c1", "c2"]}),
        rekey(9, {"c1": "d1"}),
    )
    found = unplaced(state)
    assert sorted(found) == ["b2", "c2", "d1"]
    assert found["d1"] == [
        {"seq": 5, "id": "old1", "candidates": ["d1", "b2"]},
        {"seq": 7, "id": "old2", "candidates": ["d1", "c2"]},
    ]


def test_candidates_that_a_later_rekey_merged_are_listed_once():
    state = state_of(rekey(5, unplaced={"old1": ["b1", "b2", "b3"]}), rekey(9, {"b1": "c1", "b2": "c1"}))
    found = unplaced(state)
    assert found["c1"] == [{"seq": 5, "id": "old1", "candidates": ["c1", "b3"]}]
    assert sorted(found) == ["b3", "c1"]


def test_a_later_rekey_changes_neither_the_old_id_nor_the_count():
    state = state_of(rekey(5, unplaced={"old1": ["b1", "b2"]}), rekey(9, {"old1": "c0", "b1": "c1"}))
    assert {u["id"] for entries in unplaced(state).values() for u in entries} == {"old1"}
    assert unplaced_count(state) == 1


@pytest.mark.parametrize("pairs", [[], "x", 7, None, {"b1": 7, "b2": ["c2"]}], ids=repr)
def test_a_later_rekey_whose_pairs_are_not_a_map_of_ids_renames_nothing(pairs):
    """A changed line can hold something else where the pairs are; a reader of a rekey never fails on one."""
    state = state_of(rekey(5, unplaced={"old1": ["b1", "b2"]}), {"seq": 9, "pairs": pairs})
    assert sorted(unplaced(state)) == ["b1", "b2"]


def test_a_candidate_list_that_isnt_a_list_is_left_out():
    state = state_of(rekey(5, unplaced={"old1": "b1", "old2": ["b2"]}), rekey(9, {"b2": "c2"}))
    assert unplaced(state) == {"c2": [{"seq": 5, "id": "old2", "candidates": ["c2"]}]}


def test_the_journal_s_state_reads_the_candidates_through_a_later_rekey(tmp_path):
    (tmp_path / "evidence").mkdir()
    case = create_case(tmp_path / "case", "Test", tmp_path / "evidence", "cody")
    old, b1, b2, c1 = (new_id(name) for name in ("old1", "b1", "b2", "c1"))
    journal = Journal(case)
    first = journal.append(
        "case_upgrade",
        who=SYSTEM,
        from_format=3,
        to_format=4,
        text="Event IDs changed.",
        rekey={"pairs": {}, "unplaced": {old: [b1, b2]}},
    )
    assert sorted(unplaced(journal.state)) == sorted([b1, b2])
    journal.append("case_upgrade", who=SYSTEM, from_format=4, to_format=5, text="Event IDs changed.", rekey={"pairs": {b1: c1}})
    reopened = Journal(case)
    for state in (journal.state, reopened.state):
        assert unplaced(state) == {
            c1: [{"seq": first["seq"], "id": old, "candidates": [c1, b2]}],
            b2: [{"seq": first["seq"], "id": old, "candidates": [c1, b2]}],
        }
        assert unplaced_count(state) == 1


def test_a_candidate_a_later_rekey_leaves_unplaced_reads_as_that_rekeys_candidates():
    """The events the first rekey's ID may have meant are, after the second, those the second's ID may mean, and the other
    candidate. No entry named the second rekey's unplaced ID, an event's ID between the two, so the second lists it among
    its candidates left unplaced: it gets no note of its own, and the count leaves it out."""
    state = state_of(rekey(5, unplaced={"old1": ["b1", "b2"]}), rekey(9, candidates_unplaced={"b1": ["c1", "c2"]}))
    first = {"seq": 5, "id": "old1", "candidates": ["c1", "c2", "b2"]}
    assert unplaced(state) == {"c1": [first], "c2": [first], "b2": [first]}
    assert unplaced_count(state) == 1


def test_a_candidate_an_entry_named_too_gets_its_own_note_when_a_later_rekey_leaves_it_unplaced():
    """An entry named the candidate between the two rekeys, so it is the analyst's reference: its own note is listed
    beside the first rekey's, and it counts."""
    state = state_of(rekey(5, unplaced={"old1": ["b1", "b2"]}), rekey(9, unplaced={"b1": ["c1", "c2"]}))
    found = unplaced(state)
    first = {"seq": 5, "id": "old1", "candidates": ["c1", "c2", "b2"]}
    second = {"seq": 9, "id": "b1", "candidates": ["c1", "c2"]}
    assert found == {"c1": [first, second], "c2": [first, second], "b2": [first]}
    assert unplaced_count(state) == 2


def test_a_later_rekey_whose_unplaced_list_holds_no_id_leaves_the_candidate_as_it_is():
    state = state_of(rekey(5, unplaced={"old1": ["b1", "b2"]}), rekey(9, unplaced={"b1": [7], "b2": "c2"}))
    assert sorted(unplaced(state)) == ["b1", "b2"]


def new_case(tmp_path):
    (tmp_path / "evidence").mkdir()
    return create_case(tmp_path / "case", "Test", tmp_path / "evidence", "cody")


def first_rekey(journal, old, candidates):
    """A mark on `old`, then the upgrade that leaves `old` unplaced, with `candidates`."""
    journal.append("mark", targets=[old], value="suspicious", note="")
    return journal.append("case_upgrade", who=SYSTEM, from_format=3, to_format=4, text="Event IDs changed.",
                          rekey={"pairs": {}, "unplaced": {old: candidates}})


def next_rekey(journal, case, formats, *runs):
    """The next ID-changing upgrade as the upgrade writes it: step 7 places every ID the journal names and every event an
    earlier rekey's unplaced ID may have meant (referenced_ids) on what each run in `runs`, a map of old IDs to new ones,
    gives it. The entry holds the result as its rekey, and its text counts the IDs the journal names."""
    named, candidates = referenced_ids(case.folder / JOURNAL_FILE)
    placed = _place(named, {f"run{i}": SimpleNamespace(ids=ids) for i, ids in enumerate(runs)}, candidates)
    from_format, to_format = formats
    return journal.append("case_upgrade", who=SYSTEM, from_format=from_format, to_format=to_format,
                          text=_sentence({}, placed["pairs"], placed["unplaced"], named), rekey=placed)


def test_the_upgrade_places_the_candidates_an_earlier_rekey_listed(tmp_path):
    """No entry names a candidate; the earlier rekey's record does. Without it in referenced_ids, the next rekey's pairs
    are empty and the Event page finds the entry on no event."""
    case = new_case(tmp_path)
    old, b1, b2, c1, c2 = (new_id(name) for name in ("old1", "b1", "b2", "c1", "c2"))
    journal = Journal(case)
    first = first_rekey(journal, old, [b1, b2])
    assert referenced_ids(case.folder / JOURNAL_FILE) == ({old}, {b1, b2})
    second = next_rekey(journal, case, (4, 5), {b1: c1, b2: c2})
    assert second["rekey"] == {"pairs": {b1: c1, b2: c2}, "unplaced": {}, "merged": {}}
    for state in (journal.state, Journal(case).state):
        assert unplaced(state) == {c: [{"seq": first["seq"], "id": old, "candidates": [c1, c2]}] for c in (c1, c2)}
        assert renamed(state, b1) == (c1, [second["seq"]])
        assert unplaced_count(state) == 1


def test_the_upgrade_places_a_candidate_through_the_rekeys_between(tmp_path):
    """After a second rekey the candidates are named by the IDs it gave them, which the third places in turn."""
    case = new_case(tmp_path)
    old, b1, b2, c1, c2, d1 = (new_id(name) for name in ("old1", "b1", "b2", "c1", "c2", "d1"))
    journal = Journal(case)
    first = first_rekey(journal, old, [b1, b2])
    next_rekey(journal, case, (4, 5), {b1: c1, b2: c2})
    assert referenced_ids(case.folder / JOURNAL_FILE) == ({old}, {c1, c2})
    third = next_rekey(journal, case, (5, 6), {c1: d1})
    assert third["rekey"]["pairs"] == {c1: d1}
    found = unplaced(Journal(case).state)
    assert found == {c: [{"seq": first["seq"], "id": old, "candidates": [d1, c2]}] for c in (d1, c2)}


def test_the_upgrade_that_leaves_a_candidate_unplaced_lists_the_events_it_may_mean(tmp_path):
    """No entry named the candidate, so the upgrade lists it among its candidates left unplaced, apart from the IDs the
    journal names: its events carry the first rekey's note alone, and the overview counts the one ID the analyst
    named."""
    case = new_case(tmp_path)
    old, b1, b2, c1, c2 = (new_id(name) for name in ("old1", "b1", "b2", "c1", "c2"))
    journal = Journal(case)
    first = first_rekey(journal, old, [b1, b2])
    second = next_rekey(journal, case, (4, 5), {b1: c1}, {b1: c2})
    assert second["rekey"]["unplaced"] == {} and second["rekey"]["candidates_unplaced"] == {b1: sorted([c1, c2])}
    c1, c2 = sorted([c1, c2])
    of_old = {"seq": first["seq"], "id": old, "candidates": [c1, c2, b2]}
    state = Journal(case).state
    assert unplaced(state) == {c1: [of_old], c2: [of_old], b2: [of_old]}
    assert unplaced_count(state) == 1
