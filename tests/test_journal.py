import json

import pytest

from glessner.case import create_case
from glessner.journal import Journal, JournalError, replay


@pytest.fixture
def case(tmp_path):
    (tmp_path / "evidence" / "DC01").mkdir(parents=True)
    return create_case(tmp_path / "case", "Test", tmp_path / "evidence", "cody")


def test_marks_append_and_replay(case):
    j = Journal(case)
    j.append("mark", targets=["a", "b"], value="suspicious", note="first look")
    j.append("mark", targets=["b"], value="malicious")
    j.append("mark", targets=["a"], value="unreviewed")
    assert set(j.state.marks) == {"b"} and j.state.marks["b"].value == "malicious"
    replayed = replay(case.folder / "journal.jsonl")
    assert {u: m.value for u, m in replayed.marks.items()} == {"b": "malicious"}
    assert replayed.last_seq == 4   # after the case_created entry that starts the chain
    lines = [json.loads(line) for line in (case.folder / "journal.jsonl").read_text().splitlines()]
    assert [line["seq"] for line in lines] == [1, 2, 3, 4] and all(line["who"] == "cody" for line in lines[1:])


def test_journal_reopens_and_continues_sequence(case):
    Journal(case).append("note", target="a", text="looks like RDP")
    j = Journal(case)
    entry = j.append("host_role", host="DC01", role="Domain controllers")
    assert entry["seq"] == 3
    assert j.state.notes["a"][0]["text"] == "looks like RDP"
    assert j.state.hosts["DC01"].role == "Domain controllers"


def test_host_identity_edits(case):
    j = Journal(case)
    j.append("host_identity", host="DC01", op="add_ip", value="10.0.0.5")
    j.append("host_identity", host="DC01", op="add_name", value="dc01-old")
    j.append("host_identity", host="DC01", op="remove_ip", value="10.0.0.5")
    edits = j.state.hosts["DC01"]
    assert edits.add_ips == set() and edits.remove_ips == {"10.0.0.5"} and edits.add_names == {"DC01-OLD"}


@pytest.mark.parametrize("action,payload", [
    ("mark", {"targets": ["a"], "value": "evil"}),
    ("mark", {"targets": [], "value": "malicious"}),
    ("note", {"target": "a", "text": "  "}),
    ("host_identity", {"host": "DC01", "op": "rename", "value": "x"}),
    ("case_setting", {"value": 5}),
    ("delete_everything", {}),
])
def test_invalid_actions_are_refused_and_not_written(case, action, payload):
    j = Journal(case)
    before = (case.folder / "journal.jsonl").read_bytes()
    with pytest.raises(JournalError):
        j.append(action, **payload)
    assert (case.folder / "journal.jsonl").read_bytes() == before


def test_a_second_writer_s_entries_are_applied_before_the_next_number(case):
    """The close command appends through a Journal of its own while the server's is open. The server applies the other
    writer's entries before it numbers its next one, so no two entries share a number and undo accepts the analyst's."""
    from glessner.audit import plan_undo, read_entries

    server = Journal(case)
    server.append("mark", targets=["a"], value="suspicious")
    Journal(case).append("case_setting", name="closed", value={"hash_check": "ok"})   # the close command
    entry = server.append("mark", targets=["b"], value="malicious")
    assert entry["seq"] == 4 and server.state.settings["closed"] == {"hash_check": "ok"}
    entries = read_entries(server.path)
    assert [e["seq"] for e in entries] == [1, 2, 3, 4] and server.state.last_seq == 4
    assert plan_undo(entries, 4)["changes"]
    assert set(server.state.marks) == {"a", "b"} and replay(case.folder / "journal.jsonl").marks.keys() == {"a", "b"}


# Torn lines (a torn line stopping the read, and an entry read before another writer's half-written line applied once)
# are tested in test_journal_chain.py's Torn rows, "A write in progress" among them, and in test_format3.py's torn
# format 2 journal and torn rekey line.


def test_a_journal_is_read_a_line_at_a_time(case):
    """The reader holds one line at a time, not the rest of the file and its lines at once, which would take about
    twice the journal's size in memory when a case opened, where a journal of bulk marks can run to hundreds of MB."""
    import tracemalloc

    path = case.folder / "journal.jsonl"
    with path.open("w", encoding="utf-8", newline="\n") as f:
        for seq in range(1, 31):   # 30 MB, of which the state keeps the last 1 MB value
            f.write(json.dumps({"seq": seq, "at": "", "who": "cody", "action": "case_setting", "name": "big",
                                "value": "x" * 1_000_000}) + "\n")
    tracemalloc.start()
    try:
        journal = Journal(case)
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    size = path.stat().st_size
    assert journal.state.last_seq == 30
    assert peak < size / 4, f"a peak of {peak:,} bytes reading a journal of {size:,}"


# A line missing its LF is a reported problem, not accepted silently: test_journal_chain.py's whole entry missing its
# LF, and test_format3.py's unchained tails that format 2's reader applied.
