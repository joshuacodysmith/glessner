"""The same evidence gives the same results. Two cases built from one evidence, one after the other, each by a Python process
of its own, hold the same events, derived tables, overview figures, and exports; a rebuild and a copy of a case hold the
events it held.

The builds differ in everything the app should not depend on: the seed of Python's string hashing, the evidence folder's
path and name, the case folder's path, the order the tools run and the output loads, and the clock, which names the runs.
What differs between two builds by design is left out of the comparisons: run IDs, which name the second a run started in
(and with them the run_id column, the run_id in each export row, and the raw export file), run times, the journal's
timestamps and head, and the report. A tool that works on copies of its inputs also writes the copies' paths into its own
output, so that output differs, while the events built from it name the evidence."""

import shutil
from typing import NamedTuple

import pytest
from custody_cases import (
    DERIVED_TABLES,
    event_rows,
    make_evidence,
    run_identity,
    tables_of,
    views_from_new_process,
    wait_for_a_later_second,
)

from glessner.case import Case, open_case
from glessner.cli import main
from glessner.runner import read_runs, rebuild

# Both tests read the cases the fixture builds, so they run on one worker, which builds them once
pytestmark = pytest.mark.xdist_group("same_result_twice")


class Builds(NamedTuple):
    """Two cases built from the same evidence, and what the app showed of each (custody_cases.app_views)."""

    first: Case
    second: Case
    first_views: dict
    second_views: dict


@pytest.fixture(scope="module")
def builds(tmp_path_factory):
    """Two cases built from one evidence, each in a Python process of its own. The first is built from the evidence folder
    with hash seed 1 in the usual order. The second is built with hash seed 2 from a copy of the folder at another path,
    in the opposite order, after the clock has passed the second of the first's newest run, so the cases share no run ID.
    A hash order, an evidence path, a case folder path, a load order, or a run ID that leaked into an event's key or a
    column then shows as a difference."""
    root = tmp_path_factory.mktemp("twice")
    evidence = make_evidence(root)
    moved = root / "moved" / "collection"
    shutil.copytree(evidence, moved)
    folders = root / "one" / "case", root / "elsewhere" / "deeper" / "case"
    first_views = views_from_new_process(evidence, folders[0], hash_seed=1)
    first = open_case(folders[0])
    wait_for_a_later_second(first)
    second_views = views_from_new_process(moved, folders[1], hash_seed=2, reverse=True, uid=first_views["uid"])
    return Builds(first, open_case(folders[1]), first_views, second_views)


def run_summaries(case):
    """What each run did and found, by the run's identity: its tool version, status, rows loaded, and evidence check."""
    return {run_identity(r): (r.tool_version, r.status, r.loaded_rows, r.evidence_check) for r in read_runs(case)}


def test_two_builds_from_one_evidence_agree(builds):
    first, second = builds.first, builds.second
    assert first.manifest_path.read_bytes() == second.manifest_path.read_bytes()
    first_ids, second_ids = ({r.run_id for r in read_runs(case)} for case in (first, second))
    assert first_ids and not first_ids & second_ids, "the builds share a run ID, so a leak of one would go unseen"

    # Each row's run_id is its run's tool, host, and inputs, so a row moved to another run shows too
    rows = event_rows(first, by_identity=True)
    assert len(rows) > 10 and rows == event_rows(second, by_identity=True)
    assert run_summaries(first) == run_summaries(second)
    assert {tool for tool, _, _ in run_summaries(first)} == {"event_xml", "evtxecmd", "hayabusa", "import", "pecmd",
                                                              "sqlecmd", "suricata"}

    views, other = builds.first_views, builds.second_views
    for group in ("tables", "overview"):
        assert views[group].keys() == other[group].keys()
        for name, piece in views[group].items():
            assert piece == other[group][name], f"{group}.{name}"
    for name in ("timeline_csv", "timeline_jsonl", "indicators"):
        assert views[name] == other[name], name
    # Each piece has something in it to compare
    assert all(views["tables"][name] for name in DERIVED_TABLES)
    assert views["indicators"].count(b"\n") > 1 and len(views["timeline_csv"]) > 10


def test_a_rebuild_and_a_copy_give_the_same_events(builds, tmp_path):
    first, second = builds.first, builds.second
    stored, tables = event_rows(first), tables_of(first)
    assert len(rebuild(first)) == len(read_runs(first))
    assert event_rows(first) == stored, "a rebuild in this process gave other events than the build's process did"
    assert tables_of(first) == tables
    assert event_rows(first, by_identity=True) == event_rows(second, by_identity=True)

    assert main(["copy-case", str(first.folder), str(tmp_path / "copy"), "--name", "Copy"]) == 0
    copy = open_case(tmp_path / "copy")
    assert event_rows(copy) == stored, "the copy holds the events the source held, run_id included"
    assert {r.run_id for r in read_runs(copy)} == {r.run_id for r in read_runs(first)}
