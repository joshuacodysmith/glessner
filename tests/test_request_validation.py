"""Request validation: a request value of the wrong kind is refused with the error the server answers with a 400, and a
request that names an event twice changes it once."""

import pytest

from glessner.filters import FilterError, normalize
from glessner.journal import Journal
from glessner.queries import QueryError
from glessner.rules import RuleError, parse, parse_time
from glessner.server import App, api_mark, api_rule, api_rules, api_tag


@pytest.mark.parametrize("mark", [{}, [], ["Malicious"], None, 7, "Nope"], ids=repr)
def test_a_view_mark_that_is_not_a_known_name_is_refused(mark):
    """A view's marks are text naming the View's mark choices. An entry that is an object or a list can't be looked up
    by name, so it gets the same FilterError as an unknown name."""
    with pytest.raises(FilterError, match="view marks must be some of"):
        normalize({"view": {"marks": [mark]}})


def test_view_marks_keep_their_display_order():
    """The accepted marks come back in the View's display order, whatever order the request lists them in."""
    assert normalize({"view": {"marks": ["Unreviewed", "Malicious"]}})["view"]["marks"] == ["Malicious", "Unreviewed"]


def rule_text(condition, rule_id="r"):
    return f"id: {rule_id}\nsuggest: suspicious\nwhen: {condition}\n"


NON_FINITE = [".inf", "-.inf", ".nan", "1.0e+400"]  # YAML 1.1 reads each of these as an infinity or NaN
CONDITIONS = {  # each takes the value in a rule's number field
    "equals": "{{field: record_id, equals: {}}}",
    "in": "{{field: record_id, in: [7, {}]}}",
    "between": "{{field: ts_us, between: [0, {}]}}",
}


@pytest.mark.parametrize("value", NON_FINITE)
@pytest.mark.parametrize("condition", CONDITIONS.values(), ids=list(CONDITIONS))
def test_a_rule_number_that_yaml_reads_as_infinity_or_nan_is_refused(condition, value):
    """int() of an infinity raises OverflowError and of NaN a ValueError in Python's words, so a rule number that is not
    finite is refused as a RuleError, which the server answers with a 400 that says why."""
    with pytest.raises(RuleError, match="needs a finite number"):
        parse(rule_text(condition.format(value)))


def test_finite_rule_numbers_written_as_floats_read_as_integers():
    """A float with no fraction, or one written with an exponent, reads as the integer it names."""
    assert parse(rule_text("{field: record_id, in: [7.0, 1.0e+3, -2.0]}")).params == (7, 1000, -2)


@pytest.mark.parametrize("value", [float("inf"), float("-inf"), float("nan")])
def test_parse_time_refuses_a_number_that_is_not_finite(value):
    """parse_time reads a number as epoch microseconds, so a float that is not finite gets the same RuleError as a rule
    number."""
    with pytest.raises(RuleError, match="ts_us needs a finite number"):
        parse_time(value)


def test_parse_time_reads_epoch_microseconds_and_iso_times():
    assert parse_time(1600484400000000) == 1600484400000000
    assert parse_time(1.5e15) == 1500000000000000
    assert parse_time("2020-09-19T03:00:00Z") == 1600484400000000


def test_saving_a_rule_with_a_number_that_is_not_finite_says_so(synthetic_case):
    """A rule saved through the server is refused with the reason, and a rule already in the journal with such a number
    reports the same error while the case opens and the other sources build."""
    Journal(synthetic_case).append("rule_add", id="infinite", text=rule_text("{field: record_id, equals: .inf}", "infinite"))
    app = App(synthetic_case)
    try:
        rules = {r["id"]: r for r in api_rules(app, {})["rules"]}
        assert "record_id needs a finite number" in rules["infinite"]["error"]
        assert rules["hayabusa"]["matched"] == 1
        with pytest.raises(QueryError, match="rule not saved: record_id needs a finite number"):
            api_rule(app, {"op": "add", "text": rule_text("{field: record_id, in: [1, -.inf]}")})
    finally:
        app.con.close()


@pytest.fixture
def work(synthetic_case):
    """Two events of the synthetic case, in event ID order, and the case open for work."""
    app = App(synthetic_case, for_work=True)
    try:
        (first,), (second,) = app.con.execute("SELECT event_uid FROM events ORDER BY event_uid LIMIT 2").fetchall()
        yield app, first, second
    finally:
        app.con.close()


def test_a_mark_request_that_names_an_event_twice_leaves_one_mark_row(work):
    """The marks table holds one row per marked event, so an event a request lists twice, or lists again when it is
    marked again, still has one row."""
    app, first, second = work
    api_mark(app, {"uids": [first, second, first], "value": "suspicious"})
    marks = lambda: app.con.execute("SELECT event_uid, label FROM marks ORDER BY event_uid").fetchall()
    assert marks() == [(first, "Suspicious"), (second, "Suspicious")]
    api_mark(app, {"uids": [first, first], "value": "malicious"})
    assert marks() == [(first, "Malicious"), (second, "Suspicious")]


def test_a_tag_request_that_names_an_event_twice_leaves_one_row_per_tag(work):
    """The tags table holds one row per event and tag, so an event a request lists twice gets the tag once."""
    app, first, second = work
    api_tag(app, {"uids": [first, second, first], "add": ["T1059"]})
    tags = lambda: app.con.execute("SELECT event_uid, tag FROM tags ORDER BY event_uid, tag").fetchall()
    assert tags() == [(first, "technique:T1059"), (second, "technique:T1059")]
    api_tag(app, {"uids": [first, first], "add": ["T1021.001"], "remove": ["T1059"]})
    assert tags() == [(first, "technique:T1021.001"), (second, "technique:T1059")]
