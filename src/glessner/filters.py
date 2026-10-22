"""View filters: which events the timeline shows. They never change the case.

A filter is {"only": [pred, ...], "hide": [pred, ...], "show": [pred, ...]}. A pred names field values that
must all match, for example {"host": "DC01", "channel": "Security"}. An event shows when it matches one of
the "only" preds, or there are none, and is not hidden. The most specific rule wins: a "hide" pred hides
the events it matches unless a more specific "show" pred also matches them, so a hidden host can still
show one of its files. Filters live in the server's memory under a short ID, so
a long list of hidden source files never travels in a URL; they are not journaled.

The View flyout adds an optional "view" part, {"marks": [...], "values": [pred, ...]}:
an event the sources allow shows when its mark is one of the marks or it matches one of the values. "faded"
lists pivot results to show anyway while the view hides them; the page draws those faded until they're marked.
Hidden events still count for pivots and links, which never read the filter. With "suggested_tags": true, the
view's tag and tactic values also match Hayabusa's pending tag suggestions.
"""

from __future__ import annotations

import hashlib
import json
import re

from .events import sql_literal
from .queries import EITHER_END, FIELDS, GROUP_KEYS
from .search import SearchError, account_exprs, hits_sql, value_key
from .search import parse as parse_search

# Fields read from a derived table rather than a column: a saved search, a tag key or "*" for any tag,
# and a tactic lane's name or "Untagged".
SPECIAL = {"search", "tag", "tactic"}
# An event's own data field, by name: "data.ProcessName". The name is quoted into a JSON path, so no quote or backslash.
DATA_FIELD = re.compile(r'^data\.([^"\\]{1,80})$')
MARK = GROUP_KEYS["mark"]
VIEW_MARKS = {   # the View flyout's mark choices, in their display order, and the events each one covers
    "Malicious": f"{MARK} = 'Malicious'", "Suspicious": f"{MARK} = 'Suspicious'",
    "Suggested": f"{MARK} LIKE 'Suggested: %'", "Authorized": f"{MARK} = 'Authorized'",
    "Unreviewed": f"{MARK} = 'Unreviewed'"}
MAX_VIEW_VALUES = 50
MAX_FADED = 1_000   # pivot results come back 500 at most
UID = re.compile(r"^[0-9a-f]{32}$")
MAX_PREDS = 5_000   # a filter that hides every source file of a large case still fits
KEEP = 200          # filters kept in memory; an older ID is refused, and the page registers its filter again


class FilterError(ValueError):
    """Raised for a filter with unknown fields, empty preds, or values that are not text."""


def normalize(spec: dict) -> dict:
    """Validate a filter and put it in one canonical form, so equal filters get the same ID."""
    if not isinstance(spec, dict):
        raise FilterError("a filter is an object with 'only' and 'hide' lists")
    out = {}
    for part in ("only", "hide", "show"):
        preds = spec.get(part) or []
        if not isinstance(preds, list) or len(preds) > MAX_PREDS:
            raise FilterError(f"'{part}' must be a list of at most {MAX_PREDS:,} preds")
        seen = set()
        clean = []
        for pred in preds:
            p = normalize_pred(pred)
            key = json.dumps(p, sort_keys=True)
            if key not in seen:
                seen.add(key)
                clean.append(p)
        out[part] = sorted(clean, key=lambda p: json.dumps(p, sort_keys=True))
    view = spec.get("view")
    if view is not None:   # absent rather than null when unused, so a sources-only filter keeps its ID
        if not isinstance(view, dict):
            raise FilterError("'view' is an object with 'marks' and 'values' lists")
        marks = view.get("marks") or []
        values = view.get("values") or []
        if not isinstance(marks, list) or any(not isinstance(m, str) or m not in VIEW_MARKS for m in marks):
            raise FilterError(f"view marks must be some of {list(VIEW_MARKS)}")
        if not isinstance(values, list) or len(values) > MAX_VIEW_VALUES:
            raise FilterError(f"view values must be a list of at most {MAX_VIEW_VALUES} preds")
        unique = {json.dumps(normalize_pred(p), sort_keys=True) for p in values}
        out["view"] = {"marks": [m for m in VIEW_MARKS if m in marks], "values": [json.loads(v) for v in sorted(unique)]}
        suggested = view.get("suggested_tags", False)
        if not isinstance(suggested, bool):
            raise FilterError("view suggested_tags is true or false")
        # Kept only where it changes what shows, so a view without tag values keeps its ID and its description.
        if suggested and any(widened(p) for p in out["view"]["values"]):
            out["view"]["suggested_tags"] = True
        faded = spec.get("faded") or []
        if not isinstance(faded, list) or len(faded) > MAX_FADED or not all(isinstance(u, str) and UID.match(u) for u in faded):
            raise FilterError(f"'faded' must be a list of at most {MAX_FADED:,} event IDs")
        if faded:
            out["faded"] = sorted(set(faded))
    return out


def widened(pred: dict) -> bool:
    """Whether a view's suggested_tags changes what a value matches: a tag, or a tactic other than Untagged, which keeps
    the lanes' meaning. A View with only Untagged values keeps its ID and gets no note about suggestions."""
    return "tag" in pred or pred.get("tactic", "Untagged") != "Untagged"


def normalize_pred(pred: dict) -> dict:
    if not isinstance(pred, dict) or not pred:
        raise FilterError("a pred is a non-empty object of field values")
    unknown = sorted(k for k in pred if k not in FIELDS and k not in EITHER_END and k not in SPECIAL
                     and not DATA_FIELD.match(k))
    if unknown:
        raise FilterError(f"unknown filter field {unknown[0]!r}; fields are {sorted([*FIELDS, *EITHER_END])}")
    if not all(isinstance(v, str) for v in pred.values()):
        raise FilterError("filter values must be text")
    if "search" in pred:   # a saved search as a View value; it must parse
        try:
            parse_search(pred["search"])
        except SearchError as exc:
            raise FilterError(str(exc)) from exc
    return {k: pred[k] for k in sorted(pred)}


def _preds(spec: dict) -> list[dict]:
    return [*spec["only"], *spec["hide"], *spec["show"], *spec.get("view", {}).get("values", [])]


def searches(spec: dict) -> list[str]:
    """The searches a normalized filter reads, which must be saved before its SQL runs (search.hits_sql)."""
    return sorted({p["search"] for p in _preds(spec) if "search" in p})


def data_values(spec: dict) -> list[tuple[str, str]]:
    """The event data values, such as ("data.ProcessName", value), a normalized filter reads, which are saved as its
    searches are (search.save_value)."""
    return sorted({(k, v) for p in _preds(spec) for k, v in p.items() if DATA_FIELD.match(k)})


def pred_sql(pred: dict, suggested: bool = False, value: bool = False) -> str:
    """The condition of one pred. `value` is true for a View's value, whose user also matches the bare name, as search's
    does. The Sources part's rules (only, hide, show) and a lane menu's counts leave it false: a user lane's menu makes
    {user: label} from the lane's label, so a bare name there must stay that one lane."""
    # IS NOT DISTINCT FROM is never NULL, so hiding a channel cannot drop events that have no channel.
    return "(" + " AND ".join(_match_sql(k, v, suggested, value) for k, v in pred.items()) + ")"


def _match_sql(field: str, value: str, suggested: bool = False, view_value: bool = False) -> str:
    if field == "user" and view_value:   # as search's user: reads it
        same = (f"lower({x}) IS NOT DISTINCT FROM lower({sql_literal(value)})" for x in account_exprs(value))
        return "(" + " OR ".join(same) + ")"
    if field == "search":   # its matches are saved before each use of the filter (server.App.filter)
        return hits_sql(value)
    # Tags read the analyst's tags, and with `suggested` Hayabusa's pending suggestions too: tag_suggestions already
    # leaves out a suggestion the analyst accepted or dismissed.
    tables = ("tags", "tag_suggestions") if suggested else ("tags",)
    if field == "tag":
        where = "" if value == "*" else f" WHERE tag = {sql_literal(value)}"
        return "e.event_uid IN (" + " UNION ALL ".join(f"SELECT event_uid FROM {t}{where}" for t in tables) + ")"
    if field == "tactic":
        if value == "Untagged":   # the lane's own meaning, which lanes read from accepted tags only
            return "e.event_uid NOT IN (SELECT event_uid FROM tags WHERE kind = 'tactic')"
        where = f" WHERE kind = 'tactic' AND label = {sql_literal(value)}"
        return "e.event_uid IN (" + " UNION ALL ".join(f"SELECT event_uid FROM {t}{where}" for t in tables) + ")"
    if field in EITHER_END:   # either column, each compared as ip and dest_ip are below
        return "(" + " OR ".join(f"lower({c}) IS NOT DISTINCT FROM lower({sql_literal(value)})" for c in EITHER_END[field]) + ")"
    if DATA_FIELD.match(field):   # saved before each use of the filter, so a pan reads no event's data
        return hits_sql(value_key(field, value))
    # Every field compares without case, as search does.
    return f"lower({FIELDS[field]}) IS NOT DISTINCT FROM lower({sql_literal(value)})"


def covers(outer: dict, inner: dict) -> bool:
    """True when `outer` is as broad as `inner` or broader: every field it names, `inner` names with the same value."""
    return all(inner.get(k) == v for k, v in outer.items())


def condition(spec: dict) -> str:
    """The SQL condition an event must meet to show, or '' when the filter shows everything. Needs BASE_FROM's joins.

    A hide rule is canceled for an event by any matching show rule more specific than it. Nesting works out:
    with hide DC01, show DC01's Security.evtx, and hide DC01's Security channel inside that, the innermost wins.
    """
    parts = []
    if spec["only"]:
        parts.append("(" + " OR ".join(pred_sql(p) for p in spec["only"]) + ")")
    hidden = []
    for h in spec["hide"]:
        exceptions = [s for s in spec["show"] if s != h and covers(h, s)]
        clause = pred_sql(h)
        if exceptions:
            clause += " AND NOT (" + " OR ".join(pred_sql(s) for s in exceptions) + ")"
        hidden.append(f"({clause})")
    if hidden:
        parts.append("NOT (" + " OR ".join(hidden) + ")")
    if "view" in spec:
        shown = view_condition(spec)
        if spec.get("faded"):
            shown = f"({shown} OR e.event_uid IN ({', '.join(sql_literal(u) for u in spec['faded'])}))"
        parts.append(shown)
    return " AND ".join(parts)


def view_condition(spec: dict) -> str:
    """What the view shows, without the faded pivot results: one of its marks, or one of its values."""
    view = spec["view"]
    suggested = view.get("suggested_tags", False)
    terms = [VIEW_MARKS[m] for m in view["marks"]] + [pred_sql(p, suggested, True) for p in view["values"]]
    return "(" + " OR ".join(terms) + ")" if terms else "false"


def _value_words(field: str, value: str) -> str:
    """One field of a pred in words. A saved search is worded through each term's Term.describe, so a report that names
    a View's search says what it matched: 'a search for the whole word "nmap" and host is "DC01"'. A search that no
    longer parses, which normalize refused when it was saved, reads as its text."""
    if field == "addr":
        return f"IP {value} at either end"
    if field == "search":
        try:
            return "a search for " + " and ".join(t.describe() for t in parse_search(value))
        except SearchError:
            return f"a search for {value}"
    return f"{field} {value}"


def _pred_words(pred: dict) -> str:
    return " and ".join(_value_words(k, v) for k, v in pred.items())


def view_terms(spec: dict) -> list[str]:
    """The View's terms in words, one for its marks and one per value: an event shows when it meets any of them, so a
    search result the View hides meets none."""
    if "view" not in spec:
        return []
    view = spec["view"]
    terms = [f"marked {' or '.join(view['marks'])}"] if view["marks"] else []
    terms.extend("with " + _pred_words(p) for p in view["values"])
    return terms


def faded_sql(spec: dict) -> str:
    """True for events that show only as faded pivot results, for the timeline to draw them faded."""
    return f"NOT {view_condition(spec)}" if spec.get("faded") else "false"


def where_sql(spec: dict) -> str:
    """An ' AND ...' clause for a normalized filter, or '' when it filters nothing."""
    cond = condition(spec)
    return f" AND {cond}" if cond else ""


def filter_id(spec: dict) -> str:
    return hashlib.sha256(json.dumps(spec, sort_keys=True).encode()).hexdigest()[:16]


def describe(spec: dict) -> str:
    """A precise one-line account of a filter, for export file notes and the report."""
    show = _pred_words
    out = []
    if spec["only"]:
        out.append("Only events with " + "; or ".join(show(p) for p in spec["only"]) + ".")
    if spec["hide"]:
        out.append("Hidden: events with " + "; or ".join(show(p) for p in spec["hide"]) + ".")
    if spec["show"]:
        out.append("Shown anyway: events with " + "; or ".join(show(p) for p in spec["show"]) + ".")
    if "view" in spec:
        view = spec["view"]
        terms = view_terms(spec)
        out.append("View: events " + ("; or ".join(terms) if terms else "none") + "."
                   + (" Tag values also match Hayabusa's suggested tags, not yet accepted." if view.get("suggested_tags") else "")
                   + (f" Plus {len(spec['faded']):,} pivot results, shown faded." if spec.get("faded") else ""))
    return " ".join(out)


class FilterStore:
    """Registered filters by ID, newest last."""

    def __init__(self) -> None:
        self._items: dict[str, tuple[dict, str, str, str]] = {}

    def add(self, spec: dict) -> str:
        spec = normalize(spec)
        fid = filter_id(spec)
        self._items.pop(fid, None)
        self._items[fid] = (spec, where_sql(spec), condition(spec) or "true", faded_sql(spec) if "view" in spec else "false")
        while len(self._items) > KEEP:
            self._items.pop(next(iter(self._items)))
        return fid

    def get(self, fid: str) -> tuple[dict, str, str]:
        """The filter, its ' AND ...' clause, and its bare condition (for counting with FILTER)."""
        return self._entry(fid)[:3]

    def view_terms(self, fid: str) -> list[str]:
        """The View's terms in words, or none with no View."""
        return view_terms(self._entry(fid)[0])

    def view_sql(self, fid: str) -> str:
        """The SQL that's true for events the View shows (without its faded pivot results), or 'true' with no View."""
        spec = self._entry(fid)[0]
        return view_condition(spec) if "view" in spec else "true"

    def faded(self, fid: str) -> str:
        """The SQL that's true for events shown only as faded pivot results."""
        return self._entry(fid)[3]

    def _entry(self, fid: str) -> tuple[dict, str, str, str]:
        if fid not in self._items:
            raise FilterError("unknown filter; it may predate a server restart, so reload the page")
        return self._items[fid]
