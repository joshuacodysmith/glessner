"""Suggestion rules: YAML conditions that suggest a mark for matching events.

A rule only suggests. The analyst accepts or rejects each suggestion, and only accepted ones
become marks. Rules live in the journal, so the case keeps one record of who added or changed
what. Every rule compiles to a parameterized query: values never become SQL text.

Example:

    id: backup-service-authorized
    suggest: authorized
    when:
      all:
        - {field: user_name, equals: svc_backup}
        - {field: host, in: [BACKUP01]}
        - {field: ts_us, between: ["2020-09-01T00:00:00Z", "2020-10-01T00:00:00Z"]}
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import cache

import duckdb
import yaml

from .events import BIGINT_COLUMNS, COLUMNS, NO_EXTENSION_FETCH

SUGGEST_VALUES = ("authorized", "suspicious", "malicious")
# Every events column, so a column added later is a rule field too. Left out: the event's ID, its raw fields as JSON,
# the host it was loaded under, which only the app's bookkeeping reads, and case format 3's account key and hash list,
# which the pivots read and which are not rule fields.
NUMBER_FIELDS = BIGINT_COLUMNS
TEXT_FIELDS = set(COLUMNS) - NUMBER_FIELDS - {"event_uid", "extra", "origin_host", "account_key", "hashes"}
DERIVED = {
    "account": "lower(CASE WHEN e.user_domain = '' THEN e.user_name ELSE e.user_domain || '\\' || e.user_name END)",
    "source_host": "ls.source_host",   # the logon's source, resolved through host identity
}
OPERATORS = {"equals", "in", "regex", "between", "collected"}
ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")

MACHINE_ACCOUNTS_RULE = """\
id: machine-accounts-authorized
description: >
  Machine-account network logons between collected hosts are usually routine domain traffic.
  Built in. Delete it if this case needs those logons reviewed one by one.
suggest: authorized
when:
  all:
    - {field: event_code, equals: "4624"}
    - {field: logon_type, equals: "3"}
    - {field: user_name, regex: '\\$$'}
    - {field: source_host, collected: true}
"""
# Hayabusa 4.1.0's rules for these test ShareName as written and never match, so without these built-in rules the 5145
# events they'd flag would go unsuggested. These rules read the message the EvtxECmd parser writes ("Share: \\*\IPC$ |
# Object: svcctl | Access: ..."), and the "() " that events loaded by an earlier version still carry. Raw strings, so
# the backslashes reach the regexes.
REMOTE_EXECUTION_PIPES_RULE = r"""id: remote-execution-pipes
description: >
  A network share access to a named pipe that remote execution uses: the service control manager (svcctl),
  the task scheduler (atsvc), PsExec's service and its -stdin, -stdout, and -stderr pipes, or RemCom.
  Built in. Admin tools use some of these too; delete it if this case's are routine.
suggest: suspicious
when:
  all:
    - {field: event_code, equals: "5145"}
    - {field: message, regex: '(?i)Share: \\\\\*\\IPC\$ (\(\) )?\| Object: (svcctl|atsvc|psexesvc[^ |]*|remcom_[^ |]+|[^ |]+-(stdin|stdout|stderr))( \||$)'}
"""   # noqa: E501  (the rule's text is shown and journaled as written)
# The print spooler's pipe on its own: every client of a print server opens it, so a case can drop this rule and
# keep the one above. Over IPC$ from another host it's also how the PrinterBug and SpoolSample coercion starts.
PRINT_SPOOLER_PIPE_RULE = r"""id: print-spooler-pipe
description: >
  A network share access to the print spooler's named pipe (spoolss), which remote coercion such as PrinterBug
  and SpoolSample uses. Built in. Every client of a print server opens it too; delete it on a print server.
suggest: suspicious
when:
  all:
    - {field: event_code, equals: "5145"}
    - {field: message, regex: '(?i)Share: \\\\\*\\IPC\$ (\(\) )?\| Object: spoolss( \||$)'}
"""
ADMIN_SHARE_WRITES_RULE = r"""id: admin-share-executable-writes
description: >
  A write, over an admin share (C$, ADMIN$, or another drive's $ share), of a file that runs: .exe, .dll, .bat,
  .cmd, .ps1, .vbs, .js, .hta, .scr, or .sys. Copying a tool to another host for lateral movement looks like
  this. Built in. Delete it if this case's deployments do it routinely.
suggest: suspicious
when:
  all:
    - {field: event_code, equals: "5145"}
    - {field: message, regex: '(?i)Share: \\\\\*\\(ADMIN|[A-Z])\$ .*\| Access: [^|]*(WriteData|AppendData)'}
    - {field: file_path, regex: '(?i)\.(exe|dll|bat|cmd|ps1|vbs|js|hta|scr|sys)$'}
"""
BUILTIN_RULES = {"machine-accounts-authorized": MACHINE_ACCOUNTS_RULE,
                 "remote-execution-pipes": REMOTE_EXECUTION_PIPES_RULE,
                 "print-spooler-pipe": PRINT_SPOOLER_PIPE_RULE,
                 "admin-share-executable-writes": ADMIN_SHARE_WRITES_RULE}


class RuleError(ValueError):
    """Raised for a rule that cannot be parsed or compiled."""


@dataclass(frozen=True)
class Rule:
    id: str
    suggest: str
    description: str
    where: str            # SQL condition over events e LEFT JOIN logon_links ls (relations.py)
    params: tuple


def parse(text: str) -> Rule:
    try:
        # Every value as the text written, which BaseLoader keeps: YAML 1.1's types read 0x3e7 as 999, 0400 as 256,
        # and no as false, so a text rule with such a value would match nothing. Numbers, times, and true or false
        # are read as YAML 1.1 types them (_as_before).
        data = yaml.load(text, Loader=yaml.BaseLoader)
    except yaml.YAMLError as exc:
        raise RuleError(f"not valid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise RuleError("a rule is a YAML mapping with id, suggest, and when")
    rule_id = str(data.get("id", ""))
    if not ID_PATTERN.match(rule_id):
        raise RuleError("id must be 1 to 64 letters, digits, dots, dashes, or underscores")
    suggest = data.get("suggest")
    if suggest not in SUGGEST_VALUES:
        raise RuleError(f"suggest must be one of {SUGGEST_VALUES}")
    if "when" not in data:
        raise RuleError("a rule needs 'when'")
    params: list = []
    where = _compile(data["when"], params)
    return Rule(rule_id, suggest, str(data.get("description", "")).strip(), where, tuple(params))


def _compile(node, params: list) -> str:
    if not isinstance(node, dict):
        raise RuleError(f"expected a condition mapping, got {node!r}")
    if set(node) == {"all"} or set(node) == {"any"}:
        joiner, items = (" AND ", node["all"]) if "all" in node else (" OR ", node["any"])
        if not isinstance(items, list) or not items:
            raise RuleError("all and any need a non-empty list of conditions")
        return "(" + joiner.join(_compile(item, params) for item in items) + ")"
    if set(node) == {"not"}:
        return f"(NOT {_compile(node['not'], params)})"
    field_name = node.get("field")
    ops = [k for k in node if k != "field"]
    if len(ops) != 1 or ops[0] not in OPERATORS:
        raise RuleError(f"each condition needs 'field' and one operator from {sorted(OPERATORS)}: {node!r}")
    op, value = ops[0], node[ops[0]]
    if op == "collected":
        collected = _as_before(value)
        if field_name != "source_host" or not isinstance(collected, bool):
            raise RuleError("collected applies only to source_host, with true or false")
        return "(ls.source_host IS NOT NULL AND NOT ls.outside)" if collected else "(ls.source_host IS NOT NULL AND ls.outside)"
    expr, numeric = _field(field_name)
    if op == "between":
        if not numeric or not isinstance(value, list) or len(value) != 2:
            raise RuleError("between applies to ts_us or record_id, with a list of two values")
        params.extend(_rule_number(v, field_name) for v in value)
        return f"({expr} BETWEEN ? AND ?)"
    if op == "regex":
        if numeric:
            raise RuleError("regex applies to text fields")
        try:
            re.compile(str(value))
        except re.error as exc:
            raise RuleError(f"bad regex {value!r}: {exc}") from exc
        if problem := _re2_problem(str(value)):
            raise RuleError(f"bad regex {value!r} for RE2, which runs the rules: {problem}")
        params.append(str(value))
        return f"regexp_matches(COALESCE({expr}, ''), ?)"
    values = value if op == "in" else [value]
    if op == "in" and (not isinstance(value, list) or not value):
        raise RuleError("in needs a non-empty list")
    if numeric:
        params.extend(_rule_number(v, field_name) for v in values)
        return f"({expr} IN ({', '.join('?' * len(values))}))"
    if not all(isinstance(v, str) for v in values):
        raise RuleError(f"{field_name} takes text values: {value!r}")
    params.extend(v.lower() for v in values)
    return f"(lower(COALESCE({expr}, '')) IN ({', '.join('?' * len(values))}))"


@cache
def _re2_problem(pattern: str) -> str:
    """Why RE2, which DuckDB's regexp_matches runs a rule's regex with, can't compile a pattern, or "" when it can.
    Python's re reads lookarounds and backreferences; RE2 has neither. Such a rule fails only as it runs, reported as
    "could not run", and App rebuilds the suggestions in one transaction, which that failure would abort, so parse
    refuses it."""
    with duckdb.connect(config=dict(NO_EXTENSION_FETCH)) as con:
        try:
            con.execute("SELECT regexp_matches('', ?)", [pattern])
        except duckdb.Error as exc:
            return str(exc).removeprefix("Invalid Input Error: ")
    return ""


def _field(name) -> tuple[str, bool]:
    if name in DERIVED:
        return DERIVED[name], False
    if name in TEXT_FIELDS:
        return f"e.{name}", False
    if name in NUMBER_FIELDS:
        return f"e.{name}", True
    raise RuleError(f"unknown field {name!r}; fields: {sorted(TEXT_FIELDS | NUMBER_FIELDS | set(DERIVED))}")


def _as_before(value):
    """A value as YAML 1.1 types it, as safe_load reads it, for the fields that take a number, a time, or true or
    false. A rule journaled earlier keeps its meaning: 0x10 is 16, 010 is 8, and yes is true."""
    if not isinstance(value, str):
        return value
    try:
        return yaml.safe_load(value)
    except (yaml.YAMLError, ValueError):   # ValueError: a number past Python's 4,300-digit limit
        return value


def _rule_number(value, field_name: str) -> int:
    """A ts_us or record_id value: a number, or for ts_us an ISO 8601 time."""
    return _number(_as_before(value), field_name)


def parse_time(value) -> int:
    """An ISO 8601 time (UTC when no zone is given) or epoch microseconds, as epoch microseconds."""
    return _number(value, "ts_us")


def _number(value, field_name: str) -> int:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if isinstance(value, float) and not math.isfinite(value):
            raise RuleError(f"{field_name} needs a finite number: {value!r}")
        return int(value)
    if field_name == "ts_us":
        try:
            dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError as exc:
            raise RuleError(f"ts_us values are epoch microseconds or ISO 8601 times: {value!r}") from exc
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return int(dt.timestamp()) * 1_000_000 + dt.microsecond
    raise RuleError(f"{field_name} needs a number: {value!r}")
