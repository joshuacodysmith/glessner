"""What the pivots that match a name read from each source: a service's, a task's, a connection's flow, and an alert's
rule. An event holds these in its data, not in a column of its own, so each source is read where it
keeps the name, and a pivot's matching is one narrow condition per source rather than one OR over all of them: that
OR stops DuckDB pushing the filter into the scan, and at 10.8 million events it took 768 to 830 ms where the narrow
conditions took 29 ms when measured. A file's name is in the file path, the file key, or the
process, and is matched in the same way.

Each `*_branches` returns (SQL, parameters) pairs over the events table as `e`. The branches of one pivot never match
the same event twice, since each names its own tool, event code, or artifact, so a count is the sum of their counts and
a list is their OR (queries.py).
"""

from __future__ import annotations

import json
import re

import duckdb

from .events import sql_literal

SERVICE_STATES = ("7000", "7023", "7030", "7031", "7034", "7036")   # the service is param1 of each
SERVICE_KEY_PATH = re.compile(r"\\Services\\([^\\]+)", re.IGNORECASE)   # Sysmon 12 to 14's key, ...\Services\<name>\...
RECMD_SERVICE_NAME = re.compile(r"^Name: (.*?) Desc:")                    # RECmd's Services plugin, in the row's data
TASK_PATH = re.compile(r"^Path: (.*?), Command:")                        # RECmd's TaskCache plugin, in the row's data
TASK_SCHEDULER = "Microsoft-Windows-TaskScheduler/"
TASKCACHE = "Scheduled Tasks (TaskCache):"
SERVICES_PREFIX = "Services:"
SYSMON = "Microsoft-Windows-Sysmon"
PATH_SEPARATORS = re.compile(r"[\\/]")   # a capture's URL path, /coreupdater.exe, ends in a name as a Windows path does


def extra_of(ev: dict) -> dict:
    """An event's own data, as a dict; empty when it has none or it isn't an object."""
    try:
        data = json.loads(ev.get("extra") or "null")
    except (TypeError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _json(name: str) -> str:
    """The event's data field `name` as text, quoted into the path as search.py quotes a field's name."""
    return f"json_extract_string(NULLIF(e.extra, ''), {sql_literal('$.\"' + name + '\"')})"


def _text(value) -> str:
    return value.strip() if isinstance(value, str) else ""


def _distinct(names) -> list[str]:
    seen: dict[str, str] = {}
    for n in names:
        if n and n.lower() not in seen:
            seen[n.lower()] = n
    return list(seen.values())


def autoruns_display(description: str) -> str:
    """The display name at the start of an Autoruns service's description, "Windows Audio: Manages audio ..."."""
    return description.split(": ", 1)[0].strip()


# ---------- service names ----------

def service_names(ev: dict) -> list[str]:
    """The names an event gives a service: its key name, its display name, or whichever the source writes. 7045 and the
    state changes write the display name, 7040 also the key name, 4697 and RECmd, Autoruns, and Sysmon the key name."""
    x = extra_of(ev)
    code, channel, artifact = ev.get("event_code", ""), ev.get("log_channel", ""), ev.get("artifact", "")
    names: list[str] = []
    if artifact == "evtx" and channel == "System":
        if code in SERVICE_STATES:
            names = [_text(x.get("param1"))]
        elif code == "7009":
            names = [_text(x.get("param2"))]
        elif code == "7040":
            names = [_text(x.get("param1")), _text(x.get("param4"))]
        elif code == "7045":
            names = [_text(x.get("ServiceName"))]
    elif artifact == "evtx" and code == "4697" and channel == "Security":
        names = [_text(x.get("ServiceName"))]
    elif artifact == "evtx" and ev.get("event_provider") == SYSMON and code in ("12", "13", "14"):
        m = SERVICE_KEY_PATH.search(ev.get("registry_path") or "")
        names = [m.group(1)] if m else []
    elif artifact == "autoruns" and channel in ("Services", "Drivers"):
        names = [_text(x.get("Entry")), autoruns_display(_text(x.get("Description")))]
    elif artifact == "registry" and (ev.get("message") or "").startswith(SERVICES_PREFIX):
        m = RECMD_SERVICE_NAME.match(_text(x.get("ValueData")))
        names = [m.group(1)] if m else []
    return _distinct(names)


def service_aliases(con: duckdb.DuckDBPyConnection, names: list[str]) -> list[str]:
    """`names` and the other name each is known by on any host, from the table service_aliases (analysis.py), in lower
    case. A case opened before the table existed has none."""
    wanted = _distinct(n.lower() for n in names)
    if not wanted:
        return []
    marks = ", ".join("?" for _ in wanted)
    try:
        rows = con.execute(f"SELECT key_name, display_name FROM service_aliases WHERE key_name IN ({marks}) "
                           f"OR display_name IN ({marks})", wanted + wanted).fetchall()
    except duckdb.CatalogException:
        rows = []
    return _distinct([*wanted, *(n for row in rows for n in row)])


def service_branches(names: list[str]) -> list[tuple[str, list]]:
    """One narrow condition per source that writes a service's name, matching any of `names` (lower case)."""
    marks = ", ".join("?" for _ in names)
    param = lambda field: f"lower({_json(field)}) IN ({marks})"
    return [
        ("e.event_code = '7045' AND e.log_channel = 'System' AND " + param("ServiceName"), list(names)),
        ("e.event_code = '4697' AND e.log_channel = 'Security' AND " + param("ServiceName"), list(names)),
        ("e.log_channel = 'System' AND e.event_code IN ('7000', '7023', '7030', '7031', '7034', '7036') AND "
         + param("param1"), list(names)),
        ("e.log_channel = 'System' AND e.event_code = '7009' AND " + param("param2"), list(names)),
        (f"e.log_channel = 'System' AND e.event_code = '7040' AND ({param('param1')} OR {param('param4')})",
         [*names, *names]),
        (f"e.event_provider = '{SYSMON}' AND e.event_code IN ('12', '13', '14') AND e.registry_path LIKE '%\\Services\\%'"
         f" AND lower(regexp_extract(e.registry_path, '(?i)\\\\Services\\\\([^\\\\]+)', 1)) IN ({marks})", list(names)),
        (f"e.artifact = 'autoruns' AND e.log_channel IN ('Services', 'Drivers') AND ({param('Entry')} OR "
         f"lower(split_part({_json('Description')}, ': ', 1)) IN ({marks}))", [*names, *names]),
        (f"e.artifact = 'registry' AND starts_with(e.message, '{SERVICES_PREFIX}') AND "
         f"lower(regexp_extract({_json('ValueData')}, '^Name: (.*?) Desc:', 1)) IN ({marks})", list(names)),
    ]


# ---------- task names ----------

def task_names(ev: dict) -> list[str]:
    """The task an event names, by its path and name, as every source writes it: \\Microsoft\\Windows\\... ."""
    x = extra_of(ev)
    code, channel, artifact = ev.get("event_code", ""), ev.get("log_channel", ""), ev.get("artifact", "")
    scheduled = channel.startswith(TASK_SCHEDULER) or (channel == "Security" and code in ("4698", "4699", "4702"))
    if artifact == "evtx" and scheduled:
        return _distinct([_text(x.get("TaskName"))])
    if artifact == "autoruns" and channel == "Tasks":
        return _distinct([_text(x.get("Entry"))])
    if artifact == "registry" and (ev.get("message") or "").startswith(TASKCACHE):
        m = TASK_PATH.match(_text(x.get("ValueData3")))
        return _distinct([m.group(1)] if m else [])
    return []


def task_branches(name: str) -> list[tuple[str, list]]:
    low = name.lower()
    return [
        ("e.log_channel = 'Security' AND e.event_code IN ('4698', '4699', '4702') AND "
         f"lower({_json('TaskName')}) = ?", [low]),
        (f"starts_with(e.log_channel, '{TASK_SCHEDULER}') AND lower({_json('TaskName')}) = ?", [low]),
        (f"e.artifact = 'autoruns' AND e.log_channel = 'Tasks' AND lower({_json('Entry')}) = ?", [low]),
        (f"e.artifact = 'registry' AND starts_with(e.message, '{TASKCACHE}') AND "
         f"lower(regexp_extract({_json('ValueData3')}, '^Path: (.*?), Command:', 1)) = ?", [low]),
    ]


# ---------- flows ----------

def flow_id(ev: dict) -> tuple[str, str]:
    """The connection an event belongs to, as (artifact, id): Suricata's flow_id, or the uid of a Zeek record; ("", "")
    for any other event."""
    x = extra_of(ev)
    if ev.get("artifact") == "suricata":
        return "suricata", _text(x.get("flow_id"))
    if ev.get("artifact") == "zeek":
        return "zeek", _text(x.get("uid"))
    return "", ""


def flow_branches(artifact: str, ident: str) -> list[tuple[str, list]]:
    field = "flow_id" if artifact == "suricata" else "uid"
    return [(f"e.artifact = '{artifact}' AND {_json(field)} = ?", [ident])]


# ---------- rules and signatures ----------

def rule_of(ev: dict, hit_titles: list[str]) -> tuple[str, str, str]:
    """What an alert or a Hayabusa hit is named by, as (source, key, words): ("suricata", signature ID, the signature),
    ("ids_alert", the rule's ID, the signature), or ("hayabusa", the rule's title, the title) for the most severe hit
    an event has. ("", "", "") for none."""
    x = extra_of(ev)
    if ev.get("artifact") == "suricata" and ev.get("log_channel") == "alert" and ev.get("event_code"):
        return "suricata", ev["event_code"], _text(x.get("alert.signature")) or ev["event_code"]
    if ev.get("artifact") == "ids_alert" and ev.get("event_code"):
        return "ids_alert", ev["event_code"], _text(x.get("signature")) or ev["event_code"]
    if hit_titles:
        return "hayabusa", hit_titles[0], hit_titles[0]
    return "", "", ""


def rule_branches(source: str, key: str) -> list[tuple[str, list]]:
    if source == "suricata":
        return [("e.artifact = 'suricata' AND e.log_channel = 'alert' AND e.event_code = ?", [key])]
    if source == "ids_alert":
        return [("e.artifact = 'ids_alert' AND e.event_code = ?", [key])]
    # Hayabusa's rows aren't on the timeline: the events its rule hit are, through the hits table (analysis.py)
    return [("e.event_uid IN (SELECT event_uid FROM hits WHERE list_contains(titles, ?))", [key])]


def rule_counts(source: str, key: str) -> list[tuple[str, list]] | None:
    """A faster count for a Hayabusa rule, from the hits table alone, which holds a row per event it hit and whether the
    event is on the timeline: reading the events to match their IDs took 200 ms at 11 million. None for the others,
    whose conditions read a column."""
    if source in ("suricata", "ids_alert"):
        return None
    return [("SELECT count(*) FROM hits WHERE timed AND list_contains(titles, ?)", [key])]


# ---------- file names ----------

def file_name_of(ev: dict) -> str:
    """The name of the file an event is about: the last part of its path, or of its process's when it names no file, as
    Same file's key is taken (pivots._value_of). A bare name, such as SRUM's, is the name; "" for none."""
    return PATH_SEPARATORS.split(ev.get("file_path") or ev.get("process_executable") or "")[-1]


def file_name_branches(name: str) -> list[tuple[str, list]]:
    """The conditions that an event's file name is `name` in any folder and without letter case, one per place it is read
    from, which never match an event twice. An event with a file key (parsers.common.file_key: lower case, backslashes,
    the path of its file or else its process) is matched on the key's ending, which DuckDB tests on the column's
    dictionary; the key of a capture's URL path ends in its name too. An event without a key is matched through the table
    keyless_names (analysis.py): its path's name, or its process's when it has no path, as a bare name such as SRUM's is.
    Scanning for those events took 28 to 37 ms a branch at 10.9 million events, though almost none match."""
    low = name.lower()
    return [
        ("e.file_key <> '' AND ends_with(e.file_key, ?)", ["\\" + low]),
        ("e.event_uid IN (SELECT event_uid FROM keyless_names WHERE name = ?)", [low]),
    ]
