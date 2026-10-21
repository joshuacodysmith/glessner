"""Caveats: what a kind of record does not prove.

The texts live in caveats.json, one per artifact or event type, each with its sources, so the same record always shows
the same text and the app writes none of it. The Event page shows the record's caveat beside the record, and a finding
shows the caveats of its linked events' types. A kind the table doesn't name has none until a row for it is added to
caveats.json."""

from __future__ import annotations

import json
from functools import cache
from pathlib import Path

TABLE_FILE = Path(__file__).with_name("caveats.json")
# The event columns a match reads, which the Findings page's endpoint selects for a finding's events
CAVEAT_COLUMNS = ("artifact", "event_code", "log_channel", "registry_path")


@cache
def table() -> list[dict]:
    """The caveats in the file's order, which is the order a finding lists them in."""
    return json.loads(TABLE_FILE.read_text(encoding="utf-8"))["caveats"]


def fits(match: dict, ev: dict) -> bool:
    """Whether a record fits a row's match: its artifact, and where the row gives them, its event code, its channel, or
    a word in its registry path, compared without case."""
    if str(ev.get("artifact") or "") not in match["artifact"]:
        return False
    if "event_code" in match and str(ev.get("event_code") or "") not in match["event_code"]:
        return False
    if "channel" in match and str(ev.get("log_channel") or "") not in match["channel"]:
        return False
    return "registry_path_has" not in match or match["registry_path_has"] in str(ev.get("registry_path") or "").lower()


def _shown(row: dict) -> dict:
    return {"id": row["id"], "name": row["name"], "text": row["text"], "sources": row["sources"]}


def caveat_for(ev: dict) -> dict | None:
    """The caveat of one record, or None: its id, name, text, and sources."""
    return next((_shown(row) for row in table() if fits(row["match"], ev)), None)


def caveats_for(events: list[dict]) -> list[dict]:
    """The distinct caveats of several records, in the table's order, for a finding's linked events."""
    found = {c["id"] for ev in events if (c := caveat_for(ev))}
    return [_shown(row) for row in table() if row["id"] in found]
