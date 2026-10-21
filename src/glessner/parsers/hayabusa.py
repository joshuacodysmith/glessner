"""Parses Hayabusa dfir-timeline CSV written with the verbose profile and full names (-p verbose -b).

Each row is one rule match on one event record. record_id plus the host the file was loaded under, the channel, and
the source file lets a later step join a match to its EvtxECmd event (analysis.hit_join). The recorded computer is
not part of the join.
"""

from __future__ import annotations

from collections.abc import Iterator

from ..events import Event, to_us
from .common import ParseContext, evidence_relative, is_digits, output_paths, read_csv_rows

OUTPUT_FILE = "hayabusa.csv"
EXTRA_COLUMNS = ("Details", "ExtraFieldInfo", "MitreTactics", "MitreTags", "OtherTags", "RuleFile", "RuleID")


def parse_hayabusa(ctx: ParseContext) -> Iterator[Event]:
    for row in (row for path in output_paths(ctx, "hayabusa", OUTPUT_FILE) for row in read_csv_rows(path)):
        record = row.get("RecordID", "")
        title, level = row.get("RuleTitle", ""), row.get("Level", "")
        details = row.get("Details", "")
        yield Event(
            ts_us=to_us(row.get("Timestamp")),
            ts_desc="Event Recorded",
            artifact="hayabusa",
            source_file=evidence_relative(row.get("EvtxFile", ""), ctx.evidence_root),
            source_record=f"{record}:{row.get('RuleID', '')}",
            record_id=int(record) if is_digits(record) else None,
            message=f"{title} [{level}] {details}".strip(),
            host_name_recorded=row.get("Computer", ""),
            event_code=row.get("EventID", ""),
            log_channel=row.get("Channel", ""),
            rule_title=title,
            rule_level=level,
            extra={k: row[k] for k in EXTRA_COLUMNS if row.get(k)},
        )
