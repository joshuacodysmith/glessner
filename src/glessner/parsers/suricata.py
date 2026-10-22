"""Parses Suricata's EVE JSON: from the app's own Suricata runs on packet captures, and EVE files found in the
evidence.

One event per record. Stats records, Suricata's own counters every few seconds, are left out. A line that holds no JSON
object, such as a last line cut short when Suricata stopped, makes no event, and the run's notes count such lines. The
channel is the record's event_type, such as alert, dns, http, tls, fileinfo, or flow; an alert's event code is its
rule's signature ID.

Times. A record's timestamp is in the sensor's local time with its offset. A flow record's timestamp is only when it was
logged, at the flow's end, a timeout, or shutdown, so a flow is placed at its start. Suricata's default multi-threaded
mode, reading a capture file, logs flows and some protocol records with the capture's first packet time instead: on the
Szechuan capture, 61,863 of 67,858 records. The app runs Suricata in single-thread mode,
which doesn't; for EVE files found in the evidence, a record logged before its own flow began takes the flow's start,
and its details keep the timestamp Suricata wrote.

The message names what the record is about: the rule for an alert, the name asked for a DNS query, the host and URL for
HTTP, the server name for TLS, the file name for a file seen. Every field of the record is kept in the event's details,
with nested objects as dotted names, such as alert.category.
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterator
from pathlib import Path

from ..events import Event, from_us, to_us
from .common import SKIPPED_NOTE, ParseContext, evidence_relative, file_key, flatten, normalize_ip, output_paths

OUTPUT_FILE = "eve.json"
SKIPPED = {"stats"}
LARGE = {"payload", "payload_printable", "packet", "packet_info.linktype"}   # raw bytes; long and rarely read
UNNAMED_PROTOCOLS = {"failed", "unknown"}   # app_proto when Suricata couldn't tell the protocol


def parse_suricata_eve(ctx: ParseContext) -> Iterator[Event]:
    for path in output_paths(ctx, "suricata_eve", OUTPUT_FILE):
        # The app's own run: the capture it read. A file found in the evidence: that file.
        source = evidence_relative(str(path), ctx.evidence_root) if ctx.files else (ctx.inputs[0] if ctx.inputs else "")
        starts = _flow_starts(path)
        seen: Counter[str] = Counter()
        seen_former: Counter[str] = Counter()   # format 1's keys, counted apart: they repeat as the new ones do
        dropped = 0
        for n, rec in _records(path):
            if rec is None:
                dropped += 1
            elif rec.get("event_type") not in SKIPPED:
                key = _numbered(seen, _record_key(rec, starts))
                former = _numbered(seen_former, _record_key(rec, starts, as_written=True)) if ctx.former == 1 else key
                try:
                    event = _event(rec, source, n, starts, key)
                except RecursionError:   # a list nested too deep to write back as JSON text
                    dropped += 1
                    continue
                if former != key:
                    event.former = (source, former)
                yield event
        if dropped:
            name = source if ctx.files else (f"{path.name} for {source}" if source else path.name)
            ctx.notes.append(f"{SKIPPED_NOTE}{dropped:,} {'line' if dropped == 1 else 'lines'} of {name}: not a JSON record, "
                             "or nested too deep to read, such as a last line cut short when Suricata stopped.")


def _numbered(seen: Counter[str], key: str) -> str:
    """The key with a count for a repeat, #2 on, in file order."""
    seen[key] += 1
    return key if seen[key] == 1 else f"{key}#{seen[key]}"


def _record_key(rec: dict, starts: dict[str, tuple[int, str]], as_written: bool = False) -> str:
    """What identifies a record across reruns, so marks stay on it. Neither the line
    number, the flow ID, nor the logged time does: Suricata writes records in a different order each run, flow IDs
    are random per run, and records logged when a flow times out get a slightly different time each run. The flow's
    start does not change, so a record is known by its type, its flow's start (its own timestamp without one), its
    addresses, transaction, rule, and what it's about, with a count for repeats. Checked on the Szechuan capture
    without rules: the same 67,397 keys from two single-thread runs and a multi-threaded one.

    The time is in UTC, by each of its three routes, so a rerun in another zone keeps the IDs. Format 1's keys,
    `as_written`, hold the time as Suricata wrote it, in the zone of the machine that ran it: two runs in different zones
    shared 0 of 1,445 of them."""
    flow = starts.get(str(rec.get("flow_id"))) if rec.get("flow_id") is not None else None
    when = flow[1] if flow else str(rec.get("timestamp", ""))
    if rec.get("event_type") == "flow":
        when = str((rec.get("flow") or {}).get("start", "")) or when
    if not as_written:
        when = _utc_text(when)
    about = ((rec.get("fileinfo") or {}).get("filename") or (rec.get("http") or {}).get("url")
             or (rec.get("tls") or {}).get("sni") or _dns_name(rec.get("dns") or {}) or "")
    parts = (rec.get("event_type"), when, rec.get("src_ip"), rec.get("src_port"), rec.get("dest_ip"),
             rec.get("dest_port"), rec.get("proto"), rec.get("tx_id"), (rec.get("alert") or {}).get("signature_id"), about)
    return "eve|" + "|".join("" if p is None else str(p) for p in parts)


def _utc_text(text: str) -> str:
    """A key's time as the microseconds it names, written in Suricata's own layout at +0000, so a run on a machine set to
    UTC keeps its IDs. Text to_us can't read, or a time before 1971, stays as written."""
    us = to_us(text)
    return text if us is None else from_us(us).strftime("%Y-%m-%dT%H:%M:%S.%f+0000")


def _dns_name(d: dict) -> str:
    queries = d.get("queries") or [d]
    return next((str(q["rrname"]) for q in queries if isinstance(q, dict) and q.get("rrname")), "")


def _records(path: Path) -> Iterator[tuple[int, dict | None]]:
    """Each non-empty line of the file as its number and the JSON object it holds, or None for a line that holds none:
    not JSON, nested too deep to read, or JSON of another kind."""
    with path.open(encoding="utf-8", errors="replace") as f:
        for n, line in enumerate(f, 1):
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except (ValueError, RecursionError):   # not JSON, or nested too deep to read
                rec = None
            yield n, rec if isinstance(rec, dict) else None


def _flow_starts(path: Path) -> dict[str, tuple[int, str]]:
    """Each flow's start, by flow ID, in microseconds and as written. Suricata writes a flow's record after the records
    of its traffic, so this is a first pass over the file."""
    starts = {}
    for _, rec in _records(path):
        if rec is not None and rec.get("event_type") == "flow" and rec.get("flow_id") is not None:
            text = str((rec.get("flow") or {}).get("start", ""))
            start = to_us(text)
            if start is not None:
                starts[str(rec["flow_id"])] = (start, text)
    return starts


def _time(kind: str, rec: dict, starts: dict[str, tuple[int, str]]) -> tuple[int | None, str]:
    """The event's time, and a note when it isn't the record's own timestamp."""
    logged = to_us(str(rec.get("timestamp", "")))
    flow = starts.get(str(rec.get("flow_id"))) if rec.get("flow_id") is not None else None
    start = flow[0] if flow else None
    if kind == "flow":
        return (start, "") if start is not None else (logged, "")
    if start is not None and logged is not None and logged < start:
        return start, "logged before its flow began; placed at the flow's start"
    return logged, ""


def _event(rec: dict, source: str, n: int, starts: dict[str, tuple[int, str]] | None = None,
           key: str = "") -> Event:
    kind = str(rec.get("event_type", ""))
    flat = flatten(rec)
    alert = rec.get("alert") or {}
    file_name = str((rec.get("fileinfo") or {}).get("filename", ""))
    user = str((rec.get("krb5") or {}).get("cname", "") or (rec.get("smb") or {}).get("ntlmssp", {}).get("user", ""))
    ts, note = _time(kind, rec, starts or {})
    if note:
        flat["time_note"] = note
    flat["eve_line"] = str(n)
    return Event(
        ts_us=ts, ts_desc=("Suricata flow started" if kind == "flow" else f"Suricata {kind}") if kind else "Suricata record",
        artifact="suricata", source_file=source, source_record=key or _record_key(rec, starts or {}),
        message=_message(kind, rec),
        event_code=str(alert.get("signature_id", "")), log_channel=kind, event_provider="Suricata",
        # Addresses in normalize_ip's form, as event logs store them, so an IPv6 address joins across sources; Suricata's
        # own text stays in extra as src_ip and dest_ip, and in the record key, so the ID doesn't depend on the normalized form
        source_ip=normalize_ip(str(rec.get("src_ip", ""))), source_port=str(rec.get("src_port", "")),
        dest_ip=normalize_ip(str(rec.get("dest_ip", ""))), dest_port=str(rec.get("dest_port", "")),
        user_name=user, file_path=file_name, file_key=file_key(file_name) if file_name else "",
        extra={k: v for k, v in flat.items() if v != "" and k not in LARGE} or None)


def _message(kind: str, rec: dict) -> str:
    ends = f"{rec.get('src_ip', '')}{':' + str(rec['src_port']) if rec.get('src_port') else ''} -> " \
           f"{rec.get('dest_ip', '')}{':' + str(rec['dest_port']) if rec.get('dest_port') else ''}"
    app = str(rec.get("app_proto") or "")
    # "failed" means Suricata couldn't name the protocol; as a bare word it read as if the attack failed.
    proto = str(rec.get("proto") or "") if not app or app in UNNAMED_PROTOCOLS else app
    if kind == "alert":
        a = rec.get("alert") or {}
        return f"Alert: {a.get('signature', '')} ({a.get('category', '')}, severity {a.get('severity', '')}) {proto} {ends}"
    if kind == "dns":
        d = rec.get("dns") or {}
        queries = d.get("queries") or [d]
        names = ", ".join(str(q.get("rrname", "")) for q in queries if isinstance(q, dict) and q.get("rrname"))
        rtype = next((q.get("rrtype") for q in queries if isinstance(q, dict) and q.get("rrtype")), "")
        answers = d.get("answers") or []
        data = ", ".join(str(a.get("rdata", "")) for a in answers if isinstance(a, dict) and a.get("rdata"))
        return f"DNS {d.get('type', '')} {names} {rtype}{' -> ' + data if data else ''} ({ends})"
    if kind == "http":
        h = rec.get("http") or {}
        return f"HTTP {h.get('http_method', '')} {h.get('hostname', '')}{h.get('url', '')} {h.get('status', '')} ({ends})"
    if kind == "tls":
        t = rec.get("tls") or {}
        return f"TLS {t.get('sni', '')} {t.get('version', '')} ({ends})"
    if kind == "fileinfo":
        fi = rec.get("fileinfo") or {}
        return (f"File seen: {fi.get('filename', '')} ({fi.get('magic', '') or 'type unknown'}, "
                f"{fi.get('size', '?')} bytes) {ends}")
    if kind == "flow":
        fl = rec.get("flow") or {}
        return (f"Flow {proto} {ends}, {fl.get('bytes_toserver', 0)} bytes to server, "
                f"{fl.get('bytes_toclient', 0)} to client")
    return f"{kind} {proto} {ends}".strip()
