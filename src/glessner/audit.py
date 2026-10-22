"""The audit trail: the journal in plain words, with undo for accidents.

The journal is append-only, so an undo is a new entry that reverses an earlier one, recorded as a correction of an
accident; the original stays, shown as undone. An undo reverses only what nothing later changed: an event marked again
after the entry keeps its later mark, and the confirmation says how many such events there are. Notes aren't undone;
they're retracted, and stay on record.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path

from .export import _md, _tick, _time
from .intake import matched_text, unlisted_text
from .journal import (
    DAMAGED,
    FINDING_FIELDS,
    REKEYED,
    REPLAY_ERRORS,
    SYSTEM,
    UNDOABLE,
    Check,
    State,
    _apply,
    check,
    entries,
)
from .tags import tag_label
from .version import build_id

KINDS = {"mark": "Marks", "tag": "Tags", "tag_suggestion": "Tags", "note": "Notes", "note_retract": "Notes",
         "suggestion_decision": "Suggestions", "host_role": "Hosts", "host_identity": "Hosts", "host_offset": "Hosts",
         "rule_add": "Rules", "rule_change": "Rules", "rule_remove": "Rules", "case_setting": "Settings",
         "undo": "Corrections", "host_split": "Hosts", "case_open": "Builds", "case_upgrade": "Builds",
         # The app's own records of the chain and the analyst's follow-ups, findings, and files
         "followup": "Follow-up", "finding": "Findings", "file_written": "Files", "case_created": "Builds",
         "case_yaml": "Settings", "journal_recovered": "Integrity", "chain_break": "Integrity"}
# Where a change the trail doesn't undo can be made instead: a finding changes both ways on the Findings page
PANEL = {"Hosts": "hosts", "Rules": "rules", "Findings": "findings"}
MARK_WORD = {"malicious": "Malicious", "suspicious": "Suspicious", "authorized": "Authorized", "unreviewed": "Unreviewed"}
FILE_WORD = {"timeline": "timeline", "findings_summary": "findings summary", "report": "report",
             "audit_trail": "audit trail", "indicators": "indicators"}
SCOPE_WORD = {"all": "all events", "marked": "marked events", "flagged": "malicious and suspicious events"}


def short(head: str) -> str:
    """A head or file hash as the page shows it: the first 8 and the last 4 characters."""
    return f"{head[:8]}...{head[-4:]}" if isinstance(head, str) and len(head) > 12 else str(head or "")


NAME_LIMIT = 100   # about where the trail cuts an event's name
SEPARATOR = re.compile(r"[\s|,;]")


def cut_name(name: str, limit: int = NAME_LIMIT) -> str:
    """An event's name cut for the page at the last space or separator before `limit` characters, never inside a word
    or an address, and marked with "…"; a short name is whole. The name
    "network 2023883: ET EXPLOIT_KIT ... | 192.185.21.183:80 -> 192.168.122.52:49200 | HTTP GET st.domandvilma.com/..."
    is cut before the address or after it, since an address or a URL has no separator inside it. A single run longer
    than the limit is cut at the limit, since there is no boundary to cut at."""
    if len(name) <= limit:
        return name
    cuts = [m.start() for m in SEPARATOR.finditer(name, 0, limit + 1)]
    at = cuts[-1] if cuts and cuts[-1] >= limit // 2 else limit
    return name[:at].rstrip(" |,;") + " …"


class AuditError(ValueError):
    """An undo or retraction the trail can't do, with a message for the analyst."""


def read_entries(path: Path) -> list[dict]:
    """The journal's entries in file order, each read through the case format upgrades' rekeys that follow it, so the
    trail, its filter by event, its event lists, and undo see the events' current IDs (journal.translate). A
    translated entry names the rekeys in journal.REKEYED. Read by the reader every other reader shares, which
    parses a chained line strictly and stops at the last LF."""
    return entries(path)


def read_checked(path: Path) -> Check:
    """The journal's entries as read_entries gives them, with the full check of the read that gave them: its head and
    its breaks, for the trail, undo, and the trail's export."""
    found = check(path, keep=True)
    found.entries = mark_unreadable(found.entries)
    return found


UNREADABLE = "the trail can't read it: "   # starts the DAMAGED text of an entry the journal applies but the trail can't read


def unreadable(entry: dict, lookup: dict) -> str:
    """Why the trail can't read an entry that _apply took, or "": the readers it runs on every entry are tried on it,
    its words, what it touched, the events it names, and the numbers an undo or a retraction is found by. A changed line
    can hold a payload the state takes and these don't, such as a mark whose note is null or an undo with no
    `undoes`."""
    try:
        describe(entry, {}, lookup)
        touches(entry)
        entry_targets(entry)
        action = entry.get("action")
        if action == "undo" or (action == "host_split" and entry.get("op") == "undo"):
            numbers = entry["undoes"] if action == "host_split" else [entry["undoes"]]
            if not all(isinstance(n, int) for n in numbers):
                raise ValueError("undoes is not an entry number")
        elif action == "note_retract" and not (isinstance(entry["note_seq"], int) and isinstance(entry["target"], str)):
            raise ValueError("note_seq is not an entry number")
    except REPLAY_ERRORS as exc:
        return f"{UNREADABLE}{type(exc).__name__}: {exc}"
    return ""


def mark_unreadable(entries: list[dict]) -> list[dict]:
    """The entries with each that `unreadable` refuses marked DAMAGED, as check(keep=True) marks one _apply refuses, so
    every reader of the trail leaves its words unread and undo can't undo it. Undo still counts what it applied
    (applied)."""
    lookup = lookups(entries)
    return [e if e.get(DAMAGED) or not (why := unreadable(e, lookup)) else {**e, DAMAGED: why} for e in entries]


def applied(entry: dict) -> bool:
    """Whether the journal's state holds an entry: any but one it left out, which check(keep=True) marks. One the trail
    can't read counts, since the state took it as written, so undo plans from what it did."""
    why = entry.get(DAMAGED)
    return not why or str(why).startswith(UNREADABLE)


def state_before(entries: list[dict], seq: int) -> State:
    """The analysis state just before entry `seq`, by replaying the entries before it. An entry the journal's replay
    can't apply, which check(keep=True) marks, or which fails only against the state before it, is left out and the
    state built again without it, as the journal's own is."""
    skip: set[int] = set()
    while True:
        state, failed = State(), None
        for i, entry in enumerate(entries):
            if i in skip or not applied(entry):   # before the comparison: a damaged line's seq may not be a number
                continue
            if entry["seq"] >= seq:
                break
            try:
                _apply(state, entry)
            except REPLAY_ERRORS:
                failed = i
                break
        if failed is None:
            return state
        skip.add(failed)


def touches(entry: dict) -> set[tuple[str, str, str]]:
    """What an entry changed, as (aspect, event, key): a mark, a tag, a suggestion decision, or a tag suggestion."""
    action = entry.get("action")
    if not applied(entry):
        return set()
    if action == "undo":
        return set().union(*(touches(c) for c in entry["changes"]))
    targets = entry.get("targets") or []
    if action == "mark":
        return {("mark", t, "") for t in targets}
    if action == "tag":
        return {("tag", t, k) for t in targets for k in (entry.get("add") or []) + (entry.get("remove") or [])}
    if action == "suggestion_decision":
        return {("decision", t, entry["source"]) for t in targets}
    if action == "tag_suggestion":
        return {("tag_suggestion", t, k) for t in targets for k in entry["tags"]}
    if action == "followup":
        return {("followup", t, "") for t in targets}
    return set()


def undone_by(entries: list[dict]) -> dict[int, int]:
    """Entry number -> the entry that undid it: an undo of an accident, or Undo split on the Hosts panel."""
    # An undo the trail can't read was applied all the same; it counts when the entries it names are numbers
    entries = [e for e in entries if applied(e)]
    done = {e["undoes"]: e["seq"] for e in entries if e.get("action") == "undo" and isinstance(e.get("undoes"), int)}
    for e in entries:
        if e.get("action") == "host_split" and e.get("op") == "undo" and isinstance(e.get("undoes"), list):
            done.update(dict.fromkeys((n for n in e["undoes"] if isinstance(n, int)), e["seq"]))
    return done


def _split_hint(entry: dict) -> str:
    """Where to change a split, a keep, or an undo of a split instead: each is made again on the Hosts panel."""
    host = entry.get("host", "the host")
    if entry.get("op") == "split":
        return f" Undo a split with Undo split on the Hosts panel, on {host}'s line."
    again = "after all" if entry.get("op") == "keep" else "again"
    return f" To split {host} {again}, use Split {host} by recorded computer on the Hosts panel."


def plan_undo(entries: list[dict], seq: int) -> dict:
    """The changes that would reverse entry `seq`, and the events left alone because something later changed them."""
    entry = next((e for e in entries if e["seq"] == seq), None)
    if entry is None:
        raise AuditError(f"There's no entry #{seq}.")
    if why := entry.get(DAMAGED):
        raise AuditError(f"Entry #{seq} can't be undone: its stored payload can't be "
                         + ("read here." if str(why).startswith(UNREADABLE) else "replayed, so it changed nothing."))
    if entry["action"] not in UNDOABLE:
        raise AuditError(f"Entry #{seq} can't be undone here." +
                         (" Retract a note instead." if entry["action"] == "note" else
                          _split_hint(entry) if entry["action"] == "host_split" else
                          " Change the finding on the Findings page, which changes it either way."
                          if entry["action"] == "finding" else ""))
    done = undone_by(entries)
    if seq in done:
        raise AuditError(f"Entry #{seq} was already undone by #{done[seq]}.")
    before = state_before(entries, seq)
    later = set()
    for e in entries:
        if applied(e) and e["seq"] > seq:
            try:
                later |= touches(e)
            except REPLAY_ERRORS as exc:   # applied, but what it changed can't be read, so no event is known to be free
                raise AuditError(f"Entry #{seq} can't be undone: entry #{e['seq']}, after it, has a stored payload that "
                                 "can't be read here, so what it changed since can't be told.") from exc
    groups: dict[tuple, list[str]] = defaultdict(list)
    changed, kept = set(), set()
    action, targets = entry["action"], entry["targets"]
    if action == "mark":
        for t in targets:
            if ("mark", t, "") in later:
                kept.add(t)
                continue
            prev = before.marks.get(t)
            groups[(prev.value, prev.note) if prev else ("unreviewed", "")].append(t)
        changes = [{"action": "mark", "targets": ts, "value": v, "note": n} for (v, n), ts in groups.items()]
    elif action == "tag":
        for t in targets:
            had = before.tags.get(t, {})
            free = lambda k, t=t: ("tag", t, k) not in later
            remove = tuple(k for k in entry.get("add") or [] if free(k) and k not in had)   # added by this entry
            add = tuple(k for k in entry.get("remove") or [] if free(k) and k in had)        # removed by this entry
            if remove or add:
                groups[(remove, add)].append(t)
            elif not all(free(k) for k in (entry.get("add") or []) + (entry.get("remove") or [])):
                kept.add(t)
        changes = [{"action": "tag", "targets": ts, **({"add": list(a)} if a else {}), **({"remove": list(r)} if r else {})}
                   for (r, a), ts in groups.items()]
    elif action == "suggestion_decision":
        source, back = entry["source"], "restored" if entry["decision"] == "rejected" else "rejected"
        was = {t for t, s in before.rejected if s == source}
        for t in targets:
            if ("decision", t, source) in later:
                kept.add(t)
            elif (t in was) == (back == "rejected"):   # only where this entry changed the decision
                # Undoing a restore rejects again with the note each event's earlier rejection carried, so the events
                # go by that note, as marks go by value and note
                note = before.decision_notes.get((t, source), {}).get("text", "") if back == "rejected" else ""
                groups[(note,)].append(t)
        changes = [{"action": "suggestion_decision", "targets": ts, "source": source, "decision": back,
                    **({"note": note} if note else {})} for (note,), ts in groups.items()]
    elif action == "followup":
        for t in targets:
            if ("followup", t, "") in later:
                kept.add(t)
                continue
            groups[(t in before.followed,)].append(t)
        changes = [{"action": "followup", "targets": ts, "done": ticked} for (ticked,), ts in groups.items()]
    else:   # tag_suggestion
        back = "restored" if entry["decision"] == "dismissed" else "dismissed"
        for t in targets:
            keys = tuple(k for k in entry["tags"] if ("tag_suggestion", t, k) not in later
                         and ((t, k) in before.dismissed_tags) == (back == "dismissed"))
            if keys:
                groups[keys].append(t)
            else:
                kept.add(t)
        changes = [{"action": "tag_suggestion", "targets": ts, "tags": list(keys), "decision": back}
                   for keys, ts in groups.items()]
    for c in changes:
        changed.update(c["targets"])
    return {"entry": entry, "changes": changes, "changed": sorted(changed), "kept": sorted(kept - changed)}


def lookups(entries: list[dict]) -> dict:
    """What describe looks up across entries: each finding's title, by the number of its add, as its latest edit left
    it; and for each case_yaml entry, the record of case.yaml before it, as (its entry's number, the settings it
    names, and whether it names every setting: case_created names four."""
    titles: dict[int, str] = {}
    yaml: dict[int, tuple[int, dict, bool]] = {}
    last = None
    for e in entries:
        action = e.get("action")
        if e.get(DAMAGED):
            continue
        if action == "finding" and isinstance(e.get("title"), str):
            titles[e["seq"] if e.get("op") == "add" else e.get("finding")] = e["title"]
        elif action == "case_created":
            last = (e["seq"], {k: e.get(k) for k in ("name", "created_utc", "analyst", "evidence_path")}, False)
        elif action == "case_yaml":
            if last is not None:
                yaml[e["seq"]] = last
            last = (e["seq"], e.get("settings") or {}, True)
    return {"titles": titles, "yaml": yaml}


def describe(entry: dict, events: dict[str, str] | None = None, lookup: dict | None = None) -> str:
    """One entry in plain words, and when the analyst confirmed it first what the confirm counted and how many of
    those it skipped. `events` names single events, as 'host event-code message'; `lookup` is what lookups gives for the
    whole journal, for a finding's title and case.yaml's changes."""
    text = _describe(entry, events, lookup)
    consent = entry.get("confirmed")
    if not isinstance(consent, dict) or entry.get("action") == "host_role" or entry.get(DAMAGED):   # a role's is its own
        return text
    skipped = consent.get("skipped") or 0
    return text + (f" (confirmed: {consent.get('count', 0):,} counted"
                   f"{f', {skipped:,} skipped as decided meanwhile' if skipped else ''})")


def _describe(entry: dict, events: dict[str, str] | None, lookup: dict | None) -> str:
    events = events or {}
    action = entry.get("action")
    if why := entry.get(DAMAGED):   # check(keep=True) marks an entry replay can't apply
        if str(why).startswith(UNREADABLE):   # the state applies it, as written
            return (f"A {action} entry whose stored payload the trail can't read. The journal applies it as written; "
                    "its journal line probably changed after it was written")
        return (f"A {action} entry whose stored payload can't be replayed. It applies nothing; its journal line "
                "probably changed after it was written")
    targets = entry.get("targets") or []
    n = len(targets)
    what = (events.get(targets[0]) or "1 event") if n == 1 else f"{n:,} events"
    if action in D16_WORDS:
        return D16_WORDS[action](entry, what, lookup or {})
    if action == "mark":
        word = MARK_WORD.get(entry["value"], entry["value"])
        note = entry.get("note", "")
        accepted = note.startswith("Accepted suggestion from ")
        text = f"Set {what} back to Unreviewed" if entry["value"] == "unreviewed" else f"Marked {what} {word}"
        if accepted:   # the analyst's own note, if any, follows the source after ": "
            source, _, note = note.removeprefix("Accepted suggestion from ").partition(": ")
            text += f" (accepted {source} suggestions)"
        if note:
            text += f'. Note: "{note}"'
        return text + (" (chosen by a filter)" if entry.get("filter") else "")
    if action == "tag":
        add, remove = entry.get("add") or [], entry.get("remove") or []
        parts = ([f"Tagged {what}: {', '.join(tag_label(k) for k in add)}"] if add else []) + \
                ([f"Removed tags from {what}: {', '.join(tag_label(k) for k in remove)}"] if remove else [])
        return "; ".join(parts) + (" (accepted from Hayabusa)" if entry.get("via") == "hayabusa" else "")
    if action == "tag_suggestion":
        verb = "Dismissed" if entry["decision"] == "dismissed" else "Restored"
        return f"{verb} suggested tags on {what}: {', '.join(tag_label(k) for k in entry['tags'])}"
    if action == "suggestion_decision":
        verb = "Rejected" if entry["decision"] == "rejected" else "Restored"
        note = str(entry.get("note") or "").strip()   # a Reject's note
        return f"{verb} the {entry['source']} suggestion on {what}" + (f'. Note: "{note}"' if note else "")
    if action == "note":
        return f'Note on {events.get(entry["target"]) or "an event"}: "{entry["text"]}"'
    if action == "note_retract":
        return f"Retracted the note #{entry['note_seq']} on {events.get(entry['target']) or 'an event'}"
    if action == "host_role":
        return (f"Set {entry['host']}'s role to {entry.get('role') or 'the guess'}"
                + (" (confirmed)" if entry.get("confirmed") else ""))
    if action == "host_identity":
        op = entry["op"].replace("_", " ")
        return f"{op[0].upper()}{op[1:]} {entry.get('value', '')} on {entry['host']}"
    if action == "host_offset":
        text = f"Set {entry['host']}'s clock offset to {float(entry.get('seconds', 0)):+g} s"
        if entry.get("align") == "capture":   # the Case panel's switch records why
            return f"{text} to align it with the capture ({entry.get('reference', '')}), {entry.get('basis', '')}"
        return text + (", back to its times as recorded" if entry.get("align") == "recorded" else "")
    if action == "host_split":
        if entry["op"] == "split":
            lanes = sorted(set(entry["routes"].values()))
            shown = ", ".join(lanes[:3]) + (f", and {len(lanes) - 3} more" if len(lanes) > 3 else "")
            return (f"Split {entry['host']} into {len(lanes)} new host{'s' if len(lanes) != 1 else ''} "
                    f"by recorded computer: {shown}")
        if entry["op"] == "undo":
            at = " and ".join(f"#{s}" for s in entry["undoes"])
            return f"Undid the split{'s' if len(entry['undoes']) > 1 else ''} of {entry['host']} at {at}"
        n = len(entry["computers"])
        return f"Kept {entry['host']} as one host ({n} computer name{'s' if n != 1 else ''})"
    if action in ("rule_add", "rule_change", "rule_remove"):
        verb = {"rule_add": "Added", "rule_change": "Changed", "rule_remove": "Removed"}[action]
        return f"{verb} the rule {entry['id']}" + (" (built in)" if entry.get("builtin") else "")
    if action == "case_setting":
        value = entry.get("value")
        if entry["name"] == "closed" and isinstance(value, dict) and "hash_check" in value:
            return _closed(value)
        if entry["name"] == "report_summary":   # the report's Summary, the analyst's paragraph
            text = " ".join(str(value or "").split())
            return f'Wrote the report summary: "{cut_name(text)}"' if text else "Cleared the report summary"
        shown = f"{len(value)} item{'' if len(value) == 1 else 's'}" if isinstance(value, list) else json.dumps(value)
        return f"Set {entry['name'].replace('_', ' ')} to {shown}"
    if action == "case_open":   # the app's record of which build worked on the case
        return f"Opened with {entry.get('who') or SYSTEM} {entry.get('build', '')}"   # as written, the old name too
    if action == "case_upgrade":
        text = (f"Upgraded the case from format {entry.get('from_format')} to {entry.get('to_format')}: "
                f"{entry.get('text', '')}")
        merged = len((entry.get("rekey") or {}).get("merged") or {})   # when events merge, the later mark stands
        if merged:
            text += (f" {merged:,} {'event now holds' if merged == 1 else 'events now hold'} references made under "
                     "more than one earlier ID; the later mark stands, and each event's trail shows them all.")
        if isinstance(entry.get("sealed"), dict) and isinstance(entry.get("seq"), int) and entry["seq"] > 1:
            text += f" Entries #1 to #{entry['seq'] - 1} are from before the chain, sealed by #{entry['seq']}."
        for one in entry.get("recovered") or []:   # what the step's mend of the journal's last line did
            text += f" {recovered_words(one)}."
        return text
    if action == "undo":
        changes = entry["changes"]
        count = len({t for c in changes for t in c["targets"]})
        kept = entry.get("kept", 0)
        text = f"Undo of #{entry['undoes']}: " + (f"{count:,} events back to how they were" if count != 1
                                                   else "1 event back to how it was")
        if kept:
            text += f"; {kept:,} changed since #{entry['undoes']} " + ("kept their later state" if kept != 1
                                                                        else "kept its later state")
        return text + (f'. Note: "{entry["note"]}"' if entry.get("note") else "")
    return action or "unknown entry"


def _closed(value: dict) -> str:
    """The CLI's close, in words: what its re-hash found, which the entry's value records (cli.cmd_close), then what its
    full check of the journal found. The journal keeps the first 50 problems; verification.jsonl keeps them all."""
    text = _closed_evidence(value)
    if isinstance(value.get("journal_entries"), int):
        chain = value.get("chain") or "consistent"
        n = value["journal_entries"]
        text += (f" The journal's {n:,} {'entry' if n == 1 else 'entries'} before this one "
                 f"{'was' if n == 1 else 'were'} {chain}: each names the one before it.")
        text += (" They match the head this app recorded." if value.get("head_record") == "matched"
                 else " No head recorded outside the case to compare with.")
    return text


def _closed_evidence(value: dict) -> str:
    files, problems = value.get("evidence_files"), value.get("problems") or []
    # Files intake couldn't read and folders it couldn't list, which the close checked none of. A close entry without
    # unverified counted such files in evidence_files, and one without unlisted_folders counted such folders in
    # unverified, so its count reads as files.
    unread, folders = int(value.get("unverified") or 0), int(value.get("unlisted_folders") or 0)
    skipped = (f" {unread:,} evidence {'file' if unread == 1 else 'files'} could not be read at intake and "
               f"{'is' if unread == 1 else 'are'} unverified." if unread else "")
    if folders:
        skipped += f" {unlisted_text(folders)}."
    if value.get("hash_check") == "ok":
        if files is None:
            return "Closed the case. The evidence matches the intake manifest."
        if skipped:
            return f"Closed the case. {matched_text(files)}{skipped}"
        if not files:
            return "Closed the case. No evidence file was checked: the intake manifest lists none."
        return ("Closed the case. Its 1 evidence file matches the intake manifest." if files == 1
                else f"Closed the case. All {files:,} evidence files match the intake manifest.")
    found = "; ".join(problems[:3]) + ("; and more" if len(problems) > 3 else "")
    return (f"Closed the case. The evidence doesn't match the intake manifest{f': {found}' if found else ''}. "
            f"The case folder's verification.jsonl lists every problem.{skipped}")


def _quoted(value) -> str:
    return f'"{value}"' if isinstance(value, str) else "none" if value is None else json.dumps(value, default=str)


def _followup(entry: dict, what: str, lookup: dict) -> str:
    return f"Marked {what} followed up" if entry.get("done") else f"Cleared Followed up on {what}"


def _finding(entry: dict, what: str, lookup: dict) -> str:
    """A finding's op, its title from the lookup, as an event's name is."""
    op = entry.get("op")
    fid = entry["seq"] if op == "add" else entry.get("finding")
    title = f'the finding "{(lookup.get("titles") or {}).get(fid) or entry.get("title") or f"#{fid}"}"'
    if op == "add":
        why = ", ".join([entry.get("severity", ""), *(entry.get("techniques") or [])])
        n = len(entry.get("targets") or [])
        return f"Added {title} ({why})" + (f" with {n:,} event{'' if n == 1 else 's'}" if n else "")
    if op == "edit":
        return f"Edited {title}: {', '.join(k for k in FINDING_FIELDS if k in entry)}"
    if op == "link":
        return f"Linked {what} to {title}"
    if op == "unlink":
        return f"Unlinked {what} from {title}"
    if op == "retire":
        reason = str(entry.get("reason") or "").strip()
        return f"Retired {title}" + (f'. Reason: "{reason}"' if reason else "")
    return f"Restored {title}"


def _file(entry: dict, what: str, lookup: dict) -> str:
    """A file the case wrote: its name, what it is, its scope, its rows, and its SHA-256."""
    return (f"Wrote {str(entry.get('path', '')).rsplit('/', 1)[-1]}: {file_words(entry)}, "
            f"SHA-256 {short(entry.get('sha256', ''))}")


def file_words(entry: dict) -> str:
    """What a file_written entry says the file is: its kind, scope, rows, and filters, as the trail and verify --file
    give them, such as "report, whole case, 15 events", or "indicators, from the Malicious marks, 6 values"."""
    scope = entry.get("scope") or {"marks": "all"}
    if "start" in scope and "end" in scope:
        where = f"{SCOPE_WORD.get(scope.get('marks'), 'all events')} from {_time(scope['start'])} to {_time(scope['end'])}"
    elif entry.get("kind") == "timeline":
        where = f"{SCOPE_WORD.get(scope.get('marks'), 'all events')}, whole case"
    elif entry.get("kind") == "indicators":   # the card's own words: the values come from the Malicious marks
        where = "from the Malicious marks"
    else:
        where = "whole case"
    rows = entry.get("rows", 0)
    noun = {"audit_trail": ("entry", "entries"), "indicators": ("value", "values")}.get(entry.get("kind"), ("event", "events"))
    # the filter's words end in a period, which the comma after them would follow
    filtered = f", filtered: {str(entry['filters']['text']).removesuffix('.')}" if entry.get("filters") else ""
    return f"{FILE_WORD.get(entry.get('kind'), entry.get('kind'))}, {where}, {rows:,} {noun[rows != 1]}{filtered}"


def _created(entry: dict, what: str, lookup: dict) -> str:
    """case_created: the case, its analyst, and for a copy where it came from."""
    text = f'Created the case "{entry.get("name", "")}" for {entry.get("analyst", "")}'
    source = entry.get("copied_from")
    if not isinstance(source, dict):
        return text
    if "head" in source:
        return text + f", copied from {source.get('folder', '')} (head {short(source['head'])}, entry #{source.get('seq')})"
    return text + (f", copied from {source.get('folder', '')} (its journal before the chain: "
                   f"{source.get('bytes', 0):,} bytes, SHA-256 {short(source.get('sha256', ''))})")


def _case_yaml(entry: dict, what: str, lookup: dict) -> str:
    """case.yaml's record: what changed since the record before it, or "Recorded case.yaml" with none before.
    case_created records four of its settings, so only those are compared with it."""
    before = (lookup.get("yaml") or {}).get(entry.get("seq"))
    if before is None:
        return "Recorded case.yaml"
    since, old, every = before
    new = entry.get("settings") or {}
    keys = dict.fromkeys([*old, *new]) if every else old
    changes = [f"{k} {_quoted(old.get(k))} to {_quoted(new.get(k))}" for k in keys if old.get(k) != new.get(k)]
    return f"case.yaml changed since #{since}" + (f": {'; '.join(changes)}" if changes else "")


def recovered_words(payload: dict) -> str:
    """A journal_recovered payload in words, as the trail and Integrity give it."""
    if payload.get("completed"):
        entry = payload.get("entry")
        if entry is None:
            return "Added the line end to a last line of only whitespace, which the journal's reader skips"
        return f"Added the line end missing from entry #{entry.get('seq')}"
    name, size = payload.get("saved_as", ""), payload.get("bytes", 0)
    if payload.get("found"):
        return f"Found {name} with no entry naming it, unexplained"
    held = payload.get("held")
    text = (f"Moved a cut-short last line aside, most likely left by a crash: {size:,} byte{'' if size == 1 else 's'} "
            f"kept in {name}")
    return text + (f". It held part of entry #{held.get('seq')}, a {held.get('action')}, which isn't applied"
                   if isinstance(held, dict) else "")


def _recovered(entry: dict, what: str, lookup: dict) -> str:
    return recovered_words(entry)


def _chain_break(entry: dict, what: str, lookup: dict) -> str:
    """Continue with the break on record: where the journal changed, the reason, and the seal."""
    found = entry.get("breaks") or []
    lines = [b.get("line") for b in found if b.get("line")]
    where = f" at line {lines[0]}" if lines else ""
    more = len(found) - 1
    sealed = (entry.get("sealed") or {}).get("lines", 0)
    return (f"Continued with the journal changed{where}" + (f" and {more} more break{'' if more == 1 else 's'}" if more
                                                              else "")
            + f'. Reason: "{entry.get("reason", "")}". Sealed the {sealed:,} line{"" if sealed == 1 else "s"} before '
              "this entry")


D16_WORDS = {"followup": _followup, "finding": _finding, "file_written": _file, "case_created": _created,
             "case_yaml": _case_yaml, "journal_recovered": _recovered, "chain_break": _chain_break}


def single_targets(entries: list[dict]) -> set[str]:
    """Events worth naming in descriptions: the one target of an entry, or a note's event."""
    out = set()
    for e in entries:
        if e.get(DAMAGED):
            continue
        if len(e.get("targets") or []) == 1:
            out.add(e["targets"][0])
        if e.get("target"):
            out.add(e["target"])
    return out


def rows(entries: list[dict], events: dict[str, str], *, kind: str = "", who: str = "", q: str = "",
         corrections: bool = False, event: str = "", offset: int = 0, limit: int = 200, lookup: dict | None = None,
         times: dict[str, int | None] | None = None) -> dict:
    """The trail, newest first, filtered; each row says what it did and what the analyst can do about it. `lookup` is
    lookups of the whole journal, when `entries` are some of it. A row whose text names one event (`events`) carries
    that event as `event`: its ID, its full name, the name cut for the page (cut_name), and its time from
    `times`, so the page can show the name cut with the whole in its hover and open the event."""
    lookup = lookups(entries) if lookup is None else lookup
    done = undone_by(entries)
    retracted = {(e["target"], e["note_seq"]): e["seq"] for e in entries
                 if e.get("action") == "note_retract" and not e.get(DAMAGED)}
    picked = []
    for e in reversed(entries):
        k = KINDS.get(e.get("action"), "Other")
        if (kind and k != kind) or (who and e.get("who") != who) or (corrections and e.get("action") != "undo"):
            continue
        # A damaged entry's payload is not read: it names no event the filter could match
        if event and (e.get(DAMAGED) or (event not in (e.get("targets") or []) and e.get("target") != event and
                                         event not in {t for c in e.get("changes") or [] for t in c["targets"]})):
            continue
        text = describe(e, events, lookup)
        if q and q.lower() not in f"{text} {e.get('who', '')}".lower():
            continue
        picked.append((e, k, text))
    out = []
    for e, k, text in picked[offset:offset + limit]:
        action, damaged = e.get("action"), bool(e.get(DAMAGED))
        named = None if damaged else next((t for t in single_targets([e]) if events.get(t) and events[t] in text), None)
        out.append({"seq": e["seq"], "at": e.get("at", ""), "who": e.get("who", ""), "action": action, "kind": k,
                    "text": text, "count": 0 if damaged else len(e.get("targets") or []), "undoes": e.get("undoes"),
                    "undone_by": done.get(e["seq"]),
                    "undoable": action in UNDOABLE and e["seq"] not in done and not damaged,
                    "retracted_by": retracted.get((e.get("target"), e["seq"])) if action == "note" else None,
                    "panel": PANEL.get(k), "rekeyed": rekeyed(e),
                    "event": {"uid": named, "name": events[named], "short": cut_name(events[named]),
                              "ts": (times or {}).get(named)} if named else None})
    return {"rows": out, "total": len(picked), "offset": offset,
            "analysts": sorted({e.get("who", "") for e in entries}), "kinds": sorted(set(KINDS.values()))}


def rekeyed(entry: dict) -> str:
    """For an entry read through a case format upgrade's rekey, what says why its IDs differ from its journal line, such
    as "IDs as changed at #120"; "" for any other."""
    seqs = entry.get(REKEYED) or []
    return f"IDs as changed at {' and '.join(f'#{s}' for s in seqs)}" if seqs else ""


def entry_targets(entry: dict) -> list[str]:
    """The events an entry touched: its targets, an undo's changes' targets, or a note's event. None for an entry whose
    payload replay can't read."""
    if entry.get(DAMAGED):
        return []
    if entry.get("target"):
        return [entry["target"]]
    return list(entry.get("targets") or []) or [t for c in entry.get("changes") or [] for t in c["targets"]]


def markdown(entries: list[dict], case_name: str, events: dict[str, str],
             listed: dict[int, tuple[int, list[dict]]] | None = None, head: tuple[str, int | None] | None = None,
             chain: str = "") -> str:
    """The whole trail, oldest first, as a record of the investigation's method. Its text is escaped for
    Markdown, as the report's is: events are named by their messages, which come from evidence, and a case
    folder made elsewhere brings its own journal. `listed` gives an entry of several events its count and events, as the
    trail's "N events" lists them, each written under the entry by its time, host, event code, and ID. Its opening line
    names, beside the build, the journal's head of the read it lists and `chain`, what the full check of that read
    found."""
    done = undone_by(entries)
    lookup = lookups(entries)
    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    corrections = sum(1 for e in entries if e.get("action") == "undo" and not e.get(DAMAGED))
    at = f", from the journal whose head is {head[0]} (entry #{head[1]})" if head else ""
    lines = [f"# Audit trail: {_md(case_name)}", "",
             f"Generated {now} by glessner {build_id()}{at}. {_md(chain) + ' ' if chain else ''}Every analyst action "
             f"in this case's journal, oldest first: {len(entries):,} entries, "
             f"{corrections:,} of them corrections of accidents. The journal is append-only, so an undone entry stays "
             "listed with the correction that reversed it.", ""]
    for e in entries:
        when = str(e.get("at", ""))[:19].replace("T", " ")
        flag = " *(correction of an accident)*" if e.get("action") == "undo" and not e.get(DAMAGED) else ""
        flag += f" *(undone by #{done[e['seq']]})*" if e["seq"] in done else ""
        flag += f" *({rekeyed(e)})*" if e.get(REKEYED) else ""   # so the record matches journal.jsonl's line
        lines.append(f"- **#{e['seq']}** {_md(when)} UTC, {_md(e.get('who', ''))}: "
                     f"{_md(describe(e, events, lookup))}{flag}")
        total, shown = (listed or {}).get(e["seq"], (0, []))
        lines += [f"  - {_event_line(x)}" for x in shown]
        if total > len(shown):
            lines.append(f"  - and {total - len(shown):,} more")
    return "\n".join(lines) + "\n"


def _event_line(event: dict) -> str:
    """One event of a multi-event entry in the exported trail: its time as the page lists it, host, code, and ID."""
    when = "No time recorded" if event["ts"] is None else _time(event["ts"])
    return ", ".join(_md(part) for part in (when, event["host"], event["code"]) if part) + f", ID `{_tick(event['uid'])}`"
