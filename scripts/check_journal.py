"""Check a Glessner journal of case format 3 or later: python -I check_journal.py journal.jsonl [HEAD] [--file FILE]

Exit 0 only when the chain starts at byte 0 with case_created, or with a seal that matches every byte before it; each
later line names the line before it and carries the whole envelope; nothing follows the last line end (a last line
without its LF that starts or continues the chain is named, with its head, and exits 1); there is no chain_break; HEAD,
when given, is one of the entries; and FILE, when given, is recorded at or before HEAD. The chain alone can't show
removed newest entries, a rewritten journal, or entries added after a head. A HEAD recorded outside the case shows the
first two, and only a file record at or before it counts. Exit 2, with one line naming it, when the journal or FILE
can't be read.

The standard library alone, so a reviewer can read all of it. tests/test_journal_chain.py runs it on every tamper
case beside the app.
"""
import argparse
import hashlib
import json
import os
import re
import sys

ZERO = "0" * 64
FIRST_CHAINED = 3   # the first case format whose journal has the chain
CASE_FORMAT = 4     # the case format this script checks up to; only the step from 3 to 4 carries a rekey to it
SIDE_FILE = re.compile(r"journal_torn_[^\\/]+\.bin")


def unique(pairs):
    if len({k for k, _ in pairs}) != len(pairs):
        raise ValueError("a key appears twice")
    return dict(pairs)


def finite(name):
    raise ValueError(f"{name} isn't a number this format writes")


def finite_float(text):
    value = float(text)
    if value in (float("inf"), float("-inf")):   # 1e999 overflows to inf
        finite(text)
    return value


def parse(line):
    """The line's entry: one JSON object of unique keys and finite numbers in strict UTF-8, or None."""
    try:
        entry = json.loads(line.decode("utf-8"), object_pairs_hook=unique, parse_constant=finite, parse_float=finite_float)
    except (ValueError, RecursionError):   # UnicodeDecodeError and JSONDecodeError are ValueErrors
        return None
    return entry if isinstance(entry, dict) else None


def number(value):
    return isinstance(value, int) and not isinstance(value, bool)


def lacks(entry):
    """What the line's envelope lacks, or None. Its prev is checked against the line before it."""
    if not number(entry.get("seq")):
        return f"seq {entry.get('seq')!r} isn't an integer"
    missing = [k for k in ("at", "who", "build", "action") if not (isinstance(entry.get(k), str) and entry[k])]
    missing += [] if entry.get("client") in ("server", "cli") else ["client"]
    return f"no {', '.join(missing)} in the envelope" if missing else None


def lenient(line):
    """An unchained line's entry as the app reads it before the chain starts, by json.loads as format 2's reader did, or
    {}. The side files such a line names are checked like the chain's (the seal covers their recorded hashes)."""
    try:
        entry = json.loads(line)
    except (ValueError, RecursionError):
        return {}
    return entry if isinstance(entry, dict) else {}


def recoveries(entry):
    """What an entry says it recovered, as (its seq, the payload): a journal_recovered's own, and each in a case_upgrade's
    recovered."""
    if entry.get("action") == "journal_recovered":
        return [(entry.get("seq"), entry)]
    if entry.get("action") == "case_upgrade" and isinstance(entry.get("recovered"), list):
        return [(entry.get("seq"), one) for one in entry["recovered"] if isinstance(one, dict)]
    return []


def described(rekey):
    """Whether a rekey describes its map as the step from format 3 to 4 writes it: the runs it read, and the size and
    SHA-256 of the whole map, which holds at least its pairs."""
    runs, size, digest = rekey.get("runs"), rekey.get("map_size"), rekey.get("map_sha256")
    pairs = rekey.get("pairs")
    return (isinstance(runs, dict) and bool(runs) and number(size) and isinstance(pairs, dict) and size >= len(pairs)
            and isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest) is not None)


def closes(entry):
    """Whether a chained line closes the place of the step from format 3 to 4 for a rekey in the lines after it: the
    step's own entry, whatever it holds; a case_created that says the case began at format 4 or later (case_format); or a
    manifest_recorded, which only a case at format 4 or later holds."""
    if entry is None:
        return False
    action = entry.get("action")
    if action == "case_upgrade":
        old, new = entry.get("from_format"), entry.get("to_format")
        return number(old) and number(new) and (old, new) == (3, 4)
    if action == "case_created":
        return number(entry.get("case_format")) and entry["case_format"] >= 4
    return action == "manifest_recorded"


def foreign_rekey(entry, past=False):
    """Why a rekey entry of event IDs can't be one a build of this format wrote, or None. A rekey re-points every earlier
    entry's IDs. Once the chain has started, only a later format's upgrade carries one: chained, from a format that has
    the chain to one above CASE_FORMAT; and the step from format 3 to 4, when it describes its map and no line before it
    closes its place (`past`, closes)."""
    if not isinstance(entry.get("rekey"), dict) or entry.get("action") != "case_upgrade":
        return None
    old, new = entry.get("from_format"), entry.get("to_format")
    if number(old) and number(new) and old >= FIRST_CHAINED and (
            new > max(old, CASE_FORMAT) or ((old, new) == (3, 4) and not past and described(entry["rekey"]))):
        return None
    return (f"a rekey of event IDs, from format {old!r} to {new!r}, which no build of this format writes: after the "
            "chain starts, only a later format's upgrade carries one, and the step from format 3 to 4 when it describes "
            "its map and comes before the case's format 4 entries and before any other step from 3 to 4")


def side_files(folder, named):
    """The side files the entries name that are missing from the journal's folder or differ from what the entry
    recorded."""
    out = []
    for seq, one in named:
        name = one.get("saved_as")
        if not (isinstance(name, str) and SIDE_FILE.fullmatch(name)):
            continue
        try:
            data = read(os.path.join(folder, name))
        except OSError:
            out.append(f"the side file {name}, which entry #{seq} names, is missing from the journal's folder")
            continue
        if len(data) != one.get("bytes") or hashlib.sha256(data).hexdigest() != one.get("sha256"):
            out.append(f"the side file {name} doesn't hold the {one.get('bytes')} bytes entry #{seq} recorded for it: "
                       f"its length or SHA-256 differs")
    return out


def seal_matches(entry, data, start, lines):
    sealed = entry.get("sealed")
    return (isinstance(sealed, dict) and sealed.get("bytes") == start and sealed.get("lines") == lines
            and sealed.get("sha256") == hashlib.sha256(data[:start]).hexdigest())


def starts(entry, data, start, lines):
    """Whether a chained line starts the chain: prev of 64 zeros, and case_created at byte 0 with seq 1, or a seal that
    matches the `start` bytes and `lines` before it."""
    if entry["prev"] != ZERO:
        return False
    if entry["action"] == "case_created":
        return start == 0 and entry["seq"] == 1
    return entry["action"] == "case_upgrade" and seal_matches(entry, data, start, lines)


def tail_follows(entry, data, head, seq, chained, start, lines, past):
    """Whether the last line, which no LF ends, is whole and the chain's next line, or, before any chained line, its
    start: the app adds the line end at its next write. The same rule as a line with its end, and no rekey of event IDs
    a build of this format doesn't write."""
    if entry.get("prev") != head or lacks(entry) or foreign_rekey(entry, past):
        return False
    return (number(seq) and entry["seq"] == seq + 1) if chained else starts(entry, data, start, lines)


def read(path):
    with open(path, "rb") as f:
        return f.read()


def recorded(path, records):
    """The first file_written entry holding the file's SHA-256, as (line, seq), or None and why there's none."""
    data = read(path)
    sha = hashlib.sha256(data).hexdigest()
    for n, seq, h in records:
        if h == sha:
            return (n, seq), None
    lf = data.replace(b"\r\n", b"\n")
    turned = {hashlib.sha256(d).hexdigest() for d in (lf, lf.replace(b"\n", b"\r\n"))}
    other = next((seq for _, seq, h in records if h in turned), None)
    return None, ("no entry has this file's SHA-256: it changed after it was written (a change of line endings "
                  "counts), the app stopped before it recorded the file, or another case wrote it"
                  + (f". With its line endings converted back, it matches entry #{other}" if other is not None else ""))


def check(path, expect=None, file=None):
    data = read(path)
    expect = expect.lower() if expect else None
    end = data.rfind(b"\n") + 1                      # whole lines end here; anything after is a line without its end
    last = data.rfind(b"\n", 0, max(end - 1, 0)) + 1
    if end == len(data) and b"\0" in data[last:end]:   # json.dumps never writes a NUL: a crash's last line, LF or not
        end = last
    problems, breaks = [], []
    heads, records = {}, []                          # hash -> (line, seq); file_written entries as (line, seq, sha256)
    named = []                                       # side files entries name, as (seq, what the entry recorded)
    head, seq, start, lines, chained, crlf = ZERO, None, 0, 0, False, 0
    past = False                                     # a chained line has closed the step from 3 to 4's place (closes)
    body = data[:end].split(b"\n")[:-1]
    for n, line in enumerate(body, 1):
        entry = parse(line)
        crlf += line.endswith(b"\r")
        if not chained and (entry is None or "prev" not in entry):
            named.extend(recoveries(lenient(line)))  # a side file format 2's step named, which the seal covers
            lines += bool(line.strip())              # a format 1 line, which the seal covers
            start += len(line) + 1
            continue
        if not chained:                              # the first chained line: the envelope, then where it starts
            chained = True
            problem = lacks(entry) or (foreign_rekey(entry) if starts(entry, data, start, lines) else
                                       f"the chain must start with case_created at the top, or with a seal that matches "
                                       f"the {start:,} bytes before it")
        elif not line.strip():
            problem = "a blank line inside the chain"
        elif entry is None:
            problem = "not one JSON object of unique keys and finite numbers in UTF-8"
        elif "prev" not in entry:
            problem = "no prev, so a build from before format 3 wrote it, such as one still running from before the upgrade"
        elif lacks(entry):                           # the envelope before prev, as the app checks it
            problem = lacks(entry)
        elif entry["prev"] != head:
            problem = f"prev doesn't match line {n - 1}, which changed, or a line was removed, inserted, or moved here"
        else:
            problem = (None if seq is None or entry["seq"] == seq + 1
                       else f"seq {entry['seq']} doesn't follow {seq}") or foreign_rekey(entry, past)
        if problem:
            problems.append(f"line {n}: {problem}")
        if entry is not None and entry.get("action") == "chain_break":
            sealed = "matches" if seal_matches(entry, data, start, lines) else "doesn't match"
            breaks.append(f"line {n}: chain_break by {entry.get('who')} at {entry.get('at')}, reason "
                          f"{entry.get('reason')!r}; its seal of the lines before it {sealed}")
        if entry is not None and not lacks(entry) and entry["action"] == "file_written":
            records.append((n, entry["seq"], entry.get("sha256")))
        if entry is not None and not lacks(entry):
            named.extend(recoveries(entry))
        head = hashlib.sha256(line).hexdigest()      # the next line must name this one, whatever it holds
        past = past or closes(entry)
        if entry is not None and number(entry.get("seq")):
            seq = entry["seq"]
            heads[head] = (n, seq)
        elif number(seq):
            seq += 1                                 # an unreadable line takes one number
        lines += bool(line.strip())
        start += len(line) + 1
    tail = data[end:]
    entry = None if b"\0" in tail else parse(tail)
    follows = entry is not None and tail_follows(entry, data, head, seq, chained, start, lines, past)
    if not chained and not follows:   # a first line missing only its LF is the chain's start
        problems.append("no chained line: the chain is missing, or this is a journal of format 1 or 2, which has none")
    if crlf and crlf == data[:end].count(b"\n"):
        problems.insert(0, "every line ends in CR LF: the line endings were converted, such as by a copy through a "
                           "tool that changes them")
    problems += side_files(os.path.dirname(os.path.abspath(path)), named)
    if tail:
        if follows:
            head, seq = hashlib.sha256(tail).hexdigest(), entry["seq"]
            heads[head] = (len(body) + 1, seq)
            if entry["action"] == "file_written":
                records.append((len(body) + 1, seq, entry.get("sha256")))
            problems.append(f"the last line, entry #{seq}, has no line end. The entry is whole and follows the "
                            f"line before it; the app adds the line end at its next write")
        elif entry is not None:   # a cut never leaves a whole object: its closing brace is the line's last byte
            problems.append("the last line has no line end, and its entry doesn't follow the line before it")
        else:
            problems.append(f"{len(tail):,} bytes after the last whole line, most likely a write a crash cut short; "
                            f"the app moves them to a side file at its next write")
    if expect and expect not in heads:
        problems.append("the expected head is no entry of this journal")
    if file:   # the record counts only at or before the expected head: anyone can append a chained record after it
        where, why = recorded(file, records)
        if why:
            problems.append(why)
        elif not expect:
            problems.append(f"entry #{where[1]} records this file, but no expected head was given, so nothing shows "
                            f"the entry wasn't added later")
        elif expect in heads and where[0] > heads[expect][0]:
            problems.append(f"entry #{where[1]} records this file, but it follows the expected head, so that head "
                            f"does not vouch for it")
        else:
            print(f"entry #{where[1]} records this file" + (", at or before the expected head" if expect in heads else ""))
    for text in problems + breaks:
        print(text)
    at = f"; the expected head is entry #{heads[expect][1]}" if expect in heads else ""
    print(f"{len(heads):,} chained entries, head {head} (entry #{seq}){at}")
    if not expect:
        print("No expected head given: the chain can't show removed newest entries or a rewritten journal.")
    return 1 if problems or breaks else 0


if __name__ == "__main__":
    args = argparse.ArgumentParser(description="Check a Glessner journal of case format 3 or later.")
    args.add_argument("journal")
    args.add_argument("head", nargs="?", help="a head recorded outside the case")
    args.add_argument("--file", help="a file the case wrote, which must be recorded at or before HEAD")
    a = args.parse_args()
    try:
        code = check(a.journal, a.head, a.file)
    except OSError as exc:   # a missing journal or FILE, or a folder named as one: exit 2, as for a usage error
        if exc.filename is None or exc.filename not in (a.journal, a.file):   # such as a closed pipe on the output
            raise
        why = "it is a folder" if os.path.isdir(exc.filename) else exc.strerror
        print(f"{exc.filename} is not a file this script can read: {why}", file=sys.stderr)
        code = 2
    sys.exit(code)
