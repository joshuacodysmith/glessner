"""Format 1 cases built by hand for the case format upgrade's tests (rekey.py): tool runs and loads of output found in the
evidence, each loaded with format 1's event IDs, which the parsers still give in Event.former (tests/test_event_keys.py
pins that rule against the parsers). Run IDs are numbered, so runs sort in the order a test makes them, as their times
sort them in a real case."""

import hashlib
import json
from pathlib import Path, PureWindowsPath

import yaml
from chain_fixtures import append_unchained, as_format
from rekey_fixtures import (
    NOTIFICATIONS,
    NOTIFICATIONS_CSV,
    VISITS,
    VISITS_CSV,
    eve_records,
    write_rows,
)

from glessner.case import create_case, open_case
from glessner.events import connect, load
from glessner.intake import add_new, intake, sha256_file
from glessner.journal import Journal, has_chain, replay
from glessner.parsers import PARSERS
from glessner.runner import FOUND_OUTPUT, RunRecord, _write_record, latest_runs, parse_context, read_runs

HISTORY = "WS01/Users/bob/AppData/Local/Microsoft/Edge/User Data/Default/History"
WPN = "WS01/Users/bob/AppData/Local/Microsoft/Windows/Notifications/wpndatabase.db"


def set_format(folder: Path, value: int) -> None:
    data = yaml.safe_load((folder / "case.yaml").read_text(encoding="utf-8"))
    data["case_format"] = value
    (folder / "case.yaml").write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


def case_format(case) -> int:
    return yaml.safe_load((case.folder / "case.yaml").read_text(encoding="utf-8"))["case_format"]


class Format1:
    """A format 1 case: its evidence folder holds one folder per host, and each run loads as format 1 loaded it."""

    def __init__(self, root: Path, hosts=("DESKTOP", "SENSOR", "WS01")):
        self.root = root
        self.evidence = root / "evidence"
        for host in hosts:
            (self.evidence / host).mkdir(parents=True, exist_ok=True)
        case = create_case(root / "case", "Remap", self.evidence, "cody")
        as_format(case.folder, 1)   # as a format 1 build made it: an empty journal, no chain
        self.case = open_case(case.folder)
        self.n = 0

    def reopen(self):
        self.case = open_case(self.case.folder)
        return self.case

    def run_id(self, tool: str, host: str) -> str:
        self.n += 1
        return f"20240101T00{self.n:04d}Z_{tool}_{host}"

    def take_in(self) -> None:
        """Intake, or add the files new since it."""
        (add_new if self.case.manifest_path.exists() else intake)(self.case)

    def tool_run(self, tool: str, parser: str, host: str, inputs, write, *, no_folders=False, working_copies=(),
                 evidence_root=None, status="ok", load_it=True) -> RunRecord:
        """A tool's run: write(output folder) writes its output, which its record hashes. A run made before runs recorded
        their folders (no_folders) records neither folder."""
        run_id = self.run_id(tool, host)
        folder = self.case.runs_folder / run_id
        (folder / "output").mkdir(parents=True)
        write(folder / "output")
        outputs = [{"path": p.relative_to(folder / "output").as_posix(), "size": p.stat().st_size, "sha256": sha256_file(p)}
                   for p in sorted((folder / "output").rglob("*")) if p.is_file()]
        record = RunRecord(run_id=run_id, tool=tool, tool_version="1", executable="", host=host, argv=[], cwd="",
                           inputs=list(inputs), started_utc="", status=status, parser=parser, outputs=outputs,
                           outputs_all=True, working_copies=list(working_copies))
        if not no_folders:
            record.evidence_root = str(evidence_root or self.evidence)
            record.input_root = str(folder / "input") if working_copies else ""
        if load_it:
            self.load(record)
        _write_record(folder, record)
        return record

    def found_run(self, tool: str, parser: str, host: str, inputs, *, status="ok", load_it=True) -> RunRecord:
        """A load of output found in the evidence, as runner.load_found_output records it."""
        run_id = self.run_id(tool, host)
        folder = self.case.runs_folder / run_id
        (folder / "output").mkdir(parents=True)
        record = RunRecord(run_id=run_id, tool=tool, tool_version=FOUND_OUTPUT, executable="", host=host, argv=[],
                           cwd="", inputs=sorted(inputs), started_utc="", status=status, parser=parser, from_output=True,
                           evidence_check="ok" if status == "ok" else "mismatch")
        if load_it:
            self.load(record)
        _write_record(folder, record)
        return record

    def load(self, record: RunRecord) -> None:
        load_format_1(self.case, record)

    def rebuild(self) -> None:
        rebuild_format_1(self.case)

    # ---------- the runs the tests use ----------

    def eve_run(self, hours: int = 7, capture: str = "SENSOR/capture.pcap", **kw) -> RunRecord:
        """Suricata's run on a capture, its EVE written `hours` east of UTC."""
        write = lambda out: (out / "eve.json").write_text("".join(json.dumps(r) + "\n" for r in eve_records(hours)),
                                                          encoding="utf-8")
        return self.tool_run("suricata", "suricata_eve", "SENSOR", [capture], write, **kw)

    def eve_file(self, rel: str, hours: int) -> str:
        """An EVE file in the evidence, written `hours` east of UTC."""
        path = self.evidence / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("".join(json.dumps(r) + "\n" for r in eve_records(hours)), encoding="utf-8")
        return rel

    def sqlecmd_run(self, rows=None, *, host="WS01", no_folders=True, notified_in="elsewhere", **kw) -> RunRecord:
        """SQLECmd's run on a host made before runs recorded their folders, its output naming bob's databases by copies
        in another case's folder for this run, as a case moved or copied then has them. rows(elsewhere, own) gives
        other visits, as (visit ID, path) pairs, from that folder and the run's own copies' folder; `notified_in` says
        which of the two the notification's path names."""
        run_id = f"20240101T00{self.n + 1:04d}Z_sqlecmd_{host}"
        elsewhere = PureWindowsPath("C:/Users/analyst/cases/a/runs") / run_id / "input"
        own = PureWindowsPath(self.case.runs_folder / run_id / "input")
        rows = rows(elsewhere, own) if rows else [("10", elsewhere / PureWindowsPath(HISTORY))]
        visit = lambda vid, source: {"ID": vid, "VisitID": vid, "VisitTime (UTC)": f"2024-05-14 12:00:{vid}",
                                     "URL": f"https://evil.example/{vid}", "URLTitle": "Evil", "SourceFile": str(source)}

        def write(out):
            write_rows(out / VISITS_CSV, VISITS, [visit(vid, src) for vid, src in rows])
            write_rows(out / NOTIFICATIONS_CSV, NOTIFICATIONS, [
                {"ID": "1", "Application": "Defender", "ArrivalTime": "2024-05-14 12:02:00",
                 "Payload": "<toast><text>Threats found</text></toast>",
                 "SourceFile": str({"elsewhere": elsewhere, "own": own}[notified_in] / PureWindowsPath(WPN))}])

        return self.tool_run("sqlecmd", "sqlecmd_csv", host, [HISTORY, WPN], write, no_folders=no_folders,
                             working_copies=[HISTORY, WPN], **kw)

    # ---------- reading the case ----------

    def uids(self, tool: str | None = None, where: str = "", params=()) -> list[str]:
        con = connect(self.case.db_path, read_only=True)
        try:
            sql = "SELECT event_uid FROM events WHERE " + " AND ".join(
                [*(["tool = ?"] if tool else []), *([where] if where else []), "true"])
            return sorted(u for (u,) in con.execute(sql, [*([tool] if tool else []), *params]).fetchall())
        finally:
            con.close()

    def rows(self, sql: str, params=()) -> list[tuple]:
        con = connect(self.case.db_path, read_only=True)
        try:
            return con.execute(sql, list(params)).fetchall()
        finally:
            con.close()

    def mark(self, uids, value="malicious", note="") -> dict:
        """A mark, as the build of the case's format makes it: unchained before the upgrade to format 3."""
        if has_chain(self.case.folder / "journal.jsonl"):
            return Journal(self.case).append("mark", targets=list(uids), value=value, note=note)
        return append_unchained(self.case.folder, "mark", targets=list(uids), value=value, note=note)

    def journal_bytes(self) -> bytes:
        return (self.case.folder / "journal.jsonl").read_bytes()

    def upgrades(self, to_format: int = 2) -> list[dict]:
        """The journal's case_upgrade entries to `to_format`: format 2's step's by default; the seal's with 3."""
        lines = self.journal_bytes().decode("utf-8").splitlines()
        return [e for e in map(json.loads, filter(None, lines))
                if e["action"] == "case_upgrade" and e.get("to_format") == to_format]


def load_format_1(case, record: RunRecord) -> None:
    """The run's events loaded under format 1's key rule, as a format 1 build loaded them: a load of found output
    replaced the tool's rows on the host for every file its events name, whichever run loaded them."""
    folder = case.runs_folder / record.run_id
    events = []
    for ev in PARSERS[record.parser](parse_context(case, record, folder, former=1)):
        if ev.former:
            ev.source_file, ev.source_record = ev.former
        events.append(ev)
    named = [ev.source_file for ev in events] if record.from_output else []
    result = load(case.db_path, events, host=record.host, tool=record.tool, tool_version=record.tool_version,
                  run_id=record.run_id, replaces_sources=[*record.inputs, *named], staging_dir=folder)
    record.loaded_rows = result.rows


def rebuild_format_1(case) -> None:
    """A rebuild by a format 1 build."""
    case.db_path.unlink(missing_ok=True)
    connect(case.db_path).close()
    for record in latest_runs(read_runs(case)):
        load_format_1(case, record)
        _write_record(case.runs_folder / record.run_id, record)


def digest(case, where: str = "true") -> str:
    """Every column of every events row the filter keeps, in a fixed order."""
    con = connect(case.db_path, read_only=True)
    try:
        rows = con.execute(f"SELECT * FROM events WHERE {where}").fetchall()
    finally:
        con.close()
    return hashlib.sha256("\n".join(sorted(repr(r) for r in rows)).encode("utf-8", "surrogatepass")).hexdigest()


def run_files(case) -> dict[str, bytes]:
    return {p.relative_to(case.folder).as_posix(): p.read_bytes() for p in sorted(case.runs_folder.glob("*/run.json"))}


def state_of(case) -> dict:
    """What a replay of the journal holds for events: marks, notes, and tags by ID."""
    state = replay(case.folder / "journal.jsonl")
    return {"marks": {u: (m.value, m.seq) for u, m in state.marks.items()},
            "notes": {u: [n["seq"] for n in notes] for u, notes in state.notes.items()},
            "tags": {u: sorted(t) for u, t in state.tags.items()}}
