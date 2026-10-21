"""The start page: folder checks, browsing, recent cases, and new cases and copies as jobs."""

import getpass
import json
import time
from pathlib import Path

import pytest
from conftest import junction
from test_server import login, request
from test_tools import fake_runtime

from glessner import start
from glessner.case import create_case, open_case
from glessner.intake import intake
from glessner.server import serve_start
from glessner.start import browse, check, load_recent, remember, start_copy
from glessner.tools import _executables_under, find_dotnet, load_registry


def evidence_folder(tmp_path):
    ev = tmp_path / "evidence"
    for host in ("DC01", "WS01"):
        logs = ev / host / "Windows" / "System32" / "winevt" / "Logs"
        logs.mkdir(parents=True)
        (logs / "Security.evtx").write_bytes(b"ElfFile\x00" + host.encode() * 10)
    (ev / "notes.txt").write_text("top level")
    return ev


def test_check_describes_the_chosen_folders(tmp_path):
    ev = evidence_folder(tmp_path)
    (tmp_path / "tools").mkdir()
    out = check(str(ev), str(tmp_path / "cases" / "new"), str(tmp_path / "tools"))
    assert out["evidence"] == {"ok": True, "files": 3, "bytes": out["evidence"]["bytes"], "partial": False,
                               "hosts": ["DC01", "WS01"], "root_files": 1, "message": "", "warning": "", "links": []}
    assert out["case_folder"] == {"ok": True, "message": "A new folder."}
    builtin = sum(1 for s in load_registry().values() if s.builtin)
    assert out["tools"]["ok"] and out["tools"]["found"] == builtin >= 1   # the built-in reader counts
    assert out["tools"]["executables"] == []
    assert not check(str(ev), str(ev / "case"))["case_folder"]["ok"]   # inside the evidence
    assert check(str(tmp_path / "nope"))["evidence"] == {"ok": False, "message": "Folder not found."}


def test_check_refuses_a_tools_folder_that_would_run_evidence_and_names_each_executable(tmp_path):
    """A tools folder holding the evidence, where a suspect's EvtxECmd.exe would run, is refused, as in create_case,
    and each tool found is named with the file detection would run."""
    ev = evidence_folder(tmp_path)
    planted = ev / "WS01" / "Users" / "bob" / "Downloads" / "EvtxECmd.exe"
    planted.parent.mkdir(parents=True)
    planted.write_bytes(b"")   # a placeholder: nothing runs
    case_folder = str(tmp_path / "cases" / "new")
    for tools, refusal in ((tmp_path, "evidence folder must not contain"), (ev / "WS01", "evidence folder must not"),
                           (tmp_path / "cases", "case folder must not contain"), ("\\\\server\\share", "network path")):
        out = check(str(ev), case_folder, str(tools))["tools"]
        assert not out["ok"] and refusal in out["message"], tools
    tools = tmp_path / "tools"
    (tools / "EZ" / "EvtxECmd").mkdir(parents=True)
    (tools / "EZ" / "EvtxECmd" / "EvtxECmd.exe").write_bytes(b"")
    out = check(str(ev), case_folder, str(tools))["tools"]
    assert out["ok"] and out["executables"] == [{"tool": "EvtxECmd", "path": str(tools / "EZ" / "EvtxECmd" / "EvtxECmd.exe")}]


def test_check_and_detection_skip_junctions(tmp_path):
    """The evidence check walks as intake does, so a junction is skipped and listed rather than
    counted as a host or followed; and a junction in the tools folder can't bring in an executable from elsewhere,
    such as the evidence."""
    ev = evidence_folder(tmp_path)
    outside = tmp_path / "outside"
    (outside / "Windows").mkdir(parents=True)
    (outside / "EvtxECmd.exe").write_bytes(b"")
    junction(ev / "LINKED", outside)
    junction(ev / "DC01" / "loop", ev / "DC01")
    out = check(str(ev))["evidence"]
    assert (out["files"], out["hosts"], out["root_files"]) == (3, ["DC01", "WS01"], 1)
    assert out["links"] == [f"LINKED -> {outside}", f"DC01/loop -> {ev / 'DC01'}"]
    tools = tmp_path / "tools"
    tools.mkdir()
    junction(tools / "EZ", outside)
    assert _executables_under(tools) == [] and check(tools=str(tools))["tools"]["executables"] == []
    fake_runtime(outside / "dotnet-9", "9.0.21")
    junction(tools / "dotnet-9", outside / "dotnet-9")
    assert find_dotnet(tools, 9) is None


def folders(root, *paths):
    for p in paths:
        (root / p).mkdir(parents=True, exist_ok=True)
    return root


def test_check_warns_of_several_copies_of_one_collection(tmp_path):
    """A dataset folder, as in ashemery-case1-run01, holds collection, triage, and triage_more, each with the same
    host's folder, plus the collection's own suffixed folders. The warning names the folders and one host."""
    ev = folders(tmp_path / "ashemery", "collection/WIN-7Q2K4M/Windows/System32", "collection/WIN-7Q2K4M/Users/Administrator",
                 "collection/WIN-7Q2K4M_logs/Windows/Logs", "collection/WIN-7Q2K4M_mft",
                 "triage/WIN-7Q2K4M/Windows/System32", "triage/WIN-7Q2K4M/Users",
                 "triage_more/WIN-7Q2K4M/Windows", "triage_more/WIN-7Q2K4M/xampp")
    (ev / "triage" / "WIN-7Q2K4M" / "Windows" / "System32" / "SYSTEM").write_bytes(b"regf")
    out = check(str(ev))["evidence"]
    assert out["ok"] and out["hosts"] == ["collection", "triage", "triage_more"]
    assert out["warning"] == ("collection, triage, and triage_more each hold a host folder of their own, such as "
                              "WIN-7Q2K4M. Choose the folder that holds one copy of each host.")
    # One copy, chosen as the warning asks: no warning. (collection, which splits the host across suffixed folders,
    # is a layout this rule doesn't cover.)
    assert check(str(ev / "triage"))["evidence"]["warning"] == ""
    # Two copies of a KAPE collection, whose host folders hold their volume under a drive letter (HOST\C\Windows):
    # they warn.
    kape = folders(tmp_path / "kape", *(f"{t}/DC01/{sub}" for t in ("kape", "kape_rerun")
                                        for sub in ("C/Windows/System32", "C/Users", "Modules/EventLogs")))
    assert check(str(kape))["evidence"]["warning"].startswith(
        "kape and kape_rerun each hold a host folder of their own, such as DC01. Choose")
    # Two copies read "A and B"; past three, the rest are counted. The example is the host with the most copies,
    # in any letter case, then the first by name.
    two = folders(tmp_path / "two", "triage/sensei/Users", "triage_more/SENSEI/Windows")
    assert check(str(two))["evidence"]["warning"].startswith("triage and triage_more each hold a host folder of their "
                                                             "own, such as sensei. Choose")
    five = folders(tmp_path / "five", *(f"{t}/DC01/Windows" for t in ("collection", "pilot", "triage", "triage10", "z")),
                   *(f"{t}/DESKTOP/Windows" for t in ("collection", "triage")), "images/DC01/E01-DC01")
    assert check(str(five))["evidence"]["warning"].startswith(
        "collection, pilot, triage, and 2 more folders each hold a host folder of their own, such as DC01.")
    four = folders(tmp_path / "four", *(f"{t}/WS01/Users" for t in "abcd"))
    assert check(str(four))["evidence"]["warning"].startswith("a, b, c, and 1 more folder each hold")


def test_no_copies_warning_for_a_folder_per_host_or_kape(tmp_path):
    """Layouts with one copy of each host share subfolder names too: the volume's own folders, a drive letter, and
    KAPE's target and module folders. None of them warns."""
    # A host folder holding its volume: a backup of the Users folder on each host is still one copy of each host.
    per_host = folders(tmp_path / "per_host", *(f"{h}/{sub}" for h in ("DC01", "WS01") for sub in (
        "Windows/System32", "Users/Administrator", "ProgramData", "inetpub/logs", "Backup/Users")))
    kape = folders(tmp_path / "kape", *(f"{h}/{sub}" for h in ("DC01", "WS01") for sub in (
        "C/Windows/System32", "C/Users", "tout/C/Windows", "mout/EventLogs", "Modules/EventLogs", "Modules/ProgramExecution")))
    # Other names a volume's copy may sit under, each holding Windows or Users: none of them is a host (vol1, p1, and
    # C_drive among them). KAPE's tout holds a drive letter, so it would pass for a host's folder and is named too.
    volumes = folders(tmp_path / "volumes", *(f"{h}/{sub}" for h in ("DC01", "WS01") for sub in (
        "Windows.old/Windows", "vss1/Windows", "[root]/Windows", "C%3A/Users", "vol1/Windows", "Volume2/Users",
        "p1/Windows", "partition3/Users", "C_drive/Windows", "drive_d/Users", "mnt/Windows", "tout/C/Windows")))
    # The same host's folder in two places, but only one holds a volume: a disk image beside its extracted files.
    image = folders(tmp_path / "image", "images/DC01/E01-DC01", "triage/DC01/Windows")
    # The evidence folder is itself one host's volume, as a mounted image is: ProgramData\Microsoft and
    # Windows\Microsoft both hold a Windows folder, but they aren't copies of a host named Microsoft.
    volume = folders(tmp_path / "volume", "Windows/Microsoft/Windows", "ProgramData/Microsoft/Windows", "Users/Public")
    for ev in (per_host, kape, volumes, image, volume):
        assert check(str(ev))["evidence"]["warning"] == "", ev.name


def test_copies_warning_gives_up_in_time(tmp_path, monkeypatch):
    """The copies warning has a time limit of its own, since the check of a folder with 27,184 top-level folders took
    8 s. Past COPIES_SECONDS it gives up without a warning, and the files still count."""
    ev = folders(tmp_path / "copies", "triage/DC01/Windows", "triage_more/DC01/Windows")
    (ev / "triage" / "DC01" / "Windows" / "SYSTEM").write_bytes(b"regf")
    assert check(str(ev))["evidence"]["warning"]
    monkeypatch.setattr(start, "COPIES_SECONDS", -1)
    out = check(str(ev))["evidence"]
    assert out["warning"] == "" and out["files"] == 1 and not out["partial"]


def test_the_count_stops_in_time_in_a_run_of_folders_with_no_files(tmp_path, monkeypatch):
    """The count's time limit is checked after each folder as well as each file, so a long run of folders that hold no
    files still stops in time: here, at the evidence folder itself, before the 50 empty folders and the file after
    them. A count that stops before any file says it stopped, not that the folder holds no files, which only a count
    that finished says."""
    ev = folders(tmp_path / "empty", *(f"e{i:02}" for i in range(50)), "zz")
    (ev / "zz" / "last.txt").write_bytes(b"last")
    assert check(str(ev))["evidence"]["files"] == 1
    assert check(str(folders(tmp_path / "none", "a")))["evidence"]["message"] == "The folder holds no files."
    monkeypatch.setattr(start, "CHECK_SECONDS", -1)
    out = check(str(ev))["evidence"]
    assert (out["files"], out["partial"]) == (0, True)
    assert out["message"] == ("The count stopped at its time limit before it reached a file, so the folder may still "
                              "hold files.")


def test_browse_lists_folders_only(tmp_path):
    ev = evidence_folder(tmp_path)
    out = browse(str(ev))
    assert out["folders"] == ["DC01", "WS01"] and out["parent"] == str(tmp_path)
    assert browse(str(tmp_path / "nope"))["message"] == "Folder not found."


def test_recent_cases_newest_first_without_duplicates(tmp_path):
    ev = evidence_folder(tmp_path)
    a = create_case(tmp_path / "a", "A", ev, "cody")
    b = create_case(tmp_path / "b", "B", ev, "cody")
    remember(a, 10)
    remember(b, 20)
    remember(a, 11)
    assert [(r["name"], r["events"], r["exists"]) for r in load_recent()[:2]] == [("A", 11, True), ("B", 20, True)]


def test_recent_cases_count_the_timeline_s_events_and_follow_each_load(synthetic_case):
    """Recent cases counts the timeline's events, not every row of the events table with Hayabusa's hit rows among them,
    when a case opens and after each load, so a case made on the start page reads its events after Run and load
    everything ready."""
    from types import SimpleNamespace

    from conftest import SEC, T0, WS_LOG, logon

    from glessner.events import load
    from glessner.server import Hub

    count = lambda: next(r["events"] for r in load_recent() if r["folder"] == str(synthetic_case.folder))
    hub = Hub(synthetic_case)
    try:
        assert count() == 12   # 8 logons and 4 registry values; not the Hayabusa hit
        load(synthetic_case.db_path, [logon(T0 + 1000 * SEC, 301, WS_LOG.replace("Security", "Other"))], host="DESKTOP",
             tool="evtxecmd", tool_version="t", run_id="r9", replaces_sources=[], staging_dir=synthetic_case.folder)
        hub.app.after_job(SimpleNamespace(results=[{"status": "ok", "loaded": True}], error=""))   # a Tools job that loaded it
        assert count() == 13
    finally:
        hub.app.con.close()


def test_a_recent_cases_list_that_can_t_be_written_fails_no_open_or_load(synthetic_case, tmp_path, monkeypatch, capsys):
    """The count is written after each load, so a Recent cases list that can't be written must not fail a Tools page job
    whose loads succeeded, or an import that did. The list is bookkeeping: the open and the load go on, and the console
    says the list wasn't updated. Here the settings folder is a file."""
    from types import SimpleNamespace

    from glessner.server import Hub

    settings = tmp_path / "settings"
    settings.write_text("not a folder")
    monkeypatch.setenv("GLESSNER_CONFIG_DIR", str(settings))
    hub = Hub(synthetic_case)
    try:
        loads = hub.app.loads
        hub.app.after_job(SimpleNamespace(results=[{"status": "ok", "loaded": True}], error=""))   # a Tools job that loaded
        assert hub.app.loads == loads + 1   # the derived tables were built again
    finally:
        hub.app.con.close()
    assert capsys.readouterr().err.count("Recent cases not updated") == 2   # the open and the load


def test_a_recent_cases_list_another_process_holds_is_not_written_over_as_empty(tmp_path, monkeypatch):
    """On Windows a read is refused while another process replaces recent.json (PermissionError). load_recent does not
    take that for no list, which would let remember write a list of one over up to 20 entries. A refused read is a
    missed update, with the old list as it was; the start page's own read goes on without a list."""
    from types import SimpleNamespace

    def case(name):
        return SimpleNamespace(folder=tmp_path / name, settings=SimpleNamespace(name=name, evidence_path="e", tools_folder=""))

    monkeypatch.setenv("GLESSNER_CONFIG_DIR", str(tmp_path / "config"))
    for name in "abc":
        remember(case(name), 1)
    listed = tmp_path / "config" / "recent.json"
    before = listed.read_bytes()
    real = Path.read_text

    def held(self, *args, **kwargs):
        if self.name == "recent.json":
            raise PermissionError(13, "The process cannot access the file because it is being used by another process")
        return real(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", held)
    with pytest.raises(PermissionError):
        remember(case("d"), 2)
    assert listed.read_bytes() == before and load_recent() == []
    monkeypatch.setattr(Path, "read_text", real)
    remember(case("d"), 2)
    assert [r["name"] for r in load_recent()] == ["d", "c", "b", "a"]


def test_forget_missing_takes_off_only_cases_whose_folder_is_gone(tmp_path, monkeypatch):
    """A case whose folder is gone comes off the recent list, the one named or every one, and recent.json is
    the only file that changes. A case whose case.yaml is there stays, even when named, and a folder that is there
    without its case.yaml keeps what it holds. The answer is the list as written, with no second read. The route,
    served, asks for a folder or `all`, and a list another process holds, at the read or at the replace, is left as it
    was, with the reason in a 400."""
    import threading
    from types import SimpleNamespace

    from glessner.server import start_forget

    def gone(name):
        remember(SimpleNamespace(folder=tmp_path / name, settings=SimpleNamespace(name=name, evidence_path="e",
                                                                                   tools_folder="")), 1)

    monkeypatch.setenv("GLESSNER_CONFIG_DIR", str(tmp_path / "config"))
    ev = evidence_folder(tmp_path)
    here = create_case(tmp_path / "here", "Here", ev, "cody")
    for name in ("a", "b", "c"):
        gone(name)
    remember(here, 2)
    (tmp_path / "c").mkdir()
    (tmp_path / "c" / "kept.txt").write_text("not a case")
    names = lambda: [r["name"] for r in load_recent()]
    assert start.forget_missing(str(here.folder))[0] == 0 and names() == ["Here", "c", "b", "a"]
    assert start.forget_missing(str(tmp_path / "b")) == (1, load_recent()) and names() == ["Here", "c", "a"]
    assert start.forget_missing(str(tmp_path / "b"))[0] == 0   # gone already
    with pytest.raises(ValueError, match=r"^Name the case to remove, or all\.$"):
        start_forget(None, {})
    assert start_forget(None, {"all": True}) == {"removed": 2, "recent": load_recent()} and names() == ["Here"]
    assert (tmp_path / "c" / "kept.txt").read_text() == "not a case" and (here.folder / "case.yaml").is_file()
    assert not list((tmp_path / "config").glob("recent.json.*"))   # no temporary file left
    # Served, as the page sends it
    gone("d")
    server, hub, _ = serve_start(0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]
    try:
        cookie = login(port, hub)
        res, body = request(port, "POST", "/api/start/forget", cookie=cookie, body={})
        assert res.status == 400 and json.loads(body)["error"] == "Name the case to remove, or all."
        res, body = request(port, "POST", "/api/start/forget", cookie=cookie, body={"folder": str(tmp_path / "d")})
        assert res.status == 200 and json.loads(body)["removed"] == 1 and names() == ["Here"]
    finally:
        server.shutdown()
        server.server_close()
    # A list another process holds: the read refused, then the replace
    gone("e")
    listed = tmp_path / "config" / "recent.json"
    before = listed.read_bytes()
    real = Path.read_text

    def held(self, *args, **kwargs):
        if self.name == "recent.json":
            raise PermissionError(13, "The process cannot access the file because it is being used by another process")
        return real(self, *args, **kwargs)

    def refused(path, data, shared=False):
        raise PermissionError(13, "The process cannot access the file because it is being used by another process")

    monkeypatch.setattr(Path, "read_text", held)
    with pytest.raises(ValueError, match=r"^The list wasn't changed: .*being used by another process"):
        start_forget(None, {"all": True})
    monkeypatch.setattr(Path, "read_text", real)
    monkeypatch.setattr(start, "write_atomically", refused)
    with pytest.raises(ValueError, match=r"^The list wasn't changed: .*being used by another process"):
        start_forget(None, {"all": True})
    assert listed.read_bytes() == before


def test_a_copy_whose_recent_cases_list_can_t_be_written_still_succeeds(synthetic_case, tmp_path, monkeypatch, capsys):
    """start_copy calls remember with the guard App.remember has, so a copy that was made and rebuilt is not reported
    as failed when recent.json can't be replaced. The list is bookkeeping: the copy is ready, and the console says the
    list wasn't updated."""
    monkeypatch.setenv("GLESSNER_CONFIG_DIR", str(tmp_path / "config"))

    def refused(path, data, shared=False):
        raise PermissionError(13, "The process cannot access the file because it is being used by another process")

    monkeypatch.setattr(start, "write_atomically", refused)
    target = tmp_path / "copy"
    job = start_copy({"source": str(synthetic_case.folder), "case_folder": str(target), "name": "Copy"}, "cody")
    for _ in range(600):
        if job.finished:
            break
        time.sleep(0.1)
    assert job.finished and not job.error and (target / "case.yaml").is_file()
    assert "Recent cases not updated" in capsys.readouterr().err


def wait_job(port, cookie):
    for _ in range(200):
        job = json.loads(request(port, "GET", "/api/start/job", cookie=cookie)[1])["job"]
        if job["finished"]:
            return job
        time.sleep(0.05)
    raise AssertionError("the job didn't finish")


def test_start_page_creates_takes_in_and_opens_a_case(tmp_path):
    ev = evidence_folder(tmp_path)
    server, hub, _ = serve_start(0)
    import threading
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]
    try:
        cookie = login(port, hub)
        res, body = request(port, "GET", "/", cookie=cookie)
        assert b"/js/start.js" in body   # no case open: the start page
        res, body = request(port, "GET", "/api/meta", cookie=cookie)
        assert res.status == 409 and json.loads(body)["no_case"]
        res, body = request(port, "POST", "/api/start/new", cookie=cookie, body={
            "name": "Acme", "evidence": str(ev), "case_folder": str(tmp_path / "cases" / "acme"), "tools": "", "host": "",
            "analyst": "  Ana Lyst  "})
        assert res.status == 200
        job = wait_job(port, cookie)
        assert job["opened"] and not job["error"] and job["result"]["files"] == 3
        assert open_case(tmp_path / "cases" / "acme").settings.analyst == "Ana Lyst"   # the analyst name is trimmed
        meta = json.loads(request(port, "GET", "/api/meta", cookie=cookie)[1])
        assert meta["case"] == "Acme" and meta["rows"] == 0
        res, body = request(port, "GET", "/", cookie=cookie)
        assert b"/js/main.js" in body   # a case open: its timeline
        assert b"/js/start.js" in request(port, "GET", "/start", cookie=cookie)[1]
        # A second case with the same folder is refused at once, not in the job.
        res, body = request(port, "POST", "/api/start/new", cookie=cookie, body={
            "name": "Again", "evidence": str(ev), "case_folder": str(tmp_path / "cases" / "acme")})
        assert res.status == 400 and "not empty" in json.loads(body)["error"]
        # Copy it, then open the copy.
        res, body = request(port, "POST", "/api/start/copy", cookie=cookie, body={
            "source": str(tmp_path / "cases" / "acme"), "case_folder": str(tmp_path / "cases" / "acme-copy"),
            "name": "Acme copy", "analyst": " "})
        assert res.status == 200
        job = wait_job(port, cookie)
        assert not job["error"] and job["result"] == {"runs": 0, "left_out": []}
        assert open_case(tmp_path / "cases" / "acme-copy").settings.analyst == getpass.getuser()   # none given
        assert open_case(tmp_path / "cases" / "acme-copy").settings.copied_from.startswith(str(tmp_path / "cases" / "acme"))
        res, body = request(port, "POST", "/api/start/open", cookie=cookie,
                            body={"folder": str(tmp_path / "cases" / "acme-copy")})
        assert json.loads(body)["job"]["kind"] == "open" and json.loads(body)["job"]["name"] == "Acme copy"
        job = wait_job(port, cookie)
        assert not job["error"] and job["opened"] and job["result"] == {"opened": "Acme copy"}
        info = json.loads(request(port, "GET", "/api/start", cookie=cookie)[1])
        assert [r["name"] for r in info["recent"][:2]] == ["Acme copy", "Acme"] and info["open_case"]["name"] == "Acme copy"
    finally:
        server.shutdown()
        server.server_close()
        if hub.app:
            hub.app.con.close()


def test_a_request_from_a_page_showing_another_open_is_refused_before_it_runs(synthetic_case, tmp_path):
    """A request runs only against the open it names. A second tab can open a copy of case A, which shares A's event
    IDs, and a tab still showing A must not mark, note, or change settings in the copy. Each open has an ID, which
    /api/meta gives; a request naming another open is answered 409 before its route runs, GET or POST, and one naming
    the open runs. A request without the ID, from a client other than the page, runs against the open case."""
    import shutil
    import threading

    from glessner.case import copy_case
    from glessner.journal import replay
    from glessner.server import CASE_HEADER, Hub, serve_hub

    copy = copy_case(synthetic_case, tmp_path / "copy", "Copy", "cody")
    shutil.copy2(synthetic_case.db_path, copy.db_path)   # the same events and IDs, as a copy's rebuild gives
    server, hub, _ = serve_hub(Hub(synthetic_case), 0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]
    try:
        cookie = login(port, hub)
        first = json.loads(request(port, "GET", "/api/meta", cookie=cookie)[1])
        uid = hub.app.con.execute("SELECT event_uid FROM events WHERE tool = 'evtxecmd' ORDER BY ts_us").fetchone()[0]
        res, body = request(port, "POST", "/api/start/open", cookie=cookie, body={"folder": str(copy.folder)})
        assert res.status == 200 and wait_job(port, cookie)["result"] == {"opened": "Copy"}
        stale = {CASE_HEADER: first["case_id"]}
        for method, path, body in (("POST", "/api/mark", {"uids": [uid], "value": "malicious"}),
                                   ("POST", "/api/note", {"uid": uid, "text": "from the first tab"}),
                                   ("POST", "/api/setting", {"name": "event_threshold", "value": 1000}),
                                   ("GET", "/api/lanes?groupby=host", None), ("GET", "/api/meta", None)):
            res, answer = request(port, method, path, cookie=cookie, body=body, headers=stale)
            assert res.status == 409 and json.loads(answer) == {
                "error": "Another case is open now: Copy. Reload the page to work on it; this page's request did nothing.",
                "case_changed": True}, path
        state = replay(copy.folder / "journal.jsonl")
        assert (state.marks, state.notes, state.settings) == ({}, {}, {})
        now = json.loads(request(port, "GET", "/api/meta", cookie=cookie)[1])   # a page loading afresh
        assert now["case"] == "Copy" and now["case_id"] != first["case_id"]
        res, _ = request(port, "POST", "/api/mark", cookie=cookie, body={"uids": [uid], "value": "malicious"},
                         headers={CASE_HEADER: now["case_id"]})
        assert res.status == 200 and replay(copy.folder / "journal.jsonl").marks[uid].value == "malicious"
        assert replay(synthetic_case.folder / "journal.jsonl").marks == {}
    finally:
        server.shutdown()
        server.server_close()
        if hub.app:
            hub.app.con.close()


def test_a_page_whose_case_was_opened_again_is_told_so(synthetic_case):
    """Each open has an ID of its own, so a page still showing a case that another tab opened again is refused, as it
    must be: its View filters belong to the old open. It is told that the case was opened again, not that another case
    is open."""
    import threading

    from glessner.server import CASE_HEADER, Hub, serve_hub

    server, hub, _ = serve_hub(Hub(synthetic_case), 0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]
    try:
        cookie = login(port, hub)
        first = json.loads(request(port, "GET", "/api/meta", cookie=cookie)[1])
        uid = hub.app.con.execute("SELECT event_uid FROM events WHERE tool = 'evtxecmd' ORDER BY ts_us").fetchone()[0]
        res, _ = request(port, "POST", "/api/start/open", cookie=cookie, body={"folder": str(synthetic_case.folder)})
        assert res.status == 200 and wait_job(port, cookie)["opened"]
        for method, path, body in (("POST", "/api/mark", {"uids": [uid], "value": "malicious"}),
                                   ("GET", "/api/lanes?groupby=host", None)):
            res, answer = request(port, method, path, cookie=cookie, body=body, headers={CASE_HEADER: first["case_id"]})
            assert res.status == 409 and json.loads(answer) == {
                "error": "This case was opened again in another tab or window. Reload the page to go on; this page's "
                         "request did nothing.", "case_changed": True}, path
        assert hub.app.journal.state.marks == {}
    finally:
        server.shutdown()
        server.server_close()
        if hub.app:
            hub.app.con.close()


def test_a_switch_of_case_lets_a_request_on_the_old_case_finish_without_holding_up_the_switch(synthetic_case, tmp_path):
    """The old App stays open until the requests on it end, so a request already running on it is answered, not
    refused with "Connection already closed", and the switch doesn't wait for a request holding the old lock, an
    import's whole length: the switch publishes the copy and returns while a request holds the old lock, the request's
    query runs, and the connection closes when the request leaves."""
    import threading

    import duckdb
    import pytest

    from glessner.case import copy_case
    from glessner.server import Hub

    copy = copy_case(synthetic_case, tmp_path / "copy", "Copy", "cody")
    hub = Hub(synthetic_case)
    old = hub.app
    holding, release, counted = threading.Event(), threading.Event(), []

    def in_flight():   # a request on the old case, inside its lock
        assert old.enter()
        try:
            with old.lock:
                holding.set()
                release.wait(10)
                counted.append(old.con.execute("SELECT count(*) FROM events").fetchone()[0])
        finally:
            old.leave()

    request_thread = threading.Thread(target=in_flight)
    request_thread.start()
    assert holding.wait(10)
    opener = threading.Thread(target=hub.open, args=(copy,))
    opener.start()
    try:
        opener.join(10)
        assert not opener.is_alive() and hub.app is not old   # published, and the switch didn't wait for the request
        assert old.con.execute("SELECT 1").fetchone() == (1,)   # the request's case is still open
        release.set()
        request_thread.join(10)
        assert counted and counted[0] > 0
        with pytest.raises(duckdb.Error):
            old.con.execute("SELECT 1")   # closed by the request that left last
    finally:
        release.set()
        request_thread.join(10)
        opener.join(10)
        hub.app.con.close()


def test_a_switch_of_case_closes_an_old_case_that_no_request_is_running_on_at_once(synthetic_case, tmp_path):
    """The old App's connection closes when the last request on it ends, and at once when none is running as the case
    switches; an App retired is passed over by any request that reads it after."""
    import duckdb
    import pytest

    from glessner.case import copy_case
    from glessner.server import Hub

    copy = copy_case(synthetic_case, tmp_path / "copy", "Copy", "cody")
    hub = Hub(synthetic_case)
    old = hub.app
    try:
        hub.open(copy)
        with pytest.raises(duckdb.Error):
            old.con.execute("SELECT 1")
        assert not old.enter() and old.inflight == 0
    finally:
        hub.app.con.close()


def test_a_request_running_on_the_old_case_answers_after_a_switch(synthetic_case, tmp_path, monkeypatch):
    """A request that read the old App before a switch and reaches its connection after the switch is answered, not
    refused with a 500. A request running on the old case when the switch comes finishes with its answer."""
    import threading

    from glessner import server
    from glessner.case import copy_case
    from glessner.server import Hub, serve_hub

    copy = copy_case(synthetic_case, tmp_path / "copy", "Copy", "cody")
    server_, hub, _ = serve_hub(Hub(synthetic_case), 0)
    threading.Thread(target=server_.serve_forever, daemon=True).start()
    port = server_.server_address[1]
    started, release, answers = threading.Event(), threading.Event(), []
    real_marks = server.api_marks

    def slow_marks(app, query):   # a read that comes back to its connection after the switch
        started.set()
        release.wait(10)
        return {"rows": app.reader().execute("SELECT count(*) FROM events").fetchone()[0], **real_marks(app, query)}

    monkeypatch.setitem(server.GET_ROUTES, "/api/marks", slow_marks)
    try:
        cookie = login(port, hub)

        def ask():
            answers.append(request(port, "GET", "/api/marks", cookie=cookie))

        asking = threading.Thread(target=ask)
        asking.start()
        assert started.wait(10)
        res, body = request(port, "POST", "/api/start/open", cookie=cookie, body={"folder": str(copy.folder)})
        assert res.status == 200 and wait_job(port, cookie)["result"] == {"opened": "Copy"}   # not held up by the request
        release.set()
        asking.join(10)
        (res, body), = answers
        assert res.status == 200 and json.loads(body)["rows"] > 0   # answered, not 500
    finally:
        release.set()
        server_.shutdown()
        server_.server_close()
        if hub.app:
            hub.app.con.close()


def test_a_request_that_read_the_old_app_before_a_switch_is_passed_to_the_new_one(synthetic_case, tmp_path, monkeypatch):
    """The Handler reads hub.app, and may begin on that App only after a switch retired it. Here the switch comes
    between the read and the begin; the request runs on the case that is open instead of on a closed connection."""
    import threading

    from glessner.case import copy_case
    from glessner.server import App, Hub, serve_hub

    copy = copy_case(synthetic_case, tmp_path / "copy", "Copy", "cody")
    server_, hub, _ = serve_hub(Hub(synthetic_case), 0)
    threading.Thread(target=server_.serve_forever, daemon=True).start()
    port = server_.server_address[1]
    real_enter = App.enter
    switched = []

    def enter_after_a_switch(self):
        if not switched:   # the first request's begin, on the App it read
            switched.append(True)
            hub.open(copy)
        return real_enter(self)

    monkeypatch.setattr(App, "enter", enter_after_a_switch)
    try:
        cookie = login(port, hub)
        res, body = request(port, "GET", "/api/meta", cookie=cookie)
        assert switched and res.status == 200 and json.loads(body)["case"] == "Copy"   # not 500
    finally:
        server_.shutdown()
        server_.server_close()
        if hub.app:
            hub.app.con.close()


def test_a_case_opened_again_waits_for_its_earlier_open_to_close_and_never_runs_beside_it(synthetic_case, tmp_path):
    """With the old App closing on whichever request leaves last, a reopen of the case (A to B to A) must not run while
    the first A's request is still on its connection: two Apps on one DuckDB instance collide on writes (transaction
    conflicts, 500), and a reopen racing the close fails on the file. The reopen of A waits for the first A to close,
    and a different case never waits."""
    import threading

    from glessner.case import copy_case
    from glessner.server import Hub

    other = copy_case(synthetic_case, tmp_path / "other", "Other", "cody")
    hub = Hub(synthetic_case)
    first = hub.app
    holding, release, opened = threading.Event(), threading.Event(), []

    def in_flight():   # a request on the first A that outlasts the switches
        assert first.enter()
        try:
            holding.set()
            release.wait(10)
        finally:
            first.leave()

    request_thread = threading.Thread(target=in_flight)
    request_thread.start()
    assert holding.wait(10)
    try:
        hub.open(other)   # A to B: B never waits
        assert not first.closed.is_set()
        opener = threading.Thread(target=lambda: opened.append(hub.open(synthetic_case)))
        opener.start()
        opener.join(1)
        assert opener.is_alive() and not opened   # B to A waits while the first A is open
        release.set()
        request_thread.join(10)
        opener.join(10)
        assert first.closed.is_set() and opened and opened[0] is hub.app and opened[0] is not first
    finally:
        release.set()
        request_thread.join(10)
        hub.app.con.close()


def test_a_case_opened_again_is_refused_when_its_earlier_open_does_not_close_in_time(synthetic_case, tmp_path, monkeypatch):
    """An import can hold the old App for minutes, so the reopen refuses with a message after a short wait; opening it
    again once the request is done works."""
    import pytest

    from glessner import server
    from glessner.case import copy_case
    from glessner.server import Hub

    monkeypatch.setattr(server, "REOPEN_WAIT_SECONDS", 0.2)
    other = copy_case(synthetic_case, tmp_path / "other", "Other", "cody")
    hub = Hub(synthetic_case)
    first = hub.app
    assert first.enter()
    try:
        hub.open(other)
        with pytest.raises(ValueError, match="still finishing a request"):
            hub.open(synthetic_case)
        assert hub.app.case.settings.name == "Other"   # the refusal left the open case alone
        first.leave()
        assert first.closed.is_set()
        assert hub.open(synthetic_case).case.folder == synthetic_case.folder
    finally:
        hub.app.con.close()


def test_intake_reports_progress(tmp_path):
    ev = evidence_folder(tmp_path)
    case = create_case(tmp_path / "case", "P", ev, "cody")
    seen = []
    intake(case, lambda done, total: seen.append((done, total)))
    assert seen == [(1, 3), (2, 3), (3, 3)]


def test_opening_a_case_is_a_job_the_page_can_poll(synthetic_case, monkeypatch):
    """/api/start/open answers at once with a job, as a new case and a copy do, and the open runs behind it. While it
    runs the job says "Opening" and the case's name; a second start job is refused meanwhile; a folder that isn't a
    case is refused at once, not as a job."""
    import threading

    from glessner.server import Hub

    server, hub, _ = serve_start(0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]
    inside, release = threading.Event(), threading.Event()
    real = Hub.open

    def slow(self, case, report=None):
        inside.set()
        assert release.wait(30)
        return real(self, case, report)

    monkeypatch.setattr(Hub, "open", slow)
    try:
        cookie = login(port, hub)
        res, body = request(port, "POST", "/api/start/open", cookie=cookie, body={"folder": str(synthetic_case.folder)})
        job = json.loads(body)["job"]
        assert res.status == 200 and inside.wait(10)
        assert (job["kind"], job["name"], job["stage"], job["finished"], job["opened"]) == (
            "open", synthetic_case.settings.name, "Opening", False, False)
        assert hub.app is None   # not open yet
        res, body = request(port, "POST", "/api/start/open", cookie=cookie, body={"folder": str(synthetic_case.folder)})
        assert res.status == 400 and "Still working on" in json.loads(body)["error"]
        release.set()
        job = wait_job(port, cookie)
        assert job["opened"] and not job["error"] and hub.app.case.settings.name == synthetic_case.settings.name
        res, body = request(port, "POST", "/api/start/open", cookie=cookie, body={"folder": str(synthetic_case.folder / "nope")})
        assert res.status == 400 and json.loads(body)["error"]
    finally:
        release.set()
        server.shutdown()
        server.server_close()
        if hub.app:
            hub.app.con.close()
