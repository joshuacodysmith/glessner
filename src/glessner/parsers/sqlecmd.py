"""Parses SQLECmd's CSV output: browser history, downloads, searches, typed URLs, and Windows notifications.

SQLECmd runs maps against the SQLite databases it finds and writes one CSV per map query and database, named
<time>_<CSVPrefix>_<BaseFileName>_<map Id>.csv, with the database's path in SourceFile. This parser reads only the maps
below, which convert every time to UTC in their SQL. Maps that convert to 'localtime', the zone of whatever machine ran
SQLECmd, such as the Windows Timeline map, are left out: WxTCmd reads that database in UTC.

The account is the profile folder the database sits in; the browser comes from its folder too (Chrome, Edge, Brave,
Firefox). A database read from the run's working copies is named by its evidence path, wherever the case folder is
now: the run's record names the copies' folder as it was when SQLECmd ran, and for a run whose record doesn't name it,
the path inside the run's own folder is read wherever that folder was.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from pathlib import Path, PureWindowsPath

from ..events import Event, to_us
from .common import ParseContext, evidence_relative, file_key, output_paths, profile_name, read_csv_rows

BROWSERS = (("google\\chrome", "Chrome"), ("microsoft\\edge", "Edge"), ("bravesoftware", "Brave"),
            ("mozilla\\firefox", "Firefox"))
TOAST_TEXT = re.compile(r"<text[^>]*>([^<]*)</text>")


def parse_sqlecmd(ctx: ParseContext) -> Iterator[Event]:
    for path in output_paths(ctx, "sqlecmd", "*.csv"):
        handler = _handler(path.name)
        if handler is None:
            continue   # a map this parser doesn't read
        seen: set = set()   # rows already read from this file, for maps that repeat a record
        for row in read_csv_rows(path):
            source = _source(row.get("SourceFile", ""), ctx)
            former = _source(row.get("SourceFile", ""), ctx, as_before=True) if ctx.former == 1 else source
            for ev in handler(row, source, profile_name(source), _browser(source), seen):
                if former != source:
                    ev.former = (former, ev.source_record)
                yield ev


def _handler(name: str) -> Callable | None:
    stem = Path(name).stem
    parts = stem.rsplit("_", 2)
    if len(parts) != 3:
        return None
    return MAPS.get((parts[1], parts[2].lower()))


def _source(path_text: str, ctx: ParseContext, as_before: bool = False) -> str:
    """The database's evidence path, also when SQLECmd read the run's working copy of it. The copies' folder is the one
    the run recorded, which stays right after the case is copied or moved. A run whose record doesn't name the folder is
    read against this case's own run folder, and then wherever that folder was: what follows
    runs\\<this run's ID>\\input\\ is the evidence path, so a case moved or copied with such a run reads as the evidence
    too, with the account it names. Format 1's rule, `as_before`, stopped at this case's folder, and gave
    the absolute path, and an account from it, for a case moved since (ParseContext.former)."""
    path = PureWindowsPath(path_text)
    for copies in (ctx.input_root, str(ctx.output_dir.parent / "input")):
        if copies and path.is_relative_to(PureWindowsPath(copies)):
            return path.relative_to(PureWindowsPath(copies)).as_posix()
    if not as_before:
        parts = [p.lower() for p in path.parts]
        folder = ["runs", ctx.output_dir.parent.name.lower(), "input"]
        for i in range(len(parts) - 3):   # with at least one part after the folder
            if parts[i:i + 3] == folder:
                return PureWindowsPath(*path.parts[i + 3:]).as_posix()
    return evidence_relative(path_text, ctx.evidence_root)


def _browser(source: str) -> str:
    s = source.replace("/", "\\").lower()
    return next((name for folder, name in BROWSERS if folder in s), "Browser")


def _event(row, source, user, ts_text, desc, record, message, *, code, path="", url=""):
    extra = {k: v for k, v in row.items() if v and k != "SourceFile"}
    return Event(ts_us=to_us(ts_text), ts_desc=desc, artifact="browser" if code != "notification" else "notification",
                 source_file=source, source_record=record, message=message, event_code=code, user_name=user,
                 file_path=path, file_key=file_key(path) if path else "", extra=extra or None)


def _visit(row, source, user, browser, time_col, record):
    title = f" ({row['URLTitle']})" if row.get("URLTitle") else f" ({row['Title']})" if row.get("Title") else ""
    if not to_us(row.get(time_col)):
        return
    yield _event(row, source, user, row.get(time_col), "URL visited", record,
                 f"{browser} visit: {row.get('URL', '')}{title}", code="visit")


def chromium_visits(row, source, user, browser, seen):
    yield from _visit(row, source, user, browser, "VisitTime (UTC)", f"visit|{row.get('VisitID') or row.get('ID', '')}")


def edge_navigation(row, source, user, browser, seen):
    yield from _visit(row, source, user, "Edge", "Last Visited Time", f"navigation|{row.get('ID', '')}")


def firefox_visits(row, source, user, browser, seen):
    yield from _visit(row, source, user, "Firefox", "VisitDate", f"visit|{row.get('VisitID', '')}")


def chromium_downloads(row, source, user, browser, seen):
    # The map joins the download's URL chain, so a redirected download repeats its row; one set of events per ID.
    key = (source, row.get("ID", ""))
    if key in seen:
        return
    seen.add(key)
    target, url = row.get("TargetPath", ""), row.get("DownloadURL") or row.get("SiteURL") or row.get("TabURL", "")
    what = f"{browser} download: {target} from {url}"
    for col, desc, tag in (("StartTime", "Download started", "start"), ("EndTime", "Download finished", "end"),
                           ("Opened", "Downloaded file opened", "opened")):
        if to_us(row.get(col)):
            yield _event(row, source, user, row.get(col), desc, f"download|{row.get('ID', '')}|{tag}", what,
                         code="download", path=target)


def firefox_downloads(row, source, user, browser, seen):
    what = f"Firefox download: {row.get('Target', '')} from {row.get('Source', '')}"
    for col, desc, tag in (("StartTime", "Download started", "start"), ("EndTime", "Download finished", "end")):
        if to_us(row.get(col)):
            yield _event(row, source, user, row.get(col), desc, f"download|{row.get('ID', '')}|{tag}", what,
                         code="download", path=row.get("Target", ""))


def firefox_download_places(row, source, user, browser, seen):
    if to_us(row.get("DateAdded")):
        yield _event(row, source, user, row.get("DateAdded"), "Download recorded",
                     f"downloadplace|{row.get('PlaceID', '')}|{row.get('Type', '')}",
                     f"Firefox download {row.get('Type', '').lower()}: {row.get('Content', '')} ({row.get('URL', '')})",
                     code="download")


def keyword_searches(row, source, user, browser, seen):
    if to_us(row.get("LastVisitTime")):
        yield _event(row, source, user, row.get("LastVisitTime"), "Search results last visited",
                     f"search|{row.get('KeywordID', '')}|{row.get('URLID', '')}",
                     f"{browser} search: {row.get('KeywordSearchTerm', '')} ({row.get('URL', '')})", code="search")


def omnibox_shortcuts(row, source, user, browser, seen):
    if to_us(row.get("LastAccessTime")):
        yield _event(row, source, user, row.get("LastAccessTime"), "Address bar entry last used",
                     f"shortcut|{row.get('ID', '')}",
                     f"{browser} address bar: typed {row.get('TextTyped', '')!r} for {row.get('URL', '')}", code="typed")


def notifications(row, source, user, browser, seen):
    if not to_us(row.get("ArrivalTime")):
        return
    text = " | ".join(t.strip() for t in TOAST_TEXT.findall(row.get("Payload", "")) if t.strip())[:300]
    app = row.get("Application") or row.get("HandlerId", "")
    yield _event(row, source, user, row.get("ArrivalTime"), "Notification arrived", f"notification|{row.get('ID', '')}",
                 f"Notification from {app}{': ' + text if text else ''}", code="notification")


MAPS: dict[tuple[str, str], Callable] = {
    ("HistoryVisits", "1f37cc07-2b10-4c80-b845-84708e4f7429"): chromium_visits,
    ("Downloads", "0b575bcf-ade3-44e5-8162-eb52a96c2b06"): chromium_downloads,
    ("KeywordSearches", "d968ece4-d24a-4baf-8f07-78da07727712"): keyword_searches,
    ("OmniboxShortcuts", "0e137968-371b-4078-9440-a94b3dcf0d2f"): omnibox_shortcuts,
    ("NavigationHistory", "4231f387-d112-458d-8a19-704e91125ea78"): edge_navigation,
    ("History", "2f34be88-08d0-43c1-a2fd-60fe0b71f32b"): firefox_visits,
    ("History", "e493912d-c5ea-47c7-b9d4-32f7e185931f"): firefox_visits,
    ("Downloads-DownloadsDB", "163ac574-ab35-4509-b925-f8a14a470d4a"): firefox_downloads,
    ("Downloads-PlacesDB", "f5d66594-1b5a-45f7-8cdf-57d76d646649"): firefox_download_places,
    ("NotificationsDB-Notifications", "cd952d69-7b3e-4d13-9810-8d987155bc58"): notifications,
}
