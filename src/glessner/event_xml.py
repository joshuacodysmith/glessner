"""Converts Windows event XML into the CSV layout EvtxECmd writes.

Windows event XML comes from `wevtutil qe /f:xml`, Event Viewer's Save as XML, SIEM exports, and EvidenceForge, Cisco
Talos's synthetic log generator (https://github.com/Cisco-Talos/EvidenceForge). Neither EvtxECmd nor Hayabusa reads it,
and Chainsaw 2.16.5 loaded EvidenceForge's files but parsed no events from them. This module is the built-in tool that
reads it: the runner starts it with the app's own Python, like any registry tool, so the run gets the same record,
output hashes, and evidence check. Its CSV goes through the EvtxECmd parser, so events get the same fields: accounts,
logon types, IPs and ports, processes, and Sysmon's network fields.

Usage: python -I -m glessner.event_xml <file listing the inputs, one per line> <output folder>

The files may have an <Events> root, as Event Viewer and EvidenceForge write them, or be bare <Event> elements one
after another, as wevtutil writes them. Each is read in chunks, wrapped in a root of our own, so memory stays flat and a
DOCTYPE, which Windows event XML never has, fails to parse instead of expanding entities. A file that doesn't parse
fails the run with exit code 3 and the reason on stderr; the events read before the error aren't loaded.

The message columns are a short description per event ID and a summary of the fields that identify the event. They're
not EvtxECmd's maps, which this module doesn't have.
"""

from __future__ import annotations

import csv
import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

from .identify import text_encoding

OUTPUT_FILE = "event_xml.csv"
COLUMNS = ("SourceFile", "TimeCreated", "EventId", "Level", "Provider", "Channel", "ProcessId", "ThreadId", "Computer",
           "UserId", "EventRecordId", "MapDescription", "PayloadData1", "PayloadData2", "ExecutableInfo", "Payload")
CHUNK = 1 << 20
ROOT = "twxmlroot"   # the wrapper element; never a Windows event element name

SECURITY = "Microsoft-Windows-Security-Auditing"
SYSMON = "Microsoft-Windows-Sysmon"
DESCRIPTIONS = {
    SECURITY: {
        "1102": "Audit log cleared", "4624": "Successful logon", "4625": "Failed logon", "4634": "Logoff",
        "4647": "User-initiated logoff", "4648": "Logon with explicit credentials",
        "4672": "Special privileges assigned to new logon", "4688": "Process created", "4689": "Process exited",
        "4697": "Service installed", "4698": "Scheduled task created", "4720": "User account created",
        "4728": "Member added to a global security group", "4732": "Member added to a local security group",
        "4756": "Member added to a universal security group", "4768": "Kerberos TGT requested",
        "4769": "Kerberos service ticket requested", "4771": "Kerberos pre-authentication failed",
        "4776": "Credential validation (NTLM)", "4778": "Session reconnected", "4779": "Session disconnected",
        "4800": "Workstation locked", "4801": "Workstation unlocked", "5140": "Network share accessed",
        "5145": "Network share object checked", "5156": "Filtering Platform allowed a connection",
        "5157": "Filtering Platform blocked a connection",
    },
    SYSMON: {
        "1": "Process creation", "2": "File creation time changed", "3": "Network connection", "5": "Process terminated",
        "6": "Driver loaded", "7": "Image loaded", "8": "CreateRemoteThread", "10": "Process accessed",
        "11": "File created", "12": "Registry object added or deleted", "13": "Registry value set",
        "15": "File stream created", "17": "Pipe created", "18": "Pipe connected", "22": "DNS query",
        "23": "File deleted", "25": "Process tampering", "26": "File delete logged",
    },
    "Service Control Manager": {"7045": "Service installed"},
}


def local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def child(elem: ET.Element, name: str) -> ET.Element | None:
    return next((c for c in elem if local(c.tag) == name), None)


def text_of(elem: ET.Element | None) -> str:
    return (elem.text or "").strip() if elem is not None else ""


def tree(elem: ET.Element):
    """An element as nested dicts of its children's local names, with repeated names as lists; a leaf as its text."""
    kids = list(elem)
    if not kids:
        return text_of(elem)
    out: dict = {}
    for k in kids:
        name, value = local(k.tag), tree(k)
        if name in out:
            out[name] = out[name] if isinstance(out[name], list) else [out[name]]
            out[name].append(value)
        else:
            out[name] = value
    return out


def row_for(event: ET.Element, source: str) -> dict[str, str]:
    system = child(event, "System")
    sys_ = system if system is not None else ET.Element("System")
    provider = child(sys_, "Provider")
    created = child(sys_, "TimeCreated")
    execution = child(sys_, "Execution")
    security = child(sys_, "Security")
    payload: dict = {}
    fields: dict[str, str] = {}
    event_data = child(event, "EventData")
    if event_data is not None:
        data = []
        for i, d in enumerate((d for d in event_data if local(d.tag) == "Data"), 1):
            name = d.get("Name") or f"Data{i}"   # some providers write unnamed values
            data.append({"@Name": name, "#text": text_of(d)})
            fields[name] = text_of(d)
        payload["EventData"] = {"Data": data}
    user_data = child(event, "UserData")
    if user_data is not None:
        payload["UserData"] = tree(user_data)
    error_data = child(event, "ProcessingErrorData")   # data that didn't fit the provider's template
    if error_data is not None:
        payload["ProcessingErrorData"] = tree(error_data)
    provider_name = provider.get("Name", "") if provider is not None else ""
    code = text_of(child(sys_, "EventID"))
    channel = text_of(child(sys_, "Channel"))
    info = child(event, "RenderingInfo")   # in rendered exports, such as wevtutil /f:RenderedXml
    rendered = text_of(child(info, "Message")).split("\n", 1)[0][:120] if info is not None else ""
    return {
        "SourceFile": source,
        "TimeCreated": created.get("SystemTime", "") if created is not None else "",
        "EventId": code,
        "Level": text_of(child(sys_, "Level")),
        "Provider": provider_name,
        "Channel": channel,
        "ProcessId": execution.get("ProcessID", "") if execution is not None else "",
        "ThreadId": execution.get("ThreadID", "") if execution is not None else "",
        "Computer": text_of(child(sys_, "Computer")),
        "UserId": security.get("UserID", "") if security is not None else "",
        "EventRecordId": text_of(child(sys_, "EventRecordID")),
        "MapDescription": DESCRIPTIONS.get(provider_name, {}).get(code) or rendered,
        "PayloadData1": _account(fields),
        "PayloadData2": detail(fields, addresses=not sysmon_network(provider_name, channel, code)),
        "ExecutableInfo": next((fields[k] for k in ("CommandLine", "NewProcessName", "Image", "ProcessName",
                                                    "Application") if fields.get(k)), ""),
        "Payload": json.dumps(payload, ensure_ascii=False) if payload else "",
    }


def _account(f: dict[str, str]) -> str:
    for label, domain, name in (("Target", "TargetDomainName", "TargetUserName"),
                                ("Subject", "SubjectDomainName", "SubjectUserName")):
        if f.get(name) and f[name] != "-":
            return f"{label}: {f[domain]}\\{f[name]}" if f.get(domain) and f[domain] != "-" else f"{label}: {f[name]}"
    return f"User: {f['User']}" if f.get("User") else ""


def sysmon_network(provider: str, channel: str, code: str) -> bool:
    """Whether an event is a Sysmon network connection (3), whose direction and ends the EvtxECmd parser words for this
    reader's rows as for EvtxECmd's own, so the two read alike."""
    return code == "3" and (provider == SYSMON or channel.startswith(SYSMON))


def endpoint(ip: str, port: str) -> str:
    """An address and its port, an IPv6 address in brackets so its port reads apart from it, or the address alone for
    no port, 0, or '-'. The EvtxECmd parser words Sysmon 3's ends with it too."""
    if not port or port in ("0", "-"):
        return ip
    return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"


def detail(f: dict[str, str], addresses: bool = True) -> str:
    """The PayloadData2 column: a logon type, the addresses unless the parser words them, and the event's target. The
    EvtxECmd parser words a Sysmon 3's detail again with it when it reads this reader's stored output."""
    parts = []
    if f.get("LogonType"):
        parts.append(f"LogonType {f['LogonType']}")
    src = f.get("SourceIp") or f.get("SourceAddress") or f.get("IpAddress") or ""
    src = "" if src == "-" else src   # logon events write "-" when there's no address
    sport = f.get("SourcePort") or f.get("IpPort") or ""
    dst = f.get("DestinationIp") or f.get("DestAddress") or ""
    dport = f.get("DestinationPort") or f.get("DestPort") or ""
    if addresses and src and dst:
        parts.append(f"{endpoint(src, sport)} -> {endpoint(dst, dport)}")
    elif addresses and src:
        parts.append(f"from {endpoint(src, sport)}")
    for key, label in (("QueryName", "Query"), ("TargetFilename", "File"), ("TargetObject", "Key"),
                       ("ServiceName", "Service"), ("TaskName", "Task")):
        if f.get(key):
            parts.append(f"{label}: {f[key]}")
            break
    else:
        if f.get("ShareName"):
            # As the EvtxECmd parser writes a share access, "Share: \\*\ADMIN$ (\??\C:\Windows) | Object: x.exe", so the
            # built-in share rules read both. A share with no local folder,
            # such as IPC$, has no parentheses: "Share: \\*\IPC$ | Object: svcctl".
            local = f.get("ShareLocalPath", "")
            share = f"Share: {f['ShareName']} ({local})" if local else f"Share: {f['ShareName']}"
            target = f.get("RelativeTargetName", "")
            parts.append(f"{share} | Object: {target}" if target else share)
    return ", ".join(parts)


def events_in(path: Path):
    """Yield each <Event> element in a file, freed after use, so memory stays flat on large exports."""
    with path.open("rb") as raw:
        encoding = text_encoding(raw.read(4))
    parser = ET.XMLPullParser(events=("start", "end"))
    parser.feed(f"<{ROOT}>")
    stack: list[ET.Element] = []
    with path.open(encoding=encoding, errors="replace", newline="") as f:
        first = True
        while True:
            chunk = f.read(CHUNK)
            if not chunk:
                break
            if first:   # drop the XML declaration, which can only come first and would sit inside our root
                first = False
                chunk = chunk.lstrip("\ufeff \t\r\n")
                if chunk.startswith("<?xml"):
                    end = chunk.find("?>")
                    chunk = chunk[end + 2:] if end >= 0 else chunk
            parser.feed(chunk)
            yield from _drain(parser, stack)
        parser.feed(f"</{ROOT}>")
        parser.close()
        yield from _drain(parser, stack)


def _drain(parser: ET.XMLPullParser, stack: list[ET.Element]):
    for kind, elem in parser.read_events():
        if kind == "start":
            stack.append(elem)
            continue
        stack.pop()
        if local(elem.tag) == "Event":
            yield elem
            if stack:
                stack[-1].remove(elem)


def convert(inputs: list[Path], output_dir: Path) -> int:
    rows = 0
    with (output_dir / OUTPUT_FILE).open("w", encoding="utf-8", newline="") as out:
        writer = csv.DictWriter(out, COLUMNS)
        writer.writeheader()
        for path in inputs:
            n = 0
            try:
                for event in events_in(path):
                    writer.writerow(row_for(event, str(path)))
                    n += 1
            except (ET.ParseError, UnicodeError) as exc:
                raise ValueError(f"{path}: {exc}, after {n} events") from exc
            print(f"{path}: {n} events")
            rows += n
    return rows


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__.split("\n\n")[2], file=sys.stderr)
        return 2
    inputs = [Path(line) for line in Path(argv[0]).read_text(encoding="utf-8").splitlines() if line.strip()]
    try:
        rows = convert(inputs, Path(argv[1]))
    except (ValueError, OSError) as exc:
        print(f"Could not read the event XML: {exc}", file=sys.stderr)
        return 3
    print(f"{rows} events from {len(inputs)} files")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
