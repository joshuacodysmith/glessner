"""Parses EvtxECmd CSV output.

Fields come from the Payload JSON by name. The PayloadData columns hold display strings such as
"LogonType 3" and are used only to build the one-line message.

EvtxECmd writes values as the event's XML holds them, so &gt;, &lt;, and &amp; stand for the characters, and task XML
carried in event data has them twice (&amp;gt;). Payload values and the message columns are unescaped once, so command
lines, messages, and raw fields show the event's own text. The built-in XML reader
(event_xml.py) writes text its XML parser has already decoded, so its rows aren't unescaped again.
"""

from __future__ import annotations

import html
import re
from collections.abc import Iterator
from xml.etree import ElementTree

from ..event_xml import detail, endpoint, sysmon_network
from ..events import Event, to_us
from .common import (
    ParseContext,
    clean,
    command_file,
    evidence_relative,
    file_key,
    ip_and_port,
    is_digits,
    output_paths,
    payload_fields,
    payload_text,
    port_number,
    read_csv_rows,
)

OUTPUT_FILE = "evtxecmd.csv"
SYSMON = "Microsoft-Windows-Sysmon"
# The message's parts after the event's description: EvtxECmd's map columns, and parts the parser adds: "parent" (the
# parent process's file name), "auth" (a logon's authentication package), and "task" (what a scheduled task
# runs). PayloadData3 to 6 come last, so messages other than Sysmon's start with PayloadData1 and 2. A share or object
# access's rights by name take the place of the map's own "AccessList:" part, and nothing is added where the map has
# none.
MAP_COLUMNS = ("PayloadData1", "PayloadData2", "auth", "ExecutableInfo", "PayloadData3", "PayloadData4", "PayloadData5",
               "PayloadData6")
# Windows' names for the rights a 5145 or 4663 lists as %% codes. EvtxECmd's map names a single code but writes
# "Unknown code (%%1537 | %%4423 ...)" for a list, so these names are what tell a share's writes from its reads.
ACCESS_NAMES = {"%%1537": "DELETE", "%%1538": "READ_CONTROL", "%%1539": "WRITE_DAC", "%%1540": "WRITE_OWNER",
                "%%1541": "SYNCHRONIZE", "%%1542": "ACCESS_SYS_SEC", "%%4416": "ReadData", "%%4417": "WriteData",
                "%%4418": "AppendData", "%%4419": "ReadEA", "%%4420": "WriteEA", "%%4421": "Execute",
                "%%4422": "DeleteChild", "%%4423": "ReadAttributes", "%%4424": "WriteAttributes"}
ACCESS_CODE = re.compile(r"%%\d+")
# Scheduled task created, deleted, enabled, disabled, and updated: the task's XML is in TaskContent, or TaskContentNew
# for 4702, and EvtxECmd writes all of it into the message after the task's name.
TASK_EVENTS = {"4698", "4699", "4700", "4701", "4702"}
TASK_ORDER = ("PayloadData1", "task") + tuple(c for c in MAP_COLUMNS if c not in ("PayloadData1", "PayloadData2"))
XML_DECLARATION = re.compile(r"^\s*<\?xml[^>]*\?>")
DEFAULT_NAMESPACE = re.compile(r'\sxmlns="[^"]*"')
TAG_LINE_BREAK = re.compile(r">,\s*<")
# Sysmon's maps put the process ID and GUID in PayloadData1, the rule name in PayloadData2, and the event's target (an
# address, file, key, or value) in PayloadData3 to 6, so the 160 characters lists show would hold no target. The
# parts that lead each Sysmon event's message, from EvtxECmd's maps; the rest follow in MAP_COLUMNS order.
FILE_THEN_IMAGE = ("PayloadData4", "ExecutableInfo")
SYSMON_FIRST = {
    "1": ("parent", "ExecutableInfo", "PayloadData6", "PayloadData4"),   # command line, parent's command line, image
    "2": ("PayloadData4", "PayloadData3", "PayloadData5", "PayloadData6"),   # file, image, new and previous times
    # Whether the process opened the connection or accepted it, then each end with its port as Sysmon labels it, then
    # their names. Older Sysmon writes the local side as the source either way, so on an inbound connection the
    # remote address is the destination; the direction says which case the analyst is reading.
    "3": ("direction", "source", "destination", "PayloadData3", "PayloadData5"),
    "5": ("ExecutableInfo",),
    "6": ("ExecutableInfo", "PayloadData4", "PayloadData5", "PayloadData6"),   # driver, signed, signature, its status
    "7": ("ExecutableInfo", "PayloadData5", "PayloadData4"),   # the DLL, the image loading it, signed
    "8": ("PayloadData4", "PayloadData6", "PayloadData1"),   # source image, target image, start address
    "9": ("PayloadData3", "PayloadData2"),   # image, device
    "10": ("PayloadData4", "PayloadData6", "PayloadData2", "ExecutableInfo"),   # source, target, access, call trace
    "11": ("PayloadData4", "PayloadData3"),   # file, image
    "12": ("PayloadData4", "PayloadData5", "PayloadData3"),   # created or deleted, key, image
    # The data, then the key and value name, then the image. A user's key runs past 110 characters (HKU, a SID, then
    # RunMRU), so with the key first, the command typed over RDP started after character 160.
    "13": ("PayloadData6", "PayloadData5", "PayloadData3"),
    "14": ("PayloadData5", "PayloadData6", "PayloadData3"),   # key, new name, image
    "15": ("PayloadData4", "PayloadData3", "PayloadData5"),   # file, image, stream hash
    "17": ("PayloadData2", "PayloadData5"), "18": ("PayloadData2", "PayloadData5"),   # pipe, image
    "19": ("PayloadData4", "ExecutableInfo"), "20": ("PayloadData4", "ExecutableInfo"),   # name, query or destination
    "21": ("PayloadData4", "PayloadData5"),   # consumer, filter
    "22": ("PayloadData4", "PayloadData6", "PayloadData3"),   # query, results, image
    "23": FILE_THEN_IMAGE, "26": FILE_THEN_IMAGE, "27": FILE_THEN_IMAGE, "28": FILE_THEN_IMAGE, "29": FILE_THEN_IMAGE,
    "24": ("ExecutableInfo", "PayloadData4", "PayloadData5"),   # image, session, client
    "25": ("ExecutableInfo", "PayloadData6"),   # image, tampering type
}
REPLACED = {"3": ("PayloadData4", "PayloadData6")}   # the map's IP-only parts, which "source" and "destination" replace
SYSMON_ORDER = {code: first + tuple(c for c in MAP_COLUMNS if c not in first and c not in REPLACED.get(code, ()))
                for code, first in SYSMON_FIRST.items()}
DIRECTION = {"true": "outbound", "false": "inbound"}   # Sysmon's Initiated
# The XML reader's own columns (event_xml.py): an account, then a detail such as the logon type and address.
# The XML reader writes no "AccessList:" part, so a share access's rights go after its account and detail.
XML_READER_PARTS = ("parent", "PayloadData1", "PayloadData2", "auth", "access", "task", "ExecutableInfo")
# A Sysmon 3 from the XML reader leads with its direction and ends, worded here as for EvtxECmd's rows; the reader's
# detail leaves them out.
XML_NETWORK_PARTS = SYSMON_FIRST["3"][:3] + XML_READER_PARTS
GUID = re.compile(r",\s*\w*ProcessGUID:\s*\S*")   # from Sysmon's "ProcessID: 4, ProcessGUID: {...}"; extra keeps it
PLACEHOLDER = re.compile(r"^[A-Za-z][\w ]{0,40}:\s*-?$")   # a label without a value, such as "RuleName: -"
# The account in the event's System element (EvtxECmd's UserId), for events whose data names none: a remote service's
# installer (7045), WinRM 91, MSSQL 15281. Only a user account's SID, local or domain
# (S-1-5-21) or Entra ID (S-1-12-1); LocalSystem and the service accounts are the service's own. The parser writes the
# SID as recorded, since in one pass it could only use rows before it; after the load, accounts.py names it from the
# same host's 4624s and 4672s where they record it.
ACCOUNT_SID = re.compile(r"^S-1-(?:5-21|12-1)(?:-\d+)+$")
# Sysmon's LogonId gives a process its logon session, except LocalSystem's, NetworkService's, and
# LocalService's, which every service on a host shares: joined on, they'd tie unrelated events together.
SYSTEM_SESSIONS = {"0x3e7", "0x3e4", "0x3e5"}
NO_LOGON = re.compile(r"^0x0+$|^0$", re.IGNORECASE)   # 0x0 is no logon session
# Events whose pivot fields the parser reads from more of their data. A group change's Subject is who made it, and its
# Target is the group, so Same account would lead to the group's lookups and not to the person.
GROUP_CHANGES = {"4728", "4729", "4732", "4733", "4756", "4757"}
RDP_SESSION_EVENTS = {"4778", "4779"}   # reconnect and disconnect: AccountName, AccountDomain, LogonID, ClientAddress
LOCAL_SESSION_MANAGER = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"
DEFENDER_DETECTIONS = {"1116", "1117"}
OBJECT_ACCESS = {"4656", "4660", "4663"}
# Defender's Path: "file:_C:\x.exe", with other kinds of target after "; " (containerfile:_, webfile:_, regkey:_), and a
# file inside an archive as "archive->file"
DEFENDER_FILE = re.compile(r"^(?:file|containerfile):_(.+)$", re.IGNORECASE)
# For an event EvtxECmd has no map for, the message takes the event's first fields, each cut to this length.
UNMAPPED_PARTS, UNMAPPED_LENGTH = 4, 120
UNNAMED = re.compile(r"^Data\d*$")   # unnamed values, shown without a label
NOT_SHOWN = {"EventPayload", "SecurityUserID"}   # hex, and the account the event already has


def parse_evtxecmd(ctx: ParseContext) -> Iterator[Event]:
    for path in output_paths(ctx, "evtxecmd", OUTPUT_FILE):
        for row in read_csv_rows(path):
            yield event_from_row(row, ctx)


def parse_event_xml(ctx: ParseContext) -> Iterator[Event]:
    """The built-in Windows event XML reader's output, written in EvtxECmd's layout (event_xml.py)."""
    for row in read_csv_rows(ctx.output_dir / "event_xml.csv"):
        yield event_from_row(row, ctx, xml_reader=True)


def event_from_row(row: dict[str, str], ctx: ParseContext, xml_reader: bool = False) -> Event:
    raw = row.get("Payload")
    fields = payload_fields(raw)
    if not xml_reader and raw and "&" in raw:   # JSON leaves & as it is, so a payload without one holds no entity
        fields = {k: html.unescape(v) for k, v in fields.items()}
    if "EventPayload" in fields:   # ProcessingErrorData's hex, read as text
        text = payload_text(fields["EventPayload"])
        if text:
            fields["EventPayloadText"] = text
    code = row.get("EventId", "")
    user, domain = _account(code, fields)
    user_sid = clean(row.get("UserId"))
    if ACCOUNT_SID.match(user_sid):
        fields["SecurityUserID"] = user_sid
        if not user:
            user = user_sid
    # RdpCoreTS 131 (a TCP connection accepted, before any logon) gives ClientIP as IP:port; 4624, 4625, 4768, and 4769
    # give the port apart, as IpPort. 131 draws no logon arrow. Network events give
    # both ends: Sysmon 3 as SourceIp and DestinationIp, the Filtering Platform's 5156 and 5157 as SourceAddress and
    # DestAddress. They're kept as the event records them, so source is the side the event calls the source.
    source_ip, source_port = ip_and_port(fields.get("IpAddress") or fields.get("ClientIP")
                                         or (fields.get("Param3") if code == "1149" else "")
                                         or (fields.get("ClientAddress") if code in RDP_SESSION_EVENTS else "")
                                         or (fields.get("Address") if row.get("Channel") == LOCAL_SESSION_MANAGER else "")
                                         or fields.get("SourceIp") or fields.get("SourceAddress"))
    source_port = source_port or port_number(fields.get("IpPort") or fields.get("SourcePort"))
    dest_ip, dest_port = ip_and_port(fields.get("DestinationIp") or fields.get("DestAddress"))
    dest_port = dest_port or port_number(fields.get("DestinationPort") or fields.get("DestPort"))
    # The parent: Sysmon 1's ParentImage, or 4688's ParentProcessName from Windows 10 on.
    parent = _known(fields.get("ParentImage") or fields.get("ParentProcessName"))
    # Access rights by name, beside Windows' codes in extra. Only rows with an access list pay for it.
    access = ""
    if "AccessList" in fields:
        access = ", ".join(ACCESS_NAMES.get(c, c) for c in ACCESS_CODE.findall(fields["AccessList"]))
        if access:
            fields["AccessNames"] = access
    task = _task_action(fields.get("TaskContent") or fields.get("TaskContentNew")) if code in TASK_EVENTS else None
    if task:
        fields.update({f"Task{k.capitalize()}": task[k] for k in ("command", "arguments", "principal") if task[k]})
    message = _message(code, row, fields, parent, xml_reader, access, task)
    record = row.get("EventRecordId", "")
    # The file an event is about: Sysmon 11's file, a 5145's file on the share, Sysmon 7's loaded DLL, or a service's
    # binary. For Sysmon 7, Same file then reaches the DLL; the loading process stays the process.
    target_file = (clean(fields.get("TargetFilename"))
                   or (_share_file(fields) if "ShareLocalPath" in fields else "")
                   or clean(fields.get("ImageLoaded"))
                   or (command_file(fields.get("ImagePath") or fields.get("ServiceFileName"))
                       if code in ("7045", "4697") else "")
                   or (_defender_file(fields.get("Path")) if code in DEFENDER_DETECTIONS else "")
                   or (_object_file(fields) if code in OBJECT_ACCESS else ""))
    # Sysmon 10 names the accessing process SourceImage; 5156 and 5157 name it Application; a scheduled task, its
    # action's command, written out so its file key matches the program's other records.
    process = clean(fields.get("NewProcessName") or fields.get("ProcessName") or fields.get("Image")
                    or fields.get("SourceImage") or fields.get("Application")) or (
        command_file(task["command"]) if task else "") or (
        _defender_process(fields.get("Process Name")) if code in DEFENDER_DETECTIONS else "")
    command_line = clean(fields.get("CommandLine")) or (
        " ".join(p for p in (task["command"], task["arguments"]) if p) if task else "")
    return Event(
        ts_us=to_us(row.get("TimeCreated")),
        ts_desc="Event Recorded",
        artifact="evtx",
        source_file=evidence_relative(row.get("SourceFile", ""), ctx.evidence_root),
        source_record=record,
        record_id=int(record) if is_digits(record) else None,
        message=message.strip(),
        host_name_recorded=row.get("Computer", ""),
        event_code=code,
        event_provider=row.get("Provider", ""),
        log_channel=row.get("Channel", ""),
        user_name=user,
        user_domain=domain,
        source_ip=source_ip,
        source_port=source_port,
        dest_ip=dest_ip,
        dest_port=dest_port,
        source_workstation=clean(fields.get("WorkstationName") or (fields.get("Workstation") if code == "4776" else "")),
        logon_type=clean(fields.get("LogonType")),
        logon_id=_logon_id(fields) or _user_session(row, fields),
        process_executable=process,
        process_command_line=command_line,
        process_parent_executable=parent,
        process_parent_command_line=_known(fields.get("ParentCommandLine")),
        file_path=target_file,
        registry_path=clean(fields.get("TargetObject")),
        # Sysmon 13's Details is the data written. registry_value is a value's name, as RECmd fills it, and Sysmon
        # keeps the name at the end of TargetObject, so the data has a column of its own.
        # "Binary Data" is Sysmon's stand-in for data it didn't log, kept as written.
        registry_data=clean(fields.get("Details")) if fields.get("TargetObject") else "",
        extra=fields or None,
        file_key=file_key(target_file or process),
    )


def _message(code: str, row: dict[str, str], fields: dict[str, str], parent: str, xml_reader: bool,
             access: str = "", task: dict | None = None) -> str:
    """The event ID and description, then the message parts, a Sysmon event's target first. It runs on every
    row, so each step runs only where it can change a part; run on every part, they would make parsing half again as
    slow."""
    if xml_reader and sysmon_network(row.get("Provider", ""), row.get("Channel", ""), code):
        # Stored output from an older reader holds the ends in its detail too, and a rebuild or a case copy parses
        # stored output again without running the reader, so the detail is worded again from the fields.
        row = {**row, "PayloadData2": detail(fields, addresses=False)}
        order = XML_NETWORK_PARTS
    elif xml_reader:
        if fields.get("ShareName"):
            # Stored output from an older reader holds "Share: \\*\IPC$ () | Object: svcctl" in its detail, after its
            # address, so the detail is worded again from the fields, as for Sysmon 3 above.
            row = {**row, "PayloadData2": detail(fields)}
        order = XML_READER_PARTS
    elif row.get("Provider") == SYSMON or row.get("Channel", "").startswith(SYSMON):
        order = SYSMON_ORDER.get(code, MAP_COLUMNS)
    elif task:
        order = TASK_ORDER   # what the task runs, in place of its XML, which extra keeps
    else:
        order = MAP_COLUMNS   # 4688's map leads with "Parent process:" itself
    description = row.get("MapDescription") or row.get("Provider", "")
    bits = [description] if description and not PLACEHOLDER.match(description) else []
    head = len(bits)
    for column in order:
        if column == "parent":
            part = ("parent " + parent.replace("/", "\\").rsplit("\\", 1)[-1]) if parent else ""
        elif column == "auth":
            # 4624 and 4625 name the authentication package (NTLM, Kerberos, or Negotiate), which pass-the-hash checks
            # read.
            package = clean(fields.get("AuthenticationPackageName")) if code in ("4624", "4625") else ""
            part = f"AuthenticationPackage: {package}" if package else ""
        elif column == "access":   # the XML reader's rows only
            part = f"Access: {access}" if access and code == "5145" else ""
        elif column == "direction":
            part = DIRECTION.get(clean(fields.get("Initiated")).lower(), "")
        elif column in ("source", "destination"):
            end = "Source" if column == "source" else "Destination"
            ip = clean(fields.get(f"{end}Ip"))
            part = (f"{end}: {endpoint(ip, clean(fields.get(f'{end}Port')))}" if ip
                    else row.get("PayloadData4" if column == "source" else "PayloadData6") or "")
        elif column == "task":
            part = ""
            if task:
                more = f" (+{task['more']} more action{'s' if task['more'] > 1 else ''})" if task["more"] else ""
                part = "Runs: " + " ".join(p for p in (task["command"], task["arguments"]) if p) + more
        else:
            part = row.get(column)
            if not part:
                continue
            if access and part.startswith("AccessList:"):   # the rights by name, in the map's own place for them
                part = f"Access: {access}"
            # The 5140 and 5145 maps write "Share: \\*\IPC$ ()" for a share with no local folder
            if part.endswith(" ()") and part.startswith("Share: "):
                part = part[:-3]
            if not xml_reader and "&" in part:
                part = html.unescape(part)
            if not xml_reader and "GUID" in part and column != "ExecutableInfo":
                part = GUID.sub("", part)
        part = part.strip()   # as clean() does, with the placeholder check below
        if part and part != "-" and not (part[-1] in ":-" and PLACEHOLDER.match(part)):   # a bare label ends in : or -
            bits.append(part)
    # A 5145 always names its rights, even from a map version with no "AccessList:" part: the built-in share rules read
    # them.
    if access and code == "5145" and not any(b.startswith("Access: ") for b in bits):
        bits.append(f"Access: {access}")
    if not row.get("MapDescription") and len(bits) == head:   # no map, so only the ID and provider: the fields say more
        bits += _field_parts(fields)
    return f"{code} " + " | ".join(bits)


def _share_file(fields: dict[str, str]) -> str:
    """A 5145's file: the share's local folder joined with the path under it, such as C:\\Windows\\PSEXESVC.exe from
    ADMIN$. Nothing for IPC$, whose targets are pipes and which has no local folder, or for the share's own root."""
    local = clean(fields.get("ShareLocalPath"))
    relative = clean(fields.get("RelativeTargetName")).strip("\\")
    if not local or not relative:
        return ""
    return local.removeprefix("\\??\\").rstrip("\\") + "\\" + relative


def _task_action(xml_text: str | None) -> dict | None:
    """A scheduled task's first Exec action and the account it runs as, from its XML. XML with a DTD is left alone:
    task XML never carries one, and an entity declaration in evidence could blow up the parse."""
    text = clean(xml_text)
    if "<Task" not in text or "<!DOCTYPE" in text or "<!ENTITY" in text:
        return None
    # EvtxECmd joins the lines of a multi-line value with ", ", which between tags isn't XML; the lines go back
    # together there, so the task's XML parses.
    text = TAG_LINE_BREAK.sub("><", text)
    text = DEFAULT_NAMESPACE.sub("", XML_DECLARATION.sub("", text, count=1), count=1)
    try:
        root = ElementTree.fromstring(text)
    except ElementTree.ParseError:
        return None
    actions = root.findall("Actions/Exec")
    command = (actions[0].findtext("Command") or "").strip() if actions else ""
    if not command:
        return None
    # The command and arguments of the same action; read across all of them, a second action's arguments could pair
    # with the first's command. Later actions stay in extra, where search reaches them.
    return {"command": command, "arguments": (actions[0].findtext("Arguments") or "").strip(),
            "principal": (root.findtext("Principals/Principal/UserId") or "").strip(), "more": len(actions) - 1}


def _logon_id(fields: dict[str, str]) -> str:
    """The logon session: TargetLogonId, else SubjectLogonId, else an RDP session event's LogonID, skipping 0x0, which is
    no session. A 4688 holds a TargetLogonId of 0x0 when its creator and target share a logon, and its session is the
    Subject's. 0x0 is stored as none, so no pivot offers it."""
    for name in ("TargetLogonId", "SubjectLogonId", "LogonID"):
        value = clean(fields.get(name))
        if value and not NO_LOGON.match(value):
            return value
    return ""


def _defender_file(text: str | None) -> str:
    """The file a Defender detection names: the first "file:_" or "containerfile:_" target of its Path, and for a file
    inside an archive, the archive."""
    targets = [DEFENDER_FILE.match(t.strip()) for t in clean(text).split("; ")]
    found = next((m.group(1) for m in targets if m), "")
    return found.split("->", 1)[0].strip()


def _defender_process(text: str | None) -> str:
    """The process a Defender detection names; Defender writes "Unknown" for none."""
    name = clean(text)
    return "" if name.lower() == "unknown" else name


def _object_file(fields: dict[str, str]) -> str:
    """The object a 4656, 4660, or 4663 names, when it's a file: ObjectName beside ObjectType File. Same file on these
    events finds the file, not the process doing the access."""
    return clean(fields.get("ObjectName")) if clean(fields.get("ObjectType")).lower() == "file" else ""


def _user_session(row: dict[str, str], fields: dict[str, str]) -> str:
    logon_id = clean(fields.get("LogonId"))
    if not logon_id or logon_id.lower() in SYSTEM_SESSIONS or NO_LOGON.match(logon_id):
        return ""
    return logon_id if row.get("Provider") == SYSMON or row.get("Channel", "").startswith(SYSMON) else ""


def _field_parts(fields: dict[str, str]) -> list[str]:
    """An unmapped event's first fields as message parts, such as MSSQL's unnamed strings or WinRM's error data."""
    parts = []
    for name, value in fields.items():
        if name in NOT_SHOWN:
            continue
        whole = len(value) <= 2 * UNMAPPED_LENGTH
        value = " ".join(value[:2 * UNMAPPED_LENGTH].split())   # enough to fill a part after whitespace runs close up
        if not value or value == "-":
            continue
        value = value if whole and len(value) <= UNMAPPED_LENGTH else value[:UNMAPPED_LENGTH - 3] + "..."
        parts.append(value if UNNAMED.match(name) else f"{name}: {value}")
        if len(parts) == UNMAPPED_PARTS:
            break
    return parts


def _known(text: str | None) -> str:
    """A parent's name or command line. Sysmon writes "?" for a parent it couldn't resolve, which extra keeps."""
    text = clean(text)
    return "" if text == "?" else text


def _account(code: str, fields: dict[str, str]) -> tuple[str, str]:
    """Target account for logon-style events, subject account otherwise. A group change's account is who made it, and an
    RDP session event's is its AccountName."""
    if code in GROUP_CHANGES and clean(fields.get("SubjectUserName")):
        return clean(fields["SubjectUserName"]), clean(fields.get("SubjectDomainName"))
    if code in RDP_SESSION_EVENTS and clean(fields.get("AccountName")):
        return clean(fields["AccountName"]), clean(fields.get("AccountDomain"))
    if clean(fields.get("TargetUserName")):
        return clean(fields["TargetUserName"]), clean(fields.get("TargetDomainName"))
    if code == "1149" and clean(fields.get("Param1")):   # RDP authentication succeeded, in UserData
        return clean(fields["Param1"]), clean(fields.get("Param2"))
    if clean(fields.get("SubjectUserName")):
        return clean(fields["SubjectUserName"]), clean(fields.get("SubjectDomainName"))
    # Sysmon writes the account as DOMAIN\name in one field, and a Defender detection as "Detection User"
    user = clean(fields.get("User") or (fields.get("Detection User") if code in DEFENDER_DETECTIONS else ""))
    if user:
        domain, _, name = user.rpartition("\\")
        return name, domain
    return "", ""
