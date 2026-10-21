# Glessner scope

This file describes what Glessner does, what is planned, and what it leaves out. [glossary.md](glossary.md) names the parts of the app, and [coverage_reference.md](coverage_reference.md) lists what it reads and flags.

## Purpose

An analyst points the app at a folder holding a collection from a security incident. The app hashes every file, identifies each artifact, and maps the installed forensic tools to the artifacts. It runs the tools the analyst chooses, loads other tools' output found in the folder, and imports text logs that no tool reads. Tool output goes to the case folder, and everything loads into one timeline.

The timeline scrolls horizontally and groups events into nested lanes, such as Unreviewed > Workstations > DESKTOP. The analyst pivots between related events and marks each event as authorized, suspicious, or malicious. The marks build the account of what happened and show what still needs investigation. The app also detects which tools are installed, names the missing ones that would read the evidence, and shows where to get them.

The aim is that an analyst can work across every available source when triaging a security event or incident. The work it replaces is running each tool by hand and merging the results in Timeline Explorer or a spreadsheet. The app runs alongside existing forensic tools rather than replacing them.

A typical use: put the EVTX files from several hosts in a folder, load it, and follow lateral movement through the environment on one timeline.

## What it does

| Topic | What the app does |
|---|---|
| User | One analyst works a case. The case is a folder of plain files: a manifest, a journal, run records, and a database the app can rebuild. |
| Platform | A Windows analyst workstation. The app makes no network calls, and a test checks that across a case load, a search, and every export. The app's Python sockets reach only this machine, and DuckDB never installs or autoloads an extension. The tools the app runs are separate programs, outside that test. Tool recommendations show the official download URL, and the analyst installs the tools. |
| Inputs | A folder of collected files with one top-level folder per host, or one host's files with `new-case --host`. A disk image is mounted or extracted first. The collection is assumed to be a working copy, such as KAPE output. What the app reads is under [Inputs](#inputs). |
| Tools | Run from the tool registry, one YAML file per tool, which defines how to detect the tool, the artifact types it handles, its command template and options, its output files, its parser, and its official download URL. |
| Case size | Up to about 10 hosts per case. A multi-host case can reach millions of rows, so events go in a local database. The figures come from synthetic cases built from copies of the Stolen Szechuan Sauce hosts: 5.2 million events on 10 hosts, and 10.5 million. A real collection of that size hasn't been tried. |
| Stack | A Python backend with DuckDB. The web page is served only on 127.0.0.1, with every script and style served by the app, and opens in the default browser. |
| Lanes | The analyst picks the lane grouping from seven presets of lane keys (mark, role, host, user, artifact, and tactic), such as Mark > Role > Host, the default, Host > Mark, or User > Host. Asset roles come from a host list the analyst edits, pre-filled from the evidence. |
| Timeline zoom | Zoomed out, the timeline shows event density per lane. Zoomed in, it shows individual events. |
| Relations | Pivots find events that share a value with the event, such as a logon session, an account, an address at either end, a source IP and port, a workstation, a flow, a file, a file name in any folder, a service, a task name, a rule or signature, or a hash. Another pivot finds events on the same host within an adjustable time window. A 4624 type 3 or type 10 logon, or a 4648 event, draws a link from the source host's lane to the target host's; a source outside the case gets a lane of its own. Time-window links look different from logon links and show the gap in seconds. Every link shows why it exists. |
| Marks | Unreviewed (the default), Authorized, Suspicious, and Malicious. Each mark records who, when, and an optional note. The analyst marks one event, a selection, ticked pivot or search results, or a group of suggestions. A group action, and a selection above 25 events, first asks, stating what it covers, and applies only to the events the page counted. The To investigate list holds suspicious and malicious events with counts of their unreviewed related events, and the pending suggestions. |
| Suggestions | Simple YAML rules match field conditions (equals, in list, regex, time range) and suggest a mark. Four rules are built in, and the analyst can change or remove them. Hayabusa runs as a registry tool, and its Sigma rule hits at medium level and above suggest Suspicious. So do Suricata alerts at severity 1 and 2, and imported Snort or Suricata fast alerts at priority 1 and 2. Suggestions stay separate from marks until the analyst accepts them. The app has no Sigma engine of its own. |
| Tags | ATT&CK tactics and techniques, and the analyst's own tags, journaled as marks are. Hayabusa's ATT&CK fields suggest tags, which the analyst accepts or dismisses. |
| Findings | Conclusions the analyst writes: a title, a severity in words, a narrative, ATT&CK techniques, and the events that support it. Each finding shows what its records don't prove, from a fixed, sourced caveat per kind of record. The app writes no finding and no verdict. |
| Evidence handling | The selected folder is evidence. At intake, the app records a SHA-256 hash of every file in a manifest, and files added later are hashed before anything reads them. It never writes into the evidence folder, and it doesn't follow links in it. After each tool run, it re-hashes the files that run read. At case close and for each report, it re-hashes every file. It logs every exact command line. A tool that writes beside its inputs runs on copies checked against their intake hashes. |
| Storage | Parsed events go in a database that the app can rebuild from tool output and the journal. Analyst actions go in an append-only JSONL journal, one line per action with who and when: marks, notes, tags, follow-ups, findings, host edits, splits and offsets, rules, suggestion decisions, settings, undos, and each file the case writes, with its SHA-256. Each journal line names the one before it, so a change to an earlier line shows. The journal also names each build that opens the case for work. `case.yaml` holds a case format number: a build refuses a newer format and upgrades an older one with a journal entry. |
| Time | Events are stored in UTC. A load that reads local times, an import or an Autoruns CSV, records the zone it read them in. The view shows UTC, with zone axes for a host's own zone or any other. The analyst can set a per-host clock offset. Offsets are journaled and shown on adjusted events. Original timestamps never change. |
| Exports | Every event in a time window exports as CSV or JSONL with ECS column names, for Timeline Explorer or Timesketch, optionally with the page's current filters. Marked and flagged exports cover the whole case whatever the window. Network events carry ECS network columns. The indicators export lists the addresses, domains, hashes, accounts, file paths, services, and tasks parsed from the events marked Malicious. The Markdown report has seven sections, from the analyst's summary and findings to the evidence's integrity and the method. |
| Case close | Closing re-hashes all the evidence, checks the journal's chain, journals the result, and prints the journal's head for the analyst to record outside the case. |

## Inputs

| Input | Read by |
|---|---|
| Event logs (EVTX) | EvtxECmd and Hayabusa |
| Registry hives | RECmd; SBECmd for the user hives' ShellBags; AmcacheParser for Amcache.hve |
| `$MFT` and the USN journal (`$J`) | MFTECmd |
| Prefetch, LNK files, and jump lists | PECmd, LECmd, and JLECmd |
| Recycle Bin `$I` files and SRUM | RBCmd and SrumECmd |
| Browser history, Windows notifications, and the Windows Timeline | SQLECmd and WxTCmd |
| Packet captures | Suricata, with the ET Open rules when they're beside it |
| Windows event XML, from wevtutil, Event Viewer, or a SIEM | The app's own reader, run as a registry tool |
| Tools' output in the evidence | The same parsers read EZ tools' and Hayabusa's CSVs, such as a KAPE run's, and Suricata's EVE JSON. Zeek's logs load through the import, and Sysinternals Autoruns CSVs by a parser of their own. Raw evidence comes first: where an installed tool reads a host's raw files, the app runs it, and loads found output for the rest. |
| Text logs no tool reads | The import, by a mapping: Windows Firewall, IIS, FortiGate, SonicWall, Apache and NGINX, syslog, Cisco ASA, Snort and Suricata fast alerts, lines that start with a date and time, and CSV or JSON-lines exports such as a SIEM's. |

The import and the event XML reader are the app's own readers. Binary artifacts are read only by external tools. EvtxECmd's `Payload` column holds the full event data as JSON, and the app reads relation fields from it by name.

## Defaults

| Topic | Default |
|---|---|
| Artifact identification | Identify files by signature: the EVTX, registry hive, LNK, Prefetch, and MFT headers, and those of the other artifacts. Use the filename and path as hints. Recognize text logs and other tools' output by their first lines. List unidentified files instead of skipping them. |
| Tool detection | Check a tools folder the analyst sets, plus PATH. Run each tool's version check, and record tool versions in the run records. The tools folder can't hold or sit in the evidence or case folder, or be a network path. |
| Tool runs | Run one tool at a time. Apply a timeout, and capture the exit code, stdout, and stderr. A failed run does not block other runs; a run that finds the evidence changed stops the rest. |
| Local server | Listen only on 127.0.0.1 and require a per-session token, so that other local programs and web pages cannot drive the app. |

<a id="decided-but-not-built"></a>
## Planned, not built

| Item | What it would do |
|---|---|
| Manual links between events | The analyst links two events with a reason, journaled like a mark. |
| Marking a whole lane or View result | One mark for every event in a lane or a View result, from a lane's menu and the View, always through the confirmation. |
| A custom lane grouping | Any one to four lane keys in any order, remembered per case, beside the presets. A Channel key joins the lane keys. |
| Tactic lanes with suggested tags | The Tactic lanes follow the View's Include suggested tags switch, and an accepted technique counts under its tactic. |
| Network flows assigned to hosts | The analyst assigns a network sensor's flows, by internal address and time, to the host that held the address, with the DHCP or VPN evidence for each assignment, journaled and undoable. A sensor's lane gets a sublane per internal address, and each event keeps the clock that recorded it, so a host's assigned flows stay on the sensor's clock. |
| Offsets on the host's own times | A clock offset moves only times its host's clock wrote, so a PE file's link time keeps its value. |
| A closed case kept read-only | A closed case stays read-only until the analyst reopens it with a reason, which is journaled and re-hashes the evidence. Viewing, search, and exports still work. |
| Logs from outside the evidence folder | Logs copied into the case folder and hashed into the manifest as added evidence, never into the evidence folder. |
| More IDS formats | Sguil's event text and Snort's full alert format. |

## Not in scope

| Item | Reason |
|---|---|
| More than one analyst working a case at once | The journal format keeps this possible later. |
| Downloading or installing tools | The app shows URLs only. Downloading would need network access, publisher checksum checks, and update handling. |
| Memory images | The app reads a Windows triage collection. |
| Mobile devices | Outside the Windows triage set. |
| macOS and Linux hosts' own artifacts | No parser reads their file systems or system records. Their text logs, such as syslog or a web server's access log, can be imported. |
| Cloud and SaaS logs | No tool or ready-made mapping reads them. An export as CSV or JSON lines can still go through the import with a guessed mapping, as a SIEM's export does. |
| A Sigma engine of its own | Sigma enters through Hayabusa. |
| Clocks corrected without the analyst | The clock check measures each host against a network sensor's records, Suricata's from a packet capture or Zeek's, and suggests an offset. The analyst applies it, and nothing changes a clock on its own. Offsets that change over time aren't handled. |
| Marks that spread to related events on their own | Time-window links would mislabel nearby events. Rules and alerts only suggest. |
| A formatted report generator | The Markdown report is raw material for a formatted report, and the app writes none of its narrative. |
| Linux and macOS as the analyst's platform | Windows only. |
| A desktop window in place of the browser | The app opens the default browser. A desktop window may come later as a second build. |
| Parallel tool runs | Tools run one at a time. |
| Cases with more than about 10 hosts | Velociraptor, Timesketch, or a SIEM fit that scale. |
