# Known limitations

Glessner is pre-alpha. This page lists what it doesn't do yet or doesn't do well, so you can decide how far to trust a result. Each row states a fact about the app today and what you can do about it. The README's [Limits](README.md#limits) section is the short version, and [CHANGELOG.md](CHANGELOG.md) lists changes as they land. The tools named here are listed with their publishers in the README's [Licenses and credits](README.md#licenses-and-credits).

## Before you rely on a result

- Read **What the case holds** on the Case overview first. It lists the case's gaps, such as runs that loaded nothing. An empty lane can mean no activity, a missing tool, or a source the app doesn't read.
- Check any event that matters against its source. The Event page names the tool, the run, the evidence file, and the record, and says whether the file's hash still matches intake. Each tool's own output stays in the case's `runs` folder.
- Record the journal head when you close a case or write an export. A head recorded outside the case is how you show later that the journal wasn't rewritten. See [Integrity](#integrity-and-the-claim-of-no-network-calls).

## What has been checked

Glessner has run end to end on three public practice sets whose answers are published: [the Stolen Szechuan Sauce case](https://dfirmadness.com/the-stolen-szechuan-sauce/), [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES), and [the Malware-Traffic-Analysis.net exercise of 2016-01-07](https://www.malware-traffic-analysis.net/2016/01/07/index.html). Those runs show that the data is present and readable in the app. Each set's check has a write-up in [checks/](checks/): [szechuan_sauce.md](checks/szechuan_sauce.md), [evtx_attack_samples.md](checks/evtx_attack_samples.md), and [mta_2016_01_07.md](checks/mta_2016_01_07.md). Each gives the check's score, each item's state, and the gaps the check found.

| Not yet shown | Today | What you can do |
|---|---|---|
| It helps you find what you don't already know | No analyst has worked a case with it without knowing the answer. | Treat the timeline, the ranked pivots, and the suggestions as leads for your own review. |
| It helps analysts other than its author | No other analyst has run a case with it. | Send feedback through the repository's issue forms, and report where it fails. |
| It reads a real KAPE collection | It has not been tried on one. Its test collections are built from public datasets, with one folder per host. | Run `intake` first and read the list of unidentified files before you read the timeline. |
| It works on a real multi-host incident | The multi-host cases it has run are public practice sets and synthetic copies. | Check the hosts' roles, names, and clocks in the Hosts panel before you follow a lead across hosts. |
| It reads real firewall logs | The text log import has not been tried on logs from a production firewall. | Run `import --preview` and check the field mapping and the first and last times before you load a file. |
| The same evidence gives the same result twice | A test shows it on a small synthetic collection whose tool output is already in place: two cases built from it in separate processes, with different folder paths, hash seeds, and tool and load orders, hold the same events, derived tables, overview figures, and exports, and a rebuild and a copy keep the events. Run IDs, run times, the journal's timestamps, and the report differ by design. It hasn't been checked on a full collection with the tools run. | Keep the exact command lines each run records, and record the journal head with each export. |

## Inputs

| Limit | What you can do |
|---|---|
| Glessner reads a Windows triage collection: a folder of collected files, with one top-level folder per host. It doesn't read disk images, containers (E01, VHDX, raw, zip, 7z), memory images, or mobile devices. It doesn't recover deleted files' contents or carve unallocated space. Deleted files' names and times can still load from `$MFT` entries no longer in use, from `$J`, and from Recycle Bin `$I` files. | Mount or extract an image first, and point Glessner at the extracted folder. Recover deleted files and carve unallocated space with an image tool, as [scope.md](scope.md#not-in-scope) describes. Use a memory tool for memory. |
| Binary artifacts are read only by the external tools. If a tool isn't installed, its artifacts produce no events. | Run `uv run glessner tools CASE` or open the **Tools** page to see which tools are missing before you read an absence of events as an absence of activity. |
| Glessner shows what each tool reports and doesn't parse binary artifacts itself. A tool's misreading reaches the timeline. | Compare a surprising event with the tool's own output in the run folder. |
| No reader exists for macOS and Linux hosts' own artifacts, or for cloud and SaaS logs. Their text logs, and CSV or JSON-lines exports, can go through the import. | Use `import --preview` to check the mapping. A mapping the import guesses can be wrong. |
| Windows event logs exported as JSON or JSON lines, such as by NXLog, have no reader yet, so they load through the import as plain records and get no Hayabusa rule hits. The import's guessed mapping can take as each event's time a field the collector or a SIEM added, such as `@timestamp`, which can run a minute or more behind the event. It also puts every host's events in one lane, named for the host folder that holds the file. Most of the app's account, logon, process, and registry fields stay empty, and some take the wrong field. Each record's own fields are kept, and search reaches them as `data.FIELD`. | Import the file with each event's own time and a lane for each computer, as [Windows event logs in JSON](#windows-event-logs-in-json) describes, before you mark any of its events. |
| Some Windows sources aren't read, among them `$LogFile`, `$I30`, volume shadow copies, scheduled task XML files, WMI subscriptions, BITS jobs, PowerShell console history, Defender's MPLog, WebCache, and remote access tools' logs. The [coverage reference](coverage_reference.md#coverage-at-a-glance) lists them all. | If your case turns on one, read it with another tool and import the CSV or JSON-lines output if the mapping fits. |
| Records with no time, such as a shortcut or ShellBag entry that carries none, load but stay off the timeline and out of search. | Open the tool's CSV in the run folder. |
| Some fields and tables aren't loaded: Suricata's `payload`, `payload_printable`, and `packet` fields, Amcache's device and driver tables, SRUM's energy, push notification, and `vfuprov` tables, and SQLECmd output from maps the app doesn't read. | The tool's own output is kept in the run folder. Open it there. |
| Hayabusa reads `.evtx` files only, so event XML from wevtutil, Event Viewer, or a SIEM gets no rule hits. | Run Hayabusa on the original `.evtx` files if you have them. |
| A Hayabusa hit attaches only to an event that EvtxECmd also read from the same file. A Hayabusa run without an EvtxECmd run on the same files gives hits that attach to nothing. | Run both on the raw logs. `run --all` does. |
| The app doesn't check event logs for gaps in record numbers, and it doesn't carve deleted records. | Check for gaps and cleared logs with a dedicated tool. |
| Intake skips symbolic links, junctions, and other folder reparse points, and lists each one with its target. A run of a tool that lists a host's folder itself, such as EvtxECmd or PECmd, is refused while that folder holds a link or a file the manifest doesn't list. | Read the intake summary, and collect the targets separately if they matter. To run the tool, remove each link, or replace it with a copy of the files it points to, then hash the copies and any new file with `intake --add`. |

### Windows event logs in JSON

These steps import an NXLog export of Windows event logs with each event's own time and a lane for each computer. They use NXLog's field names: `EventTime` for when the event was logged, `EventReceivedTime` for when NXLog received it, and `Hostname`. Another collector's export needs its own fields.

From the command line, give the case folder and the file's path inside the evidence folder:

```bash
uv run glessner import C:\Cases\CASE01 logs/nxlog.json --time-field EventTime --zone=-04:00 --host-field Hostname --preview
```

The preview shows the mapping and the first events. Run the command again without `--preview` to import. Add `--host NAME` to name the lane for records that have no `Hostname`.

On the **Import** page:

1. Choose the file.
2. In the menu above `@timestamp`, or whichever field the guess set to **Time**, choose **Keep as data**. Two fields set to **Time** are read as one date and time.
3. In the menu above `EventTime`, choose **Time**. Leave `EventReceivedTime` as data.
4. Under **Times without a zone are in**, choose **Another zone or offset**, and type the offset, such as `-04:00`. When the guessed field carried a zone, this setting already reads UTC and the page raises no problem, so skipping this step puts every event off by the zone's offset.
5. Under **Host lane**, choose **A field of each record**, then `Hostname`. In the box beside it, type a lane for records that have no host name.
6. Check the time shown beside **Time** against a record you trust, then import.

To find the offset, compare `EventTime` with `UtcTime` in several Sysmon records of the same export. Where `EventTime` looks like `2020-05-01 22:55:23`, it has no zone and whole seconds only, and the two usually differ by the zone's offset to within a second. If `EventTime` carries its own zone, the import reads it and doesn't use the zone setting. If the export spans a change to or from daylight saving time, type the zone's name, such as `America/New_York`, instead of an offset. Times in the hour repeated when clocks go back are read as standard time, so records from that hour's first pass land an hour late.

Importing a file again replaces its earlier events. The new lanes give the events new IDs, so marks made on the earlier import refer to events that no longer exist. Import this way before you mark events. Each lane takes the name as the field writes it, such as `PC01.example.local`, so it stays apart from a host folder's lane for the same machine.

The order still isn't exact. `EventTime` is when the record was logged, and Sysmon can log a record many seconds after its `UtcTime`, so Sysmon events can list out of order by as much. Events with the same time list in an order of their own, not the file's, and with whole-second times many events share one.

## Tools and rule sets

| Limit | What you can do |
|---|---|
| Each run records the tool's version and the exact command line. Only Suricata's ET Open rule set has its version recorded. The case doesn't record the versions of Hayabusa's rules, EvtxECmd's maps, RECmd's batch file, or SQLECmd's maps. It doesn't record a tool's file hash either. | Note those versions in your ticket. `glessner tools CASE` shows the installed tools and their versions. |
| Tools run one at a time. There is no queue to inspect and no way to cancel a run. A failed run doesn't block the others. | Choose the tools you need with `run --tool ID` when you want one result quickly. |
| Antivirus can quarantine tool output, because the output quotes attacker payloads. A removed output fails the run with an antivirus hint. Glessner can't read Defender's exclusion list without administrator rights, so it doesn't check for one. | Exclude the case and evidence folders before you run tools. |
| RECmd's USBSTOR and SCSI plugins can fail on a SYSTEM hive with the error "Array cannot be null". Then no install, first-install, or removal time loads for the hive's USB storage devices. The devices' serials still load from the USB, MountedDevices, and Device Classes rows. A Device Classes row holds a device's last arrival time in its data (ValueData2). The row itself lists at its key's last write time. | Check the RECmd run's output for the error. The times are still in the hive. Each device's key under a control set's `Enum\USBSTOR`, such as `ControlSet001\Enum\USBSTOR`, has a `Properties\{83da6326-97a6-4088-9453-a1923f573b29}` key. Read its subkeys with `RECmd -f HIVE --kn KEY --nl`, with HIVE a copy of the SYSTEM hive and KEY the subkey's path. `--nl` lets RECmd read a dirty hive whose transaction logs weren't collected. On Windows 7, the subkeys `00000064` and `00000065` each hold a subkey `00000000`, whose `Data` value is the install or first-install time, as the eight bytes of a little-endian FILETIME. A Windows 7 hive has no last arrival or removal time there. On later versions, such as Windows 10, the subkeys are `0064` to `0067`, for the install, first-install, last arrival, and removal times, and a device may lack some of them. Each one's default value is its time, which RECmd shows as a date. |
| MFTECmd writes a file's $FN times only where they differ from its $SI times. Where they match, the timeline has the file's $SI events and no $FN event. Glessner's MFTECmd runs don't pass `--at`, the option that writes every $FN time of a file's long name. | To see one file's $FN times, run `MFTECmd -f FILE --de ENTRY`, with FILE a copy of the `$MFT` and ENTRY the EntryNumber the Event page shows. It shows every $FN attribute. To see every file's $FN times, run `MFTECmd -f FILE --csv DIR --at` and open the CSV in DIR. Add `--sn` to include short (DOS 8.3) names. |
| JLECmd names a jump list's application from its built-in AppID list. The name can be a product or version the host doesn't have, such as Microsoft Outlook 2016 on a PC with Office 2013. | Treat the name as a lead. Before you name the program in a finding, check its version in the host's Uninstall rows, and its folder in App Paths or Prefetch, such as `Office15` for Office 2013. Prefetch's Version field is the prefetch file's format, not the program's version. |

## Suggestions, roles, and findings

| Limit | What you can do |
|---|---|
| Hayabusa hits at medium level and above suggest Suspicious. So do Suricata alerts of severity 1 and 2, and imported fast alerts of priority 1 and 2. Four built-in rules also suggest: `machine-accounts-authorized` suggests Authorized, and `remote-execution-pipes`, `print-spooler-pipe`, and `admin-share-executable-writes` suggest Suspicious. How often medium-level hits are noise hasn't been measured on the cases checked. Nothing is marked until you accept it. | Review pending suggestions by rule, where each group says why it fired. Read the count in the confirmation before you accept a group. Every case gets the built-in rules when it opens. Drop one with `glessner rule CASE remove ID` or on the Rules page. |
| Host roles are guessed from the evidence, such as the SYSTEM hive's product type or Kerberos ticket requests. | Confirm or change each role in the Hosts panel. The report marks an unconfirmed role "(guessed)". |
| Only eight kinds of record carry a "does not prove" note: Prefetch, Amcache file entries, AppCompatCache, shortcuts and jump lists, logon events 4624 and 4625, Autoruns entries, Suricata alerts, and service installs (7045). Each note is one fixed text per kind. It doesn't know your case. | For other kinds, state in your finding what the record can't show. |
| A finding's ATT&CK field and the tag picker accept only techniques and sub-techniques in [Enterprise ATT&CK](https://attack.mitre.org/) v20.0. | Put anything else in the finding's narrative. |
| The Event page ranks next pivots from a fixed table for each kind of event. The ranking doesn't learn from your case. A pivot flagged broad matches over 500 events or a shared value, such as a system logon session. | Read the reason and the count before you click. |
| Same logon session matches the host and the logon ID with no time bound. Logon IDs repeat after a reboot, so a match across a boot can be another session. The counts on To investigate and the Case overview include such matches. | Read each listed event's offset from the event on screen. Look for a boot (System event 6005) between events that are hours or days apart before you treat them as one session. |

## Time and links

| Limit | What you can do |
|---|---|
| Glessner stores every time in UTC and never changes a recorded time. You can set one clock offset for each host, up to one day either way. Offsets that change over time aren't handled. The clock check lists the clock changes a host logged and the span its pairs cover. | If a host's clock changed, apply an offset only for the span you are working in, or leave the times as recorded. |
| An offset moves every event on that host, including an event whose time another clock wrote, such as a file's link time. | The Event page shows each event's recorded time on its host's own clock. |
| The clock check needs a capture or Zeek logs in the case. It measures each host against the events that both sides record. Events with no pair stay in recorded order until the hosts are aligned. | Without a capture, compare a time you can trust by hand. The flags on a host lane warn when a measured skew is not applied. |
| Text logs that write no year or zone, such as RFC 3164 syslog, need you to supply them. The import asks. A wrong answer puts every event at the wrong time. | Check the preview's first and last times against a record you trust. |
| Logon links are drawn only for 4624 type 3 and type 10 logons and 4648 events. Lateral movement that other events record draws no link. | Pivot on the account or the address. |
| A logon from an IPv6 source address links to a collected host only after you add that address to the host in the Hosts panel. The app reads a host's addresses from its registry's IPv4 values, and a logon that records a source address isn't matched by its workstation name. | Add the host's IPv6 addresses in the Hosts panel. Until then, a routable source draws as a source outside the case, and a link-local one draws no link. |
| A network capture's flows aren't assigned to hosts. They stay in the capture's lane. | Pivot on the internal address to reach the hosts' own records. |

## Search, lists, and the timeline

| Limit | What you can do |
|---|---|
| A search or pivot list shows the first 500 matches, and a group of pending suggestions lists 200. The counts, the timeline's marks of up to 20,000 matches, and group decisions cover all of them. | Narrow the query. A find box above a list narrows only the rows shown, and offers to search all the matches for plain words. |
| **Select all** under a find box ticks only the rows the find shows. | Check the count in the confirmation, which states how many events a mark covers. |
| The timeline draws single events only when the window holds 50,000 events or fewer. A wider window shows density. | Zoom in until single events draw. |
| A bare word matches inside longer words, so a count can run high. Free text doesn't read the tool, artifact, run, source file, mark, role, tag, or Hayabusa rule title. | Put a word in quotes to match whole words. Use `tool:`, `file:`, or `rule:` for those fields. A search with no match lists what free text skipped. |
| The View hides events from the timeline but not from pivot counts. Marks, roles, and tags aren't search fields. | A list tags a row "hidden by the View" when the View hides it. Use the View for marks, roles, and tags. |

## Scale and speed

| Limit | What you can do |
|---|---|
| A case is sized for about 10 hosts. The performance figures come from synthetic cases built from copies of two hosts: 5.2 million events on 10 hosts, and 10.5 million. A real collection of that size hasn't been tried. | For a larger case, use a tool built for that scale, as [scope.md](scope.md#not-in-scope) says. |
| Searching a word across every field of the 5.2-million-event case takes seconds. A full-range export of that case wrote files of about 3 GB and took between 29 and 65 s. | Keep free disk space on the case's drive. The event store spills a large sort to a temporary folder in the case folder. |

## Exports and the report

| Limit | What you can do |
|---|---|
| A CSV cell that begins with `=`, `+`, `-`, `@`, their full-width forms, a tab, a carriage return, or a line feed gets a tab in front, and every text cell is quoted. An operator (`=`, `+`, `-`, `@`, or a full-width form) after a semicolon or a line break inside a cell gets a tab too. The header row is fixed app text, written as is, `@timestamp` included. A program that reads the file sees the tab. This was checked in Excel and LibreOffice Calc. Google Sheets wasn't checked. Neither [Timesketch](https://github.com/google/timesketch) nor [Timeline Explorer](https://ericzimmerman.github.io/) has been run on the changed files. | Read JSONL into a program, because it keeps every value as recorded. Open a small CSV export in your tool first. |
| The timeline CSV and JSONL have no finding column and no evidence SHA-256. | The report lists the findings each marked event supports, with its evidence SHA-256. |
| Exports quote attacker text, so antivirus can quarantine them. | Keep the case folder inside an excluded folder. |

## Integrity and the claim of no network calls

| Limit | What you can do |
|---|---|
| The journal is a hash chain, so an edited entry breaks the chain. Someone who can write to the case folder can rewrite the chain from that entry on, or append entries after yours. Either shows only against a head recorded outside the case. The app keeps the latest head on this computer, so a copy opened on another computer has no recorded head there. | Record the head that `close` and each export print. Check it later with `glessner verify CASE --journal --expect-head HEAD` or with `scripts/check_journal.py`. |
| The intake manifest isn't part of the journal's hash chain. Only a close entry's hash check vouches for it, and only at the moment of the close. Someone who can write the evidence and the case folder can change a file and its manifest line together, and `verify` then reports a match. | Record the SHA-256 of `manifest.jsonl` outside the case, with the head that `close` prints. |
| Closing a case re-hashes the evidence and records the result, but doesn't lock the case. A closed case stays open for marks, notes, and tags. | Don't change a closed case. Make a copy with `copy-case` to keep working. |
| A file that intake couldn't read has no hash, and counts as unverified. The outputs name the number. | Read the unverified count in the close result and the report, and treat those files as unchecked. |
| "No network calls" is a tested claim for the app. A test holds every Python socket to this machine and turns off DuckDB's extension download. The guard doesn't see `sendmsg`, `_socket` called directly, asyncio's Windows proactor, or code run while the tests are collected. The app uses none of these. The tools Glessner runs are separate programs outside the test, and so is your browser. Browse lists only this machine's own drives and doesn't open network paths. A mapped drive or UNC path you type on the start page is checked and opened over SMB, as Windows opens any network path. | The page's Content-Security-Policy blocks external requests from the browser. To hold the claim for a whole run, including the tools, work on a machine with no network access. To keep the app's own process off the network, type only local paths on the start page. |
| The local server listens on 127.0.0.1 and needs a session. The start link works once: the page trades its token for a session, which the browser keeps for this server's address and port and the page sends in a request header, so other web servers on 127.0.0.1 don't receive it. A used link doesn't open the app in a second browser or a new private window; restart the server for a new link. Where the browser blocks site data, the page keeps its session only until it reloads or moves between the start page and a case. An import, and a Tools run that loads events, reload the page, so they end that session too, and getting back in then needs a new link from a server restart. The session handling hasn't had the planned security review. | Work on a machine you trust. To work in a browser other than your default, start the server with `--no-browser` and open the link there. If your browser blocks site data, allow it for `127.0.0.1`. Keep an unused start link out of tickets and chat, and stop the server with Ctrl+C when you finish. [SECURITY.md](SECURITY.md) says how to report a problem. |

## Cases and upgrades

| Limit | What you can do |
|---|---|
| Pre-alpha: the page and the case format will change. A newer build upgrades a case when it opens it. An older build then refuses that case. | Work on copies, which `copy-case` makes. |
| One analyst works a case. Several analysts on one case aren't supported. | Give each analyst a copy made with `copy-case`, and compare findings by hand. |
| Windows only, for the analyst's machine and for the hosts' own artifacts. | Import other systems' text logs, such as syslog. |

## Planned, not built

[scope.md](scope.md#planned-not-built) lists each of these. [scope.md](scope.md#not-in-scope) lists what the app leaves out by design.

| Not built | What you can do today |
|---|---|
| Manual links between events | Write a note on each event, or a finding that names both events. |
| One mark for a whole lane or View result | Tick the rows in a search or pivot list and mark them. |
| A custom lane grouping | Pick one of the seven presets. |
| Tactic lanes that count suggested tags | Accept the Hayabusa tag suggestions first. The lanes count accepted tags only. |
| Network flows assigned to hosts | See the capture-flow row under Time and links. |
| A clock offset that skips times another clock wrote | See the offset row under Time and links. |
| A read-only closed case | See the closing row under Integrity. |
| Logs copied in from outside the evidence folder | Put a copy of the log in your working copy of the evidence folder, then run `uv run glessner intake C:\Cases\CASE01 --add`. |
| Disk images recognized at intake | Mount or extract the image first, and point Glessner at the extracted folder. |
| More IDS formats: Sguil's event text and Snort's full alert format | Use fast alerts, or a CSV or JSON-lines export. |

## Report a limit that isn't here

Open an issue in the repository's [issues](https://github.com/joshuacodysmith/glessner/issues) and choose a form. Describe the problem with a small synthetic example. Don't attach evidence, case files, or real incident data.
