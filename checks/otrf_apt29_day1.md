# Check: OTRF APT29 Day 1

## What this check is

This is an open-answer check. The case was worked with its answer key at hand, so the check shows whether the evidence each answer rests on is present and readable in Glessner. It doesn't show that an analyst who doesn't know the answer would find it. Blind rounds do that, and none has been finished yet. The dataset publishes no question-and-answer key, so the check built its key from the attack's emulation plan: 25 items, one for each step of the scenario's first day. The check's score is 19, 6, 0 of 25. Of the 25 items, 19 were reached, 6 were partly reached, and 0 were missed. No item is out of scope.

## The dataset

- **Source:** The APT29 Day 1 set in the [`datasets/compound/apt29`](https://github.com/OTRF/Security-Datasets/tree/master/datasets/compound/apt29) folder of [Security Datasets](https://github.com/OTRF/Security-Datasets), from the Open Threat Research Forge (OTRF). Its README says the set replicates the APT29 scenario of MITRE's ATT&CK Evaluations, Round 2, whose [emulation plan](https://github.com/mitre-attack/attack-arsenal/tree/master/adversary_emulation/APT29) MITRE published.
- **Credit and license:** The APT29 folder's README names Roberto Rodriguez as the set's creator. The repository's license file is the MIT License, copyright 2021 Open Threat Research Forge. The repository's README heads its license section "GPL-3.0" and links to that same file. The APT29 folder states no license of its own. MITRE published the emulation plan under the Apache License 2.0. This repository holds none of the dataset's files.
- **What it holds:** The scenario's first day in the `dmevals.local` domain. The attacker works from a server outside the domain, at two addresses.

  | Host | Role | Address |
  |---|---|---|
  | SCRANTON | Workstation, the first victim, used by `DMEVALS\pbeesly` | 10.0.1.4 |
  | NASHUA | Workstation, the second victim, also used by `DMEVALS\pbeesly` | 10.0.1.6 |
  | NEWYORK | Domain controller, events only | 10.0.0.4 |
  | UTICA | Workstation, events only, not a target in the plan | 10.0.1.5 |
  | The attacker's server | Command and control (C2) and the operator | 192.168.0.5 (Pupy on port 1234, and step 3.B's callback on 443) and 192.168.0.4 (step 10.B's callback on 443, Metasploit on 8443, and WebDAV on 80) |

  The check used these files from the folder:
  - `day1/apt29_evals_day1_manual.zip` (13,944,973 bytes), which holds one JSON-lines file of 385,334,029 bytes: 196,081 Windows events from all four machines, among them 143,884 from Sysmon and 28,627 from the Security log. NXLog sent them to a Windows Event Collector, and the file is that collector's export. The events run from 02:55 to 03:28 UTC on 2020-05-02.
  - `day1/pcaps/SCRANTON.zip` (46,631,415 bytes) and `day1/pcaps/NASHUA.zip` (6,955,498 bytes), each a packet capture of one victim's traffic with its SHA-1. They record another run of the scenario, on 2020-04-30, and hold live attack traffic.
  - `day1/zeek/SCRANTON-zeek_logs.zip` (24,653 bytes) and `day1/zeek/NASHUA-zeek_logs.zip` (71,772 bytes), Zeek's logs of the two captures in JSON: 14 logs for SCRANTON and 12 for NASHUA.
  - `emulationplans/apt29.xlsx` (25,051 bytes), the emulation plan as a spreadsheet, and the folder's two README files.
- **Where the answers come from:** The check built its key from the plan's `day1` sheet, 31 rows, and the two READMEs, before the case was opened. Each item is one numbered step of the plan, 1.A to 10.B: an attacker action, its host and account, its ATT&CK techniques, and the records that should show it. Six rows aren't items. Three set up the attacker's own containers on its server and leave nothing on the victims, one continues step 2.A with no technique of its own, and two are operator RDP connections made before the export begins. The key was corrected against the evidence for items 6, 9, 10, 12, 17, 18, 20, and 25, and the table under Results carries the corrections. For example, item 6's callback goes to 192.168.0.5, not 192.168.0.4. The plan gives the Pupy server's address as 192.168.0.4. The evidence puts its channel at 192.168.0.5 on port 1234, so the host table and item 1 follow the evidence. The APT29 folder's README has a Day 1 host table that matches the export in the zip, channel by channel. The `day1` folder's README has a host table for another recording.

## How it was run

[glossary.md](../glossary.md) defines terms such as lane, pivot, and lead.

**Date and build.** The check ran on 2026-10-22, the day v0.2.0 was released, on a development build made after that release and before v0.3.0. Each gap's state under Gaps found says where the gap stands in v0.3.0, and a fixed gap names the release that fixed it.

**Evidence.** The eight files above were downloaded from the repository and hashed. The capture zips are password protected, and each extracted capture matched the SHA-1 that came with it. The evidence folder held copies of the extracted files, 31 files and 443.4 MB:

- `host-events/apt29_evals_day1_manual_2020-05-01225525.json`, the host events
- `SCRANTON/SCRANTON.pcap`, `SCRANTON/SCRANTON.sha1sum`, and the 14 Zeek logs under `SCRANTON/zeek/`
- `NASHUA/NASHUA.pcap`, `NASHUA/NASHUA.sha1sum`, and the 12 Zeek logs under `NASHUA/zeek/`

Glessner expects one top-level folder per host. Each capture and its Zeek logs went in a folder named for the host whose traffic they record. The host events are one export that covers all four machines, and splitting it would change the evidence, so it went in a folder of its own.

**Loading.** A case was made from the start page, with the one-host field left empty, so each top-level folder became a host. **Create case and take in evidence** hashed the 31 files. The Tools page's **Run and load everything ready** ran Suricata 8.0.7 with ET Open rule set 11310 on each capture and loaded the Zeek logs as found output. The host events don't load there, so they were loaded from the Import page with the mapping it guessed. Each of the other 15 tools showed "Nothing in this case for it to read", the built-in event XML reader among them, since the case holds no event log files, registry hives, or other raw host artifacts.

| File | Result | Detail |
|---|---|---|
| The host events | Loaded, but not as Windows events | Identified as generic JSON lines, so the event XML reader never saw the file. The Import page guessed a mapping of 14 fields and loaded 196,081 events onto one lane, `host-events`, named for the folder. Each event's time is `@timestamp`, the time the collector received it (gaps 1, 2, and 11). |
| The two captures | Loaded | Identified by their headers. Suricata read both and the evidence checks passed: 1,392 events for NASHUA and 794 for SCRANTON, each on its host's lane. 141 alerts were suggested as Suspicious. |
| The 26 Zeek logs | Loaded | Identified as Zeek output and loaded through the ready-made Zeek mapping, one run per file: 1,725 events for NASHUA and 415 for SCRANTON. Their addresses and ports didn't load (gap 10). |
| The two `.sha1sum` files | Not loaded | Listed as unidentified. Each holds one SHA-1 and a file name, the capture's own checksum. |

The case holds 200,407 events: 196,081 host events, 2,186 from Suricata, and 2,140 from Zeek.

**Scoring.** Each answer item was looked up twice, independently, on copies of the case, with search, the Event page's data, and pivots. The lookups went through the app's local HTTP interface or its server functions, not through the pages in a browser. A third pass settled where the two differed. It tested gaps 1 to 19 and the first claim under Not counted as gaps. It ran the two lookups' searches again, read copies of the host events and the Zeek logs, and ran Hayabusa's JSON mode on a copy of the host events.

Each item has one of four states: reached, partly reached, missed, or out of scope. An out-of-scope item needs something the app doesn't do by design, so it's listed and not counted. No item in this check is out of scope. A fact that the evidence doesn't hold leaves its item partly reached, and so does a record that lists out of order by more than 5 s. [How each item is scored](README.md#how-each-item-is-scored) gives the full rubric.

**Marking and the report.** The answers were then marked on the case itself. 107 events were marked, 103 Malicious and 4 Suspicious, and each mark's note names its answer item and the times that matter. Two more notes carry item 13's comparison and the Zeek record of item 4's session. The app then wrote the Markdown report, the marked-events CSV, the indicators, and the audit trail from those marks. No Summary and no findings were written.

## Results

Item numbers are this page's own, one per step of the plan, in order. Gap numbers refer to the list under Gaps found. Each step runs on SCRANTON as `DMEVALS\pbeesly` unless its row says otherwise. Host times are UTC on 2020-05-02, each event's own time, such as Sysmon's `UtcTime`. The app lists each host event at the collector's later receive time (gap 11), and a time marked "logged" is that time. Network times are UTC on 2020-04-30, from the other run of the scenario (gap 17).

| Item | Answer | What the app showed | State |
|---|---|---|---|
| 1 | Step 1.A. A screensaver payload in `C:\ProgramData\victim\`, its name made to read as a document by a right-to-left override, runs at 02:55:56 and opens a C2 channel to 192.168.0.5 on port 1234 | Sysmon 1 at 02:55:56.157, parent explorer.exe, raw `User` `DMEVALS\pbeesly`. Sysmon 3 at 02:55:59.631 from 10.0.1.4 to 192.168.0.5, with port 1234 in a raw field only (gap 9). A 5156 with the ports, and Suricata's flow from 10.0.1.4 to 192.168.0.5:1234 at 00:08:02. The override isn't in the evidence. The collector's encoding turned it into `???` in the 4688 and 4104 records, and elsewhere into the three characters `â€®` before `cod.3aka3.scr`. Those three characters read as the override only by decoding. | Partly reached |
| 2 | Step 1.B. The payload starts `cmd.exe`, then `powershell.exe` | cmd.exe under the payload at 02:56:04.510 and 02:57:12.376, powershell.exe under cmd.exe at 02:56:14.894, and PowerShell 400 and 800 records from 02:56:15. Found by searching the raw parent field, `ParentImage:*cod.3aka3.scr`. Parent and child join on name and process ID in raw fields (gap 7). | Reached |
| 3 | Step 2.A. A PowerShell one-liner collects document and media files and compresses them to `%APPDATA%\Draft.Zip` | Sysmon 11 at 02:56:18.032 for `C:\Users\pbeesly\AppData\Roaming\Draft.Zip`, written by powershell.exe, and the one-liner's 4104 script block, logged at 02:56:18. A search for `Draft.Zip` gives 42 records, and Same file and Same script block were offered. | Reached |
| 4 | Step 2.B. Draft.Zip is taken over the C2 channel of item 1 | The channel shows, as one Sysmon 3 at 02:55:59.631 and one network flow of 705 s from 00:08:02. The transfer isn't in the evidence. None of the 42 records that name Draft.Zip is a read, and the transfer can't be told apart from the rest of the session's flow (gap 18). | Partly reached |
| 5 | Step 3.A. `monkey.png`, a PNG with a hidden PowerShell payload, is uploaded to `C:\Users\pbeesly\Downloads\` | Sysmon 11 at 02:57:00.933, written by the payload, found by searching `monkey.png`. Same file reaches its deletion by powershell at 03:08:51. The writing process is in a raw field only (gap 7). | Reached |
| 6 | Step 3.B. A COM hijack of `HKCU\Software\Classes\Folder\shell\open\command`, with `sdclt.exe`, bypasses User Account Control (UAC), and a high-integrity callback goes to 192.168.0.5 on port 443 | Sysmon 12 key creations from 02:57:18.181 and Sysmon 13 value sets at 02:58:18.576 and 02:58:30.649 on the key, with the key and data in raw fields and the message, not in the app's registry fields (gap 8). Three sdclt.exe runs at 02:58:42 and 02:58:43, the last at High integrity. control.exe at High under sdclt.exe at 02:58:43.212, then powershell.exe at High under control.exe at 02:58:44.325, and its Sysmon 3 to 192.168.0.5:443 at 02:58:45.688. Zeek holds 2 connections to 192.168.0.5:443 at 00:15:18. | Reached |
| 7 | Step 3.C. The hijack's registry keys are removed | Four Sysmon 12 key deletions at 02:59:15.911 by powershell.exe, from `Folder\shell\open\command` up to `Folder`. The raw `EventType` reads INFO, and the message names DeleteKey (gap 16), so the free-text search `code:12 DeleteKey` finds them. | Reached |
| 8 | Step 4.A. The Sysinternals suite is uploaded and expanded | Sysmon 11 for `Downloads\SysinternalsSuite.zip`, logged at 02:59:44, the `Expand-Archive` 4104 at 03:00:26, and 306 Sysmon 11 file writes by powershell under `SysinternalsSuite\` from 03:00:25.986. | Reached |
| 9 | Step 4.B. The payload's process is found and stopped, and its files are deleted with `sdelete64.exe` | The payload's exit (Sysmon 5), logged at 03:01:28. sdelete64.exe runs at 03:02:04.324 on the payload, 03:03:14.693 on Draft.Zip, and 03:03:33.984 on SysinternalsSuite.zip, and its Sysmon 23 deletions carry the names sdelete gave the files before deleting them. The deletions of monkey.png and the PFX file at 03:08:51 are by powershell, not sdelete. `CommandLine:*sdelete*` finds nothing, and `data.CommandLine:*sdelete*` finds 12 (gap 14). | Reached |
| 10 | Step 4.C. `Invoke-Discovery` runs reconnaissance inside PowerShell, some of it through the Windows API | Two 4104 script blocks at 03:04:04, the call and the function's definition, and 4103 `Get-WmiObject` records from 03:04:04 to 03:04:05. No discovery tool started a process of its own. The Same host within ±N s pivot mixes the four machines (gap 2). | Reached |
| 11 | Step 5.A. A service, "Java(TM) Virtual Machine Support Service" (`javamtsup.exe`), is created for persistence | The 7045, logged at 03:04:16.785, gives the name, the image path, and automatic start. The 4697 was logged at 03:04:16.783. Sysmon 13 records show writes under `Services\javamtsup`. The 7045's raw `AccountName` reads pbeesly, and its message gives LocalSystem (gap 16). Only the Same host within ±N s pivot was offered from it. | Reached |
| 12 | Step 5.B. A shortcut, `hostui.lnk`, is placed in the all-users Startup folder | Sysmon 11 at 03:04:23.681 for `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\hostui.lnk`, by powershell.exe. The only `CurrentVersion\Run` writes on SCRANTON are Defender's own. | Reached |
| 13 | Step 6.A. A browser-credential collector, renamed `accessChk.exe` to pass as a Sysinternals tool, is run | Sysmon 1 at 03:04:34.951 for `C:\Program Files\SysinternalsSuite\accessChk.exe`, at High under powershell.exe, and its write of `passwordsDB` at 03:04:35.069. The original name isn't in the evidence, since the file has no version resource (gap 19). The masquerade shows only by comparing its raw version fields by hand with those of sdelete64.exe and PsExec64.exe from the same folder. | Partly reached |
| 14 | Step 6.B. A private key is exported as a PFX file | Sysmon 11 at 03:04:57.460 for `Downloads\coyn5igj.3io.pfx`, by powershell, and the `Get-PrivateKeys` 4104 at 03:04:57. | Reached |
| 15 | Step 6.C. Password hashes are dumped from LSASS | Two Sysmon 10 records of powershell.exe opening lsass.exe, with access 0x1f3fff at 03:05:16.623 and 0x1fffff at 03:05:16.654. Same target program was offered. No suggestion pointed to them (gap 12). | Reached |
| 16 | Step 7.A. Screenshots, the clipboard, and keystrokes are captured | 4104 script blocks for `Invoke-ScreenCapture` from 03:05:46 to 03:05:55, `Get-Clipboard` at 03:06:43, and `Get-Keystrokes` from 03:05:46 to 03:06:59. | Reached |
| 17 | Step 7.B. Files are collected, compressed and encrypted into a 7z archive, and sent to a WebDAV share on 192.168.0.4 | The 4104 at 03:08:03, Sysmon 11 for `OfficeSupplies.7z` at 03:08:35.270, and Sysmon 3 to 192.168.0.4:80 by powershell at 03:08:47.769 and by svchost.exe at 03:08:50.904 and 03:08:50.988. Zeek's PUT of `/webdav/OfficeSupplies.7z` at 00:32:21.9, with PROPFIND and LOCK requests. The 7z's write was logged 17.1 s late, so it lists behind 90 SCRANTON records that happened up to 15.7 s after it (gap 11). svchost.exe's connections at 03:10:23 are item 19's, not this step's. | Partly reached |
| 18 | Step 8.A, SCRANTON to NASHUA. LDAP lists the domain's hosts, then a remote PowerShell (WinRM) session on NASHUA lists its processes | powershell to the domain controller, 10.0.0.4, on port 389 at 03:09:04.482. The 4104 `Invoke-Command -ComputerName NASHUA`, logged at 03:09:24, and four Sysmon 3 records to 10.0.1.6:5985 from 03:09:23.801. On NASHUA, `wsmprovhost.exe` at 03:09:23.885, four inbound Sysmon 3 records from 10.0.1.4 on port 5985, each 80 ms after one of SCRANTON's, five type 3 Kerberos logons for pbeesly, and PowerShell records with `Get-Process`. Suricata's WinRM alerts, a Case overview lead, gave the network side. The records name both ends. | Reached |
| 19 | Step 8.B, SCRANTON to NASHUA. A UPX-packed payload, `python.exe`, is staged on NASHUA (`Invoke-SeaDukeStage`) | The 4104 call, logged at 03:10:23.348, and svchost.exe's Sysmon 3 records to 192.168.0.4:80 from 03:10:23.020 to 03:10:23.187, the WebDAV fetch. NASHUA's three 5145 records of `Temp\python.exe` on ADMIN$ from 10.0.1.4, and its Sysmon 11 for `C:\Windows\Temp\python.exe`, by System, at 03:10:23.626. The packing shows in Zeek's pe record, with the sections UPX0, UPX1, and .rsrc. Its file ID joins it to Zeek's GET of `/webdav/python.exe`, 5,305,104 bytes, at 00:35:25.658. The pe record's message read only "pe: AMD64" (gap 10). | Reached |
| 20 | Step 8.C, SCRANTON to NASHUA, with stolen credentials. PsExec runs the payload on NASHUA | Four PsExec64.exe runs from 03:11:18.784, each command line naming `\\NASHUA`, an account, a password, and python.exe, and four 4648 records that name NASHUA. On NASHUA, four 7045 and four 4697 records for the PSEXESVC service, python.exe under PSEXESVC.exe, eight type 2 logons for pbeesly, and 28 5145 records from 10.0.1.4 that name PSEXESVC. Suricata's PsExec alerts, a Case overview lead, gave the network side. The records name both ends. | Reached |
| 21 | Step 9.A, the attacker to NASHUA, as an admin account. `Rar.exe` and `sdelete64.exe` are uploaded | Sysmon 11 for `C:\Windows\Temp\Rar.exe` at 03:15:31.530 and for `sdelete64.exe` at 03:15:38.985, both written by `C:\Windows\Temp\python.exe`. | Reached |
| 22 | Step 9.B, on NASHUA. Files are collected, compressed and encrypted with Rar, and sent over the C2 channel to 192.168.0.4 on port 8443 | `working.zip` written in `AppData\Roaming` at 03:16:00.353 by powershell and on the Desktop at 03:16:19.462 by Rar.exe. Rar.exe run with `a -hp` at 03:16:19.395. 348 Sysmon 3 records of python.exe to 192.168.0.4:8443 from 03:15:05.142, and Zeek's 376 ssl records of that traffic from 00:40:44.730. `dest_port:8443 artifact:jsonl` finds 348 host events, all of them 5156 records, and `DestinationPort:8443 code:3` finds the 348 Sysmon 3 records (gap 9). | Reached |
| 23 | Step 9.C, on NASHUA. The staged tools and archives are deleted | sdelete64.exe runs at 03:16:52.456, 03:17:18.030, and 03:17:41.290. Sysmon 23 deletions of Rar.exe at 03:16:52.587 and of `Desktop\working.zip` at 03:17:41.353. cmd.exe deletes sdelete64.exe at 03:17:52.009. | Reached |
| 24 | Step 10.A. SCRANTON restarts, and the `javamtsup` service runs as SYSTEM | The restart's 1074 at 03:18:30, its 6006 at 03:18:35, and its 6009 and 6005 at 03:19:11. javamtsup.exe under services.exe as SYSTEM at 03:19:14.118. Type 5 service logons through the raw `LogonType` field only (gap 6). The 6006, 6009, and 6005 were all logged at 03:19:23, so 2,668 SCRANTON records from before the 6006 list after the 6005, and 3 of the 4 marked records list behind records that happened up to 44.0 s after them (gap 11). | Partly reached |
| 25 | Step 10.B. pbeesly logs on again, and the Startup shortcut's payload starts a follow-on payload with a stolen token, which calls back to 192.168.0.4 on port 443 | Two type 10 logons for pbeesly from 172.18.39.2 at 03:20:46. cmd.exe under explorer.exe at 03:21:19.014, powershell at 03:21:19.323, hostui.exe at High at 03:21:27.276, powershell at Medium at 03:21:27.859, and its Sysmon 3 to 192.168.0.4:443 at 03:21:30.387. These were logged 40 to 46 s late, so 5 of the 6 marked records list behind records that happened up to 39.6 s after them (gap 11). The captures end before this step (gap 17). | Partly reached |

### Totals

The score is 19, 6, 0 of 25. Of the 25 items, 19 were reached (2, 3, 5 to 12, 14 to 16, and 18 to 23), 6 were partly reached (1, 4, 13, 17, 24, and 25), and 0 were missed. No item is out of scope. Of the 31 evidence files, 29 loaded. The host events loaded only from the Import page.

Three items need a fact the evidence doesn't hold: item 1's right-to-left override, item 4's transfer of Draft.Zip, and item 13's original file name. The collector's encoding destroyed the override. No fix in the app moves these three items. Items 17, 24, and 25 are partly reached on order alone, because the app lists each host event at the collector's receive time (gap 11).

Every other fact sits in a raw field of the export or in the collector's message, and search reaches it, though the app's own fields for accounts, logons, processes, registry keys, and ports are empty or wrong (gaps 5 to 9). A field that states a fact wrongly lowers an item only when nothing else states the fact correctly. Item 1's account reads `NT AUTHORITY\pbeesly` in the app's account field, and its raw `User` reads `DMEVALS\pbeesly`, so the account doesn't lower item 1 (gap 5). The key names each step's ATT&CK techniques, and each item is scored on the records of the behavior, so no detection needs to name a technique. The page gives the first run's states.

### What the check showed

- Searches on the export's own field names, such as `LogonType:3`, `TargetImage:*lsass.exe`, and `DestinationPort:8443`, reached values the app's fields left empty. Free text reached the collector's rendered message, as `code:12 DeleteKey` did where a raw field held the collector's value.
- `computer:SCRANTON*` and `computer:NASHUA*` kept one machine's events apart on the shared lane.
- The Case overview's two leads and the Suricata suggestions gave items 18 and 20 their network side.
- Same file (items 3 and 5), Same script block (item 3), and Same target program (item 15) worked where they were offered.
- Zeek's file ID, searched as text, joined the pe record to the http GET for item 19.

### The report

The report listed the 107 marked events in time order. Each had its time, lane, mark, message, mark note, any notes, the tool and its version, the run, the source file and record, the evidence SHA-256, and the event ID. The source file, record, and hash were right on every entry, and the report re-hashed all 31 evidence files, which matched. It also showed these problems:

- Every host entry named the lane `host-events`, not the machine, and gave the collector's receive time (gaps 11 and 15). The machine's name appeared nowhere in the report.
- The 11 marked network records, from the other run of the scenario, listed first, ahead of item 1's first host event. The Hosts table gave every lane's clock offset as "none", with no note (gaps 17 and 20).
- The indicators listed the victims' own addresses and missed most of the attacker's executables, its services, and every hash (gap 21).
- Each host entry was the collector's whole message on one line, and the section on what the marked evidence doesn't prove covered none of the 96 host events (gap 22).
- The entry for item 20's marked PsExec run quoted its command line, password included (see Smaller gaps).
- The marked-events CSV had no evidence SHA-256 and no notes column, so the two notes were only in the report. The [Malware-Traffic-Analysis.net check](mta_2016_01_07.md#gap-15-the-marked-events-csv-lacks-the-evidence-hash-and-notes) found the same gap, its gap 15, and it is still planned in v0.3.0. The CSV's process path was filled on 2 rows, its command line, registry path, and record number on none, and its account domain read `NT AUTHORITY` on 67 (gaps 1, 5, 7, and 8).
- The audit trail was complete and in order. It names a single marked event by the first 1,000 characters of its message, so the entry for item 25's logon was cut mid-sentence (gap 22).

## Gaps found

The check found 22 gaps that held. This page numbers them 1 to 22, in the order the check recorded them, and the results above refer to them by number. Of these, 2 are fixed in v0.3.0, 16 are planned, and 4 are outside the app. A claimed gap that didn't hold is under Not counted as gaps. [CHANGELOG.md](../CHANGELOG.md) lists what v0.3.0 changed, and [known_limitations.md](../known_limitations.md) lists what the app still doesn't do.

Most of the gaps follow from gap 1. With no reader for Windows events exported as JSON, the events load as plain records. Under the rubric only gaps 11, 18, and 19 lower an item, and a character the collector destroyed lowers item 1. The other gaps cost the analyst searches on raw fields, joins by hand, or a weaker report, without hiding a fact.

Each gap has one of the [gap states](README.md#gap-states). A fixed gap names the release that fixed it. A planned gap has a fix or documentation chosen and not yet built. A gap outside the app names where a fix would go, such as the collection, or says the evidence lacks the fact.

Each gap also has a kind and the answer items it affected:

- **Kind** is where the gap lies: no tool or parser, a field missing or wrong, hard to find, lost in the report, or not in the evidence.
- **Items** are the answer items the gap affected. A gap can affect an item without lowering its state.

### Gap 1: No reader turns the JSON export into Windows events

Kind: no tool or parser. Items: all.

Intake identifies the file as generic JSON lines, since it holds JSON, not event XML, so the app's event XML reader never sees it. No ready-made import mapping covers Windows events in JSON. The Import page guessed the time from `@timestamp` and a mapping of 14 fields: the channel, event code, provider, computer, and the collector's rendered message, and, where the names happen to fit, the user, domain, workstation, process, path, and the source and destination addresses and ports. Most of the app's fields for Windows events stay empty or take the wrong value. Gaps 2 to 9 and 11 follow from it. Every value stays in the record's raw fields, which search reaches.

**State now:** Planned. A reader for Windows events exported as JSON, with the app's account, logon, process, registry, and address fields, each event's own time, a lane for each recorded computer, a Hayabusa run in its JSON mode, and report entries named by machine. The Inputs table of [known_limitations.md](../known_limitations.md#inputs) lists such exports as having no reader yet. v0.3.0 adds its [Windows event logs in JSON](../known_limitations.md#windows-event-logs-in-json) section, which gives an import with each event's own time and a lane for each computer.

### Gap 2: Four machines share one lane

Kind: a field missing or wrong. Items: 1, 2, 10, 18 to 20, and 25.

The import takes the host from the folder, so SCRANTON's 131,119 events, NASHUA's 29,056, NEWYORK's 23,935, and UTICA's 11,971 all sit on `host-events`. Each event keeps the computer it recorded, such as `SCRANTON.dmevals.local`, but that doesn't set its lane. The Hosts panel offers a split by recorded computer only for event logs that EvtxECmd or the event XML reader loaded. Asked to split this lane, it answers "host-events's event logs record one computer, so there's nothing to split." The Same host within ±N s pivot mixes the four machines. A search term such as `computer:SCRANTON*` keeps one machine's events apart.

**State now:** Planned, with gap 1: a lane for each recorded computer, for any import that has a computer field. The import in [Windows event logs in JSON](../known_limitations.md#windows-event-logs-in-json) already gives each computer its own lane, taken from `Hostname`.

### Gap 3: The Case overview says no event logs loaded

Kind: a field missing or wrong. Items: none directly.

The Case overview lists `host-events` under "no event logs loaded", though it holds 196,081 Windows events, because its check counts only events read from `.evtx` files. The check for cleared logs needs the same events. It lost nothing here, since the export holds no 1102 or 104 and one 1100.

**State now:** Planned, with gap 1.

### Gap 4: Host roles mislead

Kind: a field missing or wrong. Items: none directly. The report shows it (gaps 15, 20, and 21).

The capture lanes, SCRANTON and NASHUA, are guessed as network devices. The four machines' host events sit on `host-events`, guessed as a workstation, with the domain controller's among them. The Case overview gives the capture lanes as the reference clock and `host-events`' clock as not measured. The report repeated the guessed roles.

**State now:** Planned, with gaps 1 and 2.

### Gap 5: The account is wrong on Sysmon events and missing on Security events

Kind: a field missing or wrong. Items: 1 and 3. The indicators show it too (gap 21).

The guessed mapping takes the account's name from Sysmon's `User` and its domain from the collector's own `Domain` field. Item 1's Sysmon 1 reads `NT AUTHORITY\pbeesly`, while its raw `User` reads `DMEVALS\pbeesly`. The 4624 and 4697 records have no account in the app's fields. Same account from the PsExec event lists 822 events and no 4624. The raw value states the account correctly, so no item is lowered.

**State now:** Planned, with gap 1.

### Gap 6: Logon details are in raw fields only

Kind: a field missing or wrong. Items: 18, 20, 24, and 25.

A 4624's logon type, account, source address, and logon ID are in raw fields only. Every 4624 is filed under "other logon types", with only the Same host within ±N s pivot offered, and no logon links are drawn. `logon_type:3 computer:NASHUA*` finds 0 events, and `LogonType:3 computer:NASHUA*` finds 41. NASHUA's logons for items 18 and 20 record `-` as their source address in the evidence itself, so even a reader for the export couldn't link those by address. Other records name both ends (see Not counted as gaps).

**State now:** Planned, with gap 1.

### Gap 7: Process starts have empty process fields

Kind: a field missing or wrong. Items: 1, 2, 5, 6, 9, 13, and 25.

Sysmon 1 and 4688 records leave the app's process, command line, parent, hash, logon ID, and version fields empty. Same file, Same hash, Same file name, and Same logon session aren't offered from them, and a process chain is joined by hand on the raw process IDs.

**State now:** Planned, with gap 1.

### Gap 8: Registry events have no key or value

Kind: a field missing or wrong. Items: 6 and 7.

Sysmon 12 and 13 records have no registry key, value, or data in the app's fields, since `TargetObject` and `Details` aren't mapped. They fall to "Any other event", with only the Same host within ±N s pivot offered, and the Run key kind can't match them. `registry_key:*Folder*` finds 0 events, and a free-text search for the hijacked key's path finds 14.

**State now:** Planned, with gap 1.

### Gap 9: Ports and addresses split across event types

Kind: a field missing or wrong. Items: 1, 4, 6, 17, 18, and 22.

The mapping reads the destination port from `DestPort`, which only the 5156 records write, so a Sysmon 3 has no destination port in the app's fields. A 5156's `SourceAddress` and `DestAddress` aren't mapped. `code:3 dest_port:8443` finds 0 events, and `DestinationPort:8443 code:3` finds 348.

**State now:** Planned, with gap 1.

### Gap 10: Zeek records had no addresses or ports

Kind: a field missing or wrong. Items: 17 and 19.

The ready-made Zeek mapping read dotted names such as `id.orig_h`, and these logs write `id_orig_h`. `artifact:zeek addr:192.168.0.4` found 0 events, and free text found 1,271. The files records still got their path and hashes, and the http messages showed the Host header. A pe record's message read only "pe: AMD64".

**State now:** Fixed in v0.3.0. Zeek logs that join field names with an underscore load with their connection addresses and ports in the event's fields and message, so `addr:` and the address pivots find them, and a pe record's message names its sections. A Zeek log that an earlier build loaded keeps its mapping through a rebuild. This case gets the fix when its Zeek logs are imported again with `--mapping zeek`, which keeps their event IDs, as the Cases and upgrades table of [known_limitations.md](../known_limitations.md#cases-and-upgrades) says.

### Gap 11: Each host event lists at the collector's receive time

Kind: a field missing or wrong. Items: 17, 24, and 25, and every host entry in the report.

The guessed mapping takes each event's time from `@timestamp`, the time the collector received it, which the app describes as "Logged". The event's own times stay in two raw fields. `EventTime` is when the host logged the event, in the host's zone, UTC-04:00. Sysmon's `UtcTime` is when the event happened, in UTC. The lag reaches 101.2 s for SCRANTON's Sysmon records, 84.4 s for its Sysmon 1, 52.0 s for Security, and 48.8 s for System. Around SCRANTON's restart, 2,668 records from before the 6006 list after the 6005. The report uses the receive time too. Since a raw field keeps each event's own time, the lag counts only through the order rule, which lowers items 17, 24, and 25.

**State now:** Planned, with gap 1: each event at its own time. v0.3.0's [Windows event logs in JSON](../known_limitations.md#windows-event-logs-in-json) gives an import that takes `EventTime` at the host's offset and gives each computer a lane. On a copy of this case imported that way, no record from before the 6006 lists after the 6005, and items 17 and 25 no longer list out of order. Item 24's service start still does, since Sysmon logged it 6.9 s after it happened. The import gives every host event a new ID, so marks made before it don't carry over. The states under Results don't count this import.

### Gap 12: No detection runs on the host events

Kind: no tool or parser. Items: 11, 15, and 20.

No rule or suggestion fires on a host event, and the Case overview's two leads are both Suricata's. Every built-in rule matches 0 host events. The app runs Hayabusa only on `.evtx` files, though Hayabusa reads this export in its JSON mode (`-J`). Hayabusa 4.1.0, run on a copy of the export, hit 28,080 of the 196,081 events, with 1 critical and 154 high detections. They cover items 1, 6, 9, 11, 12, 15, 18, 20, 22, and 23, among them the payload, the UAC bypass, the service install, the Startup shortcut, the LSASS access, WinRM, PsExec's service, Rar with a password, and the sdelete runs.

**State now:** Planned, with gap 1: a Hayabusa run in its JSON mode on Windows events exported as JSON. The Inputs table of [known_limitations.md](../known_limitations.md#inputs) says such exports get no Hayabusa rule hits.

### Gap 13: The built-in share-access rules miss the export's 5145 records

Kind: a field missing or wrong. Items: 19 and 20.

The built-in rules for share access (event 5145) read the message and file path that EvtxECmd writes. The export's 5145 messages put `Share Name:` and `Relative Target Name:` on separate lines, and the file path is empty, so the rules miss them. NASHUA holds 44 5145 records from 10.0.1.4, among them 28 that name PSEXESVC and 3 for `Temp\python.exe` on ADMIN$, and no built-in rule matched one.

**State now:** Planned, with gap 1.

### Gap 14: A search on an empty app field finds nothing, with no hint

Kind: hard to find. Items: 9.

A search field such as `CommandLine:` names the app's own command line field, which is empty here (gap 7). `CommandLine:*sdelete*` finds 0 events with no hint, while `data.CommandLine:*sdelete*` finds 12. `EventType:DeleteKey` finds 0 too. `process:*sdclt.exe` finds 3 process exits (4689) and 4 object-handle records, not the three sdclt.exe starts. The analyst must know Sysmon's and Security's field names and the `data.` prefix. The data is loaded and correct, so no item is lowered.

**State now:** Planned. A search that finds 0 events because its field is an empty app field will say so.

### Gap 15: Report entries name the lane, not the machine

Kind: lost in the report. Items: all.

Each of the 96 marked host events reads `host-events` as its host in the report, at the collector's receive time, and the machine's name appears nowhere in the report. The marked-events CSV keeps it, in `winlog.computer_name`: `SCRANTON.dmevals.local` on 75 rows and `NASHUA.dmevals.local` on 21. The report's Hosts table lists NASHUA and SCRANTON as "Network devices (guessed)" and `host-events` as "Workstations (guessed)", with no names or addresses.

**State now:** Planned, with gaps 1 and 2: report entries named by machine, at the event's own time.

### Gap 16: The collector replaced some of the events' own values

Kind: not in the evidence. Items: 6, 7, and 11.

Where an event field has the same name as one of the collector's own fields, the export's field holds the collector's value, and the rendered message keeps the event's. The raw `EventType` reads INFO on all 61,151 Sysmon 12 and 17,541 Sysmon 13 records, while their messages name the key creation, value set, or deletion. The javamtsup 7045's raw `AccountName` reads pbeesly, while its message gives LocalSystem. The message states each fact correctly, so no item is lowered.

**State now:** Outside the app, in the collector's export. The export's fields don't hold the events' values, so there is nothing to fix in Glessner.

### Gap 17: The host events and the captures come from two runs

Kind: not in the evidence. Items: 4, 17, 18, 19, and 25.

The host events record a run of the scenario on 2020-05-02, and the captures and Zeek logs record another, on 2020-04-30. The offset between them drifts from 2 days 2:47:57 at step 1.A to 2 days 2:34:20 at step 9.B, so no one clock offset aligns them, and the app leaves `host-events`' clock as not measured. Host and network records of one action match by host and address, not by time. The captures end at 00:46:59.97 on 2020-04-30, about 03:21 in host time, so step 10 has no network record. Order isn't judged across the two clocks.

**State now:** Outside the app, in the dataset. The two runs are a property of the published files.

### Gap 18: No record shows Draft.Zip's transfer

Kind: not in the evidence. Items: 4.

The transfer over the C2 channel leaves no host record of its own. None of the 42 records that name Draft.Zip is a read, and no 4656 or 4663 names it. The network records the whole C2 session as one flow of 705 s, so the transfer can't be told apart from the rest of the session.

**State now:** Outside the app, in the evidence. Only the collection could record the transfer.

### Gap 19: accessChk.exe's original name isn't recorded

Kind: not in the evidence. Items: 13.

accessChk.exe has no version resource, so its Sysmon 1 record's FileVersion, Description, Product, Company, and OriginalFileName all read `-`. sdelete64.exe and PsExec64.exe, from the same folder, carry Sysinternals version data. The masquerade shows only by comparing those raw fields by hand (gap 7).

**State now:** Outside the app, in the evidence. The evidence doesn't hold the original name, so there is nothing to fix in Glessner.

### Gap 20: The report didn't say the host and network clocks weren't aligned

Kind: lost in the report. Items: 1, 4, 6, 17 to 20, and 22.

The report's Hosts table gave every lane's clock offset as "none", with no note, while the Case overview read `host-events`' clock as not measured (gap 17). In the report's one time order, the 11 marked network records, dated 2020-04-30 and recording steps 1.A to 9.B, listed ahead of item 1's first host event.

**State now:** Fixed in v0.3.0. The report's Hosts table gives the offset applied and what the clock check found, such as `none; not measured`. The network records still list first, since the two runs are two days apart (gap 17).

### Gap 21: The indicators list the victims and miss the attacker's files

Kind: lost in the report. Items: 1, 9, 11, 13, 20, 24, and 25.

The indicators export took 25 values from the 103 Malicious events: 16 files, 5 IP addresses, 3 accounts, and 1 domain. It listed the victims' own addresses, 10.0.1.4, 10.0.1.6, and 10.0.0.4, beside the attacker's 192.168.0.5 and 192.168.0.4, since no lane has an address to leave out (gap 4). It missed the attacker's executables (the `.scr` payload, PsExec64.exe, accessChk.exe, javamtsup.exe, and hostui.exe), its services (javamtsup and PSEXESVC), and every hash, since those values are in raw fields only (gaps 1 and 7). It listed the names sdelete gave two files before deleting them, and the account as `NT AUTHORITY\pbeesly` (gap 5). The domain, `nashua`, came from the HTTP host of a WinRM alert. `C:\Windows\PSEXESVC.exe` was listed, from the process field of a NASHUA 4624.

**State now:** Planned. Indicators that leave out the case's own hosts and take the attacker's executables, services, and hashes.

### Gap 22: Host entries read as generic records

Kind: lost in the report. Items: every item with a host event.

Each host entry in the report is the collector's whole rendered message on one line. 73 of the 107 entries run over 400 characters and 28 over 1,000, up to the import's limit of 2,000 characters, which also cuts longer script blocks. The section on what the marked evidence doesn't prove has one note, for the 2 Suricata alerts, and none for the 96 host events. The audit trail names a single marked event by the first 1,000 characters of the same message, so the entry for item 25's logon is cut mid-sentence. The cause is gap 1.

**State now:** Planned. The reader in gap 1 will give each event the app's own message. The report's section on what the marked evidence doesn't prove will cover event log entries.

### Smaller gaps

The check met four more problems outside the numbered gaps.

- The report's entry for item 20's marked PsExec64.exe run, and the marked-events CSV, quote its command line with the password after `-p`. The value is in the evidence and an analyst needs it, but a report shared outside the team needs it removed. Planned: a choice to redact secrets in command lines in the report and the exports.
- The case's database file grew from 519,057,408 bytes to 1,043,083,264 on one open and a clean close. Fixed in v0.3.0, by documentation: the Scale and speed table of [known_limitations.md](../known_limitations.md#scale-and-speed) says a case's database file grows to about twice its size, once, the first time the case closes after it is built or copied.
- 18 of the 45 ATT&CK IDs in the key, such as T1086 and T1050, come from before ATT&CK had sub-techniques and aren't in ATT&CK v20.0, the version that a finding's ATT&CK field and the tag picker take ([known_limitations.md](../known_limitations.md#suggestions-roles-and-findings)). No findings were written, so this didn't arise. Outside the app, in the emulation plan's IDs.
- A Zeek files record's `tx_hosts` and `rx_hosts`, the addresses that sent and received the file, aren't read, in the checked build or in v0.3.0. Open: no fix is chosen.

### Not counted as gaps

- Item 1's file name drawn reversed. The claim was that the page draws the right-to-left override and hides the `.scr` extension. The evidence holds no override. All 133 raw records that name the payload carry `â€®` where the override was, or `???` in the 4688 and 4104 records. `â€®` is the override's UTF-8 bytes read as Windows-1252 and stored again. No event in the case holds the override, so the name draws left to right as `â€®cod.3aka3.scr`. The masquerade itself can't be shown from this evidence, and that missing fact leaves item 1 partly reached. The checked build had no handling for such characters, which put other evidence at risk. v0.3.0 shows a bidi control in evidence text as a visible `[U+202E]` on the pages, in the Markdown report, and in the audit trail. The case name in the Case panel still shows one as it is ([known_limitations.md](../known_limitations.md#search-lists-and-the-timeline)).
- No record of item 19's packing. Zeek's pe record holds it, with the sections UPX0, UPX1, and .rsrc, and its file ID joins it to the files record and the GET of python.exe.
- A join across hosts by time alone for items 18 and 20. For item 18, NASHUA's Sysmon 3 records of the WinRM connections name 10.0.1.4, and SCRANTON's script block names NASHUA. For item 20, the PsExec command lines and the 4648 records name NASHUA, and NASHUA's 5145 records name 10.0.1.4. The records name both ends, so neither item rests on a comparison by hand.

## Limits of this check

- The answers were known during the work. The check shows the evidence is present and readable, not that an analyst would find it without the answers.
- After setup, which used the start page, the Tools page, and the Import page, the work went through the app's local HTTP interface and its server functions, not by clicking through the page. How an analyst works in the page isn't measured.
- The score comes from a build made before v0.3.0. The page gives the first run's states.
- The dataset has no question-and-answer key. The 25 items are the check's reading of the emulation plan, one per step, with the corrections the evidence called for.
- The report's Summary and Findings sections weren't written, so how a written finding renders wasn't checked.
- What Hayabusa's detections add inside the app isn't measured, since the app doesn't run Hayabusa on this input (gap 12).
- The case holds one collector's export, with NXLog's field names. Other collectors' and SIEMs' exports of Windows events weren't tried.
- The host events and the captures come from two runs of the scenario, so no host record and network record of one action could be compared by time (gap 17).
- Gaps 20 to 22 were found while the report was written, and no other pass checked them. The third pass checked every other gap.
- The What has been checked section of [known_limitations.md](../known_limitations.md#what-has-been-checked) says what else hasn't been shown.
