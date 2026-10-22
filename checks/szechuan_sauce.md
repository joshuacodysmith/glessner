# Check: The Stolen Szechuan Sauce

## What this check is

This is an open-answer check. The case was worked with its published answers at hand, so the check shows whether the evidence each answer rests on is present and readable in Glessner. It doesn't show that an analyst who doesn't know the answer would find it. Blind rounds do that, and none has run yet.

The check scored 25 items from the published answers. Its score is 19, 5, 0 of 24, plus 1 out of scope. Of the 24 items in scope, 19 are reached, 5 are partly reached, and none is missed. The recommendations item is out of scope. Two more questions aren't in the score: the domain users' passwords, which only memory holds, and the original contents of Beth's secret file, which the next full run of this check scores.

## The dataset

- **Source:** [The Stolen Szechuan Sauce](https://dfirmadness.com/the-stolen-szechuan-sauce/), a case from [DFIR Madness](https://dfirmadness.com/) by its founder, James Smith.
- **Credit and license:** The case page states no formal license. It lets educators and students use the materials as long as credit goes to the site and its authors. This page credits DFIR Madness and its authors. This repository holds none of the case's files.
- **What it holds:** Two hosts in one environment. DC01 (10.42.85.10) is a Windows Server 2012 R2 domain controller that also holds a file share. DESKTOP-SDN1RPT (10.42.85.115) runs Windows 10. The case supplies, for each host, a disk image (E01), a memory capture, a pagefile, Autoruns output, and a Protected Files archive. It also supplies one packet capture of the network, `case001.pcap` (pcapng, 197,583,252 bytes). The check used the disk images, the Autoruns output, and the capture, and didn't use the memory captures, pagefiles, or Protected Files archives.
- **Where the answers come from:** The case's [answers page](https://dfirmadness.com/answers-to-szechuan-case-001/), read on 2026-10-14. Its times are UTC on 2020-09-19. It notes that the hosts' clocks were set to UTC-7 while the capture's router was right at UTC-6, so the host artifacts read an hour later than the capture.

## How it was run

[glossary.md](../glossary.md) defines terms such as lane, pivot, and mark.

**Date and build.** The check ran on 2026-10-14, on a build that predates v0.1.0, the first build with a version number. Each gap's state under Gaps found says where the gap stands in v0.2.0, and a fixed gap names the release that fixed it.

**Evidence.** Glessner reads a folder of collected files, not a disk image (see Inputs in [known_limitations.md](../known_limitations.md#inputs)). Each host's E01 image was unpacked into a collection that holds every artifact type the app reads. Each host's Autoruns CSV (from `DC01-autorunsc.zip` and `DESKTOP-SDN1RPT-autorunsc.zip`) went into its folder, and the capture (from `case001-pcap.zip`) into a folder of its own. The two Autoruns zips and the capture zip matched the MD5 hashes that the case page publishes. The evidence folder held 536 files, 715.9 MB.

**Loading.** A case was made from the start page, and intake hashed and identified the files. The Tools page's **Run and load everything ready** then made 27 tool runs in 3 minutes 35 seconds and loaded 1,243,027 events. Every run succeeded and every evidence check passed.

| Source | Runs | Events |
|---|---|---|
| EvtxECmd | 2 | 126,259 |
| Hayabusa | 2 | 2,291 hits |
| MFTECmd, `$MFT` | 2 | 901,742 |
| MFTECmd, `$J` | 2 | 125,548 |
| RECmd | 2 | 15,261 |
| Suricata, `case001.pcap` | 1 | 67,858 |
| SrumECmd | 1 | 2,481 |
| PECmd | 1 | 637 |
| AmcacheParser | 2 | 367 |
| WxTCmd | 4 | 185 |
| JLECmd | 2 | 137 |
| SBECmd | 2 | 120 |
| LECmd | 2 | 98 |
| SQLECmd | 1 | 42 (notifications) |
| RBCmd | 1 | 1 |

- Not loaded: the two Autoruns CSVs, which the build recognized as plain CSV and offered on the Import page (gap 10). Seven hash-record JSON files left by the extraction step, which were offered as JSON. One zero-filled Prefetch file, which intake listed as unidentified with its reason.
- Suricata found 461 alerts. They include 5 "Possible Metasploit Payload" alerts at severity 1 and 2 executable-download alerts at severity 1.
- SrumECmd and the SQLite tools work on copies of their databases, and those copies changed during the runs, as designed. Every evidence file matched its hash after each run and again when the summary was written.

**Working the case.** The answers were found through the app's search and event queries, the same ones the search box uses, not by clicking through the page. Searches used field terms (`code:`, `host:`, `channel:`), plain words, and exclusions. Ten answer events were marked, each with a note. The build then wrote a findings summary, a CSV of the flagged events, and the audit trail export. In v0.2.0 the Markdown report replaces the findings summary.

**Scoring.** Each item has one of four states: reached, partly reached, missed, or out of scope. An out-of-scope item needs something the app doesn't do by design, so it's listed and not counted. [How each item is scored](README.md#how-each-item-is-scored) gives the full rubric.

The answers page asks two questions beyond the 25 items. The domain users' passwords are held only in memory, which is out of scope. The other question asks for the original contents of Beth's secret file, whose original name is item 23. File contents are in scope, but this check left that question out of its 25 items and doesn't record what the app shows of the file. The next full run of this check scores it as a 26th item.

## Results

Item numbers are this page's own, in the order of the table. Gap numbers refer to the list under Gaps found. Times in brackets are host time, as the app shows it. The answers page's corrected time is an hour earlier.

| Item | Answer | What the app showed | State |
|---|---|---|---|
| 1 | Server OS: Windows Server 2012 | RECmd's system info read "Windows Server 2012 R2 Standard Evaluation". Found by searching `ProductName`. The findings summary's Hosts table showed no OS (gap 7). | Reached |
| 2 | Desktop OS: Windows 10 | RECmd's system info read "Windows 10 Enterprise Evaluation", build 19041.264. A search for `ProductName` ranked it 89th of 93 results, behind Amcache rows, and the check stopped at the server's line (gap 7). The value was loaded and correct. Being hard to find is a gap, not a lower state. | Reached |
| 3 | Server time zone: Mountain, UTC-6 per the answers page. The machines were set to UTC-7. | Both hosts read Pacific Standard Time from their SYSTEM hives, shown with the source. Matching the answers page's UTC-6 needed the clock comparison in item 14. | Partly reached |
| 4 | Entry: RDP brute force from 194.61.24.102 against Administrator on the DC | About 96 Security 4625 failures that name workstation `kali`, with the address `-`, which is how Windows logs RDP failures before authentication. RDP event 131 records from 194.61.24.102, and a 4624 type 10 logon at [03:21:48]. In the capture, 198 "MS Remote Desktop Administrator Login Request" alerts and a scan alert from 02:19. Hayabusa's suggestion "External Remote RDP Logon from Public IP" and the Sources outside the case lane, with its logon arrow into DC01, led to it. | Reached |
| 5 | Malicious process on the DC: coreupdater, later migrated into spoolsv.exe | The file and its service. DC01, a server, has no Prefetch files. A search for `coreupdater` found 115 events across both hosts and the capture. The migration is in memory only and out of scope. | Reached |
| 6 | Payload downloaded from 194.61.24.102 through Internet Explorer during the RDP session | The capture shows an HTTP GET for `/coreupdater.exe` at 02:24:06, with Emerging Threats (ET) "PE EXE or DLL Windows file download" alerts. `$J`, the NTFS change journal, shows `coreupdater[1].exe` written to the Internet Explorer cache at [03:24:06]. Internet Explorer's own history (WebCacheV01.dat) isn't read. | Reached |
| 7 | Command-and-control (C2) address 203.78.103.109 | Five "Possible Metasploit Payload" alerts at correct times. Every C2 flow sat at 21:58:07 on 2020-09-18, hours before the attack (gap 1). The alerts give the address at their own times, so the flows' wrong times don't lower the item. | Reached |
| 8 | On disk at `C:\Windows\System32\coreupdater.exe` (the answers page writes `coreupdate.exe`) | MFT records and the service install record (event 7045). | Reached |
| 9 | When it first appeared | The capture's download at 02:24:06 and `$J`'s file creation at [03:24:06] agree once the hour is allowed for. | Reached |
| 10 | Moved from Administrator's Downloads to System32 | `$J` holds the move: `\Users\Administrator\Downloads\coreupdater.exe` renamed to `\Windows\System32\coreupdater.exe` at [03:24:50], both under MFT entry 87137. The MFT flags `System32\coreupdater.exe` as copied. `$J` also shows a file of the same name created and deleted in Downloads at [03:24:12], but that was an earlier use of the same MFT entry, not the file that moved. The move was hard to find. | Reached |
| 11 | Capabilities: Metasploit | The ET alert names Metasploit. Found by search. No suggestion pointed to it (gap 3). | Reached |
| 12 | Persistence: a registry Run entry and a service | Event 7045 `coreupdater` on DC01 at [03:27:49] and on DESKTOP at [03:42:42]. RECmd's Run (SYSTEM) entry `coreupdate`, which launches hidden PowerShell, at [03:30:01]. Hayabusa's "Svc Installed" and "Suspicious Service Path" suggestions pointed to the services. Both entries are also in the DC's Autoruns CSV, which the build couldn't load without a mapping (gap 10). | Reached |
| 13 | Lateral movement: RDP from the DC to DESKTOP-SDN1RPT as Administrator, 02:35:54 corrected | DESKTOP's 4624 type 3 and type 10 logons from 10.42.85.10 at [03:36:22] and [03:36:24]. The timeline drew a logon arrow from DC01 to DESKTOP. | Reached |
| 14 | The hosts' clocks run an hour ahead of the capture's | Nothing in the build compared host times with network times. The hour was found by comparing the two times in item 9 by hand, and the findings summary sorted the two clocks as one (gap 2). | Partly reached |
| 15 | secret.zip taken from the DC at about 02:31 | `$J` shows `\FileShare\Secret.zip` created at [03:32:39]. Its transfer doesn't show. Nothing names the file inside the encrypted C2 sessions, whose flows also carried the wrong time on this build (gap 1). | Partly reached |
| 16 | loot.zip taken from the Desktop at about 02:48 | LNK shows `C:\Users\mortysmith\Documents\loot.zip` at [03:46:15]. Its transfer doesn't show, as for item 15. | Partly reached |
| 17 | Network: DC 10.42.85.10, Desktop 10.42.85.115 | Both addresses in the Hosts panel. | Reached |
| 18 | The Szechuan sauce file taken at about 02:30 | `C:\FileShare\Secret\Szechuan Sauce.txt` in LNK, jump list, and MFT entries. A search for `Sauce` found them. A search for `Szechuan` gave 5,861 matches, 29 of them real (gap 6). The answers page's timeline has the attacker accessing the file at 02:32:21. At [03:32:21.500], the same second on DC01's clock, `$J` and the MFT show `Recent\Szechuan Sauce.lnk` in Administrator's profile deleted and created again, after the RDP logon of item 4. The answers page doesn't tie the file to Secret.zip, whose transfer is item 15. | Reached |
| 19 | Beth's secret changed and Morty's file taken, about 02:34 | `Beth_Secret.txt` modified at [03:34:56] (LNK). Morty's `Thoughts.txt` is in DESKTOP's LNK files and jump lists, but its theft at 02:34 wasn't pinned down. | Partly reached |
| 20 | Last interactive logoff about 03:00. The attacker still active when the capture ended. | The last 4647 user-initiated logoff on DC01 at [03:57:40], which is 02:57:40 corrected. Metasploit alerts continue to 04:08:45. The app states no conclusion, so under the rule for conclusions in [How each item is scored](README.md#how-each-item-is-scored), the item is scored on the facts the answers page gives as its basis. The check didn't record the capture's last packet time. | Reached |
| 21 | Accounts on the DC: Administrator | Administrator's RDP logons. | Reached |
| 22 | Accounts on the Desktop: Administrator and Rick Sanchez | Logons for both, types 10, 2, and 11. | Reached |
| 23 | Beth's secret file's original name: Secret_Beth.txt | `$J` rename records and LNK entries for `SECRET_beth.txt`, found by searching `Secret_Beth`. | Reached |
| 24 | Time-stomped file: Beth_Secret.txt | MFT events for the file carry the flag `SI<FN, possible timestomping; SI times have zero microseconds`. Found by search. No suggestion pointed to it (gap 9). | Reached |
| 25 | Recommendations: RDP behind a VPN, firewall, IPS, EDR, password policy | Nothing. The app leaves recommendations to the analyst by design, so the item is out of scope and isn't counted (gap 11). | Out of scope |

### Totals

The score is 19, 5, 0 of 24, plus 1 out of scope. Of the 24 items in scope, 19 were reached (1, 2, 4 to 13, 17, 18, and 20 to 24), 5 were partly reached (3, 14, 15, 16, and 19), and 0 were missed. Item 25, the recommendations, is out of scope and isn't counted. Item 5's move into spoolsv.exe shows only in memory, so that part of the item is out of scope, and the item is scored on the rest.

The table gives each item's state on the build the check ran on, before any fix. No item has been scored again on a release. Since the fixes, item 7's C2 flows sit at the right times. Items 15 and 16 would stay partly reached. The transfers ride the encrypted C2 sessions, whose start times are now right, but nothing in the evidence names the files inside them.

### What the check showed

- The timeline and its logon links worked across the host artifacts and the capture. The attacker's address got its own lane with a logon arrow into DC01, and Hayabusa flagged the entry.
- Search found every file the answers page names. The NTFS change journal, LNK files, jump lists, and the MFT together gave the file story.
- The findings summary carried each marked event with its tool, run, source file and record, and the evidence file's SHA-256.
- The suggestions mix the attack with the dataset's own setup on 2020-09-17. Of 63 Hayabusa suggestions, some are accounts added to groups and a DCShadow warning from that setup.

## Gaps found

The check found 12 gaps. This page numbers them 1 to 12, in the order the check recorded them, and the results above refer to them by number. Of these, 10 are fixed in v0.1.0, 1 is open, and 1 is out of scope. Item 10's move was also hard to find. That gap has no number here, and no fix is chosen for it. A "Checked" line says what the same case showed after the fix. [CHANGELOG.md](../CHANGELOG.md) lists each release's changes, and [known_limitations.md](../known_limitations.md) lists what the app still doesn't do.

Each gap has one of the [gap states](README.md#gap-states). A fixed gap names the release that fixed it. An open gap is deferred or not yet decided. An out-of-scope gap is one the app leaves out by design.

### Gap 1: Suricata flow times were wrong

Suricata's EVE output gives every record a `timestamp`. For 61,863 of the capture's 67,858 records, that timestamp was the time of the capture's first packet. The affected records were every flow (32,573), most TLS records (29,206), and some SMB, DCERPC, and file records. Each flow's own `start` time was right, but the app trusted `timestamp`. The C2 and exfiltration flows sat at 21:58:07 on 2020-09-18, hours before the attack. That false spike was the busiest stretch of a search, and the transfers in items 15 and 16 couldn't be timed. The app's synthetic test capture held one short flow, so tests hadn't shown it.

**State now:** Fixed in v0.1.0. Suricata runs in single-thread mode (`--runmode single`). In its default multi-threaded mode, reading a file, Suricata gave flows the first packet's time. Single-thread mode logs each at its own time and was no slower on this capture. The app places each flow at its own start time, not at the time Suricata logged it. For EVE files made elsewhere, the app moves a record logged before its flow began to the flow's start.

Checked: a rebuild of the existing output moved 29,290 records to their flow's start, and none remained at the first packet's time. The C2 flows now start at 02:25, 02:29, 02:40 (from the Desktop), and 02:56. A fresh run in single-thread mode needed no record moved.

### Gap 2: Host and network clocks disagreed, and nothing said so

The hosts' clocks ran an hour ahead of the capture's. The build compared nothing across the two, and the findings summary's Hosts table showed "Clock offset: none" for all three lanes. The summary then told the story out of order: the capture's download at 02:24 came before DC01's RDP logon at [03:21], which really happened at 02:21. An analyst had to find the hour by hand.

**State now:** Fixed in v0.1.0. The app measures each host's clock against the capture, from events both sides record, such as an RDP connection or a file download, and shows the skew. Times stay as recorded by default. A host's lane carries a flag while a measured skew isn't applied, an event links across the hour to its pair in the capture, and you can align a host to the capture. The clock check also lists the clock changes a host logged. The app doesn't change a clock on its own. The Time and links section of [known_limitations.md](../known_limitations.md#time-and-links) lists the limits.

Checked: the app suggested an offset of -3,599.5 s for both hosts, with the capture as the reference. 495 of DC01's 535 event pairs agree with it, and all 3 of DESKTOP's. It listed DESKTOP's two clock changes. The coreupdater download's capture record and DC01's cache file entry name each other and are linked across the hour. Aligning DC01 makes the link nearly vertical.

### Gap 3: Suricata alerts didn't suggest a mark

Hayabusa hits at medium level and above suggested a mark, but Suricata alerts did not. The Metasploit and executable-download alerts were found only by search.

**State now:** Fixed in v0.1.0. Suricata alerts of severity 1 and 2 are a built-in source of Suspicious suggestions, grouped by signature. Nothing is marked until you accept it.

Checked: 11 alerts matched, 10 of them pending because one was already marked, in four groups in severity order. The pending count went from 158 to 168.

### Gap 4: The capture's lane was guessed as a workstation

A capture's folder became a host lane named `network`, and the app guessed its role as a workstation, with the note "Nothing points to a server or domain controller". The lane sat in the Workstations group and in the summary's Hosts table.

**State now:** Fixed in v0.1.0. A lane that holds only Suricata or Zeek output counts as a network device.

Checked: the `network` lane reads Network devices, "Its events all come from Suricata logs".

### Gap 5: The start page and the Tools page disagreed

The start page said "15 of 16" tools were found, and the Tools page said 16 of 16. The Tools page also listed the ready capture as a file "no installed tool reads", and listed 11 SQLite log files as unread, although SQLECmd and WxTCmd copy them with their databases.

**State now:** Fixed in v0.1.0. A capture is listed as unread only when no runnable tool reads it. A database's logs count as read when its tool copies them. The start page counts the built-in reader as a found tool.

Checked: both pages show 16 of 16 tools, there is no group of found output, and nothing is listed as unread.

### Gap 6: Search matched paths that tools wrote into their output

RECmd writes the analysis machine's full path to a plug-in's output file into its rows. A case folder whose name holds a search word makes every one of those rows match. Here the folder name held the dataset's name, so a search for `Szechuan` gave 5,861 matches and 29 were real. A client or malware name in a case path would do the same.

**State now:** Fixed in v0.1.0. The app records RECmd's `PluginDetailFile` relative to the run folder.

Checked: 29 events mention Szechuan, all of them real, and no event holds a path from the analysis machine.

### Gap 7: A host's OS was hard to find

Neither the Hosts panel nor the findings summary's Hosts table showed an OS, and finding one by search meant going through other rows (items 1 and 2). Both hosts' OS values were loaded. The gap was that they were hard to see and to find.

**State now:** Fixed in v0.1.0. The app reads each host's OS from its live SOFTWARE hive, so a Windows.old or RegBack copy can't mix in. The Hosts panel and the report show each host's product name and build.

Checked: DC01 reads Windows Server 2012 R2 Standard Evaluation, build 9600. DESKTOP reads Windows 10 Enterprise Evaluation, version 2004, build 19041.264.

### Gap 8: A Suricata message read as if the attack failed

Suricata writes `failed` as the protocol when it can't name one. The app showed that word bare, so an alert read "... (A Network Trojan was detected, severity 1) failed 203.78.103.109:443". It looked as if the attack had failed.

**State now:** Fixed in v0.1.0. The message shows the transport in place of `failed`.

Checked: no network message contains "failed".

### Gap 9: The SI<FN flag alone fires on many Windows files

The MFT flag `SI<FN` fires on many Windows servicing files. Only the zero-microseconds flag picked out `Beth_Secret.txt`. No suggestion pointed to the file, and a rule built on `SI<FN` alone would raise noise.

**State now:** Open. Deferred. A timestomping rule would need to use the zero-microseconds flag together with `SI<FN`, not `SI<FN` alone.

### Gap 10: Autoruns output wasn't loaded

The build treated Autoruns output as plain CSV. Both persistence entries of item 12 sat in it, unloaded, and an import needed a time column and a zone chosen by hand.

**State now:** Fixed in v0.1.0. The app recognizes an Autoruns CSV by its header and loads it as found output, one event per autostart entry. The image is the file path, the launch string is the command line, the location is the registry key, and the signer and hashes go in the event's data. Autoruns' Time column is the image's PE link time, or a script's last write, not when the entry was set, and the event's time description says so. Autoruns writes all its local times at one UTC offset. The app reads that offset from the host's SYSTEM hive (`ActiveTimeBias`) and records it with the load. Link times don't widen the case's window. The Import page still lists the CSV, for a host without a hive.

Checked: 849 entries loaded on DC01 and 1,283 on DESKTOP, of which 6 and 8 have no time. The Tools page counts them. Both hosts' coreupdater service and `coreupdate` Run entry load as events, and the service's image joins the MFT, `$J`, Prefetch, Amcache, SRUM, and 7045 records for coreupdater.exe. Read at UTC-07:00, the Run key's row falls in the minute of RECmd's last write for it on each host ([03:30] and [03:44]). DESKTOP's 33 location rows of 2019-12-07 fall in the hour of its MFT and RECmd records from that morning. The case's window stays 2013-06-18 to 2020-09-19, as before the load.

### Gap 11: No guidance at the end

The app lists evidence and gives no recommendations, which item 25 asks for. The findings summary listed evidence only, and the app never writes a finding for you.

**State now:** Out of scope. By design, the app writes none of the report's narrative ([scope.md](../scope.md#not-in-scope)) and no finding or verdict, so the recommendations in item 25 stay with the analyst. v0.2.0 adds Findings, where the analyst writes conclusions with the events that support them. It also adds a note on what some kinds of record don't prove, such as a Prefetch file or a Suricata alert, and an Indicators export from the events marked Malicious.

### Gap 12: Marks on network events were lost when Suricata ran again

The check found this gap while gap 1 was being fixed. Suricata records were known by their line number in the EVE file. That number changes from run to run, as do flow IDs and the times of records logged at a flow's timeout. Running Suricata again lost the two marks on network events.

**State now:** Fixed in v0.1.0. The app knows each record by its content, keyed on its flow's start. Marks made after the fix survive later Suricata runs. The fix doesn't recover marks made under the older scheme.

Checked: the keys were identical across two single-thread runs and a default run of the capture (67,397 each, run without rules). The two network marks, made again after the rebuild, survived another Suricata run. The two marks made before the fix keep their old IDs and show as orphan marks, which the app describes as marks on events no longer in the case.

The case format upgrade in v0.2.0 doesn't recover them either. It changes IDs keyed on a flow's start in the analysis machine's time zone to IDs keyed on the start in UTC, and these two marks predate both schemes. Upgrading a copy of this case to case format 3 left both as orphan marks.

### Not counted as gaps

- The 4625 failures without an address. Windows records `-` for RDP failures before authentication.
- Internet Explorer's history. The capture and `$J` covered the download. The app doesn't read WebCache yet, and [known_limitations.md](../known_limitations.md#inputs) lists it.
- Memory. Glessner reads a triage collection, not memory images.

## Limits of this check

- The answers were known during the work. The check shows the evidence is present and readable, not that an analyst would find it without the answers.
- The case was worked through the app's search and event queries, not by clicking through the page. How easily an analyst finds things in the page isn't measured.
- The states come from a build that predates v0.1.0. Each fixed gap was checked on this case before v0.1.0, but no item has been scored again on a release.
- It covers one case: two hosts and one capture from a public practice set. It includes no real incident and no real KAPE collection.
- Answers that rest on memory are out of scope. File contents are in scope, but the original contents of Beth's secret file aren't among the 25 items scored here.
- The step that unpacks the images into the evidence folder isn't part of this repository, so a reader can't yet rebuild the same folder from the published images.
- The What has been checked section of [known_limitations.md](../known_limitations.md#what-has-been-checked) says what else hasn't been shown.
