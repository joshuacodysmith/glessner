# Check: NIST CFReDS Data Leakage Case

## What this check is

This is an open-answer check. The case was worked with its published answers at hand, so the check shows whether the evidence each answer rests on is present and readable in Glessner. It doesn't show that an analyst who doesn't know the answer would find it. Blind rounds do that, and none has been finished yet. The answer document asks 60 questions, and each question is one item. The check's score is 26, 21, 10 of 57, plus 3 out of scope. Of the 57 items in scope, 26 were reached, 21 were partly reached, and 10 were missed. The other 3, items 53, 54, and 56, are out of scope. They are answered only by reading the removable media's file systems, recovering deleted files, and carving, work the app leaves to image tools by design.

## The dataset

- **Source:** [The Data Leakage Case](https://cfreds-archive.nist.gov/data_leakage_case/data-leakage-case.html), from [the CFReDS Project](https://cfreds-archive.nist.gov/), the Computer Forensic Reference Data Sets of the National Institute of Standards and Technology (NIST). The dataset page names no individual authors.
- **Credit and license:** The dataset page states no license of its own. [NIST's statement on its data](https://www.nist.gov/open/copyright-fair-use-and-licensing-statements-srd-data-software-and-technical-series-publications) says that NIST data generally aren't subject to copyright protection in the United States, that they may be protected in other countries, and that users should acknowledge NIST as the source. This page acknowledges NIST as the dataset's source. This repository holds none of the dataset's files.
- **What it holds:** An insider case from 2015-03-22 to 25, in which a PC's user is suspected of leaking the company's data. The dataset holds disk images of the PC and of three removable media. The answers name these people, devices, and addresses:

  | Name | What it is |
  |---|---|
  | informant (Iaman Informant) | The suspect and the PC's main user, RID 1000. Outlook account `iaman.informant@nist.gov` |
  | `spy.conspirator@nist.gov` | The conspirator the suspect emails |
  | admin11, ITechTeam, temporary | The PC's other local accounts, RIDs 1001 to 1003 |
  | INFORMANT-PC | The PC: Windows 7 Ultimate SP1, 64-bit, at 10.11.11.129/24 by DHCP from 10.11.11.254 |
  | RM#1 | "Company's USB": a SanDisk Cruzer Fit, serial 4C530012450531101593, exFAT, labeled "Authorized USB" |
  | RM#2 | The suspect's USB drive: a SanDisk Cruzer Fit, serial 4C530012550531106501, FAT, labeled `IAMAN $_@`, drive E: on the PC |
  | RM#3 | A CD-R burned "like a USB flash drive", in UDF |
  | The company's network drive | A share, `\\10.11.11.128\secured_drive`, mapped as V: |

  The dataset page offers each image as an E01 image, and some also as raw images, each with its hash values. It also offers the seed files, the files the scenario stored on RM#1 and the network drive. The check used the E01 images: the PC's four segments (7,825,209,454 bytes, for a disk of 21,474,836,480 bytes), RM#1's (78,186,742 bytes), RM#2's (255,051,328 bytes), and RM#3's type 3 image (94,594,894 bytes).
- **Where the answers come from:** The [answer document](https://cfreds-archive.nist.gov/data_leakage_case/leakage-answers.pdf), revision 1.32, last updated 2018-07-23, which the dataset page links in PDF and Word. Its section 6 gives 60 questions with their answers, and the 60 items below are those questions. Its times are the PC's local time, Eastern daylight time (UTC-04:00), apart from questions 6 and 10, which are at UTC-05:00, and question 3's install time, which is in GMT.

## How it was run

[glossary.md](../glossary.md) defines terms such as lane, pivot, mark, lead, and finding.

**Date and build.** The check ran on 2026-10-22, the day v0.2.0 was released, on a development build made after that release and before v0.3.0, with Hayabusa 4.1.0 and the 2026.5.0 builds of Eric Zimmerman's tools. Each gap's state under Gaps found says where the gap stands in v0.3.0, and a fixed gap names the release that fixed it.

**Evidence.** Glessner reads a folder of collected files, not a disk image (see Inputs in [known_limitations.md](../known_limitations.md#inputs)). Each image was first read in full outside the app. Its MD5 and SHA-1 matched the values stored in the E01 and the values in the answer document, which gives RM#1's in its section 4.3, not in question 1. The PC's disk holds the two partitions question 2 gives, and one shadow copy store.

The PC's image was unpacked into a collection of 483 files, 506.4 MB. It holds the artifacts the app reads, 5 hash lists from the unpacking step, and 261 files of kinds the app doesn't read yet, most of them collected to show what a case would miss. The unpacking step took no shadow copy, and it left out some files the answers need (gaps 9 and 10). It found nothing to take from the removable media, so each device's folder holds a copy of its E01 image. Read outside the app with The Sleuth Kit, RM#1 opens as exFAT with 8 files in 4 folders. RM#2 opens as FAT with one 0-byte directory entry, the state a quick format leaves, and RM#3 doesn't open. The evidence folder held 486 files, 934.2 MB, in four folders: INFORMANT-PC, RM1, RM2, and RM3.

**Loading.** A case was made from the start page, with each top-level folder as a host. The page read "Found 486 files, 934.2 MB, in 4 folders: INFORMANT-PC, RM1, RM2, RM3." and "16 of 16 registry tools found." **Create case and take in evidence** took about 7 s. The Tools page's **Run and load everything ready** then made 10 tool runs in 2 minutes 26 seconds. Every run succeeded and every evidence check passed. AmcacheParser, RBCmd, SrumECmd, Suricata, WxTCmd, and the event XML reader had nothing to read.

| Tool | Events | Run time |
|---|---|---|
| MFTECmd, `$MFT` | 361,800 | 17.0 s |
| MFTECmd, `$J` | 317,137 | 16.3 s |
| EvtxECmd | 5,199 | 7.1 s |
| RECmd | 4,595 | 21.2 s |
| Hayabusa | 494 hits | 13.0 s |
| JLECmd | 202, 10 of them without a time | 2.3 s |
| SBECmd | 200 | 1.3 s |
| SQLECmd | 176: informant's 141 Chrome visits and 28 keyword searches, admin11's 4 and 1, and 2 omnibox shortcuts | 1.7 s |
| PECmd | 95 | 0.7 s |
| LECmd | 84, 2 of them without a time | 1.6 s |

| Files | Result | Detail |
|---|---|---|
| Event logs, 53 | Loaded | EvtxECmd and Hayabusa |
| Prefetch files, 95 | Loaded | PECmd |
| Registry hives, 14 | Loaded | RECmd, and SBECmd for the 9 user hives |
| LNK files, 25, and jump lists, 20 | Loaded | LECmd and JLECmd |
| `$MFT` and `$J` | Loaded | MFTECmd |
| Chrome's History and Shortcuts databases, 4, with their 4 journals | Loaded | SQLECmd, on copies |
| Hash lists from the unpacking step, 5 | Skipped, with a reason | The Import page lists them as JSON arrays with no time field. The Tools page counts them as "5 text logs". |
| PC files no reader identifies, 261 | Unidentified | `$LogFile`, the Windows Search index (8 files, gap 6), WebCache for 3 users (17, gap 5), thumbcache (18, gap 7), CryptnetUrlCache metadata (113), scheduled tasks (89), the WMI repository (5), `setupapi.dev.log` (gap 8), the BITS queue (2), Windows Error Reporting reports (5), Defender's MPLog, and `RecentFileCache.bcf` |
| The three removable media's E01 images | Unidentified | No hint that they are disk images, and no host for them (gap 1) |

In all, 217 files loaded, 5 were skipped with a reason, and 264 were unidentified. The case held 689,476 timeline events, 12 events without a time, and 494 Hayabusa hits on 493 events.

- The runs reported these errors. RECmd failed on part of each user's NTUSER.DAT with "Object reference not set to an instance of an object", its TaskCache plugin failed on SOFTWARE, and its USBSTOR and SCSI plugins failed with "Array cannot be null" (gap 13). SQLECmd's Chrome downloads map failed (gap 20). JLECmd read 2 of admin11's custom jump lists as empty. EvtxECmd couldn't load 3 of its map files, because of duplicate keys.
- The Hosts panel showed one host, INFORMANT-PC, guessed as a workstation, with Windows 7 Ultimate SP1, build 7601, and two recorded names, INFORMANT-PC and 37L4247F27-25. RM1, RM2, and RM3 weren't hosts.
- The Overview gave the case's span as 2009-06-10 20:30:41 to 3320-11-16 08:35:52 (gap 24). It showed 3 leads and 9 pending Suspicious suggestions, all from Hayabusa (gap 23). Of Hayabusa's 494 hits, 450 are informational, 35 low, 5 medium, and 4 high.

**Scoring.** Each answer item was looked up in the app with search, the Event page, and pivots, through the app's local HTTP interface, on copies of the case. Two scorings of each item were compared, and a second pass settled the items where they differed. Outside tools read copies of the files the app doesn't read, such as WebCache and the Windows Search index, to show what those files hold. Those reads don't count toward a score.

Each item has one of four states: reached, partly reached, missed, or out of scope. An out-of-scope item needs something the app doesn't do by design, so it's listed and not counted. [How each item is scored](README.md#how-each-item-is-scored) gives the full rubric. Items 1 and 2 are answered from the images: the media hashes and the PC's partition table. They are scored by what the app shows, and a PC record that holds a fact counts, such as a file's `$MFT` entry or a device's registry key. Items 53, 54, and 56 are answered from the removable media's file systems, which are out of scope. The reads of the images outside the app don't count.

**Corrections to the answers.** The answers were checked against the evidence before scoring, and each item is scored on the corrected facts. The Answer column under Results gives the document's answers, with a note where a correction applies.

- Questions 6 and 10 give their times at UTC-05:00, not daylight time. The SAM gives informant's creation at 14:33:54 UTC, the document's 09:33:54, and the Uninstall keys give Chrome's install at 15:11:51 UTC, the document's 10:11:51.
- Question 12's 4637 row, at 2015-03-25 10:45:59, is two 4634 logoffs at 14:45:59 UTC. Windows doesn't log a logoff as 4637.
- The Security log holds 8 startups and 8 shutdowns from 3/22 to 3/25, and question 12 lists 4 of each. Its window, 09:00 to 18:00 local time, leaves out an early session on 3/25. It doesn't account for 3 shutdowns and 2 startups on 3/22 inside the window, beyond saying that it leaves out duplicated and meaningless rows. The check scores the 36 rows the document lists.
- Question 19 puts the OST in `...\Local\Microsoft\Office\`. The registry value the document quotes, and the image, put it at `C:\Users\informant\AppData\Local\Microsoft\Outlook\iaman.informant@nist.gov.ost`.
- Questions 29 to 31 give Google Drive's folder as `\User\informant\AppData\Google\Drive\user_default\`. On the image it is `\Users\informant\AppData\Local\Google\Drive\user_default\`.
- Question 30 swaps the two files' modified times. happy_holiday.jpg was modified 2015-01-29 15:35:14 and do_u_wanna_build_a_snow_man.mp3 2015-01-30 11:49:20, at UTC-05:00. The sync log lines the document quotes give these times, and question 49 agrees.
- Question 38 lists `thumbcache_64.db`, which Windows 7 doesn't make. The image's thumbcache files are `_32`, `_96`, `_256`, `_1024`, `_idx`, and `_sr`.
- Question 47's creation time is the shadow copy store's own, 14:57:27.29 UTC. The store file's `$MFT` creation time is 2.4 s earlier, 14:57:24.94. The `$MFT` also holds a deleted older store, created 14:50:37 UTC.
- The document gives the CD burning events as System event 113. The evidence has 133.
- Question 1 leaves out RM#1. Its rows for RM#3's type 1 and type 2 images are formats the check didn't use.

**Marking and the report.** The answers were then marked in the case: 464 events in 48 marks, each with a note that names its item. 204 events are marked Malicious, for the leak and the clean-up. 120 are Suspicious, for the user's preparation and the context the report should carry. 140 are Authorized, for system facts. The analyst's Summary and 7 findings followed, with the ATT&CK techniques T1039, T1036.008, T1074.001, T1567.002, T1052.001, T1052, and T1070.004. The app then wrote the Markdown report, the marked-events and flagged-events CSVs, the indicators, and the audit trail. The report re-hashed all 486 evidence files, which matched.

## Results

Item numbers are this page's own, and they match the answer document's question numbers. The document lists its 60 questions under one heading, in topic order, and the tables below group them by topic. Gap numbers refer to the list under Gaps found.

The Answer column gives the document's answer with its own times, in the PC's local time as the dataset section says. What the app showed gives times in UTC, on 2015-03-22 to 25 unless a row gives another date. To compare the two, add 4 hours to the document's times, or 5 hours for items 6 and 10. Item 3's install time is in GMT and needs no change.

### Images

| Item | Answer | What the app showed | State |
|---|---|---|---|
| 1 | The MD5 and SHA-1 of every image, and whether the acquisition and verification hashes match. PC: MD5 `a49d1254...`, SHA-1 `afe5c9ab...`. RM#2: `b4644902...`, `048961a8...`. RM#3 type 3: `df914108...`, `7f3c2eb1...`. | Nothing. The removable media's images are in the case as unidentified files (gap 1), and the PC's image isn't in the case (gap 4). The app shows each evidence file's SHA-256, not the MD5 or SHA-1 of a disk or the hashes an E01 stores (gap 2). | Missed |
| 2 | The PC image's partitions: partition 1, bootable, starts at sector 2,048 and runs 204,800 sectors (100 MB). Partition 2 starts at sector 206,848 and runs 41,734,144 sectors (19.9 GB). Both are NTFS. | The image isn't in the case (gap 4), but PC records hold part of the answer. MountedDevices gives the volumes' offsets, 0x100000 (sector 2,048) and 0x06500000 (sector 206,848), decoded by hand from its bytes (gap 14). The Windows Boot Volume row names HarddiskVolume1 as the system partition. The `$Bitmap` record's size, 652,096 bytes, gives partition 2's size only if 4 KiB clusters are assumed. Partition 1's size and its bootable flag are in no PC record. | Partly reached |

### System and accounts

| Item | Answer | What the app showed | State |
|---|---|---|---|
| 3 | Windows 7 Ultimate, version 6.1, build 7601, registered owner informant, system root `C:\Windows`, installed 2015-03-22 14:34:26 GMT | RECmd's system info rows give Windows 7 Ultimate, SP1, build 7601, owner informant, `C:\Windows`, and the install at 2015-03-22 14:34:26 UTC, and the Hosts panel shows the same. CurrentVersion 6.1 has no row (gap 12). The version shows only by reading the product name and build through a version table, which is decoding. | Partly reached |
| 4 | Time zone: Eastern Time (US and Canada), UTC-05:00, with daylight saving time | RECmd's time zone rows give Bias 300 (UTC-05:00), DaylightBias -60, and ActiveTimeBias 240. The zone name reads "Eastern Standard Time ard Time" (gap 17), which doesn't lower the item. | Reached |
| 5 | Computer name: INFORMANT-PC | RECmd's computer name row, and the Hosts panel names the host by it. | Reached |
| 6 | Accounts other than the built-in ones, with logon counts and times. informant, RID 1000, 10 logons, created 2015-03-22 09:33:54, last logon 2015-03-25 09:45:59. admin11, RID 1001, 2 logons, created 2015-03-22 10:51:54. ITechTeam, RID 1002, 0 logons. temporary, RID 1003, 1 logon. The check's facts leave out the document's password columns. | A search for `HiveType:SAM` gives the four accounts with their RIDs, and their creation and last logon times in a raw field. The rows list at their key's last write, 2015-03-22 15:53:01.90, three days before informant's last logon (gap 11). The logon counts are only in a RECmd detail file the app doesn't load (gap 16). | Partly reached |
| 7 | Last user to log on: informant | A search for `code:4624 TargetUserName:informant` finds informant's type 7 logon at 2015-03-25 14:45:59, the SAM's last logon. The last 4624 overall, at 15:18:54, is SYSTEM's type 5. | Reached |
| 8 | Last recorded shutdown: 2015-03-25 11:31:05 | The ShutdownTime row: 2015-03-25 15:31:05.23. | Reached |
| 9 | The interface with a DHCP address: Intel(R) PRO/1000 MT Network Connection, 10.11.11.129, mask 255.255.255.0, gateway and name server 10.11.11.2, domain localdomain, DHCP server 10.11.11.254 | RECmd's IPv4 network configuration rows give interface {E2B9AEEC-...} with every value. The adapter row names the Intel PRO/1000 MT but not the interface, so the two tie only by hand (gap 15). The Hosts panel gave the host no IP (gap 34). | Partly reached |

### Programs

| Item | Answer | What the app showed | State |
|---|---|---|---|
| 10 | 9 applications the suspect installed, at UTC-05:00: Office Professional Plus 2013 (2015-03-22 10:04:14), Chrome 41.0.2272.101 (10:11:51), Google Update Helper (10:16:03), Apple Application Support (2015-03-23 15:00:45), Bonjour (15:00:58), Apple Software Update (15:01:01), Google Drive 1.20.8672.3137 (15:02:46), .NET Framework 4 (2015-03-25 09:51:39), and Eraser 6.2.2962 (09:57:31) | A search for `registry_key:*Uninstall*` gives all 9, with their install dates in raw fields. The rows list at their keys' last write times, 2015-03-23 20:02:46 and 2015-03-25 15:19:05, not at the installs (gap 11). The three installed on 3/22 list on 3/23 or 3/25, and Bonjour lists about 43 hours after its install. | Partly reached |
| 11 | Application execution: 47 rows from 2015-03-22 11:11:04 to 2015-03-25, most on 3/25. They include the IE11 setup, googledrivesync.exe, icloudsetup.exe, GoogleUpdate, AppleSoftwareUpdate, StikyNot.exe, the Eraser and CCleaner installers and runs, and xpsrchvw.exe, from Prefetch (17 rows), UserAssist (16), Shimcache (11), and MuiCache (3). | The Prefetch rows give the IE11 setup, googledrivesync, icloudsetup, GoogleUpdate, StikyNot, the Eraser and CCleaner installers and runs, CCleaner's uninstaller, and XPSRCHVW, with earlier runs in raw fields. The AppCompatCache rows for these programs list at the last shutdown, 2015-03-25 15:31:05, not at their own times (gap 11). IconCache.db, which the document also names, wasn't collected (gap 9). | Partly reached |

### Power and logons

| Item | Answer | What the app showed | State |
|---|---|---|---|
| 12 | 36 rows from 2015-03-22 10:51:14 to 2015-03-25 11:31:00, limited to 09:00 to 18:00 local time: 4 startups (4608), 23 logons (4624), 5 logoffs (4 as 4647 and 1 as 4637), and 4 shutdowns (1100) | Searches for event codes 4608, 4624, 4647, 1100, and 4634 find all 36 rows at the document's times. The document's 4637 is two 4634 logoffs, as the corrections above say. | Reached |

### Browsers and searches

| Item | Answer | What the app showed | State |
|---|---|---|---|
| 13 | Web browsers: Internet Explorer 11.0.9600.17691 and Chrome 41.0.2272.101 | Chrome's version is in its Uninstall row (item 10). Internet Explorer shows through its Prefetch rows and the IE11 installer's `$MFT` records. IE's version is in the SOFTWARE hive's svcVersion value, which has no row (gap 12). | Partly reached |
| 14 | Paths of the browser history: IE 9 and earlier's History, Temporary Internet Files, and Cookies folders, IE 11's `WebCache\WebCacheV01.dat`, Chrome's `User Data\Default\History` and its folders, and Windows.edb | `$MFT` searches find informant's WebCacheV01.dat, Chrome's `Default\History`, IE's History and Cookies folders, and Windows.edb. A later search of a copy of the same case finds IE's Temporary Internet Files folder, Chrome's `Default\Application Cache`, `Default\Media Cache`, `Default\GPUCache`, and `Default\Extensions` folders, and its `Default\Cookies` and `Default\Extension Cookies` files. | Reached |
| 15 | 74 visits in IE 8, IE 11, and Chrome: 7 on 3/22, 56 on 3/23, 5 on 3/24, and 6 on 3/25, the last at 2015-03-25 10:48:12 | Chrome's visits loaded, and 54 of them match the document's rows within 2 s. 16 visits that Chrome imported from IE read "Chrome visit" (gap 27). IE 11's own visits are in WebCache and the Windows Search index, which no reader loads (gaps 5 and 6). | Partly reached |
| 16 | 28 search keywords: 24 on 3/23, 1 on 3/24 ("security checkpoint cd-r"), and 3 on 3/25. Google has 15 and Bing 13, and the Bing searches are IE 11's. | Chrome's keyword rows give informant's Google searches from 3/23 to 3/25. The 13 Bing searches are in IE's WebCache, which no reader loads (gap 5). | Partly reached |
| 17 | Explorer search: "secret", 2015-03-23 14:40:17 | The WordWheelQuery row "secret" at 18:40:17. | Reached |

### Email

| Item | Answer | What the app showed | State |
|---|---|---|---|
| 18 | Email application: Microsoft Outlook 2013 | App Paths places OUTLOOK.EXE under `Office15`, OUTLOOK.EXE's Prefetch row shows it ran, and Outlook's event 29 records it making its store. `Office15` reads as Office 2013 only through a version table, which is decoding. The jump list names the program "Microsoft Outlook 2016 64-bit", a wrong value (gap 28). The mail handler values have no row (gap 12). | Partly reached |
| 19 | The email file: `C:\Users\informant\AppData\Local\Microsoft\Office\iaman.informant@nist.gov.ost`, corrected to the `Outlook` folder | A search for the address finds Outlook's event 29, "Newly created store", and the `$MFT` record of `C:\Users\informant\AppData\Local\Microsoft\Outlook\iaman.informant@nist.gov.ost`, both at 2015-03-22 15:48:21. | Reached |
| 20 | Email account: `iaman.informant@nist.gov` | Item 19's two events. 189 events name the address. | Reached |
| 21 | 12 messages with `spy.conspirator@nist.gov`, 2015-03-23 13:29:27 to 2015-03-24 17:05:09. 4 are in Deleted Items, and 1, "It's me" at 2015-03-23 16:38:47, is recovered from the OST's unused space. | Nothing. The OST wasn't collected (gap 9). The Windows Search index holds the message list: 18 dated messages, 17 of them naming the conspirator. No reader loads it (gap 6). | Missed |

### Devices, renames, and the network drive

| Item | Answer | What the app showed | State |
|---|---|---|---|
| 22 | Two SanDisk Cruzer Fit USB drives. Serial 4C530012450531101593: first connected 2015-03-23 14:31:10, and after a reboot 2015-03-24 09:38:00. Serial 4C530012550531106501, labeled `IAMAN $_@`: first connected 2015-03-24 09:58:32, and after a reboot 09:58:33. | A search for each serial finds 10 events. System events 20003 and 20001 give the first connections, 2015-03-23 18:31:10 and 2015-03-24 13:58:32. RM#1's reconnection at 13:38:00 is only in a Device Classes row's raw field, and those rows list at 2015-03-25 10:17:27 (gap 11). The label's row lists at 2009-07-14 (gap 11). Drive E: ties to RM#2 only through MountedDevices bytes decoded by hand (gap 14). No install or removal time loaded (gap 13). | Partly reached |
| 23 | 24 renames under `Desktop\S data\`: 4 on 2015-03-23 (14:41:40, 14:41:55, 16:30:44, and 16:31:02) and 20 on 2015-03-24, from 09:49:51 to 09:56:20 | A search for `code:RenameOldName *secret_project*` gives the 26 old names, and each folder's new names follow from a search on its folder ID: all 24 renames, at the document's times. Two more records on 3/24 are moves, not renames. The folder reads `\PathUnknown\Directory with ID 0x...` in hex, while the raw fields give it in decimal, and no pivot reaches the folder (gaps 18 and 19). | Reached |
| 24 | The network drive's address, 10.11.11.128: RunMRU at 2015-03-23 16:23:28, and the Map Network Drive MRU at 16:26:04 | The RunMRU entry `\\10.11.11.128\secured_drive` at 20:23:28 and the Map Network Drive MRU at 20:26:04. | Reached |
| 25 | 8 folders browsed on RM#2, under `E:\Secret Project Data\`, 2015-03-24 10:00:19 to 16:54:07 | Shellbag rows for `E:\Secret Project Data` and its folders, 14:00:19 to 20:54:07. The answer names the folders under E:, so it needs no tie of E: to RM#2. That tie rests on the path and RM#2's arrival at 13:58:32, since E: was also RM#1's letter at 13:38:31. | Reached |
| 26 | File opened on RM#2: winter_whether_advisory.zip, 2015-03-24 10:01:23 to 10:01:29 | Jump list and shellbag records, 14:01:23 to 14:01:32. | Reached |
| 27 | 18 rows of folders browsed on the network drive, under `\\10.11.11.128\secured_drive` and V:: 16 on 2015-03-23 (16:24:01 to 16:28:17) and 2 on 2015-03-24 (09:47:54), from shellbags, jump lists, and LNK files | Searches for the address and the folder name give 27 shellbag records under the share and V:, from 2015-03-23 20:23:28 to 2015-03-24 13:47:54. An LNK event carries its target's times, and the shortcut's own times are in its `$MFT` record (gap 21). | Reached |
| 28 | Files opened on the network drive: `(secret_project)_pricing_decision.xlsx` at 2015-03-23 16:26:53 and `[secret_project]_final_meeting.pptx` at 16:27:33, in 8 rows | The xlsx at 20:26:53 and the pptx at 20:27:33, by jump list, LNK file, and Office MRU. | Reached |

### Cloud storage

| Item | Answer | What the app showed | State |
|---|---|---|---|
| 29 | Google Drive's program folder, its `user_default` folder (sync_config.db and snapshot.db deleted, sync_log.log present), `Downloads\googledrivesync.exe`, and its registry keys. Apple iCloud's `Downloads\icloudsetup.exe` and its install traces. | `$MFT` records give the two installers in Downloads at 19:55:47 and 19:56:30, Google Drive's install at 20:02:43, and `user_default` with sync_log.log and the deleted snapshot.db and sync_config.db. `Software\Google\Drive` has no row (gap 12), and Chrome's 2 download rows didn't load (gap 20). | Partly reached |
| 30 | Files deleted from Google Drive: happy_holiday.jpg and do_u_wanna_build_a_snow_man.mp3, at 2015-03-23 16:42:17, with their modified times (swapped in the document) | `$J` records give both files created at 20:32:35 and deleted at 20:42:16.964 in informant's Google Drive folder, the document's deletion time. Their modified times are only in sync_log.log, which wasn't collected (gap 9), and in the shadow copy, which wasn't extracted (gap 10). | Partly reached |
| 31 | The account that synced Google Drive: a personal Gmail account, iaman.informant.personal, signed in at 2015-03-23 16:05:32 | Nothing. sync_log.log wasn't collected (gap 9). The address is in WebCache, in an account chooser URL at 2015-03-25 15:22:08, and no reader loads WebCache (gap 5). The sign-in time is in no collected file. | Missed |

### CD-R

| Item | Answer | What the app showed | State |
|---|---|---|---|
| 32 | Burning method: Windows' built-in burning, both Type 1 ("like a USB flash drive") and Type 2 ("with a CD/DVD player", mastered) | The 4 cdrom events, System 133, at the mastered burns, and the `Burn\Burn` staging of item 34, show Type 2. The Type 1 choice is the `CD Burning` value DefaultToMastered 0, last written 2015-03-24 20:53:16.67, in a loaded hive, and it has no row (gap 12). | Partly reached |
| 33 | When the CD-R was burned: Type 2 burns on 2015-03-24 at 15:47:47, 15:56:01 and 15:56:11, 16:24:19 and 16:24:46, and 16:41:21. Type 1 chosen at 16:53:16, formatted as UDF at 16:53:17, and burned from 16:54 to 16:58. | PC part: the six Type 2 burns, 19:47:47 to 20:41:21, show by their temporary files in `$J` and by the cdrom events. The Type 1 choice at 20:53:16 has no row (gap 12). Out of scope: the format at 20:53:17 and the Type 1 burn from 20:54 to 20:58, which only RM#3's image holds (gap 3). | Partly reached |
| 34 | 20 files copied to the CD-R, staged in `Burn\Burn`: 17 in the de, pd, prog, prop, and tr folders, and Penguins.jpg, Koala.jpg, and Tulips.jpg | A search for `path:*\Burn\Burn\* code:FileCreate` gives the five folders under their first names, desktop.ini, the IE11 installer, and 8 pictures, among them the three, from 19:46:16 to 20:43:20. The other 17 files' `$J` records read `\PathUnknown\` (gap 18), so no path search finds them. A join on the parent entry number to the five folders' entries gives all 17 names at 19:46:16 to 19:46:29, and the second staging gives them again at 20:40:55. The folders are renamed to de, pd, prog, prop, and tr at 19:46:36 to 19:46:53. | Reached |
| 35 | 8 rows of files opened from the CD-R: `D:\de\winter_whether_advisory.zip`, 2015-03-24 16:44:13 to 16:44:18, and jpg files, 17:01:10 to 17:01:14 | Jump list and LNK records give the zip at 20:44:13 to 20:44:18. The `$MFT` records of the pictures' shortcuts in Recent give 21:01:10 to 21:01:14. The LNK events carry their targets' times, and the shortcuts' own times are only in their `$MFT` records (gap 21). | Reached |

### Resignation letter

| Item | Answer | What the app showed | State |
|---|---|---|---|
| 36 | `Resignation_Letter_(Iaman_Informant).docx` on the Desktop: $SI and $FN created 2015-03-24 14:48:40, and modified, accessed, and entry modified 14:59:30. The document's own properties: created 14:32:00, modified 14:59:00. | `$MFT` rows give $SI created 18:48:40.734 and modified 18:59:30.611. MFTECmd writes no $FN row where $FN equals $SI (gap 22). The document's own properties need the docx, which wasn't collected (gap 9). | Partly reached |
| 37 | Printed to XPS at 2015-03-25 11:28:34, as `Desktop\Resignation_Letter_(Iaman_Informant).xps` | The .xps file's `$MFT` record, created 15:28:33.65, and the XPS Viewer's Prefetch run at 15:28:47. The printer key has no row (gap 12), which doesn't lower the item. | Reached |

### Thumbcache and Sticky Notes

| Item | Answer | What the app showed | State |
|---|---|---|---|
| 38 | The thumbcache files under `Users\informant\AppData\Local\Microsoft\Windows\Explorer\`, corrected as above | `$MFT` records of all six files. | Reached |
| 39 | thumbcache_256.db holds thumbnails of the first pages of the secret project's PowerPoint files | Nothing. The thumbcache files are unidentified, and no reader loads them (gap 7). informant's thumbcache_256.db holds 371 entries, 170 with image data. | Missed |
| 40 | The Sticky Notes file: `Users\informant\AppData\Roaming\Microsoft\Sticky Notes\StickyNotes.snt` | The file's `$MFT` record. | Reached |
| 41 | One note, "Tomorrow... Everything will be OK...", 2015-03-24 14:31:59 | The file's `$MFT` record gives its last change at 18:31:59.46, 4 s after StikyNot.exe ran by its Prefetch row. The note's text is in the Windows Search index, dated 18:30:09.566, which no reader loads (gap 6). The file itself wasn't collected. | Partly reached |

### Windows Search

| Item | Answer | What the app showed | State |
|---|---|---|---|
| 42 | Windows Search was enabled: the WSearch service starts automatically, and the database is `C:\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb` | Event 7036 shows Windows Search reaching the running state at each boot, a RECmd row names the WSearch service, and the database's `$MFT` record gives its path. The service's start mode is only in a RECmd detail file (gap 16), and the database's FileName value has no row (gap 12). Neither lowers the item. | Reached |
| 43 | The kinds of data in the index: IE history, Outlook items, user profile files, Start Menu entries, and Sticky Notes | Nothing. The index is unidentified (gap 6). | Missed |
| 44 | 46 URLs IE visited in the index, 12 on 2015-03-22 and 34 on 2015-03-23, 11:09:22 to 16:56:33 | Nothing (gap 6). Chrome's 16 visits imported from IE are Chrome rows, not index records. | Missed |
| 45 | 16 messages in the index, 4 of them only there, among them the reply at 2015-03-23 15:19:22 with space_and_earth.mp4 attached | Nothing (gap 6). | Missed |
| 46 | 23 entries under `Users\informant\Desktop\` in the index | Nothing (gap 6). | Missed |

### Shadow copy

| Item | Answer | What the app showed | State |
|---|---|---|---|
| 47 | One store, `\System Volume Information\{9b365826-d2ef-11e4-b734-000c29ff2429}{3808876b-c176-4e48-b7ae-04046e6cc752}`, created 2015-03-25 10:57:27, 335,544,320 bytes | `$MFT` records give the store's path and size, its creation at 14:57:24.94, and the deleted older store. | Reached |
| 48 | The shadow copy holds snapshot.db and sync_config.db, which were deleted from the live volume, and its sync_log.log ends at 2015-03-23 16:47:56 | Nothing. The shadow copy wasn't extracted (gap 10). | Missed |
| 49 | 2 deleted cloud_entry records in the shadow copy's snapshot.db, at offsets 0x702 and 0x77A | Nothing (gap 10). | Missed |
| 50 | The shadow copy holds no Outlook data because `FilesNotToSnapshot` has an OutlookOST entry | The RECmd row for OutlookOST. | Reached |

### Recycle Bin and anti-forensics

| Item | Answer | What the app showed | State |
|---|---|---|---|
| 51 | 14 Recycle Bin $I entries: 4 `Burn\Burn` folders (prop, prog, pd, and tr) deleted 2015-03-24 15:51:47, and 10 files from the top of `Burn\Burn` at 16:11:42 | informant's 14 deleted $I entries in the `$MFT`: the 4 folders at 19:51:47 and the 10 files at 20:11:42. `$J` shows the 4 folders renamed to `$R` names at 19:51:47. RBCmd had no $I file to read, since the live Recycle Bin folder held only desktop.ini. | Reached |
| 52 | Anti-forensics on 2015-03-25: searches for anti-forensic tools (10:46 to 10:47), Eraser and CCleaner downloaded and installed (10:50:14 and 10:57:56), Eraser run at 11:13:30 to wipe `Desktop\temp` from 11:13:39 to 11:14:44, a Shift+Delete at 11:15:45, CCleaner at 11:15:50, an uninstall at 11:18:29, Google Drive signed out at 11:22:47, and 7 emails deleted | Prefetch rows give the Eraser installer at 14:50:14, the CCleaner installer at 14:57:56, Eraser at 15:13:30, CCleaner at 15:15:50, and its uninstaller at 15:18:29, and the Uninstall row gives Eraser's install. `$J` shows the wipe of `Desktop\temp`, listed under `Desktop\[QAT`, the name Eraser left (gap 18), and the `$MFT` shows the deleted installers. The Bing searches are in WebCache (gap 5). The sign-out is in sync_log.log, and the email deletions are in the OST, and neither was collected (gap 9). | Partly reached |

### Removable media

| Item | Answer | What the app showed | State |
|---|---|---|---|
| 53 | 17 deleted files recovered from RM#2: 2 by directory entry and 15 by carving | Nothing. The files come back only from RM#2's file system and unallocated space, which is image-tool work (gap 3). | Out of scope |
| 54 | Anti-forensics on RM#2: a quick format | Nothing. The format is inferred from item 53's recovery on RM#2's image. | Out of scope |
| 55 | Files copied from the PC to RM#2: item 53's 17 files, of which only winter_whether_advisory.zip has a trace on the PC | PC part: the zip's trace shows through item 26's jump list and shellbag records, 14:01:23 to 14:01:32. Out of scope: the other 16 files, which only RM#2's image holds (gap 3). | Reached |
| 56 | 17 hidden files carved from the CD-R | Nothing. No PC record can show a file hidden on the disc, and the `Burn\Burn` records are item 34's. | Out of scope |
| 57 | Anti-forensics on the CD-R: formatted as Type 1, confidential and meaningless files copied, and the confidential files deleted | PC parts: the copying shows through the burns and the `Burn\Burn` staging (items 32 to 34), and the staging folders' deletion through item 51. The Type 1 choice has no row (gap 12). Out of scope: the format itself and the deletion of the files on the disc, which only RM#3's image holds (gap 3). | Partly reached |

### Summary questions

| Item | Answer | What the app showed | State |
|---|---|---|---|
| 58 | A detailed timeline of the leak: 3/22, normal work and installs. 3/23, sample data sent over the internet. 3/24, data copied to storage devices. 3/25, anti-forensics, and the devices taken out. | Dated evidence for each day: on 3/22 the installs and setup (items 10, 12, and 13), on 3/23 the network drive, the renames, and Google Drive (items 23, 24, and 27 to 30), on 3/24 the USB drive and the CD-R (items 22, 25, 26, and 32 to 35), and on 3/25 the anti-forensics and the shutdown (items 52 and 8). No PC record shows the devices being taken out. From 13:00 to 15:32 on 3/25 the case holds no device arrival event and no Device Classes, USBSTOR, or SanDisk row. | Partly reached |
| 59 | The methods of leakage: email (2015-03-23 15:19 with space_and_earth.mp4 attached, and 16:38 with links to files shared in cloud storage), Google Drive (16:32, the two files of item 30), the USB drive (2015-03-24 09:58 to 10:00, then formatted), and the CD-R (16:54 to 16:58, 17 files, then deleted) | Google Drive (item 30), the USB drive (items 22, 25, and 26), and the CD-R (items 32 to 35) show. Both emails are in the Windows Search index, which no reader loads (gap 6), and the OST wasn't collected (gap 9). Out of scope: the USB drive's format, which only RM#2's image holds, and the CD-R's Type 1 burn and the deletion of the files on the disc, which only RM#3's image holds (gap 3). | Partly reached |
| 60 | A visual diagram of the results | The timeline view gives a visual summary of the case. The report has no chart (gap 25). The Overview gave the case's last time as 3320-11-16 (gap 24), while the timeline's fitted window ended 2015-03-25 15:31:06. | Reached |

### Totals

The score is 26, 21, 10 of 57, plus 3 out of scope. Of the 57 items in scope, 26 were reached (4, 5, 7, 8, 12, 14, 17, 19, 20, 23 to 28, 34, 35, 37, 38, 40, 42, 47, 50, 51, 55, and 60), 21 were partly reached (2, 3, 6, 9 to 11, 13, 15, 16, 18, 22, 29, 30, 32, 33, 36, 41, 52, and 57 to 59), and 10 were missed (1, 21, 31, 39, 43 to 46, 48, and 49). Items 53, 54, and 56 are out of scope and aren't counted. Of the 486 evidence files, 217 loaded.

Reading disk images' file systems, recovering deleted files, and carving are out of scope ([scope.md](../scope.md#not-in-scope)). Items 33, 55, 57, and 59 each have a part on the PC and a part only on a removable medium's image. Each is scored on its PC part, and its row names the part left out, as [How each item is scored](README.md#how-each-item-is-scored) says for an item partly out of scope. Item 55 is reached on the PC's trace of winter_whether_advisory.zip, the jump list and shellbag records that item 26 rests on. Items 25 and 26 ask about RM#2. Item 25's answer gives folders under drive E:, and item 26's gives the file and its times, with no device. So neither item needs a tie of E: to RM#2, and item 55 doesn't either.

Items 3 and 18 are partly reached because a version number shows only as a release name, or the reverse, which is decoding: version 6.1 from Windows 7, and Outlook 2013 from the `Office15` folder. Item 58 is partly reached because no PC record could show the devices being taken out on 3/25. Under the rule for synthesis items, a part no record could hold keeps the item partly reached. Item 1 stays counted and missed. It asks for the hashes the images store, which the app doesn't read (gap 2), and that is a different task from reading an image's file system.

The table gives each item's state on the build the check ran on, before the fixes in v0.3.0.

### What the check showed

- What loaded was correct where it showed. Event logs, the `$MFT`, `$J`, Prefetch, shellbags, jump lists, and Chrome's rows carry their records' own times. The 36 power and logon rows, the 24 renames, the burns, and the shellbags under the share and E: list at the document's times, corrected to UTC. RECmd's rows are the exception (gap 11).
- Search found the records behind each loaded fact the items needed, some of them through a join (the last point below). Free text found the drive serials (10 events each), the share's address (72), and file names such as `pricing_decision.xlsx` (47). Raw data fields worked as search terms, such as `HiveType:SAM`, `TargetUserName:informant`, and `registry_key:*Uninstall*`. `code:` matched `$J` reasons and event IDs, such as `code:RenameOldName *secret_project*` (26) and `code:4608` (8), and `provider:cdrom` found the 4 burns. `artifact:mft` with `path:` found `$MFT` records, and RECmd's plugin descriptions worked as phrases, such as `"Network Configuration (IPv4)"`.
- No lead or suggestion pointed to the leak (gap 23). Every leak fact was reached by a search the analyst had to know to make.
- A search on a field or artifact name the app doesn't know returned 0 with no hint. `registry_path:*Account\Users*` and `artifact:shellbag "Secret Project Data"` both gave 0, where `HiveType:SAM` and the free text `ShellBag "Secret Project Data"` (69) worked. The artifact's name is `shellbags`.
- A join on a `$J` record's parent entry number reached files that no path search found (items 23 and 34), one search per folder.

### The report

The report listed the 324 Malicious and Suspicious events in time order. Each had its time, host, mark, message, mark note, tool, run, source file and record, and the evidence file's SHA-256. The source file, record, and hash were right on every entry, and the host read INFORMANT-PC on all 324. The report re-hashed all 486 evidence files, printed the Summary and the 7 findings, and named the finding each of 213 entries supports. It also showed these problems:

- The 140 Authorized marks were left out, so the system facts of items 2 to 7, 9 to 14, 18, 19, 37, 38, 40, 42, 47, and 50 had no entry (gap 29). The Summary carried the OS, zone, user, last shutdown, and RM#2's serial in the analyst's words.
- 20 registry entries listed at their key's last write, not when their fact happened (gap 11). The first entry was the Volume Info Cache row naming RM#2's label, dated 2009-07-14, six years before the case.
- A finding listed its first 25 events in the order they were linked, and the cut dropped whole parts (gaps 30 and 31).
- The Summary's `\\10.11.11.128\secured_drive` printed with one leading backslash (gap 32).
- The indicators were 1 account and 127 file paths, 50 of them `\PathUnknown\`, with no address, device serial, or volume label (gap 33).
- The Hosts table gave INFORMANT-PC no IP (gap 34).
- The notes on what marked evidence doesn't prove covered 17 of the 324 entries (gap 35).
- The marked-events CSV had no evidence SHA-256 and no notes column. The MTA check found the same gap, its [gap 15](mta_2016_01_07.md#gap-15-the-marked-events-csv-lacks-the-evidence-hash-and-notes).

## Gaps found

The check found 32 gaps that held. This page numbers them 1 to 35, in the order the check recorded them, and the results above refer to them by number. A proposed fix that didn't hold is under Not counted as gaps. Two gaps are split here, since their parts have different states: the gap on the removable media's images is gaps 1 to 3, and the gap on a finding's listed events is gaps 30 and 31. Of the 35, 9 are fixed in v0.3.0, 18 are planned, 5 are open, 2 are outside the app, and 1 is out of scope. [CHANGELOG.md](../CHANGELOG.md) lists what v0.3.0 changed, and [known_limitations.md](../known_limitations.md) lists what the app still doesn't do.

Each gap has one of the [gap states](README.md#gap-states). A fixed gap names the release that fixed it, and a gap whose remedy is documentation is fixed by the release that carries it. Each gap also lists the answer items it affected.

### Gap 1: The removable media's images aren't recognized

Items: 1, 33, and 53 to 57.

Intake listed the three E01 images among 264 unidentified files, with no hint that they are disk images. RM1, RM2, and RM3 didn't appear as hosts or on the Overview.

**State now:** Planned. Intake will recognize a disk image or container, such as an E01, and say to mount or extract it first. The app still won't read the image's file system. The Planned, not built section of [known_limitations.md](../known_limitations.md#planned-not-built) lists it.

### Gap 2: The images' stored hashes don't show

Items: 1.

The app shows each evidence file's SHA-256. It doesn't read the MD5 and SHA-1 that an E01 stores for its disk, which item 1 asks for. Read outside the app, each image's stored hashes matched the hashes of its disk and the document's values.

**State now:** Open. Deferred, with the question of what else the app should read from disk images.

### Gap 3: The removable media's file systems aren't read

Items: 33, 53 to 57, and 59.

No installed tool reads RM#1's exFAT file system, the files of RM#2's quick-formatted FAT, or RM#3's UDF disc. RM#2's and RM#3's files come back only by recovering deleted files and carving.

**State now:** Out of scope. Reading disk images' file systems, recovering deleted files, and carving come before the case, with tools such as The Sleuth Kit and PhotoRec ([scope.md](../scope.md#not-in-scope)). For that reason items 53, 54, and 56 aren't counted, and items 33, 55, 57, and 59 are scored on their PC parts.

### Gap 4: The PC's own image isn't in the evidence folder

Items: 1 and 2.

The evidence folder holds the files unpacked from the PC's image, not the image, so the image's MD5, SHA-1, and partition table aren't in the case.

**State now:** Outside the app, in the collection. Glessner reads a folder of collected files, as the Inputs section of [known_limitations.md](../known_limitations.md#inputs) says.

### Gap 5: WebCache isn't read

Items: 15, 16, 31, and 52.

The WebCacheV01.dat files of three users were collected and are unidentified, and no installed tool reads their database format, ESE. Read outside the app with Plaso's WebCache parser, they hold 11,214 records. informant's Internet Explorer visits, by last access, are 29 on 3/22, 174 on 3/23, 10 on 3/24, and 60 on 3/25. The Bing searches run from 2015-03-23 18:07:54 to 2015-03-25 14:47:51. WebCache also holds item 31's address.

**State now:** Planned. A reader for ESE databases, built for WebCache and the Windows Search index together, working on copies.

### Gap 6: The Windows Search index isn't read

Items: 15, 21, 41, 43 to 46, and 59.

The index, Windows.edb, was collected and is unidentified. Read outside the app with pyesedb, from [libesedb](https://github.com/libyal/libesedb), it holds 464 records: 364 files, 47 Internet Explorer visits, 48 Outlook items, 3 offline files, and 2 Sticky Notes. They include the message list that items 21 and 59 need, with 18 dated messages, 17 of them naming the conspirator, and item 41's note text. The index doesn't hold the resignation letter's own properties (item 36).

**State now:** Planned, with gap 5's reader.

### Gap 7: Thumbcache isn't read

Items: 39.

The 18 thumbcache files were collected and are unidentified. informant's thumbcache_256.db holds 371 entries, 170 of them with image data: 96 PNG and 74 JPEG.

**State now:** Open. Deferred. No reader is chosen, and whether one would show the thumbnails is decided when it's planned.

### Gap 8: setupapi.dev.log isn't read

Items: 22, with no effect on its state.

The file holds both drives' install sections. System events 20003 and 20001 give the same first connections to within 1.3 s, so no result depends on it.

**State now:** Open. Deferred, behind the readers that change items.

### Gap 9: The collection left out files the answers need

Items: 11, 21, 30, 31, 36, 52, and 59.

The unpacking step didn't take the Outlook OST (16,818,176 bytes), Google Drive's sync_log.log (408,238 bytes), StickyNotes.snt (4,096 bytes), IconCache.db (2,405,456 bytes), the resignation letter's docx (11,893 bytes) and xps (178,139 bytes), or Internet Explorer's History.IE5. They hold the message bodies, the deleted items, and the message recovered from the OST's unused space (item 21), and the 7 deleted emails (item 52). They also hold sync_log.log's modified times (item 30), sign-in (item 31), and sign-out (item 52), the docx's own properties (item 36), and the icon cache (item 11).

**State now:** Outside the app, in the collection. The unpacking step used for these checks now takes the OST, sync_log.log, StickyNotes.snt, the user's Office documents, and IconCache.db. That step isn't part of this repository. This check's evidence folder stays as it was, so the check's later runs don't gain these files. No reader for them is planned yet.

### Gap 10: The shadow copy isn't extracted

Items: 30, 48, and 49.

The PC has one shadow copy store, created 2015-03-25 14:57:27 UTC. The unpacking step took no shadow copy, and the app reads none, as the Inputs section of [known_limitations.md](../known_limitations.md#inputs) says.

**State now:** Open. Deferred, with the question of disk images in gap 2.

### Gap 11: RECmd's rows list at their key's last write

Items: 6, 10, 11, and 22.

RECmd's plugin rows take the last write time of the key the batch file names as their time. Each entry's own time is only in a raw field (ValueData2 or ValueData3). The Uninstall rows list at 2015-03-25 15:19:05.99 (45 rows) and 2015-03-23 20:02:46.07 (16). The AppCompatCache rows list at 2015-03-25 15:31:05.17 (292) and 10:18:30.75 (13). The SAM's account rows list at 2015-03-22 15:53:01.90, the Volume Info Cache rows at 2009-07-14, and the Device Classes rows at 2015-03-25 10:17:27.55. 20 of the report's 324 entries are such rows.

**State now:** Planned. Each plugin row at its entry's own time, with one event for each time a row carries.

### Gap 12: RECmd's batch file writes no row for ten values the answers need

Items: 3, 13, 18, 29, 32, 33, and 57, and 37 and 42 with no effect on their states.

The hives load, but RECmd's batch file, DFIRBatch.reb, names none of these values: Internet Explorer's svcVersion (11.0.9600.17691), the `CD Burning` value DefaultToMastered (0, last written 2015-03-24 20:53:16.67), `Software\Google\Drive` (last written 2015-03-25 15:22:48.88), Chrome's BLBeacon version (41.0.2272.101), the mailto command, `Clients\Mail`, `Print\Printers` with the XPS Document Writer, the Windows Search database's FileName, CurrentVersion 6.1, and NetworkCards\8. RECmd shows each one when it reads a copy of the hive for that key.

**State now:** Planned. The app's own RECmd batch file, with these values and the adapter's interface ID (gap 15).

### Gap 13: RECmd's USBSTOR and SCSI plugins fail on this hive

Items: 22, and 25 and 55 as context.

Both plugins fail with "Array cannot be null" on ControlSet001 and ControlSet002, so no install, first-install, or removal time loads for either drive. The times are in the hive, one key below where the plugin looks: for RM#2, the `Properties\{83da6326-...}\00000064\00000000` key gives 2015-03-24 13:58:33.612. Device Classes rows carry each serial with its last arrival, so a later connection still ties to a serial. A volume and drive E: tie to a device only by time and by MountedDevices bytes. Items 25 and 55 don't need that tie.

**State now:** Fixed in v0.3.0, by documentation. The Tools and rule sets section of [known_limitations.md](../known_limitations.md#tools-and-rule-sets) describes the failure and how to read the times from the hive. A report to RECmd's maintainer isn't filed yet.

### Gap 14: MountedDevices shows its bytes as characters

Items: 2 and 22.

RECmd writes MountedDevices data as one character per byte, not as a disk signature and offset or a device path. The bytes survive one to one, so the offsets decode by hand, but many of them are null and control characters that a page can't show.

**State now:** Planned. MountedDevices decoded into a disk signature and offset, or a device path.

### Gap 15: The network adapter's row lacks its interface ID

Items: 9.

The Network Adapters row gives the adapter's description, driver, and provider, but not its NetCfgInstanceId, so the DHCP interface can't be tied to the adapter's name. The link is in the SYSTEM hive's `Class\{4D36E972-...}\0007` key and the SOFTWARE hive's NetworkCards\8 key, which both name {E2B9AEEC-...}, and neither has a row.

**State now:** Planned, with gap 12's batch file: the adapter's row with its interface ID.

### Gap 16: RECmd's detail files aren't loaded

Items: 6, and 42 with no effect on its state.

Some RECmd plugins write a detail file beside their rows. The SAM's logon counts (TotalLoginCount and InvalidLoginCount) and the services' start modes are only there. Each row names its detail file, but the app loads only the rows' ValueData to ValueData3 fields. The logon counts in the detail file match the document.

**State now:** Planned. The detail files' columns loaded with their rows.

### Gap 17: The time zone's name kept trailing bytes

Items: 4, with no effect on its state.

TimeZoneKeyName read "Eastern Standard Time ard Time", because RECmd writes the bytes after the value's ending null. The app's zone lookup then failed, so the Import page's choice of the host's zone became a fixed UTC-05:00 with no daylight saving time. That is an hour off for a local log from 3/22 to 3/25. No log was imported in this case.

**State now:** Fixed in v0.3.0. The zone name is read up to its ending null, and INFORMANT-PC reads Eastern Standard Time, America/New_York.

### Gap 18: $J paths resolve against the final $MFT

Items: 23, 34, and 52.

69,984 of 317,137 `$J` rows read `\PathUnknown\` for their folder. A parent folder that's gone reads as PathUnknown, and a reused or renamed folder reads as its last name. All 408 records whose parent is `Desktop\temp` list under `Desktop\[QAT`, the name Eraser left, while a path search for `\Desktop\temp` finds 7.

**State now:** Planned. Each `$J` record's path as it was at the record's time. v0.3.0 also runs MFTECmd 2026.10. Run again on a `$J` and its `$MFT`, it resolves some folders that the 2026.5.0 build left as PathUnknown ([CHANGELOG.md](../CHANGELOG.md)).

### Gap 19: No pivot reaches a record's parent folder

Items: 23 and 34.

No pivot goes from a `$J` or `$MFT` record to its parent folder's records. The PathUnknown text gives the folder's entry in hex, while the raw fields give it in decimal. The FileCreate record of `[secret_project]_detailed_proposal.docx` at 2015-03-23 18:39:35.159 reads `0x000115EB-00000006`, and its raw fields give ParentEntryNumber 71147 and ParentSequenceNumber 6. Items 23 and 34 took one search per folder.

**State now:** Planned. A pivot to a record's parent folder.

### Gap 20: SQLECmd's Chrome downloads map fails

Items: 29.

SQLECmd's map for Chromium downloads fails with "no such column: downloads.guid" on this History file's schema, version 29, so no Chrome download loads. A read-only copy of the database holds 2: icloudsetup.exe at 2015-03-23 19:55:47 and googledrivesync.exe at 19:56:30.

**State now:** Planned. A SQLECmd map for this History schema. A report to SQLECmd's maintainer isn't filed yet.

### Gap 21: An LNK event carries its target's times

Items: 27, 28, and 35.

An LNK event carries the times of the file the shortcut points to. The shortcut's own times are only in its `$MFT` record, which no pivot from the LNK event reaches. Koala.jpg.lnk was last modified at 2015-03-24 21:01:12.900, by its `$MFT` record.

**State now:** Planned. A pivot from an LNK event to the shortcut's own `$MFT` record.

### Gap 22: $FN times show only where they differ from $SI

Items: 36.

MFTECmd writes a $FN row only where its times differ from the $SI times. The resignation letter has three $SI rows and no $FN row, though its two $FN attributes hold the $SI times, as MFTECmd's `--de` option shows on a copy of the `$MFT`.

**State now:** Fixed in v0.3.0, by documentation. The Tools and rule sets section of [known_limitations.md](../known_limitations.md#tools-and-rule-sets) describes it and how to see a file's $FN times. Whether the app's MFTECmd runs should pass `--at`, which writes every $FN time, is undecided.

### Gap 23: No lead or suggestion points to the leak

Items: 22, 25 to 30, 32 to 35, 51, 52, 58, and 59.

The Overview's 3 leads are Hayabusa's high and medium hits: Password Reset By Admin and User Added To Local Admin Grp on 3/22, and Suspicious Service Path and Uncommon New Firewall Rule on 3/25. Hayabusa's 10 informational "New USB PnP Device" hits include 4 that name the two drives. Its Explicit Logon Attempt at 2015-03-23 20:23:27.97 sits next to item 24's RunMRU entry. Leads take only high and medium hits, so none of these surfaced. No rule names the burns, Eraser, or CCleaner. Every leak fact was reached by a search the analyst had to know to make. Being hard to find is a gap, not a lower state.

**State now:** Planned. Activity categories, the search behind each guided count, and recipes for common cases, such as removable media and cloud uploads. Whether Hayabusa's lower-level hits, such as these USB hits, should count is open until their noise is measured.

### Gap 24: One out-of-range time set the case's last time

Items: 60, with no effect on its state.

GOOGLE~1.HTM's $FN entry modified time, 3320-11-16 08:35:52.946, is the only event after 2015-03-26. The value is in the record, and the Overview gave it as the case's last time.

**State now:** Fixed in v0.3.0. The Overview takes each host's first and last time from its events dated 1990-01-01 or later and no more than a day after the newest run. A note counts the events outside that span, such as "1 event dated 3320-11-16, outside the rest".

### Gap 25: The report has no visual summary

Items: 60, with no effect on its state.

The report has seven sections of text and no chart. Item 60 is reached on the timeline view.

**State now:** Open. Deferred.

### Gap 26: The timestomping flag was on most $MFT rows

Items: 52, and every `$MFT` item indirectly.

MFTECmd's flag, shown as "possible timestomping", was on 315,855 of the 361,800 `$MFT` rows, 87%. By entry, 61,989 of 77,822 have SI<FN set. The Eraser installer's 6 rows carry it too, so the flag carried no signal.

**State now:** Fixed in v0.3.0. An `$MFT` event's message shows MFTECmd's mark as `SI<FN`, without the words "possible timestomping". A rebuild writes the new words, and event IDs don't change.

### Gap 27: Visits Chrome imported from IE read as Chrome visits

Items: 15, and 44 as context.

16 visits from 2015-03-22 15:09:02 to 15:11:16, all before Chrome's install at 15:11:51.92, were imported from Internet Explorer and read "Chrome visit". No field shows a visit's source.

**State now:** Planned, with gap 20's map, which will give each visit's source.

### Gap 28: Jump list application names can be wrong

Items: 18, and 28 with no effect on its state.

JLECmd names a jump list's application from its built-in AppID list, and some names are products this PC doesn't have: "Microsoft Outlook 2016 64-bit", "Microsoft Excel 12", Chrome versions 9.0 to 48.0, "Sticky Notes (Windows 10)", and "CCleaner 5.15.5513 64-bit". Three AppIDs have no name. The PC has Office 2013 and ran the CCleaner 5.04 installer.

**State now:** Fixed in v0.3.0, by documentation. A row in the Tools and rule sets section of [known_limitations.md](../known_limitations.md#tools-and-rule-sets) says to treat the name as a lead and how to check the version. A report to JLECmd's maintainer, on its AppID list, isn't filed yet.

### Gap 29: The report leaves out Authorized marks

Items: 2 to 7, 9 to 14, 18, 19, 37, 38, 40, 42, 47, and 50.

The report's timeline, caveats, and indicators take only Malicious and Suspicious marks. System facts marked Authorized as context have no entry, and a note on an Authorized event is in neither the report nor the CSVs, only in the audit trail. Finding 7 listed three events of items 18 and 19 as "Not in the timeline (Authorized)". To get a system fact into the report, the analyst has to mark it Suspicious.

**State now:** Planned. Authorized marks listed in the report as context, with their notes.

### Gap 30: A finding's events were listed in the order they were linked

Items: 10, 11, 18, 19, 22 to 28, 32 to 35, 51, and 52.

A finding listed its first 25 events in the order they were linked, while the Findings page lists them by time. Six of the seven findings listed out of time order. Finding 1 put the Map Network Drive MRU at 20:26:04 ahead of shellbags from 20:23:28. Finding 4 put Device Classes rows from 2015-03-25 and the 2009 Volume Info Cache row ahead of the 3/24 mount and shellbags. Finding 5 put the cdrom events ahead of the staging from 19:46:16.

**State now:** Fixed in v0.3.0. A finding's events are listed in order of their shown time, and the cut at 25 comes after the sort.

### Gap 31: A finding's cut at 25 events doesn't say what it leaves out

Items: as gap 30.

Findings 1, 2, 4, and 5 listed 25 of their 43, 52, 26, and 63 events, and the cut dropped whole parts. Finding 2's 25 were all old names, so no new name showed. Finding 5's stopped inside the `Burn\Burn` staging, so neither the disc opened as D: nor the Recycle Bin showed.

**State now:** Planned. A finding that says what its 25 listed events leave out.

### Gap 32: The Summary wasn't escaped

Items: 24, with no effect on its state.

The report escaped the findings' narratives for Markdown but inserted the Summary as Markdown, so `\\10.11.11.128\secured_drive` read `\10.11.11.128\secured_drive`.

**State now:** Fixed in v0.3.0. The Summary is escaped line by line, so a UNC path keeps both leading backslashes.

### Gap 33: The indicators miss the case's addresses and devices

Items: 22 to 24, 27, and 52.

The indicators were 1 account, informant, and 127 file paths. 50 paths read `\PathUnknown\`, and 10 sit under `Desktop\[QAT` (gap 18). The share's address showed only inside file paths, with no address indicator, and no device serial or volume label was listed.

**State now:** Planned. Indicators that leave out the case's own hosts and take addresses, device serials, and volume labels.

### Gap 34: The PC had no IP in the Hosts panel

Items: 9, with no effect on its state.

The Hosts panel and the report's Hosts table gave INFORMANT-PC no IP, though RECmd's Tcpip rows hold DhcpIPAddress 10.11.11.129. The app matched `\Services\Tcpip\Parameters\Interfaces\` with its letter case, and this hive writes `services`.

**State now:** Fixed in v0.3.0. The registry path matches ignore letter case, and INFORMANT-PC gains its address.

### Gap 35: The caveats cover few kinds of record

Items: 15, 16, 22 to 36, 51, and 52.

The report's section on what the marked evidence doesn't prove covered Prefetch (7 entries), AppCompatCache (2), and LNK files and jump lists (8): 17 of the 324 entries. The `$J` (104), browser (81), `$MFT` (41), shellbag (40), other registry (29), and event log (12) entries had none. A `$J` entry's folder can read PathUnknown or a later name, and a shellbag's time marks a key's first or last use, not every visit.

**State now:** Planned. Caveat texts for `$J`, shellbag, browser, `$MFT`, registry, and event log entries.

### Not counted as gaps

- The 745 event records that name the computer 37L4247F27-25: 28 dated 2010-11-21, and 717 on 2015-03-25 from 10:14:55 to 10:18:29 UTC, in an early session before the user's startup. They are context for item 12, which the corrections cover.
- An empty event log, `Key Management Service.evtx`, wasn't in the evidence. The unpacking step skipped it as a byte-for-byte copy of another empty log, `HardwareEvents.evtx`. No item needs it, and the step now keeps such copies.
- Loading the shortcut files' own times from LECmd's output, proposed as a fix for gap 21. All 25 LNK files here carry the times of the copy the unpacking step made, 2026-10-22, so loading them would add wrong times. The shortcuts' real times are in their `$MFT` records.

## Limits of this check

- The answers were known during the work. The check shows the evidence is present and readable, not that an analyst would find it without the answers.
- After the case was made, the work went through the app's local HTTP interface, not by clicking through the page. How easily an analyst finds things in the page isn't measured.
- The score comes from a build made before v0.3.0. The page gives the first run's states.
- The answer items are a reading of the answer document's section 6, with the corrections above.
- What WebCache, the Windows Search index, thumbcache, `setupapi.dev.log`, and the removable media's file systems would add inside the app isn't shown, since none of them loads. What they hold comes from outside tools, run on copies.
- The email channel isn't checked, since the OST wasn't collected.
- The check has one host. The removable media never became hosts, and the dataset has no packet capture, so pivots across hosts and the clock check had nothing to work on.
- The step that unpacks the images into the evidence folder isn't part of this repository, so a reader can't yet rebuild the same folder from the published images.
- Gaps 29 to 35 were found while the report was written, and no second pass checked them. A second pass did check every other gap, with outside tools on copies of the hives, WebCache, the index, thumbcache, Chrome's History, `setupapi.dev.log`, and the `$MFT`.
- The What has been checked section of [known_limitations.md](../known_limitations.md#what-has-been-checked) says what else hasn't been shown.
