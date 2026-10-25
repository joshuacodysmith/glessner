# Changelog

Releases of Glessner, newest first. Each release has a version, held in `pyproject.toml`, and a git tag, `v<version>`. Every output carries a build identifier: the version plus the commit. Version 0.1.0 predates this repository, so it has no tag here.

## [Unreleased]

Opening a case with this build upgrades it to case format 4, which 0.2.0 can't open. A case whose journal is read-only stays at format 3.

### Finding your way

- The Tools page names the rule or map set each tool's latest runs used, and both it and the Overview's **What the case holds** say how many rows a parser skipped. A Hayabusa lead's chips name the rule sets of the runs that made its hits.
- A reason that ends in a period no longer shows two, and the job box says why a load of found output left out every row.
- A bidi control in evidence text, such as the right-to-left override that makes `report<U+202E>fdp.scr` read as a PDF, shows on the pages as a visible `[U+202E]`: in lists, on the Event page and its pivots, in the timeline's lanes and hovers, in the Sources panel, on the status line, and in the Start page's folder checks. A click that copies a value, Copy as JSON, the search box, and the View keep the character as recorded. A list's find box and the Sources panel's find box take `[U+202E]`.
- Browse on the start page says "Browse doesn't open device paths. Type the folder's path instead." for a device path on this computer, such as `\\?\C:\Windows`, `\\.\PhysicalDrive0`, or a volume GUID path, and for one that goes through `Global` to a local name, such as `\\?\Global\C:\Windows`. It still refuses the path and opens nothing. A UNC path, a path on a mapped network drive, and a device path through UNC or GLOBALROOT, such as `\\?\Global\UNC\server\share`, still get "Browse doesn't open network folders. Type the folder's path instead." Browse also refuses a path through a junction and doesn't list a junction as a folder, as it already did for a symbolic link. A junction can lead to a symbolic link that leads to a share. A cloud-sync folder such as OneDrive is still listed and opened.
- A host whose IP has network logons (4624 type 3) that record another machine's workstation name, as after a stale DHCP lease, needs review, with a note such as "3 logons from 192.168.1.23 name ATTACKER-PC, not this host". The logon links stay as they are.
- A 4624 whose source address is loopback, link-local, or unspecified, and that no collected host owns, now links by the workstation name it records, as a logon with no address does. A logon from any other address, private ranges included, never falls back to the name.

### The Event page and pivots

- An $MFT event's message shows MFTECmd's SI<FN mark as `SI<FN`, without the words "possible timestomping", since MFTECmd sets that mark on most records of an ordinary volume.
- Zeek logs that join field names with an underscore, such as `id_orig_h` and `certificate_subject`, load with their addresses and ports in the event's fields and message, so `addr:` and the address pivots find them. A JSON log whose first record carries `ts` and `id_orig_h` is known as Zeek output whatever its file name. An x509 record's message shows its `certificate_subject`, and a pe record's message names its sections: as a JSON list from a JSON log, and comma-separated from a tab-separated log.
- A rebuild (`uv run glessner rebuild CASE`) writes the new $MFT flag words. Event IDs don't change, so marks, tags, and links stay on their events. A Zeek log loaded by an earlier build, from the Tools page or by an import, keeps the mapping it was loaded with when the case is rebuilt. To read its underscore names and pe sections, stop the server and import it again with `uv run glessner import CASE FILE --mapping zeek`, which replaces its events and keeps their IDs. Its records can then gain addresses, so a host's clock check can change: the check can pair them with that host's events, and a host whose check had no pairs can get a suggestion.
- A time the host's clock didn't write, such as an Autoruns PE link time, shows a **Host offset +N s** chip when its host has a clock offset, with the recorded time in its hover, and no clock note or host local time.
- RECmd's Services rows no longer start their message with "Services: None = ". A case an earlier build loaded keeps the old text until `uv run glessner rebuild CASE`. Event IDs don't change.

### Marking, findings, and the report

- The report's Method table has a Rules column and lists the files each tool ran with, by SHA-256, and the report gives an event of found output the same evidence hash as its Event page. A run record the app can't read fails the report by its file's name.
- The timeline export gives Suricata's flow ID and Zeek's uid their own columns, `network.flow_id` and `zeek.uid`, right after `network.community_id`. `network.community_id` holds only a community ID, so a search on it across tools no longer matches a sensor's own flow number.
- An indicator that is a file in the Windows folder's own files, or below System32, SysWOW64, or Sysnative, stays in the report's table and `indicators.csv` with a note that it may be a system tool the attacker used, so check before you block it. The table gains a Note column, and the CSV a `note` column.
- A mark, a suggestion decision, a host change, a clock alignment, or a rule write that the server accepted no longer reads as failed when the timeline then fails to reload. The status line says the write was made and the timeline didn't reload, so a retry doesn't journal it twice.
- A double click on Add the finding journals one finding, not two.

### Case records

- Case format 4: the upgrade from format 3 adds one entry to the journal and raises the number in `case.yaml`. The case's events, runs, and manifest don't change, except for found output that an earlier build loaded under a linked evidence path (the next line). A format 3 case whose journal has no chain or has a break stays at format 3 and opens read-only, as it did.
- Case format 4: the upgrade gives the event IDs a rebuild gives to found output that an earlier build loaded while `case.yaml` named the evidence through a link, such as a junction, a substituted drive, or a mapped drive. Those events named each file by its whole `//?/` path, and this build names it by its path under the evidence folder. For each such run, the upgrade reads the run's output once, keeps the names its events carried in a file in the case folder, loads the run again, which writes the run's record again with the new load's counts, and journals the old and new IDs as one rekey so marks, tags, notes, and findings follow. It checks the journal first, so a case whose journal has a break stays at format 3 with its events as they were. A stop partway through leaves format 3, and the next open finishes the upgrade with the same IDs, unless the file doesn't fit the case or a run it names can't be read, which holds the case at format 3 with a message that says what to do. A run whose output changed since its load, or can't be read at the first open, keeps its rows and IDs, and the entry names it. A load of found output also replaces rows that name one of its files by its `//?/` path, matched to the files the earlier run read under the run's one root, so a file of the same name in another folder keeps its rows, also in a single-host case, and Add new evidence doesn't leave a file's events twice. A case with no such rows keeps every ID and gets the usual entry.
- The journal's `case_created` entry names the case's format, and a rekey of event IDs from format 3 to 4 counts only in the upgrade's own place: not in a case created at format 4, not after a manifest record, and not after another upgrade from 3 to 4. A hand-made one anywhere else is a break to the app and to `scripts/check_journal.py`.
- Case format 4: each tool run records the rule or map set it used, for Hayabusa, EvtxECmd, RECmd, SQLECmd, and Suricata, such as `Hayabusa rules fffbdd1, files 7c30c465`, `Maps, 456 maps`, `DFIRBatch.reb 2.22`, and `ET Open 11310`. A Hayabusa rules folder that is a Git checkout is named by its commit and the first 8 hex digits of the folder's SHA-256, so an edited checkout reads differently from an unedited one at the same commit; one that isn't a checkout is named by the 8 digits alone. It also records the SHA-256 of the tool's executable and of the rule, map, plugin, and configuration files the run names. A run made before format 4 has no tool hashes. The Tools page and the report show the rule or map set of a Hayabusa, EvtxECmd, RECmd, or SQLECmd run made before format 4 as not recorded, a Hayabusa lead's chip reads "Hayabusa rules not recorded" for such a run, and a Suricata run still shows its ET Open version. A case kept at format 3 records no rule or map set and no tool hashes, apart from Suricata's rule set version.
- Case format 4: a run's record counts the rows or lines a parser read and made no event of, for MFTECmd, Suricata, and imports. A rebuild fills the count for runs made before format 4.
- Case format 4: the journal records the SHA-256, size, and line count of `manifest.jsonl` at each intake and Add new evidence, and a case copy carries its source's record. When the source couldn't vouch for it, because its journal has a break, no head of it is recorded on this computer, or its first record came with Add new evidence, the copy's record says why, and `verify`, `close`, the report, the Case overview's Integrity, the case state under the case name, and the audit trail repeat the reason, the case state as soon as the copy opens. A break or a head not recorded here is a warning in Integrity and the case state, and none of the reasons changes the exit of `verify` or `close`. `verify`, `close`, and the report compare the file with its record and say whether it matches, grew past it, differs, or has no record. `verify` and `close` exit 1 when it grew past or differs from its record, and `verify` also exits 1 when it is missing while the journal records it.
- Add new evidence refuses a `manifest.jsonl` that differs from its record, and `intake` refuses to write a new manifest over a missing one that the journal records. The case state and the Overview's Integrity warn when the newest full re-hash found `manifest.jsonl` changed or missing, and never call such a re-hash matched.
- A case upgraded from format 3 gets its first manifest record at the next Add new evidence that adds a file, and that record vouches only from then on.
- A load of tool output found in the evidence replaces only rows that earlier loads of the same tool's found output put on the same host, never a tool run's or an import's. A row naming another host's file or a path outside the evidence replaces no rows of other loads, and a reload of the same files replaces the earlier load whole. Rows naming a file whose events the case holds from a run of the same tool on the host are left out, and the Case overview's gaps say so when that leaves a load empty. The Event page cites the intake hash of the output its run read, not of the file the event names. Event IDs don't change.
- The text of the entry that upgrades a case from format 1 to 2 now counts the journal's references that name no loaded event, such as a mark on an event no run gives, in one more sentence, for example "2 journal references name no loaded event." It says nothing when every reference names a loaded event, and nothing for a case with no events database.
- A run of EvtxECmd or Hayabusa notes each event log that intake identified by its content but that is named otherwise than `*.evtx`, since both tools read only files with that name. A run on a host whose event logs all have another name is refused. Before, such a log was listed as an input of the run with no note, and its events and Hayabusa's alerts on them were missing.
- An import preview, an import, a tool run, and the copy step of a tool that works on copies refuse a file that became a cloud placeholder after intake hashed it, and name it, instead of reading it and downloading it with no record. For such a file the refusal says to make it available on this disk and try again, since intake's hash still covers it. When a run of a tool that lists a host's folder is refused, the refusal tells these files apart from a placeholder that intake never hashed.
- A journal entry from before case format 3 whose `who` isn't text, such as a list, no longer makes the Case overview or the audit trail fail. The audit trail and its export, the Case overview's last action, and the report show such a `who` as its JSON text, such as `["ann", "lee"]`.
- The audit trail keeps its check of the journal between requests only while the journal, the head recorded outside the case, and the side files its entries name are as they were. A side file that was replaced, changed, or deleted shows on the next request, and a check made while the journal's last line was being written isn't kept.
- `verify` exits 1 when intake hashed none of the manifest's files, and says no evidence file has an intake hash to check. A case where intake hashed some of its files exits as it did.

### Running the app

- `glessner serve CASE` says, for a case of an earlier format, that the open upgrades it to format 4. Once the case is open, it says whether the case is now at format 4, which older builds can't open, or its journal is read-only, so the case stays at format 3 and opens read-only.
- Stopping `glessner serve` with Ctrl+C waits up to 5 seconds for running requests, then interrupts any statement still running on the events database and closes it. A request in a long count no longer holds the stop up, and one that finishes within the wait answers instead of failing. If any requests were still running when the wait ended, the command says how many. A load or tool run started from the Tools page isn't a request and isn't waited for, but the rebuild of the case's tables that follows a load is, and is cut off the same way.

## [0.2.0] - 2026-10-22

Opening a case with this build upgrades it to case format 3, which 0.1.0 can't open. Try it on a copy of the case first.

### Finding your way

- A case with events opens on its **Case overview**, and a new or empty case opens on its **Tools** page. **Start here** lists leads from tool output, rules, and clock checks, ranked by severity, then by the earliest time, each with one action. **Your progress** counts your marks, worked leads, and decided suggestions from the journal. **What the case holds** gives each host's role, OS, events, and time span, the case's gaps, such as runs that loaded nothing, and its integrity.
- The header is grouped by job: the case's name and state, a path through the work (Overview, Timeline, To investigate, Findings, and Audit trail), the search box, and a **Case** menu for Hosts, Tools, Import, Rules, Export, Audit trail, and Cases.
- The timeline has its own toolbar, with a one-line hover hint for each control. Under it, a state line always says how many of the case's events the timeline shows, what is hidden, each with a **Show** that clears it, which clock the times are on, and the window. A legend of every mark the timeline draws opens with **Legend** or L.
- The timeline opens with its lanes folded to their first level, with **Open all** and **Fold all** right of UTC, and the folds are remembered by case and preset. The Details panel opens at two-thirds of the stage, or less, never under half, when two-thirds would hide a folded row.
- A reload (F5) comes back to the page that was shown: the path's step, the Details page with its pivot list and trail, the selection, the search box, the Lanes preset, and the timeline's window. Only a reload of the same open in the same tab does; a new tab from the link, a new serve run, or a case opened again from Cases starts on the Case overview, or on Tools if the case has no events. The Sources and View filters still start off, and the status line says so.
- Each list in the Details panel has a find box that narrows only the rows shown, and counts, meters, and headings still cover every row. On a list cut at 500 it says how far it reaches, and on a search it offers to search all the matches for plain words. Select all under a find ticks only the rows shown.
- The page uses one set of colors, type sizes, and contrast levels throughout, in light and dark mode. A review-state letter, U, A, S, or M, leads each event in every list, in the right-click menu's head, and on the Event page.
- The start page offers **Remove from list** for a recent case whose folder is gone, and removes them all at once when there are several.

### The Event page and pivots

- The Event page ranks the next pivots for the kind of event it shows, from a fixed table with its sources. Each row gives its reason and how many events it finds across the case before you click, and flags broad ones, such as a pivot on a system session or a shared Windows program. A pivot the event can't take is named on one line with the reason.
- Every source a caveat or a pivot shows is a public page or a file in the repository.
- A trail above the page keeps the pivots you took and the events you opened from them, and **Save trail as a note** journals it on the event the trail started from.
- One line under the header says which tool and run read the event, from which evidence file and record, whether the file's hash still matches intake, and the build. A caveat says what that kind of record does not prove, such as a Prefetch file showing that a program ran but not who ran it.
- The logon caveat says that on an NTLM logon the workstation name is the one the client sent, and cites Microsoft's MS-NLMP specification. The Amcache caveat cites Valhuntir's SRUM page for SRUM as a sign that a program ran.
- New pivots: Same service name, Same workstation, Same flow, Same task name, Same rule or signature, Same hash (by MD5, SHA-1, or SHA-256), and Same file name. Same file name matches the file's name alone, in any folder and without letter case, bare names such as SRUM's included, and its hover warns that it joins every file of that name. Same account matches an account however it was written, such as `C137\Administrator` and `Administrator@C137.LOCAL`.
- The right-click menu's Find related lists the pivots the Event page offers for the event, in the kind's order and without counts.
- Parser fixes that give pivots more to join. A 4688 joins the logon session that ran it, the account of a group change is who made it, and 4778, 4779, Defender, object access, and 4776 events fill the fields they record. A capture's IPv6 address joins an event log's. RECmd's AppCompatCache, BAM, Run, Services, and UserAssist rows, Windows Timeline programs, folder variables, and cut Prefetch names join the file they name. Run `glessner rebuild` on an existing case to apply them.

### Marking, findings, and the report

- **To investigate** is a worklist with progress. Each Malicious or Suspicious event has a **Followed up** tick you set, and beside it what is still unreviewed around it, as counts that open each pivot's list. Pending suggestions are grouped by rule, each saying why it fired, with **Review one by one** (A accepts, R rejects, N moves on), **Accept all**, and **Reject all**.
- A group action asks first. Accept all, Reject all, and a mark or tag of more than 25 hand-picked events name what they cover and the count the page loaded, and act only on those events.
- **Findings** are conclusions you write: a title, a severity in words, a narrative, ATT&CK techniques, and the events that support them. Each finding shows what its events do not prove. The app never writes a finding or its words.
- The Markdown report replaces the findings summary. Its seven sections are Summary, Findings, Timeline of marked events, Indicators, Hosts and clocks, Evidence and integrity, and Method.
- Each export says its scope and contents before you click. Marked-event exports cover the whole case whatever the window. The new **Indicators** export lists the addresses, domains, hashes, accounts, file paths, services, and tasks parsed from the events marked Malicious. Network rows carry ECS columns: the signature as `rule.name` with `rule.id` and `event.severity`, the record type as `event.dataset`, and `network.community_id`, `url.full`, `dns.question.name`, `tls.server.name`, and `client.mac`.
- Every file the case writes is hashed and journaled, and **Written from this case** lists each with its rows and SHA-256.
- A finding's ATT&CK field is a pick list: typing an ID or words of a name lists Enterprise ATT&CK v20.0's matching techniques and sub-techniques, and only a listed one can be picked; the server refuses any other. A finding saved earlier keeps its IDs, and one that isn't listed shows flagged, such as "T1086 (revoked; now T1059.001)", and must be removed before the techniques can be edited. The list ships with the app, with MITRE's copyright line and license.
- The tag picker's technique box is the same pick list, one technique at a time, and the server tags only a listed technique: a revoked ID is refused with its replacement named, such as "T1086 is revoked in ATT&CK v20.0; it's now T1059.001." An event's older tag on an ID off the list is kept, shows flagged on its chip, in the View panel, and in the report, and can be removed. Hayabusa's suggestion of a revoked ID is made as its replacement, and of an ID off the list not at all.
- The Findings page's Report and Exports sections each open under a band heading.
- No cell of a CSV the app writes can run as a spreadsheet formula. This covers the timeline CSV of every scope and `indicators.csv`. A text cell that begins with `=`, `+`, `-`, `@`, their full-width forms, a tab, a carriage return, or a line feed gets a tab in front. So does such an operator after a semicolon or a line break inside the cell, with or without one double quote between. The header row is fixed app text and goes out as written, `@timestamp` included. Every text cell is quoted, and Excel and LibreOffice keep these cells as text.
- The Exports cards name their network columns, say that a tab goes in front of text a spreadsheet would run as a formula, and say that JSONL keeps values as written.

### Search

- A word or phrase in quotes matches whole words only, so `"nmap"` finds nmap.exe and not WinMaps. The **Whole word** tick adds or removes the quotes, and **Show what the forgiving search adds** counts what the search finds without them.
- `rule:"RDP from internet"` finds the events a Hayabusa rule hit. A search whose word is in a rule's title lists that rule under the results, under **Also found by name**.
- A search with no match says what free text skips and links the values that hold your words.

### Case records

- `glessner --version` prints the build: the release version, the commit, and `.dirty` when the package's files differ from that commit. The start page, the report, the audit trail's export, and imported events show the same build, and the journal records each build that opens the case.
- `case.yaml` holds a case format number. A build refuses a case in a newer format, naming both numbers, and upgrades an older one, with a journal entry.
- Case format 2: the event IDs of Suricata, SQLECmd, and found Amcache and SRUM events no longer depend on where or in which time zone a tool ran. The upgrade reloads those events and records each old ID the journal named with its new one.
- Case format 3: the journal is a hash chain, in which each entry names the one before it and the build that wrote it, so a change to an earlier entry shows. A broken chain opens the case read-only until you continue with the break on record. The app records the journal's head on this computer after every write and compares it at each open. `close` and each export print the head, and `glessner verify CASE --journal --expect-head HEAD` checks a copy against a head you recorded, as `scripts/check_journal.py` does with Python alone.

### Running the app

- `glessner serve CASE` says what its open is doing before it prints the link: the case it opens, whether this open upgrades the case format, and each step as it starts, with the seconds since the open began and a "still working" line when a step runs 5 s without one.
- `glessner serve` tries port 47613 first, so the page's saved layout lasts from one run to the next. A tab from an earlier run is refused clearly, and each run's session cookie is named with its port.
- The server answers HTTP/1.1 and keeps the browser's connections open, so a page load opens 6 connections rather than 37 and the Event page's counts open none.
- The app is renamed Glessner, formerly triage-workbench. The command, the Python package, and the settings folder are `glessner`, and `GLESSNER_CONFIG_DIR` replaces `TW_CONFIG_DIR`. The first start copies the Recent cases list and the browser preferences from the old name's settings, and leaves the old ones in place. Journals and run records from before the rename stay as written, and both names count as the app's own entries.
- The app makes no network calls, and a test now checks it across a case load, a search, and every export. Every DuckDB connection has extension autoinstall and autoload off. In the suite, every test fails if a Python socket connects, binds, or sends to anything but this machine, or looks up a name other than localhost.
- `setup.md` takes a fresh Windows machine through uv, Python, every tool Glessner runs, and the .NET 9 runtime that RBCmd, SQLECmd, and WxTCmd need. Its blocks check each Eric Zimmerman tool's .exe file and the Suricata installer by signature, and the .NET runtime, Hayabusa, and the ET Open rule set by published hash. The page adds no check for uv, Glessner, Npcap, or the .dll files that RBCmd, SQLECmd, WxTCmd, and RECmd load from their folders. It ends with a check that the app finds every tool.
- `.python-version` pins Python 3.14, since DuckDB 1.5.6 has no Windows wheel for Python 3.15.
- The build backend requirement admits uv 0.11 through 0.13, so a current uv builds the package with its own backend and without a warning.

### Feedback and limits

- `known_limitations.md` lists what the app doesn't do yet or doesn't do well, grouped by what you rely on a result for, with what you can do about each limit.
- The repository has two issue forms, one for feedback and one for bug reports, and blank issues are off. Each form asks you not to attach evidence, case files, or real incident data.
- `SECURITY.md` says what to report as a security problem and how to report it privately through GitHub's private vulnerability reporting.

### Tests

- The suite runs in parallel with pytest-xdist, one worker per two logical CPUs. With the `lab` and `browser` tests it takes about 7 minutes on a 16-thread machine.

## [0.1.0] - 2026-10-16

The first build with a version number. Joshua Cody Smith tested it by hand on the Stolen Szechuan Sauce case on 2026-10-16, with no failures or stops. Before the release, fresh cases ran end to end on the Szechuan evidence, EVTX-ATTACK-SAMPLES (with a host split), and the Malware-Traffic-Analysis.net capture of 2016-01-07, and the defects those runs found that needed no design decision were fixed.

What it holds:

- Case folders, case copies, intake hashing against a manifest, closing a case with a re-hash, and a start page for new, recent, and copied cases.
- A tool runner with parsers for EvtxECmd, Hayabusa, RECmd, MFTECmd (including the USN journal), PECmd, LECmd, SBECmd, AmcacheParser, JLECmd, SrumECmd, RBCmd, SQLECmd, WxTCmd, and Suricata on packet captures, plus a built-in reader for Windows event XML.
- Loading other tools' output found in the evidence (KAPE CSVs, Zeek logs, Suricata EVE JSON, Autoruns CSVs), and importing text logs: firewall, web server, syslog, IDS alerts, and CSV or JSON lines.
- One lane timeline in a local browser page: host identity, logon links, pivots, search, Sources and View filters, marks with notes, tags, suggestion rules, the To investigate list, and the audit trail with undo.
- Clock offsets, clock checks against a capture, zone axes, and splitting a host by its recorded computer names, with event IDs that stay stable across all of them.
- Timeline exports and the Markdown findings summary.
