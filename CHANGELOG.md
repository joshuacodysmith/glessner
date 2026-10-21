# Changelog

Releases of Glessner, newest first. Each release has a version, held in `pyproject.toml`, and a git tag, `v<version>`. Every output carries a build identifier: the version plus the commit. Version 0.1.0 predates this repository, so it has no tag here.

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
