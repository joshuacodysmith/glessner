# Glessner coverage reference

This sheet lists what Glessner reads today, what reaches the timeline, and which rule sets flag events, as checked against the code on 2026-10-19. It ends with the common Windows DFIR sources the app doesn't cover yet, for deciding which modules, parsers, and tools to add.

[scope.md](scope.md) says what the app does and leaves out, and [glossary.md](glossary.md) names its parts. Counts for a tool's rules, maps, and batch file, and the tool versions, come from the copies installed on the machine where the sheet was checked, called the test machine below.

## Reading this sheet

- A code citation names a module under `src/glessner/` and its function or constant, such as `identify.identify_bytes`. A tool setting cites the tool's file under `registry/`.
- Each claim is Direct, read in the code or seen in a tool's own `--help` output, unless it is tagged **Inferred** (follows from the code but wasn't tested) or **Unknown**.
- The project adds no new tools, parsers, or formats until its checks against practice cases with known answers are done. After that, a new source comes only to close a gap those checks found. The gap list at the end is input for that choice.

Sections: [coverage at a glance](#coverage-at-a-glance), [how evidence enters](#how-evidence-enters), [what intake identifies](#what-intake-identifies), [registered tools](#registered-tools), [found tool output](#found-tool-output), [the text log import](#the-text-log-import), [refusals](#what-the-app-refuses-or-leaves-unread), [artifacts on the timeline](#artifacts-on-the-timeline), [search fields](#search-fields), [rule and detection sources](#rule-and-detection-sources), and [gaps](#gaps).

## Coverage at a glance

What the app reads today by evidence area, and what it leaves out. The sections after this one give the detail and the code behind each row, and [gaps](#gaps) sizes each missing piece.

| Area | Read today | Not read, or read in part |
|---|---|---|
| Event logs | EVTX through EvtxECmd, with Hayabusa and Sigma rule hits. Event XML through the built-in reader. | No rule hits for event XML. No check for record ID gaps, and no records carved from slack. |
| Registry | Every hive through RECmd's `DFIRBatch.reb`. ShellBags through SBECmd. Amcache through AmcacheParser. | Amcache's device and driver tables. RECmd's plugin CSVs. |
| Program execution | Prefetch, Amcache, AppCompatCache, BAM, UserAssist, SRUM app use, the Windows Timeline, and 4688 and Sysmon process events | RecentFileCache.bcf, Windows 11 PCA files, PowerShell console history, Defender's MPLog |
| File system | `$MFT`, `$J`, Recycle Bin `$I` files, LNK files, jump lists, and Zone.Identifier contents | `$LogFile`, `$I30`, `$Boot`, `$SDS`, INFO2, and volume shadow copies |
| Persistence | Services, Run keys, service and task events in the logs, and Autoruns CSVs found in the evidence | Scheduled task XML files, WMI subscriptions, BITS jobs |
| Browsers and applications | Chromium-based browsers' (Chrome, Edge, Brave) visits, downloads, searches, and typed addresses, and Edge's navigation history. Firefox visits and downloads. Windows notifications. | Cookies and autofill (SQLECmd writes them, the app doesn't load them), logins, WebCache, OneDrive, Teams, Office Backstage, Notepad tabs, the Windows Search index, Windows diagnostic data (`EventTranscript.db`), Windows Error Reporting, certutil downloads |
| Network | Captures through Suricata with ET Open. Suricata EVE and Zeek logs. Windows Firewall, IIS, Apache, syslog, Fortinet, SonicWall, Cisco ASA, and fast alert logs through the import. | Sguil exports, Snort full alerts |
| Other text logs | CSV, JSON lines, key=value, W3C, and timestamped lines through the import | Records that span several lines |
| Antivirus | Defender's event log | MPLog, DetectionHistory, other vendors' logs |
| Servers and remote access | Logon, RDP, and share events | User Access Logging, AnyDesk, TeamViewer, and ScreenConnect logs, the RDP bitmap cache |
| File content | None | YARA scanning |
| Inputs | Collected files, one folder per host, or one host for the whole folder | Disk images, containers, shadow copies, memory |
| Rule set versions | ET Open's version, in each Suricata run's record | Hayabusa's rules, EvtxECmd's maps, RECmd's batch file, SQLECmd's maps |

## How evidence enters

| Path | What it reads | How it becomes events | Code |
|---|---|---|---|
| Intake | Every file under the evidence folder. Each is hashed, identified by content or name, and listed in `manifest.jsonl`. | Nothing loads at intake. | `intake.intake`, `intake.add_new`, `identify.identify_file` |
| Tool run | Raw artifacts that a registered tool handles | The tool writes to the run's folder, and the parser its registry file names reads the output. | `runner.plan_runs`, `runner.run`, `runner.load_output` |
| Found output | Output a tool already wrote that sits in the evidence, known by its header or file name | The same parser a run of that tool uses. Autoruns, which the app never runs, has a parser of its own. Zeek logs load through the import's `zeek` preset. Three kinds are recognized but not loaded. | `tool_outputs.kind_of`, `toolbox.found_outputs`, `runner.load_found_output` |
| Import | Text logs, with a field mapping the analyst checks | The import's own readers, under tool `import` | `imports.run_import`, `imports.importable` |

Intake and host rules:

| Rule | Code |
|---|---|
| A case takes one intake. Files added later come in through Add new evidence, which appends entries stamped with `added_utc`. | `intake.intake`, `intake.add_new` |
| The walk skips symbolic links, junctions, and folder reparse points, and lists each one it skipped. | `intake.walk` |
| A file that can't be read gets an entry with method `unreadable`, the exception as its error, no hash, and no identification. Full checks list it as unverified. | `intake._entry`, `intake.check_files` |
| Identification reads the first 8,192 bytes. | `identify.SNIFF_BYTES` |
| A file an older build left unidentified is identified again when its name matches a newer signature or a text log's suffix. Text logs are identified again too, since they may be tool output or a format added since. The new identification is used only when it names an artifact, and the manifest isn't rewritten. | `intake.current_entries`, `intake._read_again` |
| A run re-hashes its inputs. Full checks re-hash every file at case close, at the findings summary, and on request. | `intake.verify`, `intake.check_files`, `intake.FULL_CHECKS` |
| A multi-host case has one top-level evidence folder per host. A file directly in the evidence folder belongs to no host unless the case was started as a single host. | `case.Case.host_of` |
| No tool run is planned for a file with no host. Found output with no host shows as `no_host`. | `runner.plan_runs`, `toolbox.found_outputs` |
| An import of a file with no host needs a typed host name or a host field. | `imports.host_lane` |
| Starting a case: the evidence must be a folder. A case folder that isn't empty, or that contains or sits inside the evidence, is refused. A tools folder on a network path, or overlapping the evidence or the case, is refused. Duplicate copies of a host raise a warning. | `start.check`, `case.tools_folder_problem`, `start.copies_warning` |

## What intake identifies

`identify.identify_bytes` tries these in order, and the first match wins.

| Artifact | Recognized by | Detail recorded | Read by |
|---|---|---|---|
| `evtx` | `ElfFile\0` magic | | EvtxECmd and Hayabusa |
| `registry` | `regf` magic | Hive type from the name: SYSTEM, SOFTWARE, SAM, SECURITY, DEFAULT, NTUSER, USRCLASS, AMCACHE, else "unknown hive" (`identify.HIVE_TYPES`) | RECmd. SBECmd for NTUSER and USRCLASS. AmcacheParser for AMCACHE. SrumECmd copies the host's SOFTWARE hive with SRUM. |
| `registry_log` | `regf` magic in a `.log`, `.log1`, or `.log2` file | Hive type, from the name without that extension | RECmd, as the hive's transaction log |
| `lnk` | Header `4C000000` and the shell link CLSID | | LECmd |
| `jumplist` | `.automaticDestinations-ms` with the OLE magic, or `.customDestinations-ms` at version 1 or 2 | `automatic` or `custom` | JLECmd |
| `recycle_bin` | A `$I` file at version 1 or 2 | `$I version 1` or `2` | RBCmd |
| `srum` | `SRUDB.dat` with the ESE magic at offset 4 | | SrumECmd |
| `prefetch` | `SCCA` at offset 4, or the compressed `MAM\x04` header | `uncompressed` or `compressed` | PECmd |
| `mft` | `FILE` magic in a file named `$MFT` or `_MFT` | | MFTECmd |
| `mft_mirror` | `FILE` magic in `$MFTMirr` or `_MFTMirr` | | No tool |
| `usnjrnl` | Name only: `$J`, `$UsnJrnl%3A$J`, `$UsnJrnl_$J`, `$UsnJrnl.$J`, or `$UsnJrnl$J` | `USN journal $J` | MFTECmd, with the `$MFT` in the nearest folder above the `$J` passed as `-m`, so each volume's `$J` takes its own. With none above it, the run has no `-m` and says so in its notes. |
| `sqlite` | SQLite magic | A role for ActivitiesCache.db, History, Shortcuts, places.sqlite, downloads.sqlite, and wpndatabase.db, else "SQLite database" (`identify.SQLITE_ROLES`) | SQLECmd. WxTCmd for ActivitiesCache. |
| `sqlite_log` | A `-wal`, `-shm`, or `-journal` file of a database named in `identify.SQLITE_ROLES`. Another database's logs stay unidentified. | The suffix: `wal`, `shm`, or `journal` | Copied with its database for SQLECmd and WxTCmd |
| `pcap` | One of four pcap magics, or pcapng | `pcap` or `pcapng` | Suricata |
| `event_xml` | A `.xml` file with the event schema's namespace and an `<Event>` element | `Windows event XML` | The built-in event XML reader |
| `tool_output` | A header or name in `tool_outputs.KINDS` | The kind | That kind's parser, as found output |
| `w3c_log` | A `#Fields:` header | Windows Firewall, IIS, or W3C extended | The import |
| `jsonl` | Two lines that start with `{`, a `.jsonl` or `.ndjson` name, or a `.json` file holding an array | `JSON lines` or `JSON array` | The import |
| `line_log` | A known line layout (`line_logs.detect_layout`) | The layout | The import |
| `kv_log` | Three or more `key=value` pairs a line | Fortinet or SonicWall when the keys match | The import |
| `csv` | A `.csv` or `.tsv` name with a delimiter | The delimiter, such as comma-separated | The import |
| `line_log` | Lines that start with a date and time, tried last (`line_logs.STAMPED`) | `Lines that start with a date and time` | The import |
| Unidentified | An empty file, `FILE` magic without an `$MFT` name, a `.json` file holding one object, or anything else, with a hint from its name (`identify._name_hint`) | The reason | The import offers unidentified files on request (`imports.importable`) |

## Registered tools

Sixteen files under `registry/`, loaded by `tools.load_registry`. A tool is found in the tools folder, searched recursively with links skipped, and then on PATH (`tools.detect`). Mode `host_dir` runs once per host on the host's folder. Mode `each_file` runs once per identified file (`runner.plan_runs`). `registry/known/known_tools.yaml` lists tools the app recognizes in the tools folder but doesn't run, covered under [gaps](#gaps).

| Tool | Reads | Mode | Parser | Settings in its registry file |
|---|---|---|---|---|
| EvtxECmd | `evtx` | host_dir | `evtxecmd_csv` | `-d {host_dir} --csv {output_dir} --csvf evtxecmd.csv`. Its `Maps` folder beside the executable shapes the `PayloadData` columns. |
| Hayabusa | `evtx` | host_dir | `hayabusa_csv` | `dfir-timeline -d {host_dir} -o {output_dir}\hayabusa.csv -p verbose -b -w -q -K -O -C -Q`. Option `min_level` adds `-m`. Its rows are hits, not timeline events. |
| Event XML reader, built in | `event_xml` | host_dir | `event_xml_csv` | `python -I -m glessner.event_xml`. Writes EvtxECmd's CSV layout. Its version is the app's build. |
| RECmd | `registry`, `registry_log` | host_dir | `recmd_csv` | `--bn {tool_dir}\BatchExamples\DFIRBatch.reb --nl` |
| SBECmd | `registry:NTUSER`, `registry:USRCLASS` | host_dir | `sbecmd_csv` | `--nl`. The parser reads `!SBECmd_Messages.txt` too. |
| AmcacheParser | `registry:AMCACHE` | each_file | `amcache_csv` | `-f {input_file} -i --csv {output_dir}` |
| MFTECmd | `mft` | each_file | `mftecmd_csv` | `-f {input_file} --csv {output_dir} --csvf mftecmd.csv` |
| MFTECmd for `$J` | `usnjrnl` | each_file | `mftecmd_j_csv` | The `$MFT` in the nearest folder above the `$J` as `-m`, for folder paths. With none above it, the run has no `-m`, and its notes say so. |
| PECmd | `prefetch` | host_dir | `pecmd_csv` | `--mp` |
| LECmd | `lnk` | host_dir | `lecmd_csv` | |
| JLECmd | `jumplist` | host_dir | `jlecmd_csv` | |
| RBCmd | `recycle_bin` | host_dir | `rbcmd_csv` | .NET 9 build. An empty result explains that the .NET 4 build needs administrator rights. |
| SrumECmd | `srum` | host_dir | `srumecmd_csv` | Works on copies in the run's folder, with the host's SOFTWARE hive copied too, each at its evidence path (`runner._make_copies`) |
| SQLECmd | `sqlite` | host_dir | `sqlecmd_csv` | .NET 9 build. Works on copies in the run's folder, with the logs of the databases intake knows by name. `--hunt false`. |
| WxTCmd | `sqlite:ActivitiesCache` | each_file | `wxtcmd_csv` | .NET 9 build. Works on copies with their logs, in the run's folder. |
| Suricata | `pcap` | each_file | `suricata_eve` | Needs Npcap's `wpcap.dll` (`tools.npcap_folder`). `-k none --runmode single`, with the ET Open rule file through `-S`. Timeout 240 minutes. |

Run behavior that bears on coverage:

| Behavior | Code |
|---|---|
| A tool that isn't found can't run, and a run whose output folder sits inside the evidence is refused. | `runner.run` |
| The working folder is the tool's own folder unless the registry file sets `run_in_run_folder`, so Hayabusa reads the `rules` folder beside its executable, with its `rules\config` files. | `runner.run` |
| Output with no parser is kept in the run folder and not loaded ("no parser yet"). | `runner.load_output` |
| A run's evidence check covers the identified inputs and their related files. **Inferred:** a host_dir tool's own `-d` search, such as EvtxECmd's, can read files intake left unidentified, and those files aren't in the check. | `runner.run`, `intake.verify` |
| Local-time output (Autoruns) is read at the host's zone: ActiveTimeBias from its SYSTEM hive first, then the host's configured zone. | `runner.host_zone`, `parsers.LOCAL_TIME` |

## Found tool output

`tool_outputs.KINDS` has 22 kinds, known by their header columns or file name (`tool_outputs.kind_of`). Raw evidence comes first: when the tool is installed and the same host has raw files it reads, the found output's group shows as `raw`, with **Load anyway** (`toolbox.found_outputs`). The import's ready-made kinds, Zeek, are never `raw`. When no installed, runnable tool reads captures, they are listed as "Capture files", with the note "Packet captures; no installed tool reads them yet" (`tool_outputs.CAPTURES`).

| Kind | Known by | Loaded by |
|---|---|---|
| EvtxECmd CSV | `EventRecordId TimeCreated EventId Provider Channel MapDescription PayloadData1` | `evtxecmd_csv` |
| Hayabusa CSV | `Timestamp RuleTitle Level Computer Channel EventID` | `hayabusa_csv` |
| JLECmd CSV, automatic | `SourceFile AppId DestListVersion` | `jlecmd_csv` |
| JLECmd CSV, custom | `SourceFile AppId EntryName` | `jlecmd_csv` |
| LECmd CSV | `SourceFile TargetCreated LocalPath WorkingDirectory`, without `AppId` | `lecmd_csv` |
| PECmd CSV | `SourceFilename ExecutableName RunCount LastRun` | `pecmd_csv` |
| PECmd timeline CSV | `RunTime ExecutableName` | Not loaded: it repeats the run times |
| MFTECmd `$MFT` CSV | `EntryNumber SequenceNumber InUse ParentPath Created0x10` | `mftecmd_csv` |
| MFTECmd `$J` CSV | `UpdateSequenceNumber UpdateTimestamp UpdateReasons` | `mftecmd_j_csv` |
| RECmd batch CSV | `HivePath HiveType KeyPath ValueName LastWriteTimestamp` | `recmd_csv` |
| RECmd plugin CSV | `BatchKeyPath BatchValueName` | Not loaded |
| SBECmd CSV | `BagPath Slot AbsolutePath ShellType` | `sbecmd_csv` |
| RBCmd CSV | `SourceName FileType FileName FileSize DeletedOn` | `rbcmd_csv` |
| AmcacheParser CSV | Name matching `_Amcache_\w+\.csv$` | `amcache_csv` |
| SrumECmd CSV | Name matching `_SrumECmd_\w+_Output\.csv$` | `srumecmd_csv` |
| WxTCmd Timeline CSV | `Id ActivityTypeOrg ActivityType Executable DisplayText StartTime` | `wxtcmd_csv` |
| WxTCmd package or operation CSV | `Id Platform Name Expires` | Not loaded |
| SQLECmd CSV | Name ending in a map's GUID | `sqlecmd_csv` |
| Zeek log, TSV | First line starts with `#separator` | The import's `zeek` preset |
| Zeek log, JSON | `ts` with `uid`, `uids`, `fuid`, or `id.orig_h`, or a Zeek log name (`tool_outputs.ZEEK_LOGS`) | The import's `zeek` preset |
| Suricata EVE JSON | `timestamp` and `event_type` | `suricata_eve` |
| Autoruns CSV | `Time`, `Entry Location`, `Entry`, `Enabled`, `Category`, `Profile`, `Image Path`, `Launch String` | `autoruns_csv` at the host's zone, or the import at an offset the analyst types (`imports.listed_as`) |

## The text log import

The import reads six formats (`imports.FORMATS`). Each record's fields map to the event columns through the roles in `imports.ROLES`: source IP and port, destination IP and port, account and domain, workstation, logon ID and type, recorded computer, event code, provider, channel, process and command line, parent and its command line, file path, and message (`imports.EventBuilder.event`). Every field that isn't ignored, empty, or `-` is kept in the event's own data. The time description is `Logged` (`imports.TS_DESC`).

| Format | Reader | Notes |
|---|---|---|
| `csv` | `imports._csv_records` | Delimiter guessed from comma, tab, semicolon, or pipe |
| `jsonl` | `imports._json_records` | JSON lines, or one JSON array up to 512 MB (`imports.MAX_JSON_ARRAY_BYTES`). Nested objects are flattened to dotted names. |
| `w3c` | `imports._w3c_records` | W3C extended logs with `#Fields:` |
| `kv` | `imports._kv_records` | `key=value` lines, space or comma separated |
| `lines` | `imports._line_records` | One record a line, in a layout from `line_logs.LAYOUTS` |
| `zeek` | `imports._zeek_records` | Zeek TSV or JSON. The `zeek` preset makes the log's `_path` the channel. |

Ready-made mappings (`imports.PRESETS`):

| Preset | Format | Artifact | Time | Roles mapped |
|---|---|---|---|---|
| `windows_firewall` | w3c | `windows_firewall` | `date` and `time`, zone asked | source and destination IP and port, code |
| `iis` | w3c | `iis` | `date` and `time`, UTC | source IP, destination IP and port, account, computer, code |
| `fortinet` | kv | `fortinet` | `eventtime` as epoch UTC, else `date` and `time` | source and destination IP and port, account, computer, channel, code |
| `sonicwall` | kv | `sonicwall` | `time` | source IP, destination IP, account, computer, code |
| `apache_access` | lines | `web_access` | `%d/%b/%Y:%H:%M:%S %z` | source IP, account, code |
| `apache_error` | lines | `web_error` | Guessed | source IP, code |
| `syslog` | lines | `syslog` | Guessed | source and destination IP and port, account, computer, process, command line, code |
| `cisco_asa` | lines | `cisco_asa` | Guessed | source and destination IP and port, account, computer, code |
| `snort_fast` | lines | `ids_alert` | Guessed | source and destination IP, channel, code |
| `zeek` | zeek | `zeek` | `ts`, guessed | source and destination IP and port, account and domain, file path, channel, code |
| `timestamped` | lines | `text_log` | Guessed | None: time and message only |

Line layouts (`line_logs.LAYOUTS`): Cisco ASA, Snort or Suricata fast alert, Apache or NGINX access log, Apache error log, Syslog, and lines that start with a date and time. Without a preset, the artifact is the format's name or the one the analyst types (`imports.normalize_mapping`). When the times have no year, as RFC 3164 syslog and some Cisco ASA and Snort logs write them, the import asks for one (`imports.check`, `imports.needs_year`).

## What the app refuses or leaves unread

| Input | What happens | Code |
|---|---|---|
| Disk images and containers (E01, VHDX, raw, zip, 7z) | Not identified. scope.md's Inputs row says a disk image is mounted or extracted first, for example with Plaso's `image_export`. | `identify.identify_bytes`, [scope.md](scope.md) |
| Symbolic links, junctions, folder reparse points | Skipped and listed | `intake.walk` |
| `$MFTMirr` | Identified, no tool reads it | `identify.identify_bytes` |
| `$Recycle.Bin` INFO2 (Windows XP) | Not identified, so RBCmd never runs for a host that has only INFO2. **Inferred:** on a host that also has `$I` files, RBCmd's `-d` reads its INFO2 files as well. | `identify.RECYCLE_VERSIONS`, `runner.plan_runs` |
| SQLite databases outside SQLECmd's maps | SQLECmd writes nothing for them. When no database matches, the run reports an empty result. | `registry/sqlecmd.yaml` |
| SQLECmd maps that write local time, and maps not in `sqlecmd.MAPS` (the test machine's SQLECmd has 95 maps, and the app reads 10) | Output kept, not loaded | `sqlecmd.parse_sqlecmd` |
| PECmd timeline CSV, RECmd plugin CSV, WxTCmd package CSV | Recognized as found output, not loaded | `tool_outputs.KINDS` |
| Amcache device and driver tables | Skipped | `amcache.parse_amcache` |
| SRUM energy, push notification, and `vfuprov` tables | Skipped | `srumecmd.TABLES` |
| Suricata `stats` records, and the `payload`, `payload_printable`, `packet`, and `packet_info.linktype` fields | Dropped | `suricata.SKIPPED`, `suricata.LARGE` |
| Event XML with a DOCTYPE, or that doesn't parse | The reader fails, exit code 3 | `event_xml.main` |
| An Autoruns CSV with an ambiguous date order, an unreadable time, or no known zone | Not loaded. The message points to the import with a typed offset. | `autoruns._read_times`, `autoruns._offset` |
| A file already loaded as found output | The import refuses it | `imports.run_import` |
| A file not in the manifest, or outside the evidence folder | The import refuses it | `imports._evidence_file` |
| A JSON array over 512 MB, or nested too deep | The import refuses it. A JSON line nested too deep is skipped and counted instead. | `imports._json_records` |
| An unknown format, layout, time format, or event field, a malformed artifact name, or no time field chosen | The import refuses the mapping | `imports.normalize_mapping` |
| A time field the records don't have, or times that fit no format | The import refuses the file | `imports.check` |
| Untimed records: an LNK or ShellBag without times, a jump list entry without times, an Autoruns entry without a time | Loaded, but off the timeline, which shows only timed events | `queries.BASE_WHERE` |

## Artifacts on the timeline

`parsers.PARSERS` has 17 parsers. The page name comes from `parsers.ARTIFACT_NAMES`, and an import's preset names its own. Every event has the columns in `events.COLUMNS`. Hayabusa's rows never show as events (`queries.BASE_WHERE`): each attaches as a hit to the EvtxECmd event it matched.

| Artifact (page name) | From | Times placed (`ts_desc`) | Channel, code, provider | Other columns filled | Parser |
|---|---|---|---|---|---|
| `evtx` (Event log) | EvtxECmd, the event XML reader | "Event Recorded" at `TimeCreated` | `Channel`, `EventId`, `Provider` | See [event log fields](#event-log-fields) | `evtxecmd.event_from_row` |
| `hayabusa` (Hayabusa) | Hayabusa | Hits, joined to events, not placed | `Channel`, `EventID` | Rule title, level, record ID, recorded computer. Details, MITRE tactics and tags, rule file, and rule ID kept in the event's data. | `hayabusa.parse_hayabusa` |
| `registry` (Registry) | RECmd | "Registry Key LastWrite" | None | Key path, value name, value data, hive path as the source. A file path from AppCompatCache, BAM, UserAssist, Services (the image path, or the DLL of a service svchost hosts), and Run key rows. Hive type, category, and the deleted flag kept. | `recmd.parse_recmd`, `recmd._program` |
| `mft` (MFT) | MFTECmd | One event per distinct `$SI` or `$FN` time, labeled with its MACB letters, such as "$SI M.C." | None | File path from the parent path and name. Flags for deleted, SI earlier than FN, zero microseconds, and copied. Zone.Identifier contents kept. | `mftecmd.events_from_row` |
| `usnjrnl` (USN journal) | MFTECmd | "USN journal change" | The most telling update reason as the code (`mftecmd_j.PRIORITY`) | File path with its folder from `$MFT`, the update sequence number as the record | `mftecmd_j.parse_mftecmd_j` |
| `prefetch` (Prefetch) | PECmd | "Prefetch Run Time" at `LastRun` and `PreviousRun0` to `PreviousRun6` | None | Full path matched from `FilesLoaded`. Run count and hash kept. | `pecmd.parse_pecmd` |
| `lnk` (Shortcut (LNK)) | LECmd | "LNK target created", "modified", and "accessed", and the tracker's time when it isn't later than the LNK file's own | None | Target path, recorded computer from `MachineID` | `lecmd.parse_lecmd` |
| `jumplist` (Jump list) | JLECmd | Automatic: "Jump list entry created" and "last used". Custom: the target's times. | None | Target path, account from the profile folder, recorded computer | `jlecmd.parse_jlecmd` |
| `shellbags` (ShellBag) | SBECmd | "ShellBag first interacted", "last interacted", and "ShellBag key last write" where it differs | None | Folder path, account from the hive's profile | `sbecmd.parse_sbecmd` |
| `amcache` (Amcache) | AmcacheParser | "Amcache file entry written", "Amcache program entry written", "Program installed", "Amcache shortcut entry written" | None | File path. SHA-1 into the hash list. | `amcache.parse_amcache` |
| `srum` (SRUM) | SrumECmd | "SRUM network use recorded", "network connection", "app resource use", "app timeline", hourly totals | None | Account, process | `srumecmd.parse_srumecmd` |
| `recycle_bin` (Recycle Bin) | RBCmd | "File deleted to the Recycle Bin" | None | Original path. SID kept. | `rbcmd.parse_rbcmd` |
| `browser` (Browser) | SQLECmd | "URL visited", "Download started", "Download finished", Chromium's "Downloaded file opened", Firefox's "Download recorded", "Search results last visited", "Address bar entry last used" | Code: `visit`, `download`, `search`, or `typed` | URL in the message, download target as the file path, account from the profile | `sqlecmd.parse_sqlecmd` |
| `notification` (Windows notification) | SQLECmd | "Notification arrived" | Code `notification` | The app and text in the message, account | `sqlecmd.notifications` |
| `timeline` (Windows Timeline) | WxTCmd | "Timeline activity started", "ended", and "last modified" | Code: the activity type | Process from `Executable`, account | `wxtcmd.parse_wxtcmd` |
| `suricata` (Suricata) | Suricata, or EVE JSON found in the evidence | "Suricata flow started", or "Suricata" and the record type | Channel: `event_type`. Code: the alert's signature ID. Provider: Suricata. | Source and destination IP and port, account from Kerberos `cname` or NTLM user, file name from `fileinfo`. Hashes into the hash list. | `suricata.parse_suricata_eve` |
| `autoruns` (Autoruns) | Autoruns CSV found in the evidence | "Image built (PE link time)" or "Image file last written", by the image's extension | Channel: `Category`. Provider: Autoruns. | File path from the image path. When that names no file, the process from the launch string's program. Command line from the launch string, registry key from the entry location, account from the profile. MD5, SHA-1, and SHA-256 into the hash list. | `autoruns.parse_autoruns` |
| Imports | The import | "Logged" | Mapped per preset | Mapped per preset. Zeek file hashes into the hash list. | `imports.EventBuilder` |

The hash list that the Same hash pivot reads holds Amcache SHA-1, Autoruns MD5, SHA-1, and SHA-256, Sysmon `Hashes` or `Hash`, Suricata `fileinfo` hashes, and Zeek `files` hashes. PECmd's hash and IMPHASH stay out (`hashes.HASHES_SQL`).

### Event log fields

`evtxecmd.event_from_row` reads the `Payload` fields (`EventData`, `UserData`, `ProcessingErrorData`, through `common.payload_fields`) into these columns. The message is `MapDescription` with the `PayloadData` columns.

| Column | Source fields, first match first |
|---|---|
| Record ID, recorded computer | `EventRecordId`, `Computer` |
| Account | Group changes: the subject. 4778 and 4779: `AccountName`. Then `TargetUserName`, 1149's `Param1` and `Param2`, `SubjectUserName`, Sysmon's `User`, Defender's `Detection User`. (`evtxecmd._account`). Fallback: the `UserId` SID when it is a local, domain, or Entra ID user account (`evtxecmd.ACCOUNT_SID`, in `evtxecmd.event_from_row`). |
| Source IP | `IpAddress`, `ClientIP`, 1149's `Param3`, 4778 and 4779's `ClientAddress`, LocalSessionManager's `Address`, `SourceIp`, `SourceAddress` |
| Source port | A port written with the source address, such as RdpCoreTS 131's `ClientIP`, then `IpPort`, `SourcePort` |
| Destination IP and port | `DestinationIp` or `DestAddress`, and `DestinationPort` or `DestPort` |
| Workstation | `WorkstationName`, or 4776's `Workstation` |
| Logon type | `LogonType` |
| Logon ID | `TargetLogonId`, `SubjectLogonId`, or `LogonID`, skipping `0x0`. Sysmon's `LogonId` outside system sessions. (`evtxecmd._logon_id`) |
| Process | `NewProcessName`, `ProcessName`, `Image`, `SourceImage`, `Application`, a scheduled task's command, Defender's `Process Name` |
| Command line | `CommandLine`, or a task's command with its arguments |
| Parent and its command line | `ParentImage` or `ParentProcessName`, and `ParentCommandLine` |
| File path | `TargetFilename`, 5145's share path joined to its target, `ImageLoaded`, 7045 and 4697's `ImagePath` or `ServiceFileName`, Defender's `Path`, 4656, 4660, and 4663's `ObjectName` when the object is a file |
| Registry key and data | `TargetObject`, `Details` |
| Event data kept | All payload fields, with `AccessNames`, the task values, `EventPayloadText`, and `SecurityUserID` |

The event XML reader writes this layout too, with descriptions for 46 event IDs: 27 Security, 18 Sysmon, and 7045 (`event_xml.DESCRIPTIONS`). An EvtxECmd run maps every ID its `Maps` folder covers.

## Search fields

`search.parse` reads words, quoted words and phrases, `field:value`, and `-term` to exclude.

- Words search the columns in `search.SEARCHED` and the event's own data, but not the tool, artifact, run, source file, mark, role, tags, or Hayabusa rule titles (`search.SKIPPED`). A bare word matches anywhere, inside other words too.
- A quoted word or phrase matches whole words: "nmap" finds `nmap.exe` and not `WinMaps`. The bound applies only at an end that is an ASCII letter, digit, or underscore, so ".dll" still matches inside `WinMaps.dll` (`search.bounded_pattern`). The page's Whole word tick quotes or unquotes the words (`search.whole_word`). For a quoted word, it can also show what the search would add without the quotes, and which longer words hold it (`search.search_adds`).
- `field:value` matches the whole value, without case. `*` matches any text, in words and values.
- A field that isn't listed searches the event's own data by that name. `addr:` matches either end of a connection.
- `path:` with a full path compares file keys, as Same file does. An event that names no file has its process's key.
- `user:` also matches the bare account name, and for a SID, the accounts looked up from it (`search.account_exprs`).
- `rule:` finds the events a Hayabusa rule hit, by the rule's whole title, without case, or with `*`. It reads the hits table, so it works in search only, and the View filter refuses it (`search.SEARCH_ONLY`).
- `mark:`, `role:`, `tag:`, and `tactic:` are refused (`search.JOURNAL_FIELDS`). The message says that search saves its matches and these change as the analyst works, so they are left to the View filter, to tick there or to choose as lanes.
- Since free text skips rule titles, a search with matches also lists up to three Hayabusa rules whose titles hold its first free-text word, each with its `rule:` search and its events (`search.by_name`). A search with no match says what free text covers and skips, and lists values of the skipped fields that hold the words, such as a rule, tool, file, mark, role, or tag (`search.zero_hint`).

| Field | Column | Aliases (`search.ALIASES`) |
|---|---|---|
| `host`, `tool`, `artifact`, `run` | The host, tool, artifact, and run ID | |
| `channel` | `log_channel` | |
| `file` | `source_file` | |
| `user` | Domain and account | `account` |
| `ip`, `port` | Source IP and port | `src`, `src_ip`, `source_ip`, `sport`, `src_port` |
| `dest_ip`, `dest_port` | Destination IP and port | `dst`, `dst_ip`, `dport`, `dst_port` |
| `code`, `provider`, `computer` | Event code, provider, recorded computer | `id`, `eventid` for code |
| `logon_type`, `logon_id`, `workstation` | Logon columns | `workstation_name` |
| `process`, `command_line` | Process and its command line | `cmd`, `commandline` |
| `parent`, `parent_command_line` | Parent process and its command line | `parent_process`, `parent_cmd` |
| `path` | `file_path` | |
| `registry_key`, `registry_value`, `registry_data` | Registry columns | `key` |
| `rule` | A Hayabusa rule's title, from the hits table. Search only. | `rule_title` |

Source: `queries.FIELDS`, less `mark` and `role`, which the View filter uses, plus `search.SEARCH_ONLY`. The search meaning is version 6 (`search.MEANING`), so matches saved under version 5 aren't reused.

## Rule and detection sources

| Source | What it flags | How it loads | Version recorded | Code |
|---|---|---|---|---|
| Hayabusa rules | Event log records that match Hayabusa and Sigma rules. Hits at medium or above suggest Suspicious. MITRE tactics and techniques suggest tags. | From `rules` beside `hayabusa.exe`, since the run's working folder is the tool's. The test machine has 4,984 rule files: 194 Hayabusa and 4,790 Sigma, dated 2026-09-12. The `rules` folder is a Git checkout whose last commit is dated 2026-09-03. | Only Hayabusa's version, from `hayabusa help`. The rule set's commit, which the checkout has, isn't recorded. | `registry/hayabusa.yaml`, `runner.run`, `analysis.build_tables`, `analysis.refresh_tags` |
| Hayabusa level filter | No `-m` unless the analyst sets `min_level`, so every level loads. Hayabusa's own defaults leave out deprecated, noisy, and unsupported rules, since the app passes none of `-D`, `-n`, or `-u`. Hayabusa's `rules\config` folder holds `exclude_rules.txt` (41 lines), `noisy_rules.txt` (12), and `level_tuning.txt` (7). | Hayabusa's own config, beside the executable | The option value is in the run's arguments | `registry/hayabusa.yaml` |
| ET Open for Suricata | Network alerts. Severity 1 or 2 suggests Suspicious. Severity 3 stays searchable only. | `scripts/suricata_rules.py` combines an ET Open download into `rules\suricata.rules`, leaving out `emerging-deleted` and `emerging-retired`, and writes `et-open-version.txt`. The test machine's set is 11310: 52,220 active rules, of which Suricata loads 52,211. | Yes: `runner.RunRecord.rules`, from the version file beside the rule file. The only rule set the app versions. | `registry/suricata.yaml`, `tools.rules_version`, `analysis.build_suggestions` |
| Imported fast alerts | Snort or Suricata `fast.log` lines. Priority 1 or 2 suggests Suspicious. | The import's `snort_fast` preset | The imported file's hash only | `analysis.build_suggestions`, `line_logs.LAYOUTS` |
| Built-in suggestion rules | `machine-accounts-authorized` (4624 type 3, a `$` account, from a collected host: Authorized). `remote-execution-pipes` (5145 to svcctl, atsvc, PsExec, or RemCom pipes: Suspicious). `print-spooler-pipe` (5145 to spoolss: Suspicious). `admin-share-executable-writes` (5145 writes of a runnable file over an admin share: Suspicious). | Text in the app. Each case adds a missing built-in unless the analyst removed it, and updates one the analyst hasn't changed to the app's current text. | The app's build. The journal records each add or change, with `builtin` set. | `rules.BUILTIN_RULES`, `server.ensure_builtin_rules` |
| Analyst rules | YAML conditions with `equals`, `in`, `regex` (checked against RE2), `between`, and `collected`, over the event columns (all but the event ID, the raw data, and three bookkeeping columns, `rules.TEXT_FIELDS`) plus `account` and `source_host`. They run on every event except Hayabusa's rows. | Added on the Rules page or with the `rule` command | The journal | `rules.parse`, `server.api_rule`, `cli.cmd_rule`, `analysis.build_suggestions` |
| EvtxECmd maps | Not detections: they shape `PayloadData` and the message | The `Maps` folder beside `EvtxECmd.exe` | Only EvtxECmd's version | `registry/evtxecmd.yaml` |
| RECmd batch file | Not detections: which keys reach the timeline. The test machine's `DFIRBatch.reb` is version 2.22, with about 517 entries, including 102 under Threat Hunting. | The path in the run's arguments | The path only, not the file's version | `registry/recmd.yaml` |
| Pivot table | Not detections: the Event page's ranked next pivots for 54 kinds of event, over 29 pivots, 15 of them built. 209 ranked rows, 10 broad-value rules, and 99 cited sources. The table's `about` block describes its fields (`about.explained_in` says so), and each row cites its sources by key in `sources`. | `pivot_table.json` beside `pivots.py`, read once per process | The repository's history only. The table has no version field, and the code reads none. | `pivots.table`, `pivots.BUILT`, `pivots.kind_of` |

Hayabusa hits need their EvtxECmd event. A hit joins on the EvtxECmd event's host, channel, record ID, and source file (`analysis.hit_join`). A Hayabusa run without an EvtxECmd run on the same files gives hits that join nothing, so they suggest nothing and attach to no event. **Inferred, untested:** a found Hayabusa CSV loaded beside an EvtxECmd run on the raw logs names its source files by the paths of the machine that ran it, so its hits wouldn't join either.

The pivot table's kinds cover these artifacts by name: registry (5 kinds, plus `run_key`, which also matches Sysmon 12 to 14 on Run keys and is counted with the event log kinds below), Autoruns (2), and one each for Prefetch, Amcache, MFT with the USN journal, Recycle Bin, LNK with jump lists, ShellBags, SRUM, the Windows Timeline, browsers, and notifications. Thirty-five kinds match event log codes, Suricata, Zeek, the fast alert import, and the firewall imports. One overlay adds rows for events with Hayabusa hits, and the `default` kind fits the rest, including imported IIS, web, syslog, and generic text logs (`pivots.kind_of`).

## Gaps

Common Windows DFIR sources the app doesn't cover, or covers in part, in groups for planning. The tool suggestions and artifact descriptions come from research on the outside tools in October 2026 and from general knowledge, and weren't rechecked for versions or licenses.

Size, as rough guidance:

- **S**: a registry file, a parser, and an intake signature, or a small change to intake, a parser, or the run record. Adding a tool such as SBECmd, AmcacheParser, or JLECmd is this size. SrumECmd also needed the runner's working copies, an M change.
- **M**: a new reader of the app's own, a runner or registry change, or a multi-line import reader.
- **L**: a new input model or a scope decision.

Value, **Inferred**, for intrusion triage on Windows hosts:

- **High**: often decides what happened, or is needed to defend a finding.
- **Medium**: adds corroboration or covers a common case.
- **Low**: rare, niche, or mostly images.

### Output the app already produces or recognizes

The tool already runs, or its output is already recognized, and the app drops part of what it reads.

| Gap | Covered by | Size | Value | Notes |
|---|---|---|---|---|
| Amcache device and driver tables | Parser addition | S | Medium | Drivers bear on vulnerable-driver attacks. AmcacheParser already writes these CSVs. |
| SQLECmd maps outside `sqlecmd.MAPS`, and the local-time maps | Parser additions, with a zone for local-time maps | S per map | Medium | Output already produced and kept. The test machine's SQLECmd has 95 maps, and the app reads 10. First candidates: Windows 11's search index (`Windows.db`), Windows diagnostic data (the next row), Chromium and Firefox cookies, and Chromium autofill (`Web Data`). Intake copies a database's `-wal` and journal only for the names in `identify.SQLITE_ROLES`, and none of these is there. |
| Windows diagnostic data (`EventTranscript.db`) | Parser addition for SQLECmd's two EventTranscript maps | S | Medium | Browsing history, device connectivity, and other diagnostic events on Windows 10 and 11. SQLECmd already runs both maps. **Inferred:** how much it holds depends on the host's diagnostic data setting. |
| SRUM energy and push notification tables, and `vfuprov` | Parser addition | S | Low | Output already produced and skipped (the `srumecmd.py` docstring) |
| RECmd plugin CSV, PECmd timeline CSV, WxTCmd package CSV | Parsers for found output | S | Low | Recognized today, not loaded. Most of their content reaches the timeline another way. |
| INFO2 Recycle Bin files | An intake change. RBCmd already reads INFO2. | S | Low | Only hosts older than Vista. The registry file and the parser already mention it. |

### App changes

| Gap | Covered by | Size | Value | Notes |
|---|---|---|---|---|
| Rule set and map versions in the run record (Hayabusa rules, EvtxECmd maps, RECmd batch, SQLECmd maps) | App change, like `tools.rules_version` | S | High | A finding should name the rules that raised it. Only Suricata's rule set is versioned today. Hayabusa's `rules` folder is a Git checkout, so its commit is at hand. |
| Logs from outside the evidence folder | Planned, not built | M | Medium | |

### Tools installed on the test machine or listed in `known_tools.yaml`

| Gap | Covered by | Size | Value | Notes |
|---|---|---|---|---|
| Event log record ID and time gaps, a sign of selective deletion | A query over EvtxECmd's record IDs, or [Chainsaw](https://github.com/WithSecureLabs/chainsaw)'s `analyse gaps`, installed 2.16.5 | S as a query, M with Chainsaw | High | Every EvtxECmd event already carries its record ID and channel, so gaps can be found in SQL with no new tool. `known_tools.yaml` lists Chainsaw as planned for leads of this kind. Hayabusa's installed `-x` carves records from slack, which the app doesn't pass, but hits on carved records would join no EvtxECmd event (`analysis.hit_join`). Cleared logs (1102 and 104) already show on the overview (`overview.CLEAR_WHERE`). |
| `$I30`, `$Boot`, `$SDS` | MFTECmd, installed (`-f` takes all three) | S | Medium | Intake doesn't identify them. `$I30` slack can show deleted files. [INDXRipper](https://github.com/harelsegev/INDXRipper) needs a volume or image, so MFTECmd is the only reader for collected files. |
| File content scanning | [YARA-X](https://github.com/VirusTotal/yara-x) with a rule set such as [YARA Forge](https://github.com/YARAHQ/yara-forge) | M | Medium | YARA-X writes results only to the console, which the runner can't load yet |
| RecentFileCache.bcf (Windows 7) | [RecentFileCacheParser](https://github.com/EricZimmerman/RecentFileCacheParser) | S | Low | Windows 7 and Server 2008 R2 only |
| Detection rules for event XML | Chainsaw's `hunt`, installed with Sigma rules, or [Zircolite](https://github.com/wagga40/Zircolite) | M | Low | Hayabusa reads EVTX and JSON (`-J`), not XML, and the app passes it EVTX only, so XML events get no rule hits. [Chainsaw](https://github.com/WithSecureLabs/chainsaw) reads EVTX files and event logs in JSON or XML. XML input is uncommon. |
| Deeper Chromium data (logins, cache, preferences) | [Hindsight](https://github.com/RyanDFIR/hindsight) with `-f jsonl` | M | Low | Cookies and autofill already come out of the SQLECmd run, so they belong to the SQLECmd maps row above. |

### New readers for common intrusion artifacts

| Gap | Covered by | Size | Value | Notes |
|---|---|---|---|---|
| PowerShell `ConsoleHost_history.txt` and transcripts | A built-in reader, or the import's line layout | M | High | Attackers' typed commands. The history file has no time per line, so lines take the file's times. |
| Defender `MPLog` and DetectionHistory | [Mplog-Parser](https://github.com/Intrinsec/mplog_parser), [DHParser](https://github.com/jklepsercyber/defender-detectionhistory-parser) | M | High | Detections and process names that outlast the event logs. Defender's event log is covered. **Inferred, untested:** MPLog lines that start with an ISO time may already import as timestamped lines, time and message only (`line_logs.STAMPED`). No MPLog was available to test. If they do, the gap is field extraction and DetectionHistory. |
| User Access Logging (`System32\LogFiles\Sum`) | [SumECmd](https://github.com/EricZimmerman/Sum) | S | High on servers | Accounts and source addresses per server role, kept far longer than most event logs. ESE files, so working copies, as SrumECmd uses. Server editions only. |
| Scheduled task XML (`System32\Tasks`) | A built-in reader | M | Medium | The persisted task, when the task events are missing or rolled over |
| WMI persistence (`OBJECTS.DATA`) | [WMI-Parser](https://github.com/woanware/wmi-parser) | M | Medium | |
| BITS jobs (`qmgr.db`, `qmgr*.dat`) | [BitsParser](https://github.com/fireeye/BitsParser) | M | Medium | |
| `$LogFile` | [NTFS Log Tracker](https://sites.google.com/site/forensicnote/ntfs-log-tracker) or [`dfir_ntfs`](https://github.com/msuhanov/dfir_ntfs) | **Unknown**, M at least | Medium | MFTECmd doesn't read it. Neither tool's unattended output format has been checked, and neither is installed or in `known_tools.yaml`. |
| `setupapi.dev.log` (USB first install) | A multi-line import reader | M | Medium | Each section puts the device ID and its time on separate lines, and the import's layouts match one line at a time (`line_logs.detect_layout`) |
| Remote access tool logs: AnyDesk's `ad.trace` and `connection_trace.txt`, TeamViewer's `Connections_incoming.txt` and log, ScreenConnect | An import layout per tool | S to M each | High | Common in intrusions that abuse remote management tools. **Inferred:** none fits the import's layouts today, since their lines don't start with the time. |
| Windows 11 PCA files (`Windows\appcompat\pca\PcaAppLaunchDic.txt`, `PcaGeneralDb0.txt`) | An import layout | S | Medium | Pipe-delimited program paths with last-run times, from Windows 11 22H2 |
| Windows Error Reporting (`Report.wer`) | A built-in reader | M | Low | One crash per file, such as of lsass or an exploited service |
| certutil downloads (`CryptnetUrlCache` metadata) | A parser for the cache's metadata files, or a built-in reader | M | Medium | The URL and time of a file fetched with `certutil -urlcache` |
| Other antivirus logs, such as Symantec's | [SEPparser](https://github.com/Beercow/SEPparser) | M | Low | One reader per vendor |
| SCCM software metering (also in `OBJECTS.DATA`) | [CCMRUAFinder](https://github.com/davidpany/WMI_Forensics) | M | Low | Only on SCCM-managed hosts |

### Application and user activity

| Gap | Covered by | Size | Value | Notes |
|---|---|---|---|---|
| OneDrive sync logs | [OneDriveExplorer](https://github.com/Beercow/OneDriveExplorer) | M | Medium | Bears on exfiltration to cloud storage |
| IE and Edge Legacy WebCache (`WebCacheV01.dat`) | An ESE reader, or [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) | M | Medium | Also records local file opens |
| Windows Search index on Windows 10 and earlier (`Windows.edb`) | SIDR, or an ESE reader, plus an intake signature | M | Low | Intake identifies ESE only as SRUM. [SIDR](https://github.com/strozfriedberg/sidr)'s last release was 0.9.2, on 2023-08-18, as of October 2026. Windows 11's `Windows.db` is SQLite and belongs to the SQLECmd maps row. |
| Teams, Notepad tabs, Office Backstage | [TeamsParser](https://github.com/lxndrblz/forensicsim) and similar single-purpose tools | M | Low | |
| RDP bitmap cache | [BMC-Tools](https://github.com/ANSSI-FR/bmc-tools) | M | Low | Images, little timeline value |
| Thumbnail cache (`thumbcache_*.db`) | [ThumbCacheViewer](https://thumbcacheviewer.github.io/) | M | Low | Images, little timeline value |

### Network imports

| Gap | Covered by | Size | Value | Notes |
|---|---|---|---|---|
| Sguil exports and Snort full alerts | Multi-line import readers | M | Low | The alert files of the [Malware-Traffic-Analysis.net exercise of 2016-01-07](https://www.malware-traffic-analysis.net/2016/01/07/index.html) come in these two formats, and the import reads neither. |

### Input model

| Gap | Covered by | Size | Value | Notes |
|---|---|---|---|---|
| Volume shadow copies | [Plaso](https://github.com/log2timeline/plaso) `image_export` with `--vss_stores`, then an input model change | L | High | Older copies of the logs and hives an attacker cleared. `image_export` can export the stores, so that part is a flag. What remains is the input model: each store is a second copy of the host, which `start.copies_warning` flags as a duplicate. |
| Disk images and containers (E01, VHDX, raw, zip) | Plaso `image_export` (run through Docker), [Dissect](https://github.com/fox-it/dissect) `target-dump`, [Arsenal Image Mounter](https://arsenalrecon.com/products/arsenal-image-mounter), [7-Zip](https://www.7-zip.org/) | L | High | The app reads collections only, so an image needs a step outside it |
| Memory, macOS, Linux, cloud, and mobile | [Volatility 3](https://github.com/volatilityfoundation/volatility3) for memory | Out of scope | | [scope.md](scope.md) |
