# Check: EVTX-ATTACK-SAMPLES

## What this check is

This is an open-answer check. Glessner was run on the dataset's Lateral Movement samples with the expected answers at hand, so the check shows whether the evidence each answer rests on is present and readable in Glessner. It doesn't show that an analyst who doesn't know the answer would find it. Blind rounds do that, and none has been finished yet. For this dataset an answer item is one sample file, scored against the technique the file is named for, so there are 47 items. The check's score is 37, 10, 0 of 47: 37 items were reached, 10 were partly reached, and none was missed. Each file's state rests on its facts, the records and values that show the technique it is named for, by the rules the totals under Results give.

## The dataset

- **Source:** [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES), a GitHub repository by sbousseaden.
- **Credit and license:** The dataset is by sbousseaden, under the GPL-3.0 license. This repository holds none of the dataset's files.
- **What it holds:** Windows event logs that record attack techniques, sorted into folders by ATT&CK tactic. This check used the Lateral Movement folder: 47 `.evtx` files from 11 machines, 1,288 events in all. The logs come from Sysmon, the Security and System logs, the RdpCoreTS and WinRM logs, and SQL Server's events.
- **Where the answers come from:** The dataset has no separate answer key for this check. Each file is named for the technique or tool it records, such as a PsExec, WMI, or WinRM run, and that technique is the expected answer. The names carry no technique IDs, so the check mapped each name to an ATT&CK technique ID. The table under Results lists it, with a second technique where the file records one, such as a Startup folder drop. Each file's facts are the records and values that show its technique.

## How it was run

[glossary.md](../glossary.md) defines terms such as lane, pivot, and mark.

**Date and build.** The check ran on 2026-10-14, on a build that predates v0.1.0, the first build with a version number, with Hayabusa 4.1.0. Each gap's state under Gaps found says where the gap stands in v0.3.0, and a fixed gap names the release that fixed it.

**Evidence.** The samples sit loose in one folder, not one folder per host. The case was made with `new-case --host LAB`, then `intake` and `run --all`. EvtxECmd and Hayabusa finished in 12 seconds.

**Loading.** All 47 files loaded, with 1,288 events. Nothing was skipped or left unidentified. Hayabusa wrote 1,222 rows, which joined to 1,098 events. The files came from 11 machines, but they sat in one folder, so they all loaded as one host named LAB. Gap 13 below covers this.

**Scoring.** For each file, read-only queries of the case database looked for the technique's key events and the fields that identify them. The check then looked at whether Glessner suggested a mark for them and which ATT&CK tags Hayabusa gave them. A query on the case confirmed each gap. Each file's state was then set against its facts, read from the first run's records.

Each item has one of four states: reached, partly reached, missed, or out of scope. An out-of-scope item needs something the app doesn't do by design, so it's listed and not counted. No item in this check is out of scope. A value in the raw data counts as shown, so a reached file can still have a field gap. A value that reads only after decoding or a comparison done by hand doesn't count. [How each item is scored](README.md#how-each-item-is-scored) gives the full rubric.

## Results

Each row is one answer item, a sample file. The Suggested column says whether any event in the file had a suggested mark. It records how the file's evidence could be found, beside the score, and doesn't change the score. Gap numbers refer to the list under Gaps found.

| File | Expected technique | Suggested | Score |
|---|---|---|---|
| `ImpersonateUser-via local Pass The Hash Sysmon and Security.evtx` | T1550.002 (with T1134.001) | yes | Reached |
| `lateral_movement_startup_3_11.evtx` | T1021.002 with T1547.001 | yes | Reached |
| `LM_4624_mimikatz_sekurlsa_pth_source_machine.evtx` | T1550.002 | yes | Reached |
| `LM_add_new_namedpipe_tp_nullsession_registry_turla_like_ttp.evtx` | T1112 (enabling T1021.002) | yes | Reached |
| `LM_ImageLoad_NFSH_Sysmon_7.evtx` | T1547.008 (LSASS Driver), filed under Lateral Movement | yes | Reached |
| `LM_impacket_docmexec_mmc_sysmon_01.evtx` | T1021.003 | yes | Reached |
| `LM_PowershellRemoting_sysmon_1_wsmprovhost.evtx` | T1021.006 | yes | Reached |
| `LM_regsvc_DirectoryServiceExtPt_Lsass_NTDS_AdamXpn.evtx` | T1547.008 | yes | Reached |
| `lm_remote_registry_sysmon_1_13_3.evtx` | T1112 with T1547.001 | yes | Reached |
| `LM_Remote_Service02_7045.evtx` | T1569.002 (with T1543.003 and T1021.002) | yes | Reached |
| `lm_sysmon_18_remshell_over_namedpipe.evtx` | T1021.002 | yes | Reached |
| `LM_sysmon_1_12_13_3_tsclient_SharpRdp.evtx` | T1021.001 | yes | Reached |
| `LM_sysmon_3_12_13_1_SharpRDP.evtx` | T1021.001 | yes | Reached |
| `LM_sysmon_psexec_smb_meterpreter.evtx` | T1021.002 (with T1569.002) | yes | Reached |
| `LM_tsclient_startup_folder.evtx` | T1021.001 (with T1547.001 for the Startup folder drop) | yes | Reached |
| `LM_typical_IIS_webshell_sysmon_1_10_traces.evtx` | T1505.003 | yes | Reached |
| `LM_winrm_exec_sysmon_1_winrshost.evtx` | T1021.006 | yes | Reached |
| `LM_wmi_PoisonHandler_Mr-Un1k0d3r_sysmon_1_13.evtx` | T1047 (with T1546.001 for the handler change) | yes | Reached |
| `LM_WMIC_4648_rpcss.evtx` | T1047 | yes | Reached |
| `LM_wmiexec_impacket_sysmon_whoami.evtx` | T1047 (Impacket wmiexec, DCOM transport T1021.003) | yes | Reached |
| `LM_xp_cmdshell_MSSQL_Events.evtx` | T1505.001 (xp_cmdshell, with commands run through T1059.003) | yes | Reached |
| `remote task update 4624 4702 same logonid.evtx` | T1053.005 | yes | Reached |
| `remote_file_copy_system_proc_file_write_sysmon_11.evtx` | T1570 (with T1021.002) | yes | Reached |
| `smbmap_upload_exec_sysmon.evtx` | T1021.002, T1570, T1047 | yes | Reached |
| `sysmon_1_exec_via_sql_xpcmdshell.evtx` | T1505.001 (with T1059.003) | yes | Reached |
| `wmi_remote_registry_sysmon.evtx` | T1047, T1112 (the value written is T1547.001) | yes | Reached |
| `DFIR_RDP_Client_TimeZone_RdpCoreTs_104_example.evtx` | T1021.001 | no | Reached |
| `dfir_rdpsharp_target_RdpCoreTs_168_68_131.evtx` | T1021.001 | no | Reached |
| `LM_NewShare_Added_Sysmon_12_13.evtx` | T1021.002 | no | Reached |
| `LM_Remote_Service01_5145_svcctl.evtx` | T1021.002 (with T1569.002) | no | Reached |
| `LM_ScheduledTask_ATSVC_target_host.evtx` | T1053.005 (with T1021.002) | no | Reached |
| `LM_sysmon_remote_task_src_powershell.evtx` | T1053.005 | no | Reached |
| `LM_WMI_4624_4688_TargetHost.evtx` | T1047 | no | Reached |
| `net_share_drive_5142.evtx` | T1021.002 | no | Reached |
| `RemotePowerShell_MS_Windows-Remote_Management_EventID_169.evtx` | T1021.006 | no | Reached |
| `sharprdp_sysmon_7_mstscax.dll.evtx` | T1021.001 | no | Reached |
| `spoolsample_5145.evtx` | T1187 | no | Reached |
| `LM_DCOM_MSHTA_LethalHTA_Sysmon_3_1.evtx` | T1021.003 | yes | Partly reached |
| `LM_5145_Remote_FileCopy.evtx` | T1570 (over T1021.002) | no | Partly reached |
| `LM_dcom_shwnd_shbrwnd_mmc20_failed_traces_system_10016.evtx` | T1021.003 | no | Partly reached |
| `LM_REMCOM_5145_TargetHost.evtx` | T1021.002 (with T1569.002 and T1570) | no | Partly reached |
| `LM_renamed_psexecsvc_5145.evtx` | T1021.002 (with T1569.002) | no | Partly reached |
| `LM_sysmon_3_DCOM_ShellBrowserWindow_ShellWindows.evtx` | T1021.003 | no | Partly reached |
| `LM_winrm_target_wrmlogs_91_wsmanShellStarted_poorLog.evtx` | T1021.006 | no | Partly reached |
| `MSSQL_15281_xp_cmdshell_exec_failed_attempt.evtx` | T1505.001 (attempt) | no | Partly reached |
| `powercat_revShell_sysmon_1_3.evtx` | T1059.001 with T1095 | no | Partly reached |
| `smb_bi_auth_conn_spoolsample.evtx` | T1187 | no | Partly reached |

The ten partly reached files, and why:

- `LM_DCOM_MSHTA_LethalHTA_Sysmon_3_1.evtx`: the file name names Sysmon event 3, so the connection's direction is a fact. mshta.exe's inbound connection from 10.0.2.17 reads as mshta.exe connecting out, because the address labels put the local host as the source. Only the raw `Initiated` value, read against the labels, gives its direction (gap 8).
- `LM_5145_Remote_FileCopy.evtx`: the 4 writes show only as the raw access code `%%4417`, so telling them from the 865 reads takes decoding by hand (gap 3).
- `LM_dcom_shwnd_shbrwnd_mmc20_failed_traces_system_10016.evtx`: the account, source address, and CLSID stay numbered parameters, and naming the DCOM objects the file is named for takes a CLSID lookup by hand (the DCOM 10016 gap under Smaller gaps). Its message named only the provider (gap 11).
- `LM_REMCOM_5145_TargetHost.evtx`: the 6 writes of RemComSvc.exe to ADMIN$ show only as the raw access code `%%4417`, so reading them as writes takes decoding by hand (gap 3). The svcctl pipe opens show.
- `LM_renamed_psexecsvc_5145.evtx`: the 2 writes of blabla.exe to ADMIN$ show only as the raw access code `%%4417`, so reading them as writes takes decoding by hand (gap 3). The svcctl open and the renamed service's pipes show.
- `LM_sysmon_3_DCOM_ShellBrowserWindow_ShellWindows.evtx`: the inbound connection, the file's only sign of the technique, reads as explorer.exe connecting out. Only the raw `Initiated` value, read against the address labels, gives its direction (gap 8).
- `LM_winrm_target_wrmlogs_91_wsmanShellStarted_poorLog.evtx`: the WinRM 91 event shows only its ID and provider, because Glessner dropped its account (gap 7). It also dropped the event's error data (gap 11), which surrounds the technique and isn't scored.
- `MSSQL_15281_xp_cmdshell_exec_failed_attempt.evtx`: the 15281 event shows only its ID and provider, because Glessner dropped its account and the data string that names xp_cmdshell (gaps 7 and 11).
- `powercat_revShell_sysmon_1_3.evtx`: the file name names Sysmon event 3, so the connection's direction is a fact. The record holds an inbound session to powershell.exe's listener on port 4444. The name says reverse shell, and where a name and a record disagree, the record decides. The address labels put the local host as the source, so the session reads as powershell.exe connecting out, and only the raw `Initiated` value, read against the labels, gives its direction (gap 8).
- `smb_bi_auth_conn_spoolsample.evtx`: the file name names a connection, so both connections' directions are facts. The inbound connection from 10.0.2.17 reads as outbound, because its address labels put the local host as the source, and only the raw `Initiated` value, read against them, gives its direction (gap 8). The outbound connection to 10.0.2.17 on port 445 reads right.

### Totals

- **Score:** 37, 10, 0 of 47. Of the 47 answer items, 37 were reached, 10 were partly reached, and none was missed. No item is out of scope. The score measures the build the check ran on, which predates v0.1.0 and its fixes.
- **Each file's facts:** The file names give only a technique, so each file's facts, read from the samples' records after the first run, decide its state. A file's facts are the records and values that show the technique its name names, and each part the name names, such as an event ID, a pipe, a share, a process, or a key. Records that only surround the technique are context and aren't scored. A 5145 share-access event that places a file on a share is a write, and the write is a fact. For a 5145 that opens a pipe, the kind of access isn't a fact. A value the sample doesn't hold, and the name doesn't name, isn't a fact. A file is scored on its own records, so a join counts only when both records are in the file. A connection's direction is a fact only when the file name names Sysmon event 3 or a connection.
- **What these rules changed:** Before these rules, this page gave the score as 42, 5, 0 and named seven reached files that the rules could lower. The rules lowered five reached files to partly reached, three of them among the seven. Three of the five turn on an inbound connection whose address labels put the local host as the source, in files whose names name Sysmon event 3 or a connection: `LM_DCOM_MSHTA_LethalHTA_Sysmon_3_1.evtx`, `powercat_revShell_sysmon_1_3.evtx`, and `smb_bi_auth_conn_spoolsample.evtx`. In each, the direction shows only by reading the raw `Initiated` value against the labels, a comparison by hand, as in `LM_sysmon_3_DCOM_ShellBrowserWindow_ShellWindows.evtx`. Two turn on writes to ADMIN$ whose access shows only as the raw code `%%4417`, which takes decoding: `LM_REMCOM_5145_TargetHost.evtx` and `LM_renamed_psexecsvc_5145.evtx`.
- **Four of the seven stay reached:** The name of `lm_sysmon_18_remshell_over_namedpipe.evtx` names neither Sysmon event 3 nor a connection, so its connection's direction isn't a fact, and the remote client's address shows. In `lateral_movement_startup_3_11.evtx`, the inbound connection joins the Startup folder write on time, 1.11 s apart. In `wmi_remote_registry_sysmon.evtx`, the remote side joins the Run value write, 2.41 s apart. Each join has one candidate, and in both files the address labels read right. `DFIR_RDP_Client_TimeZone_RdpCoreTs_104_example.evtx` holds no connection record to join its time zone records to, so it is reached on those records.
- **A wider reading:** Counting a connection's direction also where the file's only records of the remote host's address are inbound connections would lower three more files, `LM_impacket_docmexec_mmc_sysmon_01.evtx`, `LM_wmiexec_impacket_sysmon_whoami.evtx`, and `lm_sysmon_18_remshell_over_namedpipe.evtx`, for 34, 13, 0. These rules don't count it, since those files' names don't point to the connection.
- **Suggestions:** 27 files had suggestions, and 82 events were suggested in all (59 high, 1 critical, and 22 medium). In the two SharpRDP samples, the suggestions fell on RunMRU key creations that Hayabusa's deletion rule misnamed, and in one of them on an unrelated SYSTEM shell. The registry values that record the commands typed over RDP weren't suggested, and their data was only in the raw data (gap 5). Both files are reached, since a value in the raw data counts as shown. The misnamed rule is listed under Gaps outside the app.
- **ATT&CK tags:** These come from Hayabusa's rules. 13 files carried the expected technique or tactic, 12 carried a related one, 6 carried none that fit, and 16 carried no tag. Lateral Movement (TA0008) appears on only 20 events in 10 files, because Hayabusa's rules tag the execution or persistence side of these techniques.
- **Gaps by file:** 42 of the 47 files had a gap, and 5 had none. In 26 files, Glessner loaded the event but read EvtxECmd's output wrongly or left a value the answer uses in the raw data. In 12 files, the key events loaded, but nothing pointed an analyst to them. In one of these, `smbmap_upload_exec_sysmon.evtx`, other events were suggested, but not the upload. Those answers were hard to find, which by itself doesn't lower a score. Four of the 12 are partly reached for another reason, gap 3 or gap 8, as the notes above give. In 4 files, the sample itself doesn't hold a value. In three of them, the file name doesn't name the value either, so it isn't one of the file's facts: the impersonated account, the pipe added, and what WMIC ran. In `LM_WMI_4624_4688_TargetHost.evtx`, the 4688s hold no parent name, and WmiPrvSE.exe starting calc.exe shows through a join on process ID 0xAE8 within the host's records.

## Gaps found

The check grouped its findings into 13 gaps. This page numbers them 1 to 13, in the order the check recorded them, and the results above refer to them by number. All 13 are fixed in v0.1.0. The per-file notes also record three smaller field gaps, listed after gap 13, and each of those is open. Seven more have their cause outside Glessner, in Hayabusa, the rule sets it runs, its converter, EvtxECmd's output, or the samples, and are listed last. [CHANGELOG.md](../CHANGELOG.md) lists each release's changes, and [known_limitations.md](../known_limitations.md) lists what the app still doesn't do.

A gap's state here is one of three: fixed, with the release that fixed it; open, where the gap is deferred or no fix is chosen yet; or outside the app, where the evidence lacks the value or the cause is in another tool's rules, and the state names where a fix would go. [Gap states](README.md#gap-states) defines each.

Twelve of the 13 gaps are in how Glessner reads EvtxECmd's output or suggests marks, and one is in the workflow. Gaps 1 to 5 were rated high in value when found, and gaps 6 to 13 medium. All 13 fixes were built on 2026-10-15, the day after the run. None of the fixes changes an event's ID, so marks made before them still hold. The counts given for the fixes come from rebuilding or reparsing the samples, not from scoring the case again.

### Gap 1: The parent process was not shown

Sysmon event 1 records a process's parent and the parent's command line, and Security event 4688 records the parent's name. Glessner kept them only in the raw data, with no column, no text in the message, and no pivot. A shell started by w3wp.exe, sqlservr.exe, WmiPrvSE.exe, wsmprovhost.exe, or services.exe read in a list as a plain cmd.exe run. Those parents are what mark a web shell, SQL Server command execution, WMI, PowerShell remoting, and a remote service. The Event page's Event data group did show the parent.

**State now:** Fixed in v0.1.0. The parent process and its command line are now fields of their own, read from Sysmon 1 and from 4688. Sysmon 1's message starts with the parent. The fields can be searched and used in the View filter and in rules, and they appear on the Event page and in the exports. On the samples, 55 of 61 Sysmon 1 events show their parent. Sysmon wrote "?" for the other 6.

### Gap 2: Sysmon messages left out the deciding values

EvtxECmd puts the deciding values of many Sysmon events in its PayloadData3 to PayloadData6 columns, and Glessner's message left those columns out. Lines for Sysmon 3 (network connection), 11 (file created), 12 and 13 (registry) read as the event type, process ID, and GUID, with no address, file, key, or value. Sysmon 10 already showed its access mask and call trace. An analyst scanning a list had to open each event to learn what it did.

**State now:** Fixed in v0.1.0. A Sysmon message now leads with its target, from a table of what each event ID records: the addresses for Sysmon 3, the file for 11, the key and data for 12 and 13, and the source and target images for 10. The process GUID and empty labels are gone, and the other payload columns are added for other events. Lists show the first 160 characters of a message. On the samples, the destination of a Sysmon 3 event now fits within that width on 46 of 46 events.

### Gap 3: Share access had no file path and unreadable rights

A 5145 event records access to a network share. Glessner left its file path empty, so Same file couldn't join an ADMIN$ write of RemComSvc.exe to the file's other records. The access rights were raw codes such as %%4417, so the 4 writes among the 869 share-access events in one sample looked the same as the reads. The message did carry the share and the relative path, so a text search found the file.

**State now:** Fixed in v0.1.0. A 5145's file path is now the share's local folder joined to the path under it. IPC$ shares, whose targets are pipes, and a share's root get no path. The rights are read by name, such as WriteData, in the message and in the event's Raw fields. On the samples, 879 of 929 5145 events have a file path, the RemComSvc.exe write joins its C$ reads, and the 33 writes are named.

### Gap 4: Nothing suggested remote-execution pipes or admin-share writes

Nothing suggested a 5145 event that opens the svcctl, atsvc, spoolss, or PsExec pipes, or one that writes an executable to an admin share. Hayabusa's rules for these never match (see Gaps outside the app), so five files that hold only 5145 events had no suggestion.

**State now:** Fixed in v0.1.0. Three built-in rules each suggest Suspicious, and each can be removed like any rule. `remote-execution-pipes` covers opens of svcctl, atsvc, RemCom's pipes, and PsExec's service and stdin, stdout, and stderr pipes. `print-spooler-pipe` covers spoolss. `admin-share-executable-writes` covers writes of .exe, .dll, .bat, .cmd, .ps1, .vbs, .js, .hta, .scr, and .sys files to ADMIN$ and drive shares. On the samples they suggest 9 remote-execution pipe opens, 1 spooler pipe open, and 12 admin-share tool writes, in 4, 1, and 3 files.

### Gap 5: Registry data was never filled

Sysmon 13 records the data written to a registry value. In these samples, that data is a Run key's command, a RunMRU command typed over RDP, or a service's image path. Glessner kept it only in the raw data. The Event page's Event data group showed it, and a `Details:` search found it, but no column, filter, or message carried it.

**State now:** Fixed in v0.1.0. A new registry data field holds the data from Sysmon 13 and from RECmd. The value-name field keeps the value's name. On the samples, 31 of 31 Sysmon 13 events have registry data. For 10 of those 31, Sysmon itself wrote only "Binary Data", and Glessner keeps that as written.

### Gap 6: XML entities were not decoded

EvtxECmd's output escapes some characters as XML entities. Glessner showed them as written, so command lines held `&gt;`, `&lt;`, and `&amp;`. A search for a redirection as the attacker typed it found nothing, and a copied command line was wrong. On the samples, 13 command lines in 5 files held entities.

**State now:** Fixed in v0.1.0. EvtxECmd's values are decoded once when they load. No command line on the samples holds an entity now. Scheduled-task XML keeps its own escapes. EvtxECmd 2026.10, which v0.3.0's setup installs, writes its values already decoded, so Glessner decodes only the output of earlier EvtxECmd builds.

### Gap 7: Accounts recorded only in the System part were dropped

Some events name the account only in the System part of the event, as its user ID. They are the installer of a remote service (event 7045, three in these samples), WinRM 91, and MSSQL 15281. Glessner dropped it, so those events had no account to pivot on.

**State now:** Fixed in v0.1.0. When an event's data names no account, the user SID from the System part becomes the account. LocalSystem and the service accounts are left out, since they are the service's own. On the samples, 7 events gain an account.

### Gap 8: Inbound connections read backwards

Older Sysmon versions write the local side of a connection as the source, even for an inbound connection. On 11 inbound Sysmon 3 events, the attacker's address was the destination, so the connection read as the host reaching out. A bare-IP search and a `dst:` search already reached these events.

**State now:** Fixed in v0.1.0. A Sysmon 3 message now starts with "inbound" or "outbound", taken from Sysmon's Initiated field, and then gives each end with its port under Sysmon's own labels. The recorded source and destination stay as written. The IP pivot now matches an address at either end. On the samples, 46 of 46 Sysmon 3 events say inbound or outbound.

### Gap 9: Loaded DLLs and service binaries were not file paths

The DLL that Sysmon 7 records as loaded, and the binary that a 7045 service install records, weren't stored as file paths. Same file couldn't reach them. The remote DLL in the LSASS driver sample could be found only by text search.

**State now:** Fixed in v0.1.0. The loaded DLL is now the file path, and the loading process stays the process, so Same file centers on the DLL. A service's binary is the file path, without its arguments. On the samples, 7 of 7 Sysmon 7 DLLs and 3 of 3 service binaries have a file path.

### Gap 10: Sysmon's logon ID did not join the logon session

Sysmon records the logon ID of the session a process runs in. Glessner didn't read it into the logon session field, so Same logon session from a pass-the-hash 4624 missed the cmd.exe that the session started.

**State now:** Fixed in v0.1.0. Sysmon's logon ID now fills the field when the event has no other. The system sessions that every service on a host shares (0x3E7, 0x3E4, and 0x3E5) are left out, because joining on them would link unrelated events. On the samples, 52 Sysmon events gain a session, and Same logon session from the pass-the-hash 4624 reaches its shell.

### Gap 11: Unnamed data and error data were dropped

Glessner kept only named EventData items. MSSQL events 18454 and 15281 carry an unnamed string, and it was lost. WinRM's ProcessingErrorData was lost too. A search for xp_cmdshell missed the 15281 event that records it. For an event that EvtxECmd has no map for, lists showed only the event ID and the provider.

**State now:** Fixed in v0.1.0. Unnamed values are kept as `Data`, or as `Data1` to `DataN`, and processing-error data is kept. An event with no map shows its first four fields, named or unnamed, after the provider in its message, and the whole fields stay in the raw data that search reads. On the samples, 28 of the 31 unmapped events now show their fields, and a search for xp_cmdshell finds the 15281. The other 3, WinRM 193, carry no fields.

### Gap 12: A scheduled task's command was only in escaped XML

The action of a scheduled task is in the task XML of events 4698 to 4702, and Glessner showed that XML as escaped text. The command a remote task ran had no column and no pivot. In the atexec sample, the XML is the only record of the full command.

**State now:** Fixed in v0.1.0. Glessner now parses the task XML. The first Exec action's command becomes the process, and the command with its arguments becomes the command line. The message shows the task's name and what it runs, in place of the XML, which stays in the event's Raw fields. On the samples, 3 of 3 task events show their command.

### Gap 13: Event logs from 11 machines loaded as one host

Glessner expects one folder per host. A folder of loose event logs from several machines loaded as one host. The Hosts panel gave LAB 11 names and the role Domain controllers. The logon-session pivot joined the system session 0x3E7 across machines. Lanes mixed the machines' events, and the IP pivot joined unrelated samples that share the address 10.0.2.15.

**State now:** Fixed in v0.1.0, as an offer. The Hosts panel now offers to split a host whose event logs record several computers into one host per recorded computer. The offer shows a preview first, **Undo split** restores the single host, and no event ID changes, so marks hold. A folder of mixed logs still loads as one host until the analyst accepts the split. On a copy of this case, LAB splits into 11 hosts that hold its 1,288 event log events and 1,222 Hayabusa rows.

### Smaller gaps, still open

The per-file notes record three more field gaps. None of the 13 gaps covers them. Each is open: no fix is chosen.

- **WinRM 169:** the account is in a field named `username`, which isn't read as the account. It is the only field gap recorded for `RemotePowerShell_MS_Windows-Remote_Management_EventID_169.evtx`. That file is reached, since the account shows in the raw data.
- **MSSQL 33205:** the login's `server_principal_name` and `client_ip` appear only in the message, not in the account and source IP fields. You can't pivot on the login source, 10.0.2.17.
- **DCOM 10016:** the account (`param6` and `param7`), the source address (`param9`), and the CLSID (`param4`) stay numbered parameters, and the source IP field is empty. Naming the DCOM objects the file is named for takes a CLSID lookup by hand.

### Gaps outside the app

These came up in the same check. Their cause is in Hayabusa's rules, the rule sets it runs, its converter, EvtxECmd's output, or the samples, not in Glessner, so each one's state is outside the app.

| Finding | State |
|---|---|
| Hayabusa 4.1.0's rules that test ShareName for `\\*\IPC$` match nothing. On a copy of the samples, the shipped PsExec rule matched 0 events, and the same rule with an endswith test matched the 3 expected. | Outside the app, in Hayabusa's rules. Fixed in Hayabusa 4.2.0. It was already reported as [Hayabusa issue 1932](https://github.com/Yamato-Security/hayabusa/issues/1932). |
| Rules that test AccessList for WriteData can't match 5145's raw access codes. These rules come from the SigmaHQ rule set. | Outside the app. A fix would go in the SigmaHQ rules, and it isn't reported upstream yet. Gap 3 makes the rights readable in Glessner. |
| Hayabusa's RunMRU deletion rule fires on key creations. All 21 of its hits in the SharpRDP samples are creations, tagged as indicator removal. Hayabusa's converter maps the Sigma `registry_delete` type without its event type. | Outside the app. A fix would go in Hayabusa's converter, and it isn't reported upstream yet. Gap 2 puts the event type in Glessner's message, where the analyst can see it. |
| In `LM_WMIC_4648_rpcss.evtx`, Hayabusa's high-level rule on two of the 4648s is titled "Possible Mimikatz PrivEsc", which misnames the WMIC activity. | Outside the app. A fix would go in Hayabusa's rules. |
| No Hayabusa rule covers RdpCoreTS 104, 168, and 68, Security 5142, DCOM 10016, MSSQL 18454 and 15281, WinRM 169 and 91, or Sysmon 12 and 13 under the LanmanServer shares key. 9 of the 47 files had no Hayabusa hit at all. | Outside the app. A fix would go in Hayabusa's rules. The built-in rules from gap 4 cover share and pipe access, not these events. |
| The samples lack some values. The mimikatz 4624 of logon type 9 uses the old layout without TargetOutboundUserName. None of the 10 4688 events has a command line. Sysmon wrote "Binary Data" for 10 of 31 registry values. Several samples are one-sided, such as a remote task with only its source side. | Outside the app, in the samples. The evidence doesn't hold the value, so there is nothing to fix in Glessner. |
| EvtxECmd doesn't output the RdpCoreTS ActivityID that would tie a 104 to its 131. | Outside the app. A fix would go in EvtxECmd's output. |

## Limits of this check

- The expected answers were known during the work. The check shows the evidence is present and readable, not that an analyst would find it without the answers.
- The scoring was done by read-only queries of the case database, not by clicking through the page. How many steps an analyst takes in the app isn't measured.
- The score measures a build that predates v0.1.0, so it doesn't reflect the fixes listed under Gaps found. A run on a later release would show which items those fixes move.
- The suggestions in the table and the ATT&CK tags in the totals come from Hayabusa 4.1.0 and the rule set it ran with. Another Hayabusa version or rule set can change both.
- The dataset is 47 small logs, most of them built to show one technique, from 11 machines. It is not a real collection. Several samples are one-sided, and the files were loaded as one host, so the results say nothing about a multi-host case.
- The expected techniques come from file names. Some files carry a second technique, and the Lateral Movement folder holds files whose technique belongs to another tactic, such as T1547.008 (LSASS Driver).
- Which records and values show each technique is the check's reading of the file name, made after the first run. The totals under Results give the rules for that reading and the score under a wider reading of connection direction.
- The What has been checked section of [known_limitations.md](../known_limitations.md#what-has-been-checked) says what else hasn't been shown.
