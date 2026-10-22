# Checks

Each write-up here is an open-answer check of Glessner on a public practice set whose answers are published. Each check ran with the answers at hand, and each item of the published key was scored by what the app showed of it.

## The checks

Each write-up gives the dataset, how the check ran, each item's state, the gaps found, and the check's limits.

| Write-up | Dataset | Score | Build |
|---|---|---|---|
| [szechuan_sauce.md](szechuan_sauce.md) | [The Stolen Szechuan Sauce](https://dfirmadness.com/the-stolen-szechuan-sauce/), from DFIR Madness: two Windows hosts and a packet capture | 19, 5, 0 of 24, plus 1 out of scope | Before v0.1.0, run on 2026-10-14 |
| [evtx_attack_samples.md](evtx_attack_samples.md) | [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES), its Lateral Movement folder: 47 event logs from 11 machines | 42, 5, 0 of 47. Seven files wait on a written list of their facts, which could lower the score as far as 35, 12, 0. | Before v0.1.0, run on 2026-10-14 |
| [mta_2016_01_07.md](mta_2016_01_07.md) | [The Malware-Traffic-Analysis.net exercise of 2016-01-07](https://www.malware-traffic-analysis.net/2016/01/07/index.html): a packet capture of three hosts and two sensor alert files | 6, 7, 0 of 13, plus 1 out of scope | Before v0.1.0, run on 2026-10-15 |

[How each item is scored](#how-each-item-is-scored) defines the states and the form of a score. Each score measures the build the check ran on, before the fixes its gaps led to. v0.1.0 is the first build with a version number. [CHANGELOG.md](../CHANGELOG.md) lists each release's changes, and each write-up gives each gap's state in v0.2.0.

A check shows that the evidence for each answer is present and readable in the app. It doesn't show that an analyst who doesn't know the answer would find it. [known_limitations.md](../known_limitations.md#what-has-been-checked) lists what else hasn't been shown.

## How each item is scored

All three checks use one rubric, so their scores can be compared, and so can one check's scores across releases. The examples below come from these checks, called Szechuan, EVTX, and MTA for short. Item and gap numbers are each write-up's own. [glossary.md](../glossary.md) defines the app's terms, such as lane, pivot, and suggestion.

An item's state says what the app shows of the item on the build the check ran on. How the item was found, and how hard that was, go in the write-up's notes and its gap list.

An item's facts are what its row in the answer key names, with any correction the write-up makes against the evidence. In a list item, each row of the list is a fact, and rows the app shows beyond the key's don't count against it. EVTX has no answer key. Each of its files is an item, scored against the technique the file is named for, and its facts are the records and values that show that technique.

An item's evidence is the records that hold its facts. A record that shows without the values the item needs still shows one fact: that its event happened, on its host, at its time.

| State | Meaning | Example |
|---|---|---|
| Reached | The app shows every fact the item names, correctly. Search, pivot, suggestion, lane, and raw field all count, and so does a join under the rules below. | Szechuan item 13: DESKTOP-SDN1RPT's type 3 and type 10 logons from 10.42.85.10, and the timeline's logon arrow from DC01 to that host |
| Partly reached | The app shows some of the item's facts but not all. A fact is missing from what loaded or from the evidence, shows only through a comparison or decoding done by hand, or shows in the wrong order. | MTA item 2: JENNIFER-PC's address and MAC address show in its DHCP records, and no event holds its name |
| Missed | The app shows none of the item's evidence. | None of the 84 items in scope in these checks. An item whose only records sat in MTA's two alert files, which didn't load, would be missed. |
| Out of scope | The item needs something the app doesn't do by design, such as reading memory or giving recommendations, which it leaves to the analyst. [scope.md](../scope.md#not-in-scope) lists what the app leaves out. The write-up lists the item, and the score doesn't count it. | Szechuan item 25 and MTA item 14, the answers' recommendations |

When only part of an item is out of scope, the rest is scored, and the row names the part left out. Szechuan item 5 is reached on coreupdater's file, service, and download. Its migration into spoolsv.exe, which only memory shows, is the out-of-scope part.

The states apply as follows.

- **Hosts.** A host is one recorded machine or one network sensor, not one lane of the app. EVTX's logs come from 11 machines, which are 11 hosts, though the app loaded them as one host named LAB.
- **Joins.** A join within one host's records counts as shown when it rests on a shared value, such as a process ID, logon ID, flow ID, file name, or address. In EVTX's `LM_WMI_4624_4688_TargetHost.evtx`, calc.exe's 4688 names its creator as process 0xAE8, and the raw data of WmiPrvSE.exe's 4688 gives 0xAE8 as its new process ID. That join shows WmiPrvSE.exe starting calc.exe, so the file is reached. A join on time alone counts when only one candidate fits. One candidate within 5 s on the host's clock fits, and over a longer gap, the write-up names what rules out the others. A join across hosts counts when the records name both ends. Two sides that nothing in the records links, such as two clocks, or two hosts joined by time alone, take a comparison by hand. Szechuan item 14 is partly reached for that reason, since the hour between the hosts' clocks and the capture's came only from comparing two times by hand.
- **Several records.** When several records show the same fact, the best of them decides. In MTA item 9, the file records cut the six downloads' sizes at 102,400 bytes, and the HTTP records give the true sizes, so the item is reached.
- **Wrong values.** A field that states a fact wrongly lowers the item only when nothing else states the fact correctly: no other field of the record, no message, and no other record. The fact then comes out only by reading one field against the wrong one, which is a comparison by hand. In EVTX's `LM_sysmon_3_DCOM_ShellBrowserWindow_ShellWindows.evtx`, the address labels read the file's one inbound connection as outbound. Only the raw `Initiated` value, false, read against them gives its direction, so the file is partly reached. Where another field, the message, or another record states the fact, the item isn't lowered, and the wrong value is recorded as a gap.
- **Decoding.** Decoding reads a value through a table or conversion that neither the record nor the app gives, such as an access code read as a right, a CLSID read as a COM object's name, or a version number read as its release name or the reverse. A fact that shows only through decoding leaves its item partly reached. In EVTX's `LM_5145_Remote_FileCopy.evtx`, the 4 writes show only as the access code `%%4417`, so telling them from the 865 reads takes decoding. Text that reads through escaping, such as `&gt;` for `>`, counts as shown.
- **Times.** A time is correct when it matches the clock that wrote the event, the host's or the sensor's. When the app shows a collector's or logger's later time in its place, and a field of the record keeps the event's own time, the time counts as shown under the rule for wrong values. The delay then matters only through the order rule. A host clock that runs off is a fact of its own. Each item that asks for the clock, or for a time zone that rests on it, is scored on it, as Szechuan items 3 and 14 are, and the offset is recorded as a gap (Szechuan gap 2). The offset doesn't lower the other items whose times carry it.
- **Order.** A fact shows in the wrong order when its record lists out of place: records on the same clock that happened more than 5 s after it list ahead of it, or records that happened more than 5 s before it list after it. A swap within 5 s doesn't count. MTA item 11's second Flash request lists at the capture's last packet, after the payment page, which is one reason the item is partly reached. A record out of place counts against its own item only. Szechuan's command-and-control flows, listed at the capture's first packet (gap 1), don't lower item 6's download, which lists at its own time. Order isn't judged across hosts or sensors whose clocks the case hasn't aligned.
- **Hard to find.** An answer that was nearly missed keeps its state and gets a hard-to-find gap. Such an answer ranks low in a long list, turns up only for a search the analyst must already know to make, or is one the check missed at first. Szechuan item 2 is reached, since the desktop's product name loaded, though a search for `ProductName` ranked it 89th of 93 (gap 7).
- **Conclusions.** The app writes no finding or verdict by design, so an item that asks for a conclusion, such as "not infected", is scored on the facts the key gives as its basis. An absence counts as shown only when every evidence file that could hold the missing record loaded, or the check examined the ones that didn't. MTA item 6's basis is the redirector's 26-byte script response and the host's later traffic, which is ordinary browsing. An absence of alerts wouldn't serve, since the alert export that didn't load holds three redirector alerts on that host.
- **Names.** When the key bases a malware family, tool, or technique name on a detection, such as an alert, the name counts as shown when a loaded detection gives the same family, tool, or behavior in any rule set's wording. MTA items 8 and 13 are reached on ET Open alerts in place of the key's ETPRO alerts. When the key bases the name on behavior, as EVTX's file names do, no detection needs to name it, and the item is scored on the behavior's facts.
- **Synthesis items.** An item that asks for a timeline of the case, the methods used, or a diagram is scored as a list item on the parts the key lists. It is reached when the app shows dated evidence for every part, and partly reached for some. A diagram is reached when the app or its report gives a visual summary, and the timeline can be one. A part no record could hold, such as a physical act, keeps the item partly reached, as any fact missing from the evidence does.
- **File contents.** File contents are in scope. A fact inside a file, such as the body of a network response, counts like any other. Whether the app should read a given kind of content is decided gap by gap. MTA item 6 is partly reached because the app doesn't keep the redirector's 26-byte script (gap 18).

A score gives the reached, partly reached, and missed counts of the items in scope, then the out-of-scope count, as in "19, 5, 0 of 24, plus 1 out of scope". It doesn't count how an item was found. A write-up can give that beside the score, as the EVTX write-up's Suggested column does.

## Gap states

Each gap in a write-up has one state. Item states measure the build the check ran on, and gap states say where each gap stands in the release the write-up names. A gap can be fixed while the item it lowered keeps its state until the check runs again.

| State | Meaning | Example |
|---|---|---|
| Fixed | The named release fixes it. A gap whose remedy is documentation is fixed by the release that carries the documentation. | Szechuan gap 1, Suricata flow times, fixed in v0.1.0 |
| Planned | A fix or documentation is chosen and not built. | MTA gap 1, a reader for the Sguil alert export |
| Superseded | Another gap's fix covers it, and the state names that gap. | MTA gap 10, every event's host reading `network`, which gap 5's assignment of flows to hosts covers |
| Open | Deferred, or not yet decided. | Szechuan gap 9, a suggestion for timestomped files |
| Out of scope | The app leaves it out by design. | Szechuan gap 11 and MTA gap 19, recommendations |
| Outside the app | The evidence lacks the fact, or the cause is in a tool's rules. The state names where a fix would go, such as the collection or a report to the tool's maintainers. | EVTX's Hayabusa rules that can't match the samples' share-access events, and values the samples don't hold |

Each check will run again on each new release's build and be scored the same way. Each item will be compared with the earlier run, and each change will be given its cause, such as a fix, a new default in the release, a changed tool or rule set, or a regression. Totals will be compared only over the items in scope in both runs.
